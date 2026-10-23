//! The streamable HTTP transport that fronts the hub.
//!
//! Design decisions worth knowing about:
//!
//! * It binds loopback by default (`server.bind`) because the hub has no
//!   authentication of its own. `mcp-auth-proxy` is what protects a public URL; the
//!   local port must stay unreachable from the network.
//! * Each request is handled on its own thread, bounded by `MAX_IN_FLIGHT`, so one
//!   slow tool call cannot stall `ping`, `initialize` or another client.
//! * Browsers are only served when `Origin` names the configured `external_url`, a
//!   host this hub is actually served on (loopback, `server.bind`), or an entry in
//!   `server.allowed_origins`. There is no wildcard CORS, and the caller's own `Host`
//!   header is not accepted as proof of identity: that is what stops a page which
//!   makes its own hostname resolve to 127.0.0.1 (DNS rebinding) from calling tools.

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::fmt;
use std::io::{Cursor, Read};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::control::tokens_match;
use crate::hub::{Hub, errors, protocol_version_supported};

/// Largest JSON-RPC body we accept. MCP messages are small; this only exists so a
/// public endpoint cannot be made to buffer arbitrary amounts of memory.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Concurrently handled requests before we start answering 503.
const MAX_IN_FLIGHT: usize = 64;

/// Where and how the endpoint is exposed.
#[derive(Clone)]
pub struct HttpOptions {
    pub bind: IpAddr,
    /// 0 asks the operating system for a free port.
    pub port: u16,
    /// Public URL, used for OAuth metadata and to allow browser origins.
    pub external_url: Option<String>,
    /// Extra `scheme://host[:port]` origins allowed to call the endpoint.
    pub allowed_origins: Vec<String>,
    /// Static `Authorization: Bearer ...` token required on the hub.
    pub bearer_token: Option<String>,
    pub verbose: bool,
    /// Also log request and response payloads. Off by default: tool arguments
    /// routinely carry credentials.
    pub verbose_bodies: bool,
}

/// Never render the bearer token, not even in a debug log.
impl fmt::Debug for HttpOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpOptions")
            .field("bind", &self.bind)
            .field("port", &self.port)
            .field("external_url", &self.external_url)
            .field("allowed_origins", &self.allowed_origins)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .field("verbose", &self.verbose)
            .field("verbose_bodies", &self.verbose_bodies)
            .finish()
    }
}

/// A bound, not yet serving, endpoint.
pub struct HttpServer {
    server: Server,
    port: u16,
}

impl HttpServer {
    /// Bind the endpoint, resolving port 0 to the real port before anything else
    /// (banner, state file) reports it.
    pub fn bind(options: &HttpOptions) -> Result<Self> {
        let address = SocketAddr::new(options.bind, options.port);
        let listener =
            TcpListener::bind(address).with_context(|| format!("failed to bind {address}"))?;
        let port = listener
            .local_addr()
            .with_context(|| format!("failed to read the bound address of {address}"))?
            .port();
        let server = Server::from_listener(listener, None)
            .map_err(|error| anyhow!("failed to serve on {address}: {error}"))?;
        Ok(Self { server, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Accept and answer requests until `running` goes false.
    pub fn serve(
        self,
        hub: Arc<Hub>,
        options: HttpOptions,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        let port = self.port;
        let policy = Arc::new(OriginPolicy::new(&options));
        let in_flight = Arc::new(AtomicUsize::new(0));

        while running.load(Ordering::SeqCst) {
            let request = match self.server.recv_timeout(Duration::from_millis(200)) {
                Ok(Some(request)) => request,
                Ok(None) => continue,
                Err(error) => return Err(anyhow!("the HTTP listener stopped: {error}")),
            };

            if in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
                in_flight.fetch_sub(1, Ordering::SeqCst);
                let response = Response::from_data(Vec::new()).with_status_code(StatusCode(503));
                let _ = request.respond(response);
                continue;
            }

            let hub = Arc::clone(&hub);
            let options = options.clone();
            let policy = Arc::clone(&policy);
            let in_flight = Arc::clone(&in_flight);
            std::thread::spawn(move || {
                let _guard = InFlight(in_flight);
                if let Err(error) = handle(request, &hub, &options, &policy, port) {
                    errln!("warning: failed to answer an HTTP request: {error}");
                }
            });
        }

        Ok(())
    }
}

/// Decrements the in-flight counter however the request ends.
struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Answer one request.
fn handle(
    request: Request,
    hub: &Hub,
    options: &HttpOptions,
    policy: &OriginPolicy,
    port: u16,
) -> Result<()> {
    let method = request.method().clone();
    let url = request.url().to_string();
    let origin = header_value(&request, "origin");
    let host = header_value(&request, "host");
    let cors = cors_headers(policy, origin.as_deref(), host.as_deref());
    let allowed = policy.allows(origin.as_deref());

    if options.verbose {
        outln!("\n--> {method} {url}");
        for header in request.headers() {
            let value = if is_sensitive(header.field.as_str().as_str()) {
                "<redacted>"
            } else {
                header.value.as_str()
            };
            outln!("    {}: {value}", header.field);
        }
    }

    if !allowed {
        return respond_json(
            request,
            StatusCode(403),
            &rpc_error_body(
                errors::INVALID_REQUEST,
                "this origin is not allowed to call mcp-ctl; add it to server.allowed_origins",
            ),
            Vec::new(),
        );
    }

    let path = url.split('?').next().unwrap_or_default().to_string();

    // A bearer token guards the hub, but never the CORS preflight, the health probe
    // or the OAuth discovery documents: browsers cannot send Authorization on a
    // preflight, and probes should not need a secret.
    let public = matches!(method, Method::Options)
        || path == "/healthz"
        || path.starts_with("/.well-known/oauth-protected-resource");
    if let Some(expected) = &options.bearer_token
        && !public
        && !bearer_matches(header_value(&request, "authorization").as_deref(), expected)
    {
        return respond_json(
            request,
            StatusCode(401),
            &rpc_error_body(errors::INVALID_REQUEST, "missing or invalid bearer token"),
            with_challenge(cors),
        );
    }

    match (&method, path.as_str()) {
        (&Method::Options, _) => respond(request, StatusCode(204), cors, Vec::new()),
        (&Method::Get, "/healthz") => respond(request, StatusCode(200), Vec::new(), b"ok".to_vec()),
        (&Method::Get, "/.well-known/oauth-protected-resource")
        | (&Method::Get, "/.well-known/oauth-protected-resource/mcp") => {
            let base = options
                .external_url
                .clone()
                .unwrap_or_else(|| format!("http://127.0.0.1:{port}"));
            let body = json!({
                "resource": format!("{base}/mcp"),
                "authorization_servers": [base],
            });
            respond_json(request, StatusCode(200), &body, cors)
        }
        (&Method::Post, "/mcp") => post(request, hub, options, cors),
        (&Method::Get, "/mcp") | (&Method::Delete, "/mcp") => respond_json(
            request,
            StatusCode(405),
            &rpc_error_body(
                errors::INVALID_REQUEST,
                "mcp-ctl is stateless: POST /mcp is the only supported method (the GET stream and DELETE session endpoints are not implemented)",
            ),
            with_allow(cors, "POST"),
        ),
        _ => respond_json(
            request,
            StatusCode(404),
            &rpc_error_body(errors::INVALID_REQUEST, "unknown endpoint"),
            cors,
        ),
    }
}

/// Handle `POST /mcp`.
fn post(mut request: Request, hub: &Hub, options: &HttpOptions, cors: Vec<Header>) -> Result<()> {
    let started = Instant::now();

    // The negotiated revision is echoed in this header by 2025-06-18 clients; an
    // unknown revision means we cannot serve the request correctly.
    if let Some(version) = header_value(&request, "mcp-protocol-version")
        && !protocol_version_supported(&version)
    {
        return respond_json(
            request,
            StatusCode(400),
            &rpc_error_body(
                errors::INVALID_REQUEST,
                &format!("unsupported MCP-Protocol-Version '{version}'"),
            ),
            cors,
        );
    }

    if let Some(content_type) = header_value(&request, "content-type")
        && !content_type
            .to_ascii_lowercase()
            .starts_with("application/json")
    {
        return respond_json(
            request,
            StatusCode(415),
            &rpc_error_body(
                errors::INVALID_REQUEST,
                "Content-Type must be application/json",
            ),
            cors,
        );
    }

    if request
        .body_length()
        .is_some_and(|length| length > MAX_BODY_BYTES)
    {
        return respond_json(
            request,
            StatusCode(413),
            &rpc_error_body(errors::INVALID_REQUEST, "request body is too large"),
            cors,
        );
    }

    let mut body = Vec::new();
    let read = {
        let mut reader = request.as_reader().take(MAX_BODY_BYTES as u64);
        reader.read_to_end(&mut body)
    };
    if let Err(error) = read {
        return respond_json(
            request,
            StatusCode(400),
            &rpc_error_body(
                errors::INVALID_REQUEST,
                &format!("could not read the request body: {error}"),
            ),
            cors,
        );
    }
    if body.len() >= MAX_BODY_BYTES {
        return respond_json(
            request,
            StatusCode(413),
            &rpc_error_body(errors::INVALID_REQUEST, "request body is too large"),
            cors,
        );
    }

    let message: Value = match serde_json::from_slice(&body) {
        Ok(message) => message,
        Err(error) => {
            return respond_json(
                request,
                StatusCode(400),
                &rpc_error_body(errors::PARSE_ERROR, &format!("invalid JSON: {error}")),
                cors,
            );
        }
    };

    // Batching was removed from the protocol in 2025-06-18; say so instead of
    // answering half of it.
    if message.is_array() {
        return respond_json(
            request,
            StatusCode(400),
            &rpc_error_body(
                errors::INVALID_REQUEST,
                "JSON-RPC batching is not supported",
            ),
            cors,
        );
    }

    if options.verbose && options.verbose_bodies {
        outln!("    body: {message}");
    }

    match hub.handle(&message) {
        // A notification: accepted, and there is deliberately nothing to say back.
        None => respond(request, StatusCode(202), cors, Vec::new()),
        Some(response) => {
            if options.verbose {
                outln!(
                    "    <-- {} in {:?}",
                    if response.get("error").is_some() {
                        "error"
                    } else {
                        "ok"
                    },
                    started.elapsed()
                );
                if options.verbose_bodies {
                    outln!("    body: {response}");
                }
            }
            respond_json(request, StatusCode(200), &response, cors)
        }
    }
}

/// A parsed `scheme://host[:port]` origin.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OriginParts {
    scheme: String,
    host: String,
}

/// Browser origin policy (the DNS-rebinding protection the MCP spec asks for).
///
/// A request without `Origin` — every non-browser client — is allowed. A request with
/// an `Origin` is allowed when that origin is the configured `external_url` origin, an
/// entry in `server.allowed_origins`, or an origin on a host this hub actually answers
/// on (loopback, `server.bind`, or the public URL's host).
///
/// The request's own `Host` header is deliberately not part of the decision. A page
/// that makes its own hostname resolve to 127.0.0.1 (DNS rebinding) sends a matching
/// `Origin` and `Host`, so accepting "Origin equals Host" would accept exactly the
/// attack this policy exists to stop.
///
/// The scheme is part of the comparison: `http://host` and `https://host` are
/// different origins, so an insecure page cannot ride on an `https://` external_url.
struct OriginPolicy {
    allowed: Vec<String>,
    public_origin: Option<OriginParts>,
    /// Hosts, without ports, that this hub is served on.
    own_hosts: Vec<String>,
}

impl OriginPolicy {
    fn new(options: &HttpOptions) -> Self {
        let public_origin = options.external_url.as_deref().and_then(origin_parts);
        let mut own_hosts = ["127.0.0.1", "localhost", "::1"]
            .map(str::to_string)
            .to_vec();
        own_hosts.push(options.bind.to_string().to_ascii_lowercase());
        if let Some(public) = &public_origin {
            own_hosts.push(host_only(&public.host));
        }
        Self {
            allowed: options
                .allowed_origins
                .iter()
                .map(|origin| origin.trim_end_matches('/').to_lowercase())
                .collect(),
            public_origin,
            own_hosts,
        }
    }

    fn allows(&self, origin: Option<&str>) -> bool {
        let Some(origin) = origin else {
            return true;
        };
        let origin = origin.trim_end_matches('/').to_lowercase();
        // A sandboxed page or a `file://` document: never a legitimate caller.
        if origin == "null" {
            return false;
        }
        if self.allowed.contains(&origin) {
            return true;
        }

        let Some(parsed) = origin_parts(&origin) else {
            return false;
        };
        if self.public_origin.as_ref() == Some(&parsed) {
            return true;
        }
        if !self.own_hosts.contains(&host_only(&parsed.host)) {
            return false;
        }
        // When `external_url` names this host, it pins the scheme, so `http://`
        // cannot masquerade as the `https://` public origin.
        match &self.public_origin {
            Some(public) if public.host.eq_ignore_ascii_case(&parsed.host) => {
                public.scheme == parsed.scheme
            }
            _ => true,
        }
    }

    /// Is the caller cross-origin, and therefore in need of CORS response headers?
    fn is_cross_origin(&self, origin: &str, host: Option<&str>) -> bool {
        let Some(parsed) = origin_parts(origin) else {
            return true;
        };
        let Some(host) = host else {
            return true;
        };
        if !host.eq_ignore_ascii_case(&parsed.host) {
            return true;
        }
        match &self.public_origin {
            Some(public) if public.host.eq_ignore_ascii_case(&parsed.host) => {
                public.scheme != parsed.scheme
            }
            _ => false,
        }
    }
}

/// `127.0.0.1:37373` / `[::1]:37373` / `laptop.example.ts.net` -> the host without its port.
/// Case is left alone: both callers pass an already lowercased host.
fn host_only(host: &str) -> String {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    // A single colon introduces a port; several mean a bare IPv6 address.
    match host.split_once(':') {
        Some((name, port))
            if !name.contains(':') && port.chars().all(|character| character.is_ascii_digit()) =>
        {
            name.to_string()
        }
        _ => host.to_string(),
    }
}

/// `https://host:port/path` -> `{ scheme: "https", host: "host:port" }`.
fn origin_parts(url: &str) -> Option<OriginParts> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..end];
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    Some(OriginParts {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
    })
}

/// CORS headers for an allowed cross-origin caller; empty for same-origin requests.
fn cors_headers(policy: &OriginPolicy, origin: Option<&str>, host: Option<&str>) -> Vec<Header> {
    let Some(origin) = origin else {
        return Vec::new();
    };
    if !policy.is_cross_origin(origin, host) {
        return Vec::new();
    }
    vec![
        header("Access-Control-Allow-Origin", origin),
        header("Vary", "Origin"),
        header("Access-Control-Allow-Methods", "POST, OPTIONS"),
        // Authorization is what browser-based clients (MCP Inspector and web
        // agents) send; without it the preflight fails before the request exists.
        header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, MCP-Protocol-Version",
        ),
    ]
}

fn with_allow(mut headers: Vec<Header>, methods: &str) -> Vec<Header> {
    headers.push(header("Allow", methods));
    headers
}

fn with_challenge(mut headers: Vec<Header>) -> Vec<Header> {
    headers.push(header("WWW-Authenticate", "Bearer realm=\"mcp-ctl\""));
    headers
}

/// Does an `Authorization` header carry the expected bearer token?
///
/// The scheme is case-insensitive per RFC 7235; the comparison itself is constant
/// time, so a wrong token cannot be discovered byte by byte.
fn bearer_matches(header: Option<&str>, expected: &str) -> bool {
    let Some((scheme, token)) = header.and_then(|value| value.split_once(' ')) else {
        return false;
    };
    scheme.eq_ignore_ascii_case("bearer") && tokens_match(expected, token.trim())
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes())
        .expect("header names and values built by mcp-ctl are valid")
}

/// The first value a client sent for a header, verbatim.
fn header_value(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|header| header.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str().to_string())
}

/// Header names whose values must never reach a log.
fn is_sensitive(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
    ]
    .iter()
    .any(|sensitive| name == *sensitive)
}

/// A JSON-RPC error body for failures that happen before a request id exists.
fn rpc_error_body(code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": null, "error": { "code": code, "message": message } })
}

fn respond_json(
    request: Request,
    status: StatusCode,
    value: &Value,
    mut headers: Vec<Header>,
) -> Result<()> {
    headers.push(header("Content-Type", "application/json"));
    respond(request, status, headers, value.to_string().into_bytes())
}

fn respond(
    request: Request,
    status: StatusCode,
    headers: Vec<Header>,
    body: Vec<u8>,
) -> Result<()> {
    let mut response: Response<Cursor<Vec<u8>>> =
        Response::from_data(body).with_status_code(status);
    for header in headers {
        response.add_header(header);
    }
    request
        .respond(response)
        .map_err(|error| anyhow!("failed to write the response: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(allowed: &[&str], external_url: Option<&str>) -> HttpOptions {
        HttpOptions {
            bind: IpAddr::from([127, 0, 0, 1]),
            port: 37373,
            external_url: external_url.map(str::to_string),
            allowed_origins: allowed.iter().map(|origin| origin.to_string()).collect(),
            bearer_token: None,
            verbose: false,
            verbose_bodies: false,
        }
    }

    fn policy(allowed: &[&str], external_url: Option<&str>) -> OriginPolicy {
        OriginPolicy::new(&options(allowed, external_url))
    }

    #[test]
    fn requests_without_an_origin_are_allowed() {
        assert!(policy(&[], None).allows(None));
    }

    #[test]
    fn loopback_and_the_bind_address_are_same_origin_enough() {
        let local = policy(&[], None);
        assert!(local.allows(Some("http://127.0.0.1:37373")));
        assert!(local.allows(Some("http://localhost:37373")));
        assert!(local.allows(Some("http://[::1]:37373")));

        // A hub bound to a LAN address is reachable as that address.
        let lan = OriginPolicy::new(&HttpOptions {
            bind: IpAddr::from([192, 168, 1, 5]),
            ..options(&[], None)
        });
        assert!(lan.allows(Some("http://192.168.1.5:37373")));
        assert!(!lan.allows(Some("http://192.168.1.6:37373")));
    }

    #[test]
    fn a_caller_supplied_host_header_does_not_make_an_origin_ours() {
        // DNS rebinding: the page's own hostname resolves to 127.0.0.1, so the
        // browser sends `Origin: https://evil.example` and `Host: evil.example`.
        // Only a host we are actually served on may pass, whoever claims what.
        let local = policy(&[], None);
        assert!(!local.allows(Some("https://evil.example")));
        assert!(!local.allows(Some("http://evil.example:37373")));
        // The same request through the public URL's host is still allowed.
        let public = policy(&[], Some("https://laptop.example.ts.net"));
        assert!(public.allows(Some("https://laptop.example.ts.net")));
    }

    #[test]
    fn foreign_and_sandboxed_origins_are_refused() {
        let policy = policy(&[], None);
        assert!(!policy.allows(Some("https://evil.example")));
        assert!(!policy.allows(Some("null")));
        assert!(!policy.allows(Some("not a url")));
    }

    #[test]
    fn configured_origins_and_the_public_host_are_allowed() {
        let policy = policy(
            &["https://inspector.example:6274"],
            Some("https://laptop.example.ts.net"),
        );
        assert!(policy.allows(Some("https://inspector.example:6274")));
        assert!(policy.allows(Some("https://laptop.example.ts.net")));
        assert!(policy.allows(Some("https://LAPTOP.example.ts.net")));
        assert!(!policy.allows(Some("https://other.example")));
    }

    #[test]
    fn same_origin_requests_need_no_cors_headers() {
        let policy = policy(&[], None);
        assert!(!policy.is_cross_origin("http://127.0.0.1:37373", Some("127.0.0.1:37373")));
        assert!(policy.is_cross_origin("https://inspector.example", Some("127.0.0.1:37373")));
    }

    #[test]
    fn the_public_scheme_is_enforced() {
        let policy = policy(&[], Some("https://laptop.example.ts.net"));

        assert!(policy.allows(Some("https://laptop.example.ts.net")));
        // Same host, insecure scheme: a different origin, and not the public one.
        assert!(!policy.allows(Some("http://laptop.example.ts.net")));
    }

    #[test]
    fn hosts_are_compared_without_their_port() {
        assert_eq!(host_only("127.0.0.1:37373"), "127.0.0.1");
        assert_eq!(host_only("[::1]:37373"), "::1");
        assert_eq!(host_only("[::1]"), "::1");
        assert_eq!(host_only("::1"), "::1");
        assert_eq!(host_only("laptop.example.ts.net"), "laptop.example.ts.net");
        assert_eq!(
            host_only("LAPTOP.example.ts.net:443"),
            "LAPTOP.example.ts.net"
        );
    }

    #[test]
    fn origins_are_parsed_with_their_scheme() {
        assert_eq!(
            origin_parts("https://laptop.example.ts.net:443/mcp"),
            Some(OriginParts {
                scheme: "https".to_string(),
                host: "laptop.example.ts.net:443".to_string()
            })
        );
        assert_eq!(
            origin_parts("HTTP://127.0.0.1:37373"),
            Some(OriginParts {
                scheme: "http".to_string(),
                host: "127.0.0.1:37373".to_string()
            })
        );
        assert_eq!(origin_parts("not a url"), None);
        assert_eq!(origin_parts("file:///tmp/page.html"), None);
    }

    #[test]
    fn cors_preflight_allows_the_authorization_header() {
        let policy = policy(&["https://inspector.example:6274"], None);
        let headers = cors_headers(
            &policy,
            Some("https://inspector.example:6274"),
            Some("127.0.0.1:37373"),
        );
        let allowed = headers
            .iter()
            .find(|header| header.field.as_str().as_str() == "Access-Control-Allow-Headers")
            .map(|header| header.value.as_str().to_string())
            .unwrap_or_default();
        assert!(allowed.contains("Authorization"), "{allowed}");
    }

    #[test]
    fn bearer_tokens_are_matched_case_insensitively_and_completely() {
        assert!(bearer_matches(Some("Bearer correct"), "correct"));
        assert!(bearer_matches(Some("bearer correct"), "correct"));
        assert!(!bearer_matches(Some("Bearer incorrect"), "correct"));
        assert!(!bearer_matches(Some("Basic correct"), "correct"));
        assert!(!bearer_matches(Some("correct"), "correct"));
        assert!(!bearer_matches(None, "correct"));
    }

    #[test]
    fn sensitive_headers_are_recognised() {
        assert!(is_sensitive("Authorization"));
        assert!(is_sensitive("Cookie"));
        assert!(!is_sensitive("Content-Type"));
    }
}
