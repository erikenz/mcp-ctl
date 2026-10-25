//! The streamable HTTP transport that fronts the hub.
//!
//! Design decisions worth knowing about:
//!
//! * It binds loopback by default (`server.bind`) because the hub has no
//!   authentication of its own. `mcp-auth-proxy` is what protects a public URL; the
//!   local port must stay unreachable from the network.
//! * Each connection is handled on its own thread, bounded by `MAX_IN_FLIGHT`, and a
//!   request must arrive within `REQUEST_TIMEOUT`. The bound and the deadline matter:
//!   without them a client that sends half a request could hold a thread forever.
//! * Browsers are only served when `Origin` names the configured `external_url`, a
//!   host this hub is actually served on (loopback, `server.bind`), or an entry in
//!   `server.allowed_origins`. There is no wildcard CORS, and the caller's own `Host`
//!   header is not accepted as proof of identity: that is what stops a page which
//!   makes its own hostname resolve to 127.0.0.1 (DNS rebinding) from calling tools.

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::control::tokens_match;
use crate::hub::{Hub, errors, protocol_version_supported};

/// Largest JSON-RPC body we accept. MCP messages are small; this only exists so a
/// public endpoint cannot be made to buffer arbitrary amounts of memory.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Largest request line and largest individual header line.
const MAX_REQUEST_LINE: usize = 8 * 1024;

/// Largest combined header block, and the most headers we will parse.
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 100;

/// Concurrently handled connections before we start answering 503.
const MAX_IN_FLIGHT: usize = 64;

/// How long a whole request (line, headers and body) may take to arrive.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the client may take to read a response.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Failed bearer attempts allowed in one window before the hub answers 429.
const MAX_FAILED_AUTH: u64 = 100;
const AUTH_WINDOW: Duration = Duration::from_secs(60);

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
    listener: TcpListener,
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
        Ok(Self { listener, port })
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
        let limiter = Arc::new(AuthLimiter::new());
        let in_flight = Arc::new(AtomicUsize::new(0));
        self.listener
            .set_nonblocking(true)
            .context("failed to make the HTTP listener non-blocking")?;

        while running.load(Ordering::SeqCst) {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(error) => return Err(anyhow!("the HTTP listener stopped: {error}")),
            };

            if in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
                in_flight.fetch_sub(1, Ordering::SeqCst);
                let _ = write_unavailable(stream);
                continue;
            }

            let hub = Arc::clone(&hub);
            let options = options.clone();
            let policy = Arc::clone(&policy);
            let limiter = Arc::clone(&limiter);
            let in_flight = Arc::clone(&in_flight);
            std::thread::spawn(move || {
                let _guard = InFlight(in_flight);
                if let Err(error) =
                    serve_connection(stream, &hub, &options, &policy, &limiter, port)
                {
                    errln!("warning: failed to answer an HTTP request: {error}");
                }
            });
        }

        Ok(())
    }
}

/// Decrements the in-flight counter however the connection ends.
struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A connection that is open but has not sent a complete request yet.
struct DeadlineStream {
    stream: TcpStream,
    read_deadline: Instant,
    write_timeout: Duration,
}

impl DeadlineStream {
    fn new(stream: TcpStream, read_deadline: Instant) -> Self {
        Self {
            stream,
            read_deadline,
            write_timeout: RESPONSE_TIMEOUT,
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.read_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request deadline exceeded",
            ));
        }
        self.stream
            .set_read_timeout(Some(remaining.min(REQUEST_TIMEOUT)))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.write_timeout))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// A connection error that should become an HTTP error response.
struct RequestError {
    status: u16,
    message: String,
}

impl RequestError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn io(error: std::io::Error) -> Self {
        let status = if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            408
        } else {
            400
        };
        Self::new(status, format!("could not read the request: {error}"))
    }
}

/// One parsed HTTP request.
struct Request {
    method: Method,
    url: String,
    headers: Vec<Header>,
    body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Options,
    Delete,
    Other(String),
}

impl Method {
    fn parse(value: &str) -> Self {
        match value {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "OPTIONS" => Self::Options,
            "DELETE" => Self::Delete,
            other => Self::Other(other.to_string()),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Options => "OPTIONS",
            Self::Delete => "DELETE",
            Self::Other(other) => other,
        }
    }
}

#[derive(Clone, Debug)]
struct Header {
    name: String,
    value: String,
}

impl Header {
    fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

/// One response, written by `write_response`.
struct Response {
    status: u16,
    reason: &'static str,
    headers: Vec<Header>,
    body: Vec<u8>,
}

impl Response {
    fn new(status: u16, reason: &'static str, headers: Vec<Header>, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            headers,
            body,
        }
    }

    fn json(status: u16, reason: &'static str, value: &Value, mut headers: Vec<Header>) -> Self {
        headers.push(Header::new("Content-Type", "application/json"));
        Self::new(status, reason, headers, value.to_string().into_bytes())
    }
}

/// Read one request. `Ok(None)` means the client closed the connection cleanly.
fn read_request(reader: &mut BufReader<DeadlineStream>) -> Result<Option<Request>, RequestError> {
    let Some(line) = read_line_limited(reader, MAX_REQUEST_LINE)? else {
        return Ok(None);
    };
    if line.is_empty() {
        return Err(RequestError::new(400, "empty request line"));
    }

    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| RequestError::new(400, "malformed request line"))?;
    let url = parts
        .next()
        .ok_or_else(|| RequestError::new(400, "malformed request line"))?;
    let version = parts
        .next()
        .ok_or_else(|| RequestError::new(400, "malformed request line"))?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(RequestError::new(400, "malformed request line"));
    }

    let mut headers = Vec::new();
    let mut header_bytes = 0usize;
    loop {
        let Some(line) = read_line_limited(reader, MAX_REQUEST_LINE)? else {
            return Err(RequestError::new(
                400,
                "the request ended before its headers",
            ));
        };
        header_bytes = header_bytes.saturating_add(line.len() + 2);
        if header_bytes > MAX_HEADER_BYTES {
            return Err(RequestError::new(431, "the request headers are too large"));
        }
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(RequestError::new(431, "too many request headers"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| RequestError::new(400, "malformed header"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(RequestError::new(400, "malformed header"));
        }
        headers.push(Header::new(name, value.trim()));
    }

    let mut content_length: Option<usize> = None;
    for header in &headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let value = header
                .value
                .parse::<usize>()
                .map_err(|_| RequestError::new(400, "invalid Content-Length"))?;
            if let Some(previous) = content_length
                && previous != value
            {
                return Err(RequestError::new(400, "conflicting Content-Length headers"));
            }
            content_length = Some(value);
        }
    }

    let transfer_encoding = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|header| header.value.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(",");
    let chunked = transfer_encoding
        .split(',')
        .any(|encoding| encoding.trim() == "chunked");
    if !transfer_encoding.is_empty() && !chunked {
        return Err(RequestError::new(
            501,
            "only Transfer-Encoding: chunked is supported",
        ));
    }
    if chunked && content_length.is_some() {
        return Err(RequestError::new(
            400,
            "Content-Length and Transfer-Encoding cannot be combined",
        ));
    }

    let expects_continue = headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("expect")
            && header.value.eq_ignore_ascii_case("100-continue")
    });
    if expects_continue {
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(RequestError::io)?;
        reader.get_mut().flush().map_err(RequestError::io)?;
    }

    let body = if chunked {
        read_chunked(reader)?
    } else if let Some(length) = content_length {
        if length > MAX_BODY_BYTES {
            return Err(RequestError::new(413, "request body is too large"));
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).map_err(RequestError::io)?;
        body
    } else {
        Vec::new()
    };

    Ok(Some(Request {
        method: Method::parse(method),
        url: url.to_string(),
        headers,
        body,
    }))
}

/// Read one CRLF-terminated line, refusing a line that is longer than `max`.
fn read_line_limited<R: BufRead>(
    reader: &mut R,
    max: usize,
) -> Result<Option<String>, RequestError> {
    let mut line = Vec::new();
    let read = reader
        .by_ref()
        .take(max as u64)
        .read_until(b'\n', &mut line)
        .map_err(RequestError::io)?;
    if read == 0 {
        return Ok(None);
    }
    if line.len() >= max && !line.ends_with(b"\n") {
        return Err(RequestError::new(
            431,
            "the request line or a header is too long",
        ));
    }
    Ok(Some(
        String::from_utf8_lossy(&line)
            .trim_end_matches(['\r', '\n'])
            .to_string(),
    ))
}

/// Decode a chunked body, capped at `MAX_BODY_BYTES`.
fn read_chunked<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, RequestError> {
    let mut body = Vec::new();
    let mut trailer_bytes = 0usize;
    loop {
        let Some(line) = read_line_limited(reader, MAX_REQUEST_LINE)? else {
            return Err(RequestError::new(400, "the chunked body ended early"));
        };
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| RequestError::new(400, "invalid chunk size"))?;
        if size == 0 {
            loop {
                let Some(line) = read_line_limited(reader, MAX_REQUEST_LINE)? else {
                    return Err(RequestError::new(400, "the chunked body ended early"));
                };
                trailer_bytes = trailer_bytes.saturating_add(line.len() + 2);
                if trailer_bytes > MAX_HEADER_BYTES {
                    return Err(RequestError::new(431, "the request trailers are too large"));
                }
                if line.is_empty() {
                    return Ok(body);
                }
            }
        }
        if size > MAX_BODY_BYTES || body.len() > MAX_BODY_BYTES - size {
            return Err(RequestError::new(413, "request body is too large"));
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).map_err(RequestError::io)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).map_err(RequestError::io)?;
        if &crlf != b"\r\n" {
            return Err(RequestError::new(400, "malformed chunk"));
        }
    }
}

/// Serve one accepted connection. The transport is stateless, so one request per
/// connection is enough; closing it also makes the thread lifetime bounded.
fn serve_connection(
    stream: TcpStream,
    hub: &Hub,
    options: &HttpOptions,
    policy: &OriginPolicy,
    limiter: &AuthLimiter,
    port: u16,
) -> Result<()> {
    let _ = stream.set_nonblocking(false);
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let mut reader = BufReader::new(DeadlineStream::new(stream, deadline));

    let request = match read_request(&mut reader) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            let response = Response::json(
                error.status,
                reason(error.status),
                &rpc_error_body(errors::INVALID_REQUEST, &error.message),
                Vec::new(),
            );
            write_response(reader.get_mut(), &response)?;
            return Ok(());
        }
    };

    let response = handle(&request, hub, options, policy, limiter, port);
    write_response(reader.get_mut(), &response)?;
    Ok(())
}

/// Answer one request.
fn handle(
    request: &Request,
    hub: &Hub,
    options: &HttpOptions,
    policy: &OriginPolicy,
    limiter: &AuthLimiter,
    port: u16,
) -> Response {
    let origin = header_value(&request.headers, "origin");
    let host = header_value(&request.headers, "host");
    let cors = cors_headers(policy, origin.as_deref(), host.as_deref());
    let allowed = policy.allows(origin.as_deref());

    if options.verbose {
        // The query string can carry a token even though mcp-ctl does not use one; do
        // not copy it into a log that may be shared.
        let path = request.url.split('?').next().unwrap_or(&request.url);
        outln!("\n--> {} {path}", request.method.as_str());
        for header in &request.headers {
            let value = if is_sensitive(&header.name) {
                "<redacted>"
            } else {
                &header.value
            };
            outln!("    {}: {value}", header.name);
        }
    }

    if !allowed {
        return Response::json(
            403,
            "Forbidden",
            &rpc_error_body(
                errors::INVALID_REQUEST,
                "this origin is not allowed to call mcp-ctl; add it to server.allowed_origins",
            ),
            Vec::new(),
        );
    }

    let path = request.url.split('?').next().unwrap_or_default();

    // A bearer token guards the hub, but never the CORS preflight, the health probe
    // or the OAuth discovery documents: browsers cannot send Authorization on a
    // preflight, and probes should not need a secret.
    let public = matches!(&request.method, Method::Options)
        || path == "/healthz"
        || path.starts_with("/.well-known/oauth-protected-resource");
    if let Some(expected) = &options.bearer_token
        && !public
        && !bearer_matches(
            header_value(&request.headers, "authorization").as_deref(),
            expected,
        )
    {
        limiter.record_failure();
        if !limiter.allows() {
            return Response::json(
                429,
                "Too Many Requests",
                &rpc_error_body(
                    errors::INVALID_REQUEST,
                    "too many failed authentication attempts; retry later",
                ),
                with_retry_after(cors),
            );
        }
        return Response::json(
            401,
            "Unauthorized",
            &rpc_error_body(errors::INVALID_REQUEST, "missing or invalid bearer token"),
            with_challenge(cors),
        );
    }

    match (&request.method, path) {
        (&Method::Options, _) => Response::new(204, "No Content", cors, Vec::new()),
        (&Method::Get, "/healthz") => Response::new(200, "OK", Vec::new(), b"ok".to_vec()),
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
            Response::json(200, "OK", &body, cors)
        }
        (&Method::Post, "/mcp") => post(request, hub, options, cors),
        (&Method::Get, "/mcp") | (&Method::Delete, "/mcp") => Response::json(
            405,
            "Method Not Allowed",
            &rpc_error_body(
                errors::INVALID_REQUEST,
                "mcp-ctl is stateless: POST /mcp is the only supported method (the GET stream and DELETE session endpoints are not implemented)",
            ),
            with_allow(cors, "POST"),
        ),
        _ => Response::json(
            404,
            "Not Found",
            &rpc_error_body(errors::INVALID_REQUEST, "unknown endpoint"),
            cors,
        ),
    }
}

/// Handle `POST /mcp`.
fn post(request: &Request, hub: &Hub, options: &HttpOptions, cors: Vec<Header>) -> Response {
    let started = Instant::now();

    // The negotiated revision is echoed in this header by 2025-06-18 clients; an
    // unknown revision means we cannot serve the request correctly.
    if let Some(version) = header_value(&request.headers, "mcp-protocol-version")
        && !protocol_version_supported(&version)
    {
        return Response::json(
            400,
            "Bad Request",
            &rpc_error_body(
                errors::INVALID_REQUEST,
                &format!("unsupported MCP-Protocol-Version '{version}'"),
            ),
            cors,
        );
    }

    if let Some(content_type) = header_value(&request.headers, "content-type")
        && !content_type
            .to_ascii_lowercase()
            .starts_with("application/json")
    {
        return Response::json(
            415,
            "Unsupported Media Type",
            &rpc_error_body(
                errors::INVALID_REQUEST,
                "Content-Type must be application/json",
            ),
            cors,
        );
    }

    let message: Value = match serde_json::from_slice(&request.body) {
        Ok(message) => message,
        Err(error) => {
            return Response::json(
                400,
                "Bad Request",
                &rpc_error_body(errors::PARSE_ERROR, &format!("invalid JSON: {error}")),
                cors,
            );
        }
    };

    // Batching was removed from the protocol in 2025-06-18; say so instead of
    // answering half of it.
    if message.is_array() {
        return Response::json(
            400,
            "Bad Request",
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
        None => Response::new(202, "Accepted", cors, Vec::new()),
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
            Response::json(200, "OK", &response, cors)
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn write_response(stream: &mut DeadlineStream, response: &Response) -> Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, response.reason);
    for header in &response.headers {
        // Defence in depth: a reflected value (the allowed Origin, today) must never be
        // able to inject a second header or a bare CR into the response.
        if header.name.contains(['\r', '\n']) || header.value.contains(['\r', '\n']) {
            continue;
        }
        head.push_str(&header.name);
        head.push_str(": ");
        head.push_str(&header.value);
        head.push_str("\r\n");
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    ));
    stream
        .write_all(head.as_bytes())
        .context("failed to write the response head")?;
    stream
        .write_all(&response.body)
        .context("failed to write the response body")?;
    stream.flush().context("failed to flush the response")?;
    let _ = stream.stream.shutdown(Shutdown::Both);
    Ok(())
}

/// Answer a connection with 503 when every handler is busy. Runs on the accept thread,
/// so it uses a short write timeout and no allocation beyond the fixed response.
fn write_unavailable(mut stream: TcpStream) -> Result<()> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    stream
        .write_all(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\
              Connection: close\r\nRetry-After: 1\r\n\r\n",
        )
        .context("failed to write the busy response")?;
    stream
        .flush()
        .context("failed to flush the busy response")?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
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
/// The scheme is part of the comparison for the public host, whatever port the origin
/// names: an insecure page cannot ride on an `https://` external_url.
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
        if !self.own_hosts.contains(&host_only(&parsed.host)) {
            return false;
        }
        // When `external_url` names this host, it pins the scheme for every port. The
        // port itself is deliberately not compared (the MCP Inspector on
        // `localhost:6274` is a useful caller), but `http://host:9999` must not ride on
        // an `https://host` public URL.
        if let Some(public) = &self.public_origin
            && host_only(&public.host).eq_ignore_ascii_case(&host_only(&parsed.host))
        {
            return public.scheme == parsed.scheme;
        }
        true
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
        Header::new("Access-Control-Allow-Origin", origin),
        Header::new("Vary", "Origin"),
        Header::new("Access-Control-Allow-Methods", "POST, OPTIONS"),
        // Authorization is what browser-based clients (MCP Inspector and web
        // agents) send; without it the preflight fails before the request exists.
        Header::new(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, MCP-Protocol-Version",
        ),
    ]
}

fn with_allow(mut headers: Vec<Header>, methods: &str) -> Vec<Header> {
    headers.push(Header::new("Allow", methods));
    headers
}

fn with_challenge(mut headers: Vec<Header>) -> Vec<Header> {
    headers.push(Header::new("WWW-Authenticate", "Bearer realm=\"mcp-ctl\""));
    headers
}

fn with_retry_after(mut headers: Vec<Header>) -> Vec<Header> {
    headers.push(Header::new("Retry-After", "60"));
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

/// The first value a client sent for a header, verbatim.
fn header_value(headers: &[Header], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.clone())
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
        || [
            "auth",
            "token",
            "secret",
            "password",
            "signature",
            "credential",
            "api-key",
            "apikey",
        ]
        .iter()
        .any(|needle| name.contains(needle))
}

/// A JSON-RPC error body for failures that happen before a request id exists.
fn rpc_error_body(code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": null, "error": { "code": code, "message": message } })
}

/// Limits failed bearer attempts so a short user-chosen token is not trivially
/// brute-forced. A correct token is checked before the limiter, so a legitimate client
/// still gets through while an attacker is being throttled.
struct AuthLimiter {
    window: Mutex<AuthWindow>,
}

struct AuthWindow {
    started: Instant,
    failures: u64,
}

impl AuthLimiter {
    fn new() -> Self {
        Self {
            window: Mutex::new(AuthWindow {
                started: Instant::now(),
                failures: 0,
            }),
        }
    }

    fn record_failure(&self) {
        if let Ok(mut window) = self.window.lock() {
            if window.started.elapsed() >= AUTH_WINDOW {
                *window = AuthWindow {
                    started: Instant::now(),
                    failures: 0,
                };
            }
            window.failures = window.failures.saturating_add(1);
        }
    }

    fn allows(&self) -> bool {
        self.window
            .lock()
            .map(|window| {
                window.started.elapsed() >= AUTH_WINDOW || window.failures < MAX_FAILED_AUTH
            })
            .unwrap_or(true)
    }
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
        assert!(policy.allows(Some("https://laptop.example.ts.net:9999")));
        // Same host, insecure scheme: a different origin, and not the public one.
        assert!(!policy.allows(Some("http://laptop.example.ts.net")));
        assert!(!policy.allows(Some("http://laptop.example.ts.net:9999")));
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
            .find(|header| header.name == "Access-Control-Allow-Headers")
            .map(|header| header.value.clone())
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
        assert!(is_sensitive("X-Auth-Token"));
        assert!(is_sensitive("Private-Token"));
        assert!(is_sensitive("X-Goog-Api-Key"));
        assert!(!is_sensitive("Content-Type"));
        assert!(!is_sensitive("MCP-Protocol-Version"));
    }

    #[test]
    fn failed_bearer_attempts_are_limited() {
        let limiter = AuthLimiter::new();
        for _ in 0..MAX_FAILED_AUTH {
            limiter.record_failure();
        }
        assert!(!limiter.allows());
    }
}
