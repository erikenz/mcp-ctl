//! An OAuth 2.1 client for remote MCP servers.
//!
//! A remote MCP server that answers `401 Unauthorized` advertises where to
//! authenticate: the `WWW-Authenticate` header points at a Protected Resource
//! Metadata document ([RFC 9728]), that document names the authorization server, and
//! the authorization server's metadata ([RFC 8414]) names its endpoints. This module
//! follows exactly that chain, registers a client with Dynamic Client Registration
//! ([RFC 7591]) unless a `client_id` is configured, runs the authorization code flow
//! with PKCE ([RFC 7636]) and the `resource` parameter ([RFC 8707]), and keeps the
//! resulting tokens in the state directory.
//!
//! [RFC 9728]: https://www.rfc-editor.org/rfc/rfc9728
//! [RFC 8414]: https://www.rfc-editor.org/rfc/rfc8414
//! [RFC 7591]: https://www.rfc-editor.org/rfc/rfc7591
//! [RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
//! [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
//!
//! The redirect URI is a loopback listener started for the duration of the login, so
//! signing in never requires the hub, the machine or the profile to be reachable from
//! the internet: the browser posts the code to `127.0.0.1` on this machine.
//!
//! Tokens are bearer credentials. They are stored owner-only, redacted in `Debug`,
//! and never logged.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::Paths;
use crate::platform;

/// Path the authorization server redirects the browser back to.
pub const CALLBACK_PATH: &str = "/callback";

/// How long `auth login` waits for the browser before giving up.
pub const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// A token this close to expiring is refreshed instead of used.
const EXPIRY_SKEW_SECS: u64 = 60;

/// Bound on one metadata or callback response. These are small documents; anything
/// larger is not something this client should be reading into memory.
const MAX_RESPONSE_BYTES: u64 = 512 * 1024;

/// The MCP revision this client speaks to backends.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// One remote MCP endpoint, split into the pieces discovery needs.
///
/// A tiny parser rather than a dependency: this crate needs the scheme, host, port
/// and path of a URL and nothing else. The original string is what gets called, so
/// query parameters (`?readonly=true`) survive untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

impl Url {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        // Whitespace and control characters are not part of a URI; allowing them would
        // also let a profile file smuggle a second header into a request line.
        if input
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            bail!("'{input}' contains whitespace or a control character");
        }
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| anyhow!("'{input}' is not an absolute URL (it has no scheme)"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            bail!("'{input}' must be http:// or https://");
        }
        // A fragment can never be part of a resource identifier (RFC 8707).
        let rest = rest.split('#').next().unwrap_or_default();
        let (authority, path_and_query) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            bail!("'{input}' has no host");
        }
        if authority.contains('@') {
            bail!("'{input}' carries credentials in the URL; configure them as headers instead");
        }
        let (host, port) = match authority.rsplit_once(':') {
            // A bare IPv6 address in brackets keeps its colons; `[::1]:8080` splits here.
            Some((host, port)) if !host.ends_with(']') || host.starts_with('[') => {
                let port: u16 = port
                    .parse()
                    .with_context(|| format!("'{port}' is not a valid port in '{input}'"))?;
                (host.to_string(), Some(port))
            }
            _ => (authority.to_string(), None),
        };
        let path = path_and_query
            .split('?')
            .next()
            .unwrap_or_default()
            .to_string();
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    /// `scheme://host[:port]`, the part a well-known URL is built on.
    pub fn origin(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{port}", self.scheme, self.host),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }

    /// The canonical URI of this resource, as RFC 8707 defines it: no query, no
    /// fragment, and no trailing slash unless the path is the whole resource.
    pub fn canonical(&self) -> String {
        if self.path.is_empty() || self.path == "/" {
            self.origin()
        } else {
            format!("{}{}", self.origin(), self.path)
        }
    }

    /// The path component, without a trailing slash.
    pub fn path(&self) -> &str {
        self.path.trim_end_matches('/')
    }

    pub fn is_https(&self) -> bool {
        self.scheme == "https"
    }

    pub fn is_loopback(&self) -> bool {
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        host == "127.0.0.1" || host == "::1" || host == "localhost"
    }
}

/// Would a client be allowed to send a bearer token here?
///
/// OAuth 2.1 requires TLS for every endpoint that carries a credential; loopback is
/// the one exception, which is what keeps the fake server in the test suite possible.
fn secure_origin(url: &Url) -> bool {
    url.is_https() || url.is_loopback()
}

/// Standard base64 with padding, which is what HTTP Basic authentication wants
/// (base64url with `-` and `_` is a different encoding and would be rejected).
fn base64_standard(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = *chunk.get(1).unwrap_or(&0) as u32;
        let third = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (first << 16) | (second << 8) | third;
        out.push(TABLE[(bits >> 18) as usize & 63] as char);
        out.push(TABLE[(bits >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(bits >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[bits as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Base64url without padding, as PKCE and client credentials use it.
fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = *chunk.get(1).unwrap_or(&0) as u32;
        let third = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (first << 16) | (second << 8) | third;
        out.push(TABLE[(bits >> 18) as usize & 63] as char);
        out.push(TABLE[(bits >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(bits >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[bits as usize & 63] as char);
        }
    }
    out
}

/// The S256 PKCE challenge for a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    base64url(&Sha256::digest(verifier.as_bytes()))
}

/// A fresh PKCE verifier: 32 random bytes, 43 base64url characters (RFC 7636 §4.1).
fn pkce_verifier() -> Result<String> {
    Ok(base64url(&random_bytes(32)?))
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|error| anyhow!("no randomness available: {error}"))?;
    Ok(bytes)
}

fn random_hex(len: usize) -> Result<String> {
    Ok(random_bytes(len)?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Percent-encode one query or form value.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Percent-decode a query value, including `+` for space.
fn decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Parse an `application/x-www-form-urlencoded`-style query into a map.
fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        params
            .entry(decode_component(key))
            .or_insert_with(|| decode_component(value));
    }
    params
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

/// What is known about one remote server's credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// The resource the token is for: the Protected Resource Metadata `resource`, or
    /// the endpoint itself when the document does not name one.
    pub resource: String,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// `none`, `client_secret_post` or `client_secret_basic`.
    #[serde(default)]
    pub token_auth_method: Option<String>,
    /// The exact redirect URI the client was registered with. A different port means a
    /// different registration, so this is what decides whether the client can be reused.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Loopback port used last time, so a second login reuses the registration.
    #[serde(default)]
    pub redirect_port: Option<u16>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub tokens: Option<Tokens>,
}

impl Entry {
    fn usable_token(&self) -> Option<Tokens> {
        self.tokens.clone().filter(|tokens| !tokens.expired())
    }
}

/// A bearer token and, when the server issues one, its refresh token.
#[derive(Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    /// Unix seconds; `None` means the server did not say, so it is used until it fails.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl Tokens {
    fn expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => now_secs() + EXPIRY_SKEW_SECS >= expires_at,
            None => false,
        }
    }

    fn expiry_note(&self) -> String {
        match self.expires_at {
            Some(expires_at) if expires_at <= now_secs() => "expired".to_string(),
            Some(expires_at) => format!("expires in {}s", expires_at.saturating_sub(now_secs())),
            None => "no expiry reported".to_string(),
        }
    }
}

/// A token must never reach a log through `{:?}`.
impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("token_type", &self.token_type)
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Every stored credential, keyed by the remote endpoint's canonical URI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub servers: BTreeMap<String, Entry>,
}

pub fn store_path(paths: &Paths) -> PathBuf {
    paths.state_dir.join("oauth.json")
}

pub fn load(paths: &Paths) -> Result<Store> {
    let path = store_path(paths);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Store::default()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let store: Store = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} is not a valid token store; delete it and run `mcp-ctl auth login` again",
            path.display()
        )
    })?;
    Ok(store)
}

/// Write the store owner-only, replacing the old file atomically.
fn save(paths: &Paths, store: &Store) -> Result<()> {
    let path = store_path(paths);
    paths.ensure_state_dir()?;
    let mut store = store.clone();
    store.version = 1;
    let bytes = serde_json::to_vec_pretty(&store).context("failed to serialize the token store")?;

    let temporary = path.with_extension("json.tmp");
    {
        let mut file = platform::create_private_file(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.sync_all().ok();
    }
    // Replace rather than rewrite, so a reader never observes a half-written store.
    // Removing first is what `control::write_state` does too: Windows cannot rename
    // onto an existing file.
    let _ = std::fs::remove_file(&path);
    std::fs::rename(&temporary, &path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// The parts of a Protected Resource Metadata document this client uses.
#[derive(Debug, Clone, Deserialize)]
struct ProtectedResource {
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// The parts of an authorization server metadata document this client uses.
#[derive(Debug, Clone, Deserialize)]
struct AuthorizationServer {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    registration_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

struct Fetched {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Fetched {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Result<Value> {
        serde_json::from_str(&self.body).with_context(|| {
            format!(
                "the server did not answer with JSON: {}",
                truncate(&self.body)
            )
        })
    }
}

fn truncate(body: &str) -> String {
    let body = body.trim();
    if body.len() <= 300 {
        return body.to_string();
    }
    format!("{}...", &body[..300])
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        // 401 and 404 are answers here, not failures: the whole discovery flow is
        // built on asking a question and reading the refusal.
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into()
}

fn collect(mut response: ureq::http::Response<ureq::Body>, url: &str) -> Result<Fetched> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let reader = response.body_mut().as_reader();
    let mut bytes = Vec::new();
    reader
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read the response from {url}"))?;
    Ok(Fetched {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    })
}

fn get(agent: &ureq::Agent, url: &str) -> Result<Fetched> {
    let response = agent
        .get(url)
        .header("Accept", "application/json")
        .call()
        .with_context(|| format!("could not reach {url}"))?;
    collect(response, url)
}

fn post_json(agent: &ureq::Agent, url: &str, body: &Value) -> Result<Fetched> {
    let response = agent
        .post(url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .with_context(|| format!("could not reach {url}"))?;
    collect(response, url)
}

/// Extract `resource_metadata` from a `WWW-Authenticate: Bearer ...` challenge.
///
/// Parsed by hand rather than with `split(',')`: RFC 7235 authentication parameters
/// allow a quoted value, and a quoted value may contain commas. Splitting first would
/// truncate a URL like `...?a=1,2` and quietly derive the wrong metadata location.
fn resource_metadata_from_challenge(challenge: &str) -> Option<String> {
    let mut rest = challenge
        .strip_prefix("Bearer ")
        .or_else(|| challenge.strip_prefix("bearer "))?;
    loop {
        rest = rest.trim_start_matches([' ', ',', '\t']);
        if rest.is_empty() {
            return None;
        }
        let (name, after) = rest.split_once('=')?;
        let name = name.trim();
        let after = after.trim_start();

        let (value, tail) = if let Some(stripped) = after.strip_prefix('"') {
            let mut value = String::new();
            let mut tail = "";
            let mut characters = stripped.char_indices();
            while let Some((index, character)) = characters.next() {
                match character {
                    '\\' => {
                        if let Some((_, escaped)) = characters.next() {
                            value.push(escaped);
                        }
                    }
                    '"' => {
                        tail = &stripped[index + 1..];
                        break;
                    }
                    _ => value.push(character),
                }
            }
            (value, tail)
        } else {
            match after.split_once(',') {
                Some((value, tail)) => (value.trim().to_string(), tail),
                None => (after.trim().to_string(), ""),
            }
        };

        if name.eq_ignore_ascii_case("resource_metadata") && !value.is_empty() {
            return Some(value);
        }
        rest = tail;
    }
}

fn protected_resource_candidates(challenge: Option<&str>, endpoint: &Url) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(url) = challenge.and_then(resource_metadata_from_challenge) {
        candidates.push(url);
    }
    // RFC 9728 §3: the well-known segment goes before the resource's path.
    let origin = endpoint.origin();
    if !endpoint.path().is_empty() {
        candidates.push(format!(
            "{origin}/.well-known/oauth-protected-resource{}",
            endpoint.path()
        ));
    }
    candidates.push(format!("{origin}/.well-known/oauth-protected-resource"));
    candidates.dedup();
    candidates
}

/// What discovery found: where to authenticate, and for which resource.
struct Discovery {
    resource: String,
    server: AuthorizationServer,
}

/// Ask the MCP endpoint what it wants, then follow its metadata chain.
///
/// `makes_requests` is false for a dry run (`check`), which must never touch the
/// network; the caller can only use the entry it already has in that case.
fn discover(agent: &ureq::Agent, endpoint_url: &str) -> Result<Discovery> {
    let endpoint = Url::parse(endpoint_url)?;

    // The probe is the request a client would make anyway: an unauthenticated
    // `initialize`. A conforming server answers 401 with the metadata URL.
    let probe = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "mcp-ctl", "version": env!("CARGO_PKG_VERSION") }
        }
    });
    let request = agent
        .post(endpoint_url)
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json");
    let response = request
        .send(probe.to_string())
        .with_context(|| format!("could not reach {endpoint_url}"))?;
    let response = collect(response, endpoint_url)?;
    if response.status == 200 {
        bail!(
            "'{endpoint_url}' answered without authentication, so there is nothing to sign in to"
        );
    }
    if response.status != 401 {
        bail!(
            "'{endpoint_url}' answered {} instead of 401, so no sign-in flow can start{}",
            response.status,
            response
                .header("www-authenticate")
                .map(|challenge| format!(" (WWW-Authenticate: {challenge})"))
                .unwrap_or_default()
        );
    }

    let candidates = protected_resource_candidates(response.header("www-authenticate"), &endpoint);
    let mut tried = Vec::new();
    for candidate in &candidates {
        let fetched = get(agent, candidate)?;
        tried.push(format!("{candidate} ({})", fetched.status));
        if fetched.status != 200 {
            continue;
        }
        let metadata: ProtectedResource =
            serde_json::from_str(&fetched.body).with_context(|| {
                format!("{candidate} is not a Protected Resource Metadata document")
            })?;
        if metadata.authorization_servers.is_empty() {
            bail!("{candidate} names no authorization server");
        }

        // RFC 9728 §3.3: a client must check that the document describes the
        // resource it is trying to reach, or a hostile server could point this
        // client's token at someone else's resource.
        let resource = metadata
            .resource
            .clone()
            .unwrap_or_else(|| endpoint.canonical());
        let resource_url = Url::parse(&resource)
            .with_context(|| format!("{candidate} names an invalid resource '{resource}'"))?;
        if resource_url.origin() != endpoint.origin() {
            bail!(
                "{candidate} describes '{resource}', which is not the server being contacted \
                 ('{endpoint_url}'); refusing to request a token for it"
            );
        }

        let server_url = metadata
            .authorization_servers
            .iter()
            .map(|url| Url::parse(url).map(|parsed| (url.clone(), parsed)))
            .collect::<Result<Vec<_>>>()?;
        let (server_url, parsed) = server_url
            .into_iter()
            .find(|(_, parsed)| secure_origin(parsed))
            .ok_or_else(|| {
                anyhow!(
                    "{candidate} advertises no HTTPS authorization server: {}",
                    metadata.authorization_servers.join(", ")
                )
            })?;

        let server = authorization_metadata(agent, &server_url, &parsed)?;
        return Ok(Discovery { resource, server });
    }

    bail!(
        "could not find Protected Resource Metadata for '{endpoint_url}' (tried {})",
        tried.join(", ")
    )
}

/// Fetch the authorization server's metadata ([RFC 8414]), with the OIDC path as a
/// fallback because not every provider publishes both.
fn authorization_metadata(
    agent: &ureq::Agent,
    issuer_url: &str,
    issuer: &Url,
) -> Result<AuthorizationServer> {
    let path = issuer.path();
    let mut candidates = vec![
        format!(
            "{}/.well-known/oauth-authorization-server{path}",
            issuer.origin()
        ),
        format!("{issuer_url}/.well-known/oauth-authorization-server"),
        format!("{}/.well-known/openid-configuration{path}", issuer.origin()),
        format!("{issuer_url}/.well-known/openid-configuration"),
    ];
    candidates.dedup();

    let mut tried = Vec::new();
    for candidate in &candidates {
        let fetched = get(agent, candidate)?;
        tried.push(format!("{candidate} ({})", fetched.status));
        if fetched.status != 200 {
            continue;
        }
        let server: AuthorizationServer = serde_json::from_str(&fetched.body)
            .with_context(|| format!("{candidate} is not authorization server metadata"))?;

        // RFC 8414 §3.3: the issuer in the document must be the one that was asked
        // for. Skipping this check is the mix-up attack the spec warns about.
        if server.issuer.trim_end_matches('/') != issuer_url.trim_end_matches('/') {
            bail!(
                "{candidate} says its issuer is '{}', not '{issuer_url}'; refusing to continue",
                server.issuer
            );
        }
        if !server.code_challenge_methods_supported.is_empty()
            && !server
                .code_challenge_methods_supported
                .iter()
                .any(|method| method.eq_ignore_ascii_case("S256"))
        {
            bail!(
                "'{issuer_url}' does not support PKCE with S256 (it offers {}), which MCP requires",
                server.code_challenge_methods_supported.join(", ")
            );
        }
        let authorization = Url::parse(&server.authorization_endpoint).with_context(|| {
            format!(
                "'{issuer_url}' names an invalid authorization endpoint '{}'",
                server.authorization_endpoint
            )
        })?;
        let token = Url::parse(&server.token_endpoint).with_context(|| {
            format!(
                "'{issuer_url}' names an invalid token endpoint '{}'",
                server.token_endpoint
            )
        })?;
        if !secure_origin(&authorization) || !secure_origin(&token) {
            bail!("'{issuer_url}' serves its OAuth endpoints without HTTPS");
        }
        return Ok(server);
    }

    bail!(
        "could not read metadata for authorization server '{issuer_url}' (tried {})",
        tried.join(", ")
    )
}

// ---------------------------------------------------------------------------
// Registration and the authorization flow
// ---------------------------------------------------------------------------

struct Registration {
    client_id: String,
    client_secret: Option<String>,
}

fn register(
    agent: &ureq::Agent,
    server: &AuthorizationServer,
    redirect_uri: &str,
    scopes: &[String],
) -> Result<Registration> {
    let endpoint = server.registration_endpoint.as_deref().ok_or_else(|| {
        anyhow!(
            "'{}' does not offer dynamic client registration; set \"client_id\" (and \
             \"client_secret\" if the provider issues one) for this server",
            server.issuer
        )
    })?;
    if !server.token_endpoint_auth_methods_supported.is_empty()
        && !server
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|method| method == "none")
    {
        errln!(
            "warning: '{}' does not list 'none' as a token endpoint auth method; \
             registering as a public client anyway",
            server.issuer
        );
    }

    let mut body = json!({
        "client_name": "mcp-ctl",
        "client_uri": "https://github.com/erikenz/mcp-ctl",
        "software_id": "mcp-ctl",
        "software_version": env!("CARGO_PKG_VERSION"),
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    });
    if !scopes.is_empty()
        && let Some(object) = body.as_object_mut()
    {
        object.insert("scope".to_string(), json!(scopes.join(" ")));
    }

    let fetched = post_json(agent, endpoint, &body)?;
    if fetched.status != 200 && fetched.status != 201 {
        bail!(
            "client registration at '{endpoint}' failed with {}: {}",
            fetched.status,
            truncate(&fetched.body)
        );
    }
    let value = fetched.json()?;
    let client_id = value
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("'{endpoint}' returned a registration without a client_id"))?;
    Ok(Registration {
        client_id: client_id.to_string(),
        client_secret: value
            .get("client_secret")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientAuth {
    None,
    Post,
    Basic,
}

impl ClientAuth {
    fn from_method(method: &str) -> Self {
        match method {
            "client_secret_basic" => Self::Basic,
            "client_secret_post" => Self::Post,
            _ => Self::None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Post => "client_secret_post",
            Self::Basic => "client_secret_basic",
        }
    }
}

/// Pick the client authentication method to use for a confidential client.
///
/// Servers that say nothing get the form parameter, which is what most of them take;
/// a server that only advertises HTTP Basic gets that, because sending the secret the
/// wrong way is an `invalid_client` the user cannot diagnose.
fn choose_client_auth(server: &AuthorizationServer, has_secret: bool) -> ClientAuth {
    if !has_secret {
        return ClientAuth::None;
    }
    let supported = &server.token_endpoint_auth_methods_supported;
    if supported
        .iter()
        .any(|method| method == "client_secret_post")
    {
        return ClientAuth::Post;
    }
    if supported
        .iter()
        .any(|method| method == "client_secret_basic")
    {
        return ClientAuth::Basic;
    }
    ClientAuth::Post
}

struct TokenRequest<'a> {
    grant_type: &'a str,
    /// How the client authenticates: `none`, `client_secret_post` or
    /// `client_secret_basic`, chosen from what the server advertises.
    client_auth: ClientAuth,
    code: Option<&'a str>,
    verifier: Option<&'a str>,
    refresh_token: Option<&'a str>,
    redirect_uri: Option<&'a str>,
    resource: &'a str,
    client_id: &'a str,
    client_secret: Option<&'a str>,
}

fn token_request(agent: &ureq::Agent, endpoint: &str, parts: &TokenRequest<'_>) -> Result<Tokens> {
    let mut form = vec![
        ("grant_type", parts.grant_type.to_string()),
        ("client_id", parts.client_id.to_string()),
        ("resource", parts.resource.to_string()),
    ];
    if let Some(code) = parts.code {
        form.push(("code", code.to_string()));
    }
    if let Some(verifier) = parts.verifier {
        form.push(("code_verifier", verifier.to_string()));
    }
    if let Some(refresh_token) = parts.refresh_token {
        form.push(("refresh_token", refresh_token.to_string()));
    }
    if let Some(redirect_uri) = parts.redirect_uri {
        form.push(("redirect_uri", redirect_uri.to_string()));
    }
    // Basic carries the secret in a header; posting it too would be a duplicate.
    if parts.client_auth == ClientAuth::Post
        && let Some(secret) = parts.client_secret
    {
        form.push(("client_secret", secret.to_string()));
    }
    let body = form
        .iter()
        .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
        .collect::<Vec<_>>()
        .join("&");

    let mut request = agent
        .post(endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded");
    if parts.client_auth == ClientAuth::Basic
        && let Some(secret) = parts.client_secret
    {
        // RFC 6749 §2.3.1: both halves are form-encoded before being base64'd.
        let credentials = format!(
            "{}:{}",
            encode_component(parts.client_id),
            encode_component(secret)
        );
        request = request.header(
            "Authorization",
            format!("Basic {}", base64_standard(credentials.as_bytes())),
        );
    }
    let fetched = request
        .send(body)
        .with_context(|| format!("could not reach {endpoint}"))
        .and_then(|response| collect(response, endpoint))?;
    let value = fetched.json().unwrap_or(Value::Null);
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        let description = value
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return Err(anyhow!(
            "the token request was refused: {error}{}{}",
            if description.is_empty() { "" } else { ": " },
            description
        ));
    }
    if fetched.status != 200 {
        bail!(
            "the token endpoint answered {}: {}",
            fetched.status,
            truncate(&fetched.body)
        );
    }

    let access_token = value
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the token endpoint returned no access_token"))?;
    let expires_in = value.get("expires_in").and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
    });
    Ok(Tokens {
        access_token: access_token.to_string(),
        refresh_token: value
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::to_string),
        token_type: value
            .get("token_type")
            .and_then(Value::as_str)
            .map(str::to_string),
        scope: value
            .get("scope")
            .and_then(Value::as_str)
            .map(str::to_string),
        expires_at: expires_in.map(|seconds| now_secs().saturating_add(seconds)),
    })
}

/// Everything `auth login` needs from the profile.
pub struct LoginRequest<'a> {
    pub name: &'a str,
    pub url: &'a str,
    pub scopes: &'a [String],
    pub client_id: Option<&'a str>,
    /// Resolved already; a literal would be a secret in the profile file.
    pub client_secret: Option<String>,
    pub open_browser: bool,
    pub timeout: Duration,
}

/// Sign in to one remote server and store the tokens.
pub fn login(paths: &Paths, request: &LoginRequest<'_>) -> Result<()> {
    let endpoint = Url::parse(request.url)?;
    if !secure_origin(&endpoint) {
        bail!(
            "'{}' must be https:// (or loopback for testing) before a token can be sent to it",
            request.url
        );
    }

    let agent = agent();
    outln!(
        "Discovering how '{}' wants to be authenticated...",
        request.name
    );
    let discovery = discover(&agent, request.url)?;
    let server = &discovery.server;
    outln!(
        "  resource: {}\n  authorization server: {}",
        discovery.resource,
        server.issuer
    );

    let mut store = load(paths)?;
    let key = endpoint.canonical();
    let previous = store.servers.get(&key).cloned();

    // Bind the listener first: the redirect URI carries a port, and that exact URI is
    // what gets registered. The previous port is tried first so a second login can
    // reuse the client it already registered.
    let (listener, port) = bind_callback(previous.as_ref().and_then(|entry| entry.redirect_port))?;
    let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");

    // Only what the profile asks for: the server's `scopes_supported` is what it *can*
    // issue, not what this client needs, and requesting all of it buries the user in a
    // consent screen listing every scope the product has.
    let scopes = request.scopes.to_vec();
    if !scopes.is_empty() && !server.scopes_supported.is_empty() {
        let unknown: Vec<&str> = scopes
            .iter()
            .map(String::as_str)
            .filter(|scope| !server.scopes_supported.iter().any(|known| known == scope))
            .collect();
        if !unknown.is_empty() {
            errln!(
                "warning: '{}' does not advertise scope(s) {}; it may refuse the request",
                server.issuer,
                unknown.join(", ")
            );
        }
    }

    let registration = match (request.client_id, &previous) {
        (Some(client_id), _) => Registration {
            client_id: client_id.to_string(),
            client_secret: request.client_secret.clone(),
        },
        (None, Some(previous))
            if previous.redirect_uri.as_deref() == Some(redirect_uri.as_str())
                && previous.client_id.is_some() =>
        {
            Registration {
                client_id: previous.client_id.clone().unwrap_or_default(),
                client_secret: previous.client_secret.clone(),
            }
        }
        (None, _) => {
            outln!("  register: {}", server.issuer);
            let registration = register(&agent, server, &redirect_uri, request.scopes)?;
            outln!("  client: {}", registration.client_id);
            registration
        }
    };

    let client_auth = choose_client_auth(server, registration.client_secret.is_some());

    // Keep the registration even if the browser step never finishes: the next attempt
    // then reuses this client and this loopback port instead of registering again.
    let remember = |store: &mut Store, tokens: Option<Tokens>, scopes: &[String]| {
        store.servers.insert(
            key.clone(),
            Entry {
                resource: discovery.resource.clone(),
                issuer: Some(server.issuer.clone()),
                token_endpoint: Some(server.token_endpoint.clone()),
                client_id: Some(registration.client_id.clone()),
                client_secret: registration.client_secret.clone(),
                token_auth_method: Some(client_auth.as_str().to_string()),
                redirect_uri: Some(redirect_uri.clone()),
                redirect_port: Some(port),
                scopes: scopes.to_vec(),
                tokens,
            },
        );
    };
    remember(&mut store, None, &scopes);
    save(paths, &store)?;

    let verifier = pkce_verifier()?;
    let challenge = pkce_challenge(&verifier);
    let state = random_hex(16)?;

    let mut authorization_url = format!("{}?", server.authorization_endpoint);
    let mut query = vec![
        ("response_type", "code".to_string()),
        ("client_id", registration.client_id.clone()),
        ("redirect_uri", redirect_uri.clone()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("state", state.clone()),
        ("resource", discovery.resource.clone()),
    ];
    if !scopes.is_empty() {
        query.push(("scope", scopes.join(" ")));
    }
    authorization_url.push_str(
        &query
            .iter()
            .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
            .collect::<Vec<_>>()
            .join("&"),
    );

    outln!("\nOpen this URL to sign in:\n\n  {authorization_url}\n");
    if request.open_browser
        && let Err(error) = platform::open_url(&authorization_url)
    {
        errln!("warning: could not open a browser ({error}); open the URL above yourself");
    }

    outln!(
        "Waiting for the browser to return to {redirect_uri} ({}s)...",
        request.timeout.as_secs()
    );
    let code = wait_for_callback(&listener, &state, request.timeout)?;

    let tokens = token_request(
        &agent,
        &server.token_endpoint,
        &TokenRequest {
            grant_type: "authorization_code",
            client_auth,
            code: Some(&code),
            verifier: Some(&verifier),
            refresh_token: None,
            redirect_uri: Some(&redirect_uri),
            resource: &discovery.resource,
            client_id: &registration.client_id,
            client_secret: registration.client_secret.as_deref(),
        },
    )
    .context("the authorization code could not be exchanged for a token")?;

    let expires = tokens.expiry_note();
    // Re-read: the browser step can take minutes, and another process may have
    // written the store in the meantime.
    store = load(paths)?;
    remember(&mut store, Some(tokens), &scopes);
    save(paths, &store)?;

    outln!(
        "\n✓ '{}' is signed in ({expires}). Tokens are stored in {}.",
        request.name,
        store_path(paths).display()
    );
    Ok(())
}

/// Bind the loopback callback listener, preferring the port used last time.
fn bind_callback(preferred: Option<u16>) -> Result<(TcpListener, u16)> {
    if let Some(port) = preferred
        && let Ok(listener) = TcpListener::bind(("127.0.0.1", port))
    {
        return Ok((listener, port));
    }
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .context("could not start the loopback listener for the OAuth callback")?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

/// Wait for the browser to post the authorization code back.
///
/// Other requests (a favicon, a speculative connection) are answered and ignored: the
/// browser will not send the code until it has it.
fn wait_for_callback(listener: &TcpListener, state: &str, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    listener.set_nonblocking(true)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(result) = answer_callback(stream, state) {
                    return result;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    bail!(
                        "no OAuth callback arrived within {}s; run `mcp-ctl auth login` again",
                        timeout.as_secs()
                    );
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error).context("the OAuth callback listener failed"),
        }
    }
}

/// Read one request from the browser; `None` means it was not the callback and the
/// caller should keep waiting.
fn answer_callback(mut stream: TcpStream, state: &str) -> Option<Result<String>> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buffer = vec![0u8; 8192];
    let read = stream.read(&mut buffer).ok()?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let line = request.lines().next().unwrap_or_default();
    let target = line.split_whitespace().nth(1).unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    if path != CALLBACK_PATH {
        respond(&mut stream, 404, "Not found", "<h1>Not found</h1>");
        return None;
    }

    let params = parse_query(query);
    if let Some(error) = params.get("error") {
        let description = params
            .get("error_description")
            .map(String::as_str)
            .unwrap_or_default();
        respond(&mut stream, 400, "Sign-in failed", SIGN_IN_FAILED_HTML);
        return Some(Err(anyhow!(
            "the authorization server reported {error}{}{}",
            if description.is_empty() { "" } else { ": " },
            description
        )));
    }
    let Some(code) = params.get("code") else {
        respond(&mut stream, 400, "Sign-in failed", SIGN_IN_FAILED_HTML);
        return Some(Err(anyhow!(
            "the browser returned without an authorization code"
        )));
    };
    // RFC 6749 §10.12 and OAuth 2.1 §7.13: a code that arrives with the wrong state
    // is not the answer to the request this process made.
    if params.get("state").map(String::as_str).unwrap_or_default() != state {
        respond(&mut stream, 400, "Sign-in failed", SIGN_IN_FAILED_HTML);
        return Some(Err(anyhow!(
            "the browser returned the wrong state parameter; refusing the code"
        )));
    }

    respond(&mut stream, 200, "Signed in", SIGNED_IN_HTML);
    Some(Ok(code.clone()))
}

fn respond(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

const SIGNED_IN_HTML: &str = "<!doctype html><meta charset=\"utf-8\">\
<title>mcp-ctl</title><h1>Signed in</h1>\
<p>You can close this window and return to the terminal.</p>";

const SIGN_IN_FAILED_HTML: &str = "<!doctype html><meta charset=\"utf-8\">\
<title>mcp-ctl</title><h1>Sign-in failed</h1>\
<p>Return to the terminal: the reason is printed there.</p>";

// ---------------------------------------------------------------------------
// Using the stored token
// ---------------------------------------------------------------------------

/// Sign-in state of one remote server, for `auth status` and `check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub resource: String,
    pub issuer: Option<String>,
    pub expires_at: Option<u64>,
    pub has_refresh_token: bool,
    pub scope: Option<String>,
}

impl Status {
    pub fn expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => now_secs() + EXPIRY_SKEW_SECS >= expires_at,
            None => false,
        }
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        parts.push(if self.expired() {
            "expired".to_string()
        } else {
            match self.expires_at {
                Some(expires_at) => format!("valid for {}s", expires_at.saturating_sub(now_secs())),
                None => "valid (no expiry reported)".to_string(),
            }
        });
        if self.has_refresh_token && self.expired() {
            parts.push("will refresh on use".to_string());
        }
        if let Some(issuer) = &self.issuer {
            parts.push(format!("issued by {issuer}"));
        }
        if let Some(scope) = &self.scope {
            // A real provider can grant eighty scopes; three plus a count is what a
            // person can read, and `auth status --json` keeps the whole string.
            let granted: Vec<&str> = scope.split_whitespace().collect();
            if granted.len() > 3 {
                parts.push(format!(
                    "scope: {} and {} more",
                    granted[..3].join(" "),
                    granted.len() - 3
                ));
            } else if !granted.is_empty() {
                parts.push(format!("scope: {}", granted.join(" ")));
            }
        }
        parts.join(", ")
    }
}

/// The credentials of one remote server, as the running hub uses them.
///
/// Cheap to construct and safe to call on every request: nothing happens until a
/// token is actually needed. A caller that must not send a stored token simply does
/// not build one.
pub struct Client {
    paths: Paths,
    name: String,
    key: String,
}

impl Client {
    pub fn new(paths: &Paths, name: &str, url: &str) -> Result<Self> {
        Ok(Self {
            paths: paths.clone(),
            name: name.to_string(),
            key: Url::parse(url)?.canonical(),
        })
    }

    pub fn status(&self) -> Result<Option<Status>> {
        let store = load(&self.paths)?;
        let Some(entry) = store.servers.get(&self.key) else {
            return Ok(None);
        };
        let Some(tokens) = &entry.tokens else {
            return Ok(None);
        };
        Ok(Some(Status {
            resource: entry.resource.clone(),
            issuer: entry.issuer.clone(),
            expires_at: tokens.expires_at,
            has_refresh_token: tokens.refresh_token.is_some(),
            scope: tokens.scope.clone(),
        }))
    }

    /// A token to send now, refreshing an expired one when the server issued a
    /// refresh token. `None` means "no credentials stored", never an error: a remote
    /// server that needs no authentication must keep working.
    pub fn token(&self) -> Result<Option<String>> {
        let store = load(&self.paths)?;
        let Some(entry) = store.servers.get(&self.key) else {
            return Ok(None);
        };
        if let Some(tokens) = entry.usable_token() {
            return Ok(Some(tokens.access_token));
        }
        let can_refresh = entry
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.refresh_token.as_ref())
            .is_some();
        if !can_refresh {
            // An expired token with nothing to refresh it with: say so now, rather
            // than sending no credential and turning it into a mystery 401.
            if entry.tokens.is_some() {
                self.invalidate().ok();
                bail!("{}", self.login_hint());
            }
            return Ok(None);
        }
        self.refresh()
    }

    /// Refresh unconditionally, for after a 401.
    pub fn refresh(&self) -> Result<Option<String>> {
        let mut store = load(&self.paths)?;
        let Some(entry) = store.servers.get(&self.key).cloned() else {
            return Ok(None);
        };
        let Some(refresh_token) = entry
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.refresh_token.clone())
        else {
            return Ok(None);
        };
        let (Some(token_endpoint), Some(client_id)) =
            (entry.token_endpoint.clone(), entry.client_id.clone())
        else {
            return Ok(None);
        };

        let client_auth_method = entry
            .token_auth_method
            .clone()
            .unwrap_or_else(|| "client_secret_post".to_string());
        let agent = agent();
        let tokens = token_request(
            &agent,
            &token_endpoint,
            &TokenRequest {
                grant_type: "refresh_token",
                client_auth: ClientAuth::from_method(&client_auth_method),
                code: None,
                verifier: None,
                refresh_token: Some(&refresh_token),
                redirect_uri: None,
                resource: &entry.resource,
                client_id: &client_id,
                client_secret: entry.client_secret.as_deref(),
            },
        )
        .with_context(|| {
            format!(
                "could not refresh the token for '{}'; run `mcp-ctl auth login {}`",
                self.name, self.name
            )
        })?;

        let access_token = tokens.access_token.clone();
        let mut entry = entry;
        // Some servers rotate refresh tokens, some do not; keep the old one when the
        // response omits it rather than losing the ability to refresh.
        let mut tokens = tokens;
        if tokens.refresh_token.is_none() {
            tokens.refresh_token = Some(refresh_token);
        }
        entry.tokens = Some(tokens);
        // Re-read before writing: the network call above gave the daemon or another
        // `mcp-ctl` plenty of time to touch the file, and a blind overwrite would
        // drop its update (a fresh token, usually).
        store = load(&self.paths)?;
        store.servers.insert(self.key.clone(), entry);
        save(&self.paths, &store)?;
        Ok(Some(access_token))
    }

    /// Drop the stored tokens after the server rejected them.
    pub fn invalidate(&self) -> Result<()> {
        let mut store = load(&self.paths)?;
        if let Some(entry) = store.servers.get_mut(&self.key) {
            entry.tokens = None;
            save(&self.paths, &store)?;
        }
        Ok(())
    }

    /// The message a caller shows when a 401 could not be fixed by refreshing.
    pub fn login_hint(&self) -> String {
        format!(
            "server '{}' rejected the request as unauthenticated; run `mcp-ctl auth login {}`",
            self.name, self.name
        )
    }
}

/// Forget a server's tokens, keeping its client registration.
pub fn logout(paths: &Paths, url: &str) -> Result<bool> {
    let key = Url::parse(url)?.canonical();
    let mut store = load(paths)?;
    let Some(entry) = store.servers.get_mut(&key) else {
        return Ok(false);
    };
    let had = entry.tokens.is_some();
    entry.tokens = None;
    save(paths, &store)?;
    Ok(had)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(state: &std::path::Path) -> Paths {
        Paths {
            profile: "default".to_string(),
            config_dir: state.to_path_buf(),
            config_file: state.join("config.json"),
            state_dir: state.join("state"),
            state_file: state.join("state/daemon.json"),
            log_file: state.join("state/mcp-ctl.log"),
            env_file: state.join(".env"),
        }
    }

    #[test]
    fn a_url_is_split_into_the_parts_discovery_needs() {
        let url = Url::parse("https://mcp.example.com/mcp?readonly=true").unwrap();
        assert_eq!(url.origin(), "https://mcp.example.com");
        assert_eq!(url.canonical(), "https://mcp.example.com/mcp");
        assert_eq!(url.path(), "/mcp");
        assert!(url.is_https());
        assert!(!url.is_loopback());

        let loopback = Url::parse("http://127.0.0.1:8080/callback").unwrap();
        assert_eq!(loopback.origin(), "http://127.0.0.1:8080");
        assert!(loopback.is_loopback());
    }

    #[test]
    fn a_root_url_has_no_trailing_slash_in_its_canonical_form() {
        assert_eq!(
            Url::parse("https://example.test/").unwrap().canonical(),
            "https://example.test"
        );
        assert_eq!(
            Url::parse("https://example.test").unwrap().canonical(),
            "https://example.test"
        );
    }

    #[test]
    fn malformed_urls_are_rejected_with_a_reason() {
        assert!(Url::parse("mcp.example.com/mcp").is_err());
        assert!(Url::parse("ftp://example.test").is_err());
        assert!(Url::parse("https://user:pass@example.test/").is_err());
        assert!(Url::parse("https://example.test:notaport/").is_err());
        assert!(Url::parse("https://example.test/a b").is_err());
        assert!(Url::parse("https://example.test/mcp\r\nX-Injected: 1").is_err());
    }

    #[test]
    fn pkce_matches_the_rfc_7636_test_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        // A verifier is 43 characters: 32 random bytes in base64url without padding.
        assert_eq!(pkce_verifier().unwrap().len(), 43);
    }

    #[test]
    fn base64url_has_no_padding_and_uses_the_url_alphabet() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn query_values_round_trip() {
        assert_eq!(encode_component("a b/c?d=e"), "a%20b%2Fc%3Fd%3De");
        assert_eq!(decode_component("a%20b%2Fc"), "a b/c");
        assert_eq!(decode_component("a+b"), "a b");
        let params = parse_query("code=abc&state=de%20f&empty=");
        assert_eq!(params.get("code").unwrap(), "abc");
        assert_eq!(params.get("state").unwrap(), "de f");
        assert_eq!(params.get("empty").unwrap(), "");
    }

    #[test]
    fn a_challenge_with_commas_in_quoted_values_is_parsed_correctly() {
        // RFC 7235 allows commas inside a quoted value, and `error_description` often
        // comes first. Splitting on ',' would cut the URL at the query.
        let challenge = r#"Bearer error="invalid_token", error_description="Token expired, please sign in", resource_metadata="https://auth.example.test/meta?a=1,2""#;
        assert_eq!(
            resource_metadata_from_challenge(challenge).as_deref(),
            Some("https://auth.example.test/meta?a=1,2")
        );

        let unquoted = r#"Bearer realm="mcp", resource_metadata=https://auth.example.test/meta"#;
        assert_eq!(
            resource_metadata_from_challenge(unquoted).as_deref(),
            Some("https://auth.example.test/meta")
        );

        assert!(resource_metadata_from_challenge("Bearer realm=\"mcp-ctl\"").is_none());
        assert!(resource_metadata_from_challenge("Basic abc").is_none());
    }

    #[test]
    fn the_client_auth_method_follows_what_the_server_offers() {
        let server = |methods: &[&str]| AuthorizationServer {
            issuer: "https://auth.example.test".to_string(),
            authorization_endpoint: "https://auth.example.test/authorize".to_string(),
            token_endpoint: "https://auth.example.test/token".to_string(),
            registration_endpoint: None,
            scopes_supported: Vec::new(),
            code_challenge_methods_supported: vec!["S256".to_string()],
            token_endpoint_auth_methods_supported: methods
                .iter()
                .map(|method| method.to_string())
                .collect(),
        };

        assert_eq!(
            choose_client_auth(&server(&["none"]), false),
            ClientAuth::None
        );
        assert_eq!(choose_client_auth(&server(&[]), true), ClientAuth::Post);
        assert_eq!(
            choose_client_auth(&server(&["client_secret_basic"]), true),
            ClientAuth::Basic
        );
        // A server that takes both gets the simpler one.
        assert_eq!(
            choose_client_auth(
                &server(&["client_secret_basic", "client_secret_post"]),
                true
            ),
            ClientAuth::Post
        );
        assert_eq!(
            ClientAuth::from_method("client_secret_basic").as_str(),
            "client_secret_basic"
        );
    }

    #[test]
    fn basic_auth_uses_standard_base64_with_padding() {
        // What `printf 'user:pass' | base64` produces, not base64url.
        assert_eq!(base64_standard(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_standard(b"a"), "YQ==");
        assert_eq!(base64_standard(b"ab"), "YWI=");
        assert_eq!(base64_standard(b"abc"), "YWJj");
    }

    #[test]
    fn the_metadata_url_is_read_from_the_challenge() {
        let challenge = r#"Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp""#;
        assert_eq!(
            resource_metadata_from_challenge(challenge).as_deref(),
            Some("https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
        );
        let candidates = protected_resource_candidates(
            Some(challenge),
            &Url::parse("https://mcp.example.com/mcp").unwrap(),
        );
        assert_eq!(
            candidates[0],
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            candidates.last().unwrap(),
            "https://mcp.example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn a_challenge_without_metadata_falls_back_to_the_well_known_paths() {
        let candidates =
            protected_resource_candidates(None, &Url::parse("https://example.test/mcp").unwrap());
        assert_eq!(
            candidates,
            vec![
                "https://example.test/.well-known/oauth-protected-resource/mcp".to_string(),
                "https://example.test/.well-known/oauth-protected-resource".to_string(),
            ]
        );
        let root =
            protected_resource_candidates(None, &Url::parse("https://example.test").unwrap());
        assert_eq!(
            root,
            vec!["https://example.test/.well-known/oauth-protected-resource".to_string()]
        );
    }

    #[test]
    fn a_token_without_an_expiry_is_never_considered_expired() {
        let tokens = Tokens {
            access_token: "a".to_string(),
            refresh_token: None,
            token_type: None,
            scope: None,
            expires_at: None,
        };
        assert!(!tokens.expired());
        assert_eq!(tokens.expiry_note(), "no expiry reported");
    }

    #[test]
    fn a_token_near_its_expiry_is_refreshed_early() {
        let tokens = Tokens {
            access_token: "a".to_string(),
            refresh_token: Some("r".to_string()),
            token_type: None,
            scope: None,
            expires_at: Some(now_secs() + EXPIRY_SKEW_SECS - 1),
        };
        assert!(tokens.expired());
    }

    #[test]
    fn a_long_granted_scope_list_is_summarised() {
        let status = Status {
            resource: "https://example.test/mcp".to_string(),
            issuer: Some("https://auth.example.test".to_string()),
            expires_at: Some(now_secs() + 3600),
            has_refresh_token: true,
            scope: Some("openid profile email read write admin extra".to_string()),
        };
        let described = status.describe();
        assert!(
            described.contains("scope: openid profile email and 4 more"),
            "{described}"
        );
        assert!(!described.contains("admin"), "{described}");

        let short = Status {
            scope: Some("openid profile".to_string()),
            ..status
        };
        assert!(short.describe().contains("scope: openid profile"));
    }

    #[test]
    fn a_token_never_reaches_debug_output() {
        let tokens = Tokens {
            access_token: "secret-access".to_string(),
            refresh_token: Some("secret-refresh".to_string()),
            token_type: None,
            scope: None,
            expires_at: None,
        };
        let rendered = format!("{tokens:?}");
        assert!(!rendered.contains("secret-access"), "{rendered}");
        assert!(!rendered.contains("secret-refresh"), "{rendered}");
    }

    #[test]
    fn the_store_round_trips_and_is_owner_only() {
        let dir = std::env::temp_dir().join(format!("mcp-ctl-oauth-{}", random_hex(8).unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = paths(&dir);

        let mut store = Store::default();
        store.servers.insert(
            "https://example.test/mcp".to_string(),
            Entry {
                resource: "https://example.test/mcp".to_string(),
                issuer: Some("https://auth.example.test".to_string()),
                token_endpoint: Some("https://auth.example.test/token".to_string()),
                client_id: Some("client-1".to_string()),
                client_secret: None,
                token_auth_method: Some("none".to_string()),
                redirect_uri: Some("http://127.0.0.1:1234/callback".to_string()),
                redirect_port: Some(1234),
                scopes: vec!["read".to_string()],
                tokens: Some(Tokens {
                    access_token: "access".to_string(),
                    refresh_token: Some("refresh".to_string()),
                    token_type: Some("Bearer".to_string()),
                    scope: None,
                    expires_at: Some(now_secs() + 3600),
                }),
            },
        );
        save(&paths, &store).unwrap();

        let loaded = load(&paths).unwrap();
        assert_eq!(loaded.servers.len(), 1);
        let entry = loaded.servers.get("https://example.test/mcp").unwrap();
        assert_eq!(entry.tokens.as_ref().unwrap().access_token, "access");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store_path(&paths))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the token store must be owner-only");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_store_reads_as_empty() {
        let dir = std::env::temp_dir().join(format!("mcp-ctl-oauth-{}", random_hex(8).unwrap()));
        let paths = paths(&dir);
        assert!(load(&paths).unwrap().servers.is_empty());
    }

    #[test]
    fn a_client_without_credentials_reports_none_instead_of_failing() {
        let dir = std::env::temp_dir().join(format!("mcp-ctl-oauth-{}", random_hex(8).unwrap()));
        let paths = paths(&dir);
        let client = Client::new(&paths, "remote", "https://example.test/mcp").unwrap();
        assert!(client.token().unwrap().is_none());
        assert!(client.status().unwrap().is_none());
        assert!(client.refresh().unwrap().is_none());
        assert!(client.login_hint().contains("mcp-ctl auth login remote"));
    }
}
