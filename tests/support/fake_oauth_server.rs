//! A fake OAuth-protected MCP server, for the integration tests.
//!
//! Two listeners in one process:
//!
//! * an authorization server on `/.well-known/oauth-authorization-server`, with
//!   dynamic client registration, the authorization endpoint, and a token endpoint
//!   that verifies PKCE; and
//! * an MCP endpoint on `/mcp` that answers 401 with `resource_metadata` until it is
//!   given a token the authorization server issued.
//!
//! It prints one JSON line with both ports and then serves until it is killed:
//!
//! ```text
//! {"as_port":1234,"mcp_port":5678}
//! ```
//!
//! Flags:
//! ```text
//! --json                 answer MCP requests as application/json instead of SSE
//! --reject-first-token   the first access token stops working after one use, so a
//!                        client must refresh on 401
//! --short-expiry         issue tokens that are already expired, exercising the
//!                        proactive refresh path
//! --static-token <s>     also accept `Authorization: Bearer <s>`, for a profile that
//!                        carries its own credential
//! --redirect             answer POST /mcp with a 307 instead of serving it
//! ```

use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => options.json = true,
            "--reject-first-token" => options.reject_first_token = true,
            "--short-expiry" => options.short_expiry = true,
            "--static-token" => options.static_token = args.next(),
            "--redirect" => options.redirect = true,
            other => {
                eprintln!("fake-oauth-server: unknown flag {other}");
                std::process::exit(2);
            }
        }
    }

    let as_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the authorization server");
    let mcp_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the MCP server");
    let as_port = as_listener.local_addr().unwrap().port();
    let mcp_port = mcp_listener.local_addr().unwrap().port();

    let state = Arc::new(Mutex::new(State {
        as_port,
        mcp_port,
        options,
        next_code: 1,
        codes: HashMap::new(),
        valid_access: HashMap::new(),
        valid_refresh: HashMap::new(),
        issued: 0,
        mcp_requests: 0,
    }));

    println!("{}", json!({"as_port": as_port, "mcp_port": mcp_port}));
    let _ = std::io::stdout().flush();

    {
        let state = Arc::clone(&state);
        thread::spawn(move || serve(as_listener, Role::AuthorizationServer, state));
    }
    serve(mcp_listener, Role::Mcp, state);
}

#[derive(Default)]
struct Options {
    json: bool,
    redirect: bool,
    reject_first_token: bool,
    short_expiry: bool,
    static_token: Option<String>,
}

struct PendingCode {
    challenge: String,
    redirect_uri: String,
    resource: String,
}

struct State {
    as_port: u16,
    mcp_port: u16,
    options: Options,
    next_code: u64,
    /// code -> what the token request has to prove.
    codes: HashMap<String, PendingCode>,
    /// access token -> still valid.
    valid_access: HashMap<String, bool>,
    valid_refresh: HashMap<String, bool>,
    issued: u64,
    mcp_requests: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    AuthorizationServer,
    Mcp,
}

fn serve(listener: TcpListener, role: Role, state: Arc<Mutex<State>>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(error) = handle(stream, role, state) {
                eprintln!("fake-oauth-server: {error}");
            }
        });
    }
}

struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn handle(stream: TcpStream, role: Role, state: Arc<Mutex<State>>) -> std::io::Result<()> {
    let mut stream = stream;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some(request) = read_request(&mut reader)? else {
        return Ok(());
    };

    match role {
        Role::AuthorizationServer => authorization_server(&mut stream, &request, &state)?,
        Role::Mcp => mcp_server(&mut stream, &request, &state)?,
    }
    Ok(())
}

fn read_request(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<Request>> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (target, String::new()),
    };

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(Request {
        method,
        path,
        query,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }))
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, String)],
    body: &str,
) -> std::io::Result<()> {
    let mut response = format!("HTTP/1.1 {status} {reason}\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("Content-Length: {}\r\n", body.len()));
    response.push_str("Connection: close\r\n\r\n");
    response.push_str(body);
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn json_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    value: &Value,
    extra: &[(&str, String)],
) -> std::io::Result<()> {
    let body = value.to_string();
    let mut headers = vec![("Content-Type", "application/json".to_string())];
    headers.extend(extra.iter().cloned());
    respond(stream, status, reason, &headers, &body)
}

fn authorization_server(
    stream: &mut TcpStream,
    request: &Request,
    state: &Arc<Mutex<State>>,
) -> std::io::Result<()> {
    let (as_port, mcp_port) = {
        let state = state.lock().unwrap();
        (state.as_port, state.mcp_port)
    };

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/.well-known/oauth-authorization-server") => json_response(
            stream,
            200,
            "OK",
            &json!({
                "issuer": format!("http://127.0.0.1:{as_port}"),
                "authorization_endpoint": format!("http://127.0.0.1:{as_port}/oauth/authorize"),
                "token_endpoint": format!("http://127.0.0.1:{as_port}/oauth/token"),
                "registration_endpoint": format!("http://127.0.0.1:{as_port}/oauth/register"),
                "scopes_supported": ["read", "write"],
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none"],
                "code_challenge_methods_supported": ["S256"]
            }),
            &[],
        ),
        ("POST", "/oauth/register") => {
            let body: Value = serde_json::from_str(&request.body).unwrap_or(Value::Null);
            let redirect_uris = body
                .get("redirect_uris")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if redirect_uris.is_empty() {
                return json_response(
                    stream,
                    400,
                    "Bad Request",
                    &json!({"error": "invalid_redirect_uri"}),
                    &[],
                );
            }
            json_response(
                stream,
                201,
                "Created",
                &json!({
                    "client_id": "fake-client",
                    "redirect_uris": redirect_uris,
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"]
                }),
                &[],
            )
        }
        ("GET", "/oauth/authorize") => {
            let params = parse_query(&request.query);
            let Some(redirect_uri) = params.get("redirect_uri") else {
                return json_response(
                    stream,
                    400,
                    "Bad Request",
                    &json!({"error": "invalid_request", "error_description": "no redirect_uri"}),
                    &[],
                );
            };
            let Some(challenge) = params.get("code_challenge") else {
                return json_response(
                    stream,
                    400,
                    "Bad Request",
                    &json!({"error": "invalid_request", "error_description": "PKCE is required"}),
                    &[],
                );
            };
            if params.get("code_challenge_method").map(String::as_str) != Some("S256") {
                return json_response(
                    stream,
                    400,
                    "Bad Request",
                    &json!({"error": "invalid_request", "error_description": "S256 is required"}),
                    &[],
                );
            }
            let resource = params
                .get("resource")
                .cloned()
                .unwrap_or_else(|| format!("http://127.0.0.1:{mcp_port}/mcp"));
            let state_param = params.get("state").cloned().unwrap_or_default();
            let code = {
                let mut state = state.lock().unwrap();
                let code = format!("code-{}", state.next_code);
                state.next_code += 1;
                state.codes.insert(
                    code.clone(),
                    PendingCode {
                        challenge: challenge.clone(),
                        redirect_uri: redirect_uri.clone(),
                        resource,
                    },
                );
                code
            };
            let location = format!("{redirect_uri}?code={code}&state={state_param}");
            respond(
                stream,
                302,
                "Found",
                &[("Location", location), ("Connection", "close".to_string())],
                "",
            )
        }
        ("POST", "/oauth/token") => {
            let params = parse_query(&request.body);
            let grant = params
                .get("grant_type")
                .map(String::as_str)
                .unwrap_or_default();
            let mut state = state.lock().unwrap();
            match grant {
                "authorization_code" => {
                    let Some(code) = params.get("code") else {
                        return json_response(
                            stream,
                            400,
                            "Bad Request",
                            &json!({"error": "invalid_request"}),
                            &[],
                        );
                    };
                    let Some(pending) = state.codes.get(code) else {
                        return json_response(
                            stream,
                            400,
                            "Bad Request",
                            &json!({"error": "invalid_grant", "error_description": "unknown code"}),
                            &[],
                        );
                    };
                    let verifier = params.get("code_verifier").cloned().unwrap_or_default();
                    if pkce_challenge(&verifier) != pending.challenge {
                        return json_response(
                            stream,
                            400,
                            "Bad Request",
                            &json!({
                                "error": "invalid_grant",
                                "error_description": "PKCE verification failed"
                            }),
                            &[],
                        );
                    }
                    if params.get("redirect_uri") != Some(&pending.redirect_uri) {
                        return json_response(
                            stream,
                            400,
                            "Bad Request",
                            &json!({"error": "invalid_grant", "error_description": "redirect_uri"}),
                            &[],
                        );
                    }
                    if params.get("resource") != Some(&pending.resource) {
                        return json_response(
                            stream,
                            400,
                            "Bad Request",
                            &json!({"error": "invalid_target", "error_description": "resource"}),
                            &[],
                        );
                    }
                    state.codes.remove(code);
                    let tokens = issue(&mut state);
                    json_response(stream, 200, "OK", &tokens, &[])
                }
                "refresh_token" => {
                    let Some(refresh) = params.get("refresh_token").cloned() else {
                        return json_response(
                            stream,
                            400,
                            "Bad Request",
                            &json!({"error": "invalid_request"}),
                            &[],
                        );
                    };
                    if state.valid_refresh.get(&refresh) != Some(&true) {
                        return json_response(
                            stream,
                            400,
                            "Bad Request",
                            &json!({"error": "invalid_grant", "error_description": "refresh token"}),
                            &[],
                        );
                    }
                    let tokens = issue(&mut state);
                    json_response(stream, 200, "OK", &tokens, &[])
                }
                other => json_response(
                    stream,
                    400,
                    "Bad Request",
                    &json!({"error": "unsupported_grant_type", "error_description": other}),
                    &[],
                ),
            }
        }
        _ => respond(stream, 404, "Not Found", &[], ""),
    }
}

/// Mint a token pair, remembering which access token is currently valid.
fn issue(state: &mut State) -> Value {
    state.issued += 1;
    let access = format!("access-{}", state.issued);
    let refresh = format!("refresh-{}", state.issued);
    state.valid_access.insert(access.clone(), true);
    state.valid_refresh.insert(refresh.clone(), true);
    let expires_in = if state.options.short_expiry { 1 } else { 3600 };
    json!({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": "read write"
    })
}

fn mcp_server(
    stream: &mut TcpStream,
    request: &Request,
    state: &Arc<Mutex<State>>,
) -> std::io::Result<()> {
    let (mcp_port, as_port, json_only) = {
        let state = state.lock().unwrap();
        (state.mcp_port, state.as_port, state.options.json)
    };

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/.well-known/oauth-protected-resource")
        | ("GET", "/.well-known/oauth-protected-resource/mcp") => json_response(
            stream,
            200,
            "OK",
            &json!({
                "resource": format!("http://127.0.0.1:{mcp_port}/mcp"),
                "authorization_servers": [format!("http://127.0.0.1:{as_port}")],
                "scopes_supported": ["read", "write"],
                "bearer_methods_supported": ["header"]
            }),
            &[],
        ),
        ("POST", "/mcp") => {
            if state.lock().unwrap().options.redirect {
                return respond(
                    stream,
                    307,
                    "Temporary Redirect",
                    &[("Location", format!("http://127.0.0.1:{mcp_port}/elsewhere"))],
                    "",
                );
            }
            let authorization = request.header("authorization").unwrap_or_default();
            let token = authorization
                .strip_prefix("Bearer ")
                .or_else(|| authorization.strip_prefix("bearer "))
                .unwrap_or_default()
                .to_string();

            let accepted = {
                let mut state = state.lock().unwrap();
                let static_ok = state.options.static_token.as_deref() == Some(token.as_str())
                    && !token.is_empty();
                let valid = state.valid_access.get(&token) == Some(&true);
                if valid {
                    // One request per token, so a client that does not refresh on 401
                    // fails loudly instead of silently reusing a dead token.
                    state.mcp_requests += 1;
                    if state.options.reject_first_token && state.mcp_requests >= 2 {
                        state.valid_access.insert(token.clone(), false);
                    }
                }
                static_ok || valid
            };
            if !accepted {
                let challenge = format!(
                    "Bearer resource_metadata=\"http://127.0.0.1:{mcp_port}/.well-known/oauth-protected-resource/mcp\""
                );
                return respond(
                    stream,
                    401,
                    "Unauthorized",
                    &[
                        ("WWW-Authenticate", challenge),
                        ("Content-Type", "text/plain".to_string()),
                    ],
                    "no valid token",
                );
            }

            let message: Value = match serde_json::from_str(&request.body) {
                Ok(message) => message,
                Err(error) => {
                    return json_response(
                        stream,
                        400,
                        "Bad Request",
                        &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": error.to_string()}}),
                        &[],
                    );
                }
            };
            let method = message
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let id = message.get("id").cloned();

            if method.starts_with("notifications/") {
                return respond(stream, 202, "Accepted", &[], "");
            }
            let result = match method.as_str() {
                "initialize" => json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "fake-remote", "version": "1.0.0" }
                }),
                "tools/list" => json!({
                    "tools": [{
                        "name": "ping",
                        "description": "Answers pong",
                        "inputSchema": { "type": "object", "properties": {} }
                    }]
                }),
                "tools/call" => json!({
                    "content": [{ "type": "text", "text": "pong from remote" }]
                }),
                other => {
                    let body = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": format!("no method {other}") }
                    });
                    return json_response(stream, 200, "OK", &body, &[]);
                }
            };
            let body = json!({ "jsonrpc": "2.0", "id": id, "result": result });
            let session = ("Mcp-Session-Id", "fake-session".to_string());
            if json_only {
                json_response(stream, 200, "OK", &body, &[session])
            } else {
                let event = format!("event: message\ndata: {body}\n\n");
                respond(
                    stream,
                    200,
                    "OK",
                    &[
                        ("Content-Type", "text/event-stream".to_string()),
                        ("Cache-Control", "no-cache".to_string()),
                        session,
                    ],
                    &event,
                )
            }
        }
        _ => respond(stream, 404, "Not Found", &[], ""),
    }
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        params.entry(decode(key)).or_insert_with(|| decode(value));
    }
    params
}

fn decode(value: &str) -> String {
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
                match u8::from_str_radix(&value[index + 1..index + 3], 16) {
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

/// Same computation the client does; a mismatch fails the token request.
fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let digest = Sha256::digest(verifier.as_bytes());
    let mut out = String::with_capacity(43);
    for chunk in digest.chunks(3) {
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
