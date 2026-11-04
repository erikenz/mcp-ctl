//! A client for remote MCP servers, spoken to over Streamable HTTP.
//!
//! The hub multiplexes standard input and output for local servers. A remote server
//! has no process to multiplex, so this module speaks the same JSON-RPC messages over
//! `POST <url>` instead and hands the hub the same shape it gets from a child: a
//! `tools/list` result and one response per `tools/call`.
//!
//! Two details of the transport matter here:
//!
//! * the server may answer either with `application/json` or with a stream of
//!   server-sent events, so both shapes are decoded; and
//! * a `Mcp-Session-Id` header, when the server issues one, has to be echoed on every
//!   later request, and a session can expire mid-run.
//!
//! Authorisation is delegated to [`crate::oauth`]: a token is attached when one is
//! stored, an expired token is refreshed, and a 401 gets one retry before the call
//! fails with a message that says how to sign in again.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

use crate::hub::{BackendTimeouts, JsonRpcError, errors};
use crate::oauth;

/// Longest single message accepted from a remote server.
const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

/// The MCP revision this client asks for when it opens a session.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Why a request did not produce a message.
enum Posted {
    Message(Value),
    Unauthorized,
    /// The server no longer knows the session (a restart, or its own idle timeout).
    SessionGone,
}

pub struct RemoteServer {
    name: String,
    url: String,
    agent: ureq::Agent,
    /// Headers from the profile, resolved (so `{"source": "env"}` works here too).
    headers: Vec<(String, String)>,
    /// `None` when the profile supplies its own credential or opts out of OAuth.
    oauth: Option<oauth::Client>,
    session_id: Option<String>,
    protocol_version: Option<String>,
    tools: Vec<Value>,
    timeout: Option<Duration>,
    next_id: u64,
}

impl RemoteServer {
    /// Open a session with a remote server and list its tools.
    pub fn connect(
        name: &str,
        url: &str,
        headers: Vec<(String, String)>,
        oauth: Option<oauth::Client>,
        timeouts: BackendTimeouts,
    ) -> Result<Self> {
        let mut server = Self {
            name: name.to_string(),
            url: url.to_string(),
            agent: ureq::Agent::config_builder()
                // A 401 is how a remote server asks for authentication, and a 404 is
                // how an expired session answers; neither is a transport failure.
                .http_status_as_error(false)
                // An MCP endpoint is called where it is configured. Following a
                // redirect would turn a POST into a GET (303) or replay the body at a
                // host the profile never named, so a redirect is reported instead.
                .max_redirects(0)
                .max_redirects_will_error(false)
                .build()
                .into(),
            headers,
            oauth,
            session_id: None,
            protocol_version: None,
            tools: Vec::new(),
            timeout: timeouts.tool,
            next_id: 1,
        };
        server.handshake(timeouts.handshake)?;
        Ok(server)
    }

    pub fn tools(&self) -> &[Value] {
        &self.tools
    }

    /// Send a JSON-RPC notification; only the transport status matters.
    pub fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        let payload = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        let mut attempt = 0;
        loop {
            let token = self.token()?;
            match self.post(
                &payload,
                None,
                token.as_deref(),
                Some(Duration::from_secs(30)),
            ) {
                Ok(Posted::Message(_)) => return Ok(()),
                Ok(Posted::Unauthorized) if attempt == 0 => {
                    attempt += 1;
                    self.renew()?;
                }
                Ok(Posted::Unauthorized) => return Err(self.unauthorized()),
                Ok(Posted::SessionGone) if attempt == 0 => {
                    attempt += 1;
                    self.handshake(Duration::from_secs(30))?;
                }
                Ok(Posted::SessionGone) => {
                    return Err(anyhow!(
                        "server '{}' closed the session again right after reconnecting",
                        self.name
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Forward a `tools/call` to the remote server.
    pub fn call_tool(&mut self, params: Value) -> Result<Value> {
        self.request("tools/call", params, self.timeout)
    }

    /// Close the session, best-effort: a server that never issued one has nothing to
    /// close, and a failed DELETE must not keep the hub from stopping.
    pub fn shutdown(&mut self, _grace: Duration) -> Result<()> {
        let Some(session_id) = self.session_id.take() else {
            return Ok(());
        };
        let request = self
            .agent
            .delete(&self.url)
            .header("Mcp-Session-Id", &session_id);
        let _ = request.call();
        Ok(())
    }

    fn handshake(&mut self, timeout: Duration) -> Result<()> {
        let result = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "mcp-ctl", "version": env!("CARGO_PKG_VERSION") }
                }),
                Some(timeout),
            )
            .with_context(|| format!("server '{}' did not complete its handshake", self.name))?;

        let version = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(PROTOCOL_VERSION)
            .to_string();
        self.protocol_version = Some(version.clone());
        self.notify("notifications/initialized", json!({}))?;

        let tools = self.request("tools/list", json!({}), Some(timeout))?;
        self.tools = tools
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(())
    }

    /// Send a JSON-RPC request and wait for the response with the same id.
    pub fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });

        let mut attempts = 0;
        loop {
            attempts += 1;
            let token = self.token()?;
            match self.post(&payload, Some(id), token.as_deref(), timeout) {
                Ok(Posted::Message(mut message)) => {
                    if message.get("id").and_then(Value::as_u64) != Some(id) {
                        bail!(
                            "server '{}' answered '{method}' with another request's id",
                            self.name
                        );
                    }
                    if let Some(error) = message.get("error") {
                        return Err(anyhow::Error::new(JsonRpcError {
                            code: error
                                .get("code")
                                .and_then(Value::as_i64)
                                .unwrap_or(errors::SERVER_ERROR),
                            message: error
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("unspecified remote error")
                                .to_string(),
                            data: error.get("data").cloned(),
                        }));
                    }
                    return match message.get_mut("result").map(std::mem::take) {
                        Some(result) => Ok(result),
                        None => bail!(
                            "server '{}' answered '{method}' without a result",
                            self.name
                        ),
                    };
                }
                Ok(Posted::Unauthorized) if attempts == 1 => {
                    // An expired access token is the common cause; refresh once.
                    self.renew()?;
                }
                Ok(Posted::Unauthorized) => return Err(self.unauthorized()),
                Ok(Posted::SessionGone) if attempts == 1 => {
                    // The server forgot the session: open a new one and send the
                    // message again, so a backend restart costs one retry, not a call.
                    self.handshake(Duration::from_secs(30))?;
                }
                Ok(Posted::SessionGone) => {
                    return Err(anyhow!(
                        "server '{}' closed the session again right after reconnecting",
                        self.name
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn token(&self) -> Result<Option<String>> {
        match &self.oauth {
            Some(client) => client.token(),
            None => Ok(None),
        }
    }

    /// Force a refresh, or fail with the message that tells the user what to do.
    fn renew(&self) -> Result<()> {
        let Some(client) = &self.oauth else {
            return Ok(());
        };
        if client.refresh()?.is_none() {
            client.invalidate().ok();
            bail!("{}", client.login_hint());
        }
        Ok(())
    }

    fn unauthorized(&self) -> anyhow::Error {
        match &self.oauth {
            Some(client) => anyhow!(client.login_hint()),
            None => anyhow!(
                "server '{}' answered 401 Unauthorized; add an Authorization header for it, or set \
                 \"auth\": {{\"type\": \"oauth\"}} and run `mcp-ctl auth login {}`",
                self.name,
                self.name
            ),
        }
    }

    /// One HTTP request. `expect_id` is the JSON-RPC id to wait for in an event stream;
    /// `None` for a notification, where the transport status is the whole answer.
    fn post(
        &mut self,
        payload: &Value,
        expect_id: Option<u64>,
        token: Option<&str>,
        timeout: Option<Duration>,
    ) -> std::result::Result<Posted, anyhow::Error> {
        let mut request = self
            .agent
            .post(&self.url)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json");
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("authorization") {
                continue;
            }
            request = request.header(name, value);
        }
        // A configured Authorization header wins over a stored token: it is the
        // explicit, per-server answer for a server that takes an API key.
        let configured_authorization = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone());
        if let Some(value) = configured_authorization {
            request = request.header("Authorization", value);
        } else if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(session_id) = &self.session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }
        if let Some(version) = &self.protocol_version {
            request = request.header("MCP-Protocol-Version", version);
        }
        if let Some(timeout) = timeout {
            request = request.config().timeout_global(Some(timeout)).build();
        }

        let mut response = request
            .send(payload.to_string())
            .with_context(|| format!("could not reach server '{}' at {}", self.name, self.url))?;
        let status = response.status().as_u16();

        if let Some(session_id) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
        {
            self.session_id = Some(session_id.to_string());
        }

        if status == 401 {
            return Ok(Posted::Unauthorized);
        }
        if (300..400).contains(&status) {
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<no Location header>");
            bail!(
                "server '{}' answered {status} and points at {location}; mcp-ctl does not follow \
                 redirects, so use the final URL in the profile",
                self.name
            );
        }
        if status == 404 && self.session_id.is_some() {
            // The server forgot the session (a restart, or an idle timeout on its
            // side). The caller opens a new one and sends the message again.
            self.session_id = None;
            return Ok(Posted::SessionGone);
        }
        if !(200..300).contains(&status) {
            let body = read_body(&mut response);
            bail!(
                "server '{}' answered {status}: {}",
                self.name,
                truncate(&body)
            );
        }
        let Some(expect_id) = expect_id else {
            return Ok(Posted::Message(Value::Null));
        };

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if content_type.contains("text/event-stream") {
            let mut reader = BufReader::new(response.body_mut().as_reader());
            let message = read_event_stream(&mut reader, expect_id, &self.name)?;
            Ok(Posted::Message(message))
        } else {
            let body = read_body(&mut response);
            let message: Value = serde_json::from_str(&body).with_context(|| {
                format!(
                    "server '{}' did not answer with JSON: {}",
                    self.name,
                    truncate(&body)
                )
            })?;
            Ok(Posted::Message(message))
        }
    }
}

fn read_body(response: &mut ureq::http::Response<ureq::Body>) -> String {
    let mut bytes = Vec::new();
    let _ = response
        .body_mut()
        .as_reader()
        .take(MAX_MESSAGE_BYTES as u64)
        .read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).to_string()
}

/// Serve one remote server on this process's stdio.
///
/// `mcp-ctl run <name>` for an entry with a `url`: editors that only speak stdio can
/// use a remote server through this bridge, and the OAuth flow is the same one the
/// hub uses.
pub fn bridge(mut server: RemoteServer) -> Result<i32> {
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(message) => message,
            Err(error) => {
                outln!(
                    "{}",
                    json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": { "code": -32700, "message": format!("parse error: {error}") }
                    })
                );
                continue;
            }
        };
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        let Some(id) = message.get("id").cloned() else {
            // A notification: forward it and expect no answer.
            if let Err(error) = server.notify(&method, params) {
                errln!("warning: {error}");
            }
            continue;
        };
        let response = match server.request(&method, params, None) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(error) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32603, "message": error.to_string() }
            }),
        };
        outln!("{response}");
    }
    Ok(0)
}

fn truncate(body: &str) -> String {
    let body = body.trim();
    if body.len() <= 300 {
        return body.to_string();
    }
    format!("{}...", &body[..300])
}

/// Read server-sent events until the response with `expect_id` arrives.
///
/// Notifications the server pushes (progress, logging) are skipped: the hub does not
/// relay them yet, and waiting for them to finish would stall a tool call.
fn read_event_stream<R: BufRead>(reader: &mut R, expect_id: u64, name: &str) -> Result<Value> {
    let mut data = String::new();
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .with_context(|| format!("lost the event stream from '{name}'"))?;
        if read == 0 {
            bail!("server '{name}' closed the event stream without answering the request");
        }
        total = total.saturating_add(read);
        if total > MAX_MESSAGE_BYTES {
            bail!("server '{name}' sent more than {MAX_MESSAGE_BYTES} bytes in one response");
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            if !data.is_empty() {
                let payload = std::mem::take(&mut data);
                if let Ok(message) = serde_json::from_str::<Value>(&payload)
                    && message.get("id").and_then(Value::as_u64) == Some(expect_id)
                {
                    return Ok(message);
                }
            }
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn an_event_stream_response_is_found_after_notifications() {
        let body = ": keep-alive\n\n\
                    event: message\n\
                    data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n\
                    event: message\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n\n";
        let mut reader = Cursor::new(body.as_bytes());
        let message = read_event_stream(&mut reader, 7, "fake").unwrap();
        assert_eq!(message["result"]["tools"], json!([]));
    }

    #[test]
    fn a_multiline_event_is_joined_before_parsing() {
        let body = "data: {\"jsonrpc\":\"2.0\",\n\
                    data: \"id\":1,\"result\":{\"ok\":true}}\n\n";
        let mut reader = Cursor::new(body.as_bytes());
        let message = read_event_stream(&mut reader, 1, "fake").unwrap();
        assert_eq!(message["result"]["ok"], json!(true));
    }

    #[test]
    fn an_event_stream_that_ends_early_is_an_error() {
        let body = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n";
        let mut reader = Cursor::new(body.as_bytes());
        let error = read_event_stream(&mut reader, 7, "fake").unwrap_err();
        assert!(
            error.to_string().contains("closed the event stream"),
            "{error}"
        );
    }
}
