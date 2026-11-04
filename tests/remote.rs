//! End-to-end tests for remote MCP servers: OAuth sign-in, the token store, and the
//! hub forwarding tool calls to a server it reaches over Streamable HTTP.
//!
//! The fake server in `tests/support/fake_oauth_server.rs` plays both roles (the
//! authorization server and the protected MCP endpoint), so the whole chain is real:
//! discovery, dynamic client registration, PKCE, the loopback callback, the token
//! exchange, a 401 that forces a refresh, and the tool call itself.
//!
//! ```text
//! cargo test --all-features
//! ```

#![cfg(feature = "test-support")]

mod common;

use common::{HttpResponse, Sandbox, http, json_string};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A fake OAuth-protected MCP server, killed when the test ends.
struct FakeOAuth {
    child: Child,
    mcp_port: u16,
}

impl FakeOAuth {
    fn start(flags: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-fake-oauth-server"))
            .args(flags)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start the fake OAuth server");
        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("read the fake server's ports");
        let ports: Value = serde_json::from_str(&line).expect("the fake server prints JSON");
        assert!(ports["as_port"].as_u64().is_some(), "{ports}");
        Self {
            child,
            mcp_port: ports["mcp_port"].as_u64().unwrap() as u16,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.mcp_port)
    }

    /// The server entry a profile uses to reach it.
    fn entry(&self, extra: &str) -> String {
        format!(
            r#""remote": {{ "url": {}, "serve": true{extra} }}"#,
            json_string(&self.url())
        )
    }
}

impl Drop for FakeOAuth {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Split `http://127.0.0.1:<port>/path?query` into the port and the request target.
fn split_url(url: &str) -> (u16, String) {
    let rest = url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("not an http URL: {url}"));
    let (authority, target) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let port: u16 = authority
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("no port in {url}"))
        .1
        .parse()
        .expect("a numeric port");
    (port, target.to_string())
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// Run `auth login --no-open`, then play the browser: follow the authorization URL to
/// the loopback callback. Returns the process output.
fn login(sandbox: &Sandbox, name: &str) -> std::process::Output {
    let mut child = sandbox
        .command()
        .args(["auth", "login", name, "--no-open", "--timeout=30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start auth login");

    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut seen = String::new();
    let mut authorization_url = None;
    loop {
        let mut line = String::new();
        if stdout.read_line(&mut line).expect("read auth login output") == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            authorization_url = Some(trimmed.to_string());
            break;
        }
        seen.push_str(&line);
    }
    let authorization_url = authorization_url.unwrap_or_else(|| {
        panic!("auth login never printed an authorization URL; it said:\n{seen}")
    });

    // The browser goes to the authorization server, which redirects to the loopback
    // listener that `auth login` is waiting on.
    let (as_port, target) = split_url(&authorization_url);
    let response = http(as_port, "GET", &target, None, &[]);
    assert_eq!(
        response.status, 302,
        "the authorization endpoint should redirect: {}",
        response.head
    );
    let callback = header(&response.head, "location").expect("a Location header");
    let (callback_port, callback_target) = split_url(&callback);
    let response = http(callback_port, "GET", &callback_target, None, &[]);
    assert_eq!(
        response.status, 200,
        "the loopback callback should accept the code: {}",
        response.head
    );

    let status = child.wait().expect("wait for auth login");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr)
        .expect("read auth login stderr");
    let mut output = std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: stderr.into_bytes(),
    };
    // Keep the operator-facing output available in assertion messages.
    output.stdout.extend_from_slice(seen.as_bytes());
    output
}

fn read_hub_port(sandbox: &Sandbox) -> u16 {
    let path = sandbox.state_dir().join("daemon.json");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(state) = serde_json::from_str::<Value>(&text)
            && let Some(port) = state.get("hub_port").and_then(Value::as_u64)
            && port != 0
        {
            return port as u16;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no usable state file at {}", path.display());
}

fn call(port: u16, message: &Value) -> HttpResponse {
    http(port, "POST", "/mcp", Some(&message.to_string()), &[])
}

fn initialize(port: u16) -> HttpResponse {
    call(
        port,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0" }
            }
        }),
    )
}

fn tool_names(response: &HttpResponse) -> Vec<String> {
    response.json()["result"]["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_remote_server_signs_in_and_is_served_over_sse() {
    let fake = FakeOAuth::start(&["--reject-first-token"]);
    let sandbox = Sandbox::new("remote-oauth");
    sandbox.mcp_json(&format!(r#"{{ "mcpServers": {{ {} }} }}"#, fake.entry("")));

    // Before signing in, `auth status` says so rather than failing.
    let output = sandbox.run(&["auth", "status", "--json"]);
    assert!(
        output.status.success(),
        "auth status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Value = serde_json::from_slice(&output.stdout).expect("JSON status");
    assert_eq!(rows[0]["signed_in"], json!(false), "{rows}");

    let output = login(&sandbox, "remote");
    assert!(
        output.status.success(),
        "auth login failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Tokens are stored owner-only in the state directory.
    let store = sandbox.state_dir().join("oauth.json");
    assert!(store.is_file(), "no token store at {}", store.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&store).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the token store must be owner-only");
    }
    let stored: Value = serde_json::from_slice(&std::fs::read(&store).unwrap()).unwrap();
    let entry = stored["servers"]
        .as_object()
        .and_then(|servers| servers.values().next())
        .expect("one stored server");
    assert!(
        entry["tokens"]["refresh_token"].is_string(),
        "the refresh token should be stored: {entry}"
    );

    // Now serve it through the hub. The fake invalidates the first access token after
    // one use, so the handshake has to refresh on a 401 to get this far.
    let output = sandbox.run(&["up", "-d", "--no-tunnel", "--no-auth", "--port=0"]);
    assert!(
        output.status.success(),
        "up failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hub = read_hub_port(&sandbox);

    let response = initialize(hub);
    assert_eq!(response.status, 200, "{}", response.body);
    let listing = call(
        hub,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(tool_names(&listing), vec!["ping".to_string()]);

    let response = call(
        hub,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "ping", "arguments": {} }
        }),
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(
        response.body.contains("pong from remote"),
        "unexpected tool result: {}",
        response.body
    );

    let stored_after: Value = serde_json::from_slice(&std::fs::read(&store).unwrap()).unwrap();
    let access_after = stored_after["servers"]
        .as_object()
        .and_then(|servers| servers.values().next())
        .and_then(|entry| entry["tokens"]["access_token"].as_str())
        .expect("an access token");
    let access_before = entry["tokens"]["access_token"].as_str().unwrap();
    assert_ne!(
        access_before, access_after,
        "the token should have been refreshed after the 401"
    );

    let output = sandbox.run(&["stop"]);
    assert!(output.status.success(), "stop failed");
}

#[test]
fn a_remote_server_answering_plain_json_is_served_too() {
    let fake = FakeOAuth::start(&["--json"]);
    let sandbox = Sandbox::new("remote-json");
    sandbox.mcp_json(&format!(r#"{{ "mcpServers": {{ {} }} }}"#, fake.entry("")));
    let output = login(&sandbox, "remote");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = sandbox.run(&["up", "-d", "--no-tunnel", "--no-auth", "--port=0"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hub = read_hub_port(&sandbox);

    assert_eq!(initialize(hub).status, 200);
    let listing = call(
        hub,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(tool_names(&listing), vec!["ping".to_string()]);

    sandbox.run(&["stop"]);
}

#[test]
fn a_configured_authorization_header_is_used_instead_of_oauth() {
    let fake = FakeOAuth::start(&["--static-token", "api-key-for-tests"]);
    let sandbox = Sandbox::new("remote-header");
    sandbox.mcp_json(&format!(
        r#"{{ "mcpServers": {{ {} }} }}"#,
        fake.entry(r#", "headers": { "Authorization": "Bearer api-key-for-tests" }"#)
    ));

    let output = sandbox.run(&["up", "-d", "--no-tunnel", "--no-auth", "--port=0"]);
    assert!(
        output.status.success(),
        "up failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hub = read_hub_port(&sandbox);
    assert_eq!(initialize(hub).status, 200);
    let listing = call(
        hub,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(tool_names(&listing), vec!["ping".to_string()]);

    // No sign-in was needed, so there is nothing in the token store.
    assert!(!sandbox.state_dir().join("oauth.json").exists());

    sandbox.run(&["stop"]);
}

#[test]
fn signing_in_refuses_a_server_with_its_own_authorization_header() {
    let fake = FakeOAuth::start(&[]);
    let sandbox = Sandbox::new("remote-header-login");
    sandbox.mcp_json(&format!(
        r#"{{ "mcpServers": {{ {} }} }}"#,
        fake.entry(r#", "headers": { "Authorization": "Bearer api-key-for-tests" }"#)
    ));

    let output = sandbox.run(&["auth", "login", "remote", "--no-open"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Authorization header"), "{stderr}");
}

#[test]
fn a_remote_server_without_a_token_is_skipped_with_an_actionable_message() {
    let fake = FakeOAuth::start(&[]);
    let sandbox = Sandbox::new("remote-no-token");
    sandbox.mcp_json(&format!(r#"{{ "mcpServers": {{ {} }} }}"#, fake.entry("")));

    let output = sandbox.run(&["up", "--no-tunnel", "--no-auth", "--port=0"]);
    assert!(
        !output.status.success(),
        "up should not serve an unauthenticated remote"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mcp-ctl auth login remote"),
        "the message should say how to sign in: {stderr}"
    );
}

#[test]
fn a_redirect_is_reported_instead_of_followed() {
    // Following it would replay a tool call at a host the profile never named, so the
    // profile's URL has to be the final one.
    let fake = FakeOAuth::start(&["--redirect"]);
    let sandbox = Sandbox::new("remote-redirect");
    sandbox.mcp_json(&format!(r#"{{ "mcpServers": {{ {} }} }}"#, fake.entry("")));

    let output = sandbox.run(&["up", "--no-tunnel", "--no-auth", "--port=0"]);
    assert!(
        !output.status.success(),
        "a redirect should not be followed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not follow redirects"), "{stderr}");
}

#[test]
fn run_bridges_a_remote_server_over_stdio() {
    let fake = FakeOAuth::start(&[]);
    let sandbox = Sandbox::new("remote-run");
    sandbox.mcp_json(&format!(r#"{{ "mcpServers": {{ {} }} }}"#, fake.entry("")));
    let output = login(&sandbox, "remote");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut child = sandbox
        .command()
        .args(["run", "remote"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start the bridge");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    writeln!(stdin, "{request}").expect("write to the bridge");
    stdin.flush().ok();

    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("read the bridge's answer");
    let response: Value = serde_json::from_str(line.trim()).expect("a JSON-RPC response");
    assert_eq!(
        response["result"]["tools"][0]["name"],
        json!("ping"),
        "{response}"
    );

    drop(stdin);
    let status = child.wait().expect("wait for the bridge");
    assert!(status.success());
}
