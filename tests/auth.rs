//! Tests for the authentication path: what `up` refuses, and how it starts the gateway.
//!
//! These need the fake auth proxy, which is only built with the `test-support` feature:
//!
//! ```text
//! cargo test --all-features
//! ```

#![cfg(feature = "test-support")]

mod common;

use common::{Sandbox, fake_server_entry, http, json_string, mcp_json_with};
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, Instant};

/// Where the fake proxy writes what it was started with.
const RECORD_ENV: &str = "MCP_CTL_TEST_AUTH_PROXY_RECORD";

#[test]
fn authentication_without_an_external_url_is_refused() {
    let sandbox = Sandbox::new("auth-no-url");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    // A password never belongs in the profile file, so it comes from `.env`.
    sandbox.config_json(
        r#"{ "auth": { "password": { "source": "env", "name": "MCP_CTL_TEST_PASSWORD" } } }"#,
    );
    sandbox.env_file("MCP_CTL_TEST_PASSWORD=hunter2\n");

    let output = sandbox.run(&["up", "-d", "--no-tunnel", "--port=0"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("external_url"), "{stderr}");
}

#[test]
fn the_auth_proxy_receives_its_secret_through_the_environment() {
    let sandbox = Sandbox::new("auth-proxy");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));

    let record = sandbox.dir.join("auth-proxy.json");
    let proxy = json_string(env!("CARGO_BIN_EXE_mcp-fake-auth-proxy"));
    sandbox.config_json(&format!(
        r#"{{
            "server": {{
                "bind": "127.0.0.1",
                "listen_port": 37373,
                "proxy_port": 18080,
                "external_url": "https://device.example.ts.net",
                "auth_proxy_path": {proxy}
            }},
            "auth": {{ "password": {{ "source": "env", "name": "MCP_CTL_TEST_PASSWORD" }} }}
        }}"#
    ));
    sandbox.env_file("MCP_CTL_TEST_PASSWORD=hunter2\n");

    let output = sandbox
        .command()
        .env(RECORD_ENV, &record)
        .args(["up", "-d", "--no-tunnel", "--port=0"])
        .output()
        .expect("run the mcp-ctl binary");
    assert!(
        output.status.success(),
        "up -d failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state = wait_for_json(
        &sandbox.state_dir().join("daemon.json"),
        Duration::from_secs(10),
    )
    .expect("the daemon writes its state file");
    let hub_port = state["hub_port"].as_u64().expect("bound hub_port");

    let recorded = wait_for_json(&record, Duration::from_secs(10))
        .expect("the fake auth proxy records how it was started");
    let argv = recorded["args"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|argument| argument.as_str().map(str::to_string))
        .collect::<Vec<_>>()
        .join(" ");

    assert!(argv.contains("--external-url"), "{argv}");
    assert!(argv.contains("https://device.example.ts.net"), "{argv}");
    assert!(argv.contains("--data-path"), "{argv}");
    // The proxy is told where the hub is, and that it terminates TLS itself is off
    // because the tunnel in front of it does that.
    assert!(
        argv.contains(&format!("http://127.0.0.1:{hub_port}")),
        "{argv}"
    );
    assert!(argv.contains("--no-auto-tls"), "{argv}");
    // The password must never travel on the command line.
    assert!(!argv.contains("hunter2"), "{argv}");
    assert_eq!(recorded["env"]["PASSWORD"].as_str(), Some("hunter2"));

    // The running daemon reports the proxy, so `status` is a usable check.
    let status = sandbox.run(&["status"]);
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(status.status.success(), "{stdout}");
    assert!(stdout.contains("18080"), "{stdout}");
    assert!(stdout.contains("password"), "{stdout}");

    let stop = sandbox.run(&["stop", "--force"]);
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
}

#[test]
fn a_bearer_token_protects_the_hub_without_an_external_url() {
    let sandbox = Sandbox::new("auth-bearer");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    sandbox.config_json(
        r#"{ "auth": { "bearer_token": { "source": "env", "name": "MCP_CTL_TEST_TOKEN" } } }"#,
    );
    sandbox.env_file("MCP_CTL_TEST_TOKEN=0123456789abcdef\n");

    // No external_url and no mcp-auth-proxy: a bearer token is a complete method.
    let output = sandbox.run(&["up", "-d", "--no-tunnel", "--port=0"]);
    assert!(
        output.status.success(),
        "up -d failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state = wait_for_json(
        &sandbox.state_dir().join("daemon.json"),
        Duration::from_secs(10),
    )
    .expect("the daemon writes its state file");
    let hub_port = state["hub_port"].as_u64().expect("bound hub_port") as u16;

    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }).to_string();

    let missing = http(hub_port, "POST", "/mcp", Some(&body), &[]);
    assert_eq!(missing.status, 401, "{}", missing.body);
    assert!(
        missing
            .head
            .to_lowercase()
            .contains("www-authenticate: bearer"),
        "{}",
        missing.head
    );

    let wrong = http(
        hub_port,
        "POST",
        "/mcp",
        Some(&body),
        &[("Authorization", "Bearer nope")],
    );
    assert_eq!(wrong.status, 401, "{}", wrong.body);

    let allowed = http(
        hub_port,
        "POST",
        "/mcp",
        Some(&body),
        &[("Authorization", "Bearer 0123456789abcdef")],
    );
    assert_eq!(allowed.status, 200, "{}", allowed.body);
    assert!(allowed.json()["result"]["tools"].is_array());

    // Probes and preflights never need the token: browsers cannot send it on a
    // preflight, and a health check should not have to hold a secret.
    let health = http(hub_port, "GET", "/healthz", None, &[]);
    assert_eq!(health.status, 200);
    let preflight = http(hub_port, "OPTIONS", "/mcp", None, &[]);
    assert_eq!(preflight.status, 204);

    let stop = sandbox.run(&["stop", "--force"]);
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
}

#[test]
fn a_short_bearer_token_is_refused() {
    let sandbox = Sandbox::new("auth-short-bearer");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    sandbox.config_json(
        r#"{ "auth": { "bearer_token": { "source": "env", "name": "MCP_CTL_TEST_TOKEN" } } }"#,
    );
    sandbox.env_file("MCP_CTL_TEST_TOKEN=short\n");

    let output = sandbox.run(&["up", "-d", "--no-tunnel", "--port=0"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("too short"), "{stderr}");
}

/// Wait for a file to appear with parseable JSON in it.
fn wait_for_json(path: &Path, timeout: Duration) -> Option<Value> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(value) = serde_json::from_str::<Value>(&text)
        {
            return Some(value);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}
