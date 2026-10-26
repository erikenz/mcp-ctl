//! End-to-end tests through the real binary: the hub, its HTTP endpoint, and the
//! daemon lifecycle (including that stopping the daemon stops the backends).
//!
//! These need the fake MCP server, which is only built with the `test-support`
//! feature:
//!
//! ```text
//! cargo test --all-features
//! ```

#![cfg(feature = "test-support")]

mod common;

use common::{HttpResponse, Sandbox, fake_server_entry, http, json_string, mcp_json_with};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// A daemon started for one test, stopped again when the test ends.
struct Daemon {
    sandbox: Sandbox,
    hub_port: u16,
}

impl Daemon {
    fn start(sandbox: Sandbox) -> Self {
        Self::start_with(
            sandbox,
            &["up", "-d", "--no-tunnel", "--no-auth", "--port=0"],
        )
    }

    fn start_with(sandbox: Sandbox, args: &[&str]) -> Self {
        let output = sandbox.run(args);
        assert!(
            output.status.success(),
            "up -d failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let hub_port = read_hub_port(&sandbox);
        Self { sandbox, hub_port }
    }

    fn post(&self, body: Value) -> HttpResponse {
        self.request("POST", "/mcp", Some(body.to_string()), &[])
    }

    fn call_tool(&self, name: &str) -> HttpResponse {
        self.post(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": name, "arguments": {} }
        }))
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
        headers: &[(&str, &str)],
    ) -> HttpResponse {
        http(self.hub_port, method, path, body.as_deref(), headers)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Never leave a daemon (and its backends) behind, whatever the test did.
        let _ = self.sandbox.run(&["stop", "--force"]);
    }
}

/// Wait for the daemon to write a state file and report the hub port it bound.
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
    panic!(
        "the daemon did not write a usable state file at {}",
        path.display()
    );
}

#[test]
fn initialize_and_tools_list_are_served() {
    let sandbox = Sandbox::new("hub-init");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let initialize = daemon.post(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": "2025-06-18" }
    }));
    assert_eq!(initialize.status, 200, "{}", initialize.body);
    let initialize = initialize.json();
    assert_eq!(initialize["result"]["protocolVersion"], json!("2025-06-18"));
    assert_eq!(initialize["result"]["serverInfo"]["name"], json!("mcp-ctl"));

    let tools = daemon.post(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    let tools = tools.json();
    let names: Vec<String> = tools["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_string))
        .collect();
    assert!(names.contains(&"echo".to_string()), "{names:?}");
    assert!(names.contains(&"slow".to_string()), "{names:?}");
    assert!(names.contains(&"fail".to_string()), "{names:?}");
}

#[test]
fn a_tool_call_reaches_the_backend() {
    let sandbox = Sandbox::new("hub-call");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let response = daemon.post(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "echo", "arguments": { "hello": "world" } }
    }));
    assert_eq!(response.status, 200, "{}", response.body);
    let text = response.json()["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(text.contains("world"), "{text}");
}

#[test]
fn backend_errors_keep_their_code_and_data() {
    let sandbox = Sandbox::new("hub-error");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let body = daemon.call_tool("fail").json();
    assert_eq!(body["error"]["code"], json!(-32000));
    assert_eq!(body["error"]["message"], json!("fake failure"));
    assert_eq!(body["error"]["data"]["detail"], json!("as requested"));
}

#[test]
fn unknown_tools_and_methods_are_reported() {
    let sandbox = Sandbox::new("hub-unknown");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let tool = daemon.call_tool("nope").json();
    assert_eq!(tool["error"]["code"], json!(-32601));
    assert!(
        tool["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown tool")
    );

    let method = daemon
        .post(json!({ "jsonrpc": "2.0", "id": 5, "method": "resources/list" }))
        .json();
    assert_eq!(method["error"]["code"], json!(-32601));
}

#[test]
fn notifications_get_an_empty_accepted_response() {
    let sandbox = Sandbox::new("hub-notify");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let response = daemon.post(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    assert_eq!(response.status, 202, "{}", response.body);
    assert!(response.body.is_empty(), "{}", response.body);
}

#[test]
fn browser_origins_are_checked() {
    let sandbox = Sandbox::new("hub-origin");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let body = json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/list" }).to_string();

    let same_origin = format!("http://127.0.0.1:{}", daemon.hub_port);
    let allowed = daemon.request(
        "POST",
        "/mcp",
        Some(body.clone()),
        &[("Origin", same_origin.as_str())],
    );
    assert_eq!(allowed.status, 200, "{}", allowed.body);

    let refused = daemon.request(
        "POST",
        "/mcp",
        Some(body),
        &[("Origin", "https://evil.example")],
    );
    assert_eq!(refused.status, 403, "{}", refused.body);
}

#[test]
fn only_post_is_available_on_the_endpoint() {
    let sandbox = Sandbox::new("hub-methods");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let get = daemon.request("GET", "/mcp", None, &[]);
    assert_eq!(get.status, 405);
    assert!(
        get.head.to_lowercase().contains("allow: post"),
        "{}",
        get.head
    );

    let unknown = daemon.request("POST", "/nope", Some(json!({}).to_string()), &[]);
    assert_eq!(unknown.status, 404);

    let health = daemon.request("GET", "/healthz", None, &[]);
    assert_eq!(health.status, 200);
    assert_eq!(health.body, "ok");
}

#[test]
fn a_backend_that_prints_a_non_utf8_line_still_serves() {
    let sandbox = Sandbox::new("hub-garbage");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry(
        "alpha",
        &["--garbage"],
    )]));
    let daemon = Daemon::start(sandbox);

    // The stray byte is skipped like any other unsolicited line; the handshake and
    // the tool call must both survive it.
    let tools = daemon.post(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }));
    assert_eq!(tools.status, 200, "{}", tools.body);
    assert!(tools.body.contains("echo"), "{}", tools.body);

    let call = daemon.call_tool("echo");
    assert_eq!(call.status, 200, "{}", call.body);
    assert!(call.json()["result"].is_object(), "{}", call.body);
}

#[test]
fn invalid_json_is_reported_as_a_parse_error() {
    let sandbox = Sandbox::new("hub-parse");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let response = daemon.request("POST", "/mcp", Some("this is not json".to_string()), &[]);
    assert_eq!(response.status, 400);
    assert_eq!(response.json()["error"]["code"], json!(-32700));
}

#[test]
fn tool_timeouts_are_reported_and_the_daemon_survives() {
    let sandbox = Sandbox::new("hub-timeout");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    sandbox.config_json(r#"{ "server": { "tool_timeout_secs": 1 } }"#);
    let daemon = Daemon::start(sandbox);

    let body = daemon.call_tool("slow").json();
    let message = body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(message.contains("did not answer"), "{message}");
    assert!(message.contains("within 1s"), "{message}");

    // A timeout is not fatal: other calls still work afterwards.
    let tools = daemon.post(json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" }));
    assert_eq!(tools.status, 200);
}

#[test]
fn colliding_and_prefixed_tool_names_stay_distinct() {
    let sandbox = Sandbox::new("hub-prefix");
    let command = json_string(env!("CARGO_BIN_EXE_mcp-fake-server"));
    let prefixed = format!(
        r#""gamma": {{ "command": {command}, "args": ["--tool", "search"], "prefix": "px", "serve": true }}"#
    );
    sandbox.mcp_json(&mcp_json_with(&[
        fake_server_entry("alpha", &["--tool", "search"]),
        fake_server_entry("beta", &["--tool", "search"]),
        prefixed,
    ]));
    let daemon = Daemon::start(sandbox);

    let tools = daemon.post(json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/list" }));
    let tools = tools.json();
    let names: Vec<String> = tools["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_string))
        .collect();

    assert!(names.contains(&"search".to_string()), "{names:?}");
    assert!(names.contains(&"beta_search".to_string()), "{names:?}");
    assert!(names.contains(&"px_search".to_string()), "{names:?}");

    // The renamed tool still routes to the right backend.
    let renamed = daemon.call_tool("px_search");
    assert_eq!(renamed.status, 200, "{}", renamed.body);
    assert!(
        renamed.json()["result"]["content"].is_array(),
        "{}",
        renamed.body
    );
}

#[test]
fn profiles_run_and_stop_independently() {
    let sandbox = Sandbox::new("hub-profiles");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    sandbox.config_json(r#"{ "server": { "listen_port": 0 } }"#);

    // A second profile with its own catalogue and its own settings.
    let work_file = sandbox.config_dir.join("config.work.json");
    let mut contents = mcp_json_with(&[fake_server_entry("beta", &[])]);
    contents.insert_str(contents.len() - 1, r#", "server": { "listen_port": 0 }"#);
    std::fs::write(&work_file, contents).unwrap();

    let default_daemon = Daemon::start(sandbox);
    let sandbox = &default_daemon.sandbox;

    let work_up = sandbox.run(&[
        "--profile",
        "work",
        "up",
        "-d",
        "--no-tunnel",
        "--no-auth",
        "--port=0",
    ]);
    assert!(
        work_up.status.success(),
        "up -d for the work profile failed: {}",
        String::from_utf8_lossy(&work_up.stderr)
    );

    // Two daemons, two state files, two catalogues.
    let work_port = read_hub_port_in(&sandbox.state_dir().join("profiles").join("work"));
    assert_ne!(work_port, default_daemon.hub_port);
    let work_tools = tools_at(work_port);
    assert!(work_tools.contains(&"echo".to_string()), "{work_tools:?}");

    let all = sandbox.run(&["status"]);
    let stdout = String::from_utf8_lossy(&all.stdout);
    assert!(stdout.contains("running"), "{stdout}");
    assert!(stdout.contains("default"), "{stdout}");
    assert!(stdout.contains("work"), "{stdout}");

    // Stopping one profile leaves the other serving.
    let stopped = sandbox.run(&["--profile", "work", "stop"]);
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        !sandbox
            .state_dir()
            .join("profiles")
            .join("work")
            .join("daemon.json")
            .exists(),
        "the work profile's state file is removed"
    );
    assert!(
        sandbox.state_dir().join("daemon.json").exists(),
        "the default profile keeps running"
    );
    let default_tools = tools_at(default_daemon.hub_port);
    assert!(
        default_tools.contains(&"echo".to_string()),
        "{default_tools:?}"
    );

    // And it says which profile is still up.
    let stopped_again = sandbox.run(&["stop", "--profile", "work"]);
    let stdout = String::from_utf8_lossy(&stopped_again.stdout);
    assert!(stdout.contains("not running"), "{stdout}");
    assert!(stdout.contains("default"), "{stdout}");
}

/// The hub port recorded in a state directory.
fn read_hub_port_in(state_dir: &std::path::Path) -> u16 {
    let path = state_dir.join("daemon.json");
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

/// The tool names a hub publishes.
fn tools_at(port: u16) -> Vec<String> {
    let response = http(
        port,
        "POST",
        "/mcp",
        Some(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }).to_string()),
        &[],
    );
    response.json()["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn stopping_the_daemon_stops_the_backends() {
    let sandbox = Sandbox::new("hub-stop");
    let exit_file = sandbox.dir.join("backend-exited");
    let exit_file_text = exit_file.to_string_lossy().to_string();
    let entry = fake_server_entry("alpha", &["--exit-file", &exit_file_text]);
    sandbox.mcp_json(&mcp_json_with(&[entry]));
    let daemon = Daemon::start(sandbox);

    // The backend is up and answering before we stop anything.
    let tools = daemon.post(json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" }));
    assert_eq!(tools.status, 200);

    let stop = daemon.sandbox.run(&["stop"]);
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(String::from_utf8_lossy(&stop.stdout).contains("stopped"));

    // Closing the backend's stdin is what asks it to exit, and it says so on disk.
    assert!(
        exit_file.is_file(),
        "the backend should have exited when the daemon stopped"
    );
}

#[test]
fn a_second_daemon_is_refused() {
    let sandbox = Sandbox::new("hub-twice");
    sandbox.mcp_json(&mcp_json_with(&[fake_server_entry("alpha", &[])]));
    let daemon = Daemon::start(sandbox);

    let second = daemon
        .sandbox
        .run(&["up", "-d", "--no-tunnel", "--no-auth", "--port=0"]);
    assert!(!second.status.success());
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("already running"), "{stderr}");
}

#[test]
fn a_server_whose_secret_cannot_be_resolved_is_skipped() {
    let sandbox = Sandbox::new("hub-secret-skip");
    let broken = r#""broken": {
        "command": "true",
        "serve": true,
        "env": {
            "TOKEN": { "source": "command", "run": "mcp-ctl-definitely-missing-secret-command" }
        }
    }"#;
    sandbox.mcp_json(&mcp_json_with(&[
        fake_server_entry("alpha", &[]),
        broken.to_string(),
    ]));

    // The daemon must start with the healthy server, not fail because one secret is
    // unavailable.
    let daemon = Daemon::start(sandbox);
    let names = tools_at(daemon.hub_port);
    assert!(names.contains(&"echo".to_string()), "{names:?}");

    let log = std::fs::read_to_string(daemon.sandbox.state_dir().join("mcp-ctl.log"))
        .expect("the daemon log is readable");
    assert!(log.contains("skipping 'broken'"), "{log}");
    assert!(
        log.contains("mcp-ctl-definitely-missing-secret-command"),
        "{log}"
    );
}

#[cfg(unix)]
#[test]
fn a_secret_lookup_that_hangs_does_not_hold_up_the_daemon() {
    // The reported case: `rbw` waits for an unlock prompt that a detached daemon
    // cannot show. The server that needs it is skipped after the bounded lookup; the
    // others are served and `up -d` does not kill the daemon.
    let sandbox = Sandbox::new("hub-secret-timeout");
    let broken = r#""broken": {
        "command": "true",
        "serve": true,
        "env": {
            "TOKEN": { "source": "command", "run": "sh", "args": ["-c", "sleep 30"] }
        }
    }"#;
    sandbox.mcp_json(&mcp_json_with(&[
        fake_server_entry("alpha", &[]),
        broken.to_string(),
    ]));

    let daemon = Daemon::start(sandbox);
    let names = tools_at(daemon.hub_port);
    assert!(names.contains(&"echo".to_string()), "{names:?}");

    let log = std::fs::read_to_string(daemon.sandbox.state_dir().join("mcp-ctl.log"))
        .expect("the daemon log is readable");
    assert!(log.contains("skipping 'broken'"), "{log}");
    assert!(log.contains("did not finish within"), "{log}");
}

#[test]
fn a_detached_daemon_and_restart_keep_the_config_override() {
    let sandbox = Sandbox::new("hub-overrides");
    // The default profile would serve nothing (and pick the default port); only the
    // override points at a file with a server in it.
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);
    sandbox.config_json(r#"{ "server": { "listen_port": 37373 } }"#);

    let work = sandbox.dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let config = work.join("config.json");
    let mut contents = mcp_json_with(&[fake_server_entry("alpha", &[])]);
    contents.insert_str(contents.len() - 1, r#", "server": { "listen_port": 0 }"#);
    std::fs::write(&config, contents).unwrap();

    let config_arg = config.to_string_lossy().to_string();
    let daemon = Daemon::start_with(
        sandbox,
        &[
            "--config",
            &config_arg,
            "up",
            "-d",
            "--no-tunnel",
            "--no-auth",
        ],
    );
    assert_ne!(
        daemon.hub_port, 37373,
        "the daemon must have read the override config, not the default one"
    );

    let tools = daemon.post(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }));
    let names: Vec<String> = tools.json()["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_string))
        .collect();
    assert!(
        names.contains(&"echo".to_string()),
        "the daemon must have read the override catalogue: {names:?}"
    );

    // Restart is the same code path the tray uses; it must rebuild the same command.
    let restarted = daemon.sandbox.run(&[
        "--config",
        &config_arg,
        "restart",
        "--no-tunnel",
        "--no-auth",
    ]);
    assert!(
        restarted.status.success(),
        "restart failed: {}",
        String::from_utf8_lossy(&restarted.stderr)
    );

    let hub_port = read_hub_port(&daemon.sandbox);
    let tools = http(
        hub_port,
        "POST",
        "/mcp",
        Some(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }).to_string()),
        &[],
    );
    assert_eq!(tools.status, 200, "{}", tools.body);
    assert!(
        tools.body.contains("echo"),
        "the restarted daemon must serve the override catalogue: {}",
        tools.body
    );
}

#[test]
fn backends_honor_cwd_and_env_clear() {
    let sandbox = Sandbox::new("hub-cwd");
    let workdir = sandbox.dir.join("workdir");
    std::fs::create_dir_all(&workdir).unwrap();
    let cwd_file = sandbox.dir.join("cwd.txt");
    let env_file = sandbox.dir.join("env.txt");

    let command = json_string(env!("CARGO_BIN_EXE_mcp-fake-server"));
    let entry = format!(
        r#""alpha": {{
            "command": {command},
            "args": ["--cwd-file", {}, "--env-file", {}],
            "cwd": {},
            "env_clear": true,
            "env": {{ "MCP_CTL_TEST_SET": "yes" }},
            "serve": true
        }}"#,
        json_string(&cwd_file.to_string_lossy()),
        json_string(&env_file.to_string_lossy()),
        json_string(&workdir.to_string_lossy()),
    );
    sandbox.mcp_json(&mcp_json_with(&[entry]));

    let output = sandbox
        .command()
        .env("MCP_CTL_TEST_LEAK", "leaked")
        .args(["up", "-d", "--no-tunnel", "--no-auth", "--port=0"])
        .output()
        .expect("run the mcp-ctl binary");
    assert!(
        output.status.success(),
        "up -d failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let daemon = Daemon {
        hub_port: read_hub_port(&sandbox),
        sandbox,
    };

    let recorded_cwd = wait_for_text(&cwd_file, Duration::from_secs(10));
    assert_eq!(
        std::fs::canonicalize(recorded_cwd.trim()).unwrap(),
        std::fs::canonicalize(&workdir).unwrap(),
        "the backend must start in its configured cwd"
    );

    let environment = wait_for_text(&env_file, Duration::from_secs(10));
    assert!(
        environment.contains("MCP_CTL_TEST_SET=yes"),
        "the configured env must be visible: {environment}"
    );
    assert!(
        !environment.contains("MCP_CTL_TEST_LEAK"),
        "env_clear must hide the daemon's environment: {environment}"
    );

    drop(daemon);
}

#[test]
fn run_honors_cwd_and_env_clear() {
    let sandbox = Sandbox::new("run-cwd");
    let workdir = sandbox.dir.join("workdir");
    std::fs::create_dir_all(&workdir).unwrap();
    let cwd_file = sandbox.dir.join("cwd.txt");
    let env_file = sandbox.dir.join("env.txt");

    let command = json_string(env!("CARGO_BIN_EXE_mcp-fake-server"));
    let entry = format!(
        r#""alpha": {{
            "command": {command},
            "args": ["--cwd-file", {}, "--env-file", {}],
            "cwd": {},
            "env_clear": true,
            "env": {{ "MCP_CTL_TEST_SET": "yes" }}
        }}"#,
        json_string(&cwd_file.to_string_lossy()),
        json_string(&env_file.to_string_lossy()),
        json_string(&workdir.to_string_lossy()),
    );
    sandbox.mcp_json(&mcp_json_with(&[entry]));

    let mut child = sandbox
        .command()
        .env("MCP_CTL_TEST_LEAK", "leaked")
        .args(["run", "alpha"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run mcp-ctl run");

    let recorded_cwd = wait_for_text(&cwd_file, Duration::from_secs(10));
    let environment = wait_for_text(&env_file, Duration::from_secs(10));

    // Closing stdin is the protocol's shutdown signal; the fake server exits cleanly.
    drop(child.stdin.take());
    let status = child.wait().expect("wait for mcp-ctl run");
    assert!(status.success(), "mcp-ctl run exited with {status}");

    assert_eq!(
        std::fs::canonicalize(recorded_cwd.trim()).unwrap(),
        std::fs::canonicalize(&workdir).unwrap()
    );
    assert!(
        environment.contains("MCP_CTL_TEST_SET=yes"),
        "{environment}"
    );
    assert!(!environment.contains("MCP_CTL_TEST_LEAK"), "{environment}");
}

/// Wait for a file to exist and return its contents.
fn wait_for_text(path: &std::path::Path, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path) {
            return text;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("{} was not written within the timeout", path.display());
}
