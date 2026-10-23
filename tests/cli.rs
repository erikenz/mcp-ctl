//! End-to-end tests for the command line surface.

mod common;

use common::Sandbox;

#[test]
fn help_and_version_work_without_any_configuration() {
    let sandbox = Sandbox::new("cli-help");

    let help = sandbox.run(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("mcp-ctl"));

    let version = sandbox.run(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("mcp-ctl"));
}

#[test]
fn init_writes_the_profile_and_keeps_it_afterwards() {
    let sandbox = Sandbox::new("cli-init");

    let first = sandbox.run(&["init"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );

    let config_json = sandbox.config_dir.join("config.json");
    let env_file = sandbox.config_dir.join(".env");
    assert!(config_json.is_file(), "init should write config.json");
    assert!(env_file.is_file(), "init should write .env");
    // The template must be valid JSON that mcp-ctl itself can read back.
    let _ = sandbox.run(&["list"]);

    let before = std::fs::read_to_string(&config_json).unwrap();
    let second = sandbox.run(&["init"]);
    assert!(second.status.success());
    assert_eq!(before, std::fs::read_to_string(&config_json).unwrap());

    // A profile file can hold server environments and .env holds secrets: owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&config_json, &env_file] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} should be owner-only", path.display());
        }
    }

    // The generated catalogue must not publish anything until the user opts in.
    let up = sandbox.run(&["up"]);
    assert!(!up.status.success(), "a fresh template serves nothing");
    assert!(
        String::from_utf8_lossy(&up.stderr).contains("no servers to serve"),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
}

#[test]
fn list_reports_commands_and_flags() {
    let sandbox = Sandbox::new("cli-list");
    sandbox.mcp_json(
        r#"{"mcpServers":{
            "alpha":{"command":"true","args":["--flag"],"serve":true},
            "beta":{"url":"https://example.test/mcp"},
            "gamma":{"command":"true","enabled":false,"prefix":"g"}
        }}"#,
    );

    let output = sandbox.run(&["list"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alpha [serve]: true --flag"), "{stdout}");
    assert!(
        stdout.contains("beta [remote]: remote https://example.test/mcp"),
        "{stdout}"
    );
    assert!(stdout.contains("gamma [disabled, prefix: g]"), "{stdout}");
}

#[test]
fn a_config_typo_is_reported_instead_of_ignored() {
    let sandbox = Sandbox::new("cli-typo");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);
    sandbox.config_json(r#"{"server":{"listen_port":1,"proxy_portt":1234}}"#);

    let output = sandbox.run(&["list"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("proxy_portt"), "{stderr}");
}

#[test]
fn unusable_server_definitions_are_reported_by_run() {
    let sandbox = Sandbox::new("cli-run");
    sandbox.mcp_json(
        r#"{"mcpServers":{
            "gone":{"command":"true","enabled":false},
            "remote":{"url":"https://example.test/mcp"}
        }}"#,
    );

    let disabled = sandbox.run(&["run", "gone"]);
    assert!(!disabled.status.success());
    assert!(String::from_utf8_lossy(&disabled.stderr).contains("disabled"));

    let remote = sandbox.run(&["run", "remote"]);
    assert!(!remote.status.success());
    assert!(String::from_utf8_lossy(&remote.stderr).contains("not a local stdio server"));

    let missing = sandbox.run(&["run", "nope"]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("unknown server"));
}

#[test]
fn check_accepts_a_relative_command_path() {
    let sandbox = Sandbox::new("cli-check-relpath");
    let bin = sandbox.dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let tool = bin.join("tool");
    std::fs::write(&tool, "").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    sandbox.mcp_json(r#"{"mcpServers":{"rel":{"command":"./bin/tool","serve":true}}}"#);
    // Port 0 keeps the check independent of whatever the machine already serves.
    sandbox.config_json(r#"{ "server": { "listen_port": 0 } }"#);

    // A relative command resolves against mcp-ctl's working directory, exactly as
    // `up` and `run` start it, so `check` must not report it as "not on PATH".
    let output = sandbox
        .command()
        .current_dir(sandbox.dir.path())
        .args(["check"])
        .output()
        .expect("run mcp-ctl check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "check should accept ./bin/tool:\n{stdout}\n{stderr}"
    );
    assert!(!stdout.contains("not on PATH"), "{stdout}");
}

#[test]
fn profiles_keep_their_own_files() {
    let sandbox = Sandbox::new("cli-profile");
    let init = sandbox.run(&["--profile", "work", "init"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let profile_file = sandbox.config_dir.join("config.work.json");
    assert!(profile_file.is_file());
    assert!(
        !sandbox.config_dir.join("config.json").exists(),
        "the default profile stays untouched"
    );

    // `list` reads the profile's catalogue, and the default profile does not see it.
    std::fs::write(
        &profile_file,
        r#"{"mcpServers":{"only-here":{"command":"true","serve":true}}}"#,
    )
    .unwrap();
    let listed = sandbox.run(&["--profile", "work", "list"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("only-here"));
    let default = sandbox.run(&["list"]);
    assert!(
        !String::from_utf8_lossy(&default.stdout).contains("only-here"),
        "the default profile must not read another profile's catalogue"
    );

    // `MCP_CTL_PROFILE` does the same for scripts and editors.
    let env_listed = sandbox
        .command()
        .env("MCP_CTL_PROFILE", "work")
        .args(["list"])
        .output()
        .expect("run the mcp-ctl binary");
    assert!(String::from_utf8_lossy(&env_listed.stdout).contains("only-here"));

    // A profile name is one file name.
    let bad = sandbox.run(&["--profile", "../escape", "list"]);
    assert!(!bad.status.success());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("not a valid profile name"),
        "{}",
        String::from_utf8_lossy(&bad.stderr)
    );
}

#[test]
fn status_lists_every_profile_and_one_on_request() {
    let sandbox = Sandbox::new("cli-profiles-status");
    sandbox.mcp_json(r#"{"mcpServers":{"alpha":{"command":"true","serve":true}}}"#);
    sandbox.config_json(r#"{ "server": { "listen_port": 0 } }"#);
    let work = sandbox.config_dir.join("config.work.json");
    std::fs::write(
        &work,
        r#"{"mcpServers":{"beta":{"command":"true","serve":true},"gamma":{"command":"true"}},"server":{"listen_port":0}}"#,
    )
    .unwrap();

    let all = sandbox.run(&["status"]);
    let stdout = String::from_utf8_lossy(&all.stdout);
    assert!(all.status.success(), "{stdout}");
    assert!(stdout.contains("default"), "{stdout}");
    assert!(stdout.contains("work"), "{stdout}");
    assert!(stdout.contains("2 server(s) configured"), "{stdout}");

    let one = sandbox.run(&["status", "work"]);
    let stdout = String::from_utf8_lossy(&one.stdout);
    assert!(stdout.contains("work"), "{stdout}");
    assert!(!stdout.contains("default"), "{stdout}");

    // The machine-readable form lists the same profiles.
    let json = sandbox.run(&["status", "--json"]);
    let parsed: serde_json::Value = serde_json::from_slice(&json.stdout).expect("status --json");
    let names: Vec<&str> = parsed["profiles"]
        .as_array()
        .expect("a profiles array")
        .iter()
        .filter_map(|profile| profile["profile"].as_str())
        .collect();
    assert_eq!(names, vec!["default", "work"]);
}

#[test]
fn check_resolves_a_secret_from_the_env_file() {
    let sandbox = Sandbox::new("cli-env-file");
    sandbox.mcp_json(
        r#"{"mcpServers":{"alpha":{"command":"true","serve":true,"env":{"API_KEY":{"source":"env","name":"MCP_CTL_TEST_API_KEY"}}}}}"#,
    );
    sandbox.env_file("MCP_CTL_TEST_API_KEY=from-the-file\n");
    // Port 0 keeps the check independent of whatever the machine already serves.
    sandbox.config_json(r#"{ "server": { "listen_port": 0 } }"#);

    let output = sandbox.run(&["check"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("MCP_CTL_TEST_API_KEY"), "{stdout}");

    // A value the shell exports wins over the file, and a missing one is reported by name.
    sandbox.env_file("SOMETHING_ELSE=1\n");
    let output = sandbox.run(&["check"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "{stdout}");
    assert!(stdout.contains("MCP_CTL_TEST_API_KEY"), "{stdout}");
}

#[test]
fn a_literal_password_in_the_profile_file_is_refused() {
    let sandbox = Sandbox::new("cli-literal-auth");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);
    sandbox.config_json(r#"{ "auth": { "password": "hunter2" } }"#);

    let output = sandbox.run(&["list"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("auth.password"), "{stderr}");
    assert!(stderr.contains(".env"), "{stderr}");
}

#[test]
fn status_reports_nothing_running_on_a_fresh_install() {
    let sandbox = Sandbox::new("cli-status");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);

    let output = sandbox.run(&["status"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("not running"));

    let stop = sandbox.run(&["stop"]);
    assert!(stop.status.success());
    assert!(String::from_utf8_lossy(&stop.stdout).contains("not running"));
}

#[test]
fn check_accepts_a_configured_auth_proxy() {
    let sandbox = Sandbox::new("cli-check-proxy");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);
    let proxy = sandbox.dir.join("mcp-auth-proxy-dummy");
    std::fs::write(&proxy, "").unwrap();
    sandbox.config_json(&format!(
        r#"{{
            "server": {{
                "listen_port": 0,
                "proxy_port": {proxy_port},
                "external_url": "https://device.example.ts.net",
                "auth_proxy_path": {proxy_path}
            }},
            "auth": {{ "password": {{ "source": "env", "name": "MCP_CTL_TEST_PASSWORD" }} }}
        }}"#,
        proxy_path = common::json_string(&proxy.to_string_lossy()),
        proxy_port = free_port(),
    ));
    sandbox.env_file("MCP_CTL_TEST_PASSWORD=x\n");

    let output = sandbox.run(&["check"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "check should accept the configured proxy:\n{stdout}\n{stderr}"
    );
    assert!(stdout.contains("mcp-auth-proxy"), "{stdout}");
    assert!(!stdout.contains("external_url is"), "{stdout}");
}

#[test]
fn check_reports_auth_without_any_public_url() {
    let sandbox = Sandbox::new("cli-check-nourl");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);
    sandbox.config_json(&format!(
        r#"{{
            "server": {{ "listen_port": 0, "proxy_port": {} }},
            "auth": {{ "password": {{ "source": "env", "name": "MCP_CTL_TEST_PASSWORD" }} }}
        }}"#,
        free_port()
    ));
    sandbox.env_file("MCP_CTL_TEST_PASSWORD=x\n");

    let output = sandbox.run(&["check"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("external_url"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn check_accepts_a_public_url_detected_from_tailscale() {
    let sandbox = Sandbox::new("cli-check-tailscale");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);
    // A stand-in `tailscale` earlier on PATH than the real one, if any.
    let bin = sandbox.dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let tailscale = bin.join("tailscale");
    std::fs::write(
        &tailscale,
        "#!/bin/sh\nprintf '%s' '{\"Self\":{\"DNSName\":\"device.example.ts.net.\"}}'\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tailscale, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The point of this test is URL detection, so supply the proxy the auth config
    // implies; CI does not have mcp-auth-proxy installed.
    let proxy = sandbox.dir.join("mcp-auth-proxy-dummy");
    std::fs::write(&proxy, "").unwrap();
    sandbox.config_json(&format!(
        r#"{{
            "server": {{
                "listen_port": 0,
                "proxy_port": {proxy_port},
                "auth_proxy_path": {proxy_path}
            }},
            "tunnel": {{ "provider": "tailscale", "auto_start": false }},
            "auth": {{ "password": {{ "source": "env", "name": "MCP_CTL_TEST_PASSWORD" }} }}
        }}"#,
        proxy_path = common::json_string(&proxy.to_string_lossy()),
        proxy_port = free_port()
    ));
    sandbox.env_file("MCP_CTL_TEST_PASSWORD=x\n");

    let path = std::env::var("PATH").unwrap_or_default();
    let output = sandbox
        .command()
        .env("PATH", format!("{}:{path}", bin.display()))
        .args(["check"])
        .output()
        .expect("run mcp-ctl check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "check should accept the URL Tailscale reports:\n{stdout}\n{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn check_finds_the_auth_proxy_in_local_bin() {
    let sandbox = Sandbox::new("cli-check-localbin");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);
    let home = sandbox.dir.join("home");
    let local_bin = home.join(".local").join("bin");
    std::fs::create_dir_all(&local_bin).unwrap();
    std::fs::write(local_bin.join("mcp-auth-proxy"), "").unwrap();
    sandbox.config_json(&format!(
        r#"{{
            "server": {{
                "listen_port": 0,
                "proxy_port": {},
                "external_url": "https://device.example.ts.net"
            }},
            "auth": {{ "password": {{ "source": "env", "name": "MCP_CTL_TEST_PASSWORD" }} }}
        }}"#,
        free_port()
    ));
    sandbox.env_file("MCP_CTL_TEST_PASSWORD=x\n");

    let output = sandbox
        .command()
        .env("HOME", &home)
        .args(["check"])
        .output()
        .expect("run mcp-ctl check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "check should find ~/.local/bin/mcp-auth-proxy like `up` does:\n{stdout}\n{stderr}"
    );
}

#[test]
fn check_reports_a_missing_secret_command_in_the_auth_section() {
    let sandbox = Sandbox::new("cli-check-authcmd");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);
    sandbox.config_json(
        r#"{
            "server": { "listen_port": 0 },
            "auth": {
                "password": {
                    "source": "command",
                    "run": "mcp-ctl-definitely-missing-secret-command"
                }
            }
        }"#,
    );

    let output = sandbox.run(&["check"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("mcp-ctl-definitely-missing-secret-command"),
        "{stdout}"
    );
}

#[test]
fn a_stale_state_file_is_cleaned_up() {
    let sandbox = Sandbox::new("cli-stale");
    sandbox.mcp_json(r#"{"mcpServers":{}}"#);

    let state_dir = sandbox.state_dir();
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("daemon.json"),
        r#"{"format":1,"pid":999999,"version":"0.0.0","control_port":9,"token":"stale","hub_port":1,"log_file":"none","started_at":0}"#,
    )
    .unwrap();

    let output = sandbox.run(&["status"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("not running"));
    assert!(
        !state_dir.join("daemon.json").exists(),
        "a state file that nobody answers for should be removed"
    );
}

/// An ephemeral port that is free right now, for configurations that must differ
/// from `listen_port` without colliding with a real service.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().unwrap().port()
}
