//! `mcp-ctl check`: validate the configuration and resolve every secret without starting
//! anything. This is the fast feedback loop for a config-and-secret driven tool: it is
//! better to learn that an `op://` reference is wrong here than halfway through `up`.

use anyhow::Result;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::{SocketAddr, TcpListener};

use crate::config::{Paths, ToolConfig, TunnelProvider};
use crate::exposure;
use crate::platform;
use crate::secret;
use crate::servers::{McpServer, SecretSource, SecretValue};

/// Run every check and report. Returns the number of problems found.
pub fn run(paths: &Paths, tool_config: &ToolConfig, as_json: bool) -> Result<usize> {
    let server_config = tool_config.server();
    let auth_config = tool_config.auth();
    let tunnel_config = tool_config.tunnel();

    let mut problems: Vec<String> = Vec::new();
    let mut reports: Vec<Value> = Vec::new();
    // Programs the configuration implies we will need.
    let mut needed: BTreeSet<String> = BTreeSet::new();

    let mut servers: Vec<(&String, &McpServer)> = tool_config.mcp_servers.iter().collect();
    servers.sort_by(|left, right| left.0.cmp(right.0));

    for (name, server) in servers {
        let mut findings: Vec<Value> = Vec::new();
        let mut note = None;
        let mut status = "ok";

        if !server.enabled {
            status = "skipped";
            note = Some("\"enabled\" is false".to_string());
        } else if !server.is_stdio() {
            status = "skipped";
            note = Some("only local stdio servers can be served".to_string());
        } else {
            if let Some(command) = &server.command {
                // Only a bare name is a PATH lookup worth listing under Programs. A
                // command with a separator in it is started as given, exactly as
                // `run`/`up` do, so it must not be reported as "not on PATH".
                if !is_path(command) {
                    needed.insert(command.clone());
                }
                if !command_available(command) {
                    status = "problem";
                    problems.push(format!(
                        "{name}: '{command}' was not found or is not executable"
                    ));
                }
            }

            for (key, value) in &server.env {
                let source = secret::describe(value);
                record_program(value, &mut needed);

                match secret::resolve(key, value) {
                    // The value itself is deliberately never printed, only where it came from.
                    Ok(_) => findings.push(json!({"key": key, "source": source, "ok": true})),
                    Err(error) => {
                        status = "problem";
                        problems.push(format!("{name}: {key}: {error}"));
                        findings.push(json!({
                            "key": key,
                            "source": source,
                            "ok": false,
                            "error": error.to_string()
                        }));
                    }
                }
            }
        }

        reports.push(json!({
            "name": name,
            "status": status,
            "command": server.command_line(),
            "tools": server.tools.as_ref().map(|filter| filter.describe()),
            "env_clear": server.env_clear,
            "note": note,
            "env": findings,
        }));
    }

    // What `up` would do with this configuration, and what it would refuse. The decision
    // comes from the same place `up` takes it from, so `check` cannot promise a start that
    // `up` refuses, or warn about one it allows.
    let decision = exposure::decide(
        tool_config,
        &exposure::Request {
            config_file: paths.config_file.clone(),
            ..Default::default()
        },
    );
    problems.extend(decision.refusals.iter().cloned());
    let notes: Vec<String> = decision.notes.clone();

    // Authentication secrets are only needed when authentication is enabled, but a bad
    // reference should surface here rather than in the middle of a sign-in flow.
    let use_proxy = decision.use_proxy;
    let mut auth_proxy: Option<String> = None;
    if decision.use_auth {
        for (key, value) in auth_secrets(&auth_config) {
            record_program(value, &mut needed);
            if let Err(error) = secret::resolve(key, value) {
                problems.push(format!("{key}: {error}"));
            }
        }
    }

    if use_proxy {
        // The same lookup `up` performs: configured path, PATH, then ~/.local/bin.
        match exposure::find_auth_proxy(&server_config) {
            Ok(path) => auth_proxy = Some(path),
            Err(error) => problems.push(
                error
                    .to_string()
                    .lines()
                    .next()
                    .unwrap_or("mcp-auth-proxy was not found")
                    .to_string(),
            ),
        }
    }

    if decision.use_tunnel {
        needed.insert(
            match tunnel_config.provider {
                TunnelProvider::Tailscale => "tailscale",
                TunnelProvider::Cloudflared => "cloudflared",
                TunnelProvider::None => "",
            }
            .to_string(),
        );
    }

    if !decision.bind.is_loopback() && use_proxy {
        // The auth proxy listens on loopback and is the only intended entry point.
        problems.push(format!(
            "server.bind is {}: the hub itself has no authentication, so the proxy on port {} can be bypassed",
            decision.bind, decision.proxy_port
        ));
    }

    // Ports: bind and release, which is the cheapest honest answer.
    let mut ports: Vec<Value> = Vec::new();
    if decision.hub_port != 0 {
        let address = SocketAddr::new(decision.bind, decision.hub_port);
        let free = TcpListener::bind(address).is_ok();
        if !free {
            problems.push(format!("the hub port {address} is already in use"));
        }
        ports.push(json!({"name": "hub", "address": address.to_string(), "free": free}));
    }
    if use_proxy {
        let address = auth_proxy_address(decision.proxy_port);
        let free = TcpListener::bind(address).is_ok();
        if !free {
            problems.push(format!("the auth proxy port {address} is already in use"));
        }
        ports.push(json!({"name": "auth proxy", "address": address.to_string(), "free": free}));
    }

    let mut programs: Vec<Value> = Vec::new();
    for name in &needed {
        if name.is_empty() {
            continue;
        }
        let found = platform::find_executable(name);
        let ok = found.is_some();
        if !ok {
            problems.push(format!("'{name}' is not on PATH"));
        }
        programs.push(json!({
            "name": name,
            "path": found.map(|path| path.display().to_string()),
            "ok": ok
        }));
    }
    if use_proxy {
        // Checked with the same lookup `up` uses, so PATH, ~/.local/bin and
        // server.auth_proxy_path all count as "found".
        programs.push(json!({
            "name": "mcp-auth-proxy",
            "path": auth_proxy.clone(),
            "ok": auth_proxy.is_some(),
        }));
    }

    if as_json {
        let report = json!({
            "config_dir": paths.config_dir.display().to_string(),
            "config_file": paths.config_file.display().to_string(),
            "state_dir": paths.state_dir.display().to_string(),
            "servers": reports,
            "programs": programs,
            "ports": ports,
            "problems": problems,
            "notes": notes,
        });
        outln!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        outln!("mcp-ctl check\n");

        outln!("Paths");
        outln!("  config   {}", paths.config_file.display());
        outln!("  state    {}", paths.state_dir.display());

        outln!("\nServers ({})", reports.len());
        for report in &reports {
            let marker = match report["status"].as_str().unwrap_or_default() {
                "ok" => "✓",
                "problem" => "✗",
                _ => "-",
            };
            outln!(
                "  {marker} {:<18} {}",
                report["name"].as_str().unwrap_or_default(),
                report["command"].as_str().unwrap_or_default()
            );
            if let Some(tools) = report["tools"].as_str() {
                outln!("      tools: {tools}");
            }
            if report["env_clear"].as_bool().unwrap_or(false) {
                outln!("      starts with an empty environment");
            }
            for finding in report["env"].as_array().into_iter().flatten() {
                let mark = if finding["ok"].as_bool().unwrap_or(false) {
                    "✓"
                } else {
                    "✗"
                };
                let key = finding["key"].as_str().unwrap_or_default();
                let source = finding["source"].as_str().unwrap_or_default();
                match finding["error"].as_str() {
                    Some(error) => outln!("      {mark} env {key} ← {source}: {error}"),
                    None => outln!("      {mark} env {key} ← {source}"),
                }
            }
            if let Some(note) = report["note"].as_str() {
                outln!("      {note}");
            }
        }

        if !programs.is_empty() {
            outln!("\nPrograms");
            for program in &programs {
                let mark = if program["ok"].as_bool().unwrap_or(false) {
                    "✓"
                } else {
                    "✗"
                };
                outln!(
                    "  {mark} {:<18} {}",
                    program["name"].as_str().unwrap_or_default(),
                    program["path"].as_str().unwrap_or("not found")
                );
            }
        }

        if !ports.is_empty() {
            outln!("\nPorts");
            for port in &ports {
                let mark = if port["free"].as_bool().unwrap_or(false) {
                    "✓"
                } else {
                    "✗"
                };
                outln!(
                    "  {mark} {:<18} {} free",
                    port["name"].as_str().unwrap_or_default(),
                    port["address"].as_str().unwrap_or_default()
                );
            }
        }

        if problems.is_empty() {
            outln!("\nNo problems found.");
        } else {
            outln!("\nProblems ({})", problems.len());
            for problem in &problems {
                outln!("  - {problem}");
            }
        }

        if !notes.is_empty() {
            outln!("\nNotes ({})", notes.len());
            for note in &notes {
                outln!("  - {note}");
            }
        }
    }

    Ok(problems.len())
}

/// The secrets in the `auth` section, as `(name, value)` pairs.
fn auth_secrets(auth: &crate::config::AuthConfig) -> Vec<(&'static str, &SecretValue)> {
    let mut secrets = Vec::new();
    if let Some(value) = &auth.password {
        secrets.push(("auth.password", value));
    }
    if let Some((id, secret)) = auth.github() {
        secrets.push(("auth.github_client_id", id));
        secrets.push(("auth.github_client_secret", secret));
    }
    if let Some((id, secret)) = auth.google() {
        secrets.push(("auth.google_client_id", id));
        secrets.push(("auth.google_client_secret", secret));
    }
    if let Some(value) = &auth.bearer_token {
        secrets.push(("auth.bearer_token", value));
    }
    secrets
}

/// Record the program a secret source will need, so the same list covers server
/// environments and the `auth` section.
fn record_program(value: &SecretValue, needed: &mut BTreeSet<String>) {
    let SecretValue::Source(source) = value else {
        return;
    };
    match source {
        SecretSource::Bitwarden { .. } => {
            needed.insert("rbw".to_string());
        }
        SecretSource::OnePassword { .. } => {
            needed.insert("op".to_string());
        }
        SecretSource::Command { run, .. } => {
            needed.insert(run.clone());
        }
        _ => {}
    }
}

/// The address `start_auth_proxy` binds: always loopback, never `server.bind`.
fn auth_proxy_address(proxy_port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], proxy_port))
}

/// Does this command name a file rather than a program to look up on PATH?
fn is_path(command: &str) -> bool {
    command.contains('/') || command.contains('\\')
}

/// Is this command runnable? A path is checked directly, a bare name is looked up on PATH.
fn command_available(command: &str) -> bool {
    if is_path(command) {
        platform::is_executable_file(std::path::Path::new(command))
    } else {
        platform::find_executable(command).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_commands_are_not_available() {
        assert!(!command_available("mcp-ctl-definitely-not-a-real-program"));
        assert!(!command_available("/nonexistent/directory/program"));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_without_the_executable_bit_is_not_available() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("mcp-ctl-plain-{}", std::process::id()));
        std::fs::write(&path, "").unwrap();
        assert!(!command_available(&path.to_string_lossy()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(command_available(&path.to_string_lossy()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_command_with_a_separator_is_a_path_not_a_path_lookup() {
        assert!(is_path("/usr/bin/node"));
        assert!(is_path("./bin/tool"));
        assert!(is_path("bin\\tool.exe"));
        assert!(!is_path("npx"));
    }

    #[test]
    fn a_bound_port_is_reported_as_in_use() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        assert!(TcpListener::bind(address).is_err());
    }

    #[test]
    fn the_auth_proxy_port_is_checked_on_loopback() {
        let address = auth_proxy_address(18080);
        assert_eq!(address.ip().to_string(), "127.0.0.1");
        assert_eq!(address.port(), 18080);
    }
}
