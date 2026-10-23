//! What `mcp-ctl up` will do with the current configuration, and what it would refuse.
//!
//! `up` enforces this decision, `mcp-ctl check` prints it. Both used to work it out
//! separately, which is how they drifted: `check` promised a start that `up` refused, or
//! warned about one it allowed. One rule, computed once, in one place.

use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

use crate::config::{ServerConfig, ToolConfig, TunnelProvider};

/// The command-line choices that change what `up` will do.
#[derive(Clone, Debug, Default)]
pub struct Request {
    /// `--bind`
    pub bind: Option<IpAddr>,
    /// `--port`
    pub port: Option<u16>,
    /// `--proxy-port`
    pub proxy_port: Option<u16>,
    /// `--external-url`
    pub external_url: Option<String>,
    /// `--no-auth`
    pub no_auth: bool,
    /// `--no-tunnel`
    pub no_tunnel: bool,
    /// `--allow-unauthenticated-exposure`
    pub allow_unauthenticated_exposure: bool,
    /// The settings file this decision came from, named by the messages that point at it.
    pub config_file: PathBuf,
}

/// The decided plan: what will run, and why `up` would refuse.
#[derive(Clone, Debug)]
pub struct Decision {
    pub bind: IpAddr,
    pub hub_port: u16,
    pub proxy_port: u16,
    pub external_url: Option<String>,
    /// The external auth proxy will be started.
    pub use_proxy: bool,
    /// A static bearer token guards the hub.
    pub use_bearer: bool,
    /// Any authentication at all.
    pub use_auth: bool,
    /// The tunnel will be started.
    pub use_tunnel: bool,
    /// Why `up` refuses to start, in the order it would report them.
    pub refusals: Vec<String>,
    /// What `up` warns about without refusing.
    pub notes: Vec<String>,
}

/// Work out the plan, and everything `up` would refuse about it.
pub fn decide(config: &ToolConfig, request: &Request) -> Decision {
    let server = config.server();
    let auth = config.auth();
    let tunnel = config.tunnel();

    let bind = request.bind.unwrap_or(server.bind);
    let hub_port = request.port.unwrap_or(server.listen_port);
    let proxy_port = request.proxy_port.unwrap_or(server.proxy_port);
    let external_url = request
        .external_url
        .clone()
        .or_else(|| server.external_url())
        .or_else(|| public_url_from_tailscale(tunnel.provider));

    // Two independent mechanisms: `mcp-auth-proxy` for OAuth/password sign-in, and a
    // static bearer token the hub checks itself. `--no-auth` disables both.
    let use_proxy = !request.no_auth && auth.proxy_enabled();
    let use_bearer = !request.no_auth && auth.bearer_token.is_some();
    let use_auth = use_proxy || use_bearer;
    let use_tunnel =
        !request.no_tunnel && tunnel.auto_start && tunnel.provider != TunnelProvider::None;

    let mut refusals = Vec::new();
    let mut notes = Vec::new();
    let config_file = request.config_file.display();

    if request.no_auth && auth.is_enabled() {
        notes.push("warning: authentication is configured but disabled by --no-auth".to_string());
    }

    if use_proxy && external_url.is_none() {
        refusals.push(format!(
            "authentication is enabled but no public URL is configured.\n\
             The auth proxy needs to know the URL clients will use, otherwise sign-in \
             callbacks point at localhost and fail.\n\
             Set server.external_url in {config_file} (or pass --external-url), or run without \
             authentication using --no-auth."
        ));
    }

    // One rule for exposure: an unauthenticated hub gives anything that can reach it every
    // tool of every served server, so that needs an explicit opt-in. A bearer token
    // authenticates the hub itself and lifts the rule.
    if !use_auth && !request.allow_unauthenticated_exposure {
        if !bind.is_loopback() {
            refusals.push(format!(
                "refusing to bind the unauthenticated hub to {bind}.\n\
                 Anything that can reach this machine could call every tool of every served server.\n\
                 Configure auth.bearer_token or auth.password in {config_file}, keep the loopback \
                 default, or pass --allow-unauthenticated-exposure if that is really what you want."
            ));
        }
        if use_tunnel {
            refusals.push(format!(
                "refusing to publish an unauthenticated hub.\n\
                 The tunnel would expose every tool of every served server to the internet with no \
                 authentication at all.\n\
                 Configure auth.bearer_token or auth.password in {config_file}, run with --no-tunnel \
                 to stay local, or pass --allow-unauthenticated-exposure if that is really what you want."
            ));
        }
    }

    Decision {
        bind,
        hub_port,
        proxy_port,
        external_url,
        use_proxy,
        use_bearer,
        use_auth,
        use_tunnel,
        refusals,
        notes,
    }
}

/// This machine's public URL, when Tailscale can name it.
///
/// Only Tailscale can: a Cloudflare quick tunnel picks a random hostname and prints it
/// itself, so that one has to be configured.
fn public_url_from_tailscale(provider: TunnelProvider) -> Option<String> {
    if provider != TunnelProvider::Tailscale {
        return None;
    }
    detect_tailscale_external_url().ok()
}

/// Ask Tailscale for this machine's public DNS name.
pub fn detect_tailscale_external_url() -> Result<String> {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .context("failed to run `tailscale status --json`")?;
    if !output.status.success() {
        bail!("`tailscale status --json` failed");
    }
    let status: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("`tailscale status --json` did not return JSON")?;
    let dns_name = status
        .get("Self")
        .and_then(|this| this.get("DNSName"))
        .and_then(|name| name.as_str())
        .context("tailscale did not report a DNS name for this machine")?;
    Ok(format!("https://{}", dns_name.trim_end_matches('.')))
}

/// Locate `mcp-auth-proxy`: configured path, then PATH, then ~/.local/bin.
///
/// `check` uses the same lookup, so a proxy that `up` can find is never reported as
/// missing (and vice versa).
pub fn find_auth_proxy(server_config: &ServerConfig) -> Result<String> {
    if let Some(path) = &server_config.auth_proxy_path {
        if path.is_file() {
            return Ok(path.to_string_lossy().to_string());
        }
        bail!("server.auth_proxy_path '{}' does not exist", path.display());
    }

    if let Some(path) = crate::platform::find_executable("mcp-auth-proxy") {
        return Ok(path.to_string_lossy().to_string());
    }

    if let Some(home) = dirs::home_dir() {
        let candidate = home.join(".local").join("bin").join("mcp-auth-proxy");
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().to_string());
        }
    }

    bail!(
        "mcp-auth-proxy was not found.\n\
         mcp-ctl uses it as the OAuth 2.1 / password gateway in front of the hub.\n\
         Install it from https://github.com/sigbit/mcp-auth-proxy/releases (into \
         ~/.local/bin or anywhere on PATH), set server.auth_proxy_path in config.json, \
         or run with --no-auth for local use only."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: &str) -> ToolConfig {
        serde_json::from_str(json).expect("valid config.json")
    }

    fn request() -> Request {
        Request {
            config_file: PathBuf::from("/home/you/.config/mcp-ctl/config.json"),
            ..Default::default()
        }
    }

    #[test]
    fn a_loopback_hub_without_authentication_starts() {
        let decision = decide(&config("{}"), &request());
        assert!(decision.refusals.is_empty(), "{:?}", decision.refusals);
        assert!(!decision.use_auth);
        assert!(!decision.use_proxy);
        assert!(!decision.use_tunnel);
        assert_eq!(decision.hub_port, crate::config::default_hub_port());
    }

    #[test]
    fn a_non_loopback_hub_without_authentication_is_refused() {
        let decision = decide(&config(r#"{"server": {"bind": "0.0.0.0"}}"#), &request());
        assert_eq!(decision.refusals.len(), 1);
        assert!(
            decision.refusals[0].contains("refusing to bind"),
            "{}",
            decision.refusals[0]
        );
        // The message points at the file the decision came from.
        assert!(decision.refusals[0].contains("config.json"));
    }

    #[test]
    fn a_tunnel_without_authentication_is_refused_unless_allowed() {
        let settings = r#"{"tunnel": {"provider": "tailscale"}}"#;
        let refused = decide(&config(settings), &request());
        assert_eq!(refused.refusals.len(), 1);
        assert!(
            refused.refusals[0].contains("refusing to publish"),
            "{}",
            refused.refusals[0]
        );

        let allowed = decide(
            &config(settings),
            &Request {
                allow_unauthenticated_exposure: true,
                ..request()
            },
        );
        assert!(allowed.refusals.is_empty(), "{:?}", allowed.refusals);
        assert!(allowed.use_tunnel);
    }

    #[test]
    fn a_proxy_without_a_public_url_is_refused() {
        let decision = decide(
            &config(
                r#"{"auth": {"password": {"source": "env", "name": "MCP_CTL_AUTH_PASSWORD"}}}"#,
            ),
            &request(),
        );
        assert!(decision.use_proxy);
        assert_eq!(decision.refusals.len(), 1);
        assert!(
            decision.refusals[0].contains("no public URL"),
            "{}",
            decision.refusals[0]
        );

        // The same configuration with a public URL is fine.
        let decision = decide(
            &config(
                r#"{
                    "server": {"external_url": "https://laptop.example.ts.net"},
                    "auth": {"password": {"source": "env", "name": "MCP_CTL_AUTH_PASSWORD"}}
                }"#,
            ),
            &request(),
        );
        assert!(decision.refusals.is_empty(), "{:?}", decision.refusals);
        assert_eq!(
            decision.external_url.as_deref(),
            Some("https://laptop.example.ts.net")
        );
    }

    #[test]
    fn a_bearer_token_alone_authenticates_the_hub() {
        let decision = decide(
            &config(
                r#"{
                    "server": {"bind": "0.0.0.0"},
                    "auth": {"bearer_token": {"source": "env", "name": "MCP_CTL_BEARER_TOKEN"}}
                }"#,
            ),
            &request(),
        );
        assert!(decision.use_bearer);
        assert!(decision.use_auth);
        assert!(!decision.use_proxy);
        assert!(decision.refusals.is_empty(), "{:?}", decision.refusals);
    }

    #[test]
    fn no_auth_disables_both_mechanisms_and_says_so() {
        let decision = decide(
            &config(
                r#"{"auth": {"password": {"source": "env", "name": "MCP_CTL_AUTH_PASSWORD"}}, "server": {"external_url": "https://laptop.example.ts.net"}}"#,
            ),
            &Request {
                no_auth: true,
                ..request()
            },
        );
        assert!(!decision.use_auth);
        assert!(!decision.use_proxy);
        assert_eq!(decision.notes.len(), 1);
        assert!(
            decision.notes[0].contains("--no-auth"),
            "{}",
            decision.notes[0]
        );
    }

    #[test]
    fn no_tunnel_keeps_the_service_local() {
        let decision = decide(
            &config(r#"{"tunnel": {"provider": "cloudflared"}}"#),
            &Request {
                no_tunnel: true,
                ..request()
            },
        );
        assert!(!decision.use_tunnel);
        assert!(decision.refusals.is_empty(), "{:?}", decision.refusals);
    }

    #[test]
    fn the_command_line_wins_over_the_settings_file() {
        let decision = decide(
            &config(r#"{"server": {"bind": "0.0.0.0", "listen_port": 37373}}"#),
            &Request {
                bind: Some("127.0.0.1".parse().unwrap()),
                port: Some(0),
                ..request()
            },
        );
        assert!(decision.bind.is_loopback());
        assert_eq!(decision.hub_port, 0);
        assert!(decision.refusals.is_empty(), "{:?}", decision.refusals);
    }
}
