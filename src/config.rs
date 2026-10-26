use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::platform;
use crate::servers::{McpServer, SecretValue};

/// The profile file `mcp-ctl init` writes: mcp-ctl's settings plus the server catalogue.
///
/// One file holds both, so "which servers are defined?" has exactly one answer per profile.
pub const DEFAULT_CONFIG_JSON: &str = r#"{
    "$schema": "https://raw.githubusercontent.com/erikenz/mcp-ctl/main/schema/config.schema.json",
    "server": {
        "bind": "127.0.0.1",
        "listen_port": 37373,
        "proxy_port": 8080,
        "tool_timeout_secs": 300,
        "allowed_origins": []
    },
    "tunnel": {
        "provider": "none"
    },
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
            "serve": false
        },
        "github": {
            "command": "docker",
            "args": [
                "run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
                "ghcr.io/github/github-mcp-server"
            ],
            "env": {
                "GITHUB_PERSONAL_ACCESS_TOKEN": { "source": "env", "name": "GITHUB_TOKEN" }
            }
        }
    }
}"#;

/// The `.env` file `mcp-ctl init` writes next to it, owner-only and empty.
///
/// Secrets that belong in a file go here, not in the profile: a password in `config.json` is one
/// copy-paste away from being shared, and `mcp-ctl` refuses literal auth secrets for that reason.
pub const DEFAULT_ENV_FILE: &str = r#"# Secrets for {"source": "env"} entries in the profile files.
# mcp-ctl reads this file itself; it is never exported to the servers it runs, and the
# shell environment wins over these values.
#
# MCP_CTL_AUTH_PASSWORD=choose-a-strong-password
"#;

/// A profile file: mcp-ctl's settings and the server catalogue, in one place.
///
/// Unknown keys are rejected at this level: a typo such as `"proxy_portt"` should be reported
/// when the file is read, not silently ignored until something misbehaves. Unknown keys *inside
/// a server entry* are ignored, because those entries are the shape every MCP client uses.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolConfig {
    /// Accepted so editors can point at a JSON schema; mcp-ctl ignores it.
    #[serde(rename = "$schema", default)]
    #[allow(dead_code)]
    pub schema: Option<String>,
    /// The servers this profile manages.
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: BTreeMap<String, McpServer>,
    /// Server settings for hub and proxy ports.
    #[serde(default)]
    pub server: Option<ServerConfig>,
    /// Authentication settings for remote connections (Delta, etc.).
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    /// Tunnel settings (Tailscale, Cloudflared, etc.).
    #[serde(default)]
    pub tunnel: Option<TunnelConfig>,
    /// Tray icon settings.
    #[serde(default)]
    pub tray: Option<TrayConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address the local MCP endpoint binds to. Loopback by default: the hub has no
    /// authentication of its own and can call every tool of every served server.
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default = "default_hub_port")]
    pub listen_port: u16,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default)]
    pub external_url: Option<String>,
    /// Optional path to the `mcp-auth-proxy` executable.
    #[serde(default)]
    pub auth_proxy_path: Option<PathBuf>,
    /// Timeout for a single backend tool call, in seconds. 0 disables the timeout.
    #[serde(default = "default_tool_timeout_secs")]
    pub tool_timeout_secs: u64,
    /// Extra browser origins allowed to call the hub. An origin on a host mcp-ctl is served on
    /// (loopback, `bind`, `external_url`) is allowed without being listed; anything else is not.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            listen_port: default_hub_port(),
            proxy_port: default_proxy_port(),
            external_url: None,
            auth_proxy_path: None,
            tool_timeout_secs: default_tool_timeout_secs(),
            allowed_origins: Vec::new(),
        }
    }
}

impl ServerConfig {
    /// `external_url` without a trailing slash, ready to be joined with `/mcp`.
    pub fn external_url(&self) -> Option<String> {
        self.external_url
            .as_ref()
            .map(|url| url.trim_end_matches('/').to_string())
    }

    /// The backend tool-call timeout; `None` means "wait as long as it takes".
    pub fn tool_timeout(&self) -> Option<Duration> {
        if self.tool_timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.tool_timeout_secs))
        }
    }
}

pub fn default_bind() -> IpAddr {
    // 127.0.0.1: the hub is unauthenticated, so it must not be reachable from the
    // network unless the operator asks for that explicitly.
    IpAddr::from([127, 0, 0, 1])
}

pub fn default_hub_port() -> u16 {
    37373
}

pub fn default_proxy_port() -> u16 {
    8080
}

pub fn default_tool_timeout_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub password: Option<SecretValue>,
    #[serde(default)]
    pub github_client_id: Option<SecretValue>,
    #[serde(default)]
    pub github_client_secret: Option<SecretValue>,
    #[serde(default)]
    pub google_client_id: Option<SecretValue>,
    #[serde(default)]
    pub google_client_secret: Option<SecretValue>,
    /// A static `Authorization: Bearer ...` token checked by the hub itself.
    ///
    /// This is the zero-dependency alternative to `mcp-auth-proxy`: good for
    /// clients (Cursor, Claude Code, scripts) that can send a header, but it does
    /// not provide OAuth discovery, PKCE or browser sign-in.
    #[serde(default)]
    pub bearer_token: Option<SecretValue>,
}

impl AuthConfig {
    /// Is any authentication configured at all?
    pub fn is_enabled(&self) -> bool {
        self.proxy_enabled() || self.bearer_token.is_some()
    }

    /// Is the external `mcp-auth-proxy` needed?
    pub fn proxy_enabled(&self) -> bool {
        self.password.is_some() || self.github().is_some() || self.google().is_some()
    }

    /// The GitHub OAuth client pair, if both halves are configured.
    pub fn github(&self) -> Option<(&SecretValue, &SecretValue)> {
        match (&self.github_client_id, &self.github_client_secret) {
            (Some(id), Some(secret)) => Some((id, secret)),
            _ => None,
        }
    }

    /// The Google OAuth client pair, if both halves are configured.
    pub fn google(&self) -> Option<(&SecretValue, &SecretValue)> {
        match (&self.google_client_id, &self.google_client_secret) {
            (Some(id), Some(secret)) => Some((id, secret)),
            _ => None,
        }
    }

    /// Human-readable list of the configured methods, for the startup banner.
    pub fn methods(&self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        if self.password.is_some() {
            methods.push("password");
        }
        if self.github().is_some() {
            methods.push("GitHub OAuth");
        }
        if self.google().is_some() {
            methods.push("Google OAuth");
        }
        if self.bearer_token.is_some() {
            methods.push("bearer token");
        }
        methods
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrayConfig {
    /// Show a system tray icon while `mcp-ctl up` is running.
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    #[serde(default)]
    pub provider: TunnelProvider,
    #[serde(default = "default_true")]
    pub auto_start: bool,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProvider {
    Tailscale,
    Cloudflared,
    /// No tunnel: mcp-ctl serves locally only. This is the default, so a fresh
    /// install never publishes anything by accident.
    #[default]
    None,
}

pub fn default_true() -> bool {
    true
}

impl ToolConfig {
    /// Read a specific profile file, or return defaults when it does not exist.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::load_from_str(&text).with_context(|| format!("invalid config at {}", path.display()))
    }

    /// Parse a profile file that is already in memory.
    pub fn load_from_str(text: &str) -> Result<Self> {
        serde_json::from_str(text).context("not valid JSON")
    }

    pub fn server(&self) -> ServerConfig {
        self.server.clone().unwrap_or_default()
    }

    pub fn auth(&self) -> AuthConfig {
        self.auth.clone().unwrap_or_default()
    }

    pub fn tunnel(&self) -> TunnelConfig {
        self.tunnel.clone().unwrap_or_default()
    }

    pub fn tray(&self) -> TrayConfig {
        self.tray.clone().unwrap_or_default()
    }

    /// Report configuration mistakes at startup instead of at the first request.
    pub fn validate(&self) -> Result<()> {
        if let Some(server) = &self.server {
            if server.proxy_port == server.listen_port {
                bail!(
                    "server.listen_port and server.proxy_port must differ (both are {})",
                    server.listen_port
                );
            }
            if let Some(url) = &server.external_url {
                validate_external_url(url)?;
            }
            for origin in &server.allowed_origins {
                validate_origin(origin)?;
            }
        }

        if let Some(auth) = &self.auth {
            for (name, value) in [
                ("password", &auth.password),
                ("bearer_token", &auth.bearer_token),
                ("github_client_secret", &auth.github_client_secret),
                ("google_client_secret", &auth.google_client_secret),
            ] {
                if value.as_ref().is_some_and(is_literal) {
                    bail!(
                        "auth.{name} must not be a literal value in the profile file: that file is \
                         easy to share or commit by accident. Put the value in .env next to it and \
                         use {{\"source\": \"env\", \"name\": \"...\"}}, or read it from a vault."
                    );
                }
            }
            if auth.github_client_id.is_some() != auth.github_client_secret.is_some() {
                bail!("auth.github_client_id and auth.github_client_secret must be set together");
            }
            if auth.google_client_id.is_some() != auth.google_client_secret.is_some() {
                bail!("auth.google_client_id and auth.google_client_secret must be set together");
            }
            if auth.bearer_token.is_some() && auth.proxy_enabled() {
                bail!(
                    "auth.bearer_token cannot be combined with auth.password or the OAuth \
                     settings: the hub would require a bearer token the auth proxy does not add. \
                     Choose one authentication method."
                );
            }
        }

        if let Some(tunnel) = &self.tunnel
            && tunnel.provider == TunnelProvider::None
            && tunnel.port.is_some()
        {
            bail!("tunnel.port is set but tunnel.provider is \"none\"");
        }

        Ok(())
    }
}

/// The client-facing MCP endpoint for a public base URL: append `/mcp` unless the
/// configured URL already points at it.
pub fn mcp_endpoint_url(external_url: &str) -> String {
    let trimmed = external_url.trim_end_matches('/');
    if trimmed.ends_with("/mcp") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/mcp")
    }
}

pub(crate) fn validate_external_url(url: &str) -> Result<()> {
    let (scheme, rest) = url
        .strip_prefix("https://")
        .map(|rest| ("https", rest))
        .or_else(|| url.strip_prefix("http://").map(|rest| ("http", rest)))
        .ok_or_else(|| {
            anyhow!(
                "server.external_url must start with http:// or https:// (got '{url}'), \
                 for example \"https://device.example.ts.net\""
            )
        })?;
    if rest.is_empty() || rest.starts_with('/') || url.contains(char::is_whitespace) {
        bail!("server.external_url is not a valid URL: '{url}'");
    }
    // The auth proxy puts OAuth codes, passwords and bearer tokens on this URL. Plain HTTP
    // is only acceptable when the whole exchange stays on this machine.
    if scheme == "http" && !is_loopback_url_host(rest) {
        bail!(
            "server.external_url must use https:// for a public URL (got '{url}'); \
             http:// is only allowed for localhost/loopback testing"
        );
    }
    Ok(())
}

/// Does a URL authority (host[:port], without the scheme) name this machine?
fn is_loopback_url_host(rest: &str) -> bool {
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.split(']').next())
        .unwrap_or_else(|| host.split(':').next().unwrap_or(host));
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

/// A bearer token is the only credential protecting a directly exposed hub, so a short
/// one is not worth the false sense of security.
pub const MIN_BEARER_TOKEN_LEN: usize = 16;

pub fn validate_bearer_token(value: &str) -> Result<()> {
    if value.len() < MIN_BEARER_TOKEN_LEN {
        bail!(
            "auth.bearer_token is too short: use at least {MIN_BEARER_TOKEN_LEN} characters of \
             random data (for example `openssl rand -hex 32`)"
        );
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<()> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| {
            anyhow!(
                "server.allowed_origins entries must look like \"https://host[:port]\" (got '{origin}')"
            )
        })?;
    if rest.is_empty() || rest.contains('/') {
        bail!("server.allowed_origins entries must not contain a path: '{origin}'");
    }
    Ok(())
}

/// Every path mcp-ctl reads or writes, resolved once at startup.
#[derive(Clone)]
pub struct Paths {
    /// The profile these paths belong to; `default` is `config.json`.
    pub profile: String,
    /// The directory holding the profile files and the `.env` next to them.
    pub config_dir: PathBuf,
    /// The profile file: `config.json`, or `config.<profile>.json`.
    pub config_file: PathBuf,
    /// mcp-ctl's own state directory (daemon state file, logs).
    pub state_dir: PathBuf,
    pub state_file: PathBuf,
    pub log_file: PathBuf,
    /// `.env` next to the profile files, for `{"source": "env"}` secrets.
    pub env_file: PathBuf,
}

/// The profile that uses `config.json`, so a single-profile installation stays simple.
pub const DEFAULT_PROFILE: &str = "default";

/// Where to read configuration from, when the command line says so.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    /// `--config`: a specific profile file instead of `config.json`.
    pub config_file: Option<PathBuf>,
    /// `--profile`: a named profile instead of the default one.
    pub profile: Option<String>,
}

/// Resolve every path, honouring the `--profile` and `--config` overrides.
///
/// This does not read the profile file. `update` uses it after replacing the binary,
/// where a broken profile must not stand in the way of asking about a running daemon.
pub fn paths_with(overrides: Overrides) -> Result<Paths> {
    // Make the roots absolute before a background daemon inherits them: a relative
    // `--config work.json` must keep pointing at the same file after `up -d`
    // detaches (and after a tray or `restart` re-launches the daemon).
    let config_root = absolute_path(&config_dir()?)?;
    let state_root = absolute_path(&state_dir()?)?;

    let profile = overrides
        .profile
        .clone()
        .or_else(|| env_string("MCP_CTL_PROFILE"))
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    let mut paths = paths_for_profile(&config_root, &state_root, &profile)?;

    if let Some(path) = &overrides.config_file {
        // `--config` names the profile file itself; the state still follows the profile.
        paths.config_file = absolute_path(path)?;
        paths.config_dir = paths
            .config_file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        paths.env_file = paths.config_dir.join(".env");
    }

    Ok(paths)
}

/// Resolve every path and read the profile file.
pub fn resolve_with(overrides: Overrides) -> Result<(Paths, ToolConfig)> {
    let paths = paths_with(overrides)?;
    let tool_config = ToolConfig::load_from(&paths.config_file)?;
    tool_config.validate()?;
    Ok((paths, tool_config))
}

/// Where a profile keeps its files, without reading anything.
///
/// The default profile is `config.json`; a named profile is `config.<name>.json` next to it. Its
/// state lives under `profiles/<name>/` in the state root, which is what keeps two daemons apart:
/// separate state files, separate locks, separate logs.
pub fn paths_for_profile(config_root: &Path, state_root: &Path, profile: &str) -> Result<Paths> {
    validate_profile(profile)?;
    let (config_file, state_dir) = if profile == DEFAULT_PROFILE {
        (config_root.join("config.json"), state_root.to_path_buf())
    } else {
        (
            config_root.join(format!("config.{profile}.json")),
            state_root.join("profiles").join(profile),
        )
    };
    Ok(Paths {
        profile: profile.to_string(),
        config_dir: config_root.to_path_buf(),
        config_file,
        state_file: state_dir.join("daemon.json"),
        log_file: state_dir.join("mcp-ctl.log"),
        env_file: config_root.join(".env"),
        state_dir,
    })
}

/// Every profile on disk, `default` first, then the others in name order.
pub fn profiles(config_root: &Path) -> Vec<String> {
    let mut names = vec![DEFAULT_PROFILE.to_string()];
    let Ok(entries) = std::fs::read_dir(config_root) else {
        return names;
    };
    let mut found: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| {
            let profile = name.strip_prefix("config.")?.strip_suffix(".json")?;
            (!profile.is_empty()).then(|| profile.to_string())
        })
        .collect();
    found.sort();
    names.extend(found);
    names
}

/// A profile name is one file name: no separators, no `.` or `..`, not empty.
pub fn validate_profile(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        bail!(
            "'{name}' is not a valid profile name: use a single word, for example `work` \
             (its file is config.<name>.json)"
        );
    }
    Ok(())
}

/// Is this secret written out in the profile file?
fn is_literal(value: &SecretValue) -> bool {
    matches!(value, SecretValue::Literal(_))
}

impl Paths {
    pub fn resolve_with(overrides: Overrides) -> Result<(Paths, ToolConfig)> {
        resolve_with(overrides)
    }

    /// Create the state directory if it does not exist yet, owner-only on Unix.
    pub fn ensure_state_dir(&self) -> Result<()> {
        platform::ensure_private_dir(&self.state_dir)
            .with_context(|| format!("failed to create {}", self.state_dir.display()))
    }
}

/// mcp-ctl's config directory: $MCP_CTL_CONFIG_DIR, else the OS config directory
/// (~/.config/mcp-ctl on Linux, ~/Library/Application Support/mcp-ctl on macOS,
/// %APPDATA%\mcp-ctl on Windows).
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = env_path("MCP_CTL_CONFIG_DIR") {
        return Ok(dir);
    }
    dirs::config_dir()
        .map(|dir| dir.join("mcp-ctl"))
        .ok_or_else(|| anyhow!("could not determine the system configuration directory"))
}

/// mcp-ctl's state directory: $MCP_CTL_STATE_DIR, else the OS state directory
/// (~/.local/state/mcp-ctl on Linux, ~/Library/Application Support/mcp-ctl on
/// macOS, %LOCALAPPDATA%\mcp-ctl on Windows).
pub fn state_dir() -> Result<PathBuf> {
    if let Some(dir) = env_path("MCP_CTL_STATE_DIR") {
        return Ok(dir);
    }
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .map(|dir| dir.join("mcp-ctl"))
        .ok_or_else(|| anyhow!("could not determine the system state directory"))
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// A non-empty environment variable, trimmed.
fn env_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Make a path absolute against the current directory, without requiring it to exist.
fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("could not determine the current working directory")?
        .join(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: &str) -> ToolConfig {
        ToolConfig::load_from_str(json).expect("a valid profile file")
    }

    #[test]
    fn tray_disabled_by_default() {
        let cfg: ToolConfig = serde_json::from_str("{\"server\": {\"listen_port\": 1}}").unwrap();
        assert!(!cfg.tray().enabled);
    }

    #[test]
    fn parses_enabled_tray() {
        let cfg: ToolConfig = serde_json::from_str(r#"{"tray": {"enabled": true}}"#).unwrap();
        assert!(cfg.tray().enabled);
    }

    #[test]
    fn a_bearer_token_alone_enables_authentication() {
        let cfg: ToolConfig = serde_json::from_str(
            r#"{"auth": {"bearer_token": {"source": "env", "name": "TOKEN"}}}"#,
        )
        .unwrap();
        assert!(cfg.auth().is_enabled());
        assert!(!cfg.auth().proxy_enabled());
        assert_eq!(cfg.auth().methods(), vec!["bearer token"]);
        cfg.validate().expect("a bearer token alone is valid");
    }

    #[test]
    fn bearer_and_proxy_authentication_cannot_be_combined() {
        let cfg: ToolConfig = serde_json::from_str(
            r#"{"auth": {
                "bearer_token": {"source": "env", "name": "TOKEN"},
                "password": {"source": "env", "name": "PASSWORD"}
            }}"#,
        )
        .unwrap();
        let error = cfg.validate().unwrap_err().to_string();
        assert!(error.contains("bearer_token"), "{error}");
    }

    #[test]
    fn relative_overrides_resolve_to_absolute_paths() {
        let resolved = absolute_path(Path::new("work/config.json")).unwrap();
        assert!(resolved.is_absolute(), "{}", resolved.display());
        assert!(resolved.ends_with("work/config.json"));
    }

    #[test]
    fn a_bearer_token_must_be_long_enough() {
        assert!(validate_bearer_token("short").is_err());
        assert!(validate_bearer_token("0123456789abcdef").is_ok());
        assert!(validate_bearer_token("0123456789abcdef0123456789abcdef").is_ok());
    }

    #[test]
    fn a_public_external_url_must_be_https() {
        assert!(validate_external_url("https://laptop.example.ts.net").is_ok());
        assert!(validate_external_url("https://laptop.example.ts.net:8443/mcp").is_ok());
        assert!(validate_external_url("http://laptop.example.ts.net").is_err());
        assert!(validate_external_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_external_url("http://localhost:8080").is_ok());
        assert!(validate_external_url("http://[::1]:8080").is_ok());
        assert!(validate_external_url("http://192.168.1.5:8080").is_err());
    }

    #[test]
    fn a_profile_is_a_file_next_to_the_default_one() {
        let root = Path::new("/home/you/.config/mcp-ctl");
        let state = Path::new("/home/you/.local/state/mcp-ctl");

        let default = paths_for_profile(root, state, DEFAULT_PROFILE).unwrap();
        assert_eq!(default.config_file, root.join("config.json"));
        assert_eq!(default.state_dir, state);
        assert_eq!(default.env_file, root.join(".env"));

        let work = paths_for_profile(root, state, "work").unwrap();
        assert_eq!(work.config_file, root.join("config.work.json"));
        assert_eq!(work.state_dir, state.join("profiles").join("work"));
        assert_eq!(work.state_file, work.state_dir.join("daemon.json"));
    }

    #[test]
    fn profiles_are_discovered_from_their_file_names() {
        let dir = std::env::temp_dir().join(format!("mcp-ctl-profiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), "{}").unwrap();
        std::fs::write(dir.join("config.work.json"), "{}").unwrap();
        std::fs::write(dir.join("config.personal.json"), "{}").unwrap();
        std::fs::write(dir.join("notes.txt"), "").unwrap();

        assert_eq!(profiles(&dir), vec!["default", "personal", "work"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_profile_name_is_one_file_name() {
        assert!(validate_profile("work").is_ok());
        assert!(validate_profile("default").is_ok());
        assert!(validate_profile("../escape").is_err());
        assert!(validate_profile("").is_err());
    }

    #[test]
    fn an_auth_secret_must_not_be_written_in_the_profile_file() {
        let literal = config(r#"{"auth": {"password": "hunter2"}}"#);
        let error = literal.validate().unwrap_err().to_string();
        assert!(error.contains("auth.password"), "{error}");
        assert!(error.contains(".env"), "{error}");

        // Reading it from the environment, a vault or a command is fine.
        let from_env = config(r#"{"auth": {"password": {"source": "env"}}}"#);
        from_env.validate().expect("an environment source is fine");

        // A bearer token is held to the same rule.
        let bare = config(r#"{"auth": {"bearer_token": "token"}}"#);
        assert!(bare.validate().is_err());
    }

    #[test]
    fn a_literal_secret_source_is_not_a_thing() {
        // One way to write a value out (a plain string), one way to name a secret
        // (a source). `{"source": "literal"}` is neither, and must not parse.
        let result = crate::config::ToolConfig::load_from_str(
            r#"{"mcpServers":{"a":{"command":"true","env":{"K":{"source":"literal","value":"x"}}}}}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn the_catalogue_lives_in_the_profile_file() {
        let cfg = config(
            r#"{
                "server": {"listen_port": 37373},
                "mcpServers": {
                    "github": {"command": "npx", "args": ["-y", "server-github"], "serve": true}
                }
            }"#,
        );
        assert_eq!(cfg.mcp_servers.len(), 1);
        assert!(cfg.mcp_servers["github"].serve);
        assert_eq!(cfg.server().listen_port, 37373);
    }

    #[test]
    fn mcp_endpoint_url_appends_path_once() {
        assert_eq!(
            mcp_endpoint_url("https://laptop.ts.net"),
            "https://laptop.ts.net/mcp"
        );
        assert_eq!(
            mcp_endpoint_url("https://laptop.ts.net/mcp"),
            "https://laptop.ts.net/mcp"
        );
    }
}
