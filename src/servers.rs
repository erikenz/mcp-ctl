use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::{platform, secret};

fn default_true() -> bool {
    true
}

/// What to do when this server exits on its own.
///
/// Off by default: a server that cannot start would otherwise be respawned for as long
/// as the daemon runs. `mcp-ctl server start <name>` always works by hand, whatever
/// this is set to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Leave it stopped; its tools disappear from the hub.
    #[default]
    Never,
    /// Start it again with backoff, up to a small cap, then give up loudly.
    OnFailure,
}

/// One server definition.
///
/// Unknown keys are deliberately ignored: the same file is read by other MCP
/// clients (Claude, Cursor, VS Code, ...) which add their own fields, and refusing
/// to start because of a key we do not understand would make the file unusable
/// outside mcp-ctl.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpServer {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Secrets, keyed by the env var name the server expects. See `SecretValue`.
    #[serde(default)]
    pub env: BTreeMap<String, SecretValue>,
    /// A remote server, spoken to over Streamable HTTP.
    #[serde(default)]
    pub url: Option<String>,
    /// Headers sent with every request to a remote (`url`) server.
    ///
    /// Values are secret sources for the same reason `env` values are: an API key in
    /// the profile file is one copy-paste away from being shared. An `Authorization`
    /// header here means "this server takes a fixed credential", which turns OAuth
    /// off for it.
    #[serde(default)]
    pub headers: BTreeMap<String, SecretValue>,
    /// How to authenticate to a remote server. Absent means "use a stored OAuth
    /// token, and sign in on demand".
    #[serde(default)]
    pub auth: RemoteAuth,
    /// Whether `mcp-ctl up` (without `--all`) starts this server on daemon startup.
    #[serde(default)]
    pub autostart: Option<bool>,
    /// Deprecated synonym for `autostart`.
    #[serde(default)]
    pub serve: Option<bool>,
    /// Whether this server is enabled at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Restart this server when it exits unexpectedly; `"never"` (the default) leaves it
    /// stopped until someone runs `mcp-ctl server start`.
    #[serde(default)]
    pub restart: RestartPolicy,
    /// Optional tool prefix, so `create_issue` becomes `github_create_issue`.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Per-server override of `server.tool_timeout_secs`; 0 disables the timeout.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Which of this server's tools to publish; all of them when omitted.
    #[serde(default)]
    pub tools: Option<ToolFilter>,
    /// Start this server with an empty environment instead of inheriting mcp-ctl's.
    ///
    /// Advanced: an emptied environment has no `PATH`, so set one in `env` if the
    /// command needs to find its own helpers.
    #[serde(default)]
    pub env_clear: bool,
    /// Working directory for a stdio server, so relative `args` and `cwd`-sensitive
    /// servers behave the same whether they were started by `run` or by `up -d`.
    ///
    /// A relative path resolves against mcp-ctl's own working directory, exactly
    /// like a shell would.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
}

/// How to authenticate to a remote (`url`) server.
///
/// Absent is `oauth`, which is also the only mode that can start a sign-in when the
/// server asks for one: the other two are for servers that were configured with a
/// credential already, or that need none.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RemoteAuth {
    /// OAuth 2.1: use a stored token, refresh it, and sign in when there is none.
    Oauth {
        /// Scopes to request; the server's own list when omitted.
        #[serde(default)]
        scopes: Vec<String>,
        /// A registered client, for providers without dynamic registration.
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_secret: Option<SecretValue>,
    },
    /// No authentication: no token is attached and a 401 is reported as-is.
    None,
}

impl Default for RemoteAuth {
    fn default() -> Self {
        Self::Oauth {
            scopes: Vec::new(),
            client_id: None,
            client_secret: None,
        }
    }
}

impl RemoteAuth {
    /// The configured scopes, empty when the server's own list should be used.
    pub fn scopes(&self) -> &[String] {
        match self {
            Self::Oauth { scopes, .. } => scopes,
            Self::None => &[],
        }
    }

    pub fn client_id(&self) -> Option<&str> {
        match self {
            Self::Oauth { client_id, .. } => client_id.as_deref(),
            Self::None => None,
        }
    }

    pub fn client_secret(&self) -> Option<&SecretValue> {
        match self {
            Self::Oauth { client_secret, .. } => client_secret.as_ref(),
            Self::None => None,
        }
    }

    pub fn is_oauth(&self) -> bool {
        matches!(self, Self::Oauth { .. })
    }
}

/// Which of a server's tools are published.
///
/// An empty `include` means "everything not excluded". A pattern is either an exact
/// tool name or a prefix ending in `*`, for example `debug_*`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolFilter {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl ToolFilter {
    /// Would this tool be published?
    pub fn allows(&self, tool: &str) -> bool {
        if !self.include.is_empty()
            && !self
                .include
                .iter()
                .any(|pattern| matches_pattern(pattern, tool))
        {
            return false;
        }
        !self
            .exclude
            .iter()
            .any(|pattern| matches_pattern(pattern, tool))
    }

    /// Short description for `list` and `check` output.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.include.is_empty() {
            parts.push(format!("include: {}", self.include.join(", ")));
        }
        if !self.exclude.is_empty() {
            parts.push(format!("exclude: {}", self.exclude.join(", ")));
        }
        if parts.is_empty() {
            "all tools".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// Exact match, or a prefix when the pattern ends in `*`.
fn matches_pattern(pattern: &str, tool: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => tool.starts_with(prefix),
        None => pattern == tool,
    }
}

/// An env value is either a plain string ("MY_KEY": "abc"), for a value that is
/// not secret, or a structured { "source": ... } object that names where the
/// secret lives.
#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum SecretValue {
    Literal(String),
    Source(SecretSource),
}

/// Parse an env value: a plain string, or `{ "source": ... }`.
///
/// Written by hand rather than with `untagged`, because a shape that matches
/// neither deserves to be told what both look like instead of serde's "data did
/// not match any variant of untagged enum".
impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Literal(String),
            Source(SecretSource),
        }

        let repr = Repr::deserialize(deserializer).map_err(|_| {
            serde::de::Error::custom(
                "expected a plain string for a value that is not secret, or a secret source \
                 object such as {\"source\": \"env\", \"name\": \"GITHUB_TOKEN\"}",
            )
        })?;
        Ok(match repr {
            Repr::Literal(value) => Self::Literal(value),
            Repr::Source(source) => Self::Source(source),
        })
    }
}

/// How to obtain a secret. `tag = "source"` picks the variant by the `source`
/// field; `rename_all = "lowercase"` maps "bitwarden"/"1password"/"command"/"env".
///
/// `Debug` is implemented by hand: a secret must never reach a log through `{:?}`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "source", rename_all = "lowercase")]
pub enum SecretSource {
    Bitwarden {
        item: String,
        #[serde(default)]
        field: Option<String>,
    },
    #[serde(rename = "1password")]
    OnePassword { reference: String },
    Command {
        run: String,
        #[serde(default)]
        args: Vec<String>,
    },
    Env {
        #[serde(default)]
        name: Option<String>,
    },
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(_) => f.write_str("Literal(<redacted>)"),
            Self::Source(source) => write!(f, "Source({source:?})"),
        }
    }
}

impl fmt::Debug for SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitwarden { item, field } => f
                .debug_struct("Bitwarden")
                .field("item", item)
                .field("field", &field.as_deref().unwrap_or("password"))
                .finish(),
            Self::OnePassword { reference } => f
                .debug_struct("OnePassword")
                .field("reference", reference)
                .finish(),
            Self::Command { run, args } => f
                .debug_struct("Command")
                .field("run", run)
                .field("args", args)
                .finish(),
            Self::Env { name } => f.debug_struct("Env").field("name", name).finish(),
        }
    }
}

impl McpServer {
    /// Is this a remote server spoken to over HTTP?
    pub fn is_remote(&self) -> bool {
        self.command.is_none() && self.url.is_some()
    }

    /// A one-line description of what this entry points at.
    pub fn command_line(&self) -> String {
        if let Some(command) = &self.command {
            let mut line = command.clone();
            for arg in &self.args {
                line.push(' ');
                line.push_str(arg);
            }
            line
        } else if let Some(url) = &self.url {
            format!("remote {url}")
        } else {
            "no command or url".to_string()
        }
    }

    /// Is this a local server, started as a child process?
    pub fn is_stdio(&self) -> bool {
        self.command.is_some()
    }

    /// Does the profile supply its own credential for this remote server?
    ///
    /// A configured `Authorization` header is an explicit choice, so OAuth is not
    /// attempted behind it: a stored token would replace the header the user wrote.
    pub fn has_authorization_header(&self) -> bool {
        self.headers
            .keys()
            .any(|name| name.eq_ignore_ascii_case("authorization"))
    }

    /// The tool-call timeout for this server, falling back to the global setting.
    pub fn tool_timeout(&self, fallback: Option<Duration>) -> Option<Duration> {
        match self.timeout_secs {
            Some(0) => None,
            Some(secs) => Some(Duration::from_secs(
                secs.min(crate::config::MAX_TIMEOUT_SECS),
            )),
            None => fallback,
        }
    }

    /// Whether `mcp-ctl up` (without `--all`) starts this server on daemon startup.
    ///
    /// Prefers `autostart`, falling back to the deprecated `serve` key.
    pub fn autostart(&self) -> bool {
        self.autostart.or(self.serve).unwrap_or(false)
    }
}

/// Resolve every env entry of a server. Values stay in memory and are handed to
/// the child process only.
pub fn resolve_env(name: &str, server: &McpServer) -> Result<Vec<(String, String)>> {
    resolve_env_with_timeout(name, server, None)
}

pub fn resolve_headers_with_timeout(
    name: &str,
    server: &McpServer,
    timeout: Option<Duration>,
) -> Result<Vec<(String, String)>> {
    let mut resolved = Vec::with_capacity(server.headers.len());
    for (key, value) in &server.headers {
        let from = secret::describe(value);
        let value = secret::resolve_with_timeout(key, value, timeout).with_context(|| {
            format!("failed to resolve the {key} header for '{name}' from {from}")
        })?;
        resolved.push((key.clone(), value));
    }
    Ok(resolved)
}

/// Resolve every env entry of a server, bounding each external lookup.
///
/// A caller that must come up even when a vault is locked (`up`) passes a timeout;
/// the others wait as long as the program takes.
pub fn resolve_env_with_timeout(
    name: &str,
    server: &McpServer,
    timeout: Option<Duration>,
) -> Result<Vec<(String, String)>> {
    let mut resolved = Vec::with_capacity(server.env.len());
    for (key, value) in &server.env {
        let from = secret::describe(value);
        let value = secret::resolve_with_timeout(key, value, timeout)
            .with_context(|| format!("failed to resolve {key} for '{name}' from {from}"))?;
        resolved.push((key.clone(), value));
    }
    Ok(resolved)
}

/// Pick the servers `mcp-ctl up` should serve.
///
/// Rules:
///  * names given on the command line must exist: a typo is an error, not a silent no-op;
///  * servers with `"enabled": false` are skipped with a warning;
///  * entries that are neither a `command` nor a `url` are skipped with a warning;
///  * without names, `--all` selects every server and the default selects the ones
///    marked `"autostart": true`.
pub fn select<'a>(
    servers: &'a BTreeMap<String, McpServer>,
    names: &[String],
    all: bool,
) -> Result<Vec<(&'a String, &'a McpServer)>> {
    if !names.is_empty() {
        let unknown: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .filter(|name| !servers.contains_key(*name))
            .collect();
        if !unknown.is_empty() {
            let known: Vec<&str> = servers.keys().map(String::as_str).collect();
            bail!(
                "unknown server{}: {}\nconfigured servers: {}\n(`mcp-ctl list` shows them all)",
                if unknown.len() == 1 { "" } else { "s" },
                unknown.join(", "),
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            );
        }
    }

    let mut selected = Vec::new();
    for (name, server) in servers {
        let wanted = if names.is_empty() {
            all || server.autostart()
        } else {
            names.contains(name)
        };
        if !wanted {
            continue;
        }
        if !server.enabled {
            errln!("warning: skipping '{name}': \"enabled\" is false");
            continue;
        }
        if !server.is_stdio() && !server.is_remote() {
            errln!("warning: skipping '{name}': neither a command nor a url is configured");
            continue;
        }
        selected.push((name, server));
    }

    if selected.is_empty() {
        bail!(
            "no servers to serve{}",
            if names.is_empty() && !all {
                ": add \"autostart\": true to a server in config.json, or pass --all"
            } else {
                " (see the warnings above)"
            }
        );
    }

    Ok(selected)
}

/// Run a server on this process's stdio, resolving its secrets first.
///
/// On Unix the process is replaced by the server, so signals and the exit status
/// belong to it. The returned exit code therefore only matters on Windows, where
/// the server is spawned and waited for instead.
pub fn run(name: &str, servers: &BTreeMap<String, McpServer>) -> Result<i32> {
    let server = servers.get(name).ok_or_else(|| {
        anyhow!("unknown server '{name}' (`mcp-ctl list` shows the configured ones)")
    })?;

    let command = server.command.as_deref().ok_or_else(|| {
        anyhow!(
            "server '{name}' is not a local stdio server ({}); `mcp-ctl run` cannot start it",
            server.command_line()
        )
    })?;

    if !server.enabled {
        bail!("server '{name}' is disabled (\"enabled\": false in config.json)");
    }

    let mut cmd = std::process::Command::new(command);
    if server.env_clear {
        // Same isolation `up` applies: a server marked env_clear must not leak the
        // shell environment just because it was started through `mcp-ctl run`.
        cmd.env_clear();
    }
    if let Some(cwd) = &server.cwd {
        cmd.current_dir(cwd);
    }
    cmd.args(&server.args).envs(resolve_env(name, server)?);
    platform::run_stdio(&mut cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mcp_file_with_sources() {
        let json = r#"{
            "mcpServers": {
                "test-server": {
                    "command": "echo",
                    "args": ["hello"],
                    "serve": true,
                    "env": {
                        "LITERAL_KEY": "literal-val",
                        "ENV_KEY": { "source": "env", "name": "SOME_ENV" },
                        "BW_KEY": { "source": "bitwarden", "item": "my-item", "field": "password" },
                        "OP_KEY": { "source": "1password", "reference": "op://vault/item/field" },
                        "CMD_KEY": { "source": "command", "run": "echo", "args": ["secret"] }
                    }
                }
            }
        }"#;

        let mcp = parse(json);
        let server = mcp.get("test-server").expect("server not found");
        assert!(server.autostart());
        assert_eq!(server.serve, Some(true));
        assert!(server.enabled);
        assert_eq!(server.command.as_deref(), Some("echo"));
        assert_eq!(server.args, vec!["hello"]);
        assert_eq!(server.env.len(), 5);
    }

    fn parse(json: &str) -> BTreeMap<String, McpServer> {
        crate::config::ToolConfig::load_from_str(json)
            .expect("a valid profile file")
            .mcp_servers
    }

    #[test]
    fn autostart_prefers_explicit_key_and_falls_back_to_serve() {
        let mcp = parse(
            r#"{"mcpServers":{
                "new":{"command":"true","autostart":true},
                "legacy":{"command":"true","serve":true},
                "override_to_false":{"command":"true","autostart":false,"serve":true},
                "override_to_true":{"command":"true","autostart":true,"serve":false},
                "neither":{"command":"true"}
            }}"#,
        );
        assert!(mcp["new"].autostart());
        assert!(mcp["legacy"].autostart());
        assert!(!mcp["override_to_false"].autostart());
        assert!(mcp["override_to_true"].autostart());
        assert!(!mcp["neither"].autostart());
    }

    #[test]
    fn select_rejects_unknown_names() {
        let mcp = parse(r#"{"mcpServers":{"a":{"command":"true"}}}"#);
        let error = select(&mcp, &["b".to_string()], false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown server"), "{error}");
        assert!(error.contains("b"), "{error}");
        assert!(error.contains('a'), "{error}");
    }

    #[test]
    fn select_skips_disabled_servers_and_keeps_remote_ones() {
        let mcp = parse(
            r#"{"mcpServers":{
                "disabled":{"command":"true","enabled":false,"serve":true},
                "remote":{"url":"https://example.test/mcp","serve":true},
                "local":{"command":"true","serve":true}
            }}"#,
        );
        let selected = select(&mcp, &[], false).expect("both servers are servable");
        let names: Vec<&str> = selected.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["local", "remote"]);
    }

    #[test]
    fn an_entry_with_neither_a_command_nor_a_url_is_not_servable() {
        let mcp = parse(r#"{"mcpServers":{"empty":{"serve":true}}}"#);
        let error = select(&mcp, &[], false).unwrap_err().to_string();
        assert!(error.contains("no servers to serve"), "{error}");
    }

    #[test]
    fn select_uses_the_serve_flag_unless_all_is_set() {
        let mcp =
            parse(r#"{"mcpServers":{"a":{"command":"true"},"b":{"command":"true","serve":true}}}"#);
        assert_eq!(select(&mcp, &[], false).unwrap().len(), 1);
        assert_eq!(select(&mcp, &[], true).unwrap().len(), 2);
    }

    #[test]
    fn select_reports_when_nothing_is_servable() {
        let mcp = parse(r#"{"mcpServers":{"a":{"command":"true"}}}"#);
        let error = select(&mcp, &[], false).unwrap_err().to_string();
        assert!(error.contains("no servers to serve"), "{error}");
        assert!(error.contains("autostart"), "{error}");
    }

    #[test]
    fn an_env_value_that_matches_neither_shape_says_what_is_expected() {
        let error = crate::config::ToolConfig::load_from_str(
            r#"{"mcpServers":{"a":{"command":"true","env":{"K":{"source":"nope"}}}}}"#,
        )
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("plain string"), "{error}");
        assert!(error.contains("secret source"), "{error}");
    }

    #[test]
    fn debug_output_redacts_secrets() {
        // A plain env value is the only place a secret can be written out, so it is
        // the one that must stay out of `{:?}`.
        let mcp = parse(
            r#"{"mcpServers":{"a":{"command":"true","env":{
                "K":"literal-secret"
            }}}}"#,
        );
        let rendered = format!("{mcp:?}");
        assert!(!rendered.contains("literal-secret"), "{rendered}");
        assert!(rendered.contains("Literal(<redacted>)"), "{rendered}");
    }

    #[test]
    fn tool_filters_include_and_exclude() {
        let only_shell = ToolFilter {
            include: vec!["shell".to_string()],
            exclude: Vec::new(),
        };
        assert!(only_shell.allows("shell"));
        assert!(!only_shell.allows("read_file"));
        assert_eq!(only_shell.describe(), "include: shell");

        let most_things = ToolFilter {
            include: Vec::new(),
            exclude: vec!["write".to_string(), "delete_*".to_string()],
        };
        assert!(most_things.allows("read"));
        assert!(!most_things.allows("write"));
        assert!(!most_things.allows("delete_everything"));
        assert_eq!(most_things.describe(), "exclude: write, delete_*");

        let everything = ToolFilter::default();
        assert!(everything.allows("anything"));
        assert_eq!(everything.describe(), "all tools");
    }

    #[test]
    fn cwd_and_env_clear_are_parsed() {
        let mcp = parse(
            r#"{"mcpServers":{
                "isolated":{"command":"true","cwd":"/tmp/work","env_clear":true},
                "plain":{"command":"true"}
            }}"#,
        );
        assert_eq!(
            mcp["isolated"].cwd.as_deref(),
            Some(std::path::Path::new("/tmp/work"))
        );
        assert!(mcp["isolated"].env_clear);
        assert!(mcp["plain"].cwd.is_none());
        assert!(!mcp["plain"].env_clear);
    }

    #[test]
    fn per_server_timeout_overrides_the_global_one() {
        let mcp = parse(
            r#"{"mcpServers":{
                "override":{"command":"true","timeout_secs":5},
                "disabled":{"command":"true","timeout_secs":0},
                "inherits":{"command":"true"}
            }}"#,
        );
        let global = Some(Duration::from_secs(300));
        let overridden = mcp["override"].tool_timeout(global);
        assert_eq!(overridden, Some(Duration::from_secs(5)));
        assert_eq!(mcp["disabled"].tool_timeout(global), None);
        assert_eq!(mcp["inherits"].tool_timeout(global), global);
    }
}
