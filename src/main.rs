#[macro_use]
mod output;

mod check;
mod config;
mod control;
mod daemon;
mod exposure;
mod http;
mod hub;
mod orchestrator;
mod platform;
mod secret;
mod servers;
mod tray;
mod update;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::config::{Overrides, Paths, ToolConfig};
use crate::orchestrator::UpOptions;

/// Manage MCP servers from a single profile file.
#[derive(Parser)]
#[command(name = "mcp-ctl", version, about)]
struct Cli {
    /// Log every request: method, path and headers (credentials are redacted)
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Also log JSON-RPC payloads; they can contain credentials
    #[arg(long, global = true)]
    verbose_bodies: bool,

    /// Use a different profile file than config.json
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Use a profile instead of the default configuration
    #[arg(long, global = true, value_name = "NAME")]
    profile: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List the configured MCP servers
    List,
    /// Write the default profile file and .env (never overwrites)
    Init,
    /// Run one server on stdio, resolving its secrets first
    Run {
        /// Name of the server in the profile file
        name: String,
    },
    /// Serve servers over HTTP: local hub, optional auth proxy, optional tunnel
    Up {
        #[command(flatten)]
        serve: ServeArgs,

        /// Run in the background as a daemon
        #[arg(long, short = 'd')]
        detach: bool,
    },
    /// Stop the background hub
    Stop {
        /// Kill the process if it does not stop on its own
        #[arg(long)]
        force: bool,
    },
    /// Restart the background hub (starts it when it is not running)
    Restart(ServeArgs),
    /// Check the configuration and resolve secrets without starting anything
    Check {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Report a newer release, and install it when this copy is ours to replace
    Update {
        /// Only report whether a newer release exists
        #[arg(long)]
        check: bool,
    },
    /// Print the background hub's log
    Logs {
        /// Keep printing as new lines arrive
        #[arg(long, short)]
        follow: bool,
    },
    /// Show what the background hub is doing
    Status {
        /// Only this profile; every profile when omitted
        #[arg(value_name = "PROFILE")]
        profile: Option<String>,

        /// Machine-readable output, for scripts and menu-bar wrappers
        #[arg(long)]
        json: bool,
    },
}

/// Flags shared by `up` and `restart`.
#[derive(Args)]
struct ServeArgs {
    /// Server name(s) to serve. Defaults to every server with "serve": true.
    names: Vec<String>,

    /// Serve every enabled server, ignoring the "serve": true filter
    #[arg(long, short)]
    all: bool,

    /// Local hub port (0 picks a free port)
    #[arg(long)]
    port: Option<u16>,

    /// Port for the auth proxy
    #[arg(long)]
    proxy_port: Option<u16>,

    /// Address the hub binds to; loopback by default
    #[arg(long, value_name = "ADDRESS")]
    bind: Option<String>,

    /// Public URL clients use, e.g. https://device.example.ts.net
    #[arg(long)]
    external_url: Option<String>,

    /// Do not start the tunnel (Tailscale / Cloudflare)
    #[arg(long)]
    no_tunnel: bool,

    /// Do not start the auth proxy
    #[arg(long)]
    no_auth: bool,

    /// Really publish an unauthenticated hub when a tunnel is enabled
    #[arg(long)]
    allow_unauthenticated_exposure: bool,
}

impl ServeArgs {
    fn into_options(self, verbose: bool, verbose_bodies: bool, paths: &Paths) -> Result<UpOptions> {
        let bind = match self.bind {
            Some(bind) => Some(
                bind.parse::<IpAddr>()
                    .with_context(|| format!("--bind '{bind}' is not an IP address"))?,
            ),
            None => None,
        };
        Ok(UpOptions {
            names: self.names,
            all: self.all,
            no_tunnel: self.no_tunnel,
            no_auth: self.no_auth,
            port: self.port,
            proxy_port: self.proxy_port,
            bind,
            external_url: self.external_url,
            allow_unauthenticated_exposure: self.allow_unauthenticated_exposure,
            verbose,
            verbose_bodies,
            profile: paths.profile.clone(),
            // Pin the profile file this run resolved, so `up -d`, `restart` and the tray's
            // restart re-read exactly the same one.
            config_file: paths.config_file.clone(),
        })
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            // `{:#}` prints the whole context chain, e.g. "failed to read ...: no such file".
            errln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    // `update` only talks to GitHub. A broken profile file, or a config
    // directory the current user cannot read, must not stand in the way of
    // fixing the binary.
    if let Commands::Update { check } = &cli.command {
        return update::run(
            *check,
            Overrides {
                config_file: cli.config.clone(),
                profile: cli.profile.clone(),
            },
        );
    }
    let (paths, tool_config) = Paths::resolve_with(Overrides {
        config_file: cli.config.clone(),
        profile: cli.profile.clone(),
    })?;
    // Secrets that live in a file are read here, so every command sees the same values.
    secret::load_env_file(&paths.env_file)?;

    match cli.command {
        Commands::List => list(&paths, &tool_config)?,
        Commands::Init => init(&paths)?,
        Commands::Check { json } => {
            let problems = check::run(&paths, &tool_config, json)?;
            // A non-zero exit code is what makes `mcp-ctl check` usable in a script.
            return Ok(u8::from(problems > 0));
        }
        // Handled at the top of this function, before the profile file is read;
        // repeated here so the match stays exhaustive without a panic.
        Commands::Update { check } => {
            return update::run(
                check,
                Overrides {
                    config_file: cli.config.clone(),
                    profile: cli.profile.clone(),
                },
            );
        }
        Commands::Run { name } => {
            // On Unix this never returns: the server replaces this process.
            let code = servers::run(&name, &tool_config.mcp_servers)?;
            return Ok(code.rem_euclid(256) as u8);
        }
        Commands::Up { serve, detach } => {
            let options = serve.into_options(cli.verbose, cli.verbose_bodies, &paths)?;
            if detach {
                let pid = daemon::spawn_detached(&paths, &options.to_cli_args())?;
                outln!("mcp-ctl started in the background (PID {pid}).");
                outln!("Log file: {}", paths.log_file.display());
                outln!("Stop it with `mcp-ctl stop`.");
                return Ok(0);
            }
            orchestrator::up(&paths, &tool_config, options)?;
        }
        Commands::Stop { force } => daemon::stop(&paths, force)?,
        Commands::Restart(serve) => {
            let options = serve.into_options(cli.verbose, cli.verbose_bodies, &paths)?;
            if std::io::stdin().is_terminal() {
                preflight_secrets(&tool_config, &options);
            }
            daemon::restart(&paths, &options)?;
        }
        Commands::Status { profile, json } => {
            match profile {
                // A named profile means "just this one".
                Some(name) => {
                    let (paths, _) = Paths::resolve_with(Overrides {
                        config_file: cli.config.clone(),
                        profile: Some(name),
                    })?;
                    daemon::status(&paths, json)?;
                }
                // `--profile` or `--config` already picked one; without either, report
                // every profile that exists.
                None if cli.profile.is_some() || cli.config.is_some() => {
                    daemon::status(&paths, json)?
                }
                None => daemon::status_all(json)?,
            }
        }
        Commands::Logs { follow } => daemon::logs(&paths, follow)?,
    }

    Ok(0)
}

/// Resolve the selected servers' secrets before a restart stops the running daemon.
///
/// A password manager that is locked can prompt here, in the foreground, while the old
/// service is still up. Without this, the prompt happens during daemon startup, where a
/// secret that takes longer than `SECRET_TIMEOUT` skips its server.
fn preflight_secrets(tool_config: &ToolConfig, options: &UpOptions) {
    let Ok(selected) = servers::select(&tool_config.mcp_servers, &options.names, options.all)
    else {
        return;
    };
    if selected.iter().all(|(_, server)| server.env.is_empty()) {
        return;
    }

    outln!("Resolving server secrets before restart (unlock the vault if prompted)...");
    for (name, server) in selected {
        if let Err(error) = servers::resolve_env(name, server) {
            errln!("warning: {error:#}");
        }
    }
}

/// Write the profile file and its `.env`, without overwriting anything that already exists.
fn init(paths: &Paths) -> Result<()> {
    let mut wrote = Vec::new();
    if write_template(&paths.config_file, config::DEFAULT_CONFIG_JSON)? {
        wrote.push(paths.config_file.clone());
    }
    if write_template(&paths.env_file, config::DEFAULT_ENV_FILE)? {
        wrote.push(paths.env_file.clone());
    }

    if wrote.is_empty() {
        outln!(
            "Nothing to do: {} already exists.",
            paths.config_file.display()
        );
    } else {
        for path in &wrote {
            outln!("wrote {}", path.display());
        }
    }

    outln!("\nNext steps:");
    outln!(
        "  1. describe your servers in {}",
        paths.config_file.display()
    );
    outln!("  2. `mcp-ctl list` to check them, `mcp-ctl run <name>` for stdio clients");
    outln!("  3. set \"serve\": true on a server, then `mcp-ctl up` to serve it over HTTP");
    if paths.profile != config::DEFAULT_PROFILE {
        outln!(
            "  (add --profile {} to every command, or set MCP_CTL_PROFILE={})",
            paths.profile,
            paths.profile
        );
    }
    Ok(())
}

fn write_template(path: &std::path::Path, contents: &str) -> Result<bool> {
    if path.exists() {
        outln!("already exists: {}", path.display());
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    // Owner-only from creation: `.env` holds secrets and `config.json` names the
    // servers and vault items they come from, so no other local user may read them.
    let mut file = platform::create_private_file(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(true)
}

fn list(paths: &Paths, tool_config: &ToolConfig) -> Result<()> {
    if tool_config.mcp_servers.is_empty() {
        outln!("No servers configured in {}.", paths.config_file.display());
        outln!("Run `mcp-ctl init` to write a template.");
        return Ok(());
    }

    for (name, server) in &tool_config.mcp_servers {
        let mut flags: Vec<String> = Vec::new();
        if server.serve {
            flags.push("serve".to_string());
        }
        if !server.enabled {
            flags.push("disabled".to_string());
        }
        if !server.is_stdio() {
            flags.push("remote".to_string());
        }
        if let Some(prefix) = &server.prefix {
            flags.push(format!("prefix: {prefix}"));
        }
        if let Some(cwd) = &server.cwd {
            flags.push(format!("cwd: {}", cwd.display()));
        }
        if let Some(filter) = &server.tools {
            flags.push(format!("tools: {}", filter.describe()));
        }
        let flags = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(", "))
        };
        outln!("{name}{flags}: {}", server.command_line());
    }
    Ok(())
}
