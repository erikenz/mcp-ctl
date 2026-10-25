//! `mcp-ctl up`: start the hub, the optional auth proxy and the optional tunnel, then
//! supervise them until the operator or `mcp-ctl stop` asks for a shutdown.

use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{
    AuthConfig, Paths, ServerConfig, ToolConfig, TunnelProvider, mcp_endpoint_url,
};
use crate::control::{self, ControlInfo, ControlServer, StateFile};
use crate::exposure;
use crate::http::{HttpOptions, HttpServer};
use crate::hub::{BackendSpec, BackendTimeouts, Hub};
use crate::servers::{self, McpServer};
use crate::tray::{self, TrayAction, TrayInfo};
use crate::{daemon, platform, secret};

/// How often the supervisor checks whether a backend has died.
const HEALTH_INTERVAL: Duration = Duration::from_secs(2);

/// A supervised child process (auth proxy or tunnel).
struct ChildProc {
    name: &'static str,
    child: Child,
    /// When true, an unexpected exit stops the hub (used for the auth proxy).
    /// When false, an exit is logged as a warning and the hub keeps serving (tunnels).
    critical: bool,
    exited: bool,
}

/// Everything the `up` family of commands can be told.
pub struct UpOptions {
    pub names: Vec<String>,
    pub all: bool,
    pub no_tunnel: bool,
    pub no_auth: bool,
    pub port: Option<u16>,
    pub proxy_port: Option<u16>,
    pub bind: Option<IpAddr>,
    pub external_url: Option<String>,
    pub allow_unauthenticated_exposure: bool,
    pub verbose: bool,
    pub verbose_bodies: bool,
    /// The profile this run resolved, so a detached daemon, `restart` and the tray all
    /// keep using the same one.
    pub profile: String,
    /// Absolute profile file this run resolved, so a detached daemon and `restart`
    /// re-read the same file instead of the default one.
    pub config_file: PathBuf,
}

impl UpOptions {
    /// Rebuild the command line that produces these options, so `up -d`, `restart`
    /// and the tray's "Restart service" run exactly what the foreground command
    /// would have run — including the `--profile` and `--config` overrides.
    pub fn to_cli_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("--profile={}", self.profile),
            format!("--config={}", self.config_file.display()),
            "up".to_string(),
        ];
        if self.verbose {
            args.push("--verbose".to_string());
        }
        if self.verbose_bodies {
            args.push("--verbose-bodies".to_string());
        }
        if self.all {
            args.push("--all".to_string());
        }
        if let Some(port) = self.port {
            args.push(format!("--port={port}"));
        }
        if let Some(proxy_port) = self.proxy_port {
            args.push(format!("--proxy-port={proxy_port}"));
        }
        if let Some(bind) = self.bind {
            args.push(format!("--bind={bind}"));
        }
        if let Some(external_url) = &self.external_url {
            args.push(format!("--external-url={external_url}"));
        }
        if self.no_tunnel {
            args.push("--no-tunnel".to_string());
        }
        if self.no_auth {
            args.push("--no-auth".to_string());
        }
        if self.allow_unauthenticated_exposure {
            args.push("--allow-unauthenticated-exposure".to_string());
        }
        for name in &self.names {
            args.push(name.clone());
        }
        args
    }
}

/// Start everything and block until shutdown.
pub fn up(paths: &Paths, tool_config: &ToolConfig, options: UpOptions) -> Result<()> {
    daemon::ensure_not_running(paths)?;

    let selected: Vec<(&String, &McpServer)> =
        servers::select(&tool_config.mcp_servers, &options.names, options.all)?;

    let server_config = tool_config.server();
    let auth_config = tool_config.auth();
    let tunnel_config = tool_config.tunnel();

    // What will run, and what would be refused: the same decision `mcp-ctl check` shows.
    let decision = exposure::decide(
        tool_config,
        &exposure::Request {
            bind: options.bind,
            port: options.port,
            proxy_port: options.proxy_port,
            external_url: options.external_url.clone(),
            no_auth: options.no_auth,
            no_tunnel: options.no_tunnel,
            allow_unauthenticated_exposure: options.allow_unauthenticated_exposure,
            config_file: paths.config_file.clone(),
        },
    );
    for note in &decision.notes {
        errln!("{note}");
    }
    if let Some(refusal) = decision.refusals.first() {
        bail!("{refusal}");
    }

    let bind = decision.bind;
    let requested_hub_port = decision.hub_port;
    let proxy_port = decision.proxy_port;
    let external_url = decision.external_url.clone();
    let use_proxy = decision.use_proxy;
    let use_tunnel = decision.use_tunnel;
    let tunnel_target = decision.tunnel_target;
    let use_auth = decision.use_auth;

    let bearer_token = if decision.use_bearer {
        match &auth_config.bearer_token {
            Some(value) => {
                let token = secret::resolve("auth.bearer_token", value)
                    .context("failed to resolve auth.bearer_token")?;
                crate::config::validate_bearer_token(&token)?;
                Some(token)
            }
            None => None,
        }
    } else {
        None
    };
    let use_bearer = bearer_token.is_some();

    // --- Bind before starting anything, so a busy port fails fast -----------
    let http_options = HttpOptions {
        bind,
        port: requested_hub_port,
        external_url: external_url.clone(),
        allowed_origins: server_config.allowed_origins.clone(),
        bearer_token: bearer_token.clone(),
        verbose: options.verbose,
        verbose_bodies: options.verbose_bodies,
    };
    let http = HttpServer::bind(&http_options)?;
    let hub_port = http.port();

    let control = ControlServer::bind()?;
    let state = StateFile {
        format: StateFile::FORMAT,
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        control_port: control.port(),
        token: control.token().to_string(),
        hub_port,
        proxy_port: if use_proxy { Some(proxy_port) } else { None },
        external_url: external_url.clone(),
        log_file: paths.log_file.clone(),
        started_at: control::now_secs(),
    };

    let auth_methods: Vec<String> = if use_auth {
        auth_config
            .methods()
            .into_iter()
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };

    let hub = Arc::new(Hub::new());
    let (stop_tx, stop_rx) = channel::<()>();
    // Flipped once the backends are connected, so `up -d` reports success only when
    // the service really serves.
    let ready = Arc::new(AtomicBool::new(false));

    // Answer control requests *before* the state file exists. `status` and `stop` must
    // reach a daemon that replies the moment it is advertised, and a second `up` must
    // never read "a state file nobody answers" as proof that this one died — that used
    // to delete the state file of a daemon that was still starting its backends.
    let public_url = Arc::new(Mutex::new(external_url.clone()));
    let control_info = Arc::new(ControlInfo {
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        started_at: state.started_at,
        hub_port,
        proxy_port: state.proxy_port,
        external_url: Arc::clone(&public_url),
        auth_methods: auth_methods.clone(),
        log_file: paths.log_file.clone(),
        ready: Arc::clone(&ready),
    });
    let control_hub = Arc::clone(&hub);
    let control_stop = stop_tx.clone();
    std::thread::spawn(move || control.serve(control_info, control_hub, control_stop));
    // Claim the daemon slot before advertising it: `create_new` is atomic, so two `up`
    // started at the same moment cannot both proceed. The claim records the control
    // port this process is already listening on.
    control::claim_daemon_slot(paths, state.control_port)?;
    control::write_state(paths, &state)?;

    outln!("Serving {} server(s):", selected.len());
    for (name, server) in &selected {
        outln!("  • {name}: {}", server.command_line());
    }

    // --- Backends -----------------------------------------------------------
    let tool_timeout = server_config.tool_timeout();
    outln!("\nConnecting to backends...");
    let mut failed = Vec::new();
    for (name, server) in &selected {
        let Some(command) = &server.command else {
            continue;
        };
        let env = servers::resolve_env(name, server)?;
        let timeouts = BackendTimeouts {
            handshake: BackendTimeouts::DEFAULT_HANDSHAKE,
            tool: server.tool_timeout(tool_timeout),
        };
        let spec = BackendSpec {
            name,
            command,
            args: &server.args,
            cwd: server.cwd.as_deref(),
            env: &env,
            env_clear: server.env_clear,
            prefix: server.prefix.as_deref(),
            filter: server.tools.as_ref(),
            timeouts,
        };
        if let Err(error) = hub.add_server(spec) {
            errln!("warning: skipping '{name}': {error:#}");
            failed.push(name.as_str());
        }
    }
    if !failed.is_empty() {
        errln!(
            "warning: {} server(s) could not be started: {}",
            failed.len(),
            failed.join(", ")
        );
    }
    if hub.tool_count() == 0 {
        // Better to fail loudly than to serve an empty hub behind a public URL.
        hub.shutdown();
        control::remove_state(paths);
        bail!("none of the selected servers started, so there is nothing to serve");
    }
    ready.store(true, Ordering::SeqCst);

    // --- Shutdown wiring ----------------------------------------------------
    let running = Arc::new(AtomicBool::new(true));

    let signal_running = Arc::clone(&running);
    let signal_stop = stop_tx.clone();
    ctrlc::set_handler(move || {
        // SIGINT, and with the `termination` feature also SIGTERM/SIGHUP: the same
        // graceful path `mcp-ctl stop` takes.
        signal_running.store(false, Ordering::SeqCst);
        let _ = signal_stop.send(());
    })
    .context("failed to install the signal handler")?;

    let http_hub = Arc::clone(&hub);
    let http_running = Arc::clone(&running);
    let http_thread = std::thread::spawn(move || {
        if let Err(error) = http.serve(http_hub, http_options, http_running) {
            errln!("warning: the HTTP endpoint stopped: {error}");
        }
    });

    // --- Optional auth proxy and tunnel -------------------------------------
    let mut children: Vec<ChildProc> = Vec::new();

    if use_proxy {
        let proxy = start_auth_proxy(
            &auth_config,
            &server_config,
            external_url.as_deref(),
            proxy_port,
            hub_port,
            paths,
        )?;
        children.push(ChildProc {
            name: "mcp-auth-proxy",
            child: proxy,
            critical: true,
            exited: false,
        });
    }

    let (tunnel_url_tx, tunnel_url_rx) = channel::<String>();
    if use_tunnel {
        // `exposure::decide` has already checked the target: with proxy auth it is the
        // proxy port, and a target that would expose the unauthenticated hub was refused.
        let target = tunnel_target.unwrap_or(if use_proxy { proxy_port } else { hub_port });
        if let Some((name, child)) = start_tunnel(tunnel_config.provider, target, tunnel_url_tx) {
            children.push(ChildProc {
                name,
                child,
                critical: false,
                exited: false,
            });
        }
    }

    // --- Optional tray icon -------------------------------------------------
    let tray_cfg = tool_config.tray();
    let (tray_tx, tray_rx) = channel::<TrayAction>();
    let mut tray = None;
    if tray_cfg.enabled {
        let info = TrayInfo {
            pid: std::process::id(),
            profile: paths.profile.clone(),
            hub_port,
            proxy_port: use_proxy.then_some(proxy_port),
            external_url: external_url.clone(),
        };
        tray = tray::start(Arc::clone(&hub), info, tray_tx);
    }

    // --- Banner -------------------------------------------------------------
    outln!();
    outln!(
        "mcp-ctl is serving {} tool(s) from {} server(s).",
        hub.tool_count(),
        hub.summarize().len()
    );
    if bind.is_loopback() {
        outln!("  Hub:      http://127.0.0.1:{hub_port}/mcp");
    } else {
        outln!("  Hub:      http://{bind}:{hub_port}/mcp");
        if !use_auth {
            errln!(
                "warning: the hub is bound to {bind}, so anything that can reach this machine \
                 can call your tools; the hub has no authentication of its own"
            );
        }
    }
    if use_proxy {
        outln!(
            "  Auth:     http://127.0.0.1:{proxy_port}/mcp ({})",
            auth_methods.join(", ")
        );
        // The proxy is only one way in: the hub itself stays reachable without
        // authentication, so anything that can reach its port bypasses the proxy.
        errln!(
            "note: the hub itself ({bind}:{hub_port}) has no authentication of its own: \
             anything that can reach that port can bypass the auth proxy."
        );
    } else if use_bearer {
        outln!("  Auth:     bearer token required on the hub (Authorization: Bearer ...)");
    }
    if let Some(url) = &external_url {
        outln!("  Public:   {}", mcp_endpoint_url(url));
    }
    outln!(
        "  Control:  pid {} on port {}",
        state.pid,
        state.control_port
    );
    outln!("  Log file: {}", paths.log_file.display());
    outln!("\nPress Ctrl+C to stop, or run `mcp-ctl stop` from another shell.");

    // --- Supervision --------------------------------------------------------
    let supervisor = Supervisor {
        hub: Arc::clone(&hub),
        running: Arc::clone(&running),
        stop_rx,
        tray_rx,
        tunnel_url_rx,
        public_url,
        paths: paths.clone(),
        state,
        children,
    };

    // On macOS and Windows the tray icon belongs to the thread that runs the application
    // event loop, so the supervisor moves to a thread of its own and the tray owns this
    // one. Everywhere else the supervisor stays here and the tray runs beside it.
    let outcome = match tray {
        Some(handle) if handle.needs_main_thread() => {
            let worker = std::thread::spawn(move || supervisor.run());
            handle.run(Arc::clone(&running));
            match worker.join() {
                Ok(outcome) => outcome,
                Err(_) => bail!("the service stopped unexpectedly"),
            }
        }
        other => {
            let outcome = supervisor.run();
            if let Some(handle) = &other {
                handle.shutdown();
            }
            outcome
        }
    };
    let _ = http_thread.join();

    if matches!(outcome, Outcome::RestartRequested) {
        let pid = daemon::spawn_detached(paths, &options.to_cli_args())?;
        outln!("Restarted mcp-ctl in the background (PID {pid}).");
        outln!("Logs: {}", paths.log_file.display());
        return Ok(());
    }

    outln!("mcp-ctl stopped.");
    Ok(())
}

/// What the supervision loop decided when it stopped.
enum Outcome {
    /// The service stopped and should stay stopped.
    Stopped,
    /// The service stopped because something asked for a restart.
    RestartRequested,
}

/// Everything the running service owns after startup: the backends, the optional child
/// processes, and the wiring that stops them again.
///
/// It is a value so that supervision can run on either thread: Linux keeps it on the main
/// thread, while macOS and Windows hand the main thread to the tray icon and move this
/// beside it.
struct Supervisor {
    hub: Arc<Hub>,
    running: Arc<AtomicBool>,
    stop_rx: Receiver<()>,
    tray_rx: Receiver<TrayAction>,
    tunnel_url_rx: Receiver<String>,
    public_url: Arc<Mutex<Option<String>>>,
    paths: Paths,
    state: StateFile,
    children: Vec<ChildProc>,
}

impl Supervisor {
    /// Supervise until something asks for a shutdown, then stop every child.
    fn run(mut self) -> Outcome {
        let mut next_health_check = Instant::now() + HEALTH_INTERVAL;
        let mut restart_requested = false;

        while self.running.load(Ordering::SeqCst) {
            if self
                .stop_rx
                .recv_timeout(Duration::from_millis(500))
                .is_ok()
            {
                self.running.store(false, Ordering::SeqCst);
                break;
            }

            while let Ok(action) = self.tray_rx.try_recv() {
                match action {
                    TrayAction::Shutdown => {
                        outln!("Tray: shut down requested.");
                        self.running.store(false, Ordering::SeqCst);
                    }
                    TrayAction::Restart => {
                        outln!("Tray: restart requested.");
                        restart_requested = true;
                        self.running.store(false, Ordering::SeqCst);
                    }
                }
            }

            // A tunnel that picks its own hostname (Cloudflare quick tunnels) only tells
            // us about it after the fact.
            if let Ok(url) = self.tunnel_url_rx.try_recv() {
                let mut public = self.public_url.lock().unwrap();
                if public.is_none() {
                    outln!("\nTunnel URL: {url}/mcp");
                    outln!(
                        "Set server.external_url to this (and restart) if you want the auth proxy in front of it."
                    );
                    *public = Some(url.clone());
                    let mut updated = self.state.clone();
                    updated.external_url = Some(url);
                    let _ = control::write_state(&self.paths, &updated);
                }
            }

            // Cheap liveness check: one non-blocking wait per backend, so a backend that
            // died loses its tools instead of failing calls one at a time.
            if Instant::now() >= next_health_check {
                for gone in self.hub.drop_dead() {
                    errln!("error: backend {gone} exited; its tools are no longer served");
                }
                next_health_check = Instant::now() + HEALTH_INTERVAL;
            }

            for proc in &mut self.children {
                if proc.exited {
                    continue;
                }
                if let Ok(Some(status)) = proc.child.try_wait() {
                    proc.exited = true;
                    if proc.critical {
                        errln!(
                            "error: {} exited unexpectedly ({status}); shutting down",
                            proc.name
                        );
                        self.running.store(false, Ordering::SeqCst);
                        break;
                    }
                    // The tunnel is best effort: losing it must not stop the hub.
                    errln!(
                        "warning: {} exited ({status}); continuing without it",
                        proc.name
                    );
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        outln!("\nShutting down...");
        self.hub.shutdown();
        for mut proc in self.children.drain(..) {
            if proc.exited {
                continue;
            }
            outln!("Stopping {}...", proc.name);
            if let Err(error) = platform::terminate(&mut proc.child) {
                errln!("warning: failed to stop {}: {error}", proc.name);
            }
        }
        control::remove_state(&self.paths);

        if restart_requested {
            Outcome::RestartRequested
        } else {
            Outcome::Stopped
        }
    }
}

/// Start `mcp-auth-proxy` in front of the hub.
///
/// Secrets go through the environment rather than the command line: arguments are
/// world-readable (`ps`, `/proc/*/cmdline`), and the password is what guards the
/// public endpoint.
fn start_auth_proxy(
    auth: &AuthConfig,
    server_config: &ServerConfig,
    external_url: Option<&str>,
    proxy_port: u16,
    hub_port: u16,
    paths: &Paths,
) -> Result<Child> {
    let binary = exposure::find_auth_proxy(server_config)?;
    let external_url = external_url.context("authentication requires a public URL")?;

    // The proxy keeps its private key and secret in here: owner-only on Unix.
    let data_path = paths.state_dir.join("auth-proxy-data");
    platform::ensure_private_dir(&data_path)
        .with_context(|| format!("failed to create {}", data_path.display()))?;

    let mut command = Command::new(&binary);
    command
        .arg("--listen")
        .arg(format!("127.0.0.1:{proxy_port}"))
        .arg("--external-url")
        .arg(external_url)
        .arg("--no-auto-tls")
        .arg("--data-path")
        .arg(&data_path)
        // A URL target means the proxy forwards HTTP/SSE traffic as-is, which is
        // exactly what the hub serves at /mcp.
        .arg(format!("http://127.0.0.1:{hub_port}"));

    if let Some(password) = &auth.password {
        let password = secret::resolve("auth.password", password)
            .context("failed to resolve auth.password")?;
        command.env("PASSWORD", password);
    }
    if let Some((id, secret)) = auth.github() {
        let id = secret::resolve("auth.github_client_id", id)
            .context("failed to resolve auth.github_client_id")?;
        let client_secret = secret::resolve("auth.github_client_secret", secret)
            .context("failed to resolve auth.github_client_secret")?;
        command
            .env("GITHUB_CLIENT_ID", id)
            .env("GITHUB_CLIENT_SECRET", client_secret);
    }
    if let Some((id, secret)) = auth.google() {
        let id = secret::resolve("auth.google_client_id", id)
            .context("failed to resolve auth.google_client_id")?;
        let client_secret = secret::resolve("auth.google_client_secret", secret)
            .context("failed to resolve auth.google_client_secret")?;
        command
            .env("GOOGLE_CLIENT_ID", id)
            .env("GOOGLE_CLIENT_SECRET", client_secret);
    }

    platform::isolate_process_group(&mut command);
    command
        .spawn()
        .with_context(|| format!("failed to start {binary}"))
}

/// Start the configured tunnel; a missing tunnel binary is a warning, not a failure.
fn start_tunnel(
    provider: TunnelProvider,
    port: u16,
    discovered_url: Sender<String>,
) -> Option<(&'static str, Child)> {
    let (name, mut command) = match provider {
        TunnelProvider::Tailscale => {
            let mut command = Command::new("tailscale");
            command.arg("funnel").arg(port.to_string());
            ("tailscale funnel", command)
        }
        TunnelProvider::Cloudflared => {
            let mut command = Command::new("cloudflared");
            command
                .arg("tunnel")
                .arg("--url")
                .arg(format!("http://127.0.0.1:{port}"));
            // A quick tunnel prints its random hostname on stderr; read it so nobody
            // has to dig through the log to find out where they are published.
            command.stderr(Stdio::piped());
            ("cloudflared", command)
        }
        TunnelProvider::None => return None,
    };

    outln!("Starting {name} for port {port}...");
    platform::isolate_process_group(&mut command);
    match command.spawn() {
        Ok(mut child) => {
            if let Some(stderr) = child.stderr.take() {
                std::thread::spawn(move || watch_tunnel_output(stderr, discovered_url));
            }
            Some((name, child))
        }
        Err(error) => {
            errln!("warning: failed to start {name} ({error}); continuing without a tunnel");
            None
        }
    }
}

/// Watch a tunnel's stderr for a public URL and hand it back to the supervisor.
fn watch_tunnel_output(stderr: std::process::ChildStderr, sender: Sender<String>) {
    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
        if let Some(url) = public_url_in(&line) {
            let _ = sender.send(url);
        }
    }
}

/// Pull an `https://…trycloudflare.com` URL out of a cloudflared log line.
fn public_url_in(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let rest = &line[start..];
    let end = rest
        .find(|character: char| character.is_whitespace() || character == '|' || character == '"')
        .unwrap_or(rest.len());
    let url = rest[..end].trim_end_matches(['.', ',', ')']);
    url.contains(".trycloudflare.com").then(|| url.to_string())
}

/// Watch a tunnel's stderr for a public URL and hand it back to the supervisor.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflared_urls_are_extracted_from_its_log() {
        let line = "2026-01-01T00:00:00Z INF |  https://smooth-river-1234.trycloudflare.com  |";
        assert_eq!(
            public_url_in(line),
            Some("https://smooth-river-1234.trycloudflare.com".to_string())
        );
        assert_eq!(public_url_in("nothing to see here"), None);
        assert_eq!(public_url_in("see https://example.com for docs"), None);
        assert_eq!(
            public_url_in("url=https://plain-abc.trycloudflare.com."),
            Some("https://plain-abc.trycloudflare.com".to_string())
        );
    }
}
