//! Background daemon lifecycle: starting, stopping and inspecting `mcp-ctl up -d`.
//!
//! Everything here goes through the control channel in `src/control.rs`. Nothing in
//! mcp-ctl inspects `/proc`, sends signals to a PID it found somewhere, or guesses
//! whether a process is "ours" from its command line.

use anyhow::{Context, Result, bail};
use serde_json::json;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::config::{self, Paths, ToolConfig};
use crate::control::{self, StateFile, StatusReport};
use crate::orchestrator::UpOptions;
use crate::platform;

/// How long `stop` waits for a daemon that was asked to shut down.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a freshly spawned daemon has to start answering control requests.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// How large the daemon log may grow before it is rotated as a daemon starts.
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// How many lines `mcp-ctl logs` prints before following.
const LOG_TAIL_LINES: usize = 50;

/// The state of a daemon that is listening *right now*.
///
/// A state file whose control port does not answer belongs to a crashed daemon and
/// is removed, so nothing downstream has to reason about stale files.
pub fn running_state(paths: &Paths) -> Result<Option<StateFile>> {
    let Some(state) = control::read_state(paths)? else {
        return Ok(None);
    };
    if control::is_listening(&state) {
        return Ok(Some(state));
    }
    // One refused connection is not proof of death (a daemon may be between binding
    // its control port and serving it), so confirm before discarding it.
    sleep(Duration::from_millis(150));
    if control::is_listening(&state) {
        return Ok(Some(state));
    }
    control::remove_state(paths);
    Ok(None)
}

/// Refuse to start a second hub.
pub fn ensure_not_running(paths: &Paths) -> Result<()> {
    if let Some(state) = running_state(paths)? {
        bail!(
            "mcp-ctl is already running (PID {}, hub port {}).\nUse `mcp-ctl status` to inspect it, `mcp-ctl restart` to replace it, or `mcp-ctl stop` to stop it.",
            state.pid,
            state.hub_port
        );
    }
    Ok(())
}

/// Start `mcp-ctl up <args>` in the background, with its output appended to the log.
pub fn spawn_detached(paths: &Paths, args: &[String]) -> Result<u32> {
    ensure_not_running(paths)?;
    let exe = std::env::current_exe().context("could not determine the mcp-ctl executable path")?;
    paths.ensure_state_dir()?;
    rotate_log(paths);

    // Owner-only from creation: `--verbose-bodies` logs tool arguments and results.
    let log_file = platform::open_private_append(&paths.log_file)
        .with_context(|| format!("failed to open {}", paths.log_file.display()))?;
    // Also fix a log left by an earlier run under the process umask.
    let _ = platform::restrict_to_owner(&paths.log_file);
    let log_errors = log_file
        .try_clone()
        .context("failed to duplicate the log file handle")?;

    let mut command = Command::new(&exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_errors));
    // Detach from the terminal that started it, so closing the shell does not take
    // the daemon and every MCP server it supervises down with it.
    platform::detach(&mut command);

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {}", exe.display()))?;

    // Wait for the daemon to say it is serving, instead of guessing with a fixed sleep.
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(state) = control::read_state(paths)?
            && state.pid == child.id()
            && control::query_status(&state).is_some_and(|report| report.ready)
        {
            return Ok(state.pid);
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!(
                "mcp-ctl failed to start in the background ({status}).\nLast log lines:\n{}",
                tail(&paths.log_file, 10)
            );
        }
        if Instant::now() >= deadline {
            // Do not leave the child we started behind: `up -d` said it failed, so
            // nothing should still be serving.
            let _ = platform::terminate(&mut child);
            bail!(
                "mcp-ctl did not start within {}s.\nLast log lines:\n{}",
                STARTUP_TIMEOUT.as_secs(),
                tail(&paths.log_file, 10)
            );
        }
        sleep(Duration::from_millis(100));
    }
}

/// Stop the running daemon.
///
/// The daemon is asked over its control port first, which lets it stop its backends
/// and clean up. A process is only ever signalled after it has answered with the
/// control token, and only after the operator asked for it explicitly: a PID read from
/// a state file proves nothing on its own, since the daemon may have died and the
/// number been handed to something else.
pub fn stop(paths: &Paths, force: bool) -> Result<()> {
    let Some(state) = control::read_state(paths)? else {
        outln!("{} is not running.", service_name(paths));
        note_other_profiles(paths);
        return Ok(());
    };

    // An answer carrying this state file's own PID is the proof that the process we
    // would signal is still the daemon that wrote the file.
    let report = control::query_status(&state).filter(|report| report.pid == state.pid);

    let Some(report) = report else {
        if !control::is_listening(&state) {
            outln!(
                "{} is not running (removing the stale state file of PID {}).",
                service_name(paths),
                state.pid
            );
            control::remove_state(paths);
            note_other_profiles(paths);
            return Ok(());
        }

        // Something holds the control port without answering for it. That is not
        // enough to identify a process, so nothing is signalled.
        bail!(
            "something is listening on the control port of PID {} but did not answer with the \
             control token.\nmcp-ctl does not signal a process it cannot identify. It may still \
             be starting up (try again in a moment), or it may be wedged (kill PID {} yourself \
             if you are sure it is mcp-ctl).",
            state.pid,
            state.pid
        );
    };

    outln!("Stopping {} (PID {})...", service_name(paths), report.pid);
    let asked = control::request_shutdown(&state);

    if wait_until_stopped(&state, STOP_TIMEOUT) {
        control::remove_state(paths);
        outln!("{} stopped.", service_name(paths));
        note_other_profiles(paths);
        return Ok(());
    }

    if let Err(error) = asked {
        errln!("warning: {error}");
    }

    if !force {
        bail!(
            "PID {} is still running after {}s.\nRe-run `mcp-ctl stop --force` to kill it, or inspect it with `mcp-ctl status`.",
            state.pid,
            STOP_TIMEOUT.as_secs()
        );
    }

    outln!("Killing PID {}...", state.pid);
    platform::force_kill(state.pid)?;
    if wait_until_stopped(&state, STOP_TIMEOUT) {
        control::remove_state(paths);
        outln!("{} stopped.", service_name(paths));
        note_other_profiles(paths);
        return Ok(());
    }
    bail!("PID {} is still running after being killed", state.pid);
}

/// Other profiles whose daemon is still running, so `stop` can point at them.
fn note_other_profiles(current: &Paths) {
    let (Ok(config_root), Ok(state_root)) = (config::config_dir(), config::state_dir()) else {
        return;
    };
    let others: Vec<String> = config::profiles(&config_root)
        .into_iter()
        .filter(|name| *name != current.profile)
        .filter(|name| {
            config::paths_for_profile(&config_root, &state_root, name)
                .ok()
                .and_then(|paths| control::read_state(&paths).ok().flatten())
                .is_some_and(|state| control::is_listening(&state))
        })
        .collect();
    if others.is_empty() {
        return;
    }
    outln!(
        "note: {} other profile(s) still running: {} (`mcp-ctl stop <profile>` stops one)",
        others.len(),
        others.join(", ")
    );
}

/// Restart the daemon, or start it when it was not running.
pub fn restart(paths: &Paths, options: &UpOptions) -> Result<u32> {
    if control::read_state(paths)?.is_some() {
        stop(paths, false)?;
        // Give the operating system a moment to release the listening ports.
        sleep(Duration::from_millis(300));
    } else {
        outln!("mcp-ctl was not running; starting it now.");
    }

    let pid = spawn_detached(paths, &options.to_cli_args())?;
    outln!("mcp-ctl started in background (PID {pid}).");
    outln!("Logs: {}", paths.log_file.display());
    Ok(pid)
}

/// Report what the installation is doing: every profile, or the one detailed report when
/// there is only the default profile.
pub fn status_all(json: bool) -> Result<()> {
    let config_root = config::config_dir()?;
    let state_root = config::state_dir()?;
    let names = config::profiles(&config_root);

    // One profile means the detailed report, which is what a single-profile installation
    // has always printed.
    if names.len() == 1 {
        let paths = config::paths_for_profile(&config_root, &state_root, &names[0])?;
        return status(&paths, json);
    }

    let mut entries = Vec::new();
    for name in &names {
        let paths = config::paths_for_profile(&config_root, &state_root, name)?;
        let state = running_state(&paths)?;
        let report = state.as_ref().and_then(control::query_status);
        entries.push((name.clone(), state, report, configured_servers(&paths)));
    }

    if json {
        let profiles: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, state, report, configured)| {
                json!({
                    "profile": name,
                    "running": state.is_some(),
                    "pid": state.as_ref().map(|state| state.pid),
                    "servers_configured": configured,
                    "status": report,
                })
            })
            .collect();
        outln!(
            "{}",
            serde_json::to_string_pretty(&json!({ "profiles": profiles }))?
        );
        return Ok(());
    }

    outln!("Profiles ({})", entries.len());
    let width = entries
        .iter()
        .map(|(name, ..)| name.len())
        .max()
        .unwrap_or(0);
    for (name, state, report, configured) in &entries {
        match (state, report) {
            (Some(state), Some(report)) => outln!(
                "  ● {name:width$}  running (PID {}, hub port {}, {} tools from {} server(s), up {})",
                state.pid,
                report.hub_port,
                report.total_tools,
                report.servers.len(),
                format_duration(report.uptime_secs)
            ),
            (Some(state), None) => outln!(
                "  ● {name:width$}  running (PID {}) but did not answer a status request",
                state.pid
            ),
            (None, _) => match configured {
                Some(count) => {
                    outln!("  ○ {name:width$}  not running ({count} server(s) configured)")
                }
                None => outln!("  ○ {name:width$}  not running"),
            },
        }
    }
    outln!(
        "\n`mcp-ctl status <profile>` shows one of them, `mcp-ctl --profile <name> up -d` starts one."
    );
    Ok(())
}

/// How many servers a profile has configured, when its file can be read.
fn configured_servers(paths: &Paths) -> Option<usize> {
    let tool_config = ToolConfig::load_from(&paths.config_file).ok()?;
    Some(tool_config.mcp_servers.len())
}

/// Report what the daemon is doing, or that nothing is running.
pub fn status(paths: &Paths, as_json: bool) -> Result<()> {
    let state = running_state(paths)?;

    if as_json {
        // The same information a tray icon or a health script would want.
        match &state {
            Some(state) => {
                let value = json!({
                    "running": true,
                    "pid": state.pid,
                    "control_port": state.control_port,
                    "log_file": state.log_file.display().to_string(),
                    "status": control::query_status(state),
                });
                outln!("{}", serde_json::to_string_pretty(&value)?);
            }
            None => outln!(
                "{}",
                serde_json::to_string_pretty(&json!({"running": false}))?
            ),
        }
        return Ok(());
    }

    let Some(state) = state else {
        outln!("○ {} is not running.", service_name(paths));
        return Ok(());
    };

    match control::query_status(&state) {
        Some(report) => print_status(paths, &report),
        None => {
            outln!(
                "● {} is running (PID {}) but did not answer a status request.",
                service_name(paths),
                state.pid
            );
            outln!("  Control port: {}", state.control_port);
        }
    }
    Ok(())
}

/// What this installation calls itself in messages: `mcp-ctl`, or `mcp-ctl (work)` for a
/// profile, so two daemons are never confused for one.
fn service_name(paths: &Paths) -> String {
    if paths.profile == config::DEFAULT_PROFILE {
        "mcp-ctl".to_string()
    } else {
        format!("mcp-ctl ({})", paths.profile)
    }
}

fn print_status(paths: &Paths, report: &StatusReport) {
    outln!(
        "● {} is {} (PID {}, version {}, up {})",
        service_name(paths),
        if report.ready { "running" } else { "starting" },
        report.pid,
        report.version,
        format_duration(report.uptime_secs)
    );
    outln!("  Hub:      http://127.0.0.1:{}/mcp", report.hub_port);
    if let Some(proxy_port) = report.proxy_port {
        let methods = if report.auth_methods.is_empty() {
            "no authentication configured".to_string()
        } else {
            report.auth_methods.join(", ")
        };
        outln!("  Auth:     http://127.0.0.1:{proxy_port}/mcp ({methods})");
    } else if !report.auth_methods.is_empty() {
        // A bearer token is checked by the hub itself; there is no proxy port.
        outln!("  Auth:     {} (hub)", report.auth_methods.join(", "));
    }
    if let Some(external_url) = &report.external_url {
        outln!("  External: {external_url}/mcp");
    }
    if report.servers.is_empty() {
        outln!("  Servers:  none");
    } else {
        let servers = report
            .servers
            .iter()
            .map(|server| {
                if server.alive {
                    format!("{} ({} tools)", server.name, server.tools)
                } else {
                    format!("{} (exited)", server.name)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        outln!(
            "  Servers:  {servers} — {} tools, {} calls served",
            report.total_tools,
            report.calls
        );
    }
    outln!("  Log:      {}", report.log_file.display());
}

/// `221` -> `3m 41s`.
fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Print the daemon log, optionally following it until interrupted.
pub fn logs(paths: &Paths, follow: bool) -> Result<()> {
    if !paths.log_file.exists() {
        outln!("No log file yet at {}.", paths.log_file.display());
        outln!("Start a background daemon with `mcp-ctl up -d`.");
        return Ok(());
    }

    let contents = fs::read_to_string(&paths.log_file)
        .with_context(|| format!("failed to read {}", paths.log_file.display()))?;
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(LOG_TAIL_LINES);
    for line in &lines[start..] {
        outln!("{line}");
    }

    if !follow {
        return Ok(());
    }

    let mut offset = contents.len() as u64;
    loop {
        sleep(Duration::from_millis(250));
        let Ok(metadata) = fs::metadata(&paths.log_file) else {
            continue;
        };
        if metadata.len() < offset {
            // The log was rotated underneath us: start again from the top.
            offset = 0;
        }
        if metadata.len() <= offset {
            continue;
        }
        let mut file = fs::File::open(&paths.log_file)
            .with_context(|| format!("failed to open {}", paths.log_file.display()))?;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("failed to seek in {}", paths.log_file.display()))?;
        let mut appended = String::new();
        file.read_to_string(&mut appended)
            .with_context(|| format!("failed to read {}", paths.log_file.display()))?;
        offset += appended.len() as u64;
        for line in appended.lines() {
            outln!("{line}");
        }
    }
}

/// Rotate the daemon log once it has grown past `MAX_LOG_BYTES`.
///
/// Rotation happens when a daemon starts, which keeps a busy install bounded without a
/// background timer. A daemon that runs for months should be rotated by the system
/// (logrotate on Linux, `newsyslog` on macOS).
fn rotate_log(paths: &Paths) {
    let Ok(metadata) = fs::metadata(&paths.log_file) else {
        return;
    };
    if metadata.len() < MAX_LOG_BYTES {
        return;
    }
    let previous = paths.log_file.with_extension("log.1");
    let _ = fs::remove_file(&previous);
    let _ = fs::rename(&paths.log_file, &previous);
}

/// Wait for the control port of a daemon to stop answering.
fn wait_until_stopped(state: &StateFile, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        // The port is gone only when the process really is: a daemon that stopped
        // answering but still holds the port has not stopped.
        if !control::is_listening(state) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(100));
    }
}

/// The last `count` lines of a file, for startup failure messages.
fn tail(path: &Path, count: usize) -> String {
    let Ok(contents) = fs::read_to_string(path) else {
        return format!("  (could not read {})", path.display());
    };
    let lines: Vec<&str> = contents.lines().collect();
    if lines.is_empty() {
        return "  (the log is empty)".to_string();
    }
    let start = lines.len().saturating_sub(count);
    lines[start..]
        .iter()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::path::PathBuf;

    fn state_for(port: u16) -> StateFile {
        StateFile {
            format: StateFile::FORMAT,
            pid: 4242,
            version: "test".to_string(),
            control_port: port,
            token: "token".to_string(),
            hub_port: 37373,
            proxy_port: None,
            external_url: None,
            log_file: PathBuf::from("test.log"),
            started_at: control::now_secs(),
        }
    }

    fn sandbox_paths(tag: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("mcp-ctl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Paths {
            profile: crate::config::DEFAULT_PROFILE.to_string(),
            config_file: dir.join("config.json"),
            env_file: dir.join(".env"),
            state_file: dir.join("daemon.json"),
            log_file: dir.join("mcp-ctl.log"),
            state_dir: dir.clone(),
            config_dir: dir,
        }
    }

    #[test]
    fn a_daemon_that_does_not_answer_yet_keeps_its_state_file() {
        // A daemon that is still starting (or wedged) accepts the connection but does
        // not answer. Discarding its state file would leave it running and invisible.
        let paths = sandbox_paths("daemon-busy");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        control::write_state(&paths, &state_for(port)).unwrap();

        let state = running_state(&paths)
            .expect("the state file is readable")
            .expect("a listening daemon counts as running");
        assert_eq!(state.control_port, port);
        assert!(paths.state_file.exists(), "the state file must survive");

        let _ = std::fs::remove_dir_all(&paths.state_dir);
    }

    #[test]
    fn a_state_file_nobody_listens_for_is_removed() {
        // The control port is closed, so the daemon behind this file is gone.
        let paths = sandbox_paths("daemon-stale");
        control::write_state(&paths, &state_for(closed_port())).unwrap();

        assert!(running_state(&paths).unwrap().is_none());
        assert!(!paths.state_file.exists());

        let _ = std::fs::remove_dir_all(&paths.state_dir);
    }

    /// A loopback port nothing is listening on right now.
    ///
    /// Tests run in parallel and ephemeral ports are reused, so the port is checked
    /// before it is handed out instead of being assumed free.
    fn closed_port() -> u16 {
        for _ in 0..20 {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            if !control::is_listening(&state_for(port)) {
                return port;
            }
        }
        panic!("could not find a free loopback port");
    }

    #[test]
    fn stop_refuses_to_signal_a_process_it_cannot_identify() {
        // A state file whose control port is held by something that does not answer with
        // the token: the PID in the file may be a recycled number, so `--force` must
        // refuse rather than kill it.
        let paths = sandbox_paths("daemon-unverified");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // A PID that cannot exist, so a regression cannot kill anything real.
        let mut state = state_for(port);
        state.pid = 999_999;
        control::write_state(&paths, &state).unwrap();

        let error = stop(&paths, true).expect_err("an unverified daemon is not killed");
        let message = error.to_string();
        assert!(message.contains("cannot identify"), "{message}");
        assert!(paths.state_file.exists(), "the state file is kept");

        let _ = std::fs::remove_dir_all(&paths.state_dir);
    }

    #[test]
    fn durations_are_human_readable() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(221), "3m 41s");
        assert_eq!(format_duration(7325), "2h 2m");
    }

    #[test]
    fn tail_returns_the_last_lines() {
        let path = std::env::temp_dir().join(format!("mcp-ctl-tail-{}.log", std::process::id()));
        fs::write(&path, "one\ntwo\nthree\n").unwrap();
        let text = tail(&path, 2);
        let _ = fs::remove_file(&path);
        assert_eq!(text, "  two\n  three");
    }
}
