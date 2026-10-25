//! The daemon control channel.
//!
//! `mcp-ctl up -d` runs in the background, so the commands that manage it need to
//! find it, ask what it is doing, and stop it — on Windows just as well as on Unix,
//! where there is no SIGTERM to send.
//!
//! A daemon listens on a loopback TCP port with an operating-system-assigned number
//! and writes a small state file into its state directory:
//!
//! * the *port* tells `status` and `stop` where to connect. A successful connection is
//!   proof that the daemon is alive, which is what makes stale state files harmless:
//!   no PID is ever inspected, so a recycled PID can never be mistaken for the daemon.
//! * the *token* keeps other local users from driving your daemon.
//!
//! The state file is the only thing mcp-ctl writes that contains a secret (the
//! token), which is why it is created owner-only on Unix.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Paths;
use crate::hub::Hub;
use crate::platform;
use std::path::Path;

/// How long a control connection may take, in either direction.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// A control request is one small JSON line; a longer one is not a client we serve.
const MAX_CONTROL_LINE: usize = 8 * 1024;

/// A status reply grows with the number of servers, so it gets a larger cap than a request.
const MAX_CONTROL_REPLY: usize = 1024 * 1024;

/// Concurrent control connections. The listener is loopback-only, but a local process must
/// not be able to exhaust the daemon's threads before it even presents a token.
const MAX_CONTROL_CONNECTIONS: usize = 32;

/// What the daemon records about itself, and what `status` reads back.
#[derive(Clone, Serialize, Deserialize)]
pub struct StateFile {
    /// Format version, so a future mcp-ctl can recognise an old file.
    pub format: u32,
    pub pid: u32,
    pub version: String,
    pub control_port: u16,
    pub token: String,
    pub hub_port: u16,
    #[serde(default)]
    pub proxy_port: Option<u16>,
    #[serde(default)]
    pub external_url: Option<String>,
    pub log_file: PathBuf,
    pub started_at: u64,
}

impl StateFile {
    pub const FORMAT: u32 = 1;
}

/// Never print the control token, not even by accident.
impl fmt::Debug for StateFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateFile")
            .field("format", &self.format)
            .field("pid", &self.pid)
            .field("version", &self.version)
            .field("control_port", &self.control_port)
            .field("token", &"<redacted>")
            .field("hub_port", &self.hub_port)
            .field("proxy_port", &self.proxy_port)
            .field("external_url", &self.external_url)
            .field("log_file", &self.log_file)
            .field("started_at", &self.started_at)
            .finish()
    }
}

/// The facts about a running daemon that do not change while it runs.
#[derive(Clone, Debug)]
pub struct ControlInfo {
    pub pid: u32,
    pub version: String,
    pub started_at: u64,
    pub hub_port: u16,
    pub proxy_port: Option<u16>,
    pub external_url: Arc<Mutex<Option<String>>>,
    pub auth_methods: Vec<String>,
    pub log_file: PathBuf,
    /// Set once the backends are connected and the hub is serving, so `up -d` can wait
    /// for a service that is actually up rather than one that merely answers.
    pub ready: Arc<AtomicBool>,
}

/// A live report, assembled when `status` asks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusReport {
    pub pid: u32,
    pub version: String,
    pub uptime_secs: u64,
    pub hub_port: u16,
    #[serde(default)]
    pub proxy_port: Option<u16>,
    #[serde(default)]
    pub external_url: Option<String>,
    #[serde(default)]
    pub auth_methods: Vec<String>,
    /// False while the daemon is still starting its backends.
    #[serde(default = "ready_by_default")]
    pub ready: bool,
    pub servers: Vec<ServerStatus>,
    pub total_tools: usize,
    pub calls: u64,
    pub log_file: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerStatus {
    pub name: String,
    pub tools: usize,
    /// False once the backend process has exited and its tools were withdrawn.
    #[serde(default = "alive_by_default")]
    pub alive: bool,
}

fn alive_by_default() -> bool {
    true
}

/// A reply that does not say whether the daemon is ready comes from one that only answers once it
/// is serving, so it counts as ready.
fn ready_by_default() -> bool {
    true
}

impl ControlInfo {
    fn report(&self, hub: &Hub) -> StatusReport {
        StatusReport {
            pid: self.pid,
            version: self.version.clone(),
            uptime_secs: now_secs().saturating_sub(self.started_at),
            hub_port: self.hub_port,
            proxy_port: self.proxy_port,
            external_url: self
                .external_url
                .lock()
                .map(|url| url.clone())
                .unwrap_or_default(),
            auth_methods: self.auth_methods.clone(),
            ready: self.ready.load(Ordering::SeqCst),
            servers: hub
                .summarize()
                .into_iter()
                .map(|(name, tools, alive)| ServerStatus { name, tools, alive })
                .collect(),
            total_tools: hub.tool_count(),
            calls: hub.calls(),
            log_file: self.log_file.clone(),
        }
    }
}

/// One line of JSON in each direction.
#[derive(Serialize, Deserialize)]
struct Message {
    token: String,
    command: String,
}

#[derive(Serialize, Deserialize)]
struct Reply {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<StatusReport>,
}

impl Reply {
    fn failed(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            status: None,
        }
    }
}

/// The daemon side of the control channel.
///
/// The token is minted here, so a caller cannot accidentally serve an empty one.
pub struct ControlServer {
    listener: TcpListener,
    port: u16,
    token: String,
}

impl ControlServer {
    /// Bind on loopback only: the control channel is never exposed to the network.
    pub fn bind() -> Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .context("failed to bind the daemon control port")?;
        let port = listener
            .local_addr()
            .context("failed to read the daemon control port")?
            .port();
        Ok(Self {
            listener,
            port,
            token: random_token()?,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The token `status` and `stop` must present. It goes into the state file and
    /// nowhere else.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Answer control requests until the process exits.
    ///
    /// Every connection is answered on its own thread, so a client that connects and then
    /// says nothing holds only its own thread for the read timeout instead of delaying
    /// `status` or `stop` behind it.
    pub fn serve(self, info: Arc<ControlInfo>, hub: Arc<Hub>, stop: Sender<()>) {
        let in_flight = Arc::new(AtomicUsize::new(0));
        loop {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) => {
                    // Back off instead of spinning if the listener misbehaves.
                    errln!("warning: control connection failed: {error}");
                    std::thread::sleep(Duration::from_millis(250));
                    continue;
                }
            };
            if in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_CONTROL_CONNECTIONS {
                in_flight.fetch_sub(1, Ordering::SeqCst);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
            let token = self.token.clone();
            let info = Arc::clone(&info);
            let hub = Arc::clone(&hub);
            let stop = stop.clone();
            let guard = ControlGuard(Arc::clone(&in_flight));
            std::thread::spawn(move || {
                let _guard = guard;
                let _ = stream.set_read_timeout(Some(CONTROL_TIMEOUT));
                let _ = stream.set_write_timeout(Some(CONTROL_TIMEOUT));
                if let Err(error) = answer(&stream, &token, &info, &hub, &stop) {
                    errln!("warning: control request failed: {error}");
                }
            });
        }
    }
}

/// Decrements the control connection counter however the thread ends.
struct ControlGuard(Arc<AtomicUsize>);

impl Drop for ControlGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn answer(
    stream: &TcpStream,
    token: &str,
    info: &ControlInfo,
    hub: &Hub,
    stop: &Sender<()>,
) -> Result<()> {
    let mut line = String::new();
    BufReader::new(stream)
        .take(MAX_CONTROL_LINE as u64)
        .read_line(&mut line)
        .context("failed to read the control request")?;
    if line.len() >= MAX_CONTROL_LINE && !line.ends_with('\n') {
        bail!("control request is too long");
    }

    let message: Message =
        serde_json::from_str(line.trim()).context("malformed control request")?;
    if !tokens_match(token, &message.token) {
        return write_reply(stream, &Reply::failed("invalid control token"));
    }

    match message.command.as_str() {
        "status" => write_reply(
            stream,
            &Reply {
                ok: true,
                error: None,
                status: Some(info.report(hub)),
            },
        ),
        "shutdown" => {
            write_reply(
                stream,
                &Reply {
                    ok: true,
                    error: None,
                    status: None,
                },
            )?;
            // The supervisor loop owns shutdown: asking it to stop is what triggers the
            // graceful path (stopping backends, removing the state file).
            let _ = stop.send(());
            Ok(())
        }
        other => write_reply(
            stream,
            &Reply::failed(format!("unknown control command '{other}'")),
        ),
    }
}

fn write_reply(mut stream: &TcpStream, reply: &Reply) -> Result<()> {
    let mut line = serde_json::to_string(reply)?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .context("failed to write the control reply")?;
    stream
        .flush()
        .context("failed to flush the control reply")?;
    Ok(())
}

fn request(state: &StateFile, command: &str) -> Result<Reply> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, state.control_port));
    let stream = TcpStream::connect_timeout(&address, CONTROL_TIMEOUT)
        .with_context(|| format!("no mcp-ctl daemon is listening on {address}"))?;
    let _ = stream.set_read_timeout(Some(CONTROL_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONTROL_TIMEOUT));

    let message = serde_json::to_string(&Message {
        token: state.token.clone(),
        command: command.to_string(),
    })?;
    let mut writer = &stream;
    writer
        .write_all(message.as_bytes())
        .context("failed to write the control request")?;
    writer
        .write_all(b"\n")
        .context("failed to write the control request")?;
    writer
        .flush()
        .context("failed to flush the control request")?;

    let mut line = String::new();
    BufReader::new(&stream)
        .take(MAX_CONTROL_REPLY as u64)
        .read_line(&mut line)
        .context("failed to read the control reply")?;
    if line.len() >= MAX_CONTROL_REPLY && !line.ends_with('\n') {
        bail!("the daemon sent an overlong control reply");
    }
    let reply: Reply =
        serde_json::from_str(line.trim()).context("the daemon sent an unexpected reply")?;
    if !reply.ok {
        bail!(
            "the daemon refused: {}",
            reply.error.unwrap_or_else(|| "unknown reason".to_string())
        );
    }
    Ok(reply)
}

/// Ask a running daemon what it is doing. `None` means nothing answered.
pub fn query_status(state: &StateFile) -> Option<StatusReport> {
    request(state, "status").ok().and_then(|reply| reply.status)
}

/// Ask a running daemon to shut down gracefully.
pub fn request_shutdown(state: &StateFile) -> Result<()> {
    request(state, "shutdown").map(|_| ())
}

/// Is anything listening on this state file's control port, whether or not it answers?
///
/// A daemon that is still starting (launching its backends) or wedged accepts the
/// connection but answers late or never, so a successful connect is what separates
/// "busy" from "gone". Only a refused connection proves the state file is stale —
/// deleting one while its daemon still runs would leave that daemon unmanageable.
pub fn is_listening(state: &StateFile) -> bool {
    port_is_listening(state.control_port)
}

/// Is anything listening on this loopback port?
fn port_is_listening(port: u16) -> bool {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&address, CONTROL_TIMEOUT).is_ok()
}

/// What a daemon records when it claims the slot, before it writes its state file.
#[derive(Serialize, Deserialize)]
struct Claim {
    pid: u32,
    control_port: u16,
}

fn lock_path(paths: &Paths) -> PathBuf {
    paths.state_dir.join("daemon.lock")
}

/// Claim this installation's daemon slot, so two `up` started at the same moment cannot
/// both believe they are the only one.
///
/// The state file cannot do this job on its own: it is written once the control port is
/// bound, which leaves a window in which a second process sees no state file at all.
/// Creating a lock file is atomic on every platform, so exactly one of two racing
/// processes wins. The claim records the control port it already listens on, so a
/// process that is starting up is recognised even before it writes a state file.
///
/// A lock file left behind by a crash is reclaimed, but only when nothing is listening
/// on the port it advertises.
pub fn claim_daemon_slot(paths: &Paths, control_port: u16) -> Result<()> {
    paths.ensure_state_dir()?;
    let lock = lock_path(paths);
    let mut claim = serde_json::to_vec(&Claim {
        pid: std::process::id(),
        control_port,
    })?;
    claim.push(b'\n');

    for attempt in 0..2 {
        match platform::create_new_private_file(&lock) {
            Ok(mut file) => {
                file.write_all(&claim)
                    .with_context(|| format!("failed to write {}", lock.display()))?;
                return Ok(());
            }
            Err(_) if attempt == 0 => {
                if let Some(state) = live_daemon(paths)? {
                    bail!(
                        "mcp-ctl is already running (PID {}, hub port {}).\nUse `mcp-ctl status` to inspect it, `mcp-ctl restart` to replace it, or `mcp-ctl stop` to stop it.",
                        state.pid,
                        state.hub_port
                    );
                }
                if is_starting_up(&lock) {
                    bail!(
                        "another mcp-ctl is starting up.\nGive it a moment, then use `mcp-ctl status`."
                    );
                }
                // Nothing answers on the port it claims: a crash left the file behind.
                let _ = std::fs::remove_file(&lock);
            }
            Err(error) => bail!("another mcp-ctl is starting up: {error}"),
        }
    }
    Ok(())
}

/// The daemon described by this installation's state file, if it is still listening.
fn live_daemon(paths: &Paths) -> Result<Option<StateFile>> {
    Ok(read_state(paths)?.filter(|state| port_is_listening(state.control_port)))
}

/// Is a process in the middle of claiming the slot?
///
/// The claim file is created empty and its content written immediately afterwards, so a
/// claim read as empty belongs either to a process that is claiming right now or to one
/// that crashed in between. Waiting a moment tells the two apart, which is what keeps a
/// racing `up` from reclaiming a claim that is about to be filled in.
fn is_starting_up(lock: &Path) -> bool {
    for _ in 0..20 {
        match read_claim(lock) {
            Some(claim) => return port_is_listening(claim.control_port),
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    false
}

fn read_claim(path: &Path) -> Option<Claim> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Write the state file, atomically and readable only by its owner.
///
/// The temporary file is created with mode 0600 up front, so the control token is
/// never briefly world-readable between the write and the chmod.
pub fn write_state(paths: &Paths, state: &StateFile) -> Result<()> {
    paths.ensure_state_dir()?;
    let temporary = paths.state_file.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(state)?;
    let mut file = platform::create_private_file(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    file.write_all(&json)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    drop(file);
    // Covers a temporary file left behind by an interrupted run.
    platform::restrict_to_owner(&temporary)?;
    // Replace rather than rewrite, so a reader never observes a half-written file.
    let _ = std::fs::remove_file(&paths.state_file);
    std::fs::rename(&temporary, &paths.state_file)
        .with_context(|| format!("failed to move {} into place", temporary.display()))?;
    Ok(())
}

/// Read the state file. A missing or damaged file means "no daemon".
pub fn read_state(paths: &Paths) -> Result<Option<StateFile>> {
    if !paths.state_file.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&paths.state_file)
        .with_context(|| format!("failed to read {}", paths.state_file.display()))?;
    match serde_json::from_str(&text) {
        Ok(state) => Ok(Some(state)),
        Err(error) => {
            errln!(
                "warning: ignoring unreadable {}: {error}",
                paths.state_file.display()
            );
            Ok(None)
        }
    }
}

pub fn remove_state(paths: &Paths) {
    let _ = std::fs::remove_file(&paths.state_file);
    let _ = std::fs::remove_file(lock_path(paths));
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// A token other local users cannot guess.
///
/// This is a security token, so it comes from the operating system's CSPRNG rather than
/// from a hash seed whose algorithm is an implementation detail.
fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow!("failed to read OS randomness for the control token: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Compare two tokens without leaking their length or contents through timing.
pub(crate) fn tokens_match(expected: &str, provided: &str) -> bool {
    let expected = expected.as_bytes();
    let provided = provided.as_bytes();
    if expected.len() != provided.len() {
        return false;
    }
    let mut difference = 0u8;
    for (expected, provided) in expected.iter().zip(provided) {
        difference |= expected ^ provided;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paths for a throwaway directory, so tests do not invent their own layout.
    fn paths_in(dir: &Path) -> Paths {
        Paths {
            profile: crate::config::DEFAULT_PROFILE.to_string(),
            config_file: dir.join("config.json"),
            env_file: dir.join(".env"),
            state_file: dir.join("daemon.json"),
            log_file: dir.join("mcp-ctl.log"),
            state_dir: dir.to_path_buf(),
            config_dir: dir.to_path_buf(),
        }
    }

    fn state_for(port: u16, token: &str) -> StateFile {
        StateFile {
            format: StateFile::FORMAT,
            pid: 4242,
            version: "test".to_string(),
            control_port: port,
            token: token.to_string(),
            hub_port: 37373,
            proxy_port: None,
            external_url: None,
            log_file: PathBuf::from("test.log"),
            started_at: now_secs(),
        }
    }

    fn spawn_daemon() -> (u16, String, std::sync::mpsc::Receiver<()>) {
        let server = ControlServer::bind().expect("a loopback port is available");
        let port = server.port();
        let token = server.token().to_string();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let info = Arc::new(ControlInfo {
            pid: 4242,
            version: "test".to_string(),
            started_at: now_secs(),
            hub_port: 37373,
            proxy_port: None,
            external_url: Arc::new(Mutex::new(None)),
            auth_methods: Vec::new(),
            log_file: PathBuf::from("test.log"),
            ready: Arc::new(AtomicBool::new(true)),
        });
        let hub = Arc::new(Hub::new());
        let _daemon = std::thread::spawn(move || server.serve(info, hub, stop_tx));
        (port, token, stop_rx)
    }

    #[test]
    fn status_and_shutdown_round_trip_over_the_control_port() {
        let (port, token, stop) = spawn_daemon();
        let state = state_for(port, &token);

        let report = query_status(&state).expect("the daemon answers a status request");
        assert_eq!(report.pid, 4242);
        assert_eq!(report.hub_port, 37373);
        assert!(report.ready);
        assert!(report.servers.is_empty());
        assert!(is_listening(&state));

        request_shutdown(&state).expect("the daemon accepts a shutdown request");
        stop.recv_timeout(Duration::from_secs(5))
            .expect("the supervisor is told to stop");
    }

    #[test]
    fn a_stalled_client_does_not_delay_another_command() {
        let (port, token, _stop) = spawn_daemon();
        let state = state_for(port, &token);

        // A client that connects and says nothing used to hold the accept loop for the
        // whole read timeout, so a `status` behind it waited five seconds.
        let stalled = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).unwrap();

        let started = std::time::Instant::now();
        let report = query_status(&state).expect("the daemon still answers");
        assert_eq!(report.pid, 4242);
        assert!(
            started.elapsed() < CONTROL_TIMEOUT / 2,
            "a status request waited {:?} behind a stalled client",
            started.elapsed()
        );
        drop(stalled);
    }

    #[test]
    fn a_wrong_token_is_refused() {
        let (port, _, _stop) = spawn_daemon();
        let state = state_for(port, "not-the-token");
        assert!(query_status(&state).is_none());
        assert!(request_shutdown(&state).is_err());
    }

    #[test]
    fn nothing_answers_on_a_closed_port() {
        // A state file pointing at a port nobody listens on describes a daemon that is
        // gone, so neither a connect nor a status request succeeds.
        let state = state_for(closed_port(), "irrelevant");
        assert!(!is_listening(&state));
        assert!(query_status(&state).is_none());
    }

    #[test]
    fn only_one_daemon_can_hold_the_slot() {
        let dir = std::env::temp_dir().join(format!("mcp-ctl-claim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = paths_in(&dir);

        // A claim nobody backs (a crashed daemon) is reclaimed.
        claim_daemon_slot(&paths, closed_port()).expect("the first claim wins");
        assert!(lock_path(&paths).is_file());
        claim_daemon_slot(&paths, closed_port()).expect("a stale claim is reclaimed");

        // A claim whose control port answers belongs to a daemon that is starting up.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let live = listener.local_addr().unwrap().port();
        claim_daemon_slot(&paths, live).expect("the slot is free again");
        let error = claim_daemon_slot(&paths, closed_port())
            .expect_err("a live claim must not be stolen")
            .to_string();
        assert!(error.contains("starting up"), "{error}");

        // Stopping the daemon releases the slot.
        remove_state(&paths);
        assert!(!lock_path(&paths).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_claim_that_is_being_written_is_not_reclaimed() {
        // The claim file is created empty and filled in a moment later. A second `up`
        // that reads it in that window must wait, not delete it and start too.
        let dir = std::env::temp_dir().join(format!("mcp-ctl-midclaim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = paths_in(&dir);
        paths.ensure_state_dir().unwrap();

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let live = listener.local_addr().unwrap().port();
        std::fs::write(lock_path(&paths), "").unwrap();
        let lock = lock_path(&paths);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let claim = Claim {
                pid: 4242,
                control_port: live,
            };
            std::fs::write(&lock, serde_json::to_vec(&claim).unwrap()).unwrap();
        });

        let error = claim_daemon_slot(&paths, closed_port())
            .expect_err("a claim that is being written is not stolen")
            .to_string();
        assert!(error.contains("starting up"), "{error}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A loopback port nothing is listening on right now.
    ///
    /// Tests run in parallel and ephemeral ports are reused, so the port is checked
    /// before it is handed out instead of being assumed free.
    fn closed_port() -> u16 {
        for _ in 0..20 {
            let probe = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            if !port_is_listening(port) {
                return port;
            }
        }
        panic!("could not find a free loopback port");
    }

    #[test]
    fn tokens_are_compared_completely() {
        assert!(tokens_match("abcdef", "abcdef"));
        assert!(!tokens_match("abcdef", "abcde"));
        assert!(!tokens_match("abcdef", "abcdeg"));
        assert!(!tokens_match("abcdef", ""));
    }

    #[test]
    fn generated_tokens_differ() {
        assert_ne!(random_token().unwrap(), random_token().unwrap());
        assert_eq!(random_token().unwrap().len(), 64);
    }

    #[test]
    fn an_overlong_control_request_is_refused() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.write_all(&vec![b'x'; MAX_CONTROL_LINE + 1]).unwrap();

        let info = ControlInfo {
            pid: 4242,
            version: "test".to_string(),
            started_at: now_secs(),
            hub_port: 37373,
            proxy_port: None,
            external_url: Arc::new(Mutex::new(None)),
            auth_methods: Vec::new(),
            log_file: PathBuf::from("test.log"),
            ready: Arc::new(AtomicBool::new(true)),
        };
        let hub = Hub::new();
        let (stop, _stop_rx) = std::sync::mpsc::channel();
        let error = answer(&server, "token", &info, &hub, &stop).unwrap_err();
        assert!(error.to_string().contains("too long"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn the_state_file_and_its_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("mcp-ctl-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = paths_in(&dir);

        write_state(&paths, &state_for(1, "token")).expect("the state file is writable");

        let file = std::fs::metadata(&paths.state_file).unwrap();
        assert_eq!(file.permissions().mode() & 0o777, 0o600);
        let directory = std::fs::metadata(&paths.state_dir).unwrap();
        assert_eq!(directory.permissions().mode() & 0o777, 0o700);
        // The temporary file must not linger, private or not.
        assert!(!paths.state_file.with_extension("json.tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
