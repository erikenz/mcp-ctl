//! The MCP hub: it speaks MCP over stdio to each backend server and multiplexes
//! their tools onto a single endpoint.
//!
//! Concurrency contract: every backend owns its own mutex, so a slow tool call on
//! one server never blocks another. Locks are taken one at a time — the routing map
//! is read and released before a backend is locked — which keeps this deadlock-free.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use crate::platform;
use crate::servers::ToolFilter;

/// Revisions mcp-ctl speaks over the `initialize` handshake, newest first.
pub const HANDSHAKE_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// Revisions that use the stateless per-request envelope. Every request is answered
/// on its own, without a session, so those clients are served as well.
pub const MODERN_PROTOCOL_VERSIONS: &[&str] = &["2026-07-28"];

/// JSON-RPC error codes used by the hub.
pub mod errors {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// Backend failures that are not JSON-RPC errors (timeouts, dead processes).
    pub const SERVER_ERROR: i64 = -32000;
}

/// Can we speak this revision at all?
pub fn protocol_version_supported(version: &str) -> bool {
    HANDSHAKE_PROTOCOL_VERSIONS.contains(&version) || MODERN_PROTOCOL_VERSIONS.contains(&version)
}

/// Echo the revision the client asked for when we know it, otherwise counter-offer
/// the newest one we do speak; the client decides whether to continue.
pub fn negotiate_protocol_version(requested: Option<&str>) -> &'static str {
    let requested = requested.unwrap_or_default();
    for known in HANDSHAKE_PROTOCOL_VERSIONS
        .iter()
        .chain(MODERN_PROTOCOL_VERSIONS)
    {
        if *known == requested {
            return known;
        }
    }
    HANDSHAKE_PROTOCOL_VERSIONS[0]
}

fn server_info() -> Value {
    json!({ "name": "mcp-ctl", "version": env!("CARGO_PKG_VERSION") })
}

fn capabilities() -> Value {
    json!({ "tools": { "listChanged": false } })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i64, message: String) -> Value {
    rpc_error_with_data(id, code, message, None)
}

fn rpc_error_with_data(id: Value, code: i64, message: String, data: Option<Value>) -> Value {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data
        && let Some(object) = error.as_object_mut()
    {
        object.insert("data".to_string(), data);
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

/// A JSON-RPC error returned by a backend, kept structured so that the original
/// code and data reach the client instead of a generic wrapper.
#[derive(Debug)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "backend error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

/// How long to wait for a backend: starting it up, and finishing one tool call.
#[derive(Clone, Copy, Debug)]
pub struct BackendTimeouts {
    pub handshake: Duration,
    /// `None` waits as long as the tool takes.
    pub tool: Option<Duration>,
}

impl BackendTimeouts {
    /// A backend that cannot complete `initialize` in this long is not usable.
    pub const DEFAULT_HANDSHAKE: Duration = Duration::from_secs(30);
}

/// The name a tool is exposed under.
///
/// A configured prefix always applies. Without one, a name that is already taken
/// gets the server name prepended, and if that is taken too we keep looking, so a
/// tool is never silently dropped.
fn exposed_tool_name<F>(server: &str, prefix: Option<&str>, tool: &str, taken: F) -> String
where
    F: Fn(&str) -> bool,
{
    let base = match prefix {
        Some(prefix) => format!("{prefix}_{tool}"),
        None => tool.to_string(),
    };
    if !taken(&base) {
        return base;
    }

    let qualified = match prefix {
        Some(prefix) => format!("{server}_{prefix}_{tool}"),
        None => format!("{server}_{tool}"),
    };
    if !taken(&qualified) {
        return qualified;
    }

    // `taken` is a predicate over a finite map, so this always terminates.
    for attempt in 2.. {
        let candidate = format!("{qualified}_{attempt}");
        if !taken(&candidate) {
            return candidate;
        }
    }
    unreachable!("the loop above always returns")
}

/// A backend MCP server, spoken to over stdio.
pub struct ChildServer {
    name: String,
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Arc<MessageQueue>,
    next_id: u64,
    tools: Vec<Value>,
    /// Tool-call timeout; `None` waits as long as the tool takes.
    timeout: Option<Duration>,
    /// Messages dropped because nobody was draining the buffer. Reported if the
    /// server dies, so a chatty backend is visible instead of mysterious.
    dropped: Arc<AtomicU64>,
}

/// How many bytes of one backend's unsolicited output we buffer.
///
/// The bound used to be a message count, which put no ceiling on memory: 4096 lines
/// of screenshot-sized payload is gigabytes. A backend may keep one message of any
/// size while the queue is idle (that is what a response to an in-flight call looks
/// like), but everything queued behind it has to fit in this budget.
const MESSAGE_BUFFER_BYTES: usize = 16 * 1024 * 1024;

/// Longest single message accepted from a backend.
///
/// A tool result larger than this is refused instead of being allowed to grow the
/// daemon's memory without a bound. `take_snapshot` and friends are well below it.
const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

/// Take a lock without letting one panicked thread poison the whole service.
fn mutex_lock<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One backend's stdout messages, bounded by bytes rather than by message count.
struct MessageQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
    budget: usize,
}

#[derive(Default)]
struct QueueState {
    lines: VecDeque<String>,
    bytes: usize,
    closed: bool,
}

enum PushOutcome {
    Accepted,
    /// The queue is over budget, so the message was dropped.
    Dropped,
    /// The backend is being shut down; the reader should stop.
    Closed,
}

#[derive(Debug)]
enum RecvError {
    Timeout,
    Closed,
}

impl MessageQueue {
    fn new(budget: usize) -> Self {
        Self {
            state: Mutex::new(QueueState::default()),
            ready: Condvar::new(),
            budget,
        }
    }

    fn push(&self, line: String) -> PushOutcome {
        let mut state = mutex_lock(&self.state);
        if state.closed {
            return PushOutcome::Closed;
        }
        // An idle queue accepts one message even when it is larger than the budget:
        // dropping a response a caller is waiting for would turn a large tool result
        // into a timeout. Anything queued behind it has to fit.
        if !state.lines.is_empty() && state.bytes.saturating_add(line.len()) > self.budget {
            return PushOutcome::Dropped;
        }
        state.bytes = state.bytes.saturating_add(line.len());
        state.lines.push_back(line);
        self.ready.notify_one();
        PushOutcome::Accepted
    }

    fn close(&self) {
        mutex_lock(&self.state).closed = true;
        self.ready.notify_all();
    }

    fn recv(&self, timeout: Option<Duration>) -> Result<String, RecvError> {
        let mut state = mutex_lock(&self.state);
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        loop {
            if let Some(line) = state.lines.pop_front() {
                state.bytes = state.bytes.saturating_sub(line.len());
                return Ok(line);
            }
            if state.closed {
                return Err(RecvError::Closed);
            }
            state = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(RecvError::Timeout);
                    }
                    self.ready
                        .wait_timeout(state, remaining)
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .0
                }
                None => self
                    .ready
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            };
        }
    }
}

/// What one call to `read_capped_line` found.
enum CappedLine {
    Line,
    /// The line was longer than the cap and has been discarded in full.
    TooLong,
    /// The pipe reached EOF.
    Eof,
}

/// Read one newline-terminated message, refusing to buffer more than `max` bytes.
///
/// An oversized line is discarded through its newline, so the next read starts at
/// the next message instead of in the middle of the oversized one.
fn read_capped_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<CappedLine> {
    line.clear();
    let mut limited = std::io::Read::take(&mut *reader, max as u64 + 1);
    let read = limited.read_until(b'\n', line)?;
    if read == 0 {
        return Ok(CappedLine::Eof);
    }
    if line.len() > max {
        if !line.ends_with(b"\n") {
            discard_line(reader)?;
        }
        // Do not keep a message-sized buffer around for the rest of the run.
        *line = Vec::new();
        return Ok(CappedLine::TooLong);
    }
    Ok(CappedLine::Line)
}

/// Consume everything up to and including the next newline.
fn discard_line<R: BufRead>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(end) = available.iter().position(|byte| *byte == b'\n') {
            reader.consume(end + 1);
            return Ok(());
        }
        let length = available.len();
        reader.consume(length);
    }
}

impl ChildServer {
    /// Start a backend server and complete the MCP handshake.
    ///
    /// Any failure stops the process again: a server that cannot answer
    /// `initialize` would otherwise linger forever with nobody talking to it.
    pub fn spawn(
        name: &str,
        command: &str,
        args: &[String],
        cwd: Option<&Path>,
        env: &[(String, String)],
        env_clear: bool,
        timeouts: BackendTimeouts,
    ) -> Result<Self> {
        let mut cmd = Command::new(command);
        if env_clear {
            // The server definition asked for isolation: only `env` is visible.
            cmd.env_clear();
        }
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        cmd.args(args)
            .envs(env.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // Own process group, so stopping the hub stops whatever this server spawned
        // (`npx` starts a `node` grandchild, for instance).
        platform::isolate_process_group(&mut cmd);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn MCP server '{name}' ({command})"))?;

        let (stdin, stdout) = match (child.stdin.take(), child.stdout.take()) {
            (Some(stdin), Some(stdout)) => (stdin, stdout),
            _ => {
                let _ = platform::terminate(&mut child);
                bail!("failed to capture stdio of MCP server '{name}'");
            }
        };

        let queue = Arc::new(MessageQueue::new(MESSAGE_BUFFER_BYTES));
        let reader_queue = Arc::clone(&queue);
        let dropped = Arc::new(AtomicU64::new(0));
        let dropped_by_reader = Arc::clone(&dropped);
        let thread_name = format!("backend-{name}");
        if let Err(error) = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                let mut line = Vec::new();
                loop {
                    match read_capped_line(&mut reader, &mut line, MAX_MESSAGE_BYTES) {
                        // EOF, or a read error: either way we are done here.
                        Ok(CappedLine::Eof) | Err(_) => break,
                        Ok(CappedLine::TooLong) => {
                            dropped_by_reader.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        Ok(CappedLine::Line) => {}
                    }
                    // Decoded lossily only when it is not valid UTF-8: one stray byte
                    // (a log line, a latin-1 filename) must not look like the server
                    // having exited. The JSON parse in `request` skips anything that
                    // is not a response.
                    let text = match String::from_utf8(std::mem::take(&mut line)) {
                        Ok(text) => text,
                        Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
                    };
                    match reader_queue.push(text) {
                        PushOutcome::Accepted => {}
                        PushOutcome::Dropped => {
                            dropped_by_reader.fetch_add(1, Ordering::Relaxed);
                        }
                        PushOutcome::Closed => break,
                    }
                }
                reader_queue.close();
            })
        {
            let _ = platform::terminate(&mut child);
            bail!("failed to start the reader thread for MCP server '{name}': {error}");
        }

        let mut server = Self {
            name: name.to_string(),
            child,
            stdin: Some(stdin),
            rx: queue,
            next_id: 1,
            tools: Vec::new(),
            timeout: timeouts.tool,
            dropped,
        };

        server.tools = match server.handshake(timeouts.handshake) {
            Ok(tools) => tools,
            Err(error) => {
                let _ = server.shutdown(Duration::from_millis(250));
                return Err(error.context(format!("MCP server '{name}' failed to start")));
            }
        };

        Ok(server)
    }

    /// Send a JSON-RPC request and wait for its response.
    ///
    /// Notifications and late responses to earlier calls are skipped, so a backend
    /// that chatters on stdout is tolerated rather than fatal.
    fn request(&mut self, method: &str, params: Value, timeout: Option<Duration>) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.write_line(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))?;

        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        loop {
            let raw = self.recv(method, timeout, deadline)?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(mut message) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            if message.get("id") != Some(&json!(id)) {
                continue;
            }

            if let Some(error) = message.get("error") {
                return Err(anyhow::Error::new(JsonRpcError {
                    code: error
                        .get("code")
                        .and_then(Value::as_i64)
                        .unwrap_or(errors::SERVER_ERROR),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified backend error")
                        .to_string(),
                    data: error.get("data").cloned(),
                }));
            }

            // Move the result out: a screenshot-sized payload is too large to copy
            // just to keep the envelope alive.
            return match message.get_mut("result").map(std::mem::take) {
                Some(result) => Ok(result),
                None => bail!(
                    "server '{}' answered '{method}' without a result",
                    self.name
                ),
            };
        }
    }

    /// Wait for the next line from the backend, honouring the request deadline.
    fn recv(
        &mut self,
        method: &str,
        timeout: Option<Duration>,
        deadline: Option<Instant>,
    ) -> Result<String> {
        let remaining = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(self.timed_out(method, timeout));
                }
                Some(remaining)
            }
            None => None,
        };

        match self.rx.recv(remaining) {
            Ok(line) => Ok(line),
            Err(RecvError::Timeout) => Err(self.timed_out(method, timeout)),
            Err(RecvError::Closed) => Err(self.died(method)),
        }
    }

    fn write_line(&mut self, message: &Value) -> Result<()> {
        let name = self.name.clone();
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("server '{name}' is no longer running"))?;
        let mut line = serde_json::to_string(message)?;
        line.push('\n');
        stdin
            .write_all(line.as_bytes())
            .with_context(|| format!("failed to write to server '{name}'"))?;
        stdin
            .flush()
            .with_context(|| format!("failed to flush server '{name}'"))?;
        Ok(())
    }

    fn timed_out(&self, method: &str, timeout: Option<Duration>) -> anyhow::Error {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        let dropped_note = if dropped == 0 {
            String::new()
        } else {
            format!(
                "; {dropped} message(s) were dropped because the backend produced too much output"
            )
        };
        match timeout {
            Some(timeout) => anyhow!(
                "server '{}' did not answer '{method}' within {}s{}",
                self.name,
                timeout.as_secs(),
                dropped_note
            ),
            None => anyhow!(
                "server '{}' stopped answering '{method}'{dropped_note}",
                self.name
            ),
        }
    }

    fn died(&mut self, method: &str) -> anyhow::Error {
        let status = match self.child.try_wait() {
            Ok(Some(status)) => format!(" (exit status: {status})"),
            _ => String::new(),
        };
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        let dropped_note = if dropped == 0 {
            String::new()
        } else {
            format!(", {dropped} unsolicited messages were dropped")
        };
        anyhow!(
            "server '{}' exited before answering '{method}'{status}{dropped_note}",
            self.name
        )
    }

    /// Send a JSON-RPC notification; no response is expected.
    pub fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        self.write_line(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }))
    }

    /// Forward a `tools/call` to this server.
    ///
    /// The caller has already rewritten `name` to the tool name this backend knows,
    /// so `_meta` and any future parameter fields survive the hop unchanged.
    pub fn call_tool(&mut self, params: Value) -> Result<Value> {
        self.request("tools/call", params, self.timeout)
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Has this backend exited? Reaps it if so; `None` while it is still running.
    pub fn exited_status(&mut self) -> Option<std::process::ExitStatus> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status),
            _ => None,
        }
    }

    /// Ask the server to exit, and make sure it really is gone.
    ///
    /// Closing stdin is the only graceful shutdown a stdio MCP server has; anything
    /// still alive after `grace` is terminated along with its process group.
    pub fn shutdown(&mut self, grace: Duration) -> Result<()> {
        drop(self.stdin.take());
        if platform::wait_for_exit(&mut self.child, grace) {
            return Ok(());
        }
        platform::terminate(&mut self.child)
    }

    fn handshake(&mut self, timeout: Duration) -> Result<Vec<Value>> {
        let result = self.request(
            "initialize",
            json!({
                "protocolVersion": HANDSHAKE_PROTOCOL_VERSIONS[0],
                "capabilities": {},
                "clientInfo": { "name": "mcp-ctl", "version": env!("CARGO_PKG_VERSION") }
            }),
            Some(timeout),
        )?;

        let version = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        if !protocol_version_supported(version) {
            errln!(
                "warning: server '{}' negotiated MCP revision '{version}', which mcp-ctl does not know; its tool calls are forwarded as-is",
                self.name
            );
        }

        self.notify("notifications/initialized", json!({}))?;

        let tools = self.request("tools/list", json!({}), Some(timeout))?;
        Ok(tools
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }
}

impl Drop for ChildServer {
    /// Wake the reader thread so a dropped backend stops buffering its output.
    fn drop(&mut self) {
        self.rx.close();
    }
}

/// Point-in-time view of one backend server, used for status reporting (tray icon).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatus {
    pub name: String,
    pub tool_count: usize,
    /// False when the child process has exited.
    pub running: bool,
}

/// The hub: every served backend, and the tool names they are published under.
pub struct Hub {
    /// One lock over the whole relationship, so a backend, the names it publishes and the
    /// definitions clients see can never disagree. Each backend still has a lock of its
    /// own, so a slow tool call cannot stall the other servers.
    registry: RwLock<Registry>,
    calls: AtomicU64,
}

/// What the hub knows: which backends exist, which tool names they publish, and the
/// definitions `tools/list` hands out.
#[derive(Default)]
struct Registry {
    /// One entry per backend, keyed by its name in the profile file.
    backends: BTreeMap<String, Backend>,
    /// Exposed tool name -> the backend and tool name behind it.
    routes: BTreeMap<String, ToolRoute>,
    /// Tool definitions exactly as `tools/list` returns them.
    tools: Vec<Value>,
}

impl Registry {
    /// Publish a backend's tools, renaming anything that collides.
    ///
    /// Returns how many were published and the renames, for the caller to report.
    fn publish(
        &mut self,
        name: &str,
        prefix: Option<&str>,
        filter: Option<&ToolFilter>,
        definitions: &[Value],
    ) -> (usize, Vec<String>) {
        let mut renamed = Vec::new();
        let mut published = 0;
        for tool in definitions {
            let Some(original) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            if let Some(filter) = filter
                && !filter.allows(original)
            {
                continue;
            }
            let exposed = exposed_tool_name(name, prefix, original, |candidate| {
                self.routes.contains_key(candidate)
            });
            if exposed != original {
                renamed.push(format!("{original} -> {exposed}"));
            }
            let mut definition = tool.clone();
            if let Some(object) = definition.as_object_mut() {
                object.insert("name".to_string(), json!(exposed));
            }
            self.routes.insert(
                exposed,
                ToolRoute {
                    server: name.to_string(),
                    tool: original.to_string(),
                },
            );
            self.tools.push(definition);
            published += 1;
        }
        (published, renamed)
    }
}

/// A served backend: the process, plus how many tools it contributed and whether it is
/// still running, so that `status` never waits for a backend that is busy in a call.
struct Backend {
    server: Arc<Mutex<ChildServer>>,
    tools: usize,
    alive: bool,
    /// The backend's process id, so it can be stopped even if the lock is busy.
    pid: u32,
}

#[derive(Clone, Debug)]
struct ToolRoute {
    server: String,
    tool: String,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything needed to start one backend.
pub struct BackendSpec<'a> {
    pub name: &'a str,
    pub command: &'a str,
    pub args: &'a [String],
    pub cwd: Option<&'a Path>,
    pub env: &'a [(String, String)],
    pub env_clear: bool,
    pub prefix: Option<&'a str>,
    pub filter: Option<&'a ToolFilter>,
    pub timeouts: BackendTimeouts,
}

impl Hub {
    pub fn new() -> Self {
        Self {
            registry: RwLock::new(Registry::default()),
            calls: AtomicU64::new(0),
        }
    }

    /// Start a backend server and publish the tools that survive its filter.
    pub fn add_server(&self, spec: BackendSpec<'_>) -> Result<usize> {
        let server = ChildServer::spawn(
            spec.name,
            spec.command,
            spec.args,
            spec.cwd,
            spec.env,
            spec.env_clear,
            spec.timeouts,
        )?;
        let available = server.tool_count();
        let pid = server.pid();

        // Publishing and registering happen under one lock, so the routes, the definitions
        // and the backend itself can never disagree.
        let (published, renamed) = {
            let mut registry = write_lock(&self.registry);
            let (published, renamed) =
                registry.publish(spec.name, spec.prefix, spec.filter, &server.tools);
            registry.backends.insert(
                spec.name.to_string(),
                Backend {
                    server: Arc::new(Mutex::new(server)),
                    tools: published,
                    alive: true,
                    pid,
                },
            );
            (published, renamed)
        };

        let prefix_note = match spec.prefix {
            Some(prefix) => format!(" [prefix: {prefix}_]"),
            None => String::new(),
        };
        outln!(
            "  ✓ '{}' connected ({published} tool{}){prefix_note}",
            spec.name,
            if published == 1 { "" } else { "s" }
        );
        let hidden = available.saturating_sub(published);
        if hidden > 0 {
            outln!("    {hidden} tool(s) hidden by the tool filter");
        }
        if !renamed.is_empty() {
            // Users deserve to know why `search` came back as `github_search`.
            outln!("    exposed as: {}", renamed.join(", "));
        }

        Ok(published)
    }

    /// Dispatch one JSON-RPC message.
    ///
    /// Returns `None` for notifications, which must never get a response.
    pub fn handle(&self, message: &Value) -> Option<Value> {
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();

        // Notifications never get an answer, whatever they are called.
        if method.starts_with("notifications/") {
            return None;
        }

        let id = match message.get("id") {
            Some(id) => id.clone(),
            None => {
                // A request without an id is indistinguishable from a notification,
                // so answering it with an error keeps the client from hanging.
                return Some(rpc_error(
                    Value::Null,
                    errors::INVALID_REQUEST,
                    format!("'{method}' is a request and needs an \"id\""),
                ));
            }
        };
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
            "initialize" => Some(self.initialize(id, &params)),
            "server/discover" => Some(self.discover(id)),
            "ping" => Some(rpc_result(id, json!({}))),
            "tools/list" => {
                let tools = read_lock(&self.registry).tools.clone();
                Some(rpc_result(id, json!({ "tools": tools })))
            }
            "tools/call" => Some(self.tools_call(id, &params)),
            other => Some(rpc_error(
                id,
                errors::METHOD_NOT_FOUND,
                format!("method '{other}' is not implemented by mcp-ctl"),
            )),
        }
    }

    /// Answer `initialize`, negotiating the revision the client asked for.
    fn initialize(&self, id: Value, params: &Value) -> Value {
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        rpc_result(
            id,
            json!({
                "protocolVersion": negotiate_protocol_version(requested),
                "capabilities": capabilities(),
                "serverInfo": server_info()
            }),
        )
    }

    fn discover(&self, id: Value) -> Value {
        let versions: Vec<&str> = HANDSHAKE_PROTOCOL_VERSIONS
            .iter()
            .chain(MODERN_PROTOCOL_VERSIONS)
            .copied()
            .collect();
        rpc_result(
            id,
            json!({
                "supportedVersions": versions,
                "capabilities": capabilities(),
                "_meta": { "io.modelcontextprotocol/serverInfo": server_info() }
            }),
        )
    }

    fn tools_call(&self, id: Value, params: &Value) -> Value {
        let tool = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();

        // Resolve the route and clone the backend handle under one read, then release the
        // registry before touching a backend: locks are never held nested, which is what
        // makes the ordering deadlock-free.
        let (route, server) = {
            let registry = read_lock(&self.registry);
            let route = registry.routes.get(tool).cloned();
            let server = route
                .as_ref()
                .and_then(|route| registry.backends.get(&route.server))
                .map(|backend| Arc::clone(&backend.server));
            (route, server)
        };
        let Some(route) = route else {
            return rpc_error(
                id,
                errors::METHOD_NOT_FOUND,
                format!("unknown tool '{tool}'"),
            );
        };
        let Some(server) = server else {
            return rpc_error(
                id,
                errors::INTERNAL_ERROR,
                format!("server '{}' is not running", route.server),
            );
        };

        let mut forwarded = params.clone();
        if let Some(object) = forwarded.as_object_mut() {
            object.insert("name".to_string(), json!(route.tool));
        }

        self.calls.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let result = mutex_lock(&server).call_tool(forwarded);
        let elapsed = started.elapsed();

        // Audit line: answers "did the agent call the deploy tool, and when?" without
        // needing -v. The timestamp is seconds since the Unix epoch.
        let stamp = crate::control::now_secs();
        match &result {
            Ok(_) => outln!(
                "[tool] t={stamp} {}/{} ok in {elapsed:?}",
                route.server,
                route.tool
            ),
            Err(error) => outln!(
                "[tool] t={stamp} {}/{} failed in {elapsed:?}: {error}",
                route.server,
                route.tool
            ),
        }

        match result {
            Ok(result) => rpc_result(id, result),
            // Forward a backend's own error verbatim: clients act on the code.
            Err(error) => match error.downcast_ref::<JsonRpcError>() {
                Some(backend) => rpc_error_with_data(
                    id,
                    backend.code,
                    backend.message.clone(),
                    backend.data.clone(),
                ),
                None => rpc_error(id, errors::SERVER_ERROR, error.to_string()),
            },
        }
    }

    /// Stop every backend, giving each one a moment to exit on its own.
    pub fn shutdown(&self) {
        let running: Vec<(String, Backend)> = {
            let mut registry = write_lock(&self.registry);
            let backends = std::mem::take(&mut registry.backends);
            registry.routes.clear();
            registry.tools.clear();
            backends.into_iter().collect()
        };
        for (name, backend) in running {
            outln!("Stopping '{name}'...");
            // Graceful path first. If a tool call still holds the lock, stop the whole
            // process group instead: shutdown must not wait for a runaway tool.
            match backend.server.try_lock() {
                Ok(mut server) => {
                    if let Err(error) = server.shutdown(platform::GRACEFUL_EXIT) {
                        errln!("warning: failed to stop '{name}': {error}");
                    }
                }
                Err(_) => {
                    errln!("warning: '{name}' is still busy; terminating its process group");
                    if let Err(error) = platform::terminate_group(backend.pid) {
                        errln!("warning: failed to stop '{name}': {error}");
                    }
                }
            }
        }
    }

    /// Withdraw the tools of backends whose process has exited.
    ///
    /// Returns one line per newly dead backend so the caller can report it. Cheap:
    /// one non-blocking `waitpid` per backend, no backend locks held across the work.
    pub fn drop_dead(&self) -> Vec<String> {
        let mut gone = Vec::new();
        {
            let mut registry = write_lock(&self.registry);
            for (name, backend) in registry.backends.iter_mut() {
                if !backend.alive {
                    continue;
                }
                // `try_lock`: a backend that is busy answering a call is not dead, and
                // the supervisor must never wait on one.
                let exited = backend
                    .server
                    .try_lock()
                    .ok()
                    .and_then(|mut server| server.exited_status());
                if let Some(status) = exited {
                    backend.alive = false;
                    gone.push(format!("'{name}' ({status})"));
                }
            }
            if gone.is_empty() {
                return gone;
            }

            // Withdraw what the dead backends published: their routes, and the definitions
            // that went with them.
            let dead: BTreeSet<String> = registry
                .backends
                .iter()
                .filter(|(_, backend)| !backend.alive)
                .map(|(name, _)| name.clone())
                .collect();
            registry
                .routes
                .retain(|_, route| !dead.contains(route.server.as_str()));
            let published: BTreeSet<String> = registry.routes.keys().cloned().collect();
            registry.tools.retain(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| published.contains(name))
            });
        }
        gone
    }

    /// Every backend, its tool count and whether it is still running.
    pub fn summarize(&self) -> Vec<(String, usize, bool)> {
        read_lock(&self.registry)
            .backends
            .iter()
            .map(|(name, backend)| (name.clone(), backend.tools, backend.alive))
            .collect()
    }

    pub fn statuses(&self) -> Vec<ServerStatus> {
        self.summarize()
            .into_iter()
            .map(|(name, tool_count, running)| ServerStatus {
                name,
                tool_count,
                running,
            })
            .collect()
    }

    pub fn tool_count(&self) -> usize {
        read_lock(&self.registry).tools.len()
    }

    /// How many tool calls this hub has forwarded since it started.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Drop for Hub {
    /// Backstop for early exits (startup errors, panics): a hub never leaves its
    /// backend servers running. `shutdown` already drained them in the normal path.
    fn drop(&mut self) {
        let mut registry = write_lock(&self.registry);
        for (_, backend) in std::mem::take(&mut registry.backends) {
            match backend.server.try_lock() {
                Ok(mut server) => {
                    let _ = server.shutdown(Duration::from_millis(250));
                }
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    let mut server = poisoned.into_inner();
                    let _ = server.shutdown(Duration::from_millis(250));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    let _ = platform::terminate_group(backend.pid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_backend_line_is_refused_and_the_stream_resyncs() {
        let input = b"short\n0123456789abcdef\nnext\n";
        let mut reader = BufReader::new(&input[..]);
        let mut line = Vec::new();

        assert!(matches!(
            read_capped_line(&mut reader, &mut line, 8),
            Ok(CappedLine::Line)
        ));
        assert_eq!(line, b"short\n");
        assert!(matches!(
            read_capped_line(&mut reader, &mut line, 8),
            Ok(CappedLine::TooLong)
        ));
        assert!(matches!(
            read_capped_line(&mut reader, &mut line, 8),
            Ok(CappedLine::Line)
        ));
        assert_eq!(line, b"next\n");
    }

    #[test]
    fn the_message_queue_is_bounded_by_bytes() {
        let queue = MessageQueue::new(10);
        assert!(matches!(
            queue.push("12345".to_string()),
            PushOutcome::Accepted
        ));
        assert!(matches!(
            queue.push("67890".to_string()),
            PushOutcome::Accepted
        ));
        assert!(matches!(queue.push("x".to_string()), PushOutcome::Dropped));
        assert_eq!(queue.recv(None).unwrap(), "12345");

        // An idle queue still accepts one big response, so a large tool result does
        // not turn into a timeout.
        let queue = MessageQueue::new(10);
        assert!(matches!(queue.push("x".repeat(100)), PushOutcome::Accepted));
        assert_eq!(queue.recv(None).unwrap().len(), 100);

        queue.close();
        assert!(matches!(queue.recv(None), Err(RecvError::Closed)));
    }

    #[test]
    fn a_configured_prefix_always_applies() {
        assert_eq!(
            exposed_tool_name("github", Some("gh"), "search", |_| false),
            "gh_search"
        );
    }

    #[test]
    fn colliding_tool_names_get_the_server_name() {
        let taken = |candidate: &str| candidate == "search";
        assert_eq!(
            exposed_tool_name("github", None, "search", taken),
            "github_search"
        );
    }

    #[test]
    fn colliding_prefixed_names_keep_the_prefix() {
        let taken = |candidate: &str| candidate == "gh_search";
        assert_eq!(
            exposed_tool_name("github", Some("gh"), "search", taken),
            "github_gh_search"
        );
    }

    #[test]
    fn a_third_collision_still_produces_a_unique_name() {
        let taken = |candidate: &str| matches!(candidate, "search" | "github_search");
        assert_eq!(
            exposed_tool_name("github", None, "search", taken),
            "github_search_2"
        );
    }

    #[test]
    fn protocol_versions_are_negotiated() {
        assert_eq!(negotiate_protocol_version(Some("2024-11-05")), "2024-11-05");
        assert_eq!(
            negotiate_protocol_version(Some("1999-01-01")),
            HANDSHAKE_PROTOCOL_VERSIONS[0]
        );
        assert_eq!(
            negotiate_protocol_version(None),
            HANDSHAKE_PROTOCOL_VERSIONS[0]
        );
        assert!(protocol_version_supported("2026-07-28"));
        assert!(!protocol_version_supported("1999-01-01"));
    }

    #[test]
    fn requests_without_an_id_get_an_error_rather_than_silence() {
        let hub = Hub::new();
        let response = hub
            .handle(&json!({ "jsonrpc": "2.0", "method": "tools/list" }))
            .expect("a request must be answered");
        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], json!(errors::INVALID_REQUEST));
    }

    #[test]
    fn notifications_are_never_answered() {
        let hub = Hub::new();
        for method in ["notifications/initialized", "notifications/cancelled"] {
            assert!(
                hub.handle(&json!({ "jsonrpc": "2.0", "method": method }))
                    .is_none(),
                "{method} must not be answered"
            );
        }
    }

    #[test]
    fn unknown_methods_and_tools_are_reported() {
        let hub = Hub::new();
        let unknown_method = hub
            .handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" }))
            .expect("a request must be answered");
        assert_eq!(
            unknown_method["error"]["code"],
            json!(errors::METHOD_NOT_FOUND)
        );

        let unknown_tool = hub
            .handle(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "nope" }
            }))
            .expect("a request must be answered");
        assert_eq!(
            unknown_tool["error"]["code"],
            json!(errors::METHOD_NOT_FOUND)
        );
    }

    #[test]
    fn initialize_echoes_a_known_revision() {
        let hub = Hub::new();
        let response = hub
            .handle(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": "2025-06-18" }
            }))
            .expect("a request must be answered");
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(response["result"]["serverInfo"]["name"], "mcp-ctl");
    }
}
