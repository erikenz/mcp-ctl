//! Platform-specific process and file helpers.
//!
//! Everything else in the crate is portable; this module is the single home for
//! the places where Unix and Windows genuinely differ:
//!
//! * running a child in its own process group, so an MCP server launched through
//!   `npx` (which spawns a `node` grandchild) can be stopped as a whole;
//! * detaching the background daemon from the terminal that started it, so closing
//!   the shell does not take the daemon and every server it supervises down with it;
//! * stopping a child: stdin EOF first (that is how a stdio MCP server is told to
//!   exit), then SIGTERM, then SIGKILL.

use anyhow::Result;
// Only the non-Unix stdio runner needs the `Context` extension trait.
#[cfg(not(unix))]
use anyhow::Context;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// How long a child gets to exit on its own after its stdin has been closed.
pub const GRACEFUL_EXIT: Duration = Duration::from_secs(3);

/// How long we wait for a killed process to be reaped before giving up on it.
const REAP_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn killpg(pgrp: i32, sig: i32) -> i32;
    fn setsid() -> i32;
}

#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGKILL: i32 = 9;

/// Put a child into its own process group (or console group on Windows).
///
/// [`terminate`] relies on this: it signals the group, not just the immediate
/// child, which is what keeps `npx`/`node` grandchildren from being orphaned.
pub fn isolate_process_group(cmd: &mut Command) {
    isolate_process_group_impl(cmd);
}

#[cfg(unix)]
fn isolate_process_group_impl(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // The child becomes its own group leader, so its pid doubles as the group id.
    cmd.process_group(0);
}

#[cfg(windows)]
fn isolate_process_group_impl(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    // Ctrl+C in our console must not reach MCP servers; we stop them explicitly.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    let _ = cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

#[cfg(not(any(unix, windows)))]
fn isolate_process_group_impl(_cmd: &mut Command) {}

/// Detach a spawned daemon from the terminal that started it.
pub fn detach(cmd: &mut Command) {
    detach_impl(cmd);
}

#[cfg(unix)]
fn detach_impl(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `setsid` is async-signal-safe and allocates nothing, which is all a
    // `pre_exec` closure is allowed to rely on. Without it the daemon stays in the
    // shell's session and dies of SIGHUP when that terminal closes.
    unsafe {
        cmd.pre_exec(|| {
            if setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(windows)]
fn detach_impl(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // Rust passes `bInheritHandles = TRUE` to `CreateProcessW`, so every
    // inheritable handle in this process leaks into the daemon. Without this,
    // the long-lived daemon keeps the caller's pipes open, and commands such as
    // `mcp-ctl up -d | cat` (or a test harness capturing output) never see EOF.
    clear_std_handle_inheritance();
    let _ = cmd.creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW);
}

#[cfg(windows)]
unsafe extern "system" {
    fn GetStdHandle(std_handle: u32) -> *mut core::ffi::c_void;
    fn SetHandleInformation(object: *mut core::ffi::c_void, mask: u32, flags: u32) -> i32;
}

#[cfg(windows)]
const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6; // -10
#[cfg(windows)]
const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5; // -11
#[cfg(windows)]
const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // -12
#[cfg(windows)]
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;

/// Mark this process's stdin/stdout/stderr non-inheritable.
///
/// The handles stay usable here; only future `CreateProcess` calls stop copying
/// them into children. Console handles may reject the call, which is harmless:
/// they are not the pipes that cause the leak.
#[cfg(windows)]
fn clear_std_handle_inheritance() {
    for handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: these functions take plain handle values and do not dereference
        // anything owned by Rust. An invalid handle simply makes the call fail.
        unsafe {
            let handle = GetStdHandle(handle);
            if !handle.is_null() {
                let _ = SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn detach_impl(_cmd: &mut Command) {}

/// Stop a child and everything it spawned.
///
/// The caller is expected to have closed the child's stdin first: a stdio MCP
/// server exits on EOF, which is the only graceful shutdown the protocol defines.
/// This is the escalation: SIGTERM to the group, then SIGKILL / `taskkill /T /F`.
///
/// Callers must have spawned the child through [`isolate_process_group`].
pub fn terminate(child: &mut Child) -> Result<()> {
    terminate_impl(child)
}

#[cfg(unix)]
fn terminate_impl(child: &mut Child) -> Result<()> {
    let pid = child.id();
    if exited(child) {
        return Ok(());
    }
    if !signal_group(pid, SIGTERM) {
        let _ = signal_pid(pid, SIGTERM);
    }
    if wait_for_exit(child, GRACEFUL_EXIT) {
        return Ok(());
    }
    if !signal_group(pid, SIGKILL) {
        let _ = signal_pid(pid, SIGKILL);
    }
    if wait_for_exit(child, REAP_TIMEOUT) {
        return Ok(());
    }
    Err(anyhow::anyhow!("process {pid} survived SIGKILL"))
}

#[cfg(windows)]
fn terminate_impl(child: &mut Child) -> Result<()> {
    let pid = child.id();
    if exited(child) {
        return Ok(());
    }
    // Windows has no SIGTERM equivalent, so the tree is terminated outright.
    let _ = kill_process_tree(pid);
    if wait_for_exit(child, REAP_TIMEOUT) {
        return Ok(());
    }
    let _ = child.kill();
    if wait_for_exit(child, REAP_TIMEOUT) {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "process {pid} did not exit after being killed"
    ))
}

#[cfg(not(any(unix, windows)))]
fn terminate_impl(child: &mut Child) -> Result<()> {
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

/// Terminate a whole process group by id, without a handle to the child.
///
/// Used when the graceful path is unreachable because a tool call still holds the
/// backend's lock: stopping the hub must not wait for a runaway tool to finish.
pub fn terminate_group(pid: u32) -> Result<()> {
    terminate_group_impl(pid)
}

#[cfg(unix)]
fn terminate_group_impl(pid: u32) -> Result<()> {
    if !signal_group(pid, SIGTERM) {
        let _ = signal_pid(pid, SIGTERM);
    }
    std::thread::sleep(Duration::from_millis(500));
    if !signal_group(pid, SIGKILL) {
        let _ = signal_pid(pid, SIGKILL);
    }
    Ok(())
}

#[cfg(windows)]
fn terminate_group_impl(pid: u32) -> Result<()> {
    if kill_process_tree(pid) {
        return Ok(());
    }
    Err(anyhow::anyhow!("`taskkill /PID {pid} /T /F` failed"))
}

#[cfg(not(any(unix, windows)))]
fn terminate_group_impl(pid: u32) -> Result<()> {
    Err(anyhow::anyhow!(
        "cannot terminate the process group of {pid} on this platform"
    ))
}

/// Kill a process mcp-ctl started but no longer has a handle on, such as a daemon that
/// answered the control channel but will not exit.
pub fn force_kill(pid: u32) -> Result<()> {
    force_kill_impl(pid)
}

#[cfg(unix)]
fn force_kill_impl(pid: u32) -> Result<()> {
    if signal_pid(pid, SIGKILL) {
        return Ok(());
    }
    Err(anyhow::Error::new(std::io::Error::last_os_error())
        .context(format!("failed to kill {pid}")))
}

#[cfg(windows)]
fn force_kill_impl(pid: u32) -> Result<()> {
    if kill_process_tree(pid) {
        return Ok(());
    }
    Err(anyhow::anyhow!("`taskkill /PID {pid} /T /F` failed"))
}

#[cfg(not(any(unix, windows)))]
fn force_kill_impl(pid: u32) -> Result<()> {
    Err(anyhow::anyhow!(
        "cannot terminate process {pid} on this platform"
    ))
}

/// Look a program up on `PATH`, the way a shell would.
///
/// Only files that can actually be executed count: a non-executable file on `PATH`
/// would be reported as found by `mcp-ctl check` and then fail to spawn.
pub fn find_executable(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        for suffix in EXECUTABLE_SUFFIXES {
            let candidate = directory.join(format!("{name}{suffix}"));
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Is this a file that can be run? On Unix the executable bit decides; elsewhere
/// (Windows) a regular file is enough.
pub fn is_executable_file(path: &Path) -> bool {
    is_executable_file_impl(path)
}

#[cfg(unix)]
fn is_executable_file_impl(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file_impl(path: &Path) -> bool {
    path.is_file()
}

/// Suffixes a program name may carry on this platform.
#[cfg(windows)]
const EXECUTABLE_SUFFIXES: &[&str] = &["", ".exe", ".cmd", ".bat", ".ps1"];
#[cfg(not(windows))]
const EXECUTABLE_SUFFIXES: &[&str] = &[""];

/// Create a directory and its parents, then make the final directory owner-only.
///
/// Used for the state directory and the auth proxy's data directory: both contain
/// secrets or state that other local users must not read.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

/// Create or truncate a file with owner-only permissions from the moment it exists.
///
/// `restrict_to_owner` after a normal `fs::write` leaves a window in which the file
/// (and anything secret already written to it) is readable under the process umask.
pub fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

/// Create a file that must not exist yet, owner-only from the moment it exists.
///
/// `create_new` is atomic on every platform, which is what makes this usable as a lock:
/// of two processes calling it for the same path, exactly one succeeds.
pub fn create_new_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

/// Open a file for appending, creating it owner-only on Unix.
pub fn open_private_append(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

/// Restrict a file to its owner.
/// The daemon state file carries the control token, so it must not be readable by
/// other users. Windows has no equivalent of a POSIX mode here; the file lives in
/// the per-user local app data directory instead.
pub fn restrict_to_owner(path: &Path) -> Result<()> {
    restrict_to_owner_impl(path)
}

#[cfg(unix)]
fn restrict_to_owner_impl(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_to_owner_impl(_path: &Path) -> Result<()> {
    Ok(())
}

/// Hand this process over to an MCP server, returning its exit code.
///
/// On Unix the process is *replaced*: stdio, signals and the exit status belong to
/// the server itself, which is exactly what editors such as Zed and Neovim expect.
/// Windows has no `exec`, so the child is spawned and waited for instead.
pub fn run_stdio(cmd: &mut Command) -> Result<i32> {
    run_stdio_impl(cmd)
}

#[cfg(unix)]
fn run_stdio_impl(cmd: &mut Command) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    // `exec` returns only when it fails: on success this process *is* the server.
    let error = cmd.exec();
    Err(anyhow::Error::new(error).context("failed to start the MCP server"))
}

#[cfg(not(unix))]
fn run_stdio_impl(cmd: &mut Command) -> Result<i32> {
    let status = cmd.status().context("failed to start the MCP server")?;
    Ok(status.code().unwrap_or(1))
}

/// Has the child already exited (and been reaped)?
fn exited(child: &mut Child) -> bool {
    matches!(child.try_wait(), Ok(Some(_)))
}

/// Wait up to `timeout` for the child to exit, reaping it if it does.
///
/// Public because the hub uses it to give a backend a moment to notice that its
/// stdin was closed, before escalating to a signal.
pub fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if exited(child) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn signal_pid(pid: u32, signal: i32) -> bool {
    // SAFETY: `kill` takes no pointers and cannot dereference anything we own.
    unsafe { kill(pid as i32, signal) == 0 }
}

#[cfg(unix)]
fn signal_group(pgid: u32, signal: i32) -> bool {
    // SAFETY: as above.
    unsafe { killpg(pgid as i32, signal) == 0 }
}

#[cfg(windows)]
fn kill_process_tree(pid: u32) -> bool {
    Command::new("taskkill")
        .arg("/PID")
        .arg(pid.to_string())
        .arg("/T")
        .arg("/F")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_without_the_executable_bit_is_not_a_program() {
        let dir = std::env::temp_dir().join(format!("mcp-ctl-exec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain");
        std::fs::write(&plain, "").unwrap();
        let runnable = dir.join("runnable");
        std::fs::write(&runnable, "").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runnable, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(!is_executable_file(&plain), "a plain file is not a program");
        }
        assert!(is_executable_file(&runnable));
        assert!(!is_executable_file(&dir), "a directory is not a program");
        assert!(!is_executable_file(&dir.join("missing")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_files_can_be_written_and_appended() {
        let dir = std::env::temp_dir().join(format!("mcp-ctl-platform-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_private_dir(&dir).expect("the private directory is created");

        let file = dir.join("secret");
        {
            let mut created = create_private_file(&file).expect("the file is created");
            std::io::Write::write_all(&mut created, b"one").unwrap();
        }
        {
            let mut appended = open_private_append(&file).expect("the file is appended to");
            std::io::Write::write_all(&mut appended, b"two").unwrap();
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "onetwo");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let directory_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(directory_mode, 0o700);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
