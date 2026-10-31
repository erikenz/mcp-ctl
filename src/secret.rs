//! Secret resolution.
//!
//! A secret is declared per server in a profile file and resolved from Bitwarden (`rbw`),
//! 1Password (`op`), the environment (including the `.env` next to the profile files), an
//! arbitrary command, or a literal string. Resolved values only ever reach the child
//! process's environment: they are never written to disk, never logged, and `SecretValue`
//! (see `src/servers.rs`) redacts them in `Debug` output.

use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::platform;
use crate::servers::{SecretSource, SecretValue};

/// The `.env` next to the profile files, read once at startup.
///
/// Secrets that belong in a file go here rather than in a profile: the shell environment still
/// wins, so an exported variable overrides what the file says.
static ENV_FILE: OnceLock<(PathBuf, HashMap<String, String>)> = OnceLock::new();

/// Read the `.env` next to the profile files, if it exists. Returns how many values it holds.
pub fn load_env_file(path: &Path) -> Result<usize> {
    // `.env` is a secret store. `init` creates it 0600, but a file made by hand or
    // restored from a backup may be world-readable; refuse that rather than leak the
    // auth password or bearer token to another local user.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    bail!(
                        "{} is readable by other users (mode {mode:o}); secrets belong in an \
                         owner-only file. Run `chmod 600 {}` and try again.",
                        path.display(),
                        path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(anyhow!("failed to read {}: {error}", path.display())),
        }
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(anyhow!("failed to read {}: {error}", path.display())),
    };
    let values = parse_env_file(&text);
    let count = values.len();
    let _ = ENV_FILE.set((path.to_path_buf(), values));
    Ok(count)
}

/// `KEY=VALUE` lines: blank lines and `#` comments are ignored, an `export ` prefix is allowed,
/// and matching quotes around a value are stripped. Nothing is expanded.
fn parse_env_file(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let unquoted = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(value);
        values.insert(key.to_string(), unquoted.to_string());
    }
    values
}

/// The value of an environment variable: the shell wins, then the `.env` file.
fn env_value(name: &str) -> Option<String> {
    std::env::var(name).ok().or_else(|| {
        ENV_FILE
            .get()
            .and_then(|(_, values)| values.get(name).cloned())
    })
}

/// Where a value is looked up, for error messages.
fn env_sources() -> String {
    match ENV_FILE.get() {
        Some((path, _)) => format!("the environment or {}", path.display()),
        None => "the environment".to_string(),
    }
}

/// Resolve one secret to a concrete string.
///
/// The declaration in the profile file is authoritative: a variable that happens to be
/// set in mcp-ctl's own environment does *not* shadow a configured source. Use
/// `{"source": "env", "name": "..."}` to opt into the environment explicitly.
pub fn resolve(key: &str, value: &SecretValue) -> Result<String> {
    resolve_with_timeout(key, value, None)
}

/// Resolve one secret, allowing each external program at most `timeout`.
///
/// `None` waits as long as the program takes, which is what `run` and `check` want.
/// `up` passes a bound: a password manager waiting for an unlock or a pinentry prompt
/// must cost one server, not the whole daemon.
pub fn resolve_with_timeout(
    key: &str,
    value: &SecretValue,
    timeout: Option<Duration>,
) -> Result<String> {
    let resolved = match value {
        SecretValue::Literal(value) => value.clone(),
        SecretValue::Source(SecretSource::Env { name }) => {
            let name = name.as_deref().unwrap_or(key);
            env_value(name).ok_or_else(|| anyhow!("'{name}' is not set in {}", env_sources()))?
        }
        SecretValue::Source(SecretSource::Bitwarden { item, field }) => {
            rbw_get(item, field.as_deref().unwrap_or("password"), timeout)?
        }
        SecretValue::Source(SecretSource::OnePassword { reference }) => op_get(reference, timeout)?,
        SecretValue::Source(SecretSource::Command { run, args }) => cmd_get(run, args, timeout)?,
    };

    // An empty secret is almost always a misconfiguration: a locked vault, an
    // empty variable, a command that printed nothing. A plain value is taken as-is.
    let literal = matches!(value, SecretValue::Literal(_));
    if !literal && resolved.is_empty() {
        bail!("{} returned an empty value", describe(value));
    }

    Ok(resolved)
}

/// Describe where a secret comes from, for diagnostics. Never includes the secret.
pub fn describe(value: &SecretValue) -> String {
    match value {
        SecretValue::Literal(_) => "literal value in the profile file".to_string(),
        SecretValue::Source(SecretSource::Env { name }) => match name {
            Some(name) => format!("environment variable '{name}'"),
            None => "environment variable".to_string(),
        },
        SecretValue::Source(SecretSource::Bitwarden { item, field }) => format!(
            "bitwarden item '{item}' (field '{}')",
            field.as_deref().unwrap_or("password")
        ),
        SecretValue::Source(SecretSource::OnePassword { reference }) => {
            format!("1Password reference '{reference}'")
        }
        // Do not print the arguments: a command source may carry a token in an argument,
        // and this description ends up in `check` output and error messages.
        SecretValue::Source(SecretSource::Command { run, .. }) => format!("command `{run}`"),
    }
}

/// Ask Bitwarden (`rbw`) for a secret field.
///
/// Tries the custom field first, then falls back to `KEY=value` / `KEY: value`
/// lines in the item's notes, so one item can carry a whole server's environment.
fn rbw_get(item: &str, field: &str, timeout: Option<Duration>) -> Result<String> {
    let mut command = Command::new("rbw");
    command.args(["get", "--field", field, item]);
    let output = output_within(&mut command, timeout)
        .with_context(|| "failed to run 'rbw' (is the Bitwarden CLI installed and in PATH?)")?;
    if output.status.success() {
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !value.is_empty() {
            return Ok(value);
        }
    }

    let mut notes_command = Command::new("rbw");
    notes_command.args(["get", "--field", "notes", item]);
    if field != "password"
        && let Ok(notes) = output_within(&mut notes_command, timeout)
        && notes.status.success()
    {
        let notes = String::from_utf8_lossy(&notes.stdout);
        for line in notes.lines() {
            let trimmed = line.trim();
            let (key, value) = if let Some((key, value)) = trimmed.split_once('=') {
                (key.trim(), value.trim())
            } else if let Some((key, value)) = trimmed.split_once(':') {
                (key.trim(), value.trim())
            } else {
                continue;
            };
            if key.eq_ignore_ascii_case(field) {
                let value = value.trim_matches('"').trim_matches('\'');
                if !value.is_empty() {
                    return Ok(value.to_string());
                }
            }
        }
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.to_lowercase().contains("locked") {
        bail!("the Bitwarden vault is locked; run `rbw unlock` first");
    }
    bail!(
        "rbw get '{item}' (field '{field}') failed{}: the field is missing or empty",
        if stderr.is_empty() {
            String::new()
        } else {
            format!(" ({stderr})")
        }
    );
}

/// Ask the 1Password CLI for a secret reference: `op read <reference>`.
fn op_get(reference: &str, timeout: Option<Duration>) -> Result<String> {
    let mut command = Command::new("op");
    command.arg("read").arg(reference);
    let output = output_within(&mut command, timeout)
        .with_context(|| "failed to run 'op' (is the 1Password CLI installed and in PATH?)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!("op read '{reference}' failed: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run an arbitrary command and use its trimmed stdout as the secret.
fn cmd_get(run: &str, args: &[String], timeout: Option<Duration>) -> Result<String> {
    let mut command = Command::new(run);
    command.args(args);
    let output = output_within(&mut command, timeout).with_context(|| {
        format!("failed to run secret command '{run}' (is it installed and in PATH?)")
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        // Only the program name: the arguments may contain the secret itself.
        bail!("command `{run}` failed with {}: {stderr}", output.status);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a secret-source program and collect its output, killing it after `timeout`.
///
/// A password manager that is waiting for an unlock prompt can block forever when it
/// has no terminal to prompt on. The whole process group is stopped on timeout: `rbw`
/// often has a `pinentry` child that would otherwise keep waiting on its own.
fn output_within(command: &mut Command, timeout: Option<Duration>) -> Result<Output> {
    let Some(timeout) = timeout else {
        return Ok(command.output()?);
    };

    platform::isolate_process_group(command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;

    // Drain both pipes while waiting, so a program that fills one cannot deadlock
    // before it gets the chance to exit.
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());

    let deadline = Instant::now().checked_add(timeout);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            // `terminate` reaps the child on success. If it could not stop it, do not
            // wait: this deadline exists so a wedged program cannot block startup.
            if platform::terminate(&mut child).is_ok() {
                let _ = stdout.and_then(|handle| handle.join().ok());
                let _ = stderr.and_then(|handle| handle.join().ok());
            }
            bail!("did not finish within {}s", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Ok(Output {
        status,
        stdout: stdout
            .map(|handle| handle.join().unwrap_or_default())
            .unwrap_or_default(),
        stderr: stderr
            .map(|handle| handle.join().unwrap_or_default())
            .unwrap_or_default(),
    })
}

/// Collect a pipe on its own thread, so the parent can keep waiting on the child.
///
/// `None` when the OS refused the thread: the caller then simply has no output to
/// show, instead of the whole command panicking under resource pressure.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    std::thread::Builder::new()
        .name("secret-output".to_string())
        .spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_source_wins_over_the_ambient_environment() {
        // PATH always exists. An exported variable of the same name must not shadow
        // the configured literal: a declared secret has to depend on the declaration
        // alone, not on whatever the shell happened to export.
        let value = SecretValue::Literal("configured".to_string());
        assert_eq!(resolve("PATH", &value).unwrap(), "configured");
    }

    #[test]
    fn env_source_reads_the_named_variable() {
        let value = SecretValue::Source(SecretSource::Env { name: None });
        assert_eq!(
            resolve("PATH", &value).unwrap(),
            std::env::var("PATH").unwrap()
        );
    }

    #[test]
    fn an_env_file_holds_values_that_are_not_exported() {
        let parsed = parse_env_file(
            "# a comment\n\nMCP_CTL_AUTH_PASSWORD=hunter2\nexport QUOTED=\"two words\"\n\nnot a pair\n",
        );
        assert_eq!(parsed.get("MCP_CTL_AUTH_PASSWORD").unwrap(), "hunter2");
        assert_eq!(parsed.get("QUOTED").unwrap(), "two words");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn missing_environment_variable_is_reported_by_name() {
        let value = SecretValue::Source(SecretSource::Env {
            name: Some("MCP_CTL_TEST_MISSING_VARIABLE".to_string()),
        });
        let error = resolve("KEY", &value).unwrap_err().to_string();
        assert!(error.contains("MCP_CTL_TEST_MISSING_VARIABLE"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_env_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "mcp-ctl-env-permissions-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "TOKEN=secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = load_env_file(&path).unwrap_err().to_string();
        assert!(error.contains("chmod 600"), "{error}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn command_descriptions_do_not_print_their_arguments() {
        let value = SecretValue::Source(SecretSource::Command {
            run: "vault-read".to_string(),
            args: vec!["--token".to_string(), "super-secret".to_string()],
        });
        let description = describe(&value);
        assert_eq!(description, "command `vault-read`");
        assert!(!description.contains("super-secret"), "{description}");
    }

    #[cfg(unix)]
    #[test]
    fn command_source_trims_stdout() {
        let value = SecretValue::Source(SecretSource::Command {
            run: "echo".to_string(),
            args: vec!["hello-secret".to_string()],
        });
        assert_eq!(resolve("KEY", &value).unwrap(), "hello-secret");
    }

    #[cfg(unix)]
    #[test]
    fn empty_command_output_is_an_error() {
        let value = SecretValue::Source(SecretSource::Command {
            run: "true".to_string(),
            args: Vec::new(),
        });
        let error = resolve("KEY", &value).unwrap_err().to_string();
        assert!(error.contains("empty value"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_bounded_command_still_returns_its_value() {
        let value = SecretValue::Source(SecretSource::Command {
            run: "echo".to_string(),
            args: vec!["hello-secret".to_string()],
        });
        assert_eq!(
            resolve_with_timeout("KEY", &value, Some(Duration::from_secs(5))).unwrap(),
            "hello-secret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_never_finishes_is_stopped_at_the_deadline() {
        // A locked password manager can wait on an unlock prompt forever. Startup must
        // get an error back, not a thread parked in `wait`.
        let value = SecretValue::Source(SecretSource::Command {
            run: "sh".to_string(),
            args: vec!["-c".to_string(), "sleep 30".to_string()],
        });
        let started = std::time::Instant::now();
        let error =
            resolve_with_timeout("KEY", &value, Some(Duration::from_millis(200))).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("did not finish within"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the lookup must return at its deadline, not when the command ends"
        );
    }

    #[test]
    fn descriptions_never_contain_the_secret() {
        let literal = SecretValue::Literal("super-secret".to_string());
        assert_eq!(describe(&literal), "literal value in the profile file");

        let vault = SecretValue::Source(SecretSource::Bitwarden {
            item: "hostinger-vps".to_string(),
            field: None,
        });
        assert_eq!(
            describe(&vault),
            "bitwarden item 'hostinger-vps' (field 'password')"
        );
    }
}
