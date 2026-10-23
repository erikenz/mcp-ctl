//! A minimal stdio MCP server used by the integration tests.
//!
//! It is only built with `--features test-support` (see `Cargo.toml`), so it never
//! reaches a release archive:
//!
//! ```text
//! cargo test --all-features
//! ```
//!
//! Flags:
//! ```text
//! --name <name>          serverInfo name (default: fake)
//! --tool <name>          name of the echoing tool (default: echo)
//! --slow-ms <n>          how long the `slow` tool takes (default: 5000)
//! --exit-file <path>     written when the server exits cleanly
//! --cwd-file <path>      written with the working directory at startup
//! --env-file <path>      written with `KEY=value` lines from the environment at startup
//! --hang-initialize      never answer initialize
//! --notifications <n>    emit n unsolicited notifications after initialize
//! --garbage              write one non-UTF-8 line to stdout before answering anything
//! ```

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};

fn main() {
    let options = Options::parse(std::env::args().skip(1).collect());
    if let Err(error) = run(&options) {
        eprintln!("fake-mcp-server: {error}");
        std::process::exit(1);
    }
}

struct Options {
    name: String,
    tool: String,
    slow_ms: u64,
    exit_file: Option<String>,
    cwd_file: Option<String>,
    env_file: Option<String>,
    hang_initialize: bool,
    notifications: usize,
    garbage: bool,
}

impl Options {
    fn parse(args: Vec<String>) -> Self {
        let mut options = Self {
            name: "fake".to_string(),
            tool: "echo".to_string(),
            slow_ms: 5_000,
            exit_file: None,
            cwd_file: None,
            env_file: None,
            hang_initialize: false,
            notifications: 0,
            garbage: false,
        };

        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            let value = args.get(index + 1).cloned();
            match flag {
                "--name" => {
                    options.name = value.unwrap_or(options.name);
                    index += 2;
                }
                "--tool" => {
                    options.tool = value.unwrap_or(options.tool);
                    index += 2;
                }
                "--slow-ms" => {
                    if let Some(parsed) = value.and_then(|value| value.parse().ok()) {
                        options.slow_ms = parsed;
                    }
                    index += 2;
                }
                "--exit-file" => {
                    options.exit_file = value;
                    index += 2;
                }
                "--cwd-file" => {
                    options.cwd_file = value;
                    index += 2;
                }
                "--env-file" => {
                    options.env_file = value;
                    index += 2;
                }
                "--notifications" => {
                    if let Some(parsed) = value.and_then(|value| value.parse().ok()) {
                        options.notifications = parsed;
                    }
                    index += 2;
                }
                "--hang-initialize" => {
                    options.hang_initialize = true;
                    index += 1;
                }
                "--garbage" => {
                    options.garbage = true;
                    index += 1;
                }
                _ => index += 1,
            }
        }

        options
    }
}

fn run(options: &Options) -> Result<(), String> {
    // Record the startup environment before serving, so the tests can check what a
    // backend inherited (or did not inherit, with `env_clear`).
    if let Some(path) = &options.cwd_file {
        let cwd = std::env::current_dir().map_err(|error| format!("current_dir: {error}"))?;
        std::fs::write(path, format!("{}\n", cwd.display()))
            .map_err(|error| format!("writing {path}: {error}"))?;
    }
    if let Some(path) = &options.env_file {
        let mut lines: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
        lines.sort();
        std::fs::write(path, lines.join("\n"))
            .map_err(|error| format!("writing {path}: {error}"))?;
    }

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut line = String::new();

    if options.garbage {
        // A stray non-UTF-8 byte on stdout (a log line, a latin-1 filename) must not
        // make the hub treat this server as dead.
        stdout
            .write_all(b"\xff\xfe not valid UTF-8\n")
            .map_err(|error| format!("writing stdout: {error}"))?;
        stdout
            .flush()
            .map_err(|error| format!("flushing stdout: {error}"))?;
    }

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            // stdin was closed: that is how a stdio MCP server is asked to stop.
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => return Err(format!("reading stdin: {error}")),
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };

        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        // Notifications have no id and expect no answer.
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        if method == "initialize" && options.hang_initialize {
            std::thread::sleep(std::time::Duration::from_secs(600));
            continue;
        }

        let reply = match method.as_str() {
            "initialize" => {
                let version = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2024-11-05")
                    .to_string();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": version,
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": options.name, "version": "fake" }
                    }
                })
            }
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": [
                    { "name": options.tool, "description": "echoes its arguments", "inputSchema": { "type": "object" } },
                    { "name": "slow", "description": "sleeps before answering", "inputSchema": { "type": "object" } },
                    { "name": "fail", "description": "always fails", "inputSchema": { "type": "object" } }
                ]}
            }),
            "tools/call" => {
                let tool = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if tool == options.tool {
                    let arguments = params
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({}));
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "content": [ { "type": "text", "text": format!("echo:{arguments}") } ] }
                    })
                } else if tool == "slow" {
                    std::thread::sleep(std::time::Duration::from_millis(options.slow_ms));
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "content": [ { "type": "text", "text": "slow done" } ] }
                    })
                } else if tool == "fail" {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32000, "message": "fake failure", "data": { "detail": "as requested" } }
                    })
                } else {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": format!("unknown tool '{tool}'") }
                    })
                }
            }
            other => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("unknown method '{other}'") }
            }),
        };

        write_line(&mut stdout, &reply)?;

        // Chatty backends exist; this is how the tests produce one.
        if method == "initialize" {
            for index in 0..options.notifications {
                write_line(
                    &mut stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/message",
                        "params": { "level": "info", "data": format!("noise {index}") }
                    }),
                )?;
            }
        }
    }

    if let Some(path) = &options.exit_file {
        let _ = std::fs::write(path, "exited\n");
    }
    Ok(())
}

fn write_line(stdout: &mut impl Write, value: &Value) -> Result<(), String> {
    let mut line = value.to_string();
    line.push('\n');
    stdout
        .write_all(line.as_bytes())
        .map_err(|error| format!("writing to stdout: {error}"))?;
    stdout
        .flush()
        .map_err(|error| format!("flushing stdout: {error}"))
}
