//! Shared helpers for the integration tests.
//!
//! Every test gets its own config directory, state directory and profile file, so tests
//! never see each other's daemons and never touch the real `~/.config`.

#![allow(dead_code)] // each test binary uses a different subset

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value;

/// A temporary directory that removes itself when the test ends.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "mcp-ctl-test-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path).expect("create the test directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.join(name);
        std::fs::write(&path, contents).expect("write the test file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// An isolated `mcp-ctl` installation: config, state and server catalogue.
pub struct Sandbox {
    pub dir: TempDir,
    pub config_dir: PathBuf,
}

impl Sandbox {
    pub fn new(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        let config_dir = dir.join("config");
        std::fs::create_dir_all(&config_dir).expect("create the config directory");
        Self { dir, config_dir }
    }

    /// Write the catalogue part of the profile file.
    pub fn mcp_json(&self, contents: &str) -> PathBuf {
        self.merge_into_profile(contents)
    }

    /// Write the settings part of the profile file.
    pub fn config_json(&self, contents: &str) {
        self.merge_into_profile(contents);
    }

    /// Write a named profile: `config.<name>.json` next to the default one.
    pub fn profile(&self, name: &str, contents: &str) {
        std::fs::write(
            self.config_dir.join(format!("config.{name}.json")),
            contents,
        )
        .expect("write a profile file");
    }

    /// Write the `.env` next to the profile files, where `{"source": "env"}` looks.
    pub fn env_file(&self, contents: &str) {
        std::fs::write(self.config_dir.join(".env"), contents).expect("write .env");
    }

    /// Merge a fragment into `config.json`, so a test can write the catalogue and the settings
    /// in either order without one overwriting the other.
    fn merge_into_profile(&self, contents: &str) -> PathBuf {
        let path = self.config_dir.join("config.json");
        let mut base: serde_json::Map<String, Value> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let fragment: serde_json::Map<String, Value> =
            serde_json::from_str(contents).expect("a JSON object");
        base.extend(fragment);
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&Value::Object(base)).expect("serialize config.json"),
        )
        .expect("write config.json");
        path
    }

    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }

    /// Run `mcp-ctl` with this sandbox's paths in the environment.
    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-ctl"));
        command
            .env("MCP_CTL_CONFIG_DIR", &self.config_dir)
            .env("MCP_CTL_STATE_DIR", self.state_dir());
        command
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command()
            .args(args)
            .output()
            .expect("run the mcp-ctl binary")
    }
}

/// JSON string literal for a path, so Windows separators survive.
pub fn json_string(value: &str) -> String {
    serde_json::Value::String(value.to_string()).to_string()
}

/// One `mcpServers` entry that runs the fake MCP server.
pub fn fake_server_entry(name: &str, extra_args: &[&str]) -> String {
    let command = json_string(env!("CARGO_BIN_EXE_mcp-fake-server"));
    let mut args = vec![json_string("--name"), json_string(name)];
    for argument in extra_args {
        args.push(json_string(argument));
    }
    format!(
        r#""{name}": {{ "command": {command}, "args": [{}], "serve": true }}"#,
        args.join(", ")
    )
}

/// A complete `mcpServers` block containing the given fake servers.
pub fn mcp_json_with(entries: &[String]) -> String {
    format!(r#"{{ "mcpServers": {{ {} }} }}"#, entries.join(", "))
}

/// One HTTP response, split the way the tests assert on it.
pub struct HttpResponse {
    pub status: u16,
    pub head: String,
    pub body: String,
}

impl HttpResponse {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|error| {
            panic!("the response body is not JSON ({error}): {}", self.body)
        })
    }
}

/// A minimal HTTP/1.1 client: the tests must not need a dependency the tool does not
/// already have.
pub fn http(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the hub");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("Connection: close\r\n\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }

    stream
        .write_all(request.as_bytes())
        .expect("send the request");
    read_response(&mut stream)
}

fn read_response(stream: &mut TcpStream) -> HttpResponse {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => head.push(byte[0]),
            Err(error) => panic!("reading the response head: {error}"),
        }
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("a status line");

    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = vec![0u8; length];
    let mut filled = 0;
    while filled < length {
        match stream.read(&mut body[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) => panic!("reading the response body: {error}"),
        }
    }
    body.truncate(filled);

    HttpResponse {
        status,
        head,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}
