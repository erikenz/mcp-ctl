//! A stand-in for `mcp-auth-proxy`, used by the integration tests.
//!
//! It records the arguments and environment it was started with (to the path named by
//! `MCP_CTL_TEST_AUTH_PROXY_RECORD`) and then stays alive until the daemon stops it.
//!
//! It deliberately does **not** implement OAuth or proxy anything. What it pins down is
//! mcp-ctl's half of the contract: which flags we pass, that the hub target is right,
//! and that the password arrives through the environment rather than the command line.
//! Whether mcp-auth-proxy itself honours those flags is that project's test suite.

use std::io::Write;

fn main() {
    if let Ok(path) = std::env::var("MCP_CTL_TEST_AUTH_PROXY_RECORD") {
        let record = serde_json::json!({
            "args": std::env::args().skip(1).collect::<Vec<String>>(),
            "env": std::env::vars().collect::<std::collections::BTreeMap<String, String>>(),
        });
        if let Ok(mut file) = std::fs::File::create(&path) {
            let _ = file.write_all(record.to_string().as_bytes());
        }
    }

    // Stay alive: `up` treats a proxy that exits as a fatal error.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
