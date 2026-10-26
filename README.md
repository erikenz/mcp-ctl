# mcp-ctl

[![CI](https://github.com/erikenz/mcp-ctl/actions/workflows/ci.yml/badge.svg)](https://github.com/erikenz/mcp-ctl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

One config file for all your MCP servers. `mcp-ctl` fills in secrets from your password manager, runs a single server on stdio for a local editor, or serves everything you choose over one authenticated HTTP endpoint for remote agents.

## Requirements

| Dependency | Needed for |
| :--- | :--- |
| `rbw`, `op`, or any command | Secrets from Bitwarden, 1Password, `pass` or a script. |
| [`mcp-auth-proxy`](https://github.com/sigbit/mcp-auth-proxy/releases) | OAuth 2.1 / PKCE / password sign-in for remote clients. Not needed when clients can send a bearer token; mcp-ctl starts and supervises it. |
| `tailscale` or `cloudflared` | An HTTPS tunnel to a public URL. |

## Install

Linux and macOS, with the install script (it verifies the release checksum before writing anything):

```bash
curl -fsSL https://raw.githubusercontent.com/erikenz/mcp-ctl/main/install/install.sh | sh
```

Windows:

```powershell
irm https://raw.githubusercontent.com/erikenz/mcp-ctl/main/install/install.ps1 | iex
```

Or with Homebrew on macOS or Linux:

```bash
brew install erikenz/tap/mcp-ctl
```

Or take the archive for your platform from the [latest release](https://github.com/erikenz/mcp-ctl/releases/latest), check it against the `.sha256` beside it, and put `mcp-ctl` somewhere on your `PATH`. The same release carries a `.deb` and a `.rpm` for Debian/Ubuntu and Fedora/RHEL.

With Rust 1.88 or newer (edition 2024):

```bash
cargo install mcp-ctl
```

## Quick start

```bash
mcp-ctl init     # write ~/.config/mcp-ctl/config.json and an owner-only .env
mcp-ctl check    # validate it, resolve every secret, flag busy ports
mcp-ctl up       # serve the servers marked "serve": true
```

`init` writes a single profile file holding both the servers and mcp-ctl's own settings:

```json
{
  "$schema": "https://raw.githubusercontent.com/erikenz/mcp-ctl/main/schema/config.schema.json",
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest", "--browser-url=http://127.0.0.1:9222"],
      "serve": true
    },
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": { "source": "1password", "reference": "op://dev/github/token" }
      }
    }
  },
  "server": { "listen_port": 37373 },
  "auth": { "password": { "source": "env", "name": "MCP_CTL_AUTH_PASSWORD" } }
}
```

[`schema/config.schema.json`](https://github.com/erikenz/mcp-ctl/blob/main/schema/config.schema.json) gives editors completion and catches typos.

## Usage

```bash
mcp-ctl list              # what is configured
mcp-ctl check             # validate config, resolve secrets, flag busy ports
mcp-ctl run <name>        # run one server on stdio, for a local editor
mcp-ctl up                # serve over HTTP; add -d for the background daemon
mcp-ctl status            # what the service is doing (--json for scripts)
mcp-ctl logs -f           # follow the daemon log
mcp-ctl restart           # pick up config changes
mcp-ctl stop              # stop the service and every backend
mcp-ctl update --check    # is there a newer release?
mcp-ctl update            # update in place, when the install script owns the binary
```

`check` is the pre-flight step: it resolves every secret, reports where each value came from (never the value), and exits non-zero on a problem, which makes it usable in a script. `--config <path>` points one run at another profile file; `-v` logs requests with credentials redacted, and `--verbose-bodies` also logs payloads (debugging only).

## Configuration

### Servers

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `command` / `args` / `env` | — | A local stdio server. An `env` value may be a secret source, or a plain string for a non-secret setting. |
| `url` | — | A remote MCP server. Listed by `list`, not served yet. |
| `serve` | `false` | Whether `mcp-ctl up` serves this server without it being named on the command line. |
| `enabled` | `true` | Set to `false` to keep an entry but ignore it everywhere. |
| `prefix` | — | Prefix this server's tool names, e.g. `github_create_issue`. |
| `timeout_secs` | — | Overrides `server.tool_timeout_secs` for this server; `0` waits forever. |
| `tools.include` / `tools.exclude` | — | Publish only some of the server's tools. A pattern is a tool name or a prefix ending in `*`. |
| `env_clear` | `false` | Start the server with an empty environment instead of inheriting mcp-ctl's. |
| `cwd` | — | Working directory for a stdio server. |

Keys mcp-ctl does not know are ignored inside a server entry, because the same file is also read by other MCP clients, so a snippet copied from a server's README works as it is. Top-level keys are strict, so `"proxy_portt"` is reported instead of silently ignored.

### Settings

Every key is optional. Out of the box mcp-ctl serves `"serve": true` entries on `127.0.0.1`, with no tunnel and no authentication.

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `server.bind` | `127.0.0.1` | Address the hub binds to. It has no authentication of its own; `auth.bearer_token` is the only thing that protects this port. A non-loopback bind with proxy-only auth is refused. |
| `server.listen_port` | `37373` | Hub port. `0` asks the operating system for a free one. |
| `server.proxy_port` | `8080` | Port the auth proxy listens on. `0` is not supported: the tunnel target and `status` need the real port. |
| `server.external_url` | — | Public URL clients use, for OAuth callbacks and browser origins. Required once `mcp-auth-proxy` is enabled; Tailscale can supply it. Must be `https://` unless it is a loopback URL for local testing. |
| `server.auth_proxy_path` | — | Where `mcp-auth-proxy` lives, if it is not on `PATH`. |
| `server.tool_timeout_secs` | `300` | How long one backend tool call may take; `0` waits forever. |
| `server.allowed_origins` | `[]` | Extra browser origins allowed to call the hub. Origins on a host mcp-ctl is served on are allowed without being listed. |
| `tunnel.provider` | `none` | `none`, `tailscale` or `cloudflared`. |
| `tunnel.auto_start` | `true` | Start the tunnel when a provider is configured. |
| `tunnel.port` | — | Local port the tunnel forwards to. Defaults to the auth proxy's port, or the hub's. With proxy auth it must be the proxy port; a tunnel aimed at the unauthenticated hub is refused. |
| `auth.password` | — | Password for the auth proxy. Any secret source works. |
| `auth.github_client_id` / `_secret` | — | GitHub OAuth credentials for the auth proxy. Must be set together. |
| `auth.google_client_id` / `_secret` | — | Google OAuth credentials for the auth proxy. Must be set together. |
| `auth.bearer_token` | — | Static `Authorization: Bearer ...` token checked by the hub. No proxy and no `external_url`, but no sign-in either; cannot be combined with `password` or the OAuth settings. Use at least 16 characters of random data. |
| `tray.enabled` | `false` | Show the tray icon while `mcp-ctl up` runs. |

### Secrets

A secret is resolved when a server starts and handed to that server's environment. It is never written to disk and never logged. An `env` value is a plain string when the value is not secret, or a source when it is:

```json
{
  "env": {
    "LOG_LEVEL": "info",
    "GITHUB_TOKEN": { "source": "env", "name": "GITHUB_TOKEN" }
  }
}
```

| Provider | Example | Notes |
| :--- | :--- | :--- |
| **Bitwarden** | `{"source": "bitwarden", "item": "sentry", "field": "access_token"}` | Uses `rbw`. Falls back to `KEY=value` lines in the item's notes. |
| **1Password** | `{"source": "1password", "reference": "op://dev/github/token"}` | Uses `op read`. |
| **Command** | `{"source": "command", "run": "pass", "args": ["show", "api/key"]}` | Uses the command's trimmed stdout. |
| **Environment** | `{"source": "env", "name": "GITHUB_TOKEN"}` | Reads the environment, or `.env` next to the profile (the shell wins). |

Secrets that live in a file belong in `.env` next to the profile, which mcp-ctl reads itself and never exports to the servers it runs. `init` creates it `0600`, and on Unix mcp-ctl refuses to read a `.env` that other local users can read:

```bash
# ~/.config/mcp-ctl/.env
MCP_CTL_AUTH_PASSWORD=choose-a-strong-password
```

**A password or token must not be written out in the profile file.** That file is one copy-paste away from being shared or committed, so mcp-ctl refuses a literal for `auth` and points at `.env`, a vault or the environment. There is no `{"source": "literal"}`. A plain string in a server's `env` is for settings that are not secret; mcp-ctl cannot tell whether a value is a credential, and `check` warns when the name looks like one. A secret placed in a server's `args` is part of the command line and is shown by `list` and `check`; use `env` instead.

Five rules worth knowing:

1. **What the config says wins.** A variable exported in your shell does not shadow a configured source; use `{"source": "env"}` to read the environment on purpose.
2. **An empty result is an error.** An empty API key is almost always a locked vault or a mistyped command; a plain value is taken as it is.
3. **Resolved secrets are never printed.** `-v` redacts credential-like headers and query strings; `--verbose-bodies` is for debugging only. A secret placed in `args` is not redacted.
4. **Backends inherit the daemon's environment** unless `"env_clear": true` is set. A value read from `.env` is not exported; a value you exported in the shell is visible to every backend. Use `.env` (or `env_clear`) when only one server should see it.
5. **One unavailable secret skips one server.** If `up` cannot resolve a server's secret (a locked vault, a missing CLI, or a lookup that does not finish within a few seconds), it logs a warning and serves the rest. `mcp-ctl check` reports every problem before you start.

Environment overrides, useful in scripts and editors: `MCP_CTL_CONFIG_DIR` (where profiles and `.env` live), `MCP_CTL_PROFILE` (which profile to use), `MCP_CTL_STATE_DIR` (where the daemon state and log live).

### Profiles

A profile is a separate installation: its own file, settings, daemon and ports. One for work, one for personal servers, either stopped without touching the other.

```bash
mcp-ctl --profile work init      # writes ~/.config/mcp-ctl/config.work.json
mcp-ctl --profile work up -d     # serve it in the background
mcp-ctl status                   # every profile: running or not
mcp-ctl status work              # just that one, in detail
mcp-ctl --profile work stop      # stop it; other profiles keep running
```

The default profile keeps the paths above, so a single-profile installation is unchanged. A named profile keeps its daemon state under `profiles/<name>/`, with its own lock and log, which is what lets two daemons run at once. Give each profile its own `listen_port` and `proxy_port`, or start it with `--port 0`. `MCP_CTL_PROFILE=work` does the same for editors that cannot pass flags, and a profile name is one path-safe segment (`../escape` is rejected).

## Serving over HTTP

```bash
mcp-ctl up                         # every server with "serve": true, in the foreground
mcp-ctl up chrome-devtools sentry  # only these
mcp-ctl up --all                   # every enabled server
mcp-ctl up --no-tunnel --no-auth   # local only
mcp-ctl up --port 0                # let the OS pick a free port
```

Four rules are enforced rather than warned about:

- Publishing an unauthenticated hub, through a tunnel or a non-loopback `server.bind`, is refused unless you pass `--allow-unauthenticated-exposure`. The auth proxy does **not** count as hub authentication: it listens on loopback and protects the tunnel in front of it, while the hub port itself stays open. With `auth.password` or OAuth, keep `server.bind` loopback and let the tunnel target the proxy port. Only `auth.bearer_token` authenticates the hub itself.
- `mcp-auth-proxy` (password or OAuth) without `server.external_url` is refused: sign-in callbacks would point at localhost. `auth.bearer_token` needs no `external_url`, because there is no callback. A public `external_url` must be `https://`; `http://` is accepted only for loopback testing.
- A tunnel with proxy auth must forward to the proxy port. Setting `tunnel.port` to the hub port (or anything else) is refused; with `auth.bearer_token` the hub itself is authenticated and may be the target, and `--allow-unauthenticated-exposure` overrides the refusal.
- `--config` and `--profile` are remembered by a detached daemon, so `mcp-ctl --profile work up -d` and a later `restart` keep serving the work profile.

A background service logs to `~/.local/state/mcp-ctl/mcp-ctl.log` on Linux, `~/Library/Application Support/mcp-ctl/` on macOS and `%LOCALAPPDATA%\mcp-ctl\` on Windows; `mcp-ctl status` prints the exact path. The log rotates at 5 MiB when a daemon starts, so a service that runs for months should also be rotated by the system. `mcp-ctl stop --force` kills a daemon that answers the control channel but will not exit; mcp-ctl never signals a process it cannot identify.

A tunnel forwards to `tunnel.port`. With proxy auth, leave it unset so the tunnel reaches the proxy; pointing it at the hub would publish the unauthenticated hub and is refused. Tailscale can name its own public URL, which mcp-ctl reads from `tailscale status --json`; a Cloudflare quick tunnel picks a random hostname, which mcp-ctl reads from its output and `status` keeps showing.

### Starting on login (systemd user service)

```ini
# ~/.config/systemd/user/mcp-ctl.service
[Unit]
Description=mcp-ctl MCP hub
After=network-online.target

[Service]
ExecStart=%h/.local/bin/mcp-ctl up
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now mcp-ctl.service
```

## Connecting a client

Editors that speak MCP over stdio can run one server through `mcp-ctl run`:

```json
{ "command": "mcp-ctl", "args": ["run", "github"] }
```

or take the whole hub through [`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{ "command": "npx", "args": ["-y", "mcp-remote", "http://127.0.0.1:37373/mcp"] }
```

The key differs per editor (`context_servers` in Zed, `mcpServers` in Cursor and Claude Desktop). To pin a profile, put `MCP_CTL_PROFILE` in that entry's environment.

To reach the hub from another machine, give clients `server.external_url` with `/mcp` on the end and pick a way to sign in:

| `auth` setting | What a client does |
| :--- | :--- |
| `bearer_token` | Sends `Authorization: Bearer ...`. No proxy and no `external_url`, but no sign-in either. |
| `password` | Signs in with a password through `mcp-auth-proxy`. |
| `github_client_id` / `_secret`, `google_client_id` / `_secret` | Signs in with a GitHub or Google account through `mcp-auth-proxy`. |

The auth proxy receives its secrets through the environment rather than its command line, and keeps its state in the mcp-ctl state directory.

## Updating

```bash
mcp-ctl update --check   # prints "mcp-ctl 0.1.0 → 0.2.0 is available", exits 1
mcp-ctl update           # installs it
```

`update` replaces the binary only when the install script put it there — `~/.local/bin/mcp-ctl`. Every other copy is left alone and told to be updated the way it was installed: a `cargo install`, a `.deb`/`.rpm` or a binary you moved by hand belongs to another tool. On Windows it points at `install.ps1`, because replacing a running `.exe` is not reliable.

When a daemon is running, an interactive `mcp-ctl update` asks whether to restart it (or every running profile) on the new version. The prompt is skipped when stdin is not a terminal; run `mcp-ctl restart` in that case. The restart keeps the profile and profile file, but not extra `up` flags — repeat those with `mcp-ctl restart` if you used them.

An interactive `mcp-ctl restart` resolves the selected servers' secrets before stopping the old daemon, so a locked vault prompts while the service is still up. Without a terminal, startup keeps its bounded secret lookup and skips a server that does not answer in time.

The download is checked against the `.sha256` published beside it. That catches corruption and a network attacker who cannot alter both files, but it is **not a signature**: an attacker who can replace the release assets can replace the checksum too. For a stronger check, verify the build provenance the release workflow attaches:

```bash
gh attestation verify mcp-ctl-<version>-<target>.tar.gz --repo erikenz/mcp-ctl
```

Nothing checks for updates in the background, and `status` and `check` never touch the network.

## Tray icon

With `"tray": { "enabled": true }` an icon appears while `mcp-ctl up` runs: a line per server, the hub and public URLs, `Restart service` and `Shut down`. On Linux it is a StatusNotifierItem, so it needs a tray host (KDE Plasma, waybar, Quickshell, XFCE, GNOME with the AppIndicator extension); with none listening the icon stays hidden and the service keeps running. macOS and Windows use the platform's own status item.

## Security

- The hub binds loopback and has no authentication of its own. `auth.bearer_token` is the only thing that authenticates the hub port; the auth proxy protects the tunnel in front of it, not the hub. A non-loopback bind with proxy-only auth, or a tunnel aimed at the hub, is refused.
- Browser requests are checked against their `Origin`. The `Host` header is not trusted, so a hostname that resolves to `127.0.0.1` cannot call your tools. The port is not compared, but the public URL's scheme is enforced at every port.
- Secrets are resolved when a server starts and handed to that child. They are redacted in `Debug` output and never logged; the auth proxy receives them through the environment rather than the command line. A backend also inherits the daemon's environment unless `env_clear` is set, so prefer `.env` for a value only one server should see.
- Only `auth` literals are refused in the profile file. A plain string in a server's `env` is for non-secret settings; a secret placed in `args` is part of the command line and is shown by `list`/`check`. Use `.env`, the environment or a vault.
- `.env` is checked for owner-only permissions on Unix, and the state directory, log and files `init` writes are owner-only.
- The hub caps concurrent connections and gives each request a deadline. `auth.bearer_token` must be at least 16 characters, and failed attempts are rate-limited.
- `update` verifies the release checksum but not a signature; see [Updating](#updating) for the attestation check.

[SECURITY.md](https://github.com/erikenz/mcp-ctl/blob/main/SECURITY.md) has the threat model and how to report a vulnerability privately.

## Platforms

Linux, macOS and Windows build and test in CI. Linux is the reference platform; macOS and Windows are beta, and have not been exercised on real hardware yet — please report what breaks.

## Limitations

- Only local stdio servers are served. Entries with `url` are listed and skipped.
- Tools are exposed; resources and prompts are not.
- `POST /mcp` is the only method on the endpoint: no sessions, no server-sent stream.
- Tool-call progress notifications are not relayed yet.

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](https://github.com/erikenz/mcp-ctl/blob/main/CONTRIBUTING.md).

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
```

## Acknowledgements

mcp-ctl was inspired by [mcp-hub](https://github.com/ravitemer/mcp-hub) — the single endpoint in front of many servers, and the default port 37373, come from there. Remote authentication runs on [`mcp-auth-proxy`](https://github.com/sigbit/mcp-auth-proxy), which mcp-ctl supervises rather than reimplements.

## License

[MIT](https://github.com/erikenz/mcp-ctl/blob/main/LICENSE)
