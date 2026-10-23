# Security Policy

## Reporting a vulnerability

Please report security problems **privately**: use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability) instead of a public issue.

Include what you did, what happened, what you expected, and:

- `mcp-ctl --version`
- your operating system
- whether you were running `mcp-ctl up`, `up -d`, or `run`
- the relevant part of your profile file (`config.json`), with secrets removed

You will get an acknowledgement, an assessment, and credit in the release notes if you want it. Please give a fix a chance to ship before publishing details.

## Supported versions

Fixes land on the latest release, and that release is the only one supported. mcp-ctl is pre-1.0, so a minor version may change behaviour or configuration: the [release notes](https://github.com/erikenz/mcp-ctl/releases) say what changed and what to do about it.

## What mcp-ctl is trusted with

Be clear-eyed about the blast radius before running it:

- **It reads your secrets.** `rbw`, `op`, environment and command sources run with your privileges, and their output is injected into the environment of the servers you configure.
- **It executes what you configure.** Every `command` in your profile file and every `{"source": "command"}` is an arbitrary program, run as you.
- **It hands out tool access.** Unless `auth.bearer_token` is configured, anything that can reach the hub can call every tool of every served server, with those credentials.

## The security model

| Boundary | How it is protected |
| :--- | :--- |
| Network | The hub binds `127.0.0.1` by default. `server.bind` can widen that, and doing so is on you unless `auth.bearer_token` or `mcp-auth-proxy` is configured. |
| Public exposure | A tunnel combined with no authentication is refused unless `--allow-unauthenticated-exposure` is passed. Public deployments are expected to use `auth.bearer_token` or `mcp-auth-proxy` (OAuth 2.1 / PKCE / password). |
| Browsers | Requests carrying an `Origin` are only served when that origin is the `external_url` origin, an origin on a host mcp-ctl is actually served on (loopback, `server.bind`, `external_url`), or listed in `server.allowed_origins`. The port is not compared, so a page served by a local dev server (the MCP Inspector on `localhost:6274`, say) can call the hub without being listed. Scheme and host are both compared, so `http://host` cannot pass as `https://host`. The caller's `Host` header is never trusted as proof of identity, which is what stops a page whose own hostname resolves to `127.0.0.1` (DNS rebinding) from calling your local tools. There is no wildcard CORS. |
| Hub authentication | `auth.bearer_token` requires `Authorization: Bearer ...` on every request except the health probe, the CORS preflight and OAuth discovery; tokens are compared in constant time and never logged. |
| Exposure | Serving a server does not have to mean serving all of its tools: per-server `"tools": {"include": [...], "exclude": [...]}` decides what is published. |
| Backend environment | Backends inherit the daemon's environment — everything you exported when you started it — plus the `env` you configure. Set `"env_clear": true` on a server if you want it to see nothing else, and remember that it then needs `PATH` in `env`. |
| Auditability | Every tool call is logged at default verbosity as `[tool] t=<unix seconds> <server>/<tool> ok in 12ms`, so the log answers what was called and when. |
| Secrets at rest | Resolved secrets are never written to disk. Secrets that live in a file belong in `.env` next to the profile files: owner-only (`0600`) on Unix, read by mcp-ctl itself, and never exported to the servers it runs. A password or token may not be a literal in the profile file — mcp-ctl refuses it, because that file is one copy-paste away from being shared — and a server's `env` holds plain strings only for non-secret settings. The other file that contains a secret is the daemon state file, which holds the control token and is created owner-only (`0600`) on Unix, in a `0700` state directory alongside the owner-only daemon log and the auth proxy's data directory. |
| Secrets in logs | Resolved values are never logged, `Debug` implementations redact them, and `-v` redacts credential headers. `--verbose-bodies` deliberately logs payloads: treat those logs as sensitive even though they are owner-only. |
| Command lines | The auth proxy's password and OAuth secrets are passed through the environment, never as arguments, so they do not appear in `ps` or `/proc/*/cmdline`. |
| Local control | `status` and `stop` authenticate with a random token from the state file, and never kill a process that does not answer on that control port. `--force` is a deliberate opt-in. |
| Other local users | The hub port is loopback and unauthenticated, and the auth proxy forwards to it: any other user or process on this machine can call the hub port directly and bypass the proxy. The control port is token-guarded, but the hub port is not. Run mcp-ctl on a machine you are alone on, or keep the tool filters tight, if that matters to you. |
| Child processes | Backends and tunnels run in their own process group, so stopping the hub stops the whole tree instead of leaving `npx`/`node` behind. |
| Dependencies | mcp-ctl downloads nothing at runtime, but it does execute `mcp-auth-proxy` if you install it. Pin a release and verify it yourself. |

## Out of scope

- **An attacker with your user account.** They can read your vault CLI session, your config and the state file, and can run mcp-ctl themselves.
- **A malicious MCP server you configured.** mcp-ctl is a multiplexer, not a sandbox: a server you add can do anything you can.
- **`server.bind` pointing at a non-loopback address**, or `--allow-unauthenticated-exposure`. Both are documented foot-guns rather than vulnerabilities.
