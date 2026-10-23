# Contributing

Thanks for taking the time. This project is small enough that a clear description of the problem is worth more than a large patch, so open an issue if you are unsure about an approach.

## Development setup

```bash
git clone https://github.com/erikenz/mcp-ctl.git
cd mcp-ctl
cargo build
```

## Checks before a pull request

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

`--all-features` matters: the fake MCP server that the end-to-end tests drive lives behind the `test-support` feature, so that it never ends up in a release build or archive.

The integration tests start real daemons on ephemeral ports in their own temporary directories and stop them again. They never touch your real `~/.config` or the daemon you have running.

## Pull request titles

A squash merge makes the pull request title the commit subject, and the release notes are generated from those subjects by `cliff.toml`. Write titles as conventional commits:

```text
feat(tray): restart only the profile that was clicked
fix: keep the control port out of the state file
docs: say which platforms are beta
```

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `style`, `revert`, `chore`. A `!` before the colon marks a breaking change, e.g. `feat(config)!: rename proxy_port`. The `PR title` check fails a pull request whose title does not match, because a release with an unclassified commit is a release with a missing line.

## Design notes

A few rules keep the codebase coherent; please follow them:

- `src/platform.rs` is the only module allowed to contain `#[cfg(unix)]` / `#[cfg(windows)]` process handling. Everything else stays portable.
- The daemon never inspects PIDs and never signals a process it does not own. Lifecycle goes through the control channel in `src/control.rs`.
- Secrets are resolved in `src/secret.rs` and must never be logged. Types that hold them implement `Debug` by hand, printing `<redacted>`.
- Long-running or blocking work happens per request or per backend, never while holding a lock that other requests need.
- Behaviour that the README documents gets updated in the same pull request. This has been wrong before, and it is the fastest way to lose a reader's trust.

## Reporting bugs

Include `mcp-ctl --version`, your platform, the relevant part of your profile file with secrets removed, and the output of `mcp-ctl status`. For anything security related, follow [SECURITY.md](SECURITY.md) instead.
