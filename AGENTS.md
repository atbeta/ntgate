# AGENTS.md

Repository-level instructions for AI coding agents and human collaborators.

## Instruction priority

1. User request in the current conversation
2. This `AGENTS.md` (nearest file in the directory tree wins in monorepos)
3. Source code and tests
4. Other docs (`README`, nested `AGENTS.md`, skills)

If instructions conflict, follow the higher-priority item and state the conflict briefly.

## Default engineering preferences

### Package managers

| Stack | Tool |
|-------|------|
| Rust | **cargo** |

### Change discipline

- Smallest complete change that satisfies the request
- Read relevant code before editing; reuse existing patterns
- No drive-by refactors in the same change
- No secrets or passwords in config samples or commits
- Add or update tests when behavior changes (unless docs-only)

### Commit messages

Conventional Commits in concise English: `type(scope): subject` (subject ≤ 72 chars).

Types: `feat` `fix` `perf` `refactor` `style` `docs` `test` `chore` `ci`

≥ 4 staged files → body with 2–6 bullets (why, impact, optional risk).

## Project: ntgate

Windows local HTTP proxy facade for corporate NTLM/Negotiate/PAC proxies. Winfoom-compatible behavior; single binary + TOML; current-user SSPI; logon task instead of a SYSTEM service.

### Layout

```text
src/main.rs           CLI
src/lib.rs            crate root
src/config.rs         TOML schema
src/server.rs         accept loop + hop failover
src/auth/             NTLM/Negotiate handshake; SSPI on Windows
src/resolve/          PAC / system / static hops (WinHTTP on Windows)
src/http1.rs          HTTP/1 parse + encode
src/noproxy.rs        bypass matcher
config.example.toml   default config written on first run
```

### Commands (this repo)

```bash
cargo test
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo build --release
```

CI (`.github/workflows/ci.yml`): Ubuntu `cargo test` + clippy; Windows x64 `cargo build --release` uploads `ntgate.exe`. Tags `v*` publish a GitHub Release.

### Project-specific rules

- Windows-only for SSO, PAC evaluation, and `install`. Shared parsers/config must keep compiling on macOS (`cargo test`).
- Do not store passwords. Auth is the current Windows logon session.
- Listen should default to loopback (`127.0.0.1:3128`).
- `install` must run as the logged-on user (Task Scheduler logon trigger), never LOCAL SYSTEM.
- NTLM handshake stays on one TCP connection to the parent proxy.
- PAC SOCKS hops are skipped; only `PROXY` / `DIRECT`.
- Behavioral reference: Winfoom (`ecovaci/winfoom`), not cntlm source.

### Commit convention

None — follow base section.
