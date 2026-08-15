# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
go build -o ./bin/mcp-bridge ./cmd/mcp-bridge
go test -race ./...
go vet ./...
gofmt -l .            # must print nothing
golangci-lint run
```

Run a single test or package:

```bash
go test -race ./internal/auth/
go test -race -run TestOAuthMCPToolFlow ./tests/
```

CI (`.github/workflows/ci.yml`) runs build, vet, `test -race`, gofmt, and golangci-lint on
Linux. golangci-lint is pinned; install the same version so local runs match:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
```

The test suite is platform-independent and needs only `git` on `PATH`. macOS-only paths
(`launchctl`, `cloudflared`) sit behind injectable runner interfaces and are faked in tests,
so everything passes on Linux CI.

## Architecture

A local MCP server that exposes this machine's files and shell to a remote MCP client (e.g.
ChatGPT web) over a Cloudflare Named Tunnel. It binds loopback-only on `127.0.0.1:7676`; the
tunnel provides the public origin.

### Request path

`cmd/mcp-bridge` is a thin `main` delegating to `cli.Execute`. The whole object graph is
built in one place — `buildHTTPApp` in `internal/cli/commands.go`:

```
config.Load → store.Open (SQLite) → auth.Provider
                                  → workspace.Registry
                                  → tools.Service
                                  → mcp.NewServer → mcp.NewHTTPHandler
```

`internal/mcp/http.go` owns routing: `/healthz`, the two OAuth discovery documents,
`/register`, `/authorize`, `/token`, and `/mcp`. Every route is wrapped by
`hostMiddleware` (rejects any `Host` that is neither loopback nor the configured public
origin) and `requestLogger` (logs only the *presence* of credentials, never values, and
never the raw query, which carries authorization codes).

`/mcp` picks between two SDK transports based on the `Mcp-Protocol-Version` header:
stateless at or beyond `2026-07-28`, stateful otherwise. Unknown versions must fall back to
stateful — the version list is checked with `slices.Contains` before comparison because
plain string comparison would sort a garbage value above every real revision.

### The two security boundaries

Both deserve care; `CONTRIBUTING.md` asks that PRs touching them state the effect explicitly.

**Auth** (`internal/auth`). OAuth 2.1: dynamic client registration, PKCE (S256 only),
owner-password approval, and access/refresh token rotation. The owner password is Argon2id
hashed (`password.go`); because it may be as short as four characters and `/authorize` is
publicly reachable, approval attempts are rate-limited (5 attempts, 15-minute lockout) —
hashing alone bounds cost per guess, not guess count. Only tokens *hashes* live in SQLite.
Authorization errors redirect to the client's redirect URI only after the client and URI
validate (`RedirectableError`), so an unvalidated URI can never become an open redirect.

**Workspace containment** (`internal/workspace`). `Registry.Resolve` is the single
choke point for every file path a tool touches: it rejects absolute paths and `..`
components, then resolves symlinks with `EvalSymlinks` and re-checks that the result is
still inside the workspace root. For paths that don't exist yet it walks up to the nearest
existing parent and checks that instead. `resolveAllowedExisting` gates `open_workspace`
against the configured allowed roots, checking both lexically and after canonicalization.

Note the asymmetry: `exec_command` runs arbitrary shell through `/bin/sh -lc` and therefore
*can* step outside the workspace. Path containment protects the file tools; the allowed root
plus client trust is what bounds the shell.

### Tools and workspaces

`internal/mcp/server.go` declares the MCP tool surface — schemas, descriptions, and
thin adapters — and delegates all behavior to `tools.Service` (`internal/tools/`:
`files.go`, `search.go`, `shell.go`, `changes.go`, `artifact.go`). Tool descriptions and
`jsonschema` struct tags are the client-facing contract and are written for a model reading
them cold; keep that register when editing.

`download_artifact` is registered only when `cfg.ArtifactDownloadsEnabled` is set, so the
tool list is config-dependent — assert on tool *names*, not a count.

Clients call `open_workspace` first and pass the returned `workspace_id` to everything else.
Two modes: `checkout` uses the directory as is; `worktree` creates a detached Git worktree
from `base_ref` under the XDG state directory. Records are cached in memory and persisted to
SQLite, and a record reloaded from the store is re-validated against the allowed roots
(`validateStoredRecord`) — config may have narrowed since it was written.

`exec_command` returns a non-zero exit as a normal result, not a Go error. stdout and stderr
share a single output budget (1 MiB hard cap) so the pair cannot exceed the caller's limit,
and `WaitDelay` bounds the wait on grandchildren holding pipes open, which keeps the timeout
honest.

### Config and state

`config.Load` layers, in order: defaults → `config.json` → environment. XDG paths
throughout; nothing is created directly under `$HOME`. `Validate` enforces a loopback host,
port 7676, at least one allowed root, and an HTTPS public base URL with no path, query, or
userinfo. `Save` writes atomically through a temp file at `0600`.

Secrets never touch config: `config get/set` accepts only an allowlist of safe fields and
errors on anything else. The tunnel token is read from the environment or a file, held in
memory, passed to `cloudflared` via its environment, and zeroed — never written to the
plist, logs, or argv.

### Process lifecycle

`internal/lifecycle` runs the macOS LaunchAgent (`io.github.baleen37.mcp-bridge`) and
supervises the `cloudflared` child. `Supervisor.Run` starts the tunnel alongside the HTTP
server and writes PID files that record the expected process name, so liveness checks can
confirm the PID still belongs to the right program.

`MCP_BRIDGE_SKIP_TUNNEL=1` runs the server without a tunnel. Adding
`MCP_BRIDGE_LOCAL_AUTH_BYPASS=1` also skips auth, but only for loopback requests with a
loopback `Host` — both variables are required together, and neither belongs anywhere near
the production LaunchAgent.

## Conventions

- No new dependencies without a good reason.
- Comments here explain *why*, usually citing the RFC clause or the attack a line prevents.
  Match that: skip comments that restate the code.
- Descriptive names over abbreviations (`workspaces`, `errorsChannel`, `statusResponseWriter`).
- Never log or persist passwords, tokens, or the tunnel token. Zero password buffers after use
  (`zeroBytes`), and compare secrets with `crypto/subtle`.
- External effects go through an interface so tests can fake them: `CommandRunner`,
  `GitRunner`, `ProcessInspector`, `StateStore`.
- `.golangci.yml` enables `gosec` and excludes G204/G304 repo-wide — running commands and
  reading files *is* the feature, and containment is enforced by `Registry.Resolve`. Prefer a
  narrow `//nolint` with a reason (see the G710 case in `http.go`) over widening the excludes.
