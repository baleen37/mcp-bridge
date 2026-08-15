# mcp-bridge

A local MCP server written in Go. It binds to `127.0.0.1:7676` and exposes your machine to
remote MCP clients — such as ChatGPT web — through a Cloudflare Named Tunnel.

The server provides these tools: `open_workspace`, `read_file`, `write_file`, `grep_files`,
`list_dir`, `show_changes`, `apply_patch`, and `exec_command`. Enabling artifact downloads
adds `download_artifact`.

> **Security note:** this grants a remote MCP client the ability to read files and run shell
> commands on your machine, bounded by the allowed root you configure. Keep that root as
> narrow as your workflow permits, and only connect clients you trust.

## Requirements

- macOS — startup is managed through a LaunchAgent
- Go 1.26+
- Git
- cloudflared

```bash
brew install go git cloudflared
```

Build:

```bash
mkdir -p bin
go build -o ./bin/mcp-bridge ./cmd/mcp-bridge
```

## First-time setup

`setup` is the simplest path. It sets the allowed root to your home directory (`~`), saves
the configuration, and installs the macOS LaunchAgent. You supply the public base URL — the
HTTPS origin your Cloudflare tunnel serves. The owner password is entered twice, is never
echoed, and must be at least 4 characters.

```bash
./bin/mcp-bridge setup --public-base-url https://mcp-bridge.example.com
```

In automation, pass the owner password on stdin:

```bash
printf '%s\n' 'your-owner-password-123456' \
  | ./bin/mcp-bridge setup --public-base-url https://mcp-bridge.example.com --owner-password-stdin
```

Passwords, access tokens, refresh tokens, and the tunnel token are never written to the
repository.

## XDG paths

No dedicated state directory is created directly under your home directory.

- Configuration: `${XDG_CONFIG_HOME:-$HOME/.config}/mcp-bridge/config.json`
- SQLite state: `${XDG_STATE_HOME:-$HOME/.local/state}/mcp-bridge/state.db`
- Worktrees: `${XDG_STATE_HOME:-$HOME/.local/state}/mcp-bridge/worktrees`
- Logs and PID files: `${XDG_STATE_HOME:-$HOME/.local/state}/mcp-bridge/logs`

### Environment variables

| Variable | Purpose |
| --- | --- |
| `MCP_BRIDGE_PUBLIC_BASE_URL` | HTTPS public origin. Required if not set in the config file. |
| `MCP_BRIDGE_TUNNEL_TOKEN` | Cloudflare tunnel token. Takes precedence over the token file. |
| `MCP_BRIDGE_TUNNEL_TOKEN_FILE` | Path to a file containing the tunnel token. |
| `MCP_BRIDGE_RUNTIME_DIR` | Override the log and PID directory. |
| `MCP_BRIDGE_WORKTREE_ROOT` | Override the worktree directory. |
| `MCP_BRIDGE_ALLOWED_ROOTS` | Comma-separated roots the MCP tools may access. |
| `MCP_BRIDGE_OAUTH_REDIRECT_HOSTS` | Comma-separated additional OAuth redirect hostnames. |
| `MCP_BRIDGE_ARTIFACT_DOWNLOADS_ENABLED` | Set to `1` to enable `download_artifact`. |

With artifact downloads enabled, the allowed hosts are `chatgpt.com`, `chat.openai.com`,
`localhost`, `127.0.0.1`, and `::1`. Public hosts must use HTTPS.

## Cloudflare Tunnel

Point your Cloudflare Named Tunnel's ingress at the local origin:

```text
http://127.0.0.1:7676
```

Provide the tunnel token through the environment, or through a file readable only by you:

```bash
export MCP_BRIDGE_TUNNEL_TOKEN='your-tunnel-token'
```

```bash
install -m 600 /dev/null ~/.config/mcp-bridge/tunnel-token
printf '%s' 'your-tunnel-token' > ~/.config/mcp-bridge/tunnel-token
export MCP_BRIDGE_TUNNEL_TOKEN_FILE="$HOME/.config/mcp-bridge/tunnel-token"
```

The Go process holds the token in memory only and passes it to the `cloudflared` child
process as `TUNNEL_TOKEN`. The token is never written to the plist, the logs, or command
arguments.

## Running and restarting

```bash
./bin/mcp-bridge setup --public-base-url https://mcp-bridge.example.com
./bin/mcp-bridge status
./bin/mcp-bridge doctor
./bin/mcp-bridge config get mcp-url
./bin/mcp-bridge remove
```

`setup` starts the server and the Cloudflare tunnel, and is safe to re-run when already
configured. `status` reports local and public connectivity. `doctor` checks the required
executables, the config and state paths, the LaunchAgent, local and public health, and the
OAuth metadata. `config get/set` reads and changes only safe settings, never passwords or
tokens. `remove` disables automatic startup while preserving your XDG configuration and state.

The server binds to loopback only and starts automatically after macOS login. The LaunchAgent
label is `io.github.baleen37.mcp-bridge`.

## OAuth and connecting an MCP client

Your MCP endpoint is your public base URL with `/mcp` appended:

```text
https://mcp-bridge.example.com/mcp
```

The server supports dynamic client registration, the PKCE authorization code flow, owner
password approval, and access/refresh token rotation. Register the URL above in your MCP
client's connection screen, then enter the owner password on the OAuth approval screen.

Do not put a password or an `Authorization` header directly into the MCP URL.

## Testing tool calls locally

To exercise the MCP tools locally without OAuth, use these two environment variables
together. The server skips authentication only for loopback requests with a local `Host`
header, and does not start a tunnel.

```bash
MCP_BRIDGE_SKIP_TUNNEL=1 MCP_BRIDGE_LOCAL_AUTH_BYPASS=1 ./bin/mcp-bridge start
```

In this mode you can send `initialize`, `tools/list`, and `tools/call` to
`http://127.0.0.1:7676/mcp` without a bearer token. Requests with a public `Host` header, and
remote requests, still return 401. Never set these variables for the production LaunchAgent or
the public tunnel.

## Workspaces and tools

Call `open_workspace` first to select a project beneath an allowed root. The `workspace_id` in
the response is the handle for that workspace; pass it to subsequent tool calls to operate
inside that workspace root.

- **checkout** mode uses the existing directory as is.
- **worktree** mode creates a detached worktree from Git `HEAD` under the XDG state directory.
- File and directory paths cannot escape the workspace root.
- `exec_command` uses the workspace as its default `workdir`, with a 30-second default timeout
  and a 300-second maximum. `timeout_ms` is applied in milliseconds.
- `max_output_tokens` is applied to real output at 4 bytes per token; total output never
  exceeds 1 MiB.
- `read_file`, `grep_files`, and `list_dir` are inspection tools that return `{ "text": "..." }`.
  `read_file` takes a 1-based `offset` line number, and `grep_files` takes a Go RE2 regular
  expression as `pattern` with an optional filename glob as `include`.
- `apply_patch` replaces an `old_text` block that matches exactly once.
- `write_file` writes `content` to `path`, creating parent directories as needed. Use it for
  new files, since `apply_patch` can only replace text that already exists.
- `show_changes` reports uncommitted work in a Git workspace as porcelain status followed by a
  diff against `HEAD`, and returns
  `{ "text", "files_changed", "additions", "deletions", "untracked", "truncated" }`.
- `exec_command` returns `{ "text", "exit_code", "truncated", "timed_out" }`. An ordinary
  non-zero exit is returned as a normal result, not an error.

Keep the allowed root as narrow as possible. Shell tools can bypass the file-access
restrictions, so connect only trusted MCP clients.

## Troubleshooting

Not needed for normal use — reach for these when diagnosing a connection problem.

Check the local server:

```bash
./bin/mcp-bridge smoke-test --local
```

Check the public Cloudflare endpoint too:

```bash
./bin/mcp-bridge smoke-test --public
./bin/mcp-bridge smoke-test --all
```

Success means HTTP 200 on `/healthz` and HTTP 401 on an unauthenticated `/mcp`. A connection
failure is reported as HTTP status `000`.

To run the local server without a tunnel:

```bash
MCP_BRIDGE_SKIP_TUNNEL=1 ./bin/mcp-bridge start
```

`status` checks the config and state files, the LaunchAgent plist and its registration, PID
file format, process liveness and ownership, and local/public HTTP status, then prints
`status=ok|fail` and exits non-zero if any check fails. HTTP errors are reported as safe
classifications such as timeout or connection-refused. Tokens, passwords, and `Authorization`
values are never printed. OAuth metadata and MCP discovery/tool calls are outside the scope of
`status`.

## Development

```bash
go test -race ./...
go vet ./...
go build -o ./bin/mcp-bridge ./cmd/mcp-bridge
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
