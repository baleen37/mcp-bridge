# Contributing

Thanks for your interest in mcp-bridge.

## Getting started

```bash
go build -o ./bin/mcp-bridge ./cmd/mcp-bridge
go test -race ./...
go vet ./...
```

CI runs `go build`, `go vet`, and `go test -race` on Linux. The test suite is
platform-independent and needs only `git` on `PATH`; the macOS-specific parts
(`launchctl`) are behind an injectable command runner and are faked in tests.

## Pull requests

- Keep changes focused, and include a test for behavior changes.
- Make sure `go test -race ./...` and `go vet ./...` pass before opening the PR.
- Follow the existing style: no new dependencies without a good reason.

## Security

This project exposes file access and shell execution to a remote MCP client. When
changing anything under `internal/auth`, `internal/workspace`, or `internal/tools`,
please note in your PR how the change affects the workspace boundary or the
authentication path. Never log or persist passwords, tokens, or the tunnel token.

Please report security issues privately through GitHub's security advisory page
rather than as a public issue.
