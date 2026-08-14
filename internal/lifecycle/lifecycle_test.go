package lifecycle

import (
	"context"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baleen37/mcp-bridge/internal/config"
)

type commandCall struct {
	name string
	args []string
	env  []string
}

type fakeCommandRunner struct {
	calls  []commandCall
	output []byte
	err    error
}

func (f *fakeCommandRunner) Run(_ context.Context, name string, args []string, env []string) ([]byte, error) {
	f.calls = append(f.calls, commandCall{name: name, args: append([]string(nil), args...), env: append([]string(nil), env...)})
	return append([]byte(nil), f.output...), f.err
}

type fakeProcessInspector struct {
	command string
	err     error
	signals []int
}

func (f *fakeProcessInspector) Command(_ context.Context, _ int) (string, error) {
	return f.command, f.err
}

func (f *fakeProcessInspector) Signal(_ context.Context, pid int) error {
	f.signals = append(f.signals, pid)
	return nil
}

func TestReadTunnelTokenPrefersEnvironmentOverFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_BRIDGE_TUNNEL_TOKEN", "env-token\n")

	token, err := ReadTunnelToken(config.Config{TunnelTokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	if string(token) != "env-token" {
		t.Fatalf("token = %q, want env-token", token)
	}
}

func TestReadTunnelTokenFallsBackToFile(t *testing.T) {
	t.Setenv("MCP_BRIDGE_TUNNEL_TOKEN", "")
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("file-token\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	token, err := ReadTunnelToken(config.Config{TunnelTokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	if string(token) != "file-token" {
		t.Fatalf("token = %q, want file-token", token)
	}
}

func TestReadTunnelTokenRejectsMissingOrEmptyToken(t *testing.T) {
	emptyFile := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(emptyFile, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  config.Config
	}{
		{name: "no token configured", cfg: config.Config{}},
		{name: "empty token file", cfg: config.Config{TunnelTokenFile: emptyFile}},
		{name: "missing token file", cfg: config.Config{TunnelTokenFile: filepath.Join(t.TempDir(), "absent")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MCP_BRIDGE_TUNNEL_TOKEN", "")
			if _, err := ReadTunnelToken(tc.cfg); err == nil {
				t.Fatal("expected token error")
			}
		})
	}
}

func TestRenderLaunchAgentEscapesXMLAndOmitsTunnelToken(t *testing.T) {
	cfg := config.Config{
		RuntimeDir:      "/tmp/logs&<>",
		TunnelTokenFile: "/tmp/tunnel-token&<>\"",
		WorktreeRoot:    "/tmp/worktrees",
	}

	plist, err := RenderLaunchAgent(`/tmp/bin/mcp-bridge&<>`, cfg, 42)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := xml.Unmarshal(plist, &document); err != nil {
		t.Fatalf("invalid plist XML: %v\n%s", err, plist)
	}
	// The plist may name the token file, but must never carry the token value
	// itself: cloudflared receives it through the child process environment.
	if strings.Contains(string(plist), "<key>TUNNEL_TOKEN</key>") || strings.Contains(string(plist), "tunnel-secret") {
		t.Fatalf("plist contains tunnel secret data: %s", plist)
	}
	for _, want := range []string{"mcp-bridge", "RunAtLoad", "KeepAlive", "ThrottleInterval", "&amp;", "&lt;"} {
		if !strings.Contains(string(plist), want) {
			t.Errorf("plist missing %q", want)
		}
	}
	for _, key := range []string{"Label", "WorkingDirectory", "StandardOutPath", "StandardErrorPath"} {
		if !strings.Contains(string(plist), "<key>"+key+"</key>") {
			t.Errorf("plist has invalid or missing key %q", key)
		}
	}
}

func TestInstallAndUninstallLaunchAgentUseFixedLabel(t *testing.T) {
	home := t.TempDir()
	oldHome := userHomeDir
	oldUID := currentUserID
	userHomeDir = func() (string, error) { return home, nil }
	currentUserID = func() int { return 42 }
	t.Cleanup(func() {
		userHomeDir = oldHome
		currentUserID = oldUID
	})

	cfg := config.Config{RuntimeDir: t.TempDir(), TunnelTokenFile: "/tmp/tunnel-token"}
	runner := &fakeCommandRunner{}
	if err := InstallLaunchAgent(context.Background(), "/tmp/mcp-bridge", cfg, runner); err != nil {
		t.Fatal(err)
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
	if _, err := os.Stat(plistPath); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0].name != "launchctl" || strings.Join(runner.calls[0].args, " ") != "bootout gui/42/"+launchAgentLabel || runner.calls[1].name != "launchctl" || strings.Join(runner.calls[1].args, " ") != "bootstrap gui/42 "+plistPath {
		t.Fatalf("unexpected bootstrap call: %#v", runner.calls)
	}

	if err := UninstallLaunchAgent(context.Background(), cfg, runner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plistPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("plist still exists: %v", err)
	}
	if len(runner.calls) != 3 || strings.Join(runner.calls[2].args, " ") != "bootout gui/42/"+launchAgentLabel {
		t.Fatalf("unexpected bootout call: %#v", runner.calls)
	}
}

func TestStopRefusesPIDOwnershipMismatch(t *testing.T) {
	cfg := config.Config{RuntimeDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(cfg.RuntimeDir, "cloudflared.pid"), []byte(`{"pid":1234,"expected":"cloudflared"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inspector := &fakeProcessInspector{command: "/usr/bin/other-process"}
	if err := stop(context.Background(), cfg, inspector); err == nil {
		t.Fatal("expected ownership mismatch")
	}
	if len(inspector.signals) != 0 {
		t.Fatalf("signals = %#v", inspector.signals)
	}
}
