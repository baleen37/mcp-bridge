package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/baleen37/mcp-bridge/internal/auth"
	"github.com/baleen37/mcp-bridge/internal/config"
	"github.com/baleen37/mcp-bridge/internal/store"
)

func TestExecuteInitCreatesXDGConfigAndOwnerState(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(home, "config")
	stateHome := filepath.Join(home, "state")
	workspaceRoot := filepath.Join(home, "workspace")
	if err := os.Mkdir(workspaceRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", stateHome)

	var out bytes.Buffer
	password := "test-owner-password-123456"
	err := Execute(context.Background(), []string{
		"init", "--allowed-root", workspaceRoot, "--public-base-url", "https://example.test", "--owner-password-stdin",
	}, strings.NewReader(password+"\n"), &out, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), password) {
		t.Fatalf("owner password leaked in output: %s", out.String())
	}
	configPath := filepath.Join(configHome, "mcp-bridge", "config.json")
	statePath := filepath.Join(stateHome, "mcp-bridge", "state.db")
	if _, err := os.Stat(configPath); err != nil {
		t.Fatal(err)
	}
	state, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	hash, err := state.OwnerHash()
	if err != nil || !auth.VerifyPassword(hash, []byte(password)) {
		t.Fatalf("owner state was not initialized: %v", err)
	}
}

func TestExecuteSetupUsesHomeAndSuppliedPublicURL(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	configHome := filepath.Join(t.TempDir(), "config")
	stateHome := filepath.Join(t.TempDir(), "state")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", stateHome)

	installed := false
	oldInstaller := installLaunchAgent
	installLaunchAgent = func(_ context.Context, _ string, cfg config.Config) error {
		installed = true
		if len(cfg.AllowedRoots) != 1 || cfg.AllowedRoots[0] != home {
			t.Fatalf("allowed roots = %#v, want [%q]", cfg.AllowedRoots, home)
		}
		if cfg.PublicBaseURL != "https://bridge.example.com" {
			t.Fatalf("public base URL = %q", cfg.PublicBaseURL)
		}
		return nil
	}
	t.Cleanup(func() { installLaunchAgent = oldInstaller })

	var out bytes.Buffer
	password := "setup-owner-password-123456"
	if err := Execute(context.Background(), []string{"setup", "--public-base-url", "https://bridge.example.com", "--owner-password-stdin"}, strings.NewReader(password+"\n"), &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("setup did not install the LaunchAgent")
	}
	if strings.Contains(out.String(), password) {
		t.Fatalf("owner password leaked in output: %s", out.String())
	}
	state, err := store.Open(filepath.Join(stateHome, "mcp-bridge", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	hash, err := state.OwnerHash()
	if err != nil || !auth.VerifyPassword(hash, []byte(password)) {
		t.Fatalf("owner state was not initialized: %v", err)
	}
}

func TestSmokeOriginReportsConnectionFailureAs000(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	origin := server.URL
	server.Close()

	var out bytes.Buffer
	failed := smokeOrigin(&http.Client{Timeout: time.Second}, "local", origin, &out)
	if !failed {
		t.Fatal("expected smoke check to fail against a closed test server")
	}
	if !strings.Contains(out.String(), "000") {
		t.Fatalf("smoke output = %q", out.String())
	}
}

func TestPrintStatusOriginsReportsLocalAndPublic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	var out bytes.Buffer
	printStatusOrigins(server.Client(), server.URL, server.URL, &out)
	value := out.String()
	for _, want := range []string{"local /healthz 200", "local /mcp 401", "public /healthz 200", "public /mcp 401"} {
		if !strings.Contains(value, want) {
			t.Fatalf("status output missing %q: %s", want, value)
		}
	}
}

func TestRunStatusReportsHealthyOperationalState(t *testing.T) {
	tmp := t.TempDir()
	cfg := statusTestConfig(tmp)
	for _, path := range []string{cfg.ConfigPath, cfg.StateDBPath, filepath.Join(tmp, "Library", "LaunchAgents", "io.github.baleen37.mcp-bridge.plist")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(cfg.RuntimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RuntimeDir, "mcp-bridge.pid"), []byte(`{"pid":123,"expected":"mcp-bridge"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RuntimeDir, "cloudflared.pid"), []byte(`{"pid":456,"expected":"cloudflared"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Host, cfg.Port = host, port
	cfg.PublicBaseURL = server.URL
	var out bytes.Buffer
	err = runStatus(context.Background(), cfg, &out, statusEnvironment{
		Client: server.Client(), HomeDir: tmp,
		Stat: os.Stat,
		InspectProcess: func(_ context.Context, pid int) (string, error) {
			if pid == 456 {
				return "/usr/local/bin/cloudflared", nil
			}
			return "/usr/local/bin/mcp-bridge", nil
		},
		RunCommand: func(context.Context, string, []string, []string) ([]byte, error) { return []byte("loaded"), nil },
	})
	if err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	for _, want := range []string{
		"config=", "state=", "runtime=", "mcp=", "launch-agent=", "pid-mcp-bridge=123", "pid-cloudflared=456",
		"config-file=ok", "state-file=ok", "launch-agent-plist=ok", "launch-agent-loaded=ok",
		"process-mcp-bridge=ok pid=123", "process-cloudflared=ok pid=456",
		"local /healthz 200 status=ok", "local /mcp 401 status=ok", "public /healthz 200 status=ok", "public /mcp 401 status=ok", "status=ok",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status output missing %q: %s", want, out.String())
		}
	}
}

func TestRunStatusReportsMissingAndUnsafeFailures(t *testing.T) {
	tmp := t.TempDir()
	cfg := statusTestConfig(tmp)
	cfg.PublicBaseURL = "http://127.0.0.1:1"
	if err := os.MkdirAll(cfg.RuntimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RuntimeDir, "mcp-bridge.pid"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runStatus(context.Background(), cfg, &out, statusEnvironment{
		Client: &http.Client{Timeout: time.Second}, HomeDir: tmp, Stat: os.Stat,
		InspectProcess: func(context.Context, int) (string, error) { return "", errors.New("process not found") },
		RunCommand: func(context.Context, string, []string, []string) ([]byte, error) {
			return nil, errors.New("Authorization=secret-token command failed")
		},
	})
	if err == nil {
		t.Fatal("expected status failure")
	}
	value := out.String()
	for _, want := range []string{"config-file=fail", "state-file=fail", "launch-agent-plist=fail", "launch-agent-loaded=fail", "pid-mcp-bridge=invalid", "process-mcp-bridge=fail", "public /healthz 000 status=fail reason=connection-refused", "status=fail"} {
		if !strings.Contains(value, want) {
			t.Fatalf("status output missing %q: %s", want, value)
		}
	}
	if strings.Contains(value, "secret-token") || strings.Contains(value, "Authorization") {
		t.Fatalf("sensitive command error leaked: %s", value)
	}
}

func TestStatusHTTPClassifiesTimeoutWithoutErrorText(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}
	code, reason := statusHTTP(context.Background(), client, "http://example.test/healthz", http.StatusOK)
	if code != 0 || reason != "timeout" {
		t.Fatalf("statusHTTP = (%d, %q), want (0, timeout)", code, reason)
	}
}

func TestFileExistsRequiresRegularFile(t *testing.T) {
	if fileExists(os.Stat, t.TempDir()) {
		t.Fatal("directory must not be reported as a regular file")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func statusTestConfig(tmp string) config.Config {
	return config.Config{
		ConfigPath: filepath.Join(tmp, "config.json"), StateDBPath: filepath.Join(tmp, "state.db"), RuntimeDir: filepath.Join(tmp, "runtime"),
		Host: "127.0.0.1", Port: 7676, PublicBaseURL: "https://example.test",
	}
}

func TestDoctorReportsOperationalChecks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)

	cfg := config.Config{
		ConfigPath:    filepath.Join(t.TempDir(), "config.json"),
		StateDBPath:   filepath.Join(t.TempDir(), "state.db"),
		PublicBaseURL: server.URL,
		Host:          "127.0.0.1",
		Port:          7676,
		AllowedRoots:  []string{t.TempDir()},
		RuntimeDir:    t.TempDir(),
	}
	var out bytes.Buffer
	err := runDoctor(cfg, &out, doctorEnvironment{
		Client:       server.Client(),
		LocalOrigin:  server.URL,
		PublicOrigin: server.URL,
		LookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
		Stat: func(string) (os.FileInfo, error) {
			return fakeFileInfo{}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"doctor git=ok", "doctor public-health=ok", "doctor oauth-metadata=ok"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("doctor output missing %q: %s", want, out.String())
		}
	}
}

func TestConfigGetAndSet(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(home, "config")
	stateHome := filepath.Join(home, "state")
	root := filepath.Join(home, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", stateHome)
	if err := Execute(context.Background(), []string{
		"init", "--allowed-root", root, "--public-base-url", "https://initial.test", "--owner-password-stdin",
	}, strings.NewReader("owner-password-123456\n"), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	var getOut bytes.Buffer
	if err := Execute(context.Background(), []string{"config", "get", "public-base-url"}, strings.NewReader(""), &getOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if getOut.String() != "public-base-url=https://initial.test\n" {
		t.Fatalf("config get output = %q", getOut.String())
	}

	if err := Execute(context.Background(), []string{"config", "set", "public-base-url", "https://updated.test"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(map[string]string{"XDG_CONFIG_HOME": configHome, "XDG_STATE_HOME": stateHome}, home)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicBaseURL != "https://updated.test" {
		t.Fatalf("public base URL = %q", cfg.PublicBaseURL)
	}
}

type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return "fake" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }
