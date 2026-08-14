package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/baleen37/mcp-bridge/internal/config"
)

var ErrProcessNotFound = errors.New("process not found")

type CommandRunner interface {
	Run(ctx context.Context, name string, args []string, env []string) ([]byte, error)
}

type CommandStarter interface {
	CommandRunner
	Start(ctx context.Context, name string, args []string, env []string, stdout, stderr io.Writer) (Process, error)
}

type Process interface {
	PID() int
	Wait() error
	Signal(os.Signal) error
}

type ProcessInspector interface {
	Command(ctx context.Context, pid int) (string, error)
	Signal(ctx context.Context, pid int) error
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = commandEnv(env)
	return command.Output()
}

func (ExecCommandRunner) Start(ctx context.Context, name string, args []string, env []string, stdout, stderr io.Writer) (Process, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = commandEnv(env)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	return execProcess{command: command}, nil
}

type execProcess struct {
	command *exec.Cmd
}

func (p execProcess) PID() int {
	return p.command.Process.Pid
}

func (p execProcess) Wait() error {
	return p.command.Wait()
}

func (p execProcess) Signal(signal os.Signal) error {
	return p.command.Process.Signal(signal)
}

type OSProcessInspector struct{}

func (OSProcessInspector) Command(ctx context.Context, pid int) (string, error) {
	output, err := (ExecCommandRunner{}).Run(ctx, "ps", []string{"-p", fmt.Sprint(pid), "-o", "command="}, nil)
	if err != nil {
		return "", ErrProcessNotFound
	}
	command := strings.TrimSpace(string(output))
	if command == "" {
		return "", ErrProcessNotFound
	}
	return command, nil
}

func (OSProcessInspector) Signal(_ context.Context, pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return ErrProcessNotFound
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			return ErrProcessNotFound
		}
		return err
	}
	return nil
}

// ReadTunnelToken resolves the cloudflared tunnel token, preferring the
// MCP_BRIDGE_TUNNEL_TOKEN environment variable and falling back to the file named
// by MCP_BRIDGE_TUNNEL_TOKEN_FILE. The token is never logged; callers pass it to
// the cloudflared child process through its environment and zero it afterwards.
func ReadTunnelToken(cfg config.Config) ([]byte, error) {
	if value := os.Getenv("MCP_BRIDGE_TUNNEL_TOKEN"); value != "" {
		token := strings.TrimRight(value, "\r\n")
		if token == "" {
			return nil, errors.New("MCP_BRIDGE_TUNNEL_TOKEN is empty")
		}
		return []byte(token), nil
	}
	if cfg.TunnelTokenFile == "" {
		return nil, errors.New("tunnel token is not configured: set MCP_BRIDGE_TUNNEL_TOKEN or MCP_BRIDGE_TUNNEL_TOKEN_FILE")
	}
	content, err := os.ReadFile(cfg.TunnelTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read tunnel token file %s: %w", cfg.TunnelTokenFile, err)
	}
	token := bytes.TrimRight(content, "\r\n")
	if len(token) == 0 {
		return nil, fmt.Errorf("tunnel token file %s is empty", cfg.TunnelTokenFile)
	}
	return append([]byte(nil), token...), nil
}

type Supervisor struct {
	Server    *http.Server
	Config    config.Config
	Command   CommandStarter
	Inspector ProcessInspector
}

func (s *Supervisor) Run(ctx context.Context) error {
	if s.Server == nil {
		return errors.New("HTTP server is required")
	}
	if err := s.Config.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}
	if s.Command == nil {
		s.Command = ExecCommandRunner{}
	}
	if s.Inspector == nil {
		s.Inspector = OSProcessInspector{}
	}
	if s.Server.Addr == "" {
		s.Server.Addr = s.Config.Address()
	}
	if err := os.MkdirAll(s.Config.RuntimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}

	serverErrors := make(chan error, 1)
	go func() {
		if err := s.Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()
	if err := writePID(s.Config.RuntimeDir, "mcp-bridge", pidRecord{PID: os.Getpid(), Expected: filepath.Base(os.Args[0])}); err != nil {
		_ = shutdownServer(s.Server)
		return err
	}
	cleanupSelf := true
	defer func() {
		if cleanupSelf {
			_ = removePID(s.Config.RuntimeDir, "mcp-bridge")
		}
	}()

	if err := waitForHealth(ctx, s.Config.Address()); err != nil {
		_ = shutdownServer(s.Server)
		return err
	}
	token, err := ReadTunnelToken(s.Config)
	if err != nil {
		_ = shutdownServer(s.Server)
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(s.Config.RuntimeDir, "cloudflared.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		zeroBytes(token)
		_ = shutdownServer(s.Server)
		return fmt.Errorf("open tunnel log: %w", err)
	}
	env := withEnv(os.Environ(), "TUNNEL_TOKEN", string(token))
	zeroBytes(token)
	tunnel, err := s.Command.Start(ctx, "cloudflared", []string{"tunnel", "run"}, env, logFile, logFile)
	if err != nil {
		_ = logFile.Close()
		_ = shutdownServer(s.Server)
		return errors.New("start cloudflared failed")
	}
	if err := writePID(s.Config.RuntimeDir, "cloudflared", pidRecord{PID: tunnel.PID(), Expected: "cloudflared"}); err != nil {
		_ = tunnel.Signal(syscall.SIGTERM)
		_ = logFile.Close()
		_ = shutdownServer(s.Server)
		return err
	}

	tunnelErrors := make(chan error, 1)
	go func() { tunnelErrors <- tunnel.Wait() }()
	select {
	case <-ctx.Done():
		_ = tunnel.Signal(syscall.SIGTERM)
		_ = shutdownServer(s.Server)
		_ = logFile.Close()
		_ = removePID(s.Config.RuntimeDir, "cloudflared")
		return ctx.Err()
	case err := <-tunnelErrors:
		_ = shutdownServer(s.Server)
		_ = logFile.Close()
		_ = removePID(s.Config.RuntimeDir, "cloudflared")
		if err != nil {
			return errors.New("cloudflared exited unexpectedly")
		}
		return errors.New("cloudflared exited unexpectedly")
	case err := <-serverErrors:
		_ = tunnel.Signal(syscall.SIGTERM)
		_ = shutdownServer(s.Server)
		_ = logFile.Close()
		_ = removePID(s.Config.RuntimeDir, "cloudflared")
		return fmt.Errorf("HTTP server stopped: %w", err)
	}
}

func Stop(cfg config.Config) error {
	return stop(context.Background(), cfg, OSProcessInspector{})
}

func stop(ctx context.Context, cfg config.Config, inspector ProcessInspector) error {
	for _, name := range []string{"cloudflared", "mcp-bridge"} {
		path := filepath.Join(cfg.RuntimeDir, name+".pid")
		record, err := readPID(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s PID: %w", name, err)
		}
		command, err := inspector.Command(ctx, record.PID)
		if errors.Is(err, ErrProcessNotFound) {
			_ = os.Remove(path)
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s process: %w", name, err)
		}
		if !commandHasBinary(command, record.Expected) {
			return fmt.Errorf("refusing to stop %s PID %d: process ownership changed", name, record.PID)
		}
		if err := inspector.Signal(ctx, record.PID); err != nil && !errors.Is(err, ErrProcessNotFound) {
			return fmt.Errorf("stop %s process: %w", name, err)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s PID: %w", name, err)
		}
	}
	return nil
}

type pidRecord struct {
	PID      int    `json:"pid"`
	Expected string `json:"expected"`
}

func writePID(runtimeDir, name string, record pidRecord) error {
	if record.PID <= 0 || record.Expected == "" {
		return errors.New("invalid process PID record")
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("create PID directory: %w", err)
	}
	payload := []byte(fmt.Sprintf("{\"pid\":%d,\"expected\":%q}\n", record.PID, record.Expected))
	path := filepath.Join(runtimeDir, name+".pid")
	temporary, err := os.CreateTemp(runtimeDir, ".pid-*")
	if err != nil {
		return fmt.Errorf("create PID temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("install PID file: %w", err)
	}
	return nil
}

func readPID(path string) (pidRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pidRecord{}, err
	}
	var record pidRecord
	if _, err := fmt.Sscanf(string(data), `{"pid":%d,"expected":%q}`, &record.PID, &record.Expected); err != nil || record.PID <= 0 || record.Expected == "" {
		return pidRecord{}, errors.New("invalid PID file")
	}
	return record, nil
}

func removePID(runtimeDir, name string) error {
	err := os.Remove(filepath.Join(runtimeDir, name+".pid"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func commandHasBinary(command, expected string) bool {
	for _, field := range strings.Fields(command) {
		field = strings.Trim(field, "\"'")
		if filepath.Base(field) == expected {
			return true
		}
	}
	return false
}

func waitForHealth(ctx context.Context, address string) error {
	client := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/healthz", nil)
		if err == nil {
			response, requestErr := client.Do(request)
			if requestErr == nil {
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("local HTTP health check timed out")
		case <-ticker.C:
		}
	}
}

func shutdownServer(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}

func commandEnv(env []string) []string {
	if env == nil {
		return os.Environ()
	}
	return env
}

func withEnv(env []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		result = append(result, entry)
	}
	return append(result, prefix+value)
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
