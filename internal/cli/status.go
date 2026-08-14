package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/baleen37/mcp-bridge/internal/config"
	"github.com/baleen37/mcp-bridge/internal/lifecycle"
)

type statusEnvironment struct {
	Client         *http.Client
	HomeDir        string
	Stat           func(string) (os.FileInfo, error)
	InspectProcess func(context.Context, int) (string, error)
	RunCommand     func(context.Context, string, []string, []string) ([]byte, error)
}

type statusPIDRecord struct {
	PID      int    `json:"pid"`
	Expected string `json:"expected"`
}

func runStatus(ctx context.Context, cfg config.Config, out io.Writer, environment statusEnvironment) error {
	if environment.Client == nil {
		environment.Client = &http.Client{Timeout: 2 * time.Second}
	}
	if environment.Stat == nil {
		environment.Stat = os.Stat
	}
	if environment.InspectProcess == nil {
		inspector := lifecycle.OSProcessInspector{}
		environment.InspectProcess = inspector.Command
	}
	if environment.RunCommand == nil {
		runner := lifecycle.ExecCommandRunner{}
		environment.RunCommand = runner.Run
	}

	fmt.Fprintf(out, "config=%s\nstate=%s\nruntime=%s\nmcp=%s\nlaunch-agent=%s\n", cfg.ConfigPath, cfg.StateDBPath, cfg.RuntimeDir, cfg.MCPURL(), lifecycle.LaunchAgentLabel)
	failed := false
	check := func(name string, ok bool) {
		result := "ok"
		if !ok {
			result = "fail"
			failed = true
		}
		fmt.Fprintf(out, "%s=%s\n", name, result)
	}
	check("config-file", fileExists(environment.Stat, cfg.ConfigPath))
	check("state-file", fileExists(environment.Stat, cfg.StateDBPath))
	plist := filepath.Join(environment.HomeDir, "Library", "LaunchAgents", lifecycle.LaunchAgentLabel+".plist")
	check("launch-agent-plist", environment.HomeDir != "" && fileExists(environment.Stat, plist))
	_, launchErr := environment.RunCommand(ctx, "launchctl", []string{"print", fmt.Sprintf("gui/%d/%s", os.Getuid(), lifecycle.LaunchAgentLabel)}, nil)
	check("launch-agent-loaded", launchErr == nil)

	for _, name := range []string{"mcp-bridge", "cloudflared"} {
		record, err := readStatusPID(filepath.Join(cfg.RuntimeDir, name+".pid"))
		if err != nil {
			value := "none"
			if !errors.Is(err, os.ErrNotExist) {
				value = "invalid"
			}
			fmt.Fprintf(out, "pid-%s=%s\n", name, value)
			fmt.Fprintf(out, "process-%s=fail reason=%s\n", name, statusPIDError(err))
			failed = true
			continue
		}
		fmt.Fprintf(out, "pid-%s=%d\n", name, record.PID)
		command, inspectErr := environment.InspectProcess(ctx, record.PID)
		if inspectErr != nil {
			fmt.Fprintf(out, "process-%s=fail pid=%d reason=process-not-found\n", name, record.PID)
			failed = true
			continue
		}
		if !commandHasExpectedBinary(command, record.Expected) {
			fmt.Fprintf(out, "process-%s=fail pid=%d reason=ownership-mismatch\n", name, record.PID)
			failed = true
			continue
		}
		fmt.Fprintf(out, "process-%s=ok pid=%d\n", name, record.PID)
	}

	for _, origin := range []struct {
		name string
		url  string
	}{
		{name: "local", url: "http://" + cfg.Address()},
		{name: "public", url: strings.TrimRight(cfg.PublicBaseURL, "/")},
	} {
		for _, endpoint := range []struct {
			path     string
			expected int
		}{
			{path: "/healthz", expected: http.StatusOK},
			{path: "/mcp", expected: http.StatusUnauthorized},
		} {
			code, reason := statusHTTP(ctx, environment.Client, origin.url+endpoint.path, endpoint.expected)
			if reason == "" {
				fmt.Fprintf(out, "%s %s %03d status=ok\n", origin.name, endpoint.path, code)
			} else {
				fmt.Fprintf(out, "%s %s %03d status=fail reason=%s\n", origin.name, endpoint.path, code, reason)
				failed = true
			}
		}
	}
	if failed {
		fmt.Fprintln(out, "status=fail")
		return errors.New("status found problems")
	}
	fmt.Fprintln(out, "status=ok")
	return nil
}

func printStatusOrigins(client *http.Client, localOrigin, publicOrigin string, out io.Writer) {
	printStatusOrigin(client, "local", localOrigin, out)
	printStatusOrigin(client, "public", publicOrigin, out)
}

func printStatusOrigin(client *http.Client, name, origin string, out io.Writer) {
	for _, path := range []string{"/healthz", "/mcp"} {
		code, _ := statusHTTP(context.Background(), client, strings.TrimRight(origin, "/")+path, 0)
		fmt.Fprintf(out, "%s %s %03d\n", name, path, code)
	}
}

func fileExists(stat func(string) (os.FileInfo, error), path string) bool {
	info, err := stat(path)
	return err == nil && info.Mode().IsRegular()
}

func readStatusPID(path string) (statusPIDRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return statusPIDRecord{}, err
	}
	var record statusPIDRecord
	if err := json.Unmarshal(data, &record); err != nil || record.PID <= 0 || record.Expected == "" {
		return statusPIDRecord{}, errors.New("invalid PID file")
	}
	return record, nil
}

func statusPIDError(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "missing"
	}
	return "invalid"
}

func commandHasExpectedBinary(command, expected string) bool {
	for _, field := range strings.Fields(command) {
		field = strings.Trim(field, "\"'")
		if filepath.Base(field) == expected {
			return true
		}
	}
	return false
}

func statusHTTP(ctx context.Context, client *http.Client, url string, expected int) (int, string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "network-error"
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, classifyHTTPError(err)
	}
	response.Body.Close()
	if response.StatusCode != expected {
		return response.StatusCode, "unexpected-status"
	}
	return response.StatusCode, ""
}

func classifyHTTPError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection-refused"
	}
	return "network-error"
}
