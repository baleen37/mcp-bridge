package lifecycle

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/baleen37/mcp-bridge/internal/config"
)

const launchAgentLabel = "io.github.baleen37.mcp-bridge"

const LaunchAgentLabel = launchAgentLabel

var (
	userHomeDir   = os.UserHomeDir
	currentUserID = os.Getuid
)

func RenderLaunchAgent(binary string, cfg config.Config, _ int) ([]byte, error) {
	home, err := userHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve launch agent home: %w", err)
	}
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return nil, fmt.Errorf("resolve bridge binary: %w", err)
	}
	workingDirectory := home
	pathValue := os.Getenv("PATH")
	if pathValue == "" {
		pathValue = "/usr/bin:/bin:/usr/sbin:/sbin"
	}

	var document strings.Builder
	document.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	document.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	document.WriteString("<plist version=\"1.0\"><dict>")
	writeKeyString(&document, "Label", launchAgentLabel)
	document.WriteString("<key>ProgramArguments</key><array>")
	writeXMLString(&document, absoluteBinary)
	writeXMLString(&document, "start")
	document.WriteString("</array>")
	writeKeyString(&document, "WorkingDirectory", workingDirectory)
	document.WriteString("<key>EnvironmentVariables</key><dict>")
	for _, variable := range []struct{ key, value string }{
		{key: "HOME", value: home},
		{key: "PATH", value: pathValue},
		{key: "MCP_BRIDGE_TUNNEL_TOKEN_FILE", value: cfg.TunnelTokenFile},
		{key: "MCP_BRIDGE_RUNTIME_DIR", value: cfg.RuntimeDir},
		{key: "MCP_BRIDGE_WORKTREE_ROOT", value: cfg.WorktreeRoot},
	} {
		writeKeyString(&document, variable.key, variable.value)
	}
	document.WriteString("</dict>")
	document.WriteString("<key>RunAtLoad</key><true/>")
	document.WriteString("<key>KeepAlive</key><true/>")
	document.WriteString("<key>ThrottleInterval</key><integer>30</integer>")
	if cfg.RuntimeDir != "" {
		writeKeyString(&document, "StandardOutPath", filepath.Join(cfg.RuntimeDir, "mcp-bridge.stdout.log"))
		writeKeyString(&document, "StandardErrorPath", filepath.Join(cfg.RuntimeDir, "mcp-bridge.stderr.log"))
	}
	document.WriteString("</dict></plist>\n")
	return []byte(document.String()), nil
}

func InstallLaunchAgent(ctx context.Context, binary string, cfg config.Config, runner CommandRunner) error {
	home, err := userHomeDir()
	if err != nil {
		return fmt.Errorf("resolve launch agent home: %w", err)
	}
	plist, err := RenderLaunchAgent(binary, cfg, currentUserID())
	if err != nil {
		return err
	}
	path := filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}
	if err := writePrivateFile(path, plist); err != nil {
		return fmt.Errorf("write launch agent: %w", err)
	}
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	// bootstrap fails when the same LaunchAgent is already registered. Treat
	// bootout as best-effort so the first setup also works when no service exists.
	_, _ = runner.Run(ctx, "launchctl", []string{"bootout", "gui/" + strconv.Itoa(currentUserID()) + "/" + launchAgentLabel}, nil)
	if _, err := runner.Run(ctx, "launchctl", []string{"bootstrap", "gui/" + strconv.Itoa(currentUserID()), path}, nil); err != nil {
		return errors.New("launchctl bootstrap failed")
	}
	return nil
}

func UninstallLaunchAgent(ctx context.Context, cfg config.Config, runner CommandRunner) error {
	home, err := userHomeDir()
	if err != nil {
		return fmt.Errorf("resolve launch agent home: %w", err)
	}
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	if _, err := runner.Run(ctx, "launchctl", []string{"bootout", "gui/" + strconv.Itoa(currentUserID()) + "/" + launchAgentLabel}, nil); err != nil {
		return errors.New("launchctl bootout failed")
	}
	path := filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove launch agent: %w", err)
	}
	_ = cfg
	return nil
}

func writeKeyString(document *strings.Builder, key, value string) {
	document.WriteString("<key>")
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(key))
	document.WriteString(escaped.String())
	document.WriteString("</key>")
	writeXMLString(document, value)
}

func writeXMLString(document *strings.Builder, value string) {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(value))
	document.WriteString("<string>")
	document.WriteString(escaped.String())
	document.WriteString("</string>")
}

func writePrivateFile(path string, content []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".launch-agent-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}
