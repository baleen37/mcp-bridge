package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const maxCommandOutput = 1 << 20

type BashInput struct {
	WorkspaceID      string
	Command          string
	WorkingDirectory string
	Timeout          int
	Async            bool
	YieldTimeMS      int
	MaxOutputTokens  int
}

type ExecInput struct {
	WorkspaceID     string
	Command         string
	WorkingDir      string
	TimeoutMS       int
	MaxOutputTokens int
}

type ExecResult struct {
	Text      string
	ExitCode  int
	Truncated bool
	TimedOut  bool
}

type WriteStdinInput struct {
	WorkspaceID     string
	SessionID       int
	Chars           string
	YieldTimeMS     int
	MaxOutputTokens int
}

type ExecCommandInput struct {
	WorkspaceID     string
	Command         string
	Workdir         string
	TimeoutMS       int
	MaxOutputTokens int
}

type CommandRunner interface {
	Run(ctx context.Context, dir, command string, timeout time.Duration) (stdout, stderr []byte, exitCode int, err error)
}

type LimitedCommandRunner interface {
	RunLimited(ctx context.Context, dir, command string, timeout time.Duration, maxOutputBytes int) (stdout, stderr []byte, exitCode int, truncated bool, err error)
}

type OSCommandRunner struct{}

func (OSCommandRunner) Run(ctx context.Context, dir, command string, timeout time.Duration) ([]byte, []byte, int, error) {
	stdout, stderr, exitCode, _, err := OSCommandRunner{}.RunLimited(ctx, dir, command, timeout, maxCommandOutput)
	return stdout, stderr, exitCode, err
}

func (OSCommandRunner) RunLimited(ctx context.Context, dir, command string, timeout time.Duration, maxOutputBytes int) ([]byte, []byte, int, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	process := exec.CommandContext(ctx, "/bin/sh", "-lc", command)
	process.Dir = dir
	// Killing the shell does not close the output pipes when it left grandchildren
	// holding them open, so Run would block until those exit on their own. WaitDelay
	// bounds that wait and keeps the timeout honest.
	process.WaitDelay = 100 * time.Millisecond
	var stdout, stderr bytes.Buffer
	stdoutWriter := &limitedWriter{buffer: &stdout, limit: maxOutputBytes}
	stderrWriter := &limitedWriter{buffer: &stderr, limit: maxOutputBytes}
	process.Stdout = stdoutWriter
	process.Stderr = stderrWriter
	err := process.Run()
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		} else if ctx.Err() != nil {
			return stdout.Bytes(), stderr.Bytes(), -1, stdoutWriter.truncated || stderrWriter.truncated, fmt.Errorf("command timed out after %s: %w", timeout, context.DeadlineExceeded)
		} else {
			exitCode = -1
		}
	}
	if ctx.Err() != nil {
		return stdout.Bytes(), stderr.Bytes(), -1, stdoutWriter.truncated || stderrWriter.truncated, fmt.Errorf("command timed out after %s: %w", timeout, context.DeadlineExceeded)
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, stdoutWriter.truncated || stderrWriter.truncated, err
}

func (s *Service) Exec(ctx context.Context, input ExecInput) (ExecResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ExecResult{}, err
	}
	if strings.TrimSpace(input.Command) == "" {
		return ExecResult{}, errors.New("command is required")
	}
	workingDirectory := record.Root
	if input.WorkingDir != "" {
		workingDirectory, err = s.Workspaces.Resolve(record, input.WorkingDir, false)
		if err != nil {
			return ExecResult{}, err
		}
	}
	timeout := input.TimeoutMS
	if timeout == 0 {
		timeout = 30_000
	}
	if timeout < 1 || timeout > 300_000 {
		return ExecResult{}, errors.New("timeout_ms must be between 1 and 300000 milliseconds")
	}
	maxOutputBytes := maxCommandOutput
	if input.MaxOutputTokens > 0 {
		maxOutputBytes = input.MaxOutputTokens * 4
		if maxOutputBytes > maxCommandOutput {
			maxOutputBytes = maxCommandOutput
		}
	}
	if s.Command == nil {
		s.Command = OSCommandRunner{}
	}
	var stdout, stderr []byte
	var exitCode int
	truncated := false
	var runErr error
	if runner, ok := s.Command.(LimitedCommandRunner); ok {
		stdout, stderr, exitCode, truncated, runErr = runner.RunLimited(ctx, workingDirectory, input.Command, time.Duration(timeout)*time.Millisecond, maxOutputBytes)
	} else {
		stdout, stderr, exitCode, runErr = s.Command.Run(ctx, workingDirectory, input.Command, time.Duration(timeout)*time.Millisecond)
		text := commandText(stdout, stderr)
		if len(text) > maxOutputBytes {
			text = text[:maxOutputBytes]
			truncated = true
		}
		return ExecResult{Text: text, ExitCode: exitCode, Truncated: truncated, TimedOut: errors.Is(runErr, context.DeadlineExceeded)}, nil
	}
	text := commandText(stdout, stderr)
	if len(text) > maxOutputBytes {
		text = text[:maxOutputBytes]
		truncated = true
	}
	return ExecResult{Text: text, ExitCode: exitCode, Truncated: truncated, TimedOut: errors.Is(runErr, context.DeadlineExceeded)}, nil
}

func commandText(stdout, stderr []byte) string {
	text := string(stdout)
	if len(stderr) > 0 {
		if text != "" {
			text += "\n"
		}
		text += string(stderr)
	}
	return text
}

func (s *Service) Bash(ctx context.Context, input BashInput) (ToolResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	workingDirectory := record.Root
	if input.WorkingDirectory != "" {
		workingDirectory, err = s.Workspaces.Resolve(record, input.WorkingDirectory, false)
		if err != nil {
			return ToolResult{}, err
		}
	}
	if strings.TrimSpace(input.Command) == "" {
		return ToolResult{}, errors.New("command is required")
	}
	if input.Async {
		snapshot, startErr := s.processSessions().Start(ctx, ProcessStartInput{
			WorkspaceID:      input.WorkspaceID,
			WorkingDirectory: workingDirectory,
			Command:          input.Command,
			YieldTime:        processYield(input.YieldTimeMS),
			MaxOutputBytes:   processOutputBytes(input.MaxOutputTokens),
		})
		result := processToolResult(snapshot)
		if startErr != nil {
			return result, startErr
		}
		if !snapshot.Running && snapshot.ExitCode != 0 {
			return result, fmt.Errorf("command exited with code %d", snapshot.ExitCode)
		}
		return result, nil
	}
	timeout := input.Timeout
	if timeout == 0 {
		timeout = 30
	}
	if timeout < 1 || timeout > 300 {
		return ToolResult{}, errors.New("timeout must be between 1 and 300 seconds")
	}
	if s.Command == nil {
		s.Command = OSCommandRunner{}
	}
	stdout, stderr, exitCode, runErr := s.Command.Run(ctx, workingDirectory, input.Command, time.Duration(timeout)*time.Second)
	text := string(stdout)
	if len(stderr) > 0 {
		if text != "" {
			text += "\n"
		}
		text += string(stderr)
	}
	result := ToolResult{Text: text, ExitCode: exitCode, Truncated: len(stdout) >= maxCommandOutput || len(stderr) >= maxCommandOutput}
	if runErr != nil {
		return result, runErr
	}
	if exitCode != 0 {
		return result, fmt.Errorf("command exited with code %d", exitCode)
	}
	return result, nil
}

func (s *Service) ExecCommand(ctx context.Context, input ExecCommandInput) (ToolResult, error) {
	if input.TimeoutMS < 0 || input.TimeoutMS > 300000 {
		return ToolResult{}, errors.New("timeout_ms must be between 0 and 300000")
	}
	timeout := input.TimeoutMS / 1000
	if input.TimeoutMS > 0 && input.TimeoutMS%1000 != 0 {
		timeout++
	}
	if timeout == 0 {
		timeout = 30
	}
	result, err := s.Bash(ctx, BashInput{WorkspaceID: input.WorkspaceID, Command: input.Command, WorkingDirectory: input.Workdir, Timeout: timeout, MaxOutputTokens: input.MaxOutputTokens})
	if err != nil && result.ExitCode == 0 {
		return result, err
	}
	return result, nil
}

func (s *Service) WriteStdin(ctx context.Context, input WriteStdinInput) (ToolResult, error) {
	if _, err := s.workspace(input.WorkspaceID); err != nil {
		return ToolResult{}, err
	}
	snapshot, err := s.processSessions().Write(ctx, ProcessWriteInput{
		WorkspaceID:    input.WorkspaceID,
		SessionID:      input.SessionID,
		Chars:          input.Chars,
		YieldTime:      processYield(input.YieldTimeMS),
		MaxOutputBytes: processOutputBytes(input.MaxOutputTokens),
	})
	result := processToolResult(snapshot)
	if err != nil {
		return result, err
	}
	if !snapshot.Running && snapshot.ExitCode != 0 {
		return result, fmt.Errorf("command exited with code %d", snapshot.ExitCode)
	}
	return result, nil
}

func processToolResult(snapshot ProcessSnapshot) ToolResult {
	return ToolResult{
		Text:       snapshot.Output,
		ExitCode:   snapshot.ExitCode,
		Truncated:  snapshot.OutputTruncated,
		SessionID:  snapshot.SessionID,
		Running:    snapshot.Running,
		Signal:     snapshot.Signal,
		WallTimeMS: snapshot.WallTimeMS,
	}
}

func processYield(value int) time.Duration {
	if value <= 0 {
		return defaultProcessYield
	}
	return time.Duration(value) * time.Millisecond
}

func processOutputBytes(tokens int) int {
	if tokens <= 0 {
		return 0
	}
	return tokens * 4
}

type limitedWriter struct {
	buffer    *bytes.Buffer
	limit     int
	truncated bool
}

func (w *limitedWriter) Write(value []byte) (int, error) {
	originalLength := len(value)
	remaining := w.limit - w.buffer.Len()
	if remaining <= 0 {
		w.truncated = true
		return originalLength, nil
	}
	if len(value) > remaining {
		w.truncated = true
		value = value[:remaining]
	}
	_, _ = w.buffer.Write(value)
	return originalLength, nil
}
