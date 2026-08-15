package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxCommandOutput = 1 << 20

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
	// stdout and stderr share one budget so the buffered bytes never exceed the
	// caller's limit, instead of allowing maxOutputBytes on each stream.
	budget := &outputBudget{remaining: maxOutputBytes}
	stdoutWriter := &limitedWriter{buffer: &stdout, budget: budget}
	stderrWriter := &limitedWriter{buffer: &stderr, budget: budget}
	process.Stdout = stdoutWriter
	process.Stderr = stderrWriter
	err := process.Run()
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		} else if ctx.Err() != nil {
			return stdout.Bytes(), stderr.Bytes(), -1, budget.wasTruncated(), fmt.Errorf("command timed out after %s: %w", timeout, context.DeadlineExceeded)
		} else {
			exitCode = -1
		}
	}
	if ctx.Err() != nil {
		return stdout.Bytes(), stderr.Bytes(), -1, budget.wasTruncated(), fmt.Errorf("command timed out after %s: %w", timeout, context.DeadlineExceeded)
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, budget.wasTruncated(), err
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
		maxOutputBytes = min(input.MaxOutputTokens*4, maxCommandOutput)
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
	}
	// A runner may return more than the limit: unlimited runners ignore it, and even
	// a limited one adds the stdout/stderr separator on top of its budget.
	text := commandText(stdout, stderr)
	if len(text) > maxOutputBytes {
		text = truncateUTF8(text, maxOutputBytes)
		truncated = true
	}
	return ExecResult{Text: text, ExitCode: exitCode, Truncated: truncated, TimedOut: errors.Is(runErr, context.DeadlineExceeded)}, nil
}

// truncateUTF8 cuts text to at most limit bytes without splitting a multi-byte rune.
func truncateUTF8(text string, limit int) string {
	text = text[:limit]
	for len(text) > 0 && !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text
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

// outputBudget is the byte allowance shared by a command's stdout and stderr
// writers. exec copies the two streams on separate goroutines, so the mutex
// guards the shared counter.
type outputBudget struct {
	mutex     sync.Mutex
	remaining int
	truncated bool
}

// take reserves up to length bytes and reports how many the caller may write.
func (b *outputBudget) take(length int) int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if length > b.remaining {
		b.truncated = true
		length = b.remaining
	}
	b.remaining -= length
	return length
}

func (b *outputBudget) wasTruncated() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.truncated
}

type limitedWriter struct {
	buffer *bytes.Buffer
	budget *outputBudget
}

func (w *limitedWriter) Write(value []byte) (int, error) {
	originalLength := len(value)
	allowed := w.budget.take(originalLength)
	if allowed > 0 {
		// A partial write may land mid-rune; drop the trailing fragment rather than
		// leaving invalid UTF-8 in the buffer.
		if allowed < originalLength {
			allowed = len(truncateUTF8(string(value[:allowed]), allowed))
		}
		_, _ = w.buffer.Write(value[:allowed])
	}
	return originalLength, nil
}
