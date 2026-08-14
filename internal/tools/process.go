package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultProcessYield        = 10 * time.Second
	defaultProcessOutputMax    = 1 << 20
	completedProcessSessionTTL = 5 * time.Minute
)

type ProcessStartInput struct {
	WorkspaceID      string
	WorkingDirectory string
	Command          string
	YieldTime        time.Duration
	MaxOutputBytes   int
}

type ProcessWriteInput struct {
	WorkspaceID    string
	SessionID      int
	Chars          string
	YieldTime      time.Duration
	MaxOutputBytes int
}

type ProcessSnapshot struct {
	SessionID       int    `json:"session_id,omitempty"`
	Output          string `json:"output"`
	Running         bool   `json:"running"`
	ExitCode        int    `json:"exit_code,omitempty"`
	Signal          string `json:"signal,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
	WallTimeMS      int64  `json:"wall_time_ms"`
}

type ProcessSessionManager struct {
	mu           sync.Mutex
	sessions     map[int]*processSession
	nextID       int
	closed       bool
	completedTTL time.Duration
}

type processSession struct {
	mu           sync.Mutex
	id           int
	workspaceID  string
	command      *exec.Cmd
	stdin        io.WriteCloser
	buffer       *headTailBuffer
	startedAt    time.Time
	done         chan struct{}
	outputDone   sync.WaitGroup
	cleanupTimer *time.Timer
	running      bool
	exitCode     int
	signal       string
}

func NewProcessSessionManager() *ProcessSessionManager {
	return &ProcessSessionManager{sessions: make(map[int]*processSession), nextID: 1, completedTTL: completedProcessSessionTTL}
}

func (m *ProcessSessionManager) Start(ctx context.Context, input ProcessStartInput) (ProcessSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ProcessSnapshot{}, err
	}
	if strings.TrimSpace(input.WorkspaceID) == "" {
		return ProcessSnapshot{}, errors.New("workspace ID is required")
	}
	if strings.TrimSpace(input.WorkingDirectory) == "" {
		return ProcessSnapshot{}, errors.New("working directory is required")
	}
	if strings.TrimSpace(input.Command) == "" {
		return ProcessSnapshot{}, errors.New("command is required")
	}
	maxOutput := normalizeProcessOutputLimit(input.MaxOutputBytes)
	command := exec.Command("/bin/sh", "-lc", input.Command)
	command.Dir = input.WorkingDirectory
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := command.StdinPipe()
	if err != nil {
		return ProcessSnapshot{}, fmt.Errorf("create process stdin: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return ProcessSnapshot{}, fmt.Errorf("create process stdout: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return ProcessSnapshot{}, fmt.Errorf("create process stderr: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return ProcessSnapshot{}, fmt.Errorf("start process: %w", err)
	}

	session := &processSession{
		workspaceID: input.WorkspaceID,
		command:     command,
		stdin:       stdin,
		buffer:      newHeadTailBuffer(maxOutput),
		startedAt:   time.Now(),
		done:        make(chan struct{}),
		running:     true,
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		terminateProcess(command, syscall.SIGTERM)
		return ProcessSnapshot{}, errors.New("process session manager is closed")
	}
	session.id = m.nextID
	m.nextID++
	m.sessions[session.id] = session
	m.mu.Unlock()

	session.outputDone.Add(2)
	go func() {
		defer session.outputDone.Done()
		copyProcessOutput(session.buffer, stdout)
	}()
	go func() {
		defer session.outputDone.Done()
		copyProcessOutput(session.buffer, stderr)
	}()
	go m.wait(session)

	return m.waitAndSnapshot(ctx, session, input.YieldTime, maxOutput), nil
}

func (m *ProcessSessionManager) Write(ctx context.Context, input ProcessWriteInput) (ProcessSnapshot, error) {
	if input.SessionID <= 0 {
		return ProcessSnapshot{}, errors.New("session ID must be positive")
	}
	m.mu.Lock()
	session, ok := m.sessions[input.SessionID]
	m.mu.Unlock()
	if !ok {
		return ProcessSnapshot{}, fmt.Errorf("unknown process session: %d", input.SessionID)
	}
	if session.workspaceID != input.WorkspaceID {
		return ProcessSnapshot{}, fmt.Errorf("process session %d does not belong to workspace %s", input.SessionID, input.WorkspaceID)
	}

	session.mu.Lock()
	running := session.running
	session.mu.Unlock()
	if running && strings.Contains(input.Chars, "\u0003") {
		if err := terminateProcess(session.command, syscall.SIGINT); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return ProcessSnapshot{}, fmt.Errorf("interrupt process: %w", err)
		}
		input.Chars = strings.ReplaceAll(input.Chars, "\u0003", "")
	}
	if input.Chars != "" {
		session.mu.Lock()
		running = session.running
		stdin := session.stdin
		session.mu.Unlock()
		if running {
			if _, err := io.WriteString(stdin, input.Chars); err != nil {
				return ProcessSnapshot{}, fmt.Errorf("write process stdin: %w", err)
			}
		}
	}

	return m.waitAndSnapshot(ctx, session, input.YieldTime, normalizeProcessOutputLimit(input.MaxOutputBytes)), nil
}

func (m *ProcessSessionManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	sessions := make([]*processSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = make(map[int]*processSession)
	m.mu.Unlock()

	for _, session := range sessions {
		session.mu.Lock()
		if session.cleanupTimer != nil {
			session.cleanupTimer.Stop()
			session.cleanupTimer = nil
		}
		session.mu.Unlock()
		if err := terminateProcess(session.command, syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			_ = session.command.Process.Kill()
		}
	}
}

func (m *ProcessSessionManager) wait(session *processSession) {
	err := session.command.Wait()
	session.outputDone.Wait()
	session.mu.Lock()
	session.running = false
	if exitError, ok := err.(*exec.ExitError); ok {
		session.exitCode = exitError.ExitCode()
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			session.signal = status.Signal().String()
		}
	} else if err == nil {
		session.exitCode = 0
	} else {
		session.exitCode = -1
	}
	close(session.done)
	session.mu.Unlock()
	m.scheduleCleanup(session)
}

func (m *ProcessSessionManager) scheduleCleanup(session *processSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.sessions[session.id] != session {
		return
	}
	ttl := m.completedTTL
	if ttl <= 0 {
		ttl = completedProcessSessionTTL
	}
	session.mu.Lock()
	session.cleanupTimer = time.AfterFunc(ttl, func() {
		m.mu.Lock()
		if current, ok := m.sessions[session.id]; ok && current == session {
			delete(m.sessions, session.id)
		}
		m.mu.Unlock()
	})
	session.mu.Unlock()
}

func (m *ProcessSessionManager) removeSession(session *processSession) {
	m.mu.Lock()
	if current, ok := m.sessions[session.id]; ok && current == session {
		delete(m.sessions, session.id)
		session.mu.Lock()
		if session.cleanupTimer != nil {
			session.cleanupTimer.Stop()
			session.cleanupTimer = nil
		}
		session.mu.Unlock()
	}
	m.mu.Unlock()
}

func (m *ProcessSessionManager) waitAndSnapshot(ctx context.Context, session *processSession, requested time.Duration, maxOutput int) ProcessSnapshot {
	yield := requested
	if yield <= 0 {
		yield = defaultProcessYield
	}
	timer := time.NewTimer(yield)
	defer timer.Stop()
	select {
	case <-session.done:
	case <-timer.C:
	case <-ctx.Done():
	}

	snapshot := session.snapshot(maxOutput)
	if !snapshot.Running {
		m.removeSession(session)
	}
	return snapshot
}

func (s *processSession) snapshot(maxOutput int) ProcessSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	output, truncated := s.buffer.drain(normalizeProcessOutputLimit(maxOutput))
	snapshot := ProcessSnapshot{
		Output:          output,
		Running:         s.running,
		ExitCode:        s.exitCode,
		Signal:          s.signal,
		OutputTruncated: truncated,
		WallTimeMS:      time.Since(s.startedAt).Milliseconds(),
	}
	if s.running {
		snapshot.SessionID = s.id
	}
	return snapshot
}

func copyProcessOutput(buffer *headTailBuffer, reader io.Reader) {
	_, _ = io.Copy(buffer, reader)
}

func terminateProcess(command *exec.Cmd, signal syscall.Signal) error {
	if command == nil || command.Process == nil {
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-command.Process.Pid, signal); err == nil {
		return nil
	} else if !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return command.Process.Signal(signal)
}

func normalizeProcessOutputLimit(value int) int {
	if value <= 0 {
		return defaultProcessOutputMax
	}
	if value > 10*defaultProcessOutputMax {
		return 10 * defaultProcessOutputMax
	}
	return value
}

type headTailBuffer struct {
	mu        sync.Mutex
	limit     int
	head      []byte
	tail      []byte
	total     int
	truncated bool
}

func newHeadTailBuffer(limit int) *headTailBuffer {
	return &headTailBuffer{limit: limit}
}

func (b *headTailBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(value)
	b.total += len(value)
	if b.total <= b.limit {
		b.head = append(b.head, value...)
		return written, nil
	}
	b.truncated = true
	headLimit := b.limit / 2
	tailLimit := b.limit - headLimit
	if len(b.head) > headLimit {
		b.head = b.head[:headLimit]
	}
	remainingHead := headLimit - len(b.head)
	if remainingHead > 0 {
		consumed := minInt(remainingHead, len(value))
		b.head = append(b.head, value[:consumed]...)
		value = value[consumed:]
	}
	if len(value) > 0 {
		b.tail = append(b.tail, value...)
		if len(b.tail) > tailLimit {
			b.tail = b.tail[len(b.tail)-tailLimit:]
		}
	}
	return written, nil
}

func (b *headTailBuffer) drain(limit int) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	value := append(append([]byte(nil), b.head...), b.tail...)
	truncated := b.truncated
	b.head = nil
	b.tail = nil
	b.total = 0
	b.truncated = false
	if len(value) <= limit {
		return string(value), truncated
	}
	headLimit := limit / 2
	tailLimit := limit - headLimit
	return string(value[:headLimit]) + "\n... output truncated ...\n" + string(value[len(value)-tailLimit:]), true
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
