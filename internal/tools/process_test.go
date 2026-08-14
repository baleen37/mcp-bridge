package tools

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestProcessSessionShortCommandCompletes(t *testing.T) {
	manager := NewProcessSessionManager()
	t.Cleanup(manager.Close)

	snapshot, err := manager.Start(context.Background(), ProcessStartInput{
		WorkspaceID:      "ws-short",
		WorkingDirectory: t.TempDir(),
		Command:          "printf 'done'",
		YieldTime:        time.Second,
		MaxOutputBytes:   1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Running {
		t.Fatal("short command is still running")
	}
	if snapshot.SessionID != 0 {
		t.Fatalf("completed command returned session ID %d", snapshot.SessionID)
	}
	if snapshot.Output != "done" {
		t.Fatalf("output = %q, want done", snapshot.Output)
	}
	if snapshot.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", snapshot.ExitCode)
	}
}

func TestProcessSessionPollsRunningCommand(t *testing.T) {
	manager := NewProcessSessionManager()
	t.Cleanup(manager.Close)

	snapshot, err := manager.Start(context.Background(), ProcessStartInput{
		WorkspaceID:      "ws-running",
		WorkingDirectory: t.TempDir(),
		Command:          "sleep 0.2; printf 'done'",
		YieldTime:        10 * time.Millisecond,
		MaxOutputBytes:   1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Running || snapshot.SessionID == 0 {
		t.Fatalf("initial snapshot = %#v, want running session", snapshot)
	}

	snapshot, err = manager.Write(context.Background(), ProcessWriteInput{
		WorkspaceID:    "ws-running",
		SessionID:      snapshot.SessionID,
		YieldTime:      time.Second,
		MaxOutputBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Running || snapshot.Output != "done" || snapshot.ExitCode != 0 {
		t.Fatalf("completed snapshot = %#v", snapshot)
	}
}

func TestProcessSessionWritesStdin(t *testing.T) {
	manager := NewProcessSessionManager()
	t.Cleanup(manager.Close)

	snapshot, err := manager.Start(context.Background(), ProcessStartInput{
		WorkspaceID:      "ws-stdin",
		WorkingDirectory: t.TempDir(),
		Command:          "IFS= read line; printf 'got:%s' \"$line\"",
		YieldTime:        10 * time.Millisecond,
		MaxOutputBytes:   1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Running {
		t.Fatalf("initial snapshot = %#v, want running session", snapshot)
	}

	snapshot, err = manager.Write(context.Background(), ProcessWriteInput{
		WorkspaceID:    "ws-stdin",
		SessionID:      snapshot.SessionID,
		Chars:          "hello\n",
		YieldTime:      time.Second,
		MaxOutputBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Running || snapshot.Output != "got:hello" {
		t.Fatalf("stdin snapshot = %#v", snapshot)
	}
}

func TestProcessSessionCtrlCStopsCommand(t *testing.T) {
	manager := NewProcessSessionManager()
	t.Cleanup(manager.Close)

	snapshot, err := manager.Start(context.Background(), ProcessStartInput{
		WorkspaceID:      "ws-interrupt",
		WorkingDirectory: t.TempDir(),
		Command:          "sleep 30",
		YieldTime:        10 * time.Millisecond,
		MaxOutputBytes:   1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Running {
		t.Fatalf("initial snapshot = %#v, want running session", snapshot)
	}

	snapshot, err = manager.Write(context.Background(), ProcessWriteInput{
		WorkspaceID:    "ws-interrupt",
		SessionID:      snapshot.SessionID,
		Chars:          "\u0003",
		YieldTime:      time.Second,
		MaxOutputBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Running {
		t.Fatalf("snapshot = %#v, want stopped process", snapshot)
	}
}

func TestProcessSessionRejectsOtherWorkspace(t *testing.T) {
	manager := NewProcessSessionManager()
	t.Cleanup(manager.Close)

	snapshot, err := manager.Start(context.Background(), ProcessStartInput{
		WorkspaceID:      "ws-owner",
		WorkingDirectory: t.TempDir(),
		Command:          "sleep 1",
		YieldTime:        10 * time.Millisecond,
		MaxOutputBytes:   1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Write(context.Background(), ProcessWriteInput{
		WorkspaceID: "ws-other",
		SessionID:   snapshot.SessionID,
	})
	if err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("error = %v, want workspace ownership error", err)
	}
}

func TestProcessSessionReportsOutputTruncation(t *testing.T) {
	manager := NewProcessSessionManager()
	t.Cleanup(manager.Close)

	snapshot, err := manager.Start(context.Background(), ProcessStartInput{
		WorkspaceID:      "ws-output",
		WorkingDirectory: t.TempDir(),
		Command:          "printf '0123456789'",
		YieldTime:        time.Second,
		MaxOutputBytes:   6,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.OutputTruncated {
		t.Fatalf("snapshot = %#v, want truncated output", snapshot)
	}
	if len(snapshot.Output) == 0 || len(snapshot.Output) > 6 {
		t.Fatalf("output length = %d, want 1..6", len(snapshot.Output))
	}
}

func TestProcessSessionCleansUpUnpolledCompletedProcess(t *testing.T) {
	manager := NewProcessSessionManager()
	manager.completedTTL = 20 * time.Millisecond
	t.Cleanup(manager.Close)

	snapshot, err := manager.Start(context.Background(), ProcessStartInput{
		WorkspaceID: "ws-cleanup", WorkingDirectory: t.TempDir(), Command: "sleep 0.05; printf done",
		YieldTime: 10 * time.Millisecond, MaxOutputBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Running {
		t.Fatalf("initial snapshot = %#v, want running", snapshot)
	}
	// Wait for the process to finish and the TTL to elapse before asserting. The
	// command sleeps 50ms and the TTL is 20ms; a generous margin keeps this from
	// flaking on a loaded machine without polling, which would itself evict the
	// session and make the assertion vacuous.
	waitForSessionCleanup(t, manager, snapshot.SessionID)

	_, err = manager.Write(context.Background(), ProcessWriteInput{WorkspaceID: "ws-cleanup", SessionID: snapshot.SessionID})
	if err == nil || !strings.Contains(err.Error(), "unknown process session") {
		t.Fatalf("write after cleanup error = %v", err)
	}
}

func TestProcessSessionPollingCompletedProcessCancelsCleanup(t *testing.T) {
	manager := NewProcessSessionManager()
	manager.completedTTL = time.Hour
	t.Cleanup(manager.Close)

	snapshot, err := manager.Start(context.Background(), ProcessStartInput{
		WorkspaceID: "ws-polled", WorkingDirectory: t.TempDir(), Command: "sleep 0.05; printf done",
		YieldTime: 10 * time.Millisecond, MaxOutputBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = manager.Write(context.Background(), ProcessWriteInput{WorkspaceID: "ws-polled", SessionID: snapshot.SessionID, YieldTime: time.Second})
	if err != nil || snapshot.Running || snapshot.Output != "done" {
		t.Fatalf("completed poll = %#v, err=%v", snapshot, err)
	}
	manager.mu.Lock()
	remaining := len(manager.sessions)
	manager.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("sessions after completed poll = %d, want 0", remaining)
	}
}

func TestHeadTailBufferPreservesLargeWriteTail(t *testing.T) {
	buffer := newHeadTailBuffer(6)
	written, err := buffer.Write([]byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if written != 10 {
		t.Fatalf("written = %d, want 10", written)
	}
	output, truncated := buffer.drain(6)
	if !truncated || !strings.Contains(output, "789") {
		t.Fatalf("output = %q, truncated = %v, want tail preserved", output, truncated)
	}
}

// waitForSessionCleanup blocks until the manager has evicted the session, reading
// the session map directly. Polling through Write or Poll would remove a finished
// session itself and make the caller's assertion vacuous.
func waitForSessionCleanup(t *testing.T, manager *ProcessSessionManager, sessionID int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		manager.mu.Lock()
		_, present := manager.sessions[sessionID]
		manager.mu.Unlock()
		if !present {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %d was not cleaned up within 10s", sessionID)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
