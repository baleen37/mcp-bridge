package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baleen37/mcp-bridge/internal/store"
	"github.com/baleen37/mcp-bridge/internal/workspace"
)

func testService(t *testing.T) (*Service, workspace.Record) {
	t.Helper()
	root := t.TempDir()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	registry := &workspace.Registry{AllowedRoots: []string{root}, WorktreeRoot: filepath.Join(t.TempDir(), "worktrees"), Store: db, Git: workspace.ExecGitRunner{}}
	record, err := registry.Open(context.Background(), root, "checkout", "")
	if err != nil {
		t.Fatal(err)
	}
	return &Service{Workspaces: registry, Command: OSCommandRunner{}}, record
}

func TestReadWriteEdit(t *testing.T) {
	service, workspaceRecord := testService(t)
	if err := os.WriteFile(filepath.Join(workspaceRecord.Root, "notes.txt"), []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := service.Read(context.Background(), ReadInput{WorkspaceID: workspaceRecord.ID, Path: "notes.txt", Offset: 2, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if read.Text != "two\n" {
		t.Fatalf("read text = %q", read.Text)
	}
	if _, err := service.Write(context.Background(), WriteInput{WorkspaceID: workspaceRecord.ID, Path: "nested/new.txt", Content: "new"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Edit(context.Background(), EditInput{WorkspaceID: workspaceRecord.ID, Path: "notes.txt", Edits: []Edit{{OldText: "two", NewText: "TWO"}}}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(workspaceRecord.Root, "notes.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "one\nTWO\nthree\n" {
		t.Fatalf("edited content = %q", content)
	}
	before := string(content)
	if _, err := service.Edit(context.Background(), EditInput{WorkspaceID: workspaceRecord.ID, Path: "notes.txt", Edits: []Edit{{OldText: "one", NewText: "x"}, {OldText: "one", NewText: "y"}}}); err == nil {
		t.Fatal("duplicate edit unexpectedly succeeded")
	}
	content, err = os.ReadFile(filepath.Join(workspaceRecord.Root, "notes.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != before {
		t.Fatal("failed edit changed file")
	}
	if _, err := service.Read(context.Background(), ReadInput{WorkspaceID: workspaceRecord.ID, Path: "../notes.txt"}); !errors.Is(err, workspace.ErrWorkspaceDenied) {
		t.Fatalf("traversal error = %v", err)
	}
}

func TestGrepAndLS(t *testing.T) {
	service, workspaceRecord := testService(t)
	if err := os.MkdirAll(filepath.Join(workspaceRecord.Root, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"main.go":        "needle here\n",
		"pkg/other.go":   "another needle\n",
		"pkg/readme.txt": "needle text\n",
	}
	for path, content := range files {
		if err := os.WriteFile(filepath.Join(workspaceRecord.Root, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	grep, err := service.Grep(context.Background(), GrepInput{WorkspaceID: workspaceRecord.ID, Pattern: "needle", Include: "*.go"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(grep.Text, "main.go:1:needle here") || strings.Contains(grep.Text, "readme.txt") {
		t.Fatalf("grep output = %q", grep.Text)
	}
	ls, err := service.LS(context.Background(), LSInput{WorkspaceID: workspaceRecord.ID, Path: "pkg"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ls.Text, "other.go") || !strings.Contains(ls.Text, "readme.txt") {
		t.Fatalf("ls output = %q", ls.Text)
	}
}

func TestGrepDoesNotFollowSymlinkOutsideWorkspace(t *testing.T) {
	service, workspaceRecord := testService(t)
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("outside-secret-needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretPath, filepath.Join(workspaceRecord.Root, "leak.txt")); err != nil {
		t.Fatal(err)
	}

	result, err := service.Grep(context.Background(), GrepInput{WorkspaceID: workspaceRecord.ID, Pattern: "outside-secret-needle"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Matches != 0 || strings.Contains(result.Text, "outside-secret-needle") {
		t.Fatalf("grep followed symlink outside workspace: %#v", result)
	}
}

func TestExecAppliesTokenOutputLimit(t *testing.T) {
	service, workspaceRecord := testService(t)
	result, err := service.Exec(context.Background(), ExecInput{
		WorkspaceID:     workspaceRecord.ID,
		Command:         "printf '0123456789'",
		MaxOutputTokens: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != "01234567" || !result.Truncated || result.ExitCode != 0 || result.TimedOut {
		t.Fatalf("result = %#v, want 8-byte truncated output", result)
	}
}

func TestExecUsesMillisecondTimeoutAndReportsTimeout(t *testing.T) {
	service, workspaceRecord := testService(t)
	started := time.Now()
	result, err := service.Exec(context.Background(), ExecInput{
		WorkspaceID: workspaceRecord.ID,
		Command:     "sleep 1",
		TimeoutMS:   100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout took %s, want approximately 100ms", elapsed)
	}
	if result.ExitCode != -1 || !result.TimedOut {
		t.Fatalf("result = %#v, want timeout with exit code -1", result)
	}
}

func TestExecReturnsNonZeroExitAsResult(t *testing.T) {
	service, workspaceRecord := testService(t)
	result, err := service.Exec(context.Background(), ExecInput{
		WorkspaceID: workspaceRecord.ID,
		Command:     "printf 'failed'; exit 7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != "failed" || result.ExitCode != 7 || result.TimedOut {
		t.Fatalf("result = %#v, want ordinary exit result", result)
	}
}

func TestShowChangesReportsGitDiffAndUntrackedFiles(t *testing.T) {
	service, workspaceRecord := testService(t)
	runGit := func(args ...string) {
		t.Helper()
		if _, _, err := service.Workspaces.Git.Run(context.Background(), workspaceRecord.Root, args...); err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
	}
	runGit("init")
	if err := os.WriteFile(filepath.Join(workspaceRecord.Root, "tracked.txt"), []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "tracked.txt")
	runGit("-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "initial")
	if err := os.WriteFile(filepath.Join(workspaceRecord.Root, "tracked.txt"), []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspaceRecord.Root, "new.txt"), []byte("new file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.ShowChanges(context.Background(), ShowChangesInput{WorkspaceID: workspaceRecord.ID})
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesChanged != 2 || len(result.Untracked) != 1 || result.Untracked[0] != "new.txt" {
		t.Fatalf("change summary = %#v", result)
	}
	if !strings.Contains(result.Text, "-before") || !strings.Contains(result.Text, "+after") || !strings.Contains(result.Text, "+new file") {
		t.Fatalf("change text = %q", result.Text)
	}
	if result.Additions != 2 || result.Deletions != 1 {
		t.Fatalf("change counts = %#v", result)
	}
}

func TestShowChangesRejectsNonGitWorkspace(t *testing.T) {
	service, workspaceRecord := testService(t)
	if _, err := service.ShowChanges(context.Background(), ShowChangesInput{WorkspaceID: workspaceRecord.ID}); err == nil || !strings.Contains(err.Error(), "not a Git repository") {
		t.Fatalf("error = %v, want Git repository error", err)
	}
}
