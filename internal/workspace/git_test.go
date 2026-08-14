package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOpenCreatesDetachedManagedWorktree(t *testing.T) {
	registry, allowedRoot, sourceRoot := testRegistry(t)
	if err := runGit(sourceRoot, "init"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(sourceRoot, "config", "user.email", "test@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(sourceRoot, "config", "user.name", "Test User"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "tracked.txt"), []byte("tracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runGit(sourceRoot, "add", "tracked.txt"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(sourceRoot, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "dirty.txt"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	record, err := registry.Open(context.Background(), sourceRoot, "worktree", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if record.Mode != "worktree" || !record.Managed || !record.Detached || !record.DirtySource {
		t.Fatalf("unexpected worktree record: %#v", record)
	}
	if !isInside(record.Root, registry.WorktreeRoot) {
		t.Fatalf("worktree root %q is outside %q", record.Root, registry.WorktreeRoot)
	}
	if _, err := os.Stat(filepath.Join(record.Root, "tracked.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(record.Root, "dirty.txt")); !os.IsNotExist(err) {
		t.Fatalf("dirty file in worktree, err=%v", err)
	}
	if err := runGit(record.Root, "symbolic-ref", "--quiet", "--short", "HEAD"); err == nil {
		t.Fatal("worktree has a symbolic branch, want detached HEAD")
	}
	if err := runGit(sourceRoot, "worktree", "remove", "--force", record.Root); err != nil {
		t.Fatal(err)
	}
	_ = allowedRoot
}

func TestOpenWorktreeRejectsInvalidBaseRef(t *testing.T) {
	registry, _, sourceRoot := testRegistry(t)
	if err := runGit(sourceRoot, "init"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(sourceRoot, "config", "user.email", "test@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(sourceRoot, "config", "user.name", "Test User"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "tracked.txt"), []byte("tracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runGit(sourceRoot, "add", "tracked.txt"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(sourceRoot, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Open(context.Background(), sourceRoot, "worktree", "does-not-exist"); err == nil {
		t.Fatal("invalid base ref unexpectedly succeeded")
	}
}

func runGit(dir string, args ...string) error {
	command := exec.Command("git", args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		return &gitTestError{args: args, output: string(output), err: err}
	}
	return nil
}

type gitTestError struct {
	args   []string
	output string
	err    error
}

func (e *gitTestError) Error() string { return e.err.Error() + ": " + e.output }
func (e *gitTestError) Unwrap() error { return e.err }
