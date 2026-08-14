package workspace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/baleen37/mcp-bridge/internal/store"
)

type GitRunner interface {
	Run(ctx context.Context, dir string, args ...string) (stdout, stderr []byte, err error)
}

type ExecGitRunner struct{}

func (ExecGitRunner) Run(ctx context.Context, dir string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = dir
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return []byte(stdout.String()), []byte(stderr.String()), err
}

type Worktree struct {
	SourceRoot  string
	Path        string
	BaseRef     string
	BaseSHA     string
	DirtySource bool
	Detached    bool
	Managed     bool
}

func CreateManagedWorktree(ctx context.Context, runner GitRunner, sourcePath, worktreeRoot, baseRef string) (Worktree, error) {
	info, err := os.Stat(sourcePath)
	if err != nil || !info.IsDir() {
		return Worktree{}, fmt.Errorf("%w: source path is not a directory", store.ErrNotFound)
	}
	stdout, stderr, err := runner.Run(ctx, sourcePath, "rev-parse", "--show-toplevel")
	if err != nil {
		return Worktree{}, fmt.Errorf("source path is not a Git repository: %s", gitFailure(stderr, err))
	}
	sourceRoot, err := filepath.Abs(strings.TrimSpace(string(stdout)))
	if err != nil || sourceRoot == "" {
		return Worktree{}, fmt.Errorf("resolve Git repository root: %w", err)
	}
	if baseRef == "" {
		baseRef = "HEAD"
	}
	stdout, stderr, err = runner.Run(ctx, sourceRoot, "rev-parse", "--verify", baseRef+"^{commit}")
	if err != nil {
		return Worktree{}, fmt.Errorf("invalid base ref %q: %s", baseRef, gitFailure(stderr, err))
	}
	baseSHA := strings.TrimSpace(string(stdout))
	if baseSHA == "" {
		return Worktree{}, fmt.Errorf("invalid base ref %q", baseRef)
	}
	stdout, stderr, err = runner.Run(ctx, sourceRoot, "status", "--porcelain=v1")
	if err != nil {
		return Worktree{}, fmt.Errorf("read Git status: %s", gitFailure(stderr, err))
	}
	if err := os.MkdirAll(worktreeRoot, 0o700); err != nil {
		return Worktree{}, fmt.Errorf("create worktree root: %w", err)
	}
	repoName := sanitizePathSegment(filepath.Base(sourceRoot))
	if repoName == "" {
		repoName = "repo"
	}
	name, err := randomID()
	if err != nil {
		return Worktree{}, err
	}
	worktreePath := filepath.Join(worktreeRoot, repoName+"-"+name[:8])
	if !isInside(worktreePath, worktreeRoot) {
		return Worktree{}, ErrWorkspaceDenied
	}
	if _, _, err := runner.Run(ctx, sourceRoot, "worktree", "add", "--detach", worktreePath, baseSHA); err != nil {
		return Worktree{}, fmt.Errorf("create Git worktree: %w", err)
	}
	return Worktree{SourceRoot: sourceRoot, Path: worktreePath, BaseRef: baseRef, BaseSHA: baseSHA, DirtySource: strings.TrimSpace(string(stdout)) != "", Detached: true, Managed: true}, nil
}

func sanitizePathSegment(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func gitFailure(stderr []byte, err error) string {
	message := strings.TrimSpace(string(stderr))
	if message == "" {
		return err.Error()
	}
	return message
}
