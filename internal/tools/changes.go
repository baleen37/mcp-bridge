package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/baleen37/mcp-bridge/internal/workspace"
)

const maxChangesOutput = 1 << 20

type ShowChangesInput struct {
	WorkspaceID string
	Path        string
}

type ChangesResult struct {
	Text         string   `json:"text"`
	FilesChanged int      `json:"filesChanged"`
	Additions    int      `json:"additions"`
	Deletions    int      `json:"deletions"`
	Untracked    []string `json:"untracked,omitempty"`
	Truncated    bool     `json:"truncated,omitempty"`
}

func (s *Service) ShowChanges(ctx context.Context, input ShowChangesInput) (ChangesResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ChangesResult{}, err
	}
	if s.Workspaces.Git == nil {
		return ChangesResult{}, errors.New("git workspace support is not configured")
	}
	root, err := s.gitOutput(ctx, record.Root, "rev-parse", "--show-toplevel")
	if err != nil {
		return ChangesResult{}, errors.New("workspace is not a Git repository")
	}
	root = strings.TrimSpace(root)
	if root == "" {
		return ChangesResult{}, errors.New("workspace is not a Git repository")
	}
	pathspec := []string{"--"}
	if input.Path != "" {
		resolved, resolveErr := s.Workspaces.Resolve(record, input.Path, false)
		if resolveErr != nil {
			return ChangesResult{}, resolveErr
		}
		relative, relativeErr := filepath.Rel(root, resolved)
		if relativeErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return ChangesResult{}, workspace.ErrWorkspaceDenied
		}
		pathspec = append(pathspec, filepath.ToSlash(relative))
	}
	statusArgs := append([]string{"status", "--porcelain=v1", "--untracked-files=all"}, pathspec...)
	status, err := s.gitOutput(ctx, root, statusArgs...)
	if err != nil {
		return ChangesResult{}, fmt.Errorf("read Git status: %w", err)
	}
	result := ChangesResult{}
	var text strings.Builder
	for line := range strings.SplitSeq(strings.TrimSuffix(status, "\n"), "\n") {
		if line == "" {
			continue
		}
		result.FilesChanged++
		if after, ok := strings.CutPrefix(line, "?? "); ok {
			result.Untracked = append(result.Untracked, after)
		}
	}
	diffArgs := append([]string{"diff", "HEAD"}, pathspec...)
	diff, diffErr := s.gitOutputAllowExitOne(ctx, root, diffArgs...)
	if diffErr != nil {
		return ChangesResult{}, fmt.Errorf("read Git diff: %w", diffErr)
	}
	for _, path := range result.Untracked {
		untrackedPath := filepath.Join(root, filepath.FromSlash(path))
		if info, statErr := os.Stat(untrackedPath); statErr == nil && !info.IsDir() {
			untrackedDiff, exitErr := s.gitOutputAllowExitOne(ctx, root, "diff", "--no-index", "--", os.DevNull, untrackedPath)
			if exitErr != nil {
				return ChangesResult{}, fmt.Errorf("read untracked diff: %w", exitErr)
			}
			diff += untrackedDiff
		}
	}
	stat, statErr := s.gitOutputAllowExitOne(ctx, root, append([]string{"diff", "HEAD", "--numstat"}, pathspec...)...)
	if statErr != nil {
		return ChangesResult{}, fmt.Errorf("read Git diff stat: %w", statErr)
	}
	for line := range strings.SplitSeq(stat, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		if additions, parseErr := strconv.Atoi(fields[0]); parseErr == nil {
			result.Additions += additions
		}
		if deletions, parseErr := strconv.Atoi(fields[1]); parseErr == nil {
			result.Deletions += deletions
		}
	}
	for _, path := range result.Untracked {
		if info, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(path))); statErr == nil && !info.IsDir() {
			if content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path))); readErr == nil {
				result.Additions += strings.Count(string(content), "\n")
				if len(content) > 0 && content[len(content)-1] != '\n' {
					result.Additions++
				}
			}
		}
	}
	text.WriteString(status)
	if diff != "" {
		if text.Len() > 0 && !strings.HasSuffix(text.String(), "\n") {
			text.WriteByte('\n')
		}
		text.WriteString(diff)
	}
	result.Text, result.Truncated = limitChangesOutput(text.String())
	return result, nil
}

func (s *Service) gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	stdout, stderr, err := s.Workspaces.Git.Run(ctx, dir, args...)
	if err != nil {
		if message := strings.TrimSpace(string(stderr)); message != "" {
			return "", fmt.Errorf("%s", message)
		}
		return "", err
	}
	return string(stdout), nil
}

func (s *Service) gitOutputAllowExitOne(ctx context.Context, dir string, args ...string) (string, error) {
	stdout, stderr, err := s.Workspaces.Git.Run(ctx, dir, args...)
	if err != nil && len(stdout) == 0 {
		if message := strings.TrimSpace(string(stderr)); message != "" {
			return "", fmt.Errorf("%s", message)
		}
		return "", err
	}
	return string(stdout), nil
}

func limitChangesOutput(text string) (string, bool) {
	if len(text) <= maxChangesOutput {
		return text, false
	}
	marker := "\n... changes truncated ...\n"
	return text[:maxChangesOutput-len(marker)] + marker, true
}
