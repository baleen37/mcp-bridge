package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/baleen37/mcp-bridge/internal/workspace"
)

type Service struct {
	Workspaces *workspace.Registry
	Command    CommandRunner
	Sessions   *ProcessSessionManager
	HTTPClient *http.Client
	sessionsMu sync.Mutex
}

type ToolResult struct {
	Text       string `json:"text"`
	ExitCode   int    `json:"exit_code"`
	Truncated  bool   `json:"truncated,omitempty"`
	Matches    int    `json:"matches,omitempty"`
	SessionID  int    `json:"session_id,omitempty"`
	Running    bool   `json:"running"`
	Signal     string `json:"signal,omitempty"`
	WallTimeMS int64  `json:"wall_time_ms,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

type ReadInput struct {
	WorkspaceID string
	Path        string
	Offset      int
	Limit       int
}

type WriteInput struct {
	WorkspaceID string
	Path        string
	Content     string
}

type Edit struct {
	OldText string `json:"oldText"`
	NewText string `json:"newText"`
}

type EditInput struct {
	WorkspaceID string
	Path        string
	Edits       []Edit
}

func (s *Service) processSessions() *ProcessSessionManager {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if s.Sessions == nil {
		s.Sessions = NewProcessSessionManager()
	}
	return s.Sessions
}

func (s *Service) Close() {
	s.sessionsMu.Lock()
	sessions := s.Sessions
	s.sessionsMu.Unlock()
	if sessions != nil {
		sessions.Close()
	}
}

func (s *Service) Read(_ context.Context, input ReadInput) (ToolResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	path, err := s.Workspaces.Resolve(record, input.Path, false)
	if err != nil {
		return ToolResult{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return ToolResult{}, fmt.Errorf("read file: %w", err)
	}
	text, err := sliceLines(string(content), input.Offset, input.Limit)
	if err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Text: text}, nil
}

func (s *Service) Write(_ context.Context, input WriteInput) (ToolResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	path, err := s.Workspaces.Resolve(record, input.Path, true)
	if err != nil {
		return ToolResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return ToolResult{}, fmt.Errorf("create file parent: %w", err)
	}
	if err := atomicWrite(path, []byte(input.Content)); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Text: fmt.Sprintf("Wrote %s.", input.Path)}, nil
}

func (s *Service) Edit(_ context.Context, input EditInput) (ToolResult, error) {
	if len(input.Edits) == 0 {
		return ToolResult{}, errors.New("at least one edit is required")
	}
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	path, err := s.Workspaces.Resolve(record, input.Path, false)
	if err != nil {
		return ToolResult{}, err
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return ToolResult{}, fmt.Errorf("read file for edit: %w", err)
	}
	text := string(original)
	ranges := make([]editRange, 0, len(input.Edits))
	for _, edit := range input.Edits {
		if edit.OldText == "" {
			return ToolResult{}, errors.New("oldText must not be empty")
		}
		start := strings.Index(text, edit.OldText)
		if start < 0 || strings.Index(text[start+len(edit.OldText):], edit.OldText) >= 0 {
			return ToolResult{}, fmt.Errorf("oldText must match exactly once: %q", edit.OldText)
		}
		ranges = append(ranges, editRange{start: start, end: start + len(edit.OldText), edit: edit})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	for i := 1; i < len(ranges); i++ {
		if ranges[i].start < ranges[i-1].end {
			return ToolResult{}, errors.New("edits overlap")
		}
	}
	for i := len(ranges) - 1; i >= 0; i-- {
		item := ranges[i]
		text = text[:item.start] + item.edit.NewText + text[item.end:]
	}
	if err := atomicWrite(path, []byte(text)); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Text: fmt.Sprintf("Edited %s.", input.Path)}, nil
}

func (s *Service) workspace(id string) (workspace.Record, error) {
	if s.Workspaces == nil {
		return workspace.Record{}, errors.New("workspace registry is not configured")
	}
	return s.Workspaces.Get(id)
}

type editRange struct {
	start int
	end   int
	edit  Edit
}

func sliceLines(text string, offset, limit int) (string, error) {
	if offset < 0 || limit < 0 {
		return "", errors.New("offset and limit must not be negative")
	}
	if offset == 0 {
		offset = 1
	}
	lines := strings.SplitAfter(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if offset > len(lines) {
		return "", nil
	}
	end := len(lines)
	if limit > 0 && offset-1+limit < end {
		end = offset - 1 + limit
	}
	return strings.Join(lines[offset-1:end], ""), nil
}

func atomicWrite(path string, content []byte) error {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat file: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".mcp-bridge-write-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set file permissions: %w", err)
	}
	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace file: %w", err)
	}
	return nil
}
