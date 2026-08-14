package tools

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/baleen37/mcp-bridge/internal/workspace"
)

type GrepInput struct {
	WorkspaceID string
	Pattern     string
	Path        string
	Include     string
	Limit       int
}

type GlobInput struct {
	WorkspaceID string
	Pattern     string
	Path        string
}

type LSInput struct {
	WorkspaceID string
	Path        string
}

type ListDirInput struct {
	WorkspaceID string
	Path        string
	Offset      int
	Limit       int
	Depth       int
}

func (s *Service) Grep(_ context.Context, input GrepInput) (ToolResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	if input.Pattern == "" {
		return ToolResult{}, fmt.Errorf("pattern is required")
	}
	pattern, err := regexp.Compile(input.Pattern)
	if err != nil {
		return ToolResult{}, fmt.Errorf("compile pattern: %w", err)
	}
	root, err := s.scope(record, input.Path)
	if err != nil {
		return ToolResult{}, err
	}
	var matches []string
	err = walkFiles(root, func(filePath, relative string, info fs.FileInfo) error {
		if input.Include != "" && !globMatch(input.Include, relative) {
			return nil
		}
		workspaceRelative, relErr := filepath.Rel(record.Root, filePath)
		if relErr != nil {
			return nil
		}
		resolvedPath, resolveErr := s.Workspaces.Resolve(record, workspaceRelative, false)
		if resolveErr != nil {
			return nil
		}
		file, openErr := os.Open(resolvedPath)
		if openErr != nil {
			return nil
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			if pattern.MatchString(line) {
				matches = append(matches, fmt.Sprintf("%s:%d:%s", relative, lineNumber, line))
				if input.Limit > 0 && len(matches) >= input.Limit {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	if err != nil {
		return ToolResult{}, err
	}
	sort.Strings(matches)
	return ToolResult{Text: strings.Join(matches, "\n"), Matches: len(matches)}, nil
}

func (s *Service) Glob(_ context.Context, input GlobInput) (ToolResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	if input.Pattern == "" {
		return ToolResult{}, fmt.Errorf("pattern is required")
	}
	root, err := s.scope(record, input.Path)
	if err != nil {
		return ToolResult{}, err
	}
	matches := make([]string, 0)
	if err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		relative, relErr := filepath.Rel(record.Root, filePath)
		if relErr == nil && globMatch(input.Pattern, relative) {
			matches = append(matches, filepath.ToSlash(relative))
		}
		return nil
	}); err != nil {
		return ToolResult{}, err
	}
	sort.Strings(matches)
	return ToolResult{Text: strings.Join(matches, "\n"), Matches: len(matches)}, nil
}

func (s *Service) LS(_ context.Context, input LSInput) (ToolResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	pathValue, err := s.Workspaces.Resolve(record, input.Path, false)
	if err != nil {
		return ToolResult{}, err
	}
	entries, err := os.ReadDir(pathValue)
	if err != nil {
		return ToolResult{}, fmt.Errorf("list directory: %w", err)
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		kind := "file"
		if entry.IsDir() {
			kind = "dir"
		}
		size := int64(0)
		if info, infoErr := entry.Info(); infoErr == nil {
			size = info.Size()
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%d", entry.Name(), kind, size))
	}
	sort.Strings(lines)
	return ToolResult{Text: strings.Join(lines, "\n"), Matches: len(lines)}, nil
}

func (s *Service) ListDir(ctx context.Context, input ListDirInput) (ToolResult, error) {
	if input.Offset < 0 || input.Limit < 0 || input.Depth < 0 {
		return ToolResult{}, fmt.Errorf("offset, limit, and depth must not be negative")
	}
	if input.Depth == 0 {
		result, err := s.LS(ctx, LSInput{WorkspaceID: input.WorkspaceID, Path: input.Path})
		if err != nil {
			return ToolResult{}, err
		}
		return paginateResult(result, input.Offset, input.Limit), nil
	}
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	root, err := s.Workspaces.Resolve(record, input.Path, false)
	if err != nil {
		return ToolResult{}, err
	}
	var lines []string
	err = filepath.WalkDir(root, func(pathValue string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if pathValue == root {
			return nil
		}
		relative, relErr := filepath.Rel(root, pathValue)
		if relErr != nil {
			return nil
		}
		level := strings.Count(relative, string(filepath.Separator)) + 1
		if level > input.Depth {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		kind := "file"
		if entry.IsDir() {
			kind = "dir"
		}
		size := int64(0)
		if info, infoErr := entry.Info(); infoErr == nil {
			size = info.Size()
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%d", filepath.ToSlash(relative), kind, size))
		return nil
	})
	if err != nil {
		return ToolResult{}, err
	}
	sort.Strings(lines)
	result := ToolResult{Text: strings.Join(lines, "\n"), Matches: len(lines)}
	return paginateResult(result, input.Offset, input.Limit), nil
}

func paginateResult(result ToolResult, offset, limit int) ToolResult {
	lines := strings.Split(result.Text, "\n")
	if result.Text == "" {
		lines = nil
	}
	if offset >= len(lines) {
		lines = nil
	} else {
		lines = lines[offset:]
	}
	if limit > 0 && len(lines) > limit {
		lines = lines[:limit]
	}
	result.Text, result.Matches = strings.Join(lines, "\n"), len(lines)
	return result
}

func (s *Service) scope(record workspace.Record, relativePath string) (string, error) {
	if relativePath == "" {
		return record.Root, nil
	}
	return s.Workspaces.Resolve(record, relativePath, false)
}

func walkFiles(root string, callback func(filePath, relative string, info fs.FileInfo) error) error {
	base := root
	return filepath.Walk(root, func(filePath string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		relative, relErr := filepath.Rel(base, filePath)
		if relErr != nil {
			return nil
		}
		return callback(filePath, filepath.ToSlash(relative), info)
	})
}

func globMatch(pattern, value string) bool {
	pattern = filepath.ToSlash(pattern)
	value = filepath.ToSlash(value)
	if ok, _ := path.Match(pattern, value); ok {
		return true
	}
	if strings.HasPrefix(pattern, "**/") {
		short := strings.TrimPrefix(pattern, "**/")
		if ok, _ := path.Match(short, value); ok {
			return true
		}
		if ok, _ := path.Match(short, path.Base(value)); ok {
			return true
		}
	}
	return false
}
