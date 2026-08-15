package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
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

type LSInput struct {
	WorkspaceID string
	Path        string
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
	var matches []grepMatch
	err = walkFiles(root, func(filePath, relative string, _ fs.FileInfo) error {
		if input.Include != "" && !globMatch(input.Include, relative) {
			return nil
		}
		file, openErr := os.Open(filePath)
		if openErr != nil {
			return nil
		}
		defer file.Close()
		if binary, checkErr := isBinary(file); checkErr != nil || binary {
			return nil
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			if pattern.MatchString(line) {
				matches = append(matches, grepMatch{path: relative, line: lineNumber, text: line})
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
	slices.SortFunc(matches, func(a, b grepMatch) int {
		if c := strings.Compare(a.path, b.path); c != 0 {
			return c
		}
		return a.line - b.line
	})
	lines := make([]string, 0, len(matches))
	for _, match := range matches {
		lines = append(lines, fmt.Sprintf("%s:%d:%s", match.path, match.line, match.text))
	}
	return ToolResult{Text: strings.Join(lines, "\n"), Matches: len(matches)}, nil
}

type grepMatch struct {
	path string
	line int
	text string
}

// isBinary reports whether the head of the file contains a NUL byte, then
// rewinds so the caller can scan from the start.
func isBinary(file *os.File) (bool, error) {
	head := make([]byte, 8000)
	n, err := file.Read(head)
	if err != nil && err != io.EOF {
		return false, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	return bytes.IndexByte(head[:n], 0) >= 0, nil
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
	slices.Sort(lines)
	return ToolResult{Text: strings.Join(lines, "\n"), Matches: len(lines)}, nil
}

func (s *Service) scope(record workspace.Record, relativePath string) (string, error) {
	if relativePath == "" {
		return record.Root, nil
	}
	return s.Workspaces.Resolve(record, relativePath, false)
}

// skippedDirs are build and dependency directories that rarely contain
// source worth searching.
var skippedDirs = map[string]bool{
	".git": true, ".next": true, ".venv": true, "__pycache__": true,
	"build": true, "dist": true, "node_modules": true, "target": true, "vendor": true,
}

func walkFiles(root string, callback func(filePath, relative string, info fs.FileInfo) error) error {
	base := root
	return filepath.Walk(root, func(filePath string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skippedDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// filepath.Walk lstats entries, so symlinks arrive as symlinks and are
		// never descended into. Restricting to regular files therefore keeps
		// reads inside the canonical root without a per-file resolve.
		if !info.Mode().IsRegular() {
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
	if after, ok := strings.CutPrefix(pattern, "**/"); ok {
		short := after
		if ok, _ := path.Match(short, value); ok {
			return true
		}
		if ok, _ := path.Match(short, path.Base(value)); ok {
			return true
		}
	}
	return false
}
