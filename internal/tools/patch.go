package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ApplyPatchInput struct {
	WorkspaceID string
	Input       string
}

type patchFile struct {
	action, path, moveTo string
	content              []byte
	body                 []string
}

func (s *Service) ApplyPatch(_ context.Context, input ApplyPatchInput) (ToolResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	files, err := parsePatch(input.Input)
	if err != nil {
		return ToolResult{}, err
	}
	resolved := make([]struct {
		patchFile
		path string
	}, len(files))
	for i, file := range files {
		path, resolveErr := s.Workspaces.Resolve(record, file.path, file.action == "add")
		if resolveErr != nil {
			return ToolResult{}, resolveErr
		}
		resolved[i] = struct {
			patchFile
			path string
		}{file, path}
		if file.action == "update" || file.action == "move" {
			content, applyErr := applyHunk(path, file.body)
			if applyErr != nil {
				return ToolResult{}, applyErr
			}
			resolved[i].content = content
		}
		if file.action == "move" {
			if _, err := os.Stat(path); err != nil {
				return ToolResult{}, fmt.Errorf("move source: %w", err)
			}
		}
	}
	for _, file := range resolved {
		if file.action == "add" || file.action == "update" {
			if err := os.MkdirAll(filepath.Dir(file.path), 0o700); err != nil {
				return ToolResult{}, err
			}
			if err := atomicWrite(file.path, file.content); err != nil {
				return ToolResult{}, err
			}
		} else if file.action == "delete" {
			if err := os.Remove(file.path); err != nil {
				return ToolResult{}, err
			}
		} else {
			target, err := s.Workspaces.Resolve(record, file.moveTo, true)
			if err != nil {
				return ToolResult{}, err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return ToolResult{}, err
			}
			if len(file.content) > 0 {
				if err := atomicWrite(file.path, file.content); err != nil {
					return ToolResult{}, err
				}
			}
			if err := os.Rename(file.path, target); err != nil {
				return ToolResult{}, err
			}
		}
	}
	return ToolResult{Text: fmt.Sprintf("Applied patch to %d file(s).", len(files))}, nil
}

func parsePatch(input string) ([]patchFile, error) {
	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")
	if len(lines) < 2 || lines[0] != "*** Begin Patch" || lines[len(lines)-1] != "*** End Patch" {
		return nil, errors.New("invalid patch: expected Begin/End Patch")
	}
	var result []patchFile
	for i := 1; i < len(lines)-1; {
		line := lines[i]
		i++
		var file patchFile
		switch {
		case strings.HasPrefix(line, "*** Add File: "):
			file.action, file.path = "add", strings.TrimSpace(strings.TrimPrefix(line, "*** Add File: "))
		case strings.HasPrefix(line, "*** Update File: "):
			file.action, file.path = "update", strings.TrimSpace(strings.TrimPrefix(line, "*** Update File: "))
		case strings.HasPrefix(line, "*** Delete File: "):
			file.action, file.path = "delete", strings.TrimSpace(strings.TrimPrefix(line, "*** Delete File: "))
		case strings.HasPrefix(line, "*** Move to: "):
			if len(result) == 0 || result[len(result)-1].action != "update" {
				return nil, errors.New("invalid patch: Move to must follow an Update File")
			}
			result[len(result)-1].action = "move"
			result[len(result)-1].moveTo = strings.TrimSpace(strings.TrimPrefix(line, "*** Move to: "))
			continue
		default:
			return nil, fmt.Errorf("invalid patch header: %s", line)
		}
		if file.path == "" {
			return nil, errors.New("invalid patch: empty file path")
		}
		if file.action == "delete" {
			result = append(result, file)
			continue
		}
		if i < len(lines)-1 && strings.HasPrefix(lines[i], "*** Move to: ") {
			file.action = "move"
			file.moveTo = strings.TrimSpace(strings.TrimPrefix(lines[i], "*** Move to: "))
			i++
		}
		var body []string
		for i < len(lines)-1 && !strings.HasPrefix(lines[i], "*** ") {
			body = append(body, lines[i])
			i++
		}
		if file.action == "add" {
			for _, line := range body {
				if !strings.HasPrefix(line, "+") {
					return nil, errors.New("invalid add patch line")
				}
				file.content = append(file.content, []byte(strings.TrimPrefix(line, "+")+"\n")...)
			}
		} else if file.action == "update" || file.action == "move" {
			file.body = body
			if len(body) == 0 {
				return nil, fmt.Errorf("invalid patch: empty update for %s", file.path)
			}
		}
		result = append(result, file)
	}
	if len(result) == 0 {
		return nil, errors.New("invalid patch: no files")
	}
	return result, nil
}

func applyHunk(path string, body []string) ([]byte, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read patch target %s: %w", path, err)
	}
	oldLines := []string{}
	newLines := []string{}
	for _, line := range body {
		if line == "" {
			continue
		}
		switch line[0] {
		case ' ':
			oldLines = append(oldLines, line[1:])
			newLines = append(newLines, line[1:])
		case '-':
			oldLines = append(oldLines, line[1:])
		case '+':
			newLines = append(newLines, line[1:])
		case '@':
		default:
			return nil, fmt.Errorf("invalid patch line: %s", line)
		}
	}
	originalLines := strings.Split(strings.TrimSuffix(string(original), "\n"), "\n")
	for start := 0; start+len(oldLines) <= len(originalLines); start++ {
		match := true
		for j := range oldLines {
			if originalLines[start+j] != oldLines[j] {
				match = false
				break
			}
		}
		if match {
			out := append([]string{}, originalLines[:start]...)
			out = append(out, newLines...)
			out = append(out, originalLines[start+len(oldLines):]...)
			return []byte(strings.Join(out, "\n") + "\n"), nil
		}
	}
	return nil, fmt.Errorf("patch does not match %s", path)
}
