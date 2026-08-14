package workspace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/baleen37/mcp-bridge/internal/store"
)

var (
	ErrWorkspaceDenied  = errors.New("workspace path is outside the allowed roots")
	ErrInvalidWorkspace = errors.New("invalid workspace")
)

type Record struct {
	ID          string
	Root        string
	Mode        string
	SourceRoot  string
	BaseRef     string
	BaseSHA     string
	DirtySource bool
	Detached    bool
	Managed     bool
}

type StateStore interface {
	PutWorkspace(record store.WorkspaceRecord) error
	GetWorkspace(id string) (store.WorkspaceRecord, error)
}

type Registry struct {
	AllowedRoots []string
	WorktreeRoot string
	Store        StateStore
	Git          GitRunner

	mu      sync.RWMutex
	current map[string]Record
}

// Instructions returns only bounded, conventional project instruction files.
func Instructions(root string) map[string]string {
	result := map[string]string{}
	for _, name := range []string{"AGENTS.md", "AGENTS.override.md", "CLAUDE.md"} {
		path := filepath.Join(root, name)
		content, err := os.ReadFile(path)
		if err == nil && len(content) <= 64*1024 {
			result[name] = string(content)
		}
	}
	return result
}

func (r *Registry) Open(ctx context.Context, path, mode, baseRef string) (Record, error) {
	if mode == "" {
		mode = "checkout"
	}
	if mode != "checkout" && mode != "worktree" {
		return Record{}, fmt.Errorf("%w: mode must be checkout or worktree", ErrInvalidWorkspace)
	}
	sourcePath, err := r.resolveAllowedExisting(path)
	if err != nil {
		return Record{}, err
	}
	var record Record
	if mode == "checkout" {
		info, statErr := os.Stat(sourcePath)
		if statErr != nil {
			return Record{}, statErr
		}
		if !info.IsDir() {
			return Record{}, fmt.Errorf("%w: workspace root is not a directory", ErrInvalidWorkspace)
		}
		record = Record{Root: sourcePath, Mode: mode}
	} else {
		if r.Git == nil {
			r.Git = ExecGitRunner{}
		}
		worktree, worktreeErr := CreateManagedWorktree(ctx, r.Git, sourcePath, r.WorktreeRoot, baseRef)
		if worktreeErr != nil {
			return Record{}, worktreeErr
		}
		record = Record{
			Root: worktree.Path, Mode: mode, SourceRoot: worktree.SourceRoot,
			BaseRef: worktree.BaseRef, BaseSHA: worktree.BaseSHA,
			DirtySource: worktree.DirtySource, Detached: worktree.Detached, Managed: worktree.Managed,
		}
	}
	id, err := randomID()
	if err != nil {
		return Record{}, err
	}
	record.ID = "ws_" + id
	if r.Store != nil {
		if err := r.Store.PutWorkspace(toStoreRecord(record)); err != nil {
			return Record{}, err
		}
	}
	r.mu.Lock()
	if r.current == nil {
		r.current = map[string]Record{}
	}
	r.current[record.ID] = record
	r.mu.Unlock()
	return record, nil
}

func (r *Registry) Get(id string) (Record, error) {
	r.mu.RLock()
	record, ok := r.current[id]
	r.mu.RUnlock()
	if ok {
		return record, nil
	}
	if r.Store == nil {
		return Record{}, store.ErrNotFound
	}
	persisted, err := r.Store.GetWorkspace(id)
	if err != nil {
		return Record{}, err
	}
	record = fromStoreRecord(persisted)
	if err := r.validateStoredRecord(record); err != nil {
		return Record{}, err
	}
	r.mu.Lock()
	if r.current == nil {
		r.current = map[string]Record{}
	}
	r.current[id] = record
	r.mu.Unlock()
	return record, nil
}

func (r *Registry) Resolve(record Record, relativePath string, allowMissing bool) (string, error) {
	if filepath.IsAbs(relativePath) {
		return "", fmt.Errorf("%w: absolute paths are not allowed", ErrWorkspaceDenied)
	}
	clean := filepath.Clean(relativePath)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || hasParentComponent(relativePath) {
		return "", fmt.Errorf("%w: path traversal is not allowed", ErrWorkspaceDenied)
	}
	root, err := canonicalExisting(record.Root)
	if err != nil {
		return "", fmt.Errorf("%w: workspace root is unavailable", ErrInvalidWorkspace)
	}
	target := filepath.Join(root, clean)
	if info, statErr := os.Lstat(target); statErr == nil {
		resolved, evalErr := filepath.EvalSymlinks(target)
		if evalErr != nil {
			return "", fmt.Errorf("resolve workspace path: %w", evalErr)
		}
		resolved, _ = filepath.Abs(resolved)
		if !isInside(resolved, root) {
			return "", ErrWorkspaceDenied
		}
		if !allowMissing && info == nil {
			return "", fs.ErrNotExist
		}
		return resolved, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	} else if !allowMissing {
		return "", statErr
	}
	parent := filepath.Dir(target)
	for {
		if _, statErr := os.Lstat(parent); statErr == nil {
			resolvedParent, evalErr := filepath.EvalSymlinks(parent)
			if evalErr != nil {
				return "", evalErr
			}
			resolvedParent, _ = filepath.Abs(resolvedParent)
			if !isInside(resolvedParent, root) {
				return "", ErrWorkspaceDenied
			}
			return target, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		next := filepath.Dir(parent)
		if next == parent {
			return "", ErrWorkspaceDenied
		}
		parent = next
	}
}

func (r *Registry) resolveAllowedExisting(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: path is required", ErrWorkspaceDenied)
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	lexicallyAllowed := false
	for _, allowed := range r.AllowedRoots {
		if isInside(abs, allowed) {
			lexicallyAllowed = true
			break
		}
	}
	if !lexicallyAllowed {
		return "", ErrWorkspaceDenied
	}
	resolved, err := canonicalExisting(abs)
	if err != nil {
		return "", err
	}
	for _, allowed := range r.AllowedRoots {
		canonicalRoot, rootErr := canonicalExisting(allowed)
		if rootErr == nil && isInside(resolved, canonicalRoot) {
			return resolved, nil
		}
	}
	return "", ErrWorkspaceDenied
}

func (r *Registry) validateStoredRecord(record Record) error {
	if record.Mode == "worktree" {
		if !isInside(record.Root, r.WorktreeRoot) || !isInside(record.SourceRoot, r.AllowedRoots...) {
			return ErrWorkspaceDenied
		}
		if _, err := canonicalExisting(record.Root); err != nil {
			return fmt.Errorf("%w: worktree is unavailable", ErrInvalidWorkspace)
		}
		return nil
	}
	if _, err := r.resolveAllowedExisting(record.Root); err != nil {
		return err
	}
	return nil
}

func canonicalExisting(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func hasParentComponent(path string) bool {
	for _, component := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if component == ".." {
			return true
		}
	}
	return false
}

func isInside(path string, roots ...string) bool {
	canonicalPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for _, root := range roots {
		canonicalRoot, rootErr := filepath.Abs(root)
		if rootErr != nil {
			continue
		}
		relative, relErr := filepath.Rel(filepath.Clean(canonicalRoot), filepath.Clean(canonicalPath))
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			return true
		}
	}
	return false
}

func randomID() (string, error) {
	raw := make([]byte, 5)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func toStoreRecord(record Record) store.WorkspaceRecord {
	return store.WorkspaceRecord{ID: record.ID, Root: record.Root, Mode: record.Mode, SourceRoot: record.SourceRoot, BaseRef: record.BaseRef, BaseSHA: record.BaseSHA, DirtySource: record.DirtySource, Detached: record.Detached, Managed: record.Managed}
}

func fromStoreRecord(record store.WorkspaceRecord) Record {
	return Record{ID: record.ID, Root: record.Root, Mode: record.Mode, SourceRoot: record.SourceRoot, BaseRef: record.BaseRef, BaseSHA: record.BaseSHA, DirtySource: record.DirtySource, Detached: record.Detached, Managed: record.Managed}
}
