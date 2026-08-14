package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/baleen37/mcp-bridge/internal/store"
)

type memoryStore struct {
	records map[string]store.WorkspaceRecord
}

func (m *memoryStore) PutWorkspace(record store.WorkspaceRecord) error {
	if m.records == nil {
		m.records = map[string]store.WorkspaceRecord{}
	}
	m.records[record.ID] = record
	return nil
}

func (m *memoryStore) GetWorkspace(id string) (store.WorkspaceRecord, error) {
	record, ok := m.records[id]
	if !ok {
		return store.WorkspaceRecord{}, store.ErrNotFound
	}
	return record, nil
}

func testRegistry(t *testing.T) (*Registry, string, string) {
	t.Helper()
	root := t.TempDir()
	workspaceRoot := filepath.Join(root, "project")
	if err := os.Mkdir(workspaceRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	worktreeRoot := filepath.Join(t.TempDir(), "worktrees")
	return &Registry{
		AllowedRoots: []string{root},
		WorktreeRoot: worktreeRoot,
		Store:        &memoryStore{},
		Git:          ExecGitRunner{},
	}, root, workspaceRoot
}

func TestResolveRejectsTraversalAbsoluteAndSymlinkEscape(t *testing.T) {
	registry, allowedRoot, workspaceRoot := testRegistry(t)
	inside := filepath.Join(workspaceRoot, "inside.txt")
	if err := os.WriteFile(inside, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspaceRoot, "escape.txt")); err != nil {
		t.Fatal(err)
	}
	record := Record{ID: "ws_test", Root: workspaceRoot, Mode: "checkout"}
	canonicalWorkspaceRoot, err := canonicalExisting(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := registry.Resolve(record, "inside.txt", false)
	if err != nil || resolved != filepath.Join(canonicalWorkspaceRoot, "inside.txt") {
		t.Fatalf("inside resolve = %q, %v", resolved, err)
	}
	for _, path := range []string{"../outside.txt", allowedRoot, "escape.txt"} {
		if _, err := registry.Resolve(record, path, false); err == nil {
			t.Errorf("Resolve(%q) unexpectedly succeeded", path)
		}
	}
}

func TestResolveAllowsMissingFileInsideExistingParent(t *testing.T) {
	registry, _, workspaceRoot := testRegistry(t)
	record := Record{ID: "ws_test", Root: workspaceRoot, Mode: "checkout"}
	resolved, err := registry.Resolve(record, "new/file.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	canonicalWorkspaceRoot, err := canonicalExisting(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != filepath.Join(canonicalWorkspaceRoot, "new", "file.txt") {
		t.Fatalf("resolved path = %q", resolved)
	}
}

func TestOpenCheckoutPersistsWorkspace(t *testing.T) {
	registry, _, workspaceRoot := testRegistry(t)
	record, err := registry.Open(context.Background(), workspaceRoot, "checkout", "")
	if err != nil {
		t.Fatal(err)
	}
	canonicalWorkspaceRoot, err := canonicalExisting(workspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if record.ID == "" || record.Root != canonicalWorkspaceRoot || record.Mode != "checkout" {
		t.Fatalf("unexpected record: %#v", record)
	}
	restored, err := registry.Get(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Root != record.Root {
		t.Fatalf("restored record = %#v", restored)
	}
}

func TestGetRejectsWorkspaceOutsideAllowedRoot(t *testing.T) {
	registry, _, workspaceRoot := testRegistry(t)
	record := Record{ID: "ws_outside", Root: filepath.Join(t.TempDir(), "outside"), Mode: "checkout"}
	if err := registry.Store.PutWorkspace(toStoreRecord(record)); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Get(record.ID); !errors.Is(err, ErrWorkspaceDenied) {
		t.Fatalf("Get error = %v, want ErrWorkspaceDenied", err)
	}
	_ = workspaceRoot
}
