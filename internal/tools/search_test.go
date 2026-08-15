package tools

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestGrepSkipsSymlinkedFile(t *testing.T) {
	service, workspaceRecord := testService(t)
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("outside-needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretPath, filepath.Join(workspaceRecord.Root, "leak.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspaceRecord.Root, "leakdir")); err != nil {
		t.Fatal(err)
	}

	result, err := service.Grep(context.Background(), GrepInput{WorkspaceID: workspaceRecord.ID, Pattern: "outside-needle"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Matches != 0 {
		t.Fatalf("grep read through symlink: %#v", result)
	}
}

func TestGrepSkipsNoiseDirectories(t *testing.T) {
	service, workspaceRecord := testService(t)
	for _, dir := range []string{"node_modules", "vendor", "target", "dist", "build", ".venv", "__pycache__", ".next"} {
		full := filepath.Join(workspaceRecord.Root, dir)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, "noise.go"), []byte("needle\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(workspaceRecord.Root, "main.go"), []byte("needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.Grep(context.Background(), GrepInput{WorkspaceID: workspaceRecord.ID, Pattern: "needle"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Matches != 1 || !strings.Contains(result.Text, "main.go:1:needle") {
		t.Fatalf("grep did not skip noise directories: %#v", result)
	}
}

func TestGrepSkipsBinaryFiles(t *testing.T) {
	service, workspaceRecord := testService(t)
	if err := os.WriteFile(filepath.Join(workspaceRecord.Root, "blob.bin"), []byte("needle\x00binary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspaceRecord.Root, "text.txt"), []byte("needle\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.Grep(context.Background(), GrepInput{WorkspaceID: workspaceRecord.ID, Pattern: "needle"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Matches != 1 || !strings.Contains(result.Text, "text.txt:1:needle") {
		t.Fatalf("grep did not skip binary file: %#v", result)
	}
}

func TestGrepSortsByLineNumber(t *testing.T) {
	service, workspaceRecord := testService(t)
	content := strings.Repeat("needle\n", 12)
	if err := os.WriteFile(filepath.Join(workspaceRecord.Root, "many.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.Grep(context.Background(), GrepInput{WorkspaceID: workspaceRecord.ID, Pattern: "needle"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(result.Text, "\n")
	if len(got) != 12 {
		t.Fatalf("match count = %d, text = %q", len(got), result.Text)
	}
	for i, line := range got {
		want := "many.txt:" + strconv.Itoa(i+1) + ":needle"
		if line != want {
			t.Fatalf("line %d = %q, want %q", i, line, want)
		}
	}
}
