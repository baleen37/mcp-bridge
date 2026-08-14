package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baleen37/mcp-bridge/internal/workspace"
)

func TestValidateArtifactURLAllowsOpenAIHostsOnly(t *testing.T) {
	for _, raw := range []string{"https://files.openai.com/a", "https://cdn.oaiusercontent.com/a", "https://chatgpt.com/a"} {
		value, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateArtifactURL(value); err != nil {
			t.Errorf("%s rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://files.openai.com/a", "https://example.com/a", "https://openai.com.evil.example/a", "https://user:pass@files.openai.com/a"} {
		value, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateArtifactURL(value); err == nil {
			t.Errorf("%s unexpectedly allowed", raw)
		}
	}
}

// artifactTestService points artifact downloads at a local test server while
// leaving the HTTPS host allowlist in force.
func artifactTestService(t *testing.T, handler http.Handler) (*Service, workspace.Record) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	service, record := testService(t)
	service.HTTPClient = &http.Client{Transport: rewriteTransport{host: target.Host}}
	return service, record
}

// rewriteTransport sends requests to the test server without changing the
// allowlisted URL the caller passed in.
type rewriteTransport struct {
	host string
}

func (r rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = r.host
	return http.DefaultTransport.RoundTrip(clone)
}

func TestDownloadArtifactWritesFileAndReportsDigest(t *testing.T) {
	payload := []byte("artifact-body")
	service, record := artifactTestService(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	result, err := service.DownloadArtifact(context.Background(), DownloadArtifactInput{
		WorkspaceID: record.ID,
		File:        "https://files.openai.com/artifact.bin",
		Path:        "downloaded.bin",
	})
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if result.SHA256 != digest {
		t.Errorf("sha256 = %q, want %q", result.SHA256, digest)
	}
	written, err := os.ReadFile(filepath.Join(record.Root, "downloaded.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != string(payload) {
		t.Errorf("file contents = %q, want %q", written, payload)
	}
}

func TestDownloadArtifactVerifiesExpectedHash(t *testing.T) {
	service, record := artifactTestService(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("actual-body"))
	}))

	_, err := service.DownloadArtifact(context.Background(), DownloadArtifactInput{
		WorkspaceID: record.ID,
		File:        "https://files.openai.com/artifact.bin#sha256=" + strings.Repeat("ab", 32),
		Path:        "mismatch.bin",
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("err = %v, want SHA-256 mismatch", err)
	}
	if _, statErr := os.Stat(filepath.Join(record.Root, "mismatch.bin")); !os.IsNotExist(statErr) {
		t.Errorf("destination should not exist after a mismatch, stat err = %v", statErr)
	}
}

func TestDownloadArtifactRejectsHTTPError(t *testing.T) {
	service, record := artifactTestService(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	_, err := service.DownloadArtifact(context.Background(), DownloadArtifactInput{
		WorkspaceID: record.ID,
		File:        "https://files.openai.com/missing.bin",
		Path:        "missing.bin",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("err = %v, want HTTP 404", err)
	}
	if _, statErr := os.Stat(filepath.Join(record.Root, "missing.bin")); !os.IsNotExist(statErr) {
		t.Errorf("destination should not exist after an error, stat err = %v", statErr)
	}
}

func TestDownloadArtifactRefusesExistingDestination(t *testing.T) {
	service, record := artifactTestService(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("replacement"))
	}))
	existing := filepath.Join(record.Root, "taken.bin")
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := service.DownloadArtifact(context.Background(), DownloadArtifactInput{
		WorkspaceID: record.ID,
		File:        "https://files.openai.com/artifact.bin",
		Path:        "taken.bin",
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want already exists", err)
	}
	contents, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "original" {
		t.Errorf("existing file was modified: %q", contents)
	}
}

func TestDownloadArtifactRejectsDisallowedHost(t *testing.T) {
	service, record := artifactTestService(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should not be reached"))
	}))

	_, err := service.DownloadArtifact(context.Background(), DownloadArtifactInput{
		WorkspaceID: record.ID,
		File:        "https://example.com/artifact.bin",
		Path:        "blocked.bin",
	})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("err = %v, want host not allowed", err)
	}
}
