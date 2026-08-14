package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxArtifactBytes = 64 << 20

type DownloadArtifactInput struct {
	WorkspaceID string
	File        string
	Path        string
}

func (s *Service) DownloadArtifact(ctx context.Context, input DownloadArtifactInput) (ToolResult, error) {
	record, err := s.workspace(input.WorkspaceID)
	if err != nil {
		return ToolResult{}, err
	}
	target, err := s.Workspaces.Resolve(record, input.Path, true)
	if err != nil {
		return ToolResult{}, err
	}
	if _, err := os.Lstat(target); err == nil {
		return ToolResult{}, errors.New("artifact destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ToolResult{}, err
	}
	parsed, err := url.Parse(input.File)
	if err != nil {
		return ToolResult{}, fmt.Errorf("artifact URL: %w", err)
	}
	if err := validateArtifactURL(parsed); err != nil {
		return ToolResult{}, err
	}
	expectedHash := strings.TrimPrefix(parsed.Fragment, "sha256=")
	parsed.Fragment = ""
	client := s.artifactClient()
	response, err := client.Get(parsed.String())
	if err != nil {
		return ToolResult{}, fmt.Errorf("download artifact: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ToolResult{}, fmt.Errorf("download artifact: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxArtifactBytes {
		return ToolResult{}, errors.New("artifact exceeds maximum size")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return ToolResult{}, err
	}
	temp, err := os.CreateTemp(filepath.Dir(target), ".mcp-bridge-artifact-*")
	if err != nil {
		return ToolResult{}, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	hash := sha256.New()
	written, err := io.CopyN(io.MultiWriter(temp, hash), response.Body, maxArtifactBytes+1)
	if err != nil && !errors.Is(err, io.EOF) {
		temp.Close()
		return ToolResult{}, err
	}
	if written > maxArtifactBytes {
		temp.Close()
		return ToolResult{}, errors.New("artifact exceeds maximum size")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if expectedHash != "" && !strings.EqualFold(expectedHash, digest) {
		temp.Close()
		return ToolResult{}, errors.New("artifact SHA-256 mismatch")
	}
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return ToolResult{}, err
	}
	if err := temp.Close(); err != nil {
		return ToolResult{}, err
	}
	if err := os.Rename(tempName, target); err != nil {
		return ToolResult{}, err
	}
	return ToolResult{Text: fmt.Sprintf("Downloaded %d bytes to %s (sha256=%s).", written, input.Path, digest), SHA256: digest}, nil
}

// artifactClient returns the HTTP client used for artifact downloads, keeping
// the redirect guard in place even when a client is injected for tests.
func (s *Service) artifactClient() *http.Client {
	client := &http.Client{Timeout: 2 * time.Minute}
	if s.HTTPClient != nil {
		copied := *s.HTTPClient
		client = &copied
		if client.Timeout == 0 {
			client.Timeout = 2 * time.Minute
		}
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return validateArtifactURL(req.URL)
	}
	return client
}

func validateArtifactURL(value *url.URL) error {
	if value == nil || value.Scheme != "https" || value.User != nil || value.Hostname() == "" {
		return errors.New("artifact URL must be HTTPS")
	}
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	allowed := false
	for _, suffix := range []string{"openai.com", "openai.org", "chatgpt.com", "oaiusercontent.com"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("artifact host is not allowed: %s", host)
	}
	return nil
}
