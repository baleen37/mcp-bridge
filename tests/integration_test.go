package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baleen37/mcp-bridge/internal/auth"
	"github.com/baleen37/mcp-bridge/internal/config"
	bridgemcp "github.com/baleen37/mcp-bridge/internal/mcp"
	"github.com/baleen37/mcp-bridge/internal/store"
	"github.com/baleen37/mcp-bridge/internal/tools"
	"github.com/baleen37/mcp-bridge/internal/workspace"
)

func TestOAuthMCPToolFlow(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "sample.txt"), []byte("hello\nworld\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	cfg, err := config.Load(map[string]string{
		"MCP_BRIDGE_ALLOWED_ROOTS":   root,
		"MCP_BRIDGE_PUBLIC_BASE_URL": "https://example.test",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	provider := &auth.Provider{Store: state, PublicBaseURL: cfg.PublicBaseURL}
	if err := provider.InitializeOwner([]byte("test-owner-password-123456")); err != nil {
		t.Fatal(err)
	}
	registry := &workspace.Registry{AllowedRoots: cfg.AllowedRoots, WorktreeRoot: cfg.WorktreeRoot, Store: state, Git: workspace.ExecGitRunner{}}
	service := &tools.Service{Workspaces: registry, Command: tools.OSCommandRunner{}}
	handler := bridgemcp.NewHTTPHandler(cfg, provider, bridgemcp.NewServer(cfg, provider, registry, service))
	server := httptest.NewServer(handler)
	defer server.Close()

	tokens := authorize(t, server.Client(), server.URL, provider)
	initialize := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "integration", "version": "1"}},
	}
	response, sessionID := callMCP(t, server.Client(), server.URL, tokens.AccessToken, "", initialize)
	if response["error"] != nil || sessionID == "" {
		t.Fatalf("initialize response=%#v session=%q", response, sessionID)
	}
	listResponse, _ := callMCP(t, server.Client(), server.URL, tokens.AccessToken, sessionID, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}})
	if result, ok := listResponse["result"].(map[string]any); !ok || len(result["tools"].([]any)) != 8 {
		t.Fatalf("tools/list response=%#v", listResponse)
	}

	opened := callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 3, "open_workspace", map[string]any{"path": project, "mode": "checkout"})
	workspaceID := structuredString(t, opened, "workspace_id")
	callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 4, "read_file", map[string]any{"workspace_id": workspaceID, "path": "sample.txt"})
	callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 5, "apply_patch", map[string]any{"workspace_id": workspaceID, "path": "sample.txt", "edits": []map[string]string{{"old_text": "hello", "new_text": "edited"}}})
	callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 6, "exec_command", map[string]any{"workspace_id": workspaceID, "cmd": "printf command"})
	callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 7, "grep_files", map[string]any{"workspace_id": workspaceID, "pattern": "edited"})
	callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 8, "list_dir", map[string]any{"workspace_id": workspaceID, "path": "."})

	traversal := callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 10, "read_file", map[string]any{"workspace_id": workspaceID, "path": "../outside.txt"})
	if result := traversal["result"].(map[string]any); result["isError"] != true {
		t.Fatalf("traversal unexpectedly succeeded: %#v", traversal)
	}
	invalid := callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 11, "open_workspace", map[string]any{"path": t.TempDir(), "mode": "checkout"})
	if result := invalid["result"].(map[string]any); result["isError"] != true {
		t.Fatalf("invalid workspace unexpectedly succeeded: %#v", invalid)
	}

	gitRepo := filepath.Join(root, "git-repo")
	initGitRepo(t, gitRepo)
	callTool(t, server.Client(), server.URL, tokens.AccessToken, sessionID, 12, "open_workspace", map[string]any{"path": gitRepo, "mode": "worktree", "base_ref": "HEAD"})
}

func authorize(t *testing.T, client *http.Client, origin string, provider *auth.Provider) auth.TokenResponse {
	t.Helper()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	registered := postJSON(t, client, origin+"/register", map[string]any{"client_name": "integration", "redirect_uris": []string{"https://chatgpt.com/callback"}})
	clientID := registered["client_id"].(string)
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789-._~"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	query := url.Values{
		"client_id": {clientID}, "redirect_uri": {"https://chatgpt.com/callback"}, "response_type": {"code"},
		"scope": {"devspace"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	approvalResponse, err := client.Get(origin + "/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(approvalResponse.Body)
	approvalResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	marker := `name="approval_id" value="`
	start := strings.Index(string(body), marker)
	if start < 0 {
		t.Fatalf("approval page missing approval id: %s", body)
	}
	start += len(marker)
	end := strings.Index(string(body)[start:], `"`)
	if end < 0 {
		t.Fatal("approval id is not closed")
	}
	approvalID := string(body)[start : start+end]
	form := url.Values{"approval_id": {approvalID}, "password": {"test-owner-password-123456"}}
	approvalRequest, err := http.NewRequest(http.MethodPost, origin+"/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approvalResponse, err = client.Do(approvalRequest)
	if err != nil {
		t.Fatal(err)
	}
	location := approvalResponse.Header.Get("Location")
	approvalResponse.Body.Close()
	if approvalResponse.StatusCode != http.StatusFound {
		t.Fatalf("approval status=%d", approvalResponse.StatusCode)
	}
	redirect, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {redirect.Query().Get("code")}, "redirect_uri": {"https://chatgpt.com/callback"}, "code_verifier": {verifier}}
	tokenRequest, err := http.NewRequest(http.MethodPost, origin+"/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse, err := client.Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResponse.Body.Close()
	var tokens auth.TokenResponse
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokenResponse.StatusCode != http.StatusOK || tokens.AccessToken == "" {
		t.Fatalf("token status=%d response=%#v", tokenResponse.StatusCode, tokens)
	}
	return tokens
}

func callMCP(t *testing.T, client *http.Client, origin, token, sessionID string, payload map[string]any) (map[string]any, string) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, origin+"/mcp", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		request.Header.Set("Mcp-Session-Id", sessionID)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var value map[string]any
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatalf("MCP status=%d decode: %v", response.StatusCode, err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("MCP status=%d response=%#v", response.StatusCode, value)
	}
	return value, response.Header.Get("Mcp-Session-Id")
}

func callTool(t *testing.T, client *http.Client, origin, token, sessionID string, id int, name string, arguments map[string]any) map[string]any {
	response, _ := callMCP(t, client, origin, token, sessionID, map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": arguments}})
	return response
}

func structuredString(t *testing.T, response map[string]any, key string) string {
	t.Helper()
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result: %#v", response)
	}
	structured, ok := result["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("missing structured content: %#v", response)
	}
	value, ok := structured[key].(string)
	if !ok {
		t.Fatalf("missing structured field %q: %#v", key, response)
	}
	return value
}

func postJSON(t *testing.T, client *http.Client, endpoint string, value map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("POST %s status=%d response=%#v", endpoint, response.StatusCode, result)
	}
	return result
}

func initGitRepo(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"git", "init", "-q", path},
		{"git", "-C", path, "config", "user.email", "test@example.com"},
		{"git", "-C", path, "config", "user.name", "Integration Test"},
	} {
		if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", strings.Join(command, " "), err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(path, "tracked.txt"), []byte("tracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{{"git", "-C", path, "add", "tracked.txt"}, {"git", "-C", path, "commit", "-qm", "initial"}} {
		if output, err := exec.CommandContext(context.Background(), command[0], command[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", strings.Join(command, " "), err, output)
		}
	}
}
