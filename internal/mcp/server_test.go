package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baleen37/mcp-bridge/internal/auth"
	"github.com/baleen37/mcp-bridge/internal/config"
	"github.com/baleen37/mcp-bridge/internal/store"
	"github.com/baleen37/mcp-bridge/internal/tools"
	"github.com/baleen37/mcp-bridge/internal/workspace"
)

func testHTTPServer(t *testing.T) (*httptest.Server, *auth.Provider, string) {
	return testHTTPServerWithArtifacts(t, false)
}

func testHTTPServerWithArtifacts(t *testing.T, artifacts bool) (*httptest.Server, *auth.Provider, string) {
	t.Helper()
	root := t.TempDir()
	state, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	cfg, err := config.Load(map[string]string{
		"MCP_BRIDGE_ALLOWED_ROOTS":   root,
		"MCP_BRIDGE_PUBLIC_BASE_URL": "https://example.test",
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ArtifactDownloadsEnabled = artifacts
	provider := &auth.Provider{Store: state, PublicBaseURL: cfg.PublicBaseURL}
	if err := provider.InitializeOwner([]byte("owner-password-123456")); err != nil {
		t.Fatal(err)
	}
	registry := &workspace.Registry{AllowedRoots: cfg.AllowedRoots, WorktreeRoot: cfg.WorktreeRoot, Store: state, Git: workspace.ExecGitRunner{}}
	service := &tools.Service{Workspaces: registry, Command: tools.OSCommandRunner{}}
	handler := NewHTTPHandler(cfg, provider, NewServer(cfg, provider, registry, service))
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, provider, root
}

func TestArtifactDownloadIsConditionallyListed(t *testing.T) {
	server, provider, _ := testHTTPServerWithArtifacts(t, true)
	tokens := issueTestToken(t, provider)
	requestBody := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	request, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	session := response.Header.Get("Mcp-Session-Id")
	response.Body.Close()
	request, err = http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	request.Header.Set("Mcp-Session-Id", session)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.Result.Tools) != 7 {
		t.Fatalf("tools = %d, want 7", len(result.Result.Tools))
	}
}

func TestHealthMetadataAndUnauthorizedMCP(t *testing.T) {
	server, _, _ := testHTTPServer(t)
	response, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", response.StatusCode)
	}
	response.Body.Close()

	response, err = http.Get(server.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if metadata["resource"] != "https://example.test/mcp" {
		t.Fatalf("metadata = %#v", metadata)
	}

	request, err := http.NewRequest(http.MethodGet, server.URL+"/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthorized MCP: status=%d challenge=%q", response.StatusCode, response.Header.Get("WWW-Authenticate"))
	}
	response.Body.Close()
}

func TestLocalAuthBypassRequiresExplicitLocalMode(t *testing.T) {
	server, _, _ := testHTTPServer(t)
	t.Setenv("MCP_BRIDGE_SKIP_TUNNEL", "1")
	t.Setenv("MCP_BRIDGE_LOCAL_AUTH_BYPASS", "1")
	request, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"local","version":"1"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("local bypass status = %d", response.StatusCode)
	}
	response.Body.Close()

	t.Setenv("MCP_BRIDGE_SKIP_TUNNEL", "")
	request, err = http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"local","version":"1"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bypass without skip-tunnel status = %d", response.StatusCode)
	}
	response.Body.Close()

	t.Setenv("MCP_BRIDGE_SKIP_TUNNEL", "1")
	loopback := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	loopback.RemoteAddr = "127.0.0.1:1234"
	if localAuthBypassRequest(loopback) == false {
		t.Fatal("loopback request was not recognized")
	}
	remote := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", nil)
	remote.RemoteAddr = "192.0.2.10:1234"
	if localAuthBypassRequest(remote) {
		t.Fatal("remote request unexpectedly recognized as local")
	}
}

func TestRequestLoggerRedactsCredentials(t *testing.T) {
	var logs strings.Builder
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	request := httptest.NewRequest(http.MethodGet, "/mcp?code=query-secret", nil)
	request.Header.Set("Authorization", "Bearer bearer-secret")
	request.Header.Set("Mcp-Session-Id", "session-secret")
	request.Header.Set("Mcp-Protocol-Version", "2025-11-25")

	requestLogger(&logs, next).ServeHTTP(httptest.NewRecorder(), request)
	value := logs.String()
	for _, unwanted := range []string{"query-secret", "bearer-secret", "session-secret"} {
		if strings.Contains(value, unwanted) {
			t.Fatalf("log contains sensitive value %q: %s", unwanted, value)
		}
	}
	for _, wanted := range []string{"method=GET", "path=/mcp", "status=418", "auth=true", "session=true", "protocol=2025-11-25"} {
		if !strings.Contains(value, wanted) {
			t.Fatalf("log missing %q: %s", wanted, value)
		}
	}
}

func TestAuthorizedMCPListsSevenTools(t *testing.T) {
	server, provider, _ := testHTTPServerWithArtifacts(t, true)
	client, err := provider.RegisterClient(auth.RegisterInput{Name: "test", RedirectURIs: []string{"https://chatgpt.com/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789-._~"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	page, err := provider.BeginAuthorization(auth.AuthorizationInput{
		ClientID: client.ID, RedirectURI: client.RedirectURIs[0], ResponseType: "code", Scope: "devspace",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := provider.Approve(page.ApprovalID, "owner-password-123456")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := provider.ExchangeCode(auth.TokenInput{ClientID: client.ID, Code: parsed.Query().Get("code"), RedirectURI: client.RedirectURIs[0], CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}

	requestBody := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	request, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("initialize status=%d body=%s", response.StatusCode, body)
	}
	sessionID := response.Header.Get("Mcp-Session-Id")
	response.Body.Close()
	if sessionID == "" {
		t.Fatal("initialize did not return MCP session id")
	}

	requestBody = strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	request, err = http.NewRequest(http.MethodPost, server.URL+"/mcp", requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	request.Header.Set("Mcp-Session-Id", sessionID)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(result.Result.Tools) != 7 {
		t.Fatalf("tools/list status=%d tools=%d result=%#v", response.StatusCode, len(result.Result.Tools), result)
	}
	seen := map[string]bool{}
	for _, tool := range result.Result.Tools {
		seen[tool.Name] = true
	}
	for _, name := range []string{"open_workspace", "read_file", "grep_files", "list_dir", "apply_patch", "exec_command", "download_artifact"} {
		if !seen[name] {
			t.Errorf("missing tool %q", name)
		}
	}
}

func TestToolsExposeMinimalPublicSchemas(t *testing.T) {
	server, provider, _ := testHTTPServerWithArtifacts(t, true)
	tokens := issueTestToken(t, provider)
	callMCP(t, server.URL, tokens.AccessToken, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`)
	body := callMCP(t, server.URL, tokens.AccessToken, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`)
	var response struct {
		Result struct {
			Tools []struct {
				Name         string         `json:"name"`
				InputSchema  map[string]any `json:"inputSchema"`
				OutputSchema map[string]any `json:"outputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"apply_patch", "download_artifact", "exec_command", "grep_files", "list_dir", "open_workspace", "read_file"}
	if len(response.Result.Tools) != len(wantNames) {
		t.Fatalf("tools = %d, want %d", len(response.Result.Tools), len(wantNames))
	}
	for i, want := range wantNames {
		tool := response.Result.Tools[i]
		if tool.Name != want {
			t.Fatalf("tool[%d] = %q, want %q", i, tool.Name, want)
		}
		if tool.OutputSchema["additionalProperties"] != false {
			t.Fatalf("%s output schema is not closed: %#v", want, tool.OutputSchema)
		}
		properties, ok := tool.OutputSchema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s output properties missing: %#v", want, tool.OutputSchema)
		}
		wantFields := map[string][]string{
			"open_workspace":    {"workspace_id", "root", "instructions"},
			"read_file":         {"text"},
			"grep_files":        {"text"},
			"list_dir":          {"text"},
			"apply_patch":       {"text"},
			"exec_command":      {"text", "exit_code", "truncated", "timed_out"},
			"download_artifact": {"text", "sha256"},
		}[want]
		if len(properties) != len(wantFields) {
			t.Fatalf("%s output properties = %#v, want %v", want, properties, wantFields)
		}
		for _, field := range wantFields {
			if _, ok := properties[field]; !ok {
				t.Fatalf("%s missing output field %q", want, field)
			}
		}
	}
	allowedExecInputs := map[string]bool{"workspace_id": true, "cmd": true, "workdir": true, "timeout_ms": true, "max_output_tokens": true}
	for _, tool := range response.Result.Tools {
		if tool.Name != "exec_command" {
			continue
		}
		properties, ok := tool.InputSchema["properties"].(map[string]any)
		if !ok || len(properties) != len(allowedExecInputs) {
			t.Fatalf("exec input schema = %#v", tool.InputSchema)
		}
		for field := range properties {
			if !allowedExecInputs[field] {
				t.Fatalf("unexpected exec input %q", field)
			}
		}
	}
}

func callMCP(t *testing.T, endpoint, token, payload string) []byte {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint+"/mcp", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	if strings.Contains(payload, `"method":"server/discover"`) {
		request.Header.Set("Mcp-Protocol-Version", "2026-07-28")
		request.Header.Set("Mcp-Method", "server/discover")
	} else if strings.Contains(payload, `"method":"tools/list"`) {
		request.Header.Set("Mcp-Protocol-Version", "2026-07-28")
		request.Header.Set("Mcp-Method", "tools/list")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("MCP status = %d, body = %s", response.StatusCode, body)
	}
	return body
}

func TestModernMCPUsesStatelessTransport(t *testing.T) {
	server, provider, _ := testHTTPServer(t)
	tokens := issueTestToken(t, provider)

	requestBody := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`)
	request, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "server/discover")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("discover status=%d body=%s", response.StatusCode, body)
	}

	requestBody = strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`)
	request, err = http.NewRequest(http.MethodPost, server.URL+"/mcp", requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "tools/list")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("tools/list status=%d body=%s", response.StatusCode, body)
	}
	var result struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(result.Result.Tools) != 6 {
		t.Fatalf("tools/list status=%d tools=%d result=%#v", response.StatusCode, len(result.Result.Tools), result)
	}
}

func issueTestToken(t *testing.T, provider *auth.Provider) auth.TokenResponse {
	t.Helper()
	client, err := provider.RegisterClient(auth.RegisterInput{Name: "test", RedirectURIs: []string{"https://chatgpt.com/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789-._~"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	page, err := provider.BeginAuthorization(auth.AuthorizationInput{
		ClientID: client.ID, RedirectURI: client.RedirectURIs[0], ResponseType: "code", Scope: "devspace",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := provider.Approve(page.ApprovalID, "owner-password-123456")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := provider.ExchangeCode(auth.TokenInput{
		ClientID: client.ID, Code: parsed.Query().Get("code"), RedirectURI: client.RedirectURIs[0], CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func TestHTTPHandlerRejectsUnexpectedHost(t *testing.T) {
	server, _, _ := testHTTPServer(t)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "attacker.example"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected host status = %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestAuthorizedMCPAllowsConfiguredPublicHost(t *testing.T) {
	server, provider, _ := testHTTPServer(t)
	client, err := provider.RegisterClient(auth.RegisterInput{Name: "test", RedirectURIs: []string{"https://chatgpt.com/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789-._~"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	page, err := provider.BeginAuthorization(auth.AuthorizationInput{
		ClientID: client.ID, RedirectURI: client.RedirectURIs[0], ResponseType: "code", Scope: "devspace",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := provider.Approve(page.ApprovalID, "owner-password-123456")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := provider.ExchangeCode(auth.TokenInput{ClientID: client.ID, Code: parsed.Query().Get("code"), RedirectURI: client.RedirectURIs[0], CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}

	requestBody := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	request, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "example.test"
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("configured public host status=%d body=%s", response.StatusCode, body)
	}
}
