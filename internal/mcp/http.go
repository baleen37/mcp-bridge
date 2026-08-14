package mcp

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/baleen37/mcp-bridge/internal/auth"
	"github.com/baleen37/mcp-bridge/internal/config"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

const modernMCPProtocolVersion = "2026-07-28"

func NewHTTPHandler(cfg config.Config, provider *auth.Provider, server *sdkmcp.Server) http.Handler {
	return newHTTPHandler(cfg, provider, server, os.Stderr)
}

func newHTTPHandler(cfg config.Config, provider *auth.Provider, server *sdkmcp.Server, logOutput io.Writer) http.Handler {
	streamOptions := &sdkmcp.StreamableHTTPOptions{
		JSONResponse:               true,
		DisableLocalhostProtection: true,
	}
	statefulStream := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server { return server }, streamOptions)
	statelessStream := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server { return server }, &sdkmcp.StreamableHTTPOptions{
		JSONResponse:               true,
		Stateless:                  true,
		DisableLocalhostProtection: true,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", protectedResourceMetadata(cfg))
	mux.HandleFunc("/.well-known/oauth-authorization-server", authorizationServerMetadata(cfg))
	mux.HandleFunc("/register", registrationHandler(provider))
	mux.HandleFunc("/authorize", authorizationHandler(provider, cfg))
	mux.HandleFunc("/token", tokenHandler(provider))
	mux.Handle("/mcp", protectedMCPHandler(cfg, provider, statefulStream, statelessStream))
	return requestLogger(logOutput, hostMiddleware(cfg, mux))
}

func requestLogger(output io.Writer, next http.Handler) http.Handler {
	if output == nil {
		output = io.Discard
	}
	logger := log.New(output, "mcp-bridge ", log.LstdFlags)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := &statusResponseWriter{ResponseWriter: w}
		next.ServeHTTP(response, r)
		logger.Printf("request method=%s path=%s status=%d content_type=%q auth=%t session=%t protocol=%s",
			r.Method, r.URL.Path, response.statusCode(), response.Header().Get("Content-Type"),
			strings.TrimSpace(r.Header.Get("Authorization")) != "", r.Header.Get("Mcp-Session-Id") != "", r.Header.Get("Mcp-Protocol-Version"))
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(value []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(value)
}

func (w *statusResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func protectedResourceMetadata(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"resource":              cfg.MCPURL(),
			"authorization_servers": []string{strings.TrimRight(cfg.PublicBaseURL, "/")},
			"scopes_supported":      []string{"devspace"},
		})
	}
}

func authorizationServerMetadata(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		base := strings.TrimRight(cfg.PublicBaseURL, "/")
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"registration_endpoint":                 base + "/register",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"scopes_supported":                      []string{"devspace"},
			"token_endpoint_auth_methods_supported": []string{"none"},
		})
	}
}

func registrationHandler(provider *auth.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		var input struct {
			ClientName   string   `json:"client_name"`
			RedirectURIs []string `json:"redirect_uris"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&input); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid registration request")
			return
		}
		client, err := provider.RegisterClient(auth.RegisterInput{Name: input.ClientName, RedirectURIs: input.RedirectURIs})
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid client metadata")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"client_id":                  client.ID,
			"client_name":                client.Name,
			"redirect_uris":              client.RedirectURIs,
			"token_endpoint_auth_method": "none",
		})
	}
}

func authorizationHandler(provider *auth.Provider, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			input := auth.AuthorizationInput{
				ClientID: r.URL.Query().Get("client_id"), RedirectURI: r.URL.Query().Get("redirect_uri"),
				ResponseType: r.URL.Query().Get("response_type"), Scope: r.URL.Query().Get("scope"),
				State: r.URL.Query().Get("state"), CodeChallenge: r.URL.Query().Get("code_challenge"),
				CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"), Resource: r.URL.Query().Get("resource"),
			}
			page, err := provider.BeginAuthorization(input)
			if err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid authorization request")
				return
			}
			data := struct {
				ApprovalID string
				ClientName string
				Scope      string
				Resource   string
			}{page.ApprovalID, page.ClientName, page.Scope, page.Resource}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := approvalTemplate.Execute(w, data); err != nil {
				return
			}
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid approval form")
				return
			}
			redirect, err := provider.Approve(r.FormValue("approval_id"), r.FormValue("password"))
			if err != nil {
				writeOAuthError(w, http.StatusUnauthorized, "access_denied", "owner approval failed")
				return
			}
			http.Redirect(w, r, redirect, http.StatusFound)
		default:
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		}
		_ = cfg
	}
}

func tokenHandler(provider *auth.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
			return
		}
		input := auth.TokenInput{ClientID: r.FormValue("client_id"), Code: r.FormValue("code"), RedirectURI: r.FormValue("redirect_uri"), CodeVerifier: r.FormValue("code_verifier"), RefreshToken: r.FormValue("refresh_token"), Resource: r.FormValue("resource")}
		var response auth.TokenResponse
		var err error
		switch r.FormValue("grant_type") {
		case "authorization_code":
			response, err = provider.ExchangeCode(input)
		case "refresh_token":
			response, err = provider.Refresh(input)
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
			return
		}
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid grant")
			return
		}
		writeJSON(w, http.StatusOK, response)
	}
}

func protectedMCPHandler(cfg config.Config, provider *auth.Provider, statefulStream, statelessStream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if localAuthBypassRequest(r) {
			stream := statefulStream
			if r.Header.Get("Mcp-Protocol-Version") >= modernMCPProtocolVersion {
				stream = statelessStream
			}
			stream.ServeHTTP(w, r)
			return
		}
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")) == "" {
			challenge := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp", scope="devspace"`, strings.TrimRight(cfg.PublicBaseURL, "/"))
			w.Header().Set("WWW-Authenticate", challenge)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
			return
		}
		if err := provider.AuthenticateBearer(strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")), cfg.MCPURL()); err != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid bearer token")
			return
		}
		stream := statefulStream
		if r.Header.Get("Mcp-Protocol-Version") >= modernMCPProtocolVersion {
			stream = statelessStream
		}
		stream.ServeHTTP(w, r)
	})
}

func localAuthBypassRequest(r *http.Request) bool {
	if os.Getenv("MCP_BRIDGE_LOCAL_AUTH_BYPASS") != "1" || os.Getenv("MCP_BRIDGE_SKIP_TUNNEL") != "1" {
		return false
	}
	host := r.Host
	if hostName, _, err := netSplitHostPort(host); err == nil {
		host = hostName
	}
	if host != "localhost" && host != "127.0.0.1" && host != "::1" && host != "[::1]" {
		return false
	}
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(remoteHost, "[]"))
	return ip != nil && ip.IsLoopback()
}

func hostMiddleware(cfg config.Config, next http.Handler) http.Handler {
	allowed := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true, "[::1]": true}
	if parsed, err := url.Parse(cfg.PublicBaseURL); err == nil {
		allowed[parsed.Host] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hostName, _, err := netSplitHostPort(host); err == nil {
			host = hostName
		}
		if !allowed[host] && !allowed[r.Host] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func netSplitHostPort(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]")
		if end >= 0 && len(value) > end+1 && value[end+1] == ':' {
			return value[1:end], value[end+2:], nil
		}
	}
	index := strings.LastIndex(value, ":")
	if index > 0 && !strings.Contains(value[index+1:], ":") {
		return value[:index], value[index+1:], nil
	}
	return value, "", fmt.Errorf("no port")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

var approvalTemplate = template.Must(template.New("approval").Parse(`<!doctype html>
<html><body><h1>Authorize mcp-bridge</h1>
<p>Allow {{.ClientName}} to access the MCP server?</p>
<p>Scope: {{.Scope}}</p><p>Resource: {{.Resource}}</p>
<form method="post" action="/authorize">
<input type="hidden" name="approval_id" value="{{.ApprovalID}}">
<label>Owner password <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Approve</button>
</form></body></html>`))
