package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/baleen37/mcp-bridge/internal/auth"
	"github.com/baleen37/mcp-bridge/internal/config"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

const modernMCPProtocolVersion = "2026-07-28"

// knownMCPProtocolVersions lists the revisions this bridge recognizes, newest
// last. Versions are date strings, so an unrecognized value must not be ordered
// against them: plain string comparison would sort "garbage" above every real
// revision and silently pick the wrong transport.
var knownMCPProtocolVersions = []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}

// usesModernTransport reports whether the request declares a protocol revision
// at or beyond modernMCPProtocolVersion, which is served by the stateless
// transport. Unknown or absent versions fall back to the stateful transport.
func usesModernTransport(r *http.Request) bool {
	version := r.Header.Get("Mcp-Protocol-Version")
	if !slices.Contains(knownMCPProtocolVersions, version) {
		return false
	}
	return version >= modernMCPProtocolVersion
}

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
	// Method-qualified patterns let ServeMux answer a method mismatch with 405
	// plus the Allow header, and make GET also match HEAD.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", protectedResourceMetadata(cfg))
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", authorizationServerMetadata(cfg))
	mux.HandleFunc("POST /register", registrationHandler(provider))
	mux.HandleFunc("GET /authorize", authorizationPageHandler(provider))
	mux.HandleFunc("POST /authorize", approvalHandler(provider))
	mux.HandleFunc("POST /token", tokenHandler(provider))
	mux.Handle("/mcp", protectedMCPHandler(cfg, provider, statefulStream, statelessStream))
	return requestLogger(logOutput, hostMiddleware(cfg, mux))
}

func requestLogger(output io.Writer, next http.Handler) http.Handler {
	if output == nil {
		output = io.Discard
	}
	logger := slog.New(slog.NewTextHandler(output, nil))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := &statusResponseWriter{ResponseWriter: w}
		next.ServeHTTP(response, r)
		// Log only the presence of credentials, never their values, and never
		// the raw query, which carries authorization codes.
		logger.Info("request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", response.statusCode()),
			slog.String("content_type", response.Header().Get("Content-Type")),
			slog.Bool("auth", strings.TrimSpace(r.Header.Get("Authorization")) != ""),
			slog.Bool("session", r.Header.Get("Mcp-Session-Id") != ""),
			slog.String("protocol", r.Header.Get("Mcp-Protocol-Version")))
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
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"resource":              cfg.MCPURL(),
			"authorization_servers": []string{strings.TrimRight(cfg.PublicBaseURL, "/")},
			"scopes_supported":      []string{"devspace"},
		})
	}
}

func authorizationServerMetadata(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
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
		writeCredentialJSON(w, http.StatusCreated, map[string]any{
			"client_id":                  client.ID,
			"client_name":                client.Name,
			"redirect_uris":              client.RedirectURIs,
			"token_endpoint_auth_method": "none",
		})
	}
}

func authorizationPageHandler(provider *auth.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		input := auth.AuthorizationInput{
			ClientID: query.Get("client_id"), RedirectURI: query.Get("redirect_uri"),
			ResponseType: query.Get("response_type"), Scope: query.Get("scope"),
			State: query.Get("state"), CodeChallenge: query.Get("code_challenge"),
			CodeChallengeMethod: query.Get("code_challenge_method"), Resource: query.Get("resource"),
		}
		page, err := provider.BeginAuthorization(input)
		if err != nil {
			// RFC 6749 4.1.2.1: only redirect an error once the client and its
			// redirect URI check out. Otherwise render it, so an unvalidated URI
			// can never be used as an open redirect.
			var redirectable *auth.RedirectableError
			if errors.As(err, &redirectable) {
				http.Redirect(w, r, redirectable.RedirectURL(), http.StatusFound)
				return
			}
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
		// The approval ID is a bearer-equivalent secret; keep it out of caches.
		w.Header().Set("Cache-Control", "no-store")
		_ = approvalTemplate.Execute(w, data)
	}
}

func approvalHandler(provider *auth.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid approval form")
			return
		}
		redirect, err := provider.Approve(r.FormValue("approval_id"), r.FormValue("password"))
		if err != nil {
			if errors.Is(err, auth.ErrTooManyAttempts) {
				writeOAuthError(w, http.StatusTooManyRequests, "access_denied", "too many failed attempts; try again later")
				return
			}
			writeOAuthError(w, http.StatusUnauthorized, "access_denied", "owner approval failed")
			return
		}
		// gosec reads redirect as attacker-controlled because it cannot follow the
		// value back past the store. It is not: Approve builds it from the stored
		// code's RedirectURI, RegisterClient accepts a redirect only when
		// allowedRedirectURI passes it, and BeginAuthorization requires an exact
		// match against that registered list. The form supplies the approval ID and
		// password, never the destination.
		http.Redirect(w, r, redirect, http.StatusFound) //nolint:gosec // G710: destination is validated at registration and matched exactly at authorization
	}
}

func tokenHandler(provider *auth.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			// RFC 6749 §5.2 distinguishes a malformed request from a bad grant;
			// collapsing both into invalid_grant leaves clients unable to tell
			// a missing parameter from an expired code.
			if errors.Is(err, auth.ErrInvalidRequest) {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameter")
				return
			}
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid grant")
			return
		}
		writeCredentialJSON(w, http.StatusOK, response)
	}
}

func protectedMCPHandler(cfg config.Config, provider *auth.Provider, statefulStream, statelessStream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if localAuthBypassRequest(r) {
			stream := statefulStream
			if usesModernTransport(r) {
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
		if usesModernTransport(r) {
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

// writeCredentialJSON writes a response carrying tokens or other credentials.
// RFC 6749 §5.1 requires no-store on these so intermediaries never retain them.
func writeCredentialJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, value)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeCredentialJSON(w, status, map[string]string{"error": code, "error_description": description})
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
