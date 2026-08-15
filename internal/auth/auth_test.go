package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baleen37/mcp-bridge/internal/store"
)

func testProvider(t *testing.T) *Provider {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Provider{Store: db, PublicBaseURL: "https://example.test", AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour}
}

func TestPasswordHashAndVerification(t *testing.T) {
	hash, err := HashPassword([]byte("owner-password-123456"))
	if err != nil {
		t.Fatal(err)
	}
	if string(hash) == "owner-password-123456" {
		t.Fatal("password was stored as plaintext")
	}
	if !VerifyPassword(hash, []byte("owner-password-123456")) {
		t.Fatal("correct password did not verify")
	}
	if VerifyPassword(hash, []byte("wrong-password")) {
		t.Fatal("wrong password verified")
	}
}

func TestInitializeOwnerRequiresAtLeastFourCharacters(t *testing.T) {
	t.Run("accepts four characters", func(t *testing.T) {
		p := testProvider(t)
		if err := p.InitializeOwner([]byte("abcd")); err != nil {
			t.Fatalf("four-character password was rejected: %v", err)
		}
	})

	t.Run("rejects three characters", func(t *testing.T) {
		p := testProvider(t)
		if err := p.InitializeOwner([]byte("abc")); err == nil {
			t.Fatal("three-character password was accepted")
		}
	})

	// Three multi-byte runes are nine bytes; the length check must count
	// characters, not bytes, so this must still be rejected as too short.
	t.Run("counts unicode characters", func(t *testing.T) {
		p := testProvider(t)
		if err := p.InitializeOwner([]byte("日本語")); err == nil {
			t.Fatal("three-character multi-byte password was accepted")
		}
	})
}

func TestOAuthPKCEFlow(t *testing.T) {
	p := testProvider(t)
	if err := p.InitializeOwner([]byte("owner-password-123456")); err != nil {
		t.Fatal(err)
	}
	client, err := p.RegisterClient(RegisterInput{
		Name:         "test client",
		RedirectURIs: []string{"https://chatgpt.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789-._~"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	page, err := p.BeginAuthorization(AuthorizationInput{
		ClientID:            client.ID,
		RedirectURI:         client.RedirectURIs[0],
		ResponseType:        "code",
		Scope:               "devspace",
		State:               "state-123",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Resource:            "https://example.test/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := p.Approve(page.ApprovalID, "owner-password-123456")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("state") != "state-123" {
		t.Fatalf("state was not preserved: %s", redirect)
	}
	response, err := p.ExchangeCode(TokenInput{
		ClientID:     client.ID,
		Code:         parsed.Query().Get("code"),
		RedirectURI:  client.RedirectURIs[0],
		CodeVerifier: verifier,
		Resource:     "https://example.test/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" || response.TokenType != "Bearer" {
		t.Fatalf("incomplete token response: %#v", response)
	}
	if err := p.AuthenticateBearer(response.AccessToken, "https://example.test/mcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ExchangeCode(TokenInput{
		ClientID: client.ID, Code: parsed.Query().Get("code"), RedirectURI: client.RedirectURIs[0], CodeVerifier: verifier,
	}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("replayed code error = %v, want ErrInvalidGrant", err)
	}
}

func TestRegisterClientRestrictsRedirectHosts(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{name: "chatgpt", uri: "https://chatgpt.com/callback", ok: true},
		{name: "openai", uri: "https://chat.openai.com/callback", ok: true},
		{name: "localhost http", uri: "http://localhost:8080/callback", ok: true},
		{name: "loopback https", uri: "https://127.0.0.1/callback", ok: true},
		{name: "evil host", uri: "https://evil.example/callback", ok: false},
		{name: "fragment", uri: "https://chatgpt.com/callback#fragment", ok: false},
		{name: "wrong scheme", uri: "ftp://chatgpt.com/callback", ok: false},
		{name: "public http", uri: "http://chatgpt.com/callback", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProvider(t)
			_, err := p.RegisterClient(RegisterInput{Name: tc.name, RedirectURIs: []string{tc.uri}})
			if (err == nil) != tc.ok {
				t.Fatalf("RegisterClient(%q) error = %v, want success=%v", tc.uri, err, tc.ok)
			}
		})
	}
}

func TestRegisterClientAllowsConfiguredRedirectHost(t *testing.T) {
	p := testProvider(t)
	p.RedirectHosts = []string{"trusted.example"}
	if _, err := p.RegisterClient(RegisterInput{RedirectURIs: []string{"https://trusted.example/callback"}}); err != nil {
		t.Fatalf("configured redirect host rejected: %v", err)
	}
}

func TestOAuthRejectsWrongVerifierAndRotatesRefreshToken(t *testing.T) {
	p := testProvider(t)
	if err := p.InitializeOwner([]byte("owner-password-123456")); err != nil {
		t.Fatal(err)
	}
	client, err := p.RegisterClient(RegisterInput{Name: "test", RedirectURIs: []string{"https://chatgpt.com/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "verifier-value"
	hash := sha256.Sum256([]byte(verifier))
	page, err := p.BeginAuthorization(AuthorizationInput{
		ClientID: client.ID, RedirectURI: client.RedirectURIs[0], ResponseType: "code", Scope: "devspace",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(hash[:]), CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := p.Approve(page.ApprovalID, "owner-password-123456")
	if err != nil {
		t.Fatal(err)
	}
	code := mustParseCode(t, redirect)
	if _, err := p.ExchangeCode(TokenInput{ClientID: client.ID, Code: code, RedirectURI: client.RedirectURIs[0], CodeVerifier: "wrong"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("wrong verifier error = %v, want ErrInvalidGrant", err)
	}
	response, err := p.ExchangeCode(TokenInput{ClientID: client.ID, Code: code, RedirectURI: client.RedirectURIs[0], CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := p.Refresh(TokenInput{ClientID: client.ID, RefreshToken: response.RefreshToken, Resource: "https://example.test/mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RefreshToken == response.RefreshToken || refreshed.AccessToken == response.AccessToken {
		t.Fatal("refresh token rotation did not create new credentials")
	}
	if _, err := p.Refresh(TokenInput{ClientID: client.ID, RefreshToken: response.RefreshToken}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("reused refresh token error = %v, want ErrInvalidGrant", err)
	}
}

func mustParseCode(t *testing.T, redirect string) string {
	t.Helper()
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	code := parsed.Query().Get("code")
	if strings.TrimSpace(code) == "" {
		t.Fatalf("redirect has no code: %s", redirect)
	}
	return code
}

// registerTestClient registers a client and returns its ID and redirect URI.
func registerTestClient(t *testing.T, provider *Provider) (string, string) {
	t.Helper()
	const redirect = "https://chatgpt.com/connector_platform_oauth_redirect"
	client, err := provider.RegisterClient(RegisterInput{Name: "test", RedirectURIs: []string{redirect}})
	if err != nil {
		t.Fatal(err)
	}
	return client.ID, redirect
}

func TestAuthorizationErrorsRedirectOnlyAfterClientIsValidated(t *testing.T) {
	provider := testProvider(t)
	clientID, redirect := registerTestClient(t, provider)

	valid := AuthorizationInput{
		ClientID: clientID, RedirectURI: redirect, ResponseType: "code",
		Scope: "devspace", State: "xyz", CodeChallenge: "challenge", CodeChallengeMethod: "S256",
	}

	t.Run("unknown client renders, never redirects", func(t *testing.T) {
		input := valid
		input.ClientID = "does-not-exist"
		_, err := provider.BeginAuthorization(input)
		var redirectable *RedirectableError
		if errors.As(err, &redirectable) {
			t.Fatal("unknown client produced a redirect; that is an open redirect")
		}
	})

	t.Run("unregistered redirect URI renders, never redirects", func(t *testing.T) {
		input := valid
		input.RedirectURI = "https://attacker.example/steal"
		_, err := provider.BeginAuthorization(input)
		var redirectable *RedirectableError
		if errors.As(err, &redirectable) {
			t.Fatal("unregistered redirect URI produced a redirect; that is an open redirect")
		}
	})

	for _, testCase := range []struct {
		name   string
		mutate func(*AuthorizationInput)
		want   string
	}{
		{"bad response type", func(i *AuthorizationInput) { i.ResponseType = "token" }, "unsupported_response_type"},
		{"bad scope", func(i *AuthorizationInput) { i.Scope = "other" }, "invalid_scope"},
		{"missing PKCE", func(i *AuthorizationInput) { i.CodeChallenge = "" }, "invalid_request"},
		{"plain PKCE", func(i *AuthorizationInput) { i.CodeChallengeMethod = "plain" }, "invalid_request"},
		{"wrong resource", func(i *AuthorizationInput) { i.Resource = "https://elsewhere.test/mcp" }, "invalid_target"},
	} {
		t.Run(testCase.name+" redirects to the client", func(t *testing.T) {
			input := valid
			testCase.mutate(&input)
			_, err := provider.BeginAuthorization(input)
			var redirectable *RedirectableError
			if !errors.As(err, &redirectable) {
				t.Fatalf("err = %v, want a RedirectableError so the client learns why", err)
			}
			if redirectable.Code != testCase.want {
				t.Errorf("error code = %q, want %q", redirectable.Code, testCase.want)
			}
			target, parseErr := url.Parse(redirectable.RedirectURL())
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if got := target.Query().Get("error"); got != testCase.want {
				t.Errorf("redirect error param = %q, want %q", got, testCase.want)
			}
			if got := target.Query().Get("state"); got != "xyz" {
				t.Errorf("redirect state = %q, want %q", got, "xyz")
			}
			if !strings.HasPrefix(redirectable.RedirectURL(), redirect) {
				t.Errorf("redirect target = %q, want it under %q", redirectable.RedirectURL(), redirect)
			}
		})
	}
}

func TestResourceComparisonToleratesCaseAndTrailingSlash(t *testing.T) {
	for _, testCase := range []struct {
		left, right string
		want        bool
	}{
		{"https://example.test/mcp", "https://example.test/mcp", true},
		{"HTTPS://EXAMPLE.TEST/mcp", "https://example.test/mcp", true},
		{"https://example.test/mcp/", "https://example.test/mcp", true},
		{"https://example.test/mcp", "https://other.test/mcp", false},
		{"https://example.test/other", "https://example.test/mcp", false},
	} {
		if got := sameResource(testCase.left, testCase.right); got != testCase.want {
			t.Errorf("sameResource(%q, %q) = %v, want %v", testCase.left, testCase.right, got, testCase.want)
		}
	}
}

func TestApproveLocksOutAfterRepeatedWrongPasswords(t *testing.T) {
	provider := testProvider(t)
	if err := provider.InitializeOwner([]byte("owner-password-123456")); err != nil {
		t.Fatal(err)
	}
	clientID, redirect := registerTestClient(t, provider)
	begin := func() string {
		t.Helper()
		page, err := provider.BeginAuthorization(AuthorizationInput{
			ClientID: clientID, RedirectURI: redirect, ResponseType: "code",
			Scope: "devspace", CodeChallenge: "challenge", CodeChallengeMethod: "S256",
		})
		if err != nil {
			t.Fatal(err)
		}
		return page.ApprovalID
	}

	for attempt := range maxApprovalAttempts {
		if _, err := provider.Approve(begin(), "wrong-password"); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("attempt %d: err = %v, want ErrUnauthorized", attempt, err)
		}
	}

	// The correct password must now be refused too, otherwise the limit only
	// slows an attacker down rather than stopping the guessing.
	if _, err := provider.Approve(begin(), "owner-password-123456"); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("after lockout err = %v, want ErrTooManyAttempts", err)
	}
}

func TestApproveResetsAttemptsAfterSuccess(t *testing.T) {
	provider := testProvider(t)
	if err := provider.InitializeOwner([]byte("owner-password-123456")); err != nil {
		t.Fatal(err)
	}
	clientID, redirect := registerTestClient(t, provider)
	begin := func() string {
		t.Helper()
		page, err := provider.BeginAuthorization(AuthorizationInput{
			ClientID: clientID, RedirectURI: redirect, ResponseType: "code",
			Scope: "devspace", CodeChallenge: "challenge", CodeChallengeMethod: "S256",
		})
		if err != nil {
			t.Fatal(err)
		}
		return page.ApprovalID
	}

	if _, err := provider.Approve(begin(), "wrong-password"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal(err)
	}
	if _, err := provider.Approve(begin(), "owner-password-123456"); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	// A success clears the counter, so the budget is available again.
	for attempt := range maxApprovalAttempts - 1 {
		if _, err := provider.Approve(begin(), "wrong-password"); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("attempt %d after reset: err = %v, want ErrUnauthorized", attempt, err)
		}
	}
}
