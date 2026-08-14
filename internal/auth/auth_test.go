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
