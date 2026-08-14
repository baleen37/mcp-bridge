package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenCreatesSchema(t *testing.T) {
	s := openTestStore(t)
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		seen[name] = true
	}
	for _, name := range []string{"owner", "oauth_clients", "oauth_codes", "oauth_access_tokens", "oauth_refresh_tokens", "workspaces"} {
		if !seen[name] {
			t.Errorf("missing table %q", name)
		}
	}
}

func TestOpenRestrictsStateDatabasePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state database mode = %o, want 600", info.Mode().Perm())
	}
}

func TestOwnerHashRoundTrip(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.OwnerHash(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OwnerHash before initialization: %v", err)
	}
	if err := s.SetOwnerHash([]byte("hash")); err != nil {
		t.Fatal(err)
	}
	hash, err := s.OwnerHash()
	if err != nil {
		t.Fatal(err)
	}
	if string(hash) != "hash" {
		t.Fatalf("owner hash = %q", hash)
	}
}

func TestAuthorizationCodeIsOneTime(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateClient(Client{ID: "client", Name: "test", RedirectURIs: []string{"https://example.test/callback"}}); err != nil {
		t.Fatal(err)
	}
	code := AuthorizationCode{
		Hash:                []byte("code-hash"),
		ClientID:            "client",
		RedirectURI:         "https://example.test/callback",
		Scope:               "devspace",
		Resource:            "https://example.test/mcp",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
		Approved:            true,
	}
	if err := s.CreateCode(code); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeCode(code.Hash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != code.ClientID {
		t.Fatalf("client id = %q", got.ClientID)
	}
	if _, err := s.ConsumeCode(code.Hash, time.Now()); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume error = %v, want ErrConsumed", err)
	}
}

func TestExpiredAccessTokenIsRejected(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateClient(Client{ID: "client", Name: "test", RedirectURIs: []string{"https://example.test/callback"}}); err != nil {
		t.Fatal(err)
	}
	token := AccessToken{
		Hash:      []byte("expired-token"),
		ClientID:  "client",
		Scope:     "devspace",
		Resource:  "https://example.test/mcp",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := s.CreateAccessToken(token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAccessToken(token.Hash, time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatalf("GetAccessToken error = %v, want ErrExpired", err)
	}
}

func TestWorkspaceRoundTrip(t *testing.T) {
	s := openTestStore(t)
	want := WorkspaceRecord{
		ID: "ws_123", Root: "/tmp/workspace", Mode: "checkout", Managed: false,
		CreatedAt: time.Now().Truncate(time.Second),
	}
	if err := s.PutWorkspace(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWorkspace(want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Root != want.Root || got.Mode != want.Mode || got.Managed != want.Managed {
		t.Fatalf("workspace = %#v, want %#v", got, want)
	}
}
