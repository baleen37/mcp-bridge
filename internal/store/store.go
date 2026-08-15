package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound    = errors.New("record not found")
	ErrExpired     = errors.New("record expired")
	ErrConsumed    = errors.New("record already consumed")
	ErrNotApproved = errors.New("authorization not approved")
	ErrApproved    = errors.New("authorization already approved")
)

type Store struct {
	db *sql.DB
}

type Client struct {
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
}

type AuthorizationCode struct {
	Hash                []byte
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	Resource            string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Approved            bool
}

type AccessToken struct {
	Hash      []byte
	ClientID  string
	Scope     string
	Resource  string
	ExpiresAt time.Time
}

type RefreshToken struct {
	Hash      []byte
	ClientID  string
	Scope     string
	Resource  string
	ExpiresAt time.Time
}

type WorkspaceRecord struct {
	ID          string
	Root        string
	Mode        string
	SourceRoot  string
	BaseRef     string
	BaseSHA     string
	DirtySource bool
	Detached    bool
	Managed     bool
	CreatedAt   time.Time
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	store := &Store{db: db}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize state schema: %w", err)
	}
	if path != ":memory:" {
		if err := os.Chmod(path, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("restrict state database permissions: %w", err)
		}
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SetOwnerHash(hash []byte) error {
	_, err := s.db.Exec(`
INSERT INTO owner (id, password_hash)
VALUES (1, ?)
ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash`, hash)
	return err
}

func (s *Store) OwnerHash() ([]byte, error) {
	var hash []byte
	if err := s.db.QueryRow(`SELECT password_hash FROM owner WHERE id = 1`).Scan(&hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return append([]byte(nil), hash...), nil
}

func (s *Store) CreateClient(client Client) error {
	redirects, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return fmt.Errorf("encode redirect URIs: %w", err)
	}
	createdAt := client.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	_, err = s.db.Exec(`
INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at)
VALUES (?, ?, ?, ?)`, client.ID, client.Name, redirects, createdAt.Unix())
	return err
}

func (s *Store) GetClient(id string) (Client, error) {
	var client Client
	var redirects []byte
	var createdAt int64
	if err := s.db.QueryRow(`
SELECT client_id, client_name, redirect_uris, created_at
FROM oauth_clients WHERE client_id = ?`, id).Scan(&client.ID, &client.Name, &redirects, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Client{}, ErrNotFound
		}
		return Client{}, err
	}
	if err := json.Unmarshal(redirects, &client.RedirectURIs); err != nil {
		return Client{}, fmt.Errorf("decode redirect URIs: %w", err)
	}
	client.CreatedAt = time.Unix(createdAt, 0)
	return client, nil
}

func (s *Store) CreateCode(code AuthorizationCode) error {
	_, err := s.db.Exec(`
INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, state, scope, resource, code_challenge, code_challenge_method, expires_at, approved)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, code.Hash, code.ClientID, code.RedirectURI, code.State, code.Scope, code.Resource, code.CodeChallenge, code.CodeChallengeMethod, code.ExpiresAt.Unix(), code.Approved)
	return err
}

func (s *Store) GetAuthorizationCode(hash []byte, now time.Time) (AuthorizationCode, error) {
	var code AuthorizationCode
	var expiresAt int64
	var consumedAt sql.NullInt64
	var approved bool
	if err := s.db.QueryRow(`
SELECT code_hash, client_id, redirect_uri, state, scope, resource, code_challenge, code_challenge_method, expires_at, consumed_at, approved
FROM oauth_codes WHERE code_hash = ?`, hash).Scan(
		&code.Hash, &code.ClientID, &code.RedirectURI, &code.State, &code.Scope, &code.Resource,
		&code.CodeChallenge, &code.CodeChallengeMethod, &expiresAt, &consumedAt, &approved,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthorizationCode{}, ErrNotFound
		}
		return AuthorizationCode{}, err
	}
	if consumedAt.Valid {
		return AuthorizationCode{}, ErrConsumed
	}
	if !approved {
		return AuthorizationCode{}, ErrNotApproved
	}
	code.ExpiresAt = time.Unix(expiresAt, 0)
	if !code.ExpiresAt.After(now) {
		return AuthorizationCode{}, ErrExpired
	}
	code.Approved = true
	return code, nil
}

func (s *Store) ConsumeCode(hash []byte, now time.Time) (AuthorizationCode, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return AuthorizationCode{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var code AuthorizationCode
	var expiresAt int64
	var consumedAt sql.NullInt64
	var approved bool
	if err := tx.QueryRow(`
SELECT code_hash, client_id, redirect_uri, state, scope, resource, code_challenge, code_challenge_method, expires_at, consumed_at, approved
FROM oauth_codes WHERE code_hash = ?`, hash).Scan(
		&code.Hash, &code.ClientID, &code.RedirectURI, &code.State, &code.Scope, &code.Resource,
		&code.CodeChallenge, &code.CodeChallengeMethod, &expiresAt, &consumedAt, &approved,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthorizationCode{}, ErrNotFound
		}
		return AuthorizationCode{}, err
	}
	if consumedAt.Valid {
		return AuthorizationCode{}, ErrConsumed
	}
	if !approved {
		return AuthorizationCode{}, ErrNotApproved
	}
	code.ExpiresAt = time.Unix(expiresAt, 0)
	if !code.ExpiresAt.After(now) {
		return AuthorizationCode{}, ErrExpired
	}
	if _, err := tx.Exec(`UPDATE oauth_codes SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL`, now.Unix(), hash); err != nil {
		return AuthorizationCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationCode{}, err
	}
	return code, nil
}

func (s *Store) ApproveCode(hash []byte) (AuthorizationCode, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return AuthorizationCode{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var code AuthorizationCode
	var expiresAt int64
	var consumedAt sql.NullInt64
	var approved bool
	if err := tx.QueryRow(`
SELECT code_hash, client_id, redirect_uri, state, scope, resource, code_challenge, code_challenge_method, expires_at, consumed_at, approved
FROM oauth_codes WHERE code_hash = ?`, hash).Scan(
		&code.Hash, &code.ClientID, &code.RedirectURI, &code.State, &code.Scope, &code.Resource,
		&code.CodeChallenge, &code.CodeChallengeMethod, &expiresAt, &consumedAt, &approved,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthorizationCode{}, ErrNotFound
		}
		return AuthorizationCode{}, err
	}
	if consumedAt.Valid {
		return AuthorizationCode{}, ErrConsumed
	}
	if approved {
		return AuthorizationCode{}, ErrApproved
	}
	code.ExpiresAt = time.Unix(expiresAt, 0)
	if !code.ExpiresAt.After(time.Now()) {
		return AuthorizationCode{}, ErrExpired
	}
	if _, err := tx.Exec(`UPDATE oauth_codes SET approved = 1 WHERE code_hash = ? AND approved = 0`, hash); err != nil {
		return AuthorizationCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationCode{}, err
	}
	code.Approved = true
	return code, nil
}

func (s *Store) CreateAccessToken(token AccessToken) error {
	_, err := s.db.Exec(`
INSERT INTO oauth_access_tokens (token_hash, client_id, scope, resource, expires_at)
VALUES (?, ?, ?, ?, ?)`, token.Hash, token.ClientID, token.Scope, token.Resource, token.ExpiresAt.Unix())
	return err
}

func (s *Store) GetAccessToken(hash []byte, now time.Time) (AccessToken, error) {
	var token AccessToken
	var expiresAt int64
	if err := s.db.QueryRow(`
SELECT token_hash, client_id, scope, resource, expires_at
FROM oauth_access_tokens WHERE token_hash = ?`, hash).Scan(&token.Hash, &token.ClientID, &token.Scope, &token.Resource, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AccessToken{}, ErrNotFound
		}
		return AccessToken{}, err
	}
	token.ExpiresAt = time.Unix(expiresAt, 0)
	if !token.ExpiresAt.After(now) {
		return AccessToken{}, ErrExpired
	}
	return token, nil
}

func (s *Store) CreateRefreshToken(token RefreshToken) error {
	_, err := s.db.Exec(`
INSERT INTO oauth_refresh_tokens (token_hash, client_id, scope, resource, expires_at)
VALUES (?, ?, ?, ?, ?)`, token.Hash, token.ClientID, token.Scope, token.Resource, token.ExpiresAt.Unix())
	return err
}

func (s *Store) GetRefreshToken(hash []byte, now time.Time) (RefreshToken, error) {
	var token RefreshToken
	var expiresAt int64
	var rotatedAt sql.NullInt64
	if err := s.db.QueryRow(`
SELECT token_hash, client_id, scope, resource, expires_at, rotated_at
FROM oauth_refresh_tokens WHERE token_hash = ?`, hash).Scan(
		&token.Hash, &token.ClientID, &token.Scope, &token.Resource, &expiresAt, &rotatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RefreshToken{}, ErrNotFound
		}
		return RefreshToken{}, err
	}
	if rotatedAt.Valid {
		return RefreshToken{}, ErrConsumed
	}
	token.ExpiresAt = time.Unix(expiresAt, 0)
	if !token.ExpiresAt.After(now) {
		return RefreshToken{}, ErrExpired
	}
	return token, nil
}

func (s *Store) RotateRefreshToken(oldHash []byte, replacement RefreshToken, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var expiresAt int64
	var rotatedAt sql.NullInt64
	if err := tx.QueryRow(`
SELECT expires_at, rotated_at FROM oauth_refresh_tokens WHERE token_hash = ?`, oldHash).Scan(&expiresAt, &rotatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if rotatedAt.Valid {
		return ErrConsumed
	}
	if !time.Unix(expiresAt, 0).After(now) {
		return ErrExpired
	}
	if _, err := tx.Exec(`UPDATE oauth_refresh_tokens SET rotated_at = ? WHERE token_hash = ? AND rotated_at IS NULL`, now.Unix(), oldHash); err != nil {
		return err
	}
	if _, err := tx.Exec(`
INSERT INTO oauth_refresh_tokens (token_hash, client_id, scope, resource, expires_at)
VALUES (?, ?, ?, ?, ?)`, replacement.Hash, replacement.ClientID, replacement.Scope, replacement.Resource, replacement.ExpiresAt.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// PurgeExpired deletes authorization codes and tokens that expired before now.
// Nothing else removes them, so without this the database grows without bound
// and retains credential hashes long after they stop being usable.
func (s *Store) PurgeExpired(now time.Time) error {
	cutoff := now.Unix()
	for _, statement := range []string{
		`DELETE FROM oauth_codes WHERE expires_at <= ?`,
		`DELETE FROM oauth_access_tokens WHERE expires_at <= ?`,
		`DELETE FROM oauth_refresh_tokens WHERE expires_at <= ?`,
	} {
		if _, err := s.db.Exec(statement, cutoff); err != nil {
			return fmt.Errorf("purge expired records: %w", err)
		}
	}
	return nil
}

func (s *Store) PutWorkspace(record WorkspaceRecord) error {
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	_, err := s.db.Exec(`
INSERT INTO workspaces (workspace_id, root, mode, source_root, base_ref, base_sha, dirty_source, detached, managed, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(workspace_id) DO UPDATE SET
root = excluded.root, mode = excluded.mode, source_root = excluded.source_root,
base_ref = excluded.base_ref, base_sha = excluded.base_sha, dirty_source = excluded.dirty_source,
detached = excluded.detached, managed = excluded.managed`,
		record.ID, record.Root, record.Mode, record.SourceRoot, record.BaseRef, record.BaseSHA,
		record.DirtySource, record.Detached, record.Managed, createdAt.Unix())
	return err
}

func (s *Store) GetWorkspace(id string) (WorkspaceRecord, error) {
	var record WorkspaceRecord
	var dirty, detached, managed bool
	var createdAt int64
	if err := s.db.QueryRow(`
SELECT workspace_id, root, mode, source_root, base_ref, base_sha, dirty_source, detached, managed, created_at
FROM workspaces WHERE workspace_id = ?`, id).Scan(
		&record.ID, &record.Root, &record.Mode, &record.SourceRoot, &record.BaseRef, &record.BaseSHA,
		&dirty, &detached, &managed, &createdAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WorkspaceRecord{}, ErrNotFound
		}
		return WorkspaceRecord{}, err
	}
	record.DirtySource = dirty
	record.Detached = detached
	record.Managed = managed
	record.CreatedAt = time.Unix(createdAt, 0)
	return record, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS owner (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash BLOB PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  state TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  approved INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS oauth_codes_expires_at_idx ON oauth_codes(expires_at);
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
  token_hash BLOB PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_access_tokens_expires_at_idx ON oauth_access_tokens(expires_at);
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token_hash BLOB PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  rotated_at INTEGER
);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expires_at_idx ON oauth_refresh_tokens(expires_at);
CREATE TABLE IF NOT EXISTS workspaces (
  workspace_id TEXT PRIMARY KEY,
  root TEXT NOT NULL,
  mode TEXT NOT NULL,
  source_root TEXT NOT NULL,
  base_ref TEXT NOT NULL,
  base_sha TEXT NOT NULL,
  dirty_source INTEGER NOT NULL,
  detached INTEGER NOT NULL,
  managed INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
`
