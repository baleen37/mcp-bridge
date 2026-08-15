package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/baleen37/mcp-bridge/internal/store"
)

var (
	ErrInvalidClient   = errors.New("invalid client")
	ErrInvalidGrant    = errors.New("invalid grant")
	ErrInvalidRequest  = errors.New("invalid request")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrTooManyAttempts = errors.New("too many failed approval attempts")
)

const (
	// The owner password may be as short as four characters and the approval
	// endpoint is reachable through the public tunnel, so cap how fast it can
	// be guessed. Argon2 alone only makes each guess expensive, not bounded.
	maxApprovalAttempts = 5
	approvalLockout     = 15 * time.Minute
)

// RedirectableError is an authorization failure that RFC 6749 4.1.2.1 requires
// be delivered to the client's redirect URI. It is only produced after the
// client and its redirect URI have been validated.
type RedirectableError struct {
	RedirectURI string
	State       string
	Code        string
	Description string
}

func (e *RedirectableError) Error() string {
	return e.Code + ": " + e.Description
}

// RedirectURL renders the redirect URI carrying the OAuth error parameters.
func (e *RedirectableError) RedirectURL() string {
	target, err := url.Parse(e.RedirectURI)
	if err != nil {
		return e.RedirectURI
	}
	query := target.Query()
	query.Set("error", e.Code)
	if e.Description != "" {
		query.Set("error_description", e.Description)
	}
	if e.State != "" {
		query.Set("state", e.State)
	}
	target.RawQuery = query.Encode()
	return target.String()
}

// sameResource compares RFC 8707 resource indicators. The MCP specification
// says to accept case variation in scheme and host and to tolerate a trailing
// slash, so a byte-exact match would reject conformant clients.
func sameResource(left, right string) bool {
	return canonicalResource(left) == canonicalResource(right)
}

func canonicalResource(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return strings.TrimRight(value, "/")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String()
}

type Provider struct {
	Store         *store.Store
	PublicBaseURL string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	RedirectHosts []string

	// Approval throttling. There is a single owner, so one counter is enough.
	approvalMu       sync.Mutex
	approvalFailures int
	approvalBlocked  time.Time
}

type Client struct {
	ID           string
	Name         string
	RedirectURIs []string
}

type RegisterInput struct {
	Name         string
	RedirectURIs []string
}

type AuthorizationInput struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

type AuthorizationPage struct {
	ApprovalID    string
	ClientName    string
	RedirectURI   string
	Scope         string
	Resource      string
	State         string
	CodeChallenge string
}

type TokenInput struct {
	ClientID     string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Resource     string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

func (p *Provider) InitializeOwner(password []byte) error {
	if utf8.RuneCount(password) < 4 {
		return errors.New("owner password must be at least 4 characters")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return p.Store.SetOwnerHash(hash)
}

func (p *Provider) RegisterClient(input RegisterInput) (Client, error) {
	if len(input.RedirectURIs) == 0 {
		return Client{}, fmt.Errorf("%w: redirect_uris is required", ErrInvalidRequest)
	}
	redirects := make([]string, len(input.RedirectURIs))
	for i, redirect := range input.RedirectURIs {
		parsed, err := url.Parse(redirect)
		if err != nil || !p.allowedRedirectURI(parsed) || parsed.Fragment != "" || strings.ContainsAny(redirect, "\r\n") {
			return Client{}, fmt.Errorf("%w: invalid redirect URI", ErrInvalidRequest)
		}
		redirects[i] = redirect
	}
	id, err := randomToken(24)
	if err != nil {
		return Client{}, err
	}
	client := Client{ID: "devspace-" + id[:16], Name: input.Name, RedirectURIs: redirects}
	if client.Name == "" {
		client.Name = "MCP client"
	}
	if err := p.Store.CreateClient(store.Client{ID: client.ID, Name: client.Name, RedirectURIs: redirects}); err != nil {
		return Client{}, err
	}
	return client, nil
}

func (p *Provider) allowedRedirectURI(parsed *url.URL) bool {
	if parsed == nil || parsed.User != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	allowed := p.RedirectHosts
	if len(allowed) == 0 {
		allowed = []string{"chatgpt.com", "chat.openai.com", "localhost", "127.0.0.1", "::1"}
	}
	matched := false
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), host) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	return parsed.Scheme == "https"
}

func (p *Provider) BeginAuthorization(input AuthorizationInput) (AuthorizationPage, error) {
	client, err := p.Store.GetClient(input.ClientID)
	if err != nil {
		return AuthorizationPage{}, ErrInvalidClient
	}
	// The redirect URI must be validated before any error can be sent to it,
	// otherwise the error path itself becomes an open redirect.
	if !slices.Contains(client.RedirectURIs, input.RedirectURI) {
		return AuthorizationPage{}, ErrInvalidRequest
	}
	// From here the client and redirect URI are trusted, so RFC 6749 4.1.2.1
	// wants failures reported back to the client rather than rendered here.
	redirectErr := func(code, description string) error {
		return &RedirectableError{
			RedirectURI: input.RedirectURI, State: input.State,
			Code: code, Description: description,
		}
	}
	if input.ResponseType != "code" {
		return AuthorizationPage{}, redirectErr("unsupported_response_type", "response_type must be code")
	}
	scope := input.Scope
	if scope == "" {
		scope = "devspace"
	}
	if !slices.Contains(strings.Fields(scope), "devspace") {
		return AuthorizationPage{}, redirectErr("invalid_scope", "scope must include devspace")
	}
	if input.CodeChallenge == "" || input.CodeChallengeMethod != "S256" {
		return AuthorizationPage{}, redirectErr("invalid_request", "PKCE with S256 is required")
	}
	resource := input.Resource
	if resource == "" {
		resource = p.ResourceURL()
	}
	if !sameResource(resource, p.ResourceURL()) {
		return AuthorizationPage{}, redirectErr("invalid_target", "resource does not match this server")
	}
	code, err := randomToken(32)
	if err != nil {
		return AuthorizationPage{}, redirectErr("server_error", "could not create authorization code")
	}
	if err := p.Store.CreateCode(store.AuthorizationCode{
		Hash:                hashToken(code),
		ClientID:            input.ClientID,
		RedirectURI:         input.RedirectURI,
		State:               input.State,
		Scope:               scope,
		Resource:            resource,
		CodeChallenge:       input.CodeChallenge,
		CodeChallengeMethod: input.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}); err != nil {
		return AuthorizationPage{}, err
	}
	return AuthorizationPage{
		ApprovalID: code, ClientName: client.Name, RedirectURI: input.RedirectURI,
		Scope: scope, Resource: resource, State: input.State, CodeChallenge: input.CodeChallenge,
	}, nil
}

func (p *Provider) Approve(approvalID, password string) (string, error) {
	if err := p.checkApprovalAllowed(time.Now()); err != nil {
		return "", err
	}
	hash, err := p.Store.OwnerHash()
	if err != nil {
		return "", ErrUnauthorized
	}
	if !VerifyPassword(hash, []byte(password)) {
		p.recordApprovalFailure(time.Now())
		return "", ErrUnauthorized
	}
	p.resetApprovalFailures()
	code, err := p.Store.ApproveCode(hashToken(approvalID))
	if err != nil {
		return "", ErrInvalidGrant
	}
	redirect, err := url.Parse(code.RedirectURI)
	if err != nil {
		return "", ErrInvalidGrant
	}
	query := redirect.Query()
	query.Set("code", approvalID)
	if code.State != "" {
		query.Set("state", code.State)
	}
	redirect.RawQuery = query.Encode()
	return redirect.String(), nil
}

// checkApprovalAllowed reports whether another owner-password attempt may be
// made, refusing every attempt while a lockout is in effect so that a correct
// guess arriving mid-lockout still fails.
func (p *Provider) checkApprovalAllowed(now time.Time) error {
	p.approvalMu.Lock()
	defer p.approvalMu.Unlock()
	if p.approvalBlocked.IsZero() {
		return nil
	}
	if now.Before(p.approvalBlocked) {
		return ErrTooManyAttempts
	}
	// The lockout elapsed; start a fresh budget.
	p.approvalBlocked = time.Time{}
	p.approvalFailures = 0
	return nil
}

func (p *Provider) recordApprovalFailure(now time.Time) {
	p.approvalMu.Lock()
	defer p.approvalMu.Unlock()
	p.approvalFailures++
	if p.approvalFailures >= maxApprovalAttempts {
		p.approvalBlocked = now.Add(approvalLockout)
	}
}

func (p *Provider) resetApprovalFailures() {
	p.approvalMu.Lock()
	defer p.approvalMu.Unlock()
	p.approvalFailures = 0
	p.approvalBlocked = time.Time{}
}

func (p *Provider) ExchangeCode(input TokenInput) (TokenResponse, error) {
	if input.ClientID == "" || input.Code == "" || input.RedirectURI == "" || input.CodeVerifier == "" {
		return TokenResponse{}, fmt.Errorf("%w: missing required token parameter", ErrInvalidRequest)
	}
	code, err := p.Store.GetAuthorizationCode(hashToken(input.Code), time.Now())
	if err != nil || code.ClientID != input.ClientID || code.RedirectURI != input.RedirectURI {
		return TokenResponse{}, ErrInvalidGrant
	}
	if !verifyPKCE(code.CodeChallenge, input.CodeVerifier) {
		return TokenResponse{}, ErrInvalidGrant
	}
	resource := input.Resource
	if resource == "" {
		resource = code.Resource
	}
	if !sameResource(resource, code.Resource) {
		return TokenResponse{}, ErrInvalidGrant
	}
	if _, err := p.Store.ConsumeCode(hashToken(input.Code), time.Now()); err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	return p.issueTokens(code.ClientID, code.Scope, code.Resource)
}

func (p *Provider) Refresh(input TokenInput) (TokenResponse, error) {
	if input.ClientID == "" || input.RefreshToken == "" {
		return TokenResponse{}, fmt.Errorf("%w: missing required token parameter", ErrInvalidRequest)
	}
	old, err := p.Store.GetRefreshToken(hashToken(input.RefreshToken), time.Now())
	if err != nil || old.ClientID != input.ClientID {
		return TokenResponse{}, ErrInvalidGrant
	}
	resource := input.Resource
	if resource == "" {
		resource = old.Resource
	}
	if !sameResource(resource, old.Resource) {
		return TokenResponse{}, ErrInvalidGrant
	}
	response, err := p.issueRefreshedTokens(old, input.RefreshToken)
	if err != nil {
		return TokenResponse{}, err
	}
	return response, nil
}

func (p *Provider) AuthenticateBearer(raw, resource string) error {
	token, err := p.Store.GetAccessToken(hashToken(raw), time.Now())
	if err != nil || !sameResource(token.Resource, resource) {
		return ErrUnauthorized
	}
	return nil
}

func (p *Provider) ResourceURL() string {
	return strings.TrimRight(p.PublicBaseURL, "/") + "/mcp"
}

func (p *Provider) issueTokens(clientID, scope, resource string) (TokenResponse, error) {
	access, err := randomToken(32)
	if err != nil {
		return TokenResponse{}, err
	}
	refresh, err := randomToken(32)
	if err != nil {
		return TokenResponse{}, err
	}
	accessTTL := p.accessTTL()
	refreshTTL := p.refreshTTL()
	if err := p.Store.CreateAccessToken(store.AccessToken{
		Hash: hashToken(access), ClientID: clientID, Scope: scope, Resource: resource,
		ExpiresAt: time.Now().Add(accessTTL),
	}); err != nil {
		return TokenResponse{}, err
	}
	if err := p.Store.CreateRefreshToken(store.RefreshToken{
		Hash: hashToken(refresh), ClientID: clientID, Scope: scope, Resource: resource,
		ExpiresAt: time.Now().Add(refreshTTL),
	}); err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(accessTTL / time.Second), RefreshToken: refresh, Scope: scope}, nil
}

func (p *Provider) issueRefreshedTokens(old store.RefreshToken, oldRaw string) (TokenResponse, error) {
	access, err := randomToken(32)
	if err != nil {
		return TokenResponse{}, err
	}
	refresh, err := randomToken(32)
	if err != nil {
		return TokenResponse{}, err
	}
	accessTTL := p.accessTTL()
	if err := p.Store.CreateAccessToken(store.AccessToken{
		Hash: hashToken(access), ClientID: old.ClientID, Scope: old.Scope, Resource: old.Resource,
		ExpiresAt: time.Now().Add(accessTTL),
	}); err != nil {
		return TokenResponse{}, err
	}
	if err := p.Store.RotateRefreshToken(hashToken(oldRaw), store.RefreshToken{
		Hash: hashToken(refresh), ClientID: old.ClientID, Scope: old.Scope,
		Resource: old.Resource, ExpiresAt: time.Now().Add(p.refreshTTL()),
	}, time.Now()); err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	return TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(accessTTL / time.Second), RefreshToken: refresh, Scope: old.Scope}, nil
}

func (p *Provider) accessTTL() time.Duration {
	if p.AccessTTL <= 0 {
		return time.Hour
	}
	return p.AccessTTL
}

func (p *Provider) refreshTTL() time.Duration {
	if p.RefreshTTL <= 0 {
		return 30 * 24 * time.Hour
	}
	return p.RefreshTTL
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashToken(raw string) []byte {
	hash := sha256.Sum256([]byte(raw))
	return hash[:]
}

func verifyPKCE(challenge, verifier string) bool {
	hash := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(computed)) == 1
}
