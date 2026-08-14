package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	DefaultHost = "127.0.0.1"
	DefaultPort = 7676
)

var DefaultOAuthRedirectHosts = []string{"chatgpt.com", "chat.openai.com", "localhost", "127.0.0.1", "::1"}

type Config struct {
	Host                     string   `json:"host"`
	Port                     int      `json:"port"`
	AllowedRoots             []string `json:"allowedRoots"`
	PublicBaseURL            string   `json:"publicBaseUrl"`
	WorktreeRoot             string   `json:"worktreeRoot"`
	OAuthRedirectHosts       []string `json:"oauthRedirectHosts"`
	ArtifactDownloadsEnabled bool     `json:"artifactDownloadsEnabled"`

	ConfigPath      string `json:"-"`
	StateDBPath     string `json:"-"`
	RuntimeDir      string `json:"-"`
	TunnelTokenFile string `json:"-"`
}

type persisted struct {
	Host                     string   `json:"host"`
	Port                     int      `json:"port"`
	AllowedRoots             []string `json:"allowedRoots"`
	PublicBaseURL            string   `json:"publicBaseUrl"`
	WorktreeRoot             string   `json:"worktreeRoot"`
	OAuthRedirectHosts       []string `json:"oauthRedirectHosts,omitempty"`
	RuntimeDir               string   `json:"runtimeDir,omitempty"`
	ArtifactDownloadsEnabled bool     `json:"artifactDownloadsEnabled,omitempty"`
}

func Load(env map[string]string, home string) (Config, error) {
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return Config{}, fmt.Errorf("resolve home: %w", err)
		}
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return Config{}, fmt.Errorf("resolve home: %w", err)
	}

	configHome := envOr(env, "XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	stateHome := envOr(env, "XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	configDir := filepath.Join(expandHome(configHome, home), "mcp-bridge")
	stateDir := filepath.Join(expandHome(stateHome, home), "mcp-bridge")
	cfg := Config{
		Host:               DefaultHost,
		Port:               DefaultPort,
		WorktreeRoot:       filepath.Join(stateDir, "worktrees"),
		OAuthRedirectHosts: append([]string(nil), DefaultOAuthRedirectHosts...),
		ConfigPath:         filepath.Join(configDir, "config.json"),
		StateDBPath:        filepath.Join(stateDir, "state.db"),
		RuntimeDir:         filepath.Join(stateDir, "logs"),
	}

	if raw, readErr := os.ReadFile(cfg.ConfigPath); readErr == nil {
		var saved persisted
		if err := json.Unmarshal(raw, &saved); err != nil {
			return Config{}, fmt.Errorf("read config %s: %w", cfg.ConfigPath, err)
		}
		if saved.Host != "" {
			cfg.Host = saved.Host
		}
		if saved.Port != 0 {
			cfg.Port = saved.Port
		}
		if saved.AllowedRoots != nil {
			cfg.AllowedRoots = append([]string(nil), saved.AllowedRoots...)
		}
		if saved.PublicBaseURL != "" {
			cfg.PublicBaseURL = saved.PublicBaseURL
		}
		if saved.WorktreeRoot != "" {
			cfg.WorktreeRoot = saved.WorktreeRoot
		}
		if saved.OAuthRedirectHosts != nil {
			cfg.OAuthRedirectHosts = append([]string(nil), saved.OAuthRedirectHosts...)
		}
		if saved.RuntimeDir != "" {
			cfg.RuntimeDir = saved.RuntimeDir
		}
		cfg.ArtifactDownloadsEnabled = saved.ArtifactDownloadsEnabled
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return Config{}, fmt.Errorf("read config %s: %w", cfg.ConfigPath, readErr)
	}

	if value := env["HOST"]; value != "" {
		cfg.Host = value
	}
	if value := env["PORT"]; value != "" {
		port, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return Config{}, fmt.Errorf("parse PORT: %w", parseErr)
		}
		cfg.Port = port
	}
	if value := env["MCP_BRIDGE_ALLOWED_ROOTS"]; value != "" {
		cfg.AllowedRoots = splitPaths(value, home)
	}
	if value := env["MCP_BRIDGE_PUBLIC_BASE_URL"]; value != "" {
		cfg.PublicBaseURL = value
	}
	if value := env["MCP_BRIDGE_WORKTREE_ROOT"]; value != "" {
		cfg.WorktreeRoot = expandHome(value, home)
	}
	if value := env["MCP_BRIDGE_RUNTIME_DIR"]; value != "" {
		cfg.RuntimeDir = expandHome(value, home)
	}
	if value := env["MCP_BRIDGE_OAUTH_REDIRECT_HOSTS"]; value != "" {
		cfg.OAuthRedirectHosts = splitValues(value)
	}
	if value := env["MCP_BRIDGE_ARTIFACT_DOWNLOADS_ENABLED"]; value == "1" || strings.EqualFold(value, "true") {
		cfg.ArtifactDownloadsEnabled = true
	}
	if value := env["MCP_BRIDGE_TUNNEL_TOKEN_FILE"]; value != "" {
		cfg.TunnelTokenFile = expandHome(value, home)
	}

	cfg.AllowedRoots = cleanPaths(cfg.AllowedRoots, home)
	cfg.WorktreeRoot = absolutePath(cfg.WorktreeRoot, home)
	cfg.RuntimeDir = absolutePath(cfg.RuntimeDir, home)
	cfg.TunnelTokenFile = absolutePath(cfg.TunnelTokenFile, home)
	if len(cfg.OAuthRedirectHosts) == 0 {
		cfg.OAuthRedirectHosts = append([]string(nil), DefaultOAuthRedirectHosts...)
	}
	return cfg, nil
}

func (c Config) Address() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

func (c Config) MCPURL() string {
	return strings.TrimRight(c.PublicBaseURL, "/") + "/mcp"
}

func (c Config) Validate() error {
	if c.Host != "localhost" {
		ip := net.ParseIP(c.Host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("host must be loopback, got %q", c.Host)
		}
	}
	if c.Port != DefaultPort {
		return fmt.Errorf("port must be %d, got %d", DefaultPort, c.Port)
	}
	if len(c.AllowedRoots) == 0 {
		return errors.New("at least one allowed root is required")
	}
	if c.PublicBaseURL == "" {
		return errors.New("public base URL is required: set MCP_BRIDGE_PUBLIC_BASE_URL or pass --public-base-url https://<your-host>")
	}
	parsed, err := url.Parse(c.PublicBaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("public base URL must be an HTTPS origin without a path: %q", c.PublicBaseURL)
	}
	return nil
}

func Save(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.ConfigPath), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	payload, err := json.MarshalIndent(persisted{
		Host:                     c.Host,
		Port:                     c.Port,
		AllowedRoots:             c.AllowedRoots,
		PublicBaseURL:            c.PublicBaseURL,
		WorktreeRoot:             c.WorktreeRoot,
		OAuthRedirectHosts:       c.OAuthRedirectHosts,
		RuntimeDir:               c.RuntimeDir,
		ArtifactDownloadsEnabled: c.ArtifactDownloadsEnabled,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	payload = append(payload, '\n')
	temp, err := os.CreateTemp(filepath.Dir(c.ConfigPath), ".config-*")
	if err != nil {
		return fmt.Errorf("create config temporary file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set config permissions: %w", err)
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(tempName, c.ConfigPath); err != nil {
		return fmt.Errorf("install config: %w", err)
	}
	return nil
}

func splitValues(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, strings.ToLower(value))
		}
	}
	return result
}

func envOr(env map[string]string, key, fallback string) string {
	if value := env[key]; value != "" {
		return value
	}
	return fallback
}

func splitPaths(value, home string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			result = append(result, expandHome(strings.TrimSpace(part), home))
		}
	}
	return result
}

func cleanPaths(paths []string, home string) []string {
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) != "" {
			result = append(result, absolutePath(path, home))
		}
	}
	return result
}

func absolutePath(path, home string) string {
	if path == "" {
		return ""
	}
	path = expandHome(path, home)
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(absolute)
}

func expandHome(path, home string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}
