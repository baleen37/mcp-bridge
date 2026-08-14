package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUsesXDGDefaults(t *testing.T) {
	home := t.TempDir()
	cfg, err := Load(map[string]string{}, home)
	if err != nil {
		t.Fatal(err)
	}

	wantConfig := filepath.Join(home, ".config", "mcp-bridge", "config.json")
	wantState := filepath.Join(home, ".local", "state", "mcp-bridge", "state.db")
	if cfg.ConfigPath != wantConfig || cfg.StateDBPath != wantState {
		t.Fatalf("unexpected XDG paths: config=%q state=%q", cfg.ConfigPath, cfg.StateDBPath)
	}
	if cfg.WorktreeRoot != filepath.Join(home, ".local", "state", "mcp-bridge", "worktrees") {
		t.Fatalf("unexpected worktree root: %q", cfg.WorktreeRoot)
	}
	if cfg.RuntimeDir != filepath.Join(home, ".local", "state", "mcp-bridge", "logs") {
		t.Fatalf("unexpected runtime dir: %q", cfg.RuntimeDir)
	}
	if cfg.TunnelTokenFile != "" {
		t.Fatalf("tunnel token file should be unset by default: %q", cfg.TunnelTokenFile)
	}
	if cfg.PublicBaseURL != "" {
		t.Fatalf("public base URL should have no default: %q", cfg.PublicBaseURL)
	}
	if cfg.Host != "127.0.0.1" || cfg.Port != 7676 {
		t.Fatalf("unexpected defaults: %s:%d", cfg.Host, cfg.Port)
	}
	if len(cfg.OAuthRedirectHosts) != len(DefaultOAuthRedirectHosts) {
		t.Fatalf("unexpected OAuth redirect hosts: %#v", cfg.OAuthRedirectHosts)
	}
}

func TestLoadUsesExplicitXDGAndEnvironmentOverrides(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(t.TempDir(), "config")
	stateHome := filepath.Join(t.TempDir(), "state")
	runtimeDir := filepath.Join(t.TempDir(), "logs")
	cfg, err := Load(map[string]string{
		"XDG_CONFIG_HOME":                 configHome,
		"XDG_STATE_HOME":                  stateHome,
		"MCP_BRIDGE_PUBLIC_BASE_URL":      "https://example.test",
		"MCP_BRIDGE_RUNTIME_DIR":          runtimeDir,
		"MCP_BRIDGE_ALLOWED_ROOTS":        filepath.Join(home, "projects") + "," + filepath.Join(home, "other"),
		"MCP_BRIDGE_WORKTREE_ROOT":        filepath.Join(stateHome, "custom-worktrees"),
		"MCP_BRIDGE_OAUTH_REDIRECT_HOSTS": "trusted.example,localhost",
		"MCP_BRIDGE_TUNNEL_TOKEN_FILE":    filepath.Join(home, "tunnel-token"),
	}, home)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ConfigPath != filepath.Join(configHome, "mcp-bridge", "config.json") {
		t.Fatalf("unexpected config path: %q", cfg.ConfigPath)
	}
	if cfg.StateDBPath != filepath.Join(stateHome, "mcp-bridge", "state.db") {
		t.Fatalf("unexpected state path: %q", cfg.StateDBPath)
	}
	if cfg.RuntimeDir != runtimeDir {
		t.Fatalf("unexpected runtime path: %q", cfg.RuntimeDir)
	}
	if len(cfg.AllowedRoots) != 2 || cfg.AllowedRoots[0] != filepath.Join(home, "projects") {
		t.Fatalf("unexpected allowed roots: %#v", cfg.AllowedRoots)
	}
	if cfg.PublicBaseURL != "https://example.test" || cfg.WorktreeRoot != filepath.Join(stateHome, "custom-worktrees") {
		t.Fatalf("environment overrides were not applied: %#v", cfg)
	}
	if len(cfg.OAuthRedirectHosts) != 2 || cfg.OAuthRedirectHosts[0] != "trusted.example" {
		t.Fatalf("unexpected OAuth redirect hosts: %#v", cfg.OAuthRedirectHosts)
	}
	if cfg.TunnelTokenFile != filepath.Join(home, "tunnel-token") {
		t.Fatalf("unexpected tunnel token file: %q", cfg.TunnelTokenFile)
	}
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Config)
	}{
		{name: "non-loopback host", edit: func(c *Config) { c.Host = "0.0.0.0" }},
		{name: "wrong port", edit: func(c *Config) { c.Port = 8080 }},
		{name: "non-https public URL", edit: func(c *Config) { c.PublicBaseURL = "http://example.test" }},
		{name: "public URL path", edit: func(c *Config) { c.PublicBaseURL = "https://example.test/mcp" }},
		{name: "missing public URL", edit: func(c *Config) { c.PublicBaseURL = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(map[string]string{}, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSaveAndLoadPersistedConfig(t *testing.T) {
	home := t.TempDir()
	cfg, err := Load(map[string]string{}, home)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AllowedRoots = []string{filepath.Join(home, "workspace")}
	cfg.PublicBaseURL = "https://persisted.test"
	cfg.OAuthRedirectHosts = []string{"trusted.example"}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}

	loaded, err := Load(map[string]string{}, home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PublicBaseURL != cfg.PublicBaseURL || len(loaded.AllowedRoots) != 1 || len(loaded.OAuthRedirectHosts) != 1 || loaded.OAuthRedirectHosts[0] != "trusted.example" {
		t.Fatalf("persisted config not loaded: %#v", loaded)
	}
}
