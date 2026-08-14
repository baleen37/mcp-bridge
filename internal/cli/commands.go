package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/baleen37/mcp-bridge/internal/auth"
	"github.com/baleen37/mcp-bridge/internal/config"
	"github.com/baleen37/mcp-bridge/internal/lifecycle"
	bridgemcp "github.com/baleen37/mcp-bridge/internal/mcp"
	"github.com/baleen37/mcp-bridge/internal/store"
	"github.com/baleen37/mcp-bridge/internal/tools"
	"github.com/baleen37/mcp-bridge/internal/workspace"
	"golang.org/x/term"
)

var errUsage = errors.New("invalid command usage")

var installLaunchAgent = func(ctx context.Context, binary string, cfg config.Config) error {
	return lifecycle.InstallLaunchAgent(ctx, binary, cfg, lifecycle.ExecCommandRunner{})
}

func Execute(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printHelp(out)
		return nil
	}
	switch args[0] {
	case "init":
		return executeInit(args[1:], in, out, errOut)
	case "setup":
		return executeSetup(ctx, args[1:], in, out, errOut)
	case "start":
		return executeStart(ctx, args[1:], out, errOut)
	case "stop":
		return executeStop(args[1:], out, errOut)
	case "smoke-test":
		return executeSmokeTest(args[1:], out, errOut)
	case "install":
		return executeInstall(ctx, args[1:], out, errOut)
	case "remove", "uninstall":
		return executeRemove(ctx, args[1:], out, errOut)
	case "status":
		return executeStatus(ctx, args[1:], out, errOut)
	case "doctor":
		return executeDoctor(args[1:], out, errOut)
	case "config":
		return executeConfig(args[1:], out, errOut)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func executeInit(args []string, in io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(errOut)
	allowedRoot := flags.String("allowed-root", "", "workspace root allowed for MCP tools")
	publicBaseURL := flags.String("public-base-url", "", "HTTPS public origin, e.g. https://mcp-bridge.example.com")
	ownerPasswordStdin := flags.Bool("owner-password-stdin", false, "read the owner password from stdin")
	if err := flags.Parse(args); err != nil {
		return errUsage
	}
	if *allowedRoot == "" || *publicBaseURL == "" || !*ownerPasswordStdin || flags.NArg() != 0 {
		return errors.New("init requires --allowed-root, --public-base-url, and --owner-password-stdin")
	}
	root, err := filepath.Abs(*allowedRoot)
	if err != nil {
		return fmt.Errorf("resolve allowed root: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return errors.New("allowed root must be an existing directory")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.AllowedRoots = []string{root}
	cfg.PublicBaseURL = *publicBaseURL
	password, err := io.ReadAll(io.LimitReader(in, 1024*1024))
	if err != nil {
		return errors.New("read owner password failed")
	}
	password = []byte(strings.TrimRight(string(password), "\r\n"))
	defer zeroBytes(password)
	if err := initializeOwner(cfg, password); err != nil {
		return err
	}
	fmt.Fprintf(out, "initialized\nconfig=%s\nstate=%s\n", cfg.ConfigPath, cfg.StateDBPath)
	return nil
}

func executeSetup(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(errOut)
	publicBaseURL := flags.String("public-base-url", "", "HTTPS public origin, e.g. https://mcp-bridge.example.com")
	ownerPasswordStdin := flags.Bool("owner-password-stdin", false, "read the owner password from stdin")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	if *publicBaseURL == "" {
		return errors.New("setup requires --public-base-url https://<your-host>")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	root, err := filepath.Abs(home)
	if err != nil {
		return fmt.Errorf("resolve allowed root: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return errors.New("home directory must be an existing directory")
	}

	password, err := readSetupPassword(in, out, *ownerPasswordStdin)
	if err != nil {
		return err
	}
	defer zeroBytes(password)

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.AllowedRoots = []string{root}
	cfg.PublicBaseURL = *publicBaseURL
	if err := initializeOwner(cfg, password); err != nil {
		return err
	}
	if err := executeInstall(ctx, nil, out, errOut); err != nil {
		return err
	}
	fmt.Fprintf(out, "setup complete\nconfig=%s\nstate=%s\n", cfg.ConfigPath, cfg.StateDBPath)
	return nil
}

func initializeOwner(cfg config.Config, password []byte) error {
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	state, err := store.Open(cfg.StateDBPath)
	if err != nil {
		return err
	}
	defer state.Close()
	provider := &auth.Provider{Store: state, PublicBaseURL: cfg.PublicBaseURL, RedirectHosts: cfg.OAuthRedirectHosts}
	return provider.InitializeOwner(password)
}

func readSetupPassword(in io.Reader, out io.Writer, stdin bool) ([]byte, error) {
	if stdin {
		password, err := io.ReadAll(io.LimitReader(in, 1024*1024))
		if err != nil {
			return nil, errors.New("read owner password failed")
		}
		return []byte(strings.TrimRight(string(password), "\r\n")), nil
	}

	file, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil, errors.New("setup requires an interactive terminal; use --owner-password-stdin for automation")
	}
	password, err := readHiddenPassword(file, out, "Owner password: ")
	if err != nil {
		return nil, err
	}
	confirmation, err := readHiddenPassword(file, out, "Confirm owner password: ")
	if err != nil {
		zeroBytes(password)
		return nil, err
	}
	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		zeroBytes(password)
		zeroBytes(confirmation)
		return nil, errors.New("owner passwords do not match")
	}
	zeroBytes(confirmation)
	return password, nil
}

func readHiddenPassword(file *os.File, out io.Writer, prompt string) ([]byte, error) {
	fmt.Fprint(out, prompt)
	password, err := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		zeroBytes(password)
		return nil, errors.New("read owner password failed")
	}
	return password, nil
}

func executeStart(ctx context.Context, args []string, _ io.Writer, _ io.Writer) error {
	flags := flag.NewFlagSet("start", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, state, service, handler, err := buildHTTPApp()
	if err != nil {
		return err
	}
	defer state.Close()
	defer service.Close()
	server := &http.Server{Addr: cfg.Address(), Handler: handler}
	if os.Getenv("MCP_BRIDGE_SKIP_TUNNEL") == "1" {
		err := serveUntilContext(ctx, server)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	err = (&lifecycle.Supervisor{Server: server, Config: cfg, Command: lifecycle.ExecCommandRunner{}, Inspector: lifecycle.OSProcessInspector{}}).Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func executeStop(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("stop", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := lifecycle.Stop(cfg); err != nil {
		return err
	}
	fmt.Fprintln(out, "stopped")
	return nil
}

func executeSmokeTest(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("smoke-test", flag.ContinueOnError)
	flags.SetOutput(errOut)
	local := flags.Bool("local", false, "check the local HTTP server")
	public := flags.Bool("public", false, "check the public origin")
	all := flags.Bool("all", false, "check local and public HTTP servers")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	if *all {
		*local = true
		*public = true
	}
	if !*local && !*public {
		return errors.New("smoke-test requires --local, --public, or --all")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	failed := false
	if *local {
		failed = smokeOrigin(client, "local", "http://"+cfg.Address(), out) || failed
	}
	if *public {
		failed = smokeOrigin(client, "public", strings.TrimRight(cfg.PublicBaseURL, "/"), out) || failed
	}
	if failed {
		return errors.New("smoke-test failed")
	}
	return nil
}

func smokeOrigin(client *http.Client, name, origin string, out io.Writer) bool {
	failed := false
	for _, endpoint := range []struct {
		path     string
		expected int
	}{
		{path: "/healthz", expected: http.StatusOK},
		{path: "/mcp", expected: http.StatusUnauthorized},
	} {
		status := 0
		request, err := http.NewRequest(http.MethodGet, origin+endpoint.path, nil)
		if err == nil {
			response, requestErr := client.Do(request)
			if requestErr == nil {
				status = response.StatusCode
				response.Body.Close()
			}
		}
		pass := status == endpoint.expected
		if !pass {
			failed = true
		}
		result := "FAIL"
		if pass {
			result = "PASS"
		}
		fmt.Fprintf(out, "%s %s %s %03d\n", name, endpoint.path, result, status)
	}
	return failed
}

func executeInstall(ctx context.Context, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	if err := installLaunchAgent(ctx, binary, cfg); err != nil {
		return err
	}
	fmt.Fprintf(out, "installed label=%s\n", lifecycle.LaunchAgentLabel)
	return nil
}

func executeRemove(ctx context.Context, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("remove", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := lifecycle.UninstallLaunchAgent(ctx, cfg, lifecycle.ExecCommandRunner{}); err != nil {
		return err
	}
	fmt.Fprintf(out, "removed label=%s\n", lifecycle.LaunchAgentLabel)
	return nil
}

func executeStatus(ctx context.Context, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	return runStatus(ctx, cfg, out, statusEnvironment{HomeDir: home})
}

type doctorEnvironment struct {
	Client       *http.Client
	LocalOrigin  string
	PublicOrigin string
	HomeDir      string
	LookPath     func(string) (string, error)
	Stat         func(string) (os.FileInfo, error)
}

func executeDoctor(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(errOut)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	return runDoctor(cfg, out, doctorEnvironment{
		Client:       &http.Client{Timeout: 3 * time.Second},
		LocalOrigin:  "http://" + cfg.Address(),
		PublicOrigin: strings.TrimRight(cfg.PublicBaseURL, "/"),
		HomeDir:      home,
		LookPath:     exec.LookPath,
		Stat:         os.Stat,
	})
}

func runDoctor(cfg config.Config, out io.Writer, environment doctorEnvironment) error {
	if environment.Client == nil {
		environment.Client = &http.Client{Timeout: 3 * time.Second}
	}
	if environment.LookPath == nil {
		environment.LookPath = exec.LookPath
	}
	if environment.Stat == nil {
		environment.Stat = os.Stat
	}
	if environment.LocalOrigin == "" {
		environment.LocalOrigin = "http://" + cfg.Address()
	}
	if environment.PublicOrigin == "" {
		environment.PublicOrigin = strings.TrimRight(cfg.PublicBaseURL, "/")
	}
	failed := false
	check := func(name string, ok bool) {
		status := "ok"
		if !ok {
			status = "fail"
			failed = true
		}
		fmt.Fprintf(out, "doctor %s=%s\n", name, status)
	}
	for _, name := range []string{"git", "cloudflared"} {
		_, err := environment.LookPath(name)
		check(name, err == nil)
	}
	for name, path := range map[string]string{
		"config": cfg.ConfigPath,
		"state":  cfg.StateDBPath,
	} {
		_, err := environment.Stat(path)
		check(name, err == nil)
	}
	if environment.HomeDir != "" {
		launchAgent := filepath.Join(environment.HomeDir, "Library", "LaunchAgents", lifecycle.LaunchAgentLabel+".plist")
		_, err := environment.Stat(launchAgent)
		check("launch-agent", err == nil)
	}
	checkStatus := func(name, origin, path string, expected int) {
		status := 0
		request, err := http.NewRequest(http.MethodGet, strings.TrimRight(origin, "/")+path, nil)
		if err == nil {
			response, requestErr := environment.Client.Do(request)
			if requestErr == nil {
				status = response.StatusCode
				response.Body.Close()
			}
		}
		check(name, status == expected)
	}
	checkStatus("local-health", environment.LocalOrigin, "/healthz", http.StatusOK)
	checkStatus("local-mcp", environment.LocalOrigin, "/mcp", http.StatusUnauthorized)
	checkStatus("public-health", environment.PublicOrigin, "/healthz", http.StatusOK)
	checkStatus("public-mcp", environment.PublicOrigin, "/mcp", http.StatusUnauthorized)
	checkStatus("oauth-metadata", environment.PublicOrigin, "/.well-known/oauth-authorization-server", http.StatusOK)
	if failed {
		return errors.New("doctor found problems")
	}
	return nil
}

func executeConfig(args []string, out, errOut io.Writer) error {
	if len(args) < 2 {
		return errors.New("config requires get or set")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "get":
		if len(args) != 2 {
			return errors.New("config get requires a field")
		}
		value, err := configField(cfg, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s=%s\n", args[1], value)
		return nil
	case "set":
		if len(args) != 3 {
			return errors.New("config set requires a field and value")
		}
		if err := setConfigField(&cfg, args[1], args[2]); err != nil {
			return err
		}
		if err := config.Save(cfg); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s=%s\n", args[1], args[2])
		return nil
	default:
		return fmt.Errorf("unknown config operation %q", args[0])
	}
}

func configField(cfg config.Config, field string) (string, error) {
	switch field {
	case "public-base-url":
		return cfg.PublicBaseURL, nil
	case "allowed-roots":
		return strings.Join(cfg.AllowedRoots, ","), nil
	case "worktree-root":
		return cfg.WorktreeRoot, nil
	case "runtime-dir":
		return cfg.RuntimeDir, nil
	case "config-path":
		return cfg.ConfigPath, nil
	case "state-path":
		return cfg.StateDBPath, nil
	case "mcp-url":
		return cfg.MCPURL(), nil
	default:
		return "", fmt.Errorf("unknown or secret config field %q", field)
	}
}

func setConfigField(cfg *config.Config, field, value string) error {
	switch field {
	case "public-base-url":
		cfg.PublicBaseURL = value
	case "allowed-root":
		root, err := filepath.Abs(value)
		if err != nil {
			return fmt.Errorf("resolve allowed root: %w", err)
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return errors.New("allowed root must be an existing directory")
		}
		cfg.AllowedRoots = []string{root}
	case "worktree-root", "runtime-dir":
		path, err := filepath.Abs(value)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", field, err)
		}
		if field == "worktree-root" {
			cfg.WorktreeRoot = path
		} else {
			cfg.RuntimeDir = path
		}
	default:
		return fmt.Errorf("unknown or secret config field %q", field)
	}
	return cfg.Validate()
}

func buildHTTPApp() (config.Config, *store.Store, *tools.Service, http.Handler, error) {
	cfg, err := loadConfig()
	if err != nil {
		return config.Config{}, nil, nil, nil, err
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, nil, nil, nil, err
	}
	state, err := store.Open(cfg.StateDBPath)
	if err != nil {
		return config.Config{}, nil, nil, nil, err
	}
	if _, err := state.OwnerHash(); err != nil {
		_ = state.Close()
		return config.Config{}, nil, nil, nil, errors.New("owner is not initialized")
	}
	provider := &auth.Provider{Store: state, PublicBaseURL: cfg.PublicBaseURL, RedirectHosts: cfg.OAuthRedirectHosts}
	registry := &workspace.Registry{AllowedRoots: cfg.AllowedRoots, WorktreeRoot: cfg.WorktreeRoot, Store: state, Git: workspace.ExecGitRunner{}}
	service := &tools.Service{Workspaces: registry, Command: tools.OSCommandRunner{}}
	sdkServer := bridgemcp.NewServer(cfg, provider, registry, service)
	return cfg, state, service, bridgemcp.NewHTTPHandler(cfg, provider, sdkServer), nil
}

func serveUntilContext(ctx context.Context, server *http.Server) error {
	errorsChannel := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsChannel <- err
		}
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errorsChannel:
		return err
	}
}

func loadConfig() (config.Config, error) {
	cfg, err := config.Load(environment(), "")
	if err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func environment() map[string]string {
	result := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			result[key] = value
		}
	}
	return result
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func printHelp(out io.Writer) {
	fmt.Fprintln(out, "Usage: mcp-bridge <command>")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Commands:")
	for _, command := range []string{
		"setup     run first-time setup, or re-run it",
		"status    show the connection status",
		"doctor    diagnose the runtime environment and connectivity",
		"config    inspect and change settings safely",
		"remove    disable automatic startup",
	} {
		fmt.Fprintln(out, "  "+command)
	}
}
