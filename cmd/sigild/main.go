// Command sigild is the trusted Sigil broker daemon. It alone owns role
// configuration, private-key loading, installation cache state, credential
// minting, and compatibility command execution.
//
// Same-user workstation mode (default) prevents accidental credential
// fallback and API misuse, but it does NOT make broker files unreadable to
// another process with the same UID. Enforced key secrecy requires a
// hard-isolation deployment with a separate broker identity and restricted
// admin-socket reachability.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sigil/internal/broker"
	"sigil/internal/provider/github"
	"sigil/internal/runtime"
	"sigil/internal/secret"
	utransport "sigil/internal/transport/unix"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sigild: %v\n", err)
		os.Exit(1)
	}
}

type rootList []string

func (s *rootList) String() string     { return strings.Join(*s, ",") }
func (s *rootList) Set(v string) error { *s = append(*s, v); return nil }

func run() error {
	var workspaceRoots rootList
	flags := flag.NewFlagSet("sigild", flag.ContinueOnError)
	configDir := flags.String("config-dir", defaultConfigDir(), "broker-owned role configuration directory")
	cacheDir := flags.String("cache-dir", defaultCacheDir(), "broker-owned cache directory")
	runtimeDir := flags.String("runtime-dir", "", "runtime directory override (default: XDG_RUNTIME_DIR/sigil or ~/.local/state/sigil)")
	flags.Var(&workspaceRoots, "workspace-root", "approved workspace root (repeatable)")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}

	// Restrictive umask before creating any runtime, socket, lock, or temp files.
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	paths, err := runtime.Resolve()
	if err != nil {
		return err
	}
	if *runtimeDir != "" {
		paths = runtime.Paths{
			Dir:         *runtimeDir,
			AgentSocket: filepath.Join(*runtimeDir, "sigil.sock"),
			AdminSocket: filepath.Join(*runtimeDir, "sigil-admin.sock"),
			LockFile:    filepath.Join(*runtimeDir, "sigild.lock"),
		}
	}
	if err := runtime.EnsureDir(paths.Dir); err != nil {
		return err
	}
	lock, err := runtime.Lock(paths.LockFile)
	if err != nil {
		return err
	}
	defer runtime.Unlock(lock)
	// Only after the instance lock is held: reclaim stale sockets, refuse to
	// replace a live broker.
	if err := runtime.ClaimSocket(paths.AgentSocket); err != nil {
		return err
	}
	if err := runtime.ClaimSocket(paths.AdminSocket); err != nil {
		return err
	}
	defer runtime.CleanupSockets(paths.AgentSocket, paths.AdminSocket)

	roles, err := broker.LoadRoleSet(*configDir)
	if err != nil {
		return err
	}
	roots := append([]string(nil), workspaceRoots...)
	if extra := os.Getenv("SIGIL_WORKSPACE_ROOTS"); extra != "" {
		roots = append(roots, filepath.SplitList(extra)...)
	}
	if len(roots) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("no workspace roots configured and no home directory: specify --workspace-root: %w", err)
		}
		roots = []string{home}
	}
	provider := github.NewProvider(secret.FileStore{}, *cacheDir, roles.Bindings)
	daemon, err := broker.New(broker.Config{
		ConfigDir:      *configDir,
		CacheDir:       *cacheDir,
		WorkspaceRoots: roots,
		Roles:          roles,
		Provider:       provider,
	})
	if err != nil {
		return err
	}

	// Daemon-lifetime context: active executions derive from this via
	// BaseContext, so SIGINT/SIGTERM cancellation propagates to runner.Run
	// and the SIGTERM->SIGKILL killTree path runs. http.Server.Shutdown alone
	// does not interrupt active connections; without this a long-running
	// gh/git child could be orphaned with the broker credential in its env.
	// See https://pkg.go.dev/net/http#Server.Shutdown
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	defer daemonCancel()

	agentListener, agentServer, err := utransport.ServeOnSocketWithBase(paths.AgentSocket, utransport.AgentHandler(), daemonCtx)
	if err != nil {
		return err
	}
	defer agentListener.Close()
	adminListener, adminServer, err := utransport.ServeOnSocketWithBase(paths.AdminSocket,
		utransport.AdminHandler(utransport.ExecutorFunc(daemon.ExecTransport)), daemonCtx)
	if err != nil {
		return err
	}
	defer adminListener.Close()

	fmt.Printf("sigild: agent socket %s\n", paths.AgentSocket)
	fmt.Printf("sigild: admin socket %s\n", paths.AdminSocket)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	// Cancel active executions first so the runner tears down the child
	// process group, then wait for handlers to finish.
	daemonCancel()
	// Shutdown budget must cover the runner SIGTERM grace (5s) + SIGKILL reap
	// (1s) plus transport overhead; TermGracePeriod alone (5s) is too short.
	shutCtx, cancel := context.WithTimeout(context.Background(), utransport.TermGracePeriod+10*time.Second)
	defer cancel()
	if err := agentServer.Shutdown(shutCtx); err != nil {
		return fmt.Errorf("agent shutdown: %w", err)
	}
	if err := adminServer.Shutdown(shutCtx); err != nil {
		return fmt.Errorf("admin shutdown: %w", err)
	}
	return nil
}

func defaultConfigDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "sigil")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "sigil")
}

func defaultCacheDir() string {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "sigil")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "sigil")
}
