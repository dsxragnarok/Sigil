// Package broker orchestrates admin-socket execution server-side:
// validate request, resolve the role binding from broker-owned
// configuration, obtain a provider credential, and drive the hardened runner.
// Configuration and cache locations are fixed at construction; client
// environment cannot redirect them.
package broker

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"sigil/internal/provider"
	"sigil/internal/provider/github"
	"sigil/internal/runner"
	utransport "sigil/internal/transport/unix"
)

var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// ExecRequest is one validated admin execution. Role is admin-path only.
type ExecRequest struct {
	Role           string
	Repository     string
	InstallationID int64
	WorkingDir     string
	Command        []string
	Timeout        time.Duration
}

// Provider mints short-lived credentials inside the broker. It is the
// shared credential-oriented contract; see internal/provider.
type Provider = provider.Provider

// RunnerFunc executes a hardened child process.
type RunnerFunc func(ctx context.Context, req runner.Request) (int, error)

// Broker owns config/cache locations, workspace roots, and the
// validate -> resolve -> credential -> execute -> stream flow.
type Broker struct {
	configDir string
	cacheDir  string
	roots     []string
	bindings  map[string]github.Binding
	defaults  map[string]string
	provider  Provider
	run       RunnerFunc
}

// Config fixes broker-owned state at daemon startup.
type Config struct {
	ConfigDir      string
	CacheDir       string
	WorkspaceRoots []string
	Roles          RoleSet
	Provider       Provider
	Runner         RunnerFunc
}

// New validates workspace roots (canonicalized up front) and returns the
// broker. Roots must exist and be resolvable; ambiguity fails closed.
func New(config Config) (*Broker, error) {
	if config.ConfigDir == "" || config.CacheDir == "" {
		return nil, fmt.Errorf("config and cache directories are required")
	}
	if len(config.Roles.Bindings) == 0 {
		return nil, fmt.Errorf("no role bindings configured")
	}
	if config.Provider == nil {
		return nil, fmt.Errorf("provider is required")
	}
	run := config.Runner
	if run == nil {
		run = runner.Run
	}
	roots, err := canonicalizeRoots(config.WorkspaceRoots)
	if err != nil {
		return nil, err
	}
	return &Broker{
		configDir: config.ConfigDir,
		cacheDir:  config.CacheDir,
		roots:     roots,
		bindings:  config.Roles.Bindings,
		defaults:  config.Roles.DefaultRepos,
		provider:  config.Provider,
		run:       run,
	}, nil
}

// ExecTransport adapts the broker to the chunked transport executor: it
// converts wire metadata into an ExecRequest and streams IO through.
func (b *Broker) ExecTransport(ctx context.Context, meta utransport.Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return b.Exec(ctx, ExecRequest{
		Role:           meta.Role,
		Repository:     meta.Repository,
		InstallationID: meta.InstallationID,
		WorkingDir:     meta.WorkingDir,
		Command:        meta.Command,
		Timeout:        utransport.TimeoutFor(meta.TimeoutSeconds),
	}, stdin, stdout, stderr)
}

// Exec runs validate -> resolve -> credential -> execute -> stream.
func (b *Broker) Exec(ctx context.Context, req ExecRequest, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if !roleNamePattern.MatchString(req.Role) {
		return 0, fmt.Errorf("invalid role %q", req.Role)
	}
	if _, ok := b.bindings[req.Role]; !ok {
		return 0, fmt.Errorf("unknown role %q", req.Role)
	}
	if len(req.Command) == 0 {
		return 0, fmt.Errorf("missing command")
	}
	if req.Command[0] != "gh" && req.Command[0] != "git" {
		return 0, fmt.Errorf("command must be gh or git, got %q", req.Command[0])
	}

	repository := req.Repository
	if repository == "" {
		repository = repositoryFromCommand(req.Command)
	}
	if repository == "" {
		repository = b.defaults[req.Role]
	}
	if repository == "" {
		return 0, fmt.Errorf("no repository supplied; use --repo owner/name, a gh -R/--repo flag, or default_repository in the role config")
	}
	if _, _, err := github.SplitRepository(repository); err != nil {
		return 0, err
	}

	workdir, err := b.canonicalWorkdir(req.WorkingDir, req.Command[0])
	if err != nil {
		return 0, err
	}

	provider := b.provider
	if req.InstallationID != 0 {
		overrider, ok := provider.(interface {
			WithInstallationOverride(role string, id int64) *github.Provider
		})
		if !ok {
			return 0, fmt.Errorf("installation ID overrides are not supported")
		}
		provider = overrider.WithInstallationOverride(req.Role, req.InstallationID)
	}

	credential, err := provider.Prepare(ctx, github.CredentialRequest{Identity: req.Role, Repository: repository})
	if err != nil {
		return 0, err
	}
	code, err := b.run(ctx, runner.Request{
		Command:    req.Command,
		Token:      credential.Token,
		Repository: repository,
		WorkingDir: workdir,
		Stdin:      stdin,
		Stdout:     stdout,
		Stderr:     stderr,
		Timeout:    req.Timeout,
	})
	if err != nil {
		return 0, err
	}
	return code, nil
}

// repositoryFromCommand infers owner/name from gh -R/--repo flags.
func repositoryFromCommand(command []string) string {
	if len(command) == 0 || command[0] != "gh" {
		return ""
	}
	for index := 1; index < len(command); index++ {
		arg := command[index]
		if arg == "--" {
			break
		}
		var candidate string
		switch {
		case arg == "-R" || arg == "--repo":
			if index+1 < len(command) {
				candidate = command[index+1]
				index++
			}
		case strings.HasPrefix(arg, "--repo="):
			candidate = strings.TrimPrefix(arg, "--repo=")
		case strings.HasPrefix(arg, "-R") && len(arg) > 2:
			candidate = strings.TrimPrefix(arg, "-R")
		}
		if candidate != "" && !strings.HasPrefix(candidate, "-") {
			trimmed := strings.TrimPrefix(candidate, "github.com/")
			if _, _, err := github.SplitRepository(trimmed); err == nil {
				return trimmed
			}
		}
	}
	return ""
}
