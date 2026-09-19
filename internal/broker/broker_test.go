package broker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sigil/internal/provider/github"
	"sigil/internal/runner"
)

type fakeProvider struct {
	token string
	err   error
	last  github.CredentialRequest
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) ResolveIdentity(_ context.Context, binding github.Binding) (github.Identity, error) {
	return github.Identity{Name: binding.Name, ClientID: binding.ClientID}, nil
}

func (f *fakeProvider) Prepare(_ context.Context, req github.CredentialRequest) (github.Credential, error) {
	f.last = req
	if f.err != nil {
		return github.Credential{}, f.err
	}
	return github.Credential{Token: f.token, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type stubRunner struct {
	err      error
	code     int
	sawToken string
	sawDir   string
	sawCmd   []string
	stdout   string
	stderr   string
}

func (s *stubRunner) run(_ context.Context, req runner.Request) (int, error) {
	s.sawToken = req.Token
	s.sawDir = req.WorkingDir
	s.sawCmd = req.Command
	if s.stdout != "" {
		_, _ = io.WriteString(req.Stdout, s.stdout)
	}
	if s.stderr != "" {
		_, _ = io.WriteString(req.Stderr, s.stderr)
	}
	return s.code, s.err
}

func testBroker(t *testing.T, provider Provider, run RunnerFunc) (*Broker, string) {
	t.Helper()
	configDir := t.TempDir()
	roleJSON := `{"client_id": "client-1", "private_key_path": "key.pem", "default_repository": "dsxragnarok/council"}`
	if err := os.WriteFile(filepath.Join(configDir, "reviewer.json"), []byte(roleJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	bareJSON := `{"client_id": "client-2", "private_key_path": "key.pem"}`
	if err := os.WriteFile(filepath.Join(configDir, "nodefault.json"), []byte(bareJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	roles, err := LoadRoleSet(configDir)
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	// Broker canonicalizes roots (e.g. /var -> /private/var on macOS);
	// tests must compare against the canonical form.
	workspace, err = filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{
		ConfigDir:      configDir,
		CacheDir:       t.TempDir(),
		WorkspaceRoots: []string{workspace},
		Roles:          roles,
		Provider:       provider,
		Runner:         run,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b, workspace
}

func TestExecResolvesBindingAndStreams(t *testing.T) {
	provider := &fakeProvider{token: "broker-token"}
	stub := &stubRunner{stdout: "out", stderr: "err"}
	b, workspace := testBroker(t, provider, stub.run)

	var out, errOut bytes.Buffer
	code, err := b.Exec(context.Background(), ExecRequest{
		Role:       "reviewer",
		Repository: "dsxragnarok/council",
		WorkingDir: workspace,
		Command:    []string{"gh", "pr", "view", "1"},
	}, strings.NewReader("in"), &out, &errOut)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if provider.last.Identity != "reviewer" || provider.last.Repository != "dsxragnarok/council" {
		t.Fatalf("provider req = %#v", provider.last)
	}
	if stub.sawToken != "broker-token" {
		t.Fatalf("runner token = %q", stub.sawToken)
	}
	if stub.sawDir != workspace {
		t.Fatalf("runner dir = %q, want %q", stub.sawDir, workspace)
	}
	if out.String() != "out" || errOut.String() != "err" {
		t.Fatalf("streams = %q %q", out.String(), errOut.String())
	}
}

func TestUnknownRoleMalformedRepoFailClosed(t *testing.T) {
	provider := &fakeProvider{token: "x"}
	stub := &stubRunner{}
	b, workspace := testBroker(t, provider, stub.run)

	for name, req := range map[string]ExecRequest{
		"unknown role":  {Role: "admin", Repository: "o/r", WorkingDir: workspace, Command: []string{"gh"}},
		"invalid role":  {Role: "../x", Repository: "o/r", WorkingDir: workspace, Command: []string{"gh"}},
		"bad repo":      {Role: "reviewer", Repository: "not-a-repo", WorkingDir: workspace, Command: []string{"gh"}},
		"no repo":       {Role: "nodefault", WorkingDir: workspace, Command: []string{"git", "status"}},
		"bad program":   {Role: "reviewer", Repository: "o/r", WorkingDir: workspace, Command: []string{"sh", "-c", "x"}},
		"no command":    {Role: "reviewer", Repository: "o/r", WorkingDir: workspace},
		"git needs dir": {Role: "reviewer", Repository: "o/r", Command: []string{"git", "status"}},
	} {
		if _, err := b.Exec(context.Background(), req, nil, io.Discard, io.Discard); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	if stub.sawToken != "" {
		t.Fatal("runner must not run on invalid requests")
	}
}

func TestRepositoryInference(t *testing.T) {
	provider := &fakeProvider{token: "x"}
	stub := &stubRunner{}
	b, workspace := testBroker(t, provider, stub.run)

	// From gh -R flag.
	if _, err := b.Exec(context.Background(), ExecRequest{Role: "reviewer", WorkingDir: workspace,
		Command: []string{"gh", "pr", "view", "-R", "o/inferred"}}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if provider.last.Repository != "o/inferred" {
		t.Fatalf("repository = %q", provider.last.Repository)
	}
	// From role default.
	stub2 := &stubRunner{}
	b2, _ := testBroker(t, provider, stub2.run)
	if _, err := b2.Exec(context.Background(), ExecRequest{Role: "reviewer",
		Command: []string{"gh", "status"}}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if provider.last.Repository != "dsxragnarok/council" {
		t.Fatalf("default repository = %q", provider.last.Repository)
	}
}

func TestWorkdirConfinement(t *testing.T) {
	provider := &fakeProvider{token: "x"}
	stub := &stubRunner{}
	b, workspace := testBroker(t, provider, stub.run)

	sub := filepath.Join(workspace, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Exec(context.Background(), ExecRequest{Role: "reviewer", Repository: "o/r",
		WorkingDir: sub, Command: []string{"git", "status"}}, nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("subdir must be allowed: %v", err)
	}
	if stub.sawDir != sub {
		t.Fatalf("runner dir = %q", stub.sawDir)
	}

	outside := t.TempDir()
	if _, err := b.Exec(context.Background(), ExecRequest{Role: "reviewer", Repository: "o/r",
		WorkingDir: outside, Command: []string{"git", "status"}}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected out-of-root denial")
	}

	// Symlink escape from an allowed root is denied after canonicalization.
	link := filepath.Join(workspace, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Exec(context.Background(), ExecRequest{Role: "reviewer", Repository: "o/r",
		WorkingDir: link, Command: []string{"git", "status"}}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected symlink-escape denial")
	}

	if _, err := b.Exec(context.Background(), ExecRequest{Role: "reviewer", Repository: "o/r",
		WorkingDir: "relative/path", Command: []string{"git", "status"}}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected relative-path denial")
	}
}

func TestClientEnvCannotRedirectBrokerState(t *testing.T) {
	provider := &fakeProvider{token: "x"}
	stub := &stubRunner{}
	b, workspace := testBroker(t, provider, stub.run)

	evil := t.TempDir()
	t.Setenv("SIGIL_CONFIG_DIR", evil)
	t.Setenv("SIGIL_CACHE_DIR", evil)
	if err := os.WriteFile(filepath.Join(evil, "reviewer.json"), []byte(`{"client_id":"evil"} lal`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Exec(context.Background(), ExecRequest{Role: "reviewer", Repository: "o/r",
		WorkingDir: workspace, Command: []string{"gh"}}, nil, io.Discard, io.Discard); err != nil {
		t.Fatalf("broker must ignore client env: %v", err)
	}
	if stub.sawToken != "x" {
		t.Fatal("expected stub runner to run with broker config")
	}
}

func TestNoCredentialInErrors(t *testing.T) {
	provider := &fakeProvider{token: "ghs_marker-token-1"}
	runnerErr := fmt.Errorf("runner exploded")
	stub := &stubRunner{err: runnerErr}
	b, workspace := testBroker(t, provider, stub.run)

	_, err := b.Exec(context.Background(), ExecRequest{Role: "reviewer", Repository: "o/r",
		WorkingDir: workspace, Command: []string{"gh"}}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected runner error")
	}
	if strings.Contains(err.Error(), "ghs_marker-token-1") {
		t.Fatalf("credential in error: %q", err.Error())
	}

	provider2 := &fakeProvider{err: fmt.Errorf("provider exploded")}
	b2, workspace2 := testBroker(t, provider2, (&stubRunner{}).run)
	_, err = b2.Exec(context.Background(), ExecRequest{Role: "unknown-role", Repository: "o/r",
		WorkingDir: workspace2, Command: []string{"gh"}}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unknown role") {
		t.Fatalf("expected unknown-role error, got %v", err)
	}
}

func TestExplicitIdentityRequired(t *testing.T) {
	configDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "reviewer.json"), []byte(`{"private_key_path":"k.pem"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRoleSet(configDir); err == nil || !strings.Contains(err.Error(), "client_id is required") {
		t.Fatalf("expected explicit client_id error, got %v", err)
	}
}

func TestNewRejectsBadRoots(t *testing.T) {
	roles := RoleSet{Bindings: map[string]github.Binding{"r": {}}, DefaultRepos: map[string]string{}}
	provider := &fakeProvider{}
	for name, roots := range map[string][]string{
		"relative": {"relative/path"},
		"missing":  {filepath.Join(os.TempDir(), "sigil-no-such-root-xyz")},
	} {
		_, err := New(Config{ConfigDir: "c", CacheDir: "c", WorkspaceRoots: roots, Roles: roles, Provider: provider})
		if err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}
