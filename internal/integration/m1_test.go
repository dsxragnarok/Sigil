// Package integration proves the M1 full chain with nothing faked except
// the external GitHub API boundary:
//
//	sigil CLI -> sigil-admin.sock -> broker -> provider -> runner (real git)
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"sigil/internal/broker"
	"sigil/internal/provider/github"
	"sigil/internal/secret"
	"sigil/internal/sigil"
	utransport "sigil/internal/transport/unix"
)

const integrationToken = "ghs_integration-marker-token"

type apiStub struct {
	t            *testing.T
	discoveries  atomic.Int32
	tokensMinted atomic.Int32
	sawAuth      atomic.Bool
}

func (s *apiStub) handler(w http.ResponseWriter, r *http.Request) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") && len(auth) > 20 {
		s.sawAuth.Store(true)
	} else {
		s.t.Errorf("missing app JWT auth on %s %s", r.Method, r.URL.Path)
	}
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/installation"):
		s.discoveries.Add(1)
		_, _ = io.WriteString(w, `{"id":424242}`)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens"):
		s.tokensMinted.Add(1)
		_, _ = io.WriteString(w, `{"token":"`+integrationToken+`","expires_at":"2030-01-02T03:04:05Z"}`)
	default:
		s.t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func newStubServer(t *testing.T, stub *apiStub) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(stub.handler))
	t.Cleanup(server.Close)
	return server
}

type chain struct {
	workspace string
	repo      string
	stub      *apiStub
}

func startChain(t *testing.T) *chain {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	cacheDir := filepath.Join(base, "cache")
	workspace := filepath.Join(base, "work")
	for _, dir := range []string{configDir, cacheDir, workspace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(configDir, "reviewer.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	roleJSON := `{"client_id": "integration-client", "private_key_path": "reviewer.pem", "default_repository": "o/integration"}`
	if err := os.WriteFile(filepath.Join(configDir, "reviewer.json"), []byte(roleJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	stub := &apiStub{t: t}
	_ = &http.Server{Handler: http.HandlerFunc(stub.handler)}
	server := newStubServer(t, stub)

	roles, err := broker.LoadRoleSet(configDir)
	if err != nil {
		t.Fatal(err)
	}
	provider := &github.Provider{
		Secrets:  secret.FileStore{},
		Cache:    github.NewInstallationCache(cacheDir),
		API:      &github.Client{BaseURL: server.URL, HTTPClient: server.Client()},
		Bindings: roles.Bindings,
	}
	daemon, err := broker.New(broker.Config{
		ConfigDir:      configDir,
		CacheDir:       cacheDir,
		WorkspaceRoots: []string{workspace},
		Roles:          roles,
		Provider:       provider,
	})
	if err != nil {
		t.Fatal(err)
	}

	socketDir, err := os.MkdirTemp("/tmp", "sigil-int-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	adminSock := filepath.Join(socketDir, "admin.sock")
	agentSock := filepath.Join(socketDir, "agent.sock")
	agentListener, agentServer, err := utransport.ServeOnSocket(agentSock, utransport.AgentHandler())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agentServer.Close(); agentListener.Close() })
	adminListener, adminServer, err := utransport.ServeOnSocket(adminSock,
		utransport.AdminHandler(utransport.ExecutorFunc(daemon.ExecTransport)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adminServer.Close(); adminListener.Close() })

	t.Setenv("SIGIL_ADMIN_SOCKET", adminSock)
	// Broker-owned state must win even when the client points elsewhere.
	t.Setenv("SIGIL_CONFIG_DIR", t.TempDir())
	t.Setenv("SIGIL_CACHE_DIR", t.TempDir())
	t.Setenv("GH_TOKEN", "leak-personal-token")

	return &chain{workspace: workspace, stub: stub}
}

func (c *chain) run(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := sigil.Run(context.Background(), args, strings.NewReader(stdin), &out, &errOut)
	return out.String(), errOut.String(), err
}

func TestFullChainGitVersion(t *testing.T) {
	c := startChain(t)
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(c.workspace); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(previous) }()

	out, _, err := c.run(t, "", "exec", "reviewer", "--", "git", "--version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "git version") {
		t.Fatalf("unexpected output %q", out)
	}
	if strings.Contains(out, integrationToken) {
		t.Fatalf("token leaked to client: %q", out)
	}
	if c.stub.discoveries.Load() != 1 || c.stub.tokensMinted.Load() != 1 {
		t.Fatalf("provider did not mint server-side: discoveries=%d tokens=%d",
			c.stub.discoveries.Load(), c.stub.tokensMinted.Load())
	}
	if !c.stub.sawAuth.Load() {
		t.Fatal("provider never authenticated with app JWT")
	}
}

func TestFullChainHookSuppressedOnRealPath(t *testing.T) {
	c := startChain(t)
	repo := filepath.Join(c.workspace, "repo")
	if err := os.Mkdir(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if combined, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, combined)
		}
	}
	git("init", "-q")
	git("config", "user.email", "t@t")
	git("config", "user.name", "t")
	marker := filepath.Join(repo, "hook-marker")
	if err := os.WriteFile(filepath.Join(repo, ".git", "hooks", "pre-commit"),
		[]byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// The dumb client sends its cwd; run the chain from inside the repo.
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repo); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(previous) }()

	out, errOut, err := c.run(t, "", "exec", "reviewer", "--", "git",
		"-c", "user.email=t@t", "-c", "user.name=t", "commit", "--allow-empty", "-m", "chain")
	if err != nil {
		t.Fatalf("err=%v stdout=%q stderr=%q", err, out, errOut)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("repository hook executed on the real broker path")
	}
	if strings.Contains(out+errOut, integrationToken) {
		t.Fatal("token leaked to client streams")
	}
}

func TestFullChainDangerousGitRejected(t *testing.T) {
	c := startChain(t)
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(c.workspace); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(previous) }()

	_, _, err = c.run(t, "", "exec", "reviewer", "--", "git", "--git-dir=/evil", "status")
	if err == nil {
		t.Fatal("expected broker rejection of --git-dir")
	}
	if strings.Contains(fmt.Sprint(err), integrationToken) {
		t.Fatal("token in rejection error")
	}
}
