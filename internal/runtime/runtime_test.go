package runtime

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveUsesXDGWhenSet(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	paths, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if want := "/run/user/1000/sigil"; paths.Dir != want {
		t.Fatalf("Dir = %q, want %q", paths.Dir, want)
	}
	if !strings.HasSuffix(paths.AgentSocket, "sigil.sock") || !strings.HasSuffix(paths.AdminSocket, "sigil-admin.sock") {
		t.Fatalf("unexpected socket paths: %#v", paths)
	}
}

func TestResolveFallsBackToLocalState(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	paths, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(paths.Dir, ".local/run") {
		t.Fatalf("must not use ~/.local/run, got %q", paths.Dir)
	}
	if !strings.HasSuffix(paths.Dir, filepath.Join(".local", "state", "sigil")) {
		t.Fatalf("unexpected fallback dir %q", paths.Dir)
	}
}

func TestEnsureDirIsOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sigil")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("runtime dir mode = %o, want 700", perm)
	}
}

func TestSecondLockFailsAlreadyRunning(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "sigild.lock")
	first, err := Lock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer Unlock(first)
	if _, err := Lock(lockPath); err == nil || !strings.Contains(err.Error(), "sigild already running") {
		t.Fatalf("expected already-running error, got %v", err)
	}
}

func TestClaimSocketReclaimsStaleButNotLive(t *testing.T) {
	// Unix socket paths are length-limited; keep the dir short.
	dir, err := os.MkdirTemp("/tmp", "sigil-rt-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	stale := filepath.Join(dir, "stale.sock")
	listener, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	// Live socket must be refused.
	if err := ClaimSocket(stale); err == nil || !strings.Contains(err.Error(), "is live") {
		t.Fatalf("expected live-socket refusal, got %v", err)
	}
	listener.Close()
	// Closed listener leaves a stale socket file: must be reclaimed.
	if err := ClaimSocket(stale); err != nil {
		t.Fatalf("expected stale reclaim, got %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale socket not removed: %v", err)
	}
	// Missing socket is fine.
	if err := ClaimSocket(filepath.Join(dir, "missing.sock")); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupSocketsRemovesOwned(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.sock")
	b := filepath.Join(dir, "b.sock")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	CleanupSockets(a, b, filepath.Join(dir, "missing.sock"))
	for _, p := range []string{a, b} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("socket %s not cleaned", p)
		}
	}
}
