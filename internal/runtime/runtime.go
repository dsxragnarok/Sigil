package runtime

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Paths owns the broker runtime file locations. The directory is owner-only
// (0700) in default same-user mode. Same-UID processes are NOT kept out by
// file modes alone; hard isolation needs an OS/container boundary.
type Paths struct {
	Dir         string
	AgentSocket string
	AdminSocket string
	LockFile    string
}

// Resolve returns runtime paths. Linux/XDG uses $XDG_RUNTIME_DIR/sigil;
// otherwise falls back to ~/.local/state/sigil. Never ~/.local/run.
func Resolve() (Paths, error) {
	var dir string
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		dir = filepath.Join(runtimeDir, "sigil")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, fmt.Errorf("find home directory: %w", err)
		}
		dir = filepath.Join(home, ".local", "state", "sigil")
	}
	return Paths{
		Dir:         dir,
		AgentSocket: filepath.Join(dir, "sigil.sock"),
		AdminSocket: filepath.Join(dir, "sigil-admin.sock"),
		LockFile:    filepath.Join(dir, "sigild.lock"),
	}, nil
}

// EnsureDir creates the runtime directory under umask 0077 and enforces
// owner-only permissions.
func EnsureDir(dir string) error {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create runtime directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure runtime directory %s: %w", dir, err)
	}
	return nil
}

// Lock acquires a non-blocking exclusive flock held for the daemon lifetime.
// Returns the open lock file; caller must keep it open and Close on shutdown.
func Lock(lockPath string) (*os.File, error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("sigild already running (lock %s): %w", lockPath, err)
	}
	return f, nil
}

// Unlock releases the lock file.
func Unlock(f *os.File) {
	if f != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}

// SocketLive reports whether a Unix socket accepts connections.
func SocketLive(path string) bool {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ClaimSocket removes a stale socket after the instance lock is held, and
// refuses to replace a live one. Must only be called while holding Lock.
func ClaimSocket(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	if SocketLive(path) {
		return fmt.Errorf("socket %s is live; refusing to replace a running broker", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

// CleanupSockets unlinks owned socket paths on graceful shutdown.
func CleanupSockets(paths ...string) {
	for _, path := range paths {
		_ = os.Remove(path)
	}
}
