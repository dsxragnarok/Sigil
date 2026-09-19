// Package runner spawns trusted gh/git processes for the broker.
// Every child runs in a sanitized world: fresh broker-owned HOME and empty
// GH_CONFIG_DIR, scrubbed personal-credential environment, suppressed Git
// hooks, an explicit canonical working directory, and its own process group
// so timeouts reap the whole tree. Credentials never appear in argv, temp
// files, or error strings; child stdout/stderr is scrubbed of the broker
// token and `gh auth` disclosure commands are rejected so bearer material
// cannot cross IPC via output frames.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// DefaultTimeout bounds one execution when the caller sets no timeout.
const DefaultTimeout = 120 * time.Second

// GracePeriod is the SIGTERM-to-SIGKILL delay for the child process group.
const GracePeriod = 5 * time.Second

var standardSystemDirs = []string{
	"/opt/homebrew/bin",
	"/usr/local/bin",
	"/usr/bin",
	"/bin",
}

// testTrustedDirs overrides lookup directories in unit tests.
var testTrustedDirs []string

func trustedDirs() []string {
	if len(testTrustedDirs) > 0 {
		return testTrustedDirs
	}
	return standardSystemDirs
}

// Request is one hardened compatibility execution. WorkingDir must already
// be validated and canonicalized by the broker; when empty the child runs in
// a fresh empty temp directory, never the daemon cwd.
type Request struct {
	Command    []string
	Token      string
	Repository string
	WorkingDir string
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	Timeout    time.Duration
}

// Run executes the request, streaming IO. A started child that exits non-zero
// returns its code with a nil error; inability to start, timeouts, and
// cancellations return errors without credential material.
func Run(ctx context.Context, req Request) (int, error) {
	if len(req.Command) == 0 {
		return 0, fmt.Errorf("missing command")
	}
	program := req.Command[0]
	if strings.ContainsAny(program, `/\`) || (program != "gh" && program != "git") {
		return 0, fmt.Errorf("command must be gh or git, got %q", program)
	}
	arguments := append([]string(nil), req.Command[1:]...)
	if program == "gh" {
		if err := ValidateGhArguments(arguments); err != nil {
			return 0, err
		}
	}
	if program == "git" {
		if err := ValidateGitArguments(arguments); err != nil {
			return 0, err
		}
		// Mandatory hook suppression ahead of caller arguments. Current Git
		// defines no global --no-hooks flag; core.hooksPath=/dev/null is the
		// supported all-hooks control. Repository-controlled hooks must never
		// execute inside the broker process tree.
		arguments = append([]string{
			"--no-pager",
			"-c", "core.hooksPath=/dev/null",
			"-c", "credential.https://github.com.helper=",
			"-c", "credential.https://github.com.helper=!gh auth git-credential",
		}, arguments...)
	}

	trustedPathStr := trustedPath()
	if trustedPathStr == "" {
		return 0, errors.New("no safe directories available in trusted PATH")
	}
	targetBinary, err := lookPathIn(program, trustedPathStr)
	if err != nil {
		return 0, fmt.Errorf("lookup %s: %w", program, err)
	}

	dir := req.WorkingDir
	if dir == "" {
		empty, err := freshTempDir("sigil-work-")
		if err != nil {
			return 0, err
		}
		defer os.RemoveAll(empty)
		dir = empty
	} else {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return 0, fmt.Errorf("working directory is not a directory")
		}
	}

	home, ghConfigDir, cleanup, err := freshExecHome()
	if err != nil {
		return 0, err
	}
	defer cleanup()

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdin := req.Stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	stdout := req.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := req.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	// Bearer material must never cross IPC via child output. The broker
	// credential lives in the child environment (required for gh/git HTTPS),
	// so `gh auth token`, repo-local `!` aliases (`!env`, `!echo $GH_TOKEN`),
	// or helpers could otherwise echo it to stdout/stderr frames. Wrap both
	// streams with a token-scrubbing filter; `gh auth` disclosure commands
	// are rejected above, this is defense in depth for arbitrary output.
	var stdoutFilter, stderrFilter *redactWriter
	if req.Token != "" {
		stdoutFilter = newRedactWriter(stdout, req.Token)
		stderrFilter = newRedactWriter(stderr, req.Token)
		stdout = stdoutFilter
		stderr = stderrFilter
	}

	child := exec.CommandContext(ctx, targetBinary, arguments...)
	child.Dir = dir
	child.Stdin = stdin
	child.Stdout = stdout
	child.Stderr = stderr
	child.Env = childEnv(os.Environ(), req.Token, req.Repository, trustedPathStr, home, ghConfigDir)
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Disable the Go 1.20+ default Cancel (immediate SIGKILL on context
	// expiry) so timeouts honor the SIGTERM grace period in killTree.
	child.Cancel = func() error { return nil }

	if err := child.Start(); err != nil {
		return 0, fmt.Errorf("run %s: %w", program, err)
	}
	// Flush redaction buffers on every exit path so trailing bytes (up to
	// len(token)-1 held to catch split-token writes) are emitted scrubbed.
	if stdoutFilter != nil {
		defer func() { _ = stdoutFilter.Flush() }()
	}
	if stderrFilter != nil {
		defer func() { _ = stderrFilter.Flush() }()
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- child.Wait() }()

	select {
	case waitErr := <-waitCh:
		// Child exited first and waitCh is drained: do not call killTree
		// here, it would block the full grace+reap timeouts on an empty
		// channel. The child is reaped; just report timeout/cancel if the
		// context also fired.
		if ctx.Err() == context.DeadlineExceeded {
			return 0, fmt.Errorf("%s execution timed out", program)
		}
		if ctx.Err() == context.Canceled {
			return 0, fmt.Errorf("%s execution cancelled", program)
		}
		if waitErr != nil {
			var exitError *exec.ExitError
			if errors.As(waitErr, &exitError) {
				return exitError.ExitCode(), nil
			}
			return 0, fmt.Errorf("run %s: %w", program, waitErr)
		}
		return 0, nil
	case <-ctx.Done():
		// Timeout or cancellation: SIGTERM the whole process group, wait the
		// grace period, then SIGKILL any remainder so forked descendants
		// cannot linger.
		killTree(child, waitCh)
		if ctx.Err() == context.DeadlineExceeded {
			return 0, fmt.Errorf("%s execution timed out", program)
		}
		return 0, fmt.Errorf("%s execution cancelled", program)
	}
}

// killTree SIGTERMs the child process group, waits the grace period for the
// reaped child, then SIGKILLs the group if anything remains.
func killTree(child *exec.Cmd, waitCh <-chan error) {
	if child.Process == nil {
		return
	}
	if child.ProcessState != nil && child.ProcessState.Exited() {
		return
	}
	_ = syscall.Kill(-child.Process.Pid, syscall.SIGTERM)
	select {
	case <-waitCh:
		return
	case <-time.After(GracePeriod):
	}
	_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
	// Brief reap poll only: SIGKILL leaves no graceful remainder to wait for.
	select {
	case <-waitCh:
	case <-time.After(time.Second):
	}
}

// freshTempDir creates an owner-only temp directory.
func freshTempDir(prefix string) (string, error) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", fmt.Errorf("create execution home: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("secure execution home: %w", err)
	}
	return dir, nil
}

// freshExecHome creates a fresh broker-owned HOME containing a fresh empty
// GH_CONFIG_DIR. Caller must run cleanup after the child exits.
func freshExecHome() (home, ghConfigDir string, cleanup func(), err error) {
	home, err = freshTempDir("sigil-exec-")
	if err != nil {
		return "", "", nil, err
	}
	ghConfigDir = filepath.Join(home, "gh-config")
	if err := os.Mkdir(ghConfigDir, 0o700); err != nil {
		os.RemoveAll(home)
		return "", "", nil, fmt.Errorf("create GH_CONFIG_DIR: %w", err)
	}
	return home, ghConfigDir, func() { _ = os.RemoveAll(home) }, nil
}

func isSafeDir(dir string) bool {
	if dir == "" || dir == "." || !filepath.IsAbs(dir) {
		return false
	}
	clean := filepath.Clean(dir)
	if len(testTrustedDirs) == 0 {
		if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") ||
			clean == "/var/tmp" || strings.HasPrefix(clean, "/var/tmp/") ||
			clean == "/dev/shm" || strings.HasPrefix(clean, "/dev/shm/") ||
			clean == "/private/tmp" || strings.HasPrefix(clean, "/private/tmp/") ||
			clean == "/private/var/tmp" || strings.HasPrefix(clean, "/private/var/tmp/") {
			return false
		}
	}
	info, err := os.Stat(clean)
	if err != nil || !info.IsDir() {
		return false
	}
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return false
	}
	if perm&0o020 != 0 {
		if !isOwnedByCurrentOrRoot(info) {
			return false
		}
	}
	return true
}

func isOwnedByCurrentOrRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == 0 || stat.Uid == uint32(os.Getuid())
}

func trustedPath() string {
	var safe []string
	for _, dir := range trustedDirs() {
		clean := filepath.Clean(dir)
		if isSafeDir(clean) {
			safe = append(safe, clean)
		}
	}
	return strings.Join(safe, string(filepath.ListSeparator))
}

func lookPathIn(file string, pathEnv string) (string, error) {
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		target := filepath.Join(dir, file)
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		if !info.IsDir() && info.Mode()&0o111 != 0 {
			return target, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in PATH", file)
}

// redactWriter scrubs bearer material from a streaming child output.
// The token may split across Write calls, so up to len(token)-1 trailing
// bytes are held back until the next Write or Flush. Flush must run after
// the child exits to emit the tail scrubbed.
type redactWriter struct {
	w     io.Writer
	token []byte
	repl  []byte
	buf   []byte
}

func newRedactWriter(w io.Writer, token string) *redactWriter {
	return &redactWriter{w: w, token: []byte(token), repl: []byte("[REDACTED]")}
}

func (r *redactWriter) Write(p []byte) (int, error) {
	if len(r.token) == 0 {
		return r.w.Write(p)
	}
	r.buf = append(r.buf, p...)
	r.buf = bytes.ReplaceAll(r.buf, r.token, r.repl)
	keep := len(r.token) - 1
	if keep < 0 {
		keep = 0
	}
	if len(r.buf) <= keep {
		return len(p), nil
	}
	flushUpTo := len(r.buf) - keep
	wrote := 0
	for wrote < flushUpTo {
		n, err := r.w.Write(r.buf[wrote:flushUpTo])
		wrote += n
		if err != nil {
			// Keep unwritten tail (including flushed-prefix remainder) buffered.
			remaining := append([]byte(nil), r.buf[wrote:]...)
			r.buf = remaining
			return 0, err
		}
		if n == 0 {
			break
		}
	}
	remaining := append([]byte(nil), r.buf[flushUpTo:]...)
	r.buf = remaining
	return len(p), nil
}

// Flush emits any held-back tail, scrubbed. Call after child exit.
func (r *redactWriter) Flush() error {
	if len(r.buf) == 0 {
		return nil
	}
	if len(r.token) > 0 {
		r.buf = bytes.ReplaceAll(r.buf, r.token, r.repl)
	}
	_, err := r.w.Write(r.buf)
	r.buf = nil
	return err
}

// childEnv builds the sanitized child environment: a small allowlist plus
// broker pins, with caller personal-credential state scrubbed before the
// broker-minted credential is injected.
func childEnv(environment []string, token, repository, trustedPathStr, home, ghConfigDir string) []string {
	allowed := map[string]bool{
		"USER": true,
		"LANG": true,
		"TZ":   true,
		"TERM": true,
	}
	var filtered []string
	for _, entry := range environment {
		eq := strings.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}
		key := entry[:eq]
		// Scrub personal GitHub/enterprise token state, host overrides, SSH
		// agent state, and CLI config locations before injection.
		if key == "GH_TOKEN" || key == "GITHUB_TOKEN" || key == "GH_ENTERPRISE_TOKEN" ||
			key == "GH_HOST" || key == "GH_REPO" || key == "GH_CONFIG_DIR" ||
			key == "SSH_AUTH_SOCK" || key == "HOME" || key == "PATH" {
			continue
		}
		if strings.HasPrefix(key, "GITHUB_") && strings.HasSuffix(key, "_TOKEN") {
			continue
		}
		if allowed[key] {
			filtered = append(filtered, entry)
		}
	}
	filtered = append(filtered, "PATH="+trustedPathStr)
	filtered = append(filtered, "HOME="+home)
	filtered = append(filtered, "GH_CONFIG_DIR="+ghConfigDir)
	filtered = append(filtered, "GH_TOKEN="+token)
	if repository != "" {
		filtered = append(filtered, "GH_REPO="+repository)
	}
	filtered = append(filtered, "GIT_CONFIG_NOSYSTEM=1")
	filtered = append(filtered, "GIT_CONFIG_GLOBAL="+os.DevNull)
	filtered = append(filtered, "GIT_CONFIG_SYSTEM="+os.DevNull)
	filtered = append(filtered, "GIT_SSH_COMMAND=ssh -F "+os.DevNull)
	filtered = append(filtered, "GIT_PAGER=cat")
	filtered = append(filtered, "PAGER=cat")
	filtered = append(filtered, "GIT_EDITOR=true")
	filtered = append(filtered, "GIT_SEQUENCE_EDITOR=true")
	return filtered
}
