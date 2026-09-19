package runner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func setTestTrustedDirs(t *testing.T, dirs ...string) {
	t.Helper()
	prev := testTrustedDirs
	testTrustedDirs = dirs
	t.Cleanup(func() { testTrustedDirs = prev })
}

func writeFake(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestFreshIsolatedCLIState(t *testing.T) {
	dir := t.TempDir()
	// The fake proves emptiness itself: cleanup runs before Run returns, so
	// the test cannot inspect the dir afterwards.
	writeFake(t, dir, "gh", "#!/bin/sh\ncount=$(/bin/ls -A \"$GH_CONFIG_DIR\" | /usr/bin/wc -l)\n/bin/echo \"HOME=$HOME GH_CONFIG_DIR=$GH_CONFIG_DIR EMPTY=$count\"\n")
	setTestTrustedDirs(t, dir)
	t.Setenv("HOME", "/leak/home")
	t.Setenv("GH_CONFIG_DIR", "/leak/gh-config")

	var out bytes.Buffer
	if _, err := Run(context.Background(), Request{Command: []string{"gh"}, Token: "tok", Stdout: &out}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	home := afterPrefix(t, got, "HOME=", " ")
	ghDir := afterPrefix(t, got, "GH_CONFIG_DIR=", " ")
	if home == "/leak/home" || home == "" {
		t.Fatalf("HOME not isolated: %q", home)
	}
	if ghDir == "/leak/gh-config" || ghDir == "" {
		t.Fatalf("GH_CONFIG_DIR not isolated: %q", ghDir)
	}
	if !strings.HasPrefix(ghDir, home) {
		t.Fatalf("GH_CONFIG_DIR %q not inside exec home %q", ghDir, home)
	}
	if !strings.Contains(got, "EMPTY=       0") && !strings.Contains(got, "EMPTY=0") {
		t.Fatalf("GH_CONFIG_DIR not empty during run: %q", got)
	}
	// Temp execution state must be gone after the child exits.
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("exec home not cleaned: %v", err)
	}
}

func afterPrefix(t *testing.T, s, prefix, sep string) string {
	t.Helper()
	idx := strings.Index(s, prefix)
	if idx == -1 {
		t.Fatalf("missing %q in %q", prefix, s)
	}
	rest := s[idx+len(prefix):]
	if end := strings.Index(rest, sep); end != -1 {
		return rest[:end]
	}
	return rest
}

func TestPersonalCredentialEnvScrubbed(t *testing.T) {
	dir := t.TempDir()
	writeFake(t, dir, "gh", "#!/bin/sh\nprintf 'GH_TOKEN=%s GITHUB_TOKEN=%s ENTERPRISE=%s WILD=%s APP=%s HOST=%s SSH=%s REPO=%s' \"$GH_TOKEN\" \"$GITHUB_TOKEN\" \"$GH_ENTERPRISE_TOKEN\" \"$GITHUB_X_TOKEN\" \"$GITHUB_APP_TOKEN\" \"$GH_HOST\" \"$SSH_AUTH_SOCK\" \"$GH_REPO\"\n")
	setTestTrustedDirs(t, dir)
	t.Setenv("GITHUB_TOKEN", "leak-github")
	t.Setenv("GH_ENTERPRISE_TOKEN", "leak-enterprise")
	t.Setenv("GITHUB_X_TOKEN", "leak-wild")
	t.Setenv("GITHUB_APP_TOKEN", "leak-app")
	t.Setenv("GH_HOST", "leak-host.example")
	t.Setenv("SSH_AUTH_SOCK", "/leak/agent.sock")
	t.Setenv("GH_REPO", "leak/repo")

	var out bytes.Buffer
	code, err := Run(context.Background(), Request{Command: []string{"gh"}, Token: "child-token", Repository: "o/r", Stdout: &out})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	got := out.String()
	if !strings.Contains(got, "GH_TOKEN=child-token") {
		t.Fatalf("broker token not injected: %q", got)
	}
	for _, leak := range []string{"leak-github", "leak-enterprise", "leak-wild", "leak-app", "leak-host.example", "/leak/agent.sock", "leak/repo"} {
		if strings.Contains(got, leak) {
			t.Fatalf("caller secret leaked: %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "REPO=o/r") {
		t.Fatalf("broker repository not set: %q", got)
	}
}

func TestHookSuppressionInjectedAheadOfCallerArgs(t *testing.T) {
	dir := t.TempDir()
	writeFake(t, dir, "git", "#!/bin/sh\nprintf '%s' \"$*\"\n")
	setTestTrustedDirs(t, dir)

	var out bytes.Buffer
	if _, err := Run(context.Background(), Request{Command: []string{"git", "push", "origin", "main"}, Token: "tok", Stdout: &out}); err != nil {
		t.Fatal(err)
	}
	args := out.String()
	marker := "-c core.hooksPath=/dev/null"
	idx := strings.Index(args, marker)
	if idx == -1 {
		t.Fatalf("hook suppression missing in %q", args)
	}
	if strings.Index(args, "push") < idx {
		t.Fatalf("suppression must precede caller args in %q", args)
	}
	if strings.Contains(args, "--no-hooks") {
		t.Fatalf("unsupported --no-hooks flag must not be emitted: %q", args)
	}
}

func TestMaliciousHookDoesNotExecute(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	_ = git
	realDir, err := filepath.EvalSymlinks(filepath.Dir(mustLookPath(t, "git")))
	if err != nil {
		t.Fatal(err)
	}
	setTestTrustedDirs(t, realDir)

	work := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(mustLookPath(t, "git"), args...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_SYSTEM="+os.DevNull)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@t")
	run("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(work, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f.txt")
	run("commit", "-qm", "init")
	marker := filepath.Join(work, "hook-marker")
	hook := "#!/bin/sh\ntouch " + marker + "\n"
	if err := os.WriteFile(filepath.Join(work, ".git", "hooks", "pre-push"), []byte(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	bare := t.TempDir() + "/remote.git"
	cmd := exec.Command(mustLookPath(t, "git"), "init", "-q", "--bare", bare)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}

	var out, errOut bytes.Buffer
	code, err := Run(context.Background(), Request{
		Command:    []string{"git", "push", bare, "HEAD:main"},
		Token:      "test-token",
		WorkingDir: work,
		Stdout:     &out,
		Stderr:     &errOut,
		Timeout:    60 * time.Second,
	})
	if err != nil || code != 0 {
		t.Fatalf("push code=%d err=%v stdout=%q stderr=%q", code, err, out.String(), errOut.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("repository hook executed inside broker tree")
	}
}

func mustLookPath(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not available", name)
	}
	return path
}

func TestTimeoutTerminatesGrandchildren(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	writeFake(t, dir, "gh", "#!/bin/sh\n/bin/sleep 60 & echo $! > \"$1\"\nwait\n")
	setTestTrustedDirs(t, dir)

	start := time.Now()
	_, err := Run(context.Background(), Request{Command: []string{"gh", pidFile}, Token: "tok", Timeout: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatalf("timeout took too long: %v", time.Since(start))
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("child pid not recorded: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	// Grandchild must be dead: signal 0 fails on a reaped process.
	time.Sleep(300 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("timed-out grandchild still alive")
	}
}

func TestStdinStreamsAndTargetFailureIsCode(t *testing.T) {
	dir := t.TempDir()
	writeFake(t, dir, "gh", "#!/bin/sh\n/bin/cat\nexit 3\n")
	setTestTrustedDirs(t, dir)

	var out bytes.Buffer
	code, err := Run(context.Background(), Request{
		Command: []string{"gh"}, Token: "tok",
		Stdin: strings.NewReader("stream-me"), Stdout: &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Fatalf("code = %d, want 3", code)
	}
	if out.String() != "stream-me" {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestNoCredentialInArgvOrErrors(t *testing.T) {
	dir := t.TempDir()
	writeFake(t, dir, "gh", "#!/bin/sh\nprintf 'ARGV:%s ' \"$@\"\nprintf '\\n'\nexport\n")
	setTestTrustedDirs(t, dir)
	token := "ghs_s3cr3t-token-xyz"

	var out bytes.Buffer
	if _, err := Run(context.Background(), Request{Command: []string{"gh", "pr", "view"}, Token: token, Stdout: &out}); err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(out.String(), "\n", 2)
	if strings.Contains(lines[0], token) {
		t.Fatalf("credential in argv: %q", lines[0])
	}

	setTestTrustedDirs(t, "/nonexistent/trusted-dir-xyz")
	_, err := Run(context.Background(), Request{Command: []string{"gh"}, Token: token})
	if err == nil {
		t.Fatal("expected lookup error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("credential in error: %q", err.Error())
	}
}

func TestWorkingDirMustExist(t *testing.T) {
	dir := t.TempDir()
	writeFake(t, dir, "gh", "#!/bin/sh\nexit 0\n")
	setTestTrustedDirs(t, dir)
	if _, err := Run(context.Background(), Request{Command: []string{"gh"}, Token: "t", WorkingDir: filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("expected error for missing working dir")
	}
}

func TestDangerousGitFlagsRejected(t *testing.T) {
	dir := t.TempDir()
	writeFake(t, dir, "git", "#!/bin/sh\nexit 0\n")
	setTestTrustedDirs(t, dir)
	blocked := [][]string{
		{"git", "--git-dir=/evil", "status"},
		{"git", "-C", "/evil", "status"},
		{"git", "-c", "core.sshCommand=evil", "status"},
		{"git", "push", "--exec=evil"},
	}
	for _, cmd := range blocked {
		if _, err := Run(context.Background(), Request{Command: cmd, Token: "t"}); err == nil {
			t.Fatalf("expected rejection for %#v", cmd)
		}
	}
}
