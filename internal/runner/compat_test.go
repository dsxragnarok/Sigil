package runner

// Ported M0 regression gates: these preserve the original compatibility-runner
// behaviors through the broker-owned runner. New M1 hardening (isolated HOME,
// hook suppression, process-group timeouts) is covered in runner_test.go.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCompat(t *testing.T, command []string, token, repository string, stdin string) (string, error) {
	t.Helper()
	var output bytes.Buffer
	code, err := Run(context.Background(), Request{
		Command:    command,
		Token:      token,
		Repository: repository,
		Stdin:      strings.NewReader(stdin),
		Stdout:     &output,
		Stderr:     &output,
	})
	if err != nil {
		return "", err
	}
	if code != 0 {
		t.Fatalf("exit code = %d for %#v", code, command)
	}
	return output.String(), nil
}

func TestCompatTokenLimitedToChildEnvironment(t *testing.T) {
	directory := t.TempDir()
	writeFake(t, directory, "gh", "#!/bin/sh\nprintf '%s' \"$GH_TOKEN\"\n")
	setTestTrustedDirs(t, directory)
	t.Setenv("GH_TOKEN", "parent-token")
	got, err := runCompat(t, []string{"gh"}, "child-token", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "child-token" {
		t.Fatalf("child token = %q", got)
	}
	if parent := os.Getenv("GH_TOKEN"); parent != "parent-token" {
		t.Fatalf("parent GH_TOKEN changed to %q", parent)
	}
}

func TestCompatRejectsPathBypass(t *testing.T) {
	for _, cmd := range []string{"./gh", "../gh", "/tmp/evil/gh", "bin/gh", `.\gh`} {
		_, err := Run(context.Background(), Request{Command: []string{cmd}, Token: "token"})
		if err == nil || !strings.Contains(err.Error(), "must be gh or git") {
			t.Fatalf("expected path bypass error for %q, got %v", cmd, err)
		}
	}
}

func TestCompatRejectsOtherPrograms(t *testing.T) {
	_, err := Run(context.Background(), Request{Command: []string{"sh", "-c", "true"}, Token: "secret"})
	if err == nil || !strings.Contains(err.Error(), "must be gh or git") {
		t.Fatalf("error = %v", err)
	}
}

func TestCompatStripsUnallowedEnvironmentVariables(t *testing.T) {
	directory := t.TempDir()
	writeFake(t, directory, "gh", "#!/bin/sh\nprintf 'GITHUB_TOKEN=%s GH_HOST=%s AWS_SECRET=%s GH_REPO=%s' \"$GITHUB_TOKEN\" \"$GH_HOST\" \"$AWS_SECRET_ACCESS_KEY\" \"$GH_REPO\"\n")
	setTestTrustedDirs(t, directory)
	t.Setenv("GITHUB_TOKEN", "leak-github-token")
	t.Setenv("GH_HOST", "leak-host.com")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "leak-aws-secret")
	t.Setenv("GH_REPO", "leak-repo")

	got, err := runCompat(t, []string{"gh"}, "child-token", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := "GITHUB_TOKEN= GH_HOST= AWS_SECRET= GH_REPO="; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestCompatPinsGitAndSshEnvironment(t *testing.T) {
	directory := t.TempDir()
	writeFake(t, directory, "gh", "#!/bin/sh\nprintf 'NOSYSTEM=%s GLOBAL=%s SYSTEM=%s SSH_CMD=%s PAGER=%s GIT_PAGER=%s GIT_EDITOR=%s GIT_SEQ_EDITOR=%s' \"$GIT_CONFIG_NOSYSTEM\" \"$GIT_CONFIG_GLOBAL\" \"$GIT_CONFIG_SYSTEM\" \"$GIT_SSH_COMMAND\" \"$PAGER\" \"$GIT_PAGER\" \"$GIT_EDITOR\" \"$GIT_SEQUENCE_EDITOR\"\n")
	setTestTrustedDirs(t, directory)

	got, err := runCompat(t, []string{"gh"}, "token", "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := "NOSYSTEM=1 GLOBAL=" + os.DevNull + " SYSTEM=" + os.DevNull + " SSH_CMD=ssh -F " + os.DevNull + " PAGER=cat GIT_PAGER=cat GIT_EDITOR=true GIT_SEQ_EDITOR=true"
	if got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestCompatIgnoresCallerPathForLookupAndChild(t *testing.T) {
	attackerDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(attackerDir, "gh"), []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	trustedDir := t.TempDir()
	writeFake(t, trustedDir, "gh", "#!/bin/sh\nprintf 'good-gh PATH=%s' \"$PATH\"\n")
	setTestTrustedDirs(t, trustedDir)
	t.Setenv("PATH", attackerDir)

	got, err := runCompat(t, []string{"gh"}, "token", "", "")
	if err != nil {
		t.Fatalf("expected trustedDir binary to run, got: %v", err)
	}
	if !strings.HasPrefix(got, "good-gh") {
		t.Fatalf("expected good-gh to run, got output: %q", got)
	}
	if strings.Contains(got, attackerDir) {
		t.Fatalf("attackerDir leaked into child PATH: %q", got)
	}
}

func TestCompatBlocksGitOverrides(t *testing.T) {
	directory := t.TempDir()
	writeFake(t, directory, "git", "#!/bin/sh\nexit 0\n")
	setTestTrustedDirs(t, directory)

	blocked := [][]string{
		{"git", "-c", "credential.helper=!evil", "clone", "repo"},
		{"git", "-c", "credential.https://github.com.helper=!evil", "clone", "repo"},
		{"git", "-ccredential.helper=!evil", "clone", "repo"},
		{"git", "--config-env=credential.helper=EVIL", "clone", "repo"},
		{"git", "-c", "core.sshCommand=evil", "clone", "repo"},
		{"git", "-c", "core.askPass=evil", "clone", "repo"},
		{"git", "-c", "core.pager=evil", "clone", "repo"},
		{"git", "-c", "core.fsmonitor=evil", "clone", "repo"},
		{"git", "-ccore.sshCommand=evil", "clone", "repo"},
		{"git", "-c", "remote.origin.uploadpack=evil", "fetch"},
		{"git", "-c", "url.https://evil.com/.insteadOf=https://github.com/", "clone", "repo"},
		{"git", "-c", "include.path=/evil/gitconfig", "status"},
		{"git", "-c", "includeIf.gitdir:/foo.path=/evil", "status"},
		{"git", "-c", "alias.clone=!evil", "status"},
		{"git", "-c", "safe.directory=*", "status"},
		{"git", "-c", "http.proxy=http://evil.com", "status"},
		{"git", "-c", "http.extraHeader=evil", "status"},
		{"git", "-c", "gpg.program=evil", "status"},
		{"git", "-c", "gpg.ssh.defaultKeyCommand=evil", "status"},
		{"git", "-c", "ssh.variant=evil", "status"},
		{"git", "-c", "submodule.evil.update=!evil", "status"},
		{"git", "-c", "tar.tar.gz.command=evil", "status"},
		{"git", "-c", "man.viewer=evil", "status"},
		{"git", "-c", "browser.evil.cmd=evil", "status"},
		{"git", "-c", "extensions.worktreeConfig=true", "status"},
		{"git", "-c", "diff.external=evil", "status"},
		{"git", "-c", "merge.evil.driver=evil", "status"},
		{"git", "-c", "filter.evil.clean=evil", "status"},
		{"git", "--exec-path=/evil", "status"},
		{"git", "--exec-path", "/evil", "status"},
		{"git", "clone", "--template=/evil", "repo"},
		{"git", "clone", "--template", "/evil", "repo"},
		{"git", "clone", "--upload-pack=evil", "repo"},
		{"git", "clone", "--upload-pack", "evil", "repo"},
		{"git", "fetch", "--upload-pack=evil"},
		{"git", "fetch", "--upload-pack", "evil"},
		{"git", "ls-remote", "--upload-pack=evil"},
		{"git", "ls-remote", "--upload-pack", "evil"},
		{"git", "push", "--receive-pack=evil"},
		{"git", "push", "--receive-pack", "evil"},
		{"git", "push", "--exec=evil"},
		{"git", "push", "--exec", "evil"},
		{"git", "archive", "--exec=evil"},
		{"git", "archive", "--exec", "evil"},
		{"git", "clone", "-u", "evil", "repo"},
		{"git", "clone", "-uevil", "repo"},
		{"git", "-u", "clone", "repo"},
		{"git", "-u", "status"},
		{"git", "-C", "/evil", "status"},
		{"git", "-C/evil", "status"},
		{"git", "clone", "-C", "/evil", "repo"},
		{"git", "status", "-C", "/evil"},
		{"git", "commit", "-C/evil"},
		{"git", "--git-dir=/evil", "status"},
		{"git", "--git-dir", "/evil", "status"},
		{"git", "--work-tree=/evil", "status"},
		{"git", "--work-tree", "/evil", "status"},
		{"git", "--config-env", "VAR=VAL", "status"},
		{"git", "--config", "VAR=VAL", "status"},
	}
	for _, cmd := range blocked {
		if _, err := Run(context.Background(), Request{Command: cmd, Token: "token"}); err == nil {
			t.Fatalf("expected git override blocked for %#v, got nil error", cmd)
		}
	}
}

func TestCompatAllowsSafeGitArguments(t *testing.T) {
	directory := t.TempDir()
	writeFake(t, directory, "git", "#!/bin/sh\nexit 0\n")
	setTestTrustedDirs(t, directory)

	allowed := [][]string{
		{"git", "status"},
		{"git", "clone", "https://github.com/dsxragnarok/council.git"},
		{"git", "commit", "-C", "HEAD"},
		{"git", "push", "-u", "origin", "main"},
		{"git", "fetch", "-u"},
		{"git", "status", "-u"},
		{"git", "-c", "user.name=Alice", "status"},
		{"git", "-c", "user.email=alice@example.com", "status"},
		{"git", "-c", "pull.rebase=true", "pull"},
		{"git", "-c", "core.autocrlf=input", "status"},
		{"git", "-c", "branch.main.remote=origin", "status"},
		{"git", "-c", "init.defaultBranch=main", "status"},
	}
	for _, cmd := range allowed {
		if _, err := runCompat(t, cmd, "token", "", ""); err != nil {
			t.Fatalf("expected safe git command %#v to succeed, got error: %v", cmd, err)
		}
	}
}

func TestCompatFailsWhenNoSafeDirsInTrustedPath(t *testing.T) {
	setTestTrustedDirs(t, "/nonexistent/directory/that/does/not/exist")
	_, err := Run(context.Background(), Request{Command: []string{"gh"}, Token: "token"})
	if err == nil || !strings.Contains(err.Error(), "no safe directories available in trusted PATH") {
		t.Fatalf("expected no safe directories error, got: %v", err)
	}
}

func TestCompatSetsGhRepo(t *testing.T) {
	directory := t.TempDir()
	writeFake(t, directory, "gh", "#!/bin/sh\nprintf '%s' \"$GH_REPO\"\n")
	setTestTrustedDirs(t, directory)

	got, err := runCompat(t, []string{"gh"}, "child-token", "dsxragnarok/council", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "dsxragnarok/council" {
		t.Fatalf("child GH_REPO = %q", got)
	}
}

func TestCompatTrustedPathExcludesUnsafeDirs(t *testing.T) {
	parent := t.TempDir()
	safeDir := filepath.Join(parent, "safe")
	if err := os.Mkdir(safeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	worldWritableDir := filepath.Join(parent, "world")
	if err := os.Mkdir(worldWritableDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritableDir, 0o777); err != nil {
		t.Fatal(err)
	}
	setTestTrustedDirs(t, worldWritableDir, "/nonexistent", safeDir)
	if result := trustedPath(); result != safeDir {
		t.Fatalf("trustedPath() = %q, want %q", result, safeDir)
	}
}
