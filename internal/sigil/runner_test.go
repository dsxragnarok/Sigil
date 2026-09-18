package sigil

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setTestTrustedDirs(t *testing.T, dirs ...string) {
	t.Helper()
	prev := testTrustedDirs
	testTrustedDirs = dirs
	t.Cleanup(func() {
		testTrustedDirs = prev
	})
}

func TestRunChildLimitsTokenToChildEnvironment(t *testing.T) {
	directory := t.TempDir()
	fakeGH := filepath.Join(directory, "gh")
	if err := os.WriteFile(fakeGH, []byte("#!/bin/sh\nprintf '%s' \"$GH_TOKEN\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestTrustedDirs(t, directory)
	t.Setenv("GH_TOKEN", "parent-token")
	var output bytes.Buffer
	if err := runChild(context.Background(), []string{"gh"}, "child-token", "", strings.NewReader(""), &output, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "child-token" {
		t.Fatalf("child token = %q", output.String())
	}
	if got := os.Getenv("GH_TOKEN"); got != "parent-token" {
		t.Fatalf("parent GH_TOKEN changed to %q", got)
	}
}

func TestRunChildRejectsPathBypass(t *testing.T) {
	tests := []string{
		"./gh",
		"../gh",
		"/tmp/evil/gh",
		"bin/gh",
		`.\gh`,
	}
	for _, cmd := range tests {
		err := runChild(context.Background(), []string{cmd}, "token", "", nil, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "must be gh or git") {
			t.Fatalf("expected path bypass error for %q, got %v", cmd, err)
		}
	}
}

func TestRunChildRejectsOtherPrograms(t *testing.T) {
	err := runChild(context.Background(), []string{"sh", "-c", "true"}, "secret", "", nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must be gh or git") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunChildStripsUnallowedEnvironmentVariables(t *testing.T) {
	directory := t.TempDir()
	fakeGH := filepath.Join(directory, "gh")
	script := "#!/bin/sh\nprintf 'GITHUB_TOKEN=%s GH_HOST=%s AWS_SECRET=%s GH_REPO=%s' \"$GITHUB_TOKEN\" \"$GH_HOST\" \"$AWS_SECRET_ACCESS_KEY\" \"$GH_REPO\"\n"
	if err := os.WriteFile(fakeGH, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestTrustedDirs(t, directory)
	t.Setenv("GITHUB_TOKEN", "leak-github-token")
	t.Setenv("GH_HOST", "leak-host.com")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "leak-aws-secret")
	t.Setenv("GH_REPO", "leak-repo")

	var output bytes.Buffer
	if err := runChild(context.Background(), []string{"gh"}, "child-token", "", strings.NewReader(""), &output, &output); err != nil {
		t.Fatal(err)
	}
	want := "GITHUB_TOKEN= GH_HOST= AWS_SECRET= GH_REPO="
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestRunChildPinsGitAndSshEnvironment(t *testing.T) {
	directory := t.TempDir()
	fakeGH := filepath.Join(directory, "gh")
	script := "#!/bin/sh\nprintf 'NOSYSTEM=%s GLOBAL=%s SYSTEM=%s SSH_CMD=%s PAGER=%s GIT_PAGER=%s GIT_EDITOR=%s GIT_SEQ_EDITOR=%s' \"$GIT_CONFIG_NOSYSTEM\" \"$GIT_CONFIG_GLOBAL\" \"$GIT_CONFIG_SYSTEM\" \"$GIT_SSH_COMMAND\" \"$PAGER\" \"$GIT_PAGER\" \"$GIT_EDITOR\" \"$GIT_SEQUENCE_EDITOR\"\n"
	if err := os.WriteFile(fakeGH, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestTrustedDirs(t, directory)

	var output bytes.Buffer
	if err := runChild(context.Background(), []string{"gh"}, "token", "", strings.NewReader(""), &output, &output); err != nil {
		t.Fatal(err)
	}
	want := "NOSYSTEM=1 GLOBAL=" + os.DevNull + " SYSTEM=" + os.DevNull + " SSH_CMD=ssh -F " + os.DevNull + " PAGER=cat GIT_PAGER=cat GIT_EDITOR=true GIT_SEQ_EDITOR=true"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestRunChildIgnoresCallerPathForLookupAndChild(t *testing.T) {
	attackerDir := t.TempDir()
	evilGH := filepath.Join(attackerDir, "gh")
	if err := os.WriteFile(evilGH, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	trustedDir := t.TempDir()
	goodGH := filepath.Join(trustedDir, "gh")
	script := "#!/bin/sh\nprintf 'good-gh PATH=%s' \"$PATH\"\n"
	if err := os.WriteFile(goodGH, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	setTestTrustedDirs(t, trustedDir)

	// Caller PATH points to attacker directory
	t.Setenv("PATH", attackerDir)

	var output bytes.Buffer
	err := runChild(context.Background(), []string{"gh"}, "token", "", strings.NewReader(""), &output, &output)
	if err != nil {
		t.Fatalf("expected runChild to succeed using trustedDir, got: %v", err)
	}
	if !strings.HasPrefix(output.String(), "good-gh") {
		t.Fatalf("expected good-gh to run, got output: %q", output.String())
	}
	if strings.Contains(output.String(), attackerDir) {
		t.Fatalf("attackerDir leaked into child PATH: %q", output.String())
	}
}

func TestRunChildBlocksGitOverrides(t *testing.T) {
	directory := t.TempDir()
	fakeGit := filepath.Join(directory, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestTrustedDirs(t, directory)

	blocked := [][]string{
		// Credential helper overrides
		{"git", "-c", "credential.helper=!evil", "clone", "repo"},
		{"git", "-c", "credential.https://github.com.helper=!evil", "clone", "repo"},
		{"git", "-ccredential.helper=!evil", "clone", "repo"},
		{"git", "--config-env=credential.helper=EVIL", "clone", "repo"},

		// Core command execution configs
		{"git", "-c", "core.sshCommand=evil", "clone", "repo"},
		{"git", "-c", "core.askPass=evil", "clone", "repo"},
		{"git", "-c", "core.pager=evil", "clone", "repo"},
		{"git", "-c", "core.fsmonitor=evil", "clone", "repo"},
		{"git", "-ccore.sshCommand=evil", "clone", "repo"},

		// Remote, URL, Include, Alias, and Hook configs
		{"git", "-c", "remote.origin.uploadpack=evil", "fetch"},
		{"git", "-c", "url.https://evil.com/.insteadOf=https://github.com/", "clone", "repo"},
		{"git", "-c", "include.path=/evil/gitconfig", "status"},
		{"git", "-c", "includeIf.gitdir:/foo.path=/evil", "status"},
		{"git", "-c", "alias.clone=!evil", "status"},
		{"git", "-c", "safe.directory=*", "status"},

		// Network / GPG / Execution configs (allowlist rejection)
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

		// Execution path and template flags
		{"git", "--exec-path=/evil", "status"},
		{"git", "--exec-path", "/evil", "status"},
		{"git", "clone", "--template=/evil", "repo"},
		{"git", "clone", "--template", "/evil", "repo"},

		// Upload-pack and receive-pack flags
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

		// Dangerous -u flags (clone specifies upload-pack, pre-subcommand is invalid)
		{"git", "clone", "-u", "evil", "repo"},
		{"git", "clone", "-uevil", "repo"},
		{"git", "-u", "clone", "repo"},
		{"git", "-u", "status"},

		// Directory overrides
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
		err := runChild(context.Background(), cmd, "token", "", nil, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("expected git override blocked for %#v, got nil error", cmd)
		}
	}
}

func TestRunChildAllowsSafeGitArguments(t *testing.T) {
	directory := t.TempDir()
	fakeGit := filepath.Join(directory, "git")
	// Fake git that exits 0
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestTrustedDirs(t, directory)

	allowed := [][]string{
		{"git", "status"},
		{"git", "clone", "https://github.com/dsxragnarok/council.git"},
		{"git", "commit", "-C", "HEAD"}, // -C after commit subcommand is valid commit reuse-message
		{"git", "push", "-u", "origin", "main"}, // -u after push subcommand is set-upstream
		{"git", "fetch", "-u"},                  // -u after fetch subcommand is update-head-ok
		{"git", "status", "-u"},                 // -u after status subcommand is untracked-files
		{"git", "-c", "user.name=Alice", "status"},
		{"git", "-c", "user.email=alice@example.com", "status"},
		{"git", "-c", "pull.rebase=true", "pull"},
		{"git", "-c", "core.autocrlf=input", "status"},
		{"git", "-c", "branch.main.remote=origin", "status"},
		{"git", "-c", "init.defaultBranch=main", "status"},
	}

	for _, cmd := range allowed {
		var output bytes.Buffer
		err := runChild(context.Background(), cmd, "token", "", strings.NewReader(""), &output, &output)
		if err != nil {
			t.Fatalf("expected safe git command %#v to succeed, got error: %v", cmd, err)
		}
	}
}

func TestRunChildFailsWhenNoSafeDirsInTrustedPath(t *testing.T) {
	setTestTrustedDirs(t, "/nonexistent/directory/that/does/not/exist")
	err := runChild(context.Background(), []string{"gh"}, "token", "", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no safe directories available in trusted PATH") {
		t.Fatalf("expected no safe directories error, got: %v", err)
	}
}

func TestRunChildSetsGhRepo(t *testing.T) {
	directory := t.TempDir()
	fakeGH := filepath.Join(directory, "gh")
	if err := os.WriteFile(fakeGH, []byte("#!/bin/sh\nprintf '%s' \"$GH_REPO\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestTrustedDirs(t, directory)

	var output bytes.Buffer
	if err := runChild(context.Background(), []string{"gh"}, "child-token", "dsxragnarok/council", strings.NewReader(""), &output, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "dsxragnarok/council" {
		t.Fatalf("child GH_REPO = %q, want %q", output.String(), "dsxragnarok/council")
	}
}

func TestTrustedPathExcludesUnsafeDirs(t *testing.T) {
	parent := t.TempDir()
	safeDir := filepath.Join(parent, "safe")
	if err := os.Mkdir(safeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	worldWritableDir := filepath.Join(parent, "world")
	if err := os.Mkdir(worldWritableDir, 0o777); err != nil {
		t.Fatal(err)
	}
	// Explicitly chmod in case umask restricted it
	if err := os.Chmod(worldWritableDir, 0o777); err != nil {
		t.Fatal(err)
	}

	setTestTrustedDirs(t, worldWritableDir, "/nonexistent", safeDir)
	result := trustedPath()
	if result != safeDir {
		t.Fatalf("trustedPath() = %q, want %q", result, safeDir)
	}
}
