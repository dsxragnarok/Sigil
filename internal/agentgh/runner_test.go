package agentgh

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunChildLimitsTokenToChildEnvironment(t *testing.T) {
	directory := t.TempDir()
	fakeGH := filepath.Join(directory, "gh")
	if err := os.WriteFile(fakeGH, []byte("#!/bin/sh\nprintf '%s' \"$GH_TOKEN\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_TOKEN", "parent-token")
	t.Setenv("AGENT_GH_ALLOW_TMP_PATH", "1")
	t.Setenv("PATH", directory+string(filepath.ListSeparator)+os.Getenv("PATH"))
	var output bytes.Buffer
	if err := runChild(context.Background(), []string{"gh"}, "child-token", strings.NewReader(""), &output, &output); err != nil {
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
		err := runChild(context.Background(), []string{cmd}, "token", nil, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "must be gh or git") {
			t.Fatalf("expected path bypass error for %q, got %v", cmd, err)
		}
	}
}

func TestRunChildRejectsOtherPrograms(t *testing.T) {
	err := runChild(context.Background(), []string{"sh", "-c", "true"}, "secret", nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must be gh or git") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunChildStripsUnallowedEnvironmentVariables(t *testing.T) {
	directory := t.TempDir()
	fakeGH := filepath.Join(directory, "gh")
	script := "#!/bin/sh\nprintf 'GITHUB_TOKEN=%s GH_HOST=%s AWS_SECRET=%s' \"$GITHUB_TOKEN\" \"$GH_HOST\" \"$AWS_SECRET_ACCESS_KEY\"\n"
	if err := os.WriteFile(fakeGH, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_TOKEN", "leak-github-token")
	t.Setenv("GH_HOST", "leak-host.com")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "leak-aws-secret")
	t.Setenv("AGENT_GH_ALLOW_TMP_PATH", "1")
	t.Setenv("PATH", directory+string(filepath.ListSeparator)+os.Getenv("PATH"))

	var output bytes.Buffer
	if err := runChild(context.Background(), []string{"gh"}, "child-token", strings.NewReader(""), &output, &output); err != nil {
		t.Fatal(err)
	}
	want := "GITHUB_TOKEN= GH_HOST= AWS_SECRET="
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestRunChildBlocksGitCredentialOverride(t *testing.T) {
	directory := t.TempDir()
	fakeGit := filepath.Join(directory, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_GH_ALLOW_TMP_PATH", "1")
	t.Setenv("PATH", directory+string(filepath.ListSeparator)+os.Getenv("PATH"))

	tests := [][]string{
		{"git", "-c", "credential.helper=!evil", "clone", "repo"},
		{"git", "-c", "credential.https://github.com.helper=!evil", "clone", "repo"},
		{"git", "-ccredential.helper=!evil", "clone", "repo"},
		{"git", "--config-env=credential.helper=EVIL", "clone", "repo"},
	}
	for _, cmd := range tests {
		err := runChild(context.Background(), cmd, "token", nil, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "configuration override is not allowed") {
			t.Fatalf("expected git override blocked for %#v, got %v", cmd, err)
		}
	}
}

func TestSanitizePath(t *testing.T) {
	raw := strings.Join([]string{
		".",
		"relative/path",
		"/tmp/evil",
		"/usr/bin",
	}, string(filepath.ListSeparator))

	sanitized := sanitizePath(raw)
	entries := filepath.SplitList(sanitized)
	for _, entry := range entries {
		if entry == "." || entry == "relative/path" || strings.HasPrefix(entry, "/tmp") {
			t.Fatalf("untrusted entry found in sanitized PATH: %s", entry)
		}
	}
}
