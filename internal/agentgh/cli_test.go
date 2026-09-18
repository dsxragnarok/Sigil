package agentgh

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestParseArguments(t *testing.T) {
	request, err := parseArguments([]string{
		"exec", "reviewer", "--repo", "dsxragnarok/council", "--", "gh", "pr", "view", "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.role != "reviewer" || request.repository != "dsxragnarok/council" {
		t.Fatalf("unexpected request: %#v", request)
	}
	wantCommand := []string{"gh", "pr", "view", "1"}
	if !reflect.DeepEqual(request.command, wantCommand) {
		t.Fatalf("command = %#v, want %#v", request.command, wantCommand)
	}
}

func TestRepositoryFromCommand(t *testing.T) {
	tests := []struct {
		name    string
		command []string
		want    string
	}{
		{"short separate", []string{"gh", "pr", "view", "-R", "dsxragnarok/council"}, "dsxragnarok/council"},
		{"short joined", []string{"gh", "pr", "view", "-Rdsxragnarok/council"}, "dsxragnarok/council"},
		{"long separate", []string{"gh", "pr", "view", "--repo", "dsxragnarok/council"}, "dsxragnarok/council"},
		{"long joined", []string{"gh", "pr", "view", "--repo=dsxragnarok/council"}, "dsxragnarok/council"},
		{"host prefix stripped", []string{"gh", "pr", "view", "-R", "github.com/dsxragnarok/council"}, "dsxragnarok/council"},
		{"git", []string{"git", "status"}, ""},
		{"path bypass gh", []string{"./gh", "pr", "view", "-R", "dsxragnarok/council"}, ""},
		{"dash dash stop", []string{"gh", "pr", "view", "--", "-R", "dsxragnarok/council"}, ""},
		{"adjacent flags not a repo", []string{"gh", "issue", "list", "--search", "--repo", "dummy"}, ""},
		{"repo flag followed by another flag", []string{"gh", "issue", "list", "--repo", "-R"}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := repositoryFromCommand(test.command); got != test.want {
				t.Fatalf("repository = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRunEnvWarnings(t *testing.T) {
	t.Setenv("AGENT_GH_CONFIG_DIR", "/custom/config")
	t.Setenv("AGENT_GH_CACHE_DIR", "/custom/cache")

	var stderr bytes.Buffer
	// Invalid role causes early return after warnings are printed
	_ = Run(context.Background(), []string{"exec", "reviewer", "--", "gh", "status"}, nil, nil, &stderr)

	output := stderr.String()
	if !strings.Contains(output, "warning: AGENT_GH_CONFIG_DIR is set (/custom/config)") {
		t.Fatalf("expected AGENT_GH_CONFIG_DIR warning, got: %q", output)
	}
	if !strings.Contains(output, "warning: AGENT_GH_CACHE_DIR is set (/custom/cache)") {
		t.Fatalf("expected AGENT_GH_CACHE_DIR warning, got: %q", output)
	}
}

func TestRunNilStreamsDoesNotPanic(t *testing.T) {
	t.Setenv("AGENT_GH_CONFIG_DIR", "/custom/config")
	t.Setenv("AGENT_GH_CACHE_DIR", "/custom/cache")
	// Run with nil stdin, stdout, stderr should not panic
	_ = Run(context.Background(), []string{"exec", "reviewer", "--", "gh", "status"}, nil, nil, nil)
}

