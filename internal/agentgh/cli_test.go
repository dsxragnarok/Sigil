package agentgh

import (
	"reflect"
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
		{"git", []string{"git", "status"}, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := repositoryFromCommand(test.command); got != test.want {
				t.Fatalf("repository = %q, want %q", got, test.want)
			}
		})
	}
}
