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
	var output bytes.Buffer
	if err := runChild(context.Background(), []string{fakeGH}, "child-token", strings.NewReader(""), &output, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "child-token" {
		t.Fatalf("child token = %q", output.String())
	}
	if got := os.Getenv("GH_TOKEN"); got != "parent-token" {
		t.Fatalf("parent GH_TOKEN changed to %q", got)
	}
}

func TestRunChildRejectsOtherPrograms(t *testing.T) {
	err := runChild(context.Background(), []string{"sh", "-c", "true"}, "secret", nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must be gh or git") {
		t.Fatalf("error = %v", err)
	}
}
