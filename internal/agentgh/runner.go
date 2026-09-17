package agentgh

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func runChild(ctx context.Context, command []string, token string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(command) == 0 {
		return fmt.Errorf("missing command after --")
	}
	program := filepath.Base(command[0])
	if program != "gh" && program != "git" {
		return fmt.Errorf("command must be gh or git, got %q", command[0])
	}

	arguments := append([]string(nil), command[1:]...)
	if program == "git" {
		// Git does not read GH_TOKEN itself. Route GitHub HTTPS credential requests
		// through gh, which reads GH_TOKEN from this child environment.
		arguments = append([]string{
			"-c", "credential.https://github.com.helper=",
			"-c", "credential.https://github.com.helper=!gh auth git-credential",
		}, arguments...)
	}

	child := exec.CommandContext(ctx, command[0], arguments...)
	child.Stdin = stdin
	child.Stdout = stdout
	child.Stderr = stderr
	child.Env = withToken(os.Environ(), token)
	if err := child.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("%s exited with status %d", program, exitError.ExitCode())
		}
		return fmt.Errorf("run %s: %w", program, err)
	}
	return nil
}

func withToken(environment []string, token string) []string {
	filtered := make([]string, 0, len(environment)+1)
	for _, value := range environment {
		if !strings.HasPrefix(value, "GH_TOKEN=") {
			filtered = append(filtered, value)
		}
	}
	return append(filtered, "GH_TOKEN="+token)
}
