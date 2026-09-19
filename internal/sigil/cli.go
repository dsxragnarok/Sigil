package sigil

// The sigil CLI is a dumb admin-socket streaming client. It parses arguments,
// sends metadata/stream frames to sigild, renders stdout/stderr, and exits
// with the target exit code. It never loads role config, reads private keys,
// mints credentials, discovers installations, touches cache state, or honors
// SIGIL_CONFIG_DIR/SIGIL_CACHE_DIR.
//
// Explicit-role execution is the trusted/admin compatibility path and uses
// the admin socket, which must only be reachable in trusted launcher
// environments. Never export SIGIL_ADMIN_SOCKET into agent environments.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"sigil/internal/runtime"
	utransport "sigil/internal/transport/unix"
)

const usage = `Usage:
  sigil exec <role> [--repo owner/name] [--installation-id id] -- <gh|git> [args...]

Example:
  sigil exec reviewer -- gh pr view 1 -R dsxragnarok/council

Requires the trusted broker daemon (sigild) to be running.`

// ExitError carries the target exit code from the broker exit frame so the
// CLI exits with the same status. It is not a broker failure.
type ExitError struct {
	Code int
}

func (err *ExitError) Error() string {
	return fmt.Sprintf("command exited with status %d", err.Code)
}

func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if stderr == nil {
		stderr = io.Discard
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}

	request, err := parseArguments(args)
	if err != nil {
		if errors.Is(err, errHelp) {
			fmt.Fprintln(stdout, usage)
			return nil
		}
		return fmt.Errorf("%w\n\n%s", err, usage)
	}

	// Client-supplied config/cache overrides have no effect: the broker owns
	// its configuration and cache state. They are ignored, not warned about,
	// so scripts cannot mistake client environment for daemon state.

	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}

	socketPath := adminSocketPath()
	client := utransport.NewClient(socketPath, "/v1/exec")
	code, err := client.Exec(ctx, utransport.Meta{
		Role:           request.role,
		Repository:     request.repository,
		InstallationID: request.installationID,
		WorkingDir:     workingDir,
		Command:        request.command,
	}, stdin, stdout, stderr)
	if err != nil {
		return err
	}
	if code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

// adminSocketPath resolves the admin socket: explicit trusted-launcher
// override first, otherwise the broker default runtime path.
func adminSocketPath() string {
	if override := os.Getenv("SIGIL_ADMIN_SOCKET"); override != "" {
		return override
	}
	paths, err := runtime.Resolve()
	if err != nil {
		return ""
	}
	return paths.AdminSocket
}

var errHelp = errors.New("help requested")

type execRequest struct {
	role           string
	repository     string
	installationID int64
	command        []string
}

func parseArguments(args []string) (execRequest, error) {
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		return execRequest{}, errHelp
	}
	if len(args) < 2 || args[0] != "exec" {
		return execRequest{}, errors.New("expected exec followed by a role")
	}
	request := execRequest{role: args[1]}
	separator := -1
	for index := 2; index < len(args); index++ {
		if args[index] == "--" {
			separator = index
			break
		}
		switch args[index] {
		case "--repo":
			index++
			if index >= len(args) {
				return execRequest{}, errors.New("--repo requires owner/name")
			}
			request.repository = args[index]
		case "--installation-id":
			index++
			if index >= len(args) {
				return execRequest{}, errors.New("--installation-id requires a number")
			}
			id, err := strconv.ParseInt(args[index], 10, 64)
			if err != nil || id <= 0 {
				return execRequest{}, fmt.Errorf("invalid installation ID %q", args[index])
			}
			request.installationID = id
		default:
			return execRequest{}, fmt.Errorf("unknown option %q before --", args[index])
		}
	}
	if separator == -1 || separator == len(args)-1 {
		return execRequest{}, errors.New("missing command after --")
	}
	request.command = args[separator+1:]
	if !roleNamePattern.MatchString(request.role) {
		return execRequest{}, fmt.Errorf("invalid role %q", request.role)
	}
	return request, nil
}
