package agentgh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const usage = `Usage:
  agent-gh exec <role> [--repo owner/name] [--installation-id id] -- <gh|git> [args...]

Example:
  agent-gh exec reviewer -- gh pr view 1 -R dsxragnarok/council`

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

	if dir := os.Getenv("AGENT_GH_CONFIG_DIR"); dir != "" {
		fmt.Fprintf(stderr, "agent-gh: warning: AGENT_GH_CONFIG_DIR is set (%s); overriding config directory\n", dir)
	}
	if dir := os.Getenv("AGENT_GH_CACHE_DIR"); dir != "" {
		fmt.Fprintf(stderr, "agent-gh: warning: AGENT_GH_CACHE_DIR is set (%s); overriding cache directory\n", dir)
	}

	config, _, err := LoadRoleConfig(request.role)
	if err != nil {
		return err
	}
	repository := request.repository
	if repository == "" {
		repository = repositoryFromCommand(request.command)
	}
	if repository == "" {
		repository = config.DefaultRepository
	}
	if repository == "" && request.installationID == 0 && config.InstallationID == 0 {
		return errors.New("no repository supplied; use --repo owner/name, a gh -R/--repo flag, or default_repository in the role config")
	}
	if repository != "" {
		if _, _, err := splitRepository(repository); err != nil {
			return err
		}
	}

	privateKey, err := LoadRSAPrivateKey(config.PrivateKeyPath)
	if err != nil {
		return err
	}
	appJWT, err := CreateAppJWT(config.ClientID, privateKey, time.Now())
	if err != nil {
		return err
	}

	installationID := request.installationID
	if installationID == 0 {
		installationID = config.InstallationID
	}
	if installationID == 0 && repository != "" {
		installationID, err = cachedInstallationID(request.role, repository)
		if err != nil {
			return err
		}
	}
	client := NewGitHubClient()
	if installationID == 0 {
		installationID, err = client.FindInstallation(ctx, appJWT, repository)
		if err != nil {
			return err
		}
		if err := cacheInstallationID(request.role, repository, installationID); err != nil {
			return err
		}
	}

	var tokenRepos []string
	if repository != "" {
		_, repoName, err := splitRepository(repository)
		if err != nil {
			return err
		}
		tokenRepos = []string{repoName}
	} else {
		fmt.Fprintln(stderr, "agent-gh: warning: minting unscoped installation token (access to all installation repositories)")
	}

	token, _, err := client.CreateInstallationToken(ctx, appJWT, installationID, tokenRepos...)
	if err != nil {
		return err
	}
	return runChild(ctx, request.command, token, repository, stdin, stdout, stderr)
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

func repositoryFromCommand(command []string) string {
	if len(command) == 0 || command[0] != "gh" {
		return ""
	}
	for index := 1; index < len(command); index++ {
		arg := command[index]
		if arg == "--" {
			break
		}
		var candidate string
		switch {
		case arg == "-R" || arg == "--repo":
			if index+1 < len(command) {
				candidate = command[index+1]
				index++
			}
		case strings.HasPrefix(arg, "--repo="):
			candidate = strings.TrimPrefix(arg, "--repo=")
		case strings.HasPrefix(arg, "-R") && len(arg) > 2:
			candidate = strings.TrimPrefix(arg, "-R")
		}
		if candidate != "" && !strings.HasPrefix(candidate, "-") {
			trimmed := strings.TrimPrefix(candidate, "github.com/")
			if _, _, err := splitRepository(trimmed); err == nil {
				return trimmed
			}
		}
	}
	return ""
}
