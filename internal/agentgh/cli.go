package agentgh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const usage = `Usage:
  agent-gh exec <role> [--repo owner/name] [--installation-id id] -- <gh|git> [args...]

Example:
  agent-gh exec reviewer -- gh pr view 1 -R dsxragnarok/council`

func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	request, err := parseArguments(args)
	if err != nil {
		if errors.Is(err, errHelp) {
			fmt.Fprintln(stdout, usage)
			return nil
		}
		return fmt.Errorf("%w\n\n%s", err, usage)
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

	token, _, err := client.CreateInstallationToken(ctx, appJWT, installationID)
	if err != nil {
		return err
	}
	return runChild(ctx, request.command, token, stdin, stdout, stderr)
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
	if len(command) == 0 || filepathBase(command[0]) != "gh" {
		return ""
	}
	for index := 1; index < len(command); index++ {
		switch command[index] {
		case "-R", "--repo":
			if index+1 < len(command) {
				return command[index+1]
			}
		default:
			if strings.HasPrefix(command[index], "--repo=") {
				return strings.TrimPrefix(command[index], "--repo=")
			}
			if strings.HasPrefix(command[index], "-R") && len(command[index]) > 2 {
				return strings.TrimPrefix(command[index], "-R")
			}
		}
	}
	return ""
}

func filepathBase(path string) string {
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}
