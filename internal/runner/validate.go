package runner

import (
	"fmt"
	"strings"
)

// ValidateGitArguments inspects user-provided git arguments to block flags
// and configuration directives that can execute arbitrary commands, redirect
// URLs, load untrusted configs/templates, or re-point the repository and
// working directory.
//
// An allowlist is enforced for git -c configuration directives.
// Pre-subcommand and command-execution flags (--upload-pack, --receive-pack,
// --exec, --exec-path, --template, --git-dir, --work-tree, --config-env,
// --config) are blocked. -C is blocked everywhere except git commit -C
// <commit> (which reuses commit messages). -u is blocked pre-subcommand and
// for git clone (where it specifies upload-pack).
// ValidateGhArguments rejects token-revealing compatibility commands.
// All `gh auth` subcommands are denied: `gh auth token` prints the active
// token and `gh auth status --show-token` does the same. Blocking the whole
// family is intentional — no legitimate broker execution needs to mutate or
// disclose authentication state, and the internal `gh auth git-credential`
// helper used by broker-spawned git is invoked by git itself, not via this
// user-command path.
func ValidateGhArguments(arguments []string) error {
	for _, arg := range arguments {
		if arg == "--show-token" || strings.HasPrefix(arg, "--show-token=") {
			return fmt.Errorf("gh flag %s is not allowed", arg)
		}
	}
	subcommand := ""
	for i := 0; i < len(arguments); i++ {
		arg := arguments[i]
		if arg == "--" {
			if i+1 < len(arguments) {
				subcommand = arguments[i+1]
			}
			break
		}
		if strings.HasPrefix(arg, "-") {
			// Skip values for known global flags that take a separate arg.
			if arg == "-R" || arg == "--repo" || arg == "--hostname" {
				i++
			}
			continue
		}
		subcommand = arg
		break
	}
	if subcommand == "auth" {
		return fmt.Errorf("gh auth commands are not allowed through the broker")
	}
	return nil
}

func ValidateGitArguments(arguments []string) error {
	subcommand := ""
	for i := 0; i < len(arguments); i++ {
		arg := arguments[i]

		if arg == "-c" {
			if i+1 < len(arguments) {
				val := arguments[i+1]
				if !isAllowedGitConfig(val) {
					return fmt.Errorf("git configuration override is not allowed: %s", val)
				}
				i++
			} else {
				return fmt.Errorf("git -c requires a configuration key=value")
			}
			continue
		} else if strings.HasPrefix(arg, "-c") {
			val := strings.TrimPrefix(arg, "-c")
			if !isAllowedGitConfig(val) {
				return fmt.Errorf("git configuration override is not allowed: %s", val)
			}
			continue
		}

		if subcommand == "" && !strings.HasPrefix(arg, "-") {
			subcommand = arg
		}

		if arg == "--config-env" || strings.HasPrefix(arg, "--config-env=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}
		if arg == "--config" || strings.HasPrefix(arg, "--config=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}
		if arg == "--exec-path" || strings.HasPrefix(arg, "--exec-path=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}
		if arg == "--template" || strings.HasPrefix(arg, "--template=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}
		if arg == "--git-dir" || strings.HasPrefix(arg, "--git-dir=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}
		if arg == "--work-tree" || strings.HasPrefix(arg, "--work-tree=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}
		if arg == "--upload-pack" || strings.HasPrefix(arg, "--upload-pack=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}
		if arg == "--receive-pack" || strings.HasPrefix(arg, "--receive-pack=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}
		if arg == "--exec" || strings.HasPrefix(arg, "--exec=") {
			return fmt.Errorf("git flag %s is not allowed", arg)
		}

		if arg == "-C" || strings.HasPrefix(arg, "-C") {
			if !(subcommand == "commit" && arg == "-C") {
				return fmt.Errorf("git flag %s is not allowed", arg)
			}
		}

		if arg == "-u" || strings.HasPrefix(arg, "-u") {
			if subcommand == "" || subcommand == "clone" {
				return fmt.Errorf("git flag %s is not allowed", arg)
			}
		}
	}
	return nil
}

var allowedConfigPrefixes = []string{
	"user.",
	"pull.",
	"push.",
	"branch.",
	"commit.",
	"tag.",
	"log.",
	"format.",
	"status.",
	"init.",
	"advice.",
	"color.",
}

var allowedExactConfigs = map[string]bool{
	"core.autocrlf":   true,
	"core.eol":        true,
	"core.safecrlf":   true,
	"core.ignorecase": true,
	"core.filemode":   true,
}

func isAllowedGitConfig(val string) bool {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return false
	}
	key := strings.ToLower(strings.SplitN(trimmed, "=", 2)[0])
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	for _, r := range key {
		if r < ' ' || r > '~' {
			return false
		}
	}
	if allowedExactConfigs[key] {
		return true
	}
	for _, prefix := range allowedConfigPrefixes {
		if strings.HasPrefix(key, prefix) && len(key) > len(prefix) {
			return true
		}
	}
	return false
}
