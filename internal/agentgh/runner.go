package agentgh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

var standardSystemDirs = []string{
	"/opt/homebrew/bin",
	"/usr/local/bin",
	"/usr/bin",
	"/bin",
}

// testTrustedDirs is a test hook to override lookup directories in unit tests.
var testTrustedDirs []string

func trustedDirs() []string {
	if len(testTrustedDirs) > 0 {
		return testTrustedDirs
	}
	return standardSystemDirs
}

func isSafeDir(dir string) bool {
	if dir == "" || dir == "." || !filepath.IsAbs(dir) {
		return false
	}
	clean := filepath.Clean(dir)
	// In production, reject all temporary and shared memory locations.
	if len(testTrustedDirs) == 0 {
		if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") ||
			clean == "/var/tmp" || strings.HasPrefix(clean, "/var/tmp/") ||
			clean == "/dev/shm" || strings.HasPrefix(clean, "/dev/shm/") ||
			clean == "/private/tmp" || strings.HasPrefix(clean, "/private/tmp/") ||
			clean == "/private/var/tmp" || strings.HasPrefix(clean, "/private/var/tmp/") {
			return false
		}
	}
	info, err := os.Stat(clean)
	if err != nil || !info.IsDir() {
		return false
	}
	perm := info.Mode().Perm()
	// World-writable directories are always rejected.
	if perm&0o002 != 0 {
		return false
	}
	// Group-writable directories are rejected unless owned by root or the current user.
	// This assumes single-user / individual workstation group hygiene (e.g. standard macOS).
	// On multi-user systems with shared primary groups, group-writable dirs could pose higher risk.
	if perm&0o020 != 0 {
		if !isOwnedByCurrentOrRoot(info) {
			return false
		}
	}
	return true
}

func isOwnedByCurrentOrRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == 0 || stat.Uid == uint32(os.Getuid())
}

func trustedPath() string {
	var safe []string
	for _, dir := range trustedDirs() {
		clean := filepath.Clean(dir)
		if isSafeDir(clean) {
			safe = append(safe, clean)
		}
	}
	return strings.Join(safe, string(filepath.ListSeparator))
}

func runChild(ctx context.Context, command []string, token string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(command) == 0 {
		return fmt.Errorf("missing command after --")
	}
	if strings.ContainsAny(command[0], `/\`) || (command[0] != "gh" && command[0] != "git") {
		return fmt.Errorf("command must be gh or git, got %q", command[0])
	}
	program := command[0]

	arguments := append([]string(nil), command[1:]...)
	if program == "git" {
		if err := validateGitArguments(arguments); err != nil {
			return err
		}

		// Git does not read GH_TOKEN itself. Route GitHub HTTPS credential requests
		// through gh, which reads GH_TOKEN from this child environment.
		// Also disable pagination via top-level --no-pager.
		arguments = append([]string{
			"--no-pager",
			"-c", "credential.https://github.com.helper=",
			"-c", "credential.https://github.com.helper=!gh auth git-credential",
		}, arguments...)
	}

	trustedPathStr := trustedPath()
	if trustedPathStr == "" {
		return errors.New("no safe directories available in trusted PATH")
	}
	targetBinary, err := lookPathIn(program, trustedPathStr)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", program, err)
	}

	child := exec.CommandContext(ctx, targetBinary, arguments...)
	child.Stdin = stdin
	child.Stdout = stdout
	child.Stderr = stderr
	child.Env = withToken(os.Environ(), token, trustedPathStr)
	if err := child.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("%s exited with status %d", program, exitError.ExitCode())
		}
		return fmt.Errorf("run %s: %w", program, err)
	}
	return nil
}

// validateGitArguments inspects user-provided git arguments to block flags and
// configuration directives that can execute arbitrary commands, redirect URLs,
// load untrusted configs/templates, or re-point the repository / working directory.
//
// An allowlist is enforced for git -c configuration directives.
// Pre-subcommand and command-execution flags (--upload-pack, --receive-pack, --exec,
// --exec-path, --template, --git-dir, --work-tree, --config-env, --config) are blocked.
// -C is blocked everywhere except git commit -C <commit> (which reuses commit messages).
// -u is blocked pre-subcommand and for git clone (where it specifies upload-pack).
func validateGitArguments(arguments []string) error {
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

// lookPathIn resolves an executable within a PATH string.
// Note: It performs stat-then-exec without checking binary ownership or file mode,
// which is an accepted risk because directories in trustedPath have already been
// validated to be safe (root/self-owned, non-world-writable, and non-temporary).
func lookPathIn(file string, pathEnv string) (string, error) {
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		target := filepath.Join(dir, file)
		info, err := os.Stat(target)
		if err != nil {
			continue
		}
		if !info.IsDir() && info.Mode()&0o111 != 0 {
			return target, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in PATH", file)
}

func withToken(environment []string, token string, trustedPathStr string) []string {
	allowed := map[string]bool{
		"PATH": true,
		"HOME": true,
		"USER": true,
		"LANG": true,
		"TZ":   true,
		"TERM": true,
	}
	var filtered []string
	for _, entry := range environment {
		eq := strings.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}
		key := entry[:eq]
		if key == "GITHUB_TOKEN" || key == "GH_HOST" || key == "GH_TOKEN" {
			continue
		}
		if key == "PATH" {
			// Do not pass caller PATH through; child PATH is set to trustedPath() below.
			continue
		}
		if allowed[key] {
			filtered = append(filtered, entry)
		}
	}
	filtered = append(filtered, "PATH="+trustedPathStr)
	filtered = append(filtered, "GH_TOKEN="+token)
	filtered = append(filtered, "GIT_CONFIG_NOSYSTEM=1")
	filtered = append(filtered, "GIT_CONFIG_GLOBAL="+os.DevNull)
	filtered = append(filtered, "GIT_CONFIG_SYSTEM="+os.DevNull)
	filtered = append(filtered, "GIT_SSH_COMMAND=ssh -F "+os.DevNull)
	filtered = append(filtered, "GIT_PAGER=cat")
	filtered = append(filtered, "PAGER=cat")
	filtered = append(filtered, "GIT_EDITOR=true")
	filtered = append(filtered, "GIT_SEQUENCE_EDITOR=true")
	return filtered
}
