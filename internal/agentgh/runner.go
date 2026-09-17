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
	if strings.ContainsAny(command[0], `/\`) || (command[0] != "gh" && command[0] != "git") {
		return fmt.Errorf("command must be gh or git, got %q", command[0])
	}
	program := command[0]

	arguments := append([]string(nil), command[1:]...)
	if program == "git" {
		for i := 0; i < len(arguments); i++ {
			arg := arguments[i]
			if arg == "-c" {
				if i+1 < len(arguments) {
					val := strings.TrimSpace(arguments[i+1])
					if isBlockedGitConfig(val) {
						return fmt.Errorf("git configuration override is not allowed: %s", val)
					}
				}
			} else if strings.HasPrefix(arg, "-c") {
				val := strings.TrimSpace(strings.TrimPrefix(arg, "-c"))
				if isBlockedGitConfig(val) {
					return fmt.Errorf("git configuration override is not allowed: %s", val)
				}
			} else if strings.HasPrefix(arg, "--config") {
				return fmt.Errorf("git configuration override is not allowed: %s", arg)
			}
		}

		// Git does not read GH_TOKEN itself. Route GitHub HTTPS credential requests
		// through gh, which reads GH_TOKEN from this child environment.
		arguments = append([]string{
			"-c", "credential.https://github.com.helper=",
			"-c", "credential.https://github.com.helper=!gh auth git-credential",
		}, arguments...)
	}

	sanitizedPath := sanitizePath(os.Getenv("PATH"))
	targetBinary, err := lookPathIn(program, sanitizedPath)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", program, err)
	}

	child := exec.CommandContext(ctx, targetBinary, arguments...)
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

func isBlockedGitConfig(val string) bool {
	lower := strings.ToLower(val)
	return strings.HasPrefix(lower, "credential.") || strings.HasPrefix(lower, "credential=") || lower == "credential"
}

func sanitizePath(rawPath string) string {
	allowTmp := os.Getenv("AGENT_GH_ALLOW_TMP_PATH") == "1"
	entries := filepath.SplitList(rawPath)
	var safe []string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || entry == "." {
			continue
		}
		if !filepath.IsAbs(entry) {
			continue
		}
		clean := filepath.Clean(entry)
		if !allowTmp {
			if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") ||
				clean == "/var/tmp" || strings.HasPrefix(clean, "/var/tmp/") ||
				clean == "/dev/shm" || strings.HasPrefix(clean, "/dev/shm/") {
				continue
			}
		}
		info, err := os.Stat(clean)
		if err != nil || !info.IsDir() {
			continue
		}
		if info.Mode().Perm()&0o002 != 0 {
			// World-writable directory
			continue
		}
		safe = append(safe, clean)
	}
	if len(safe) == 0 {
		for _, def := range []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"} {
			if info, err := os.Stat(def); err == nil && info.IsDir() && info.Mode().Perm()&0o002 == 0 {
				safe = append(safe, def)
			}
		}
	}
	return strings.Join(safe, string(filepath.ListSeparator))
}

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

func withToken(environment []string, token string) []string {
	allowed := map[string]bool{
		"PATH": true,
		"HOME": true,
		"USER": true,
		"LANG": true,
		"TZ":   true,
		"TERM": true,
	}
	var filtered []string
	hasPath := false
	for _, entry := range environment {
		eq := strings.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}
		key := entry[:eq]
		if key == "GITHUB_TOKEN" || key == "GH_HOST" || key == "GH_TOKEN" {
			continue
		}
		if allowed[key] {
			if key == "PATH" {
				filtered = append(filtered, "PATH="+sanitizePath(entry[eq+1:]))
				hasPath = true
			} else {
				filtered = append(filtered, entry)
			}
		}
	}
	if !hasPath {
		filtered = append(filtered, "PATH="+sanitizePath(""))
	}
	filtered = append(filtered, "GH_TOKEN="+token)
	filtered = append(filtered, "GIT_CONFIG_NOSYSTEM=1")
	return filtered
}
