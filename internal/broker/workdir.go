package broker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// canonicalizeRoots resolves every workspace root with symlink resolution.
// Roots must be absolute, must resolve safely, and must exist as directories.
// Ambiguity fails closed at daemon startup.
func canonicalizeRoots(roots []string) ([]string, error) {
	var canonical []string
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("workspace root %q must be absolute", root)
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("workspace root %q cannot be resolved safely: %w", root, err)
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("workspace root %q is not a directory", root)
		}
		canonical = append(canonical, filepath.Clean(resolved))
	}
	return canonical, nil
}

// canonicalWorkdir validates and canonicalizes a working directory against
// the broker-approved workspace roots. git execution always requires an
// explicit directory; gh execution may omit it (the runner then uses a fresh
// empty temp directory, never the daemon cwd).
func (b *Broker) canonicalWorkdir(dir, program string) (string, error) {
	if dir == "" {
		if program == "git" {
			return "", fmt.Errorf("working_dir is required for git execution")
		}
		return "", nil
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("working_dir %q must be absolute", dir)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("working_dir %q cannot be resolved safely: %w", dir, err)
	}
	resolved = filepath.Clean(resolved)
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("working_dir %q is not a directory", dir)
	}
	for _, root := range b.roots {
		if resolved == root || strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("working_dir %q is outside approved workspace roots", dir)
}
