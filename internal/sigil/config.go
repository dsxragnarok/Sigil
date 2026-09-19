package sigil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var roleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// RoleConfig is deliberately role-neutral. Every role binding must declare
// its client_id explicitly; there are no role-specific defaults.
type RoleConfig struct {
	ClientID          string `json:"client_id"`
	PrivateKeyPath    string `json:"private_key_path"`
	DefaultRepository string `json:"default_repository,omitempty"`
	InstallationID    int64  `json:"installation_id,omitempty"`
}

func LoadRoleConfig(role string) (RoleConfig, string, error) {
	if !roleNamePattern.MatchString(role) {
		return RoleConfig{}, "", fmt.Errorf("invalid role %q", role)
	}

	configDir, err := configDirectory()
	if err != nil {
		return RoleConfig{}, "", err
	}
	path := filepath.Join(configDir, role+".json")
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RoleConfig{}, path, fmt.Errorf("config for role %q not found at %s", role, path)
		}
		return RoleConfig{}, path, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return RoleConfig{}, path, fmt.Errorf("inspect config %s: %w", path, err)
	}
	if info.IsDir() {
		return RoleConfig{}, path, fmt.Errorf("config %s is a directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return RoleConfig{}, path, fmt.Errorf("config %s is readable by other users; run chmod 600 %q", path, path)
	}

	var config RoleConfig
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return RoleConfig{}, path, fmt.Errorf("read config %s: %w", path, err)
	}
	if config.ClientID == "" {
		return RoleConfig{}, path, fmt.Errorf("config %s: client_id is required", path)
	}
	if config.PrivateKeyPath == "" {
		return RoleConfig{}, path, fmt.Errorf("config %s: private_key_path is required", path)
	}
	config.PrivateKeyPath, err = resolveKeyPath(configDir, config.PrivateKeyPath)
	if err != nil {
		return RoleConfig{}, path, fmt.Errorf("config %s: %w", path, err)
	}
	return config, path, nil
}

func configDirectory() (string, error) {
	if dir := os.Getenv("SIGIL_CONFIG_DIR"); dir != "" {
		return filepath.Abs(dir)
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "sigil"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".config", "sigil"), nil
}

func cacheFilePath() (string, error) {
	if dir := os.Getenv("SIGIL_CACHE_DIR"); dir != "" {
		absolute, err := filepath.Abs(dir)
		if err != nil {
			return "", err
		}
		return filepath.Join(absolute, "installations.json"), nil
	}
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "sigil", "installations.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".cache", "sigil", "installations.json"), nil
}

func expandHome(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand private key path: %w", err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func resolveKeyPath(configDir, path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		return expandHome(path)
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	return filepath.Clean(filepath.Join(configDir, path)), nil
}
