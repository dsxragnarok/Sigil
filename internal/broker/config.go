package broker

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sigil/internal/provider/github"
)

// roleFile is the on-disk role binding. Every identity declares its client_id
// and private_key_path explicitly; unknown fields are rejected.
type roleFile struct {
	ClientID          string `json:"client_id"`
	PrivateKeyPath    string `json:"private_key_path"`
	DefaultRepository string `json:"default_repository,omitempty"`
	InstallationID    int64  `json:"installation_id,omitempty"`
}

// RoleSet is the broker-owned role configuration: provider bindings plus
// per-role default repositories for repository inference.
type RoleSet struct {
	Bindings     map[string]github.Binding
	DefaultRepos map[string]string
}

// LoadRoleSet reads every <role>.json file in the broker-owned config dir.
// Client environment plays no part: the directory is fixed at daemon startup.
func LoadRoleSet(configDir string) (RoleSet, error) {
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return RoleSet{}, fmt.Errorf("read broker config directory: %w", err)
	}
	set := RoleSet{Bindings: make(map[string]github.Binding), DefaultRepos: make(map[string]string)}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		role := strings.TrimSuffix(name, ".json")
		if !roleNamePattern.MatchString(role) {
			continue
		}
		binding, defaultRepo, err := loadRoleBinding(configDir, role)
		if err != nil {
			return RoleSet{}, err
		}
		set.Bindings[role] = binding
		if defaultRepo != "" {
			set.DefaultRepos[role] = defaultRepo
		}
	}
	if len(set.Bindings) == 0 {
		return RoleSet{}, fmt.Errorf("no role bindings in %s", configDir)
	}
	return set, nil
}

func loadRoleBinding(configDir, role string) (github.Binding, string, error) {
	path := filepath.Join(configDir, role+".json")
	f, err := os.Open(path)
	if err != nil {
		return github.Binding{}, "", fmt.Errorf("open config for role %q: %w", role, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return github.Binding{}, "", fmt.Errorf("inspect config for role %q: %w", role, err)
	}
	if info.IsDir() {
		return github.Binding{}, "", fmt.Errorf("config for role %q is a directory", role)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return github.Binding{}, "", fmt.Errorf("config for role %q is readable by other users", role)
	}
	var file roleFile
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return github.Binding{}, "", fmt.Errorf("read config for role %q: %w", role, err)
	}
	if file.ClientID == "" {
		return github.Binding{}, "", fmt.Errorf("config for role %q: client_id is required", role)
	}
	if file.PrivateKeyPath == "" {
		return github.Binding{}, "", fmt.Errorf("config for role %q: private_key_path is required", role)
	}
	keyPath, err := resolveBrokerKeyPath(configDir, file.PrivateKeyPath)
	if err != nil {
		return github.Binding{}, "", fmt.Errorf("config for role %q: %w", role, err)
	}
	return github.Binding{
		Name:           role,
		ClientID:       file.ClientID,
		PrivateKeyRef:  "file:" + keyPath,
		InstallationID: file.InstallationID,
	}, file.DefaultRepository, nil
}

func resolveBrokerKeyPath(configDir, path string) (string, error) {
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
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	return filepath.Join(configDir, path), nil
}
