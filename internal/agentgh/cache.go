package agentgh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type installationCache struct {
	Roles map[string]map[string]int64 `json:"roles"`
}

func cachedInstallationID(role, repository string) (int64, error) {
	path, err := cacheFilePath()
	if err != nil {
		return 0, err
	}
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read installation cache %s: %w", path, err)
	}
	var cache installationCache
	if err := json.Unmarshal(contents, &cache); err != nil {
		return 0, fmt.Errorf("read installation cache %s: %w", path, err)
	}
	return cache.Roles[role][repository], nil
}

func cacheInstallationID(role, repository string, id int64) error {
	path, err := cacheFilePath()
	if err != nil {
		return err
	}
	cache := installationCache{Roles: make(map[string]map[string]int64)}
	if contents, readErr := os.ReadFile(path); readErr == nil {
		if err := json.Unmarshal(contents, &cache); err != nil {
			return fmt.Errorf("read installation cache %s: %w", path, err)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read installation cache %s: %w", path, readErr)
	}
	if cache.Roles == nil {
		cache.Roles = make(map[string]map[string]int64)
	}
	if cache.Roles[role] == nil {
		cache.Roles[role] = make(map[string]int64)
	}
	cache.Roles[role][repository] = id

	contents, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".installations-*")
	if err != nil {
		return fmt.Errorf("create installation cache: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write installation cache: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close installation cache: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace installation cache: %w", err)
	}
	return nil
}
