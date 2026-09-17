package agentgh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type installationCache struct {
	Roles map[string]map[string]int64 `json:"roles"`
}

func lockCache(path string, exclusive bool) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	lockPath := filepath.Join(filepath.Dir(path), ".installations.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cache lock: %w", err)
	}
	flag := syscall.LOCK_SH
	if exclusive {
		flag = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(lockFile.Fd()), flag); err != nil {
		lockFile.Close()
		return nil, fmt.Errorf("lock cache: %w", err)
	}
	return lockFile, nil
}

func unlockCache(lockFile *os.File) {
	if lockFile != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}
}

func cachedInstallationID(role, repository string) (int64, error) {
	path, err := cacheFilePath()
	if err != nil {
		return 0, err
	}
	lockFile, err := lockCache(path, false)
	if err != nil {
		return 0, err
	}
	defer unlockCache(lockFile)

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
	lockFile, err := lockCache(path, true)
	if err != nil {
		return err
	}
	defer unlockCache(lockFile)

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
