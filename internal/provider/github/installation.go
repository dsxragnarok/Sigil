package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// InstallationCache maps identity+repository to installation IDs. It is
// broker-owned: the directory is fixed at daemon startup, files are 0600,
// and only numeric IDs (never credentials) are cached.
type InstallationCache struct {
	dir string
}

// NewInstallationCache creates a cache rooted at dir.
func NewInstallationCache(dir string) *InstallationCache {
	return &InstallationCache{dir: dir}
}

func (c *InstallationCache) path() string {
	return filepath.Join(c.dir, "installations.json")
}

func (c *InstallationCache) lock(exclusive bool) (*os.File, error) {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	lockFile, err := os.OpenFile(filepath.Join(c.dir, ".installations.lock"), os.O_CREATE|os.O_RDWR, 0o600)
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

func unlock(lockFile *os.File) {
	if lockFile != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}
}

type installationCacheFile struct {
	Roles map[string]map[string]int64 `json:"roles"`
}

// Get returns the cached installation ID or 0.
func (c *InstallationCache) Get(identity, repository string) (int64, error) {
	lockFile, err := c.lock(false)
	if err != nil {
		return 0, err
	}
	defer unlock(lockFile)
	contents, err := os.ReadFile(c.path())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read installation cache: %w", err)
	}
	var cache installationCacheFile
	if err := json.Unmarshal(contents, &cache); err != nil {
		return 0, fmt.Errorf("read installation cache: %w", err)
	}
	return cache.Roles[identity][repository], nil
}

// Put stores an installation ID.
func (c *InstallationCache) Put(identity, repository string, id int64) error {
	lockFile, err := c.lock(true)
	if err != nil {
		return err
	}
	defer unlock(lockFile)
	cache := installationCacheFile{Roles: make(map[string]map[string]int64)}
	if contents, readErr := os.ReadFile(c.path()); readErr == nil {
		if err := json.Unmarshal(contents, &cache); err != nil {
			return fmt.Errorf("read installation cache: %w", err)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read installation cache: %w", readErr)
	}
	if cache.Roles == nil {
		cache.Roles = make(map[string]map[string]int64)
	}
	if cache.Roles[identity] == nil {
		cache.Roles[identity] = make(map[string]int64)
	}
	cache.Roles[identity][repository] = id
	contents, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	temporary, err := os.CreateTemp(c.dir, ".installations-*")
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
	if err := os.Rename(temporaryPath, c.path()); err != nil {
		return fmt.Errorf("replace installation cache: %w", err)
	}
	return nil
}
