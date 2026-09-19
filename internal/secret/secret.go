// Package secret loads long-lived credential material for the broker.
// Only sigild code paths use this package; the CLI never touches it.
package secret

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Store resolves a secret reference to bytes.
type Store interface {
	Get(ctx context.Context, ref string) ([]byte, error)
}

// FileStore resolves file: references and plain paths. It preserves the
// permission checks from the M0 helper: group/other-readable files are
// rejected, content is size-bounded, and errors never include secret bytes.
type FileStore struct{}

func (FileStore) Get(ctx context.Context, ref string) ([]byte, error) {
	path := strings.TrimPrefix(ref, "file:")
	if path == "" {
		return nil, fmt.Errorf("empty secret reference")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var err error
	path, err = expandSecretPath(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open secret: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect secret: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("secret reference is a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret file is readable by other users; run chmod 600 on the secret file")
	}
	contents, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return contents, nil
}

func expandSecretPath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand secret path: %w", err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}
