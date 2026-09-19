package secret

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("secret-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := (FileStore{}).Get(context.Background(), "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret-bytes" {
		t.Fatalf("got %q", got)
	}
}

func TestFileStoreRejectsGroupReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("secret-bytes"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := (FileStore{}).Get(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("expected permission error, got %v", err)
	}
}

func TestFileStoreErrorsNeverIncludeSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pem")
	_, err := (FileStore{}).Get(context.Background(), path)
	if err == nil {
		t.Fatal("expected error")
	}
	dir := t.TempDir()
	if _, err := (FileStore{}).Get(context.Background(), dir); err == nil {
		t.Fatal("expected directory error")
	}
	if _, err := (FileStore{}).Get(context.Background(), ""); err == nil {
		t.Fatal("expected empty-ref error")
	}
}
