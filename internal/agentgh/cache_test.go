package agentgh

import (
	"fmt"
	"sync"
	"testing"
)

func TestInstallationCacheIsScopedByRoleAndRepository(t *testing.T) {
	t.Setenv("AGENT_GH_CACHE_DIR", t.TempDir())
	if err := cacheInstallationID("reviewer", "dsxragnarok/council", 101); err != nil {
		t.Fatal(err)
	}
	if err := cacheInstallationID("tester", "dsxragnarok/council", 202); err != nil {
		t.Fatal(err)
	}
	if err := cacheInstallationID("reviewer", "dsxragnarok/other", 303); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		role       string
		repository string
		want       int64
	}{
		{"reviewer", "dsxragnarok/council", 101},
		{"tester", "dsxragnarok/council", 202},
		{"reviewer", "dsxragnarok/other", 303},
		{"missing", "dsxragnarok/council", 0},
	}
	for _, test := range tests {
		got, err := cachedInstallationID(test.role, test.repository)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("cached ID for %s/%s = %d, want %d", test.role, test.repository, got, test.want)
		}
	}
}

func TestInstallationCacheConcurrency(t *testing.T) {
	t.Setenv("AGENT_GH_CACHE_DIR", t.TempDir())
	const numGoroutines = 20
	errCh := make(chan error, numGoroutines)
	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			role := fmt.Sprintf("role-%d", idx%3)
			repo := fmt.Sprintf("org/repo-%d", idx)
			id := int64(1000 + idx)
			if err := cacheInstallationID(role, repo, id); err != nil {
				errCh <- err
				return
			}
			got, err := cachedInstallationID(role, repo)
			if err != nil {
				errCh <- err
				return
			}
			if got != id {
				errCh <- fmt.Errorf("got id %d, want %d", got, id)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
