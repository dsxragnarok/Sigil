package agentgh

import "testing"

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
