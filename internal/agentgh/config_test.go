package agentgh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRoleConfigPermissionsAndPathResolution(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("AGENT_GH_CONFIG_DIR", configDir)

	rolePath := filepath.Join(configDir, "reviewer.json")
	roleJSON := `{
  "client_id": "Iv23liYTtTwOvyDhpyK0",
  "private_key_path": "reviewer.pem",
  "default_repository": "dsxragnarok/council"
}`

	// Write with 0644 (should fail permission check)
	if err := os.WriteFile(rolePath, []byte(roleJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadRoleConfig("reviewer")
	if err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("expected permission error for 0644 role config, got: %v", err)
	}

	// Change to 0600 (should succeed)
	if err := os.Chmod(rolePath, 0o600); err != nil {
		t.Fatal(err)
	}

	config, path, err := LoadRoleConfig("reviewer")
	if err != nil {
		t.Fatalf("unexpected error loading role config: %v", err)
	}
	if path != rolePath {
		t.Fatalf("config path = %q, want %q", path, rolePath)
	}

	// Verify relative private_key_path was resolved against configDir
	wantKeyPath := filepath.Join(configDir, "reviewer.pem")
	if config.PrivateKeyPath != wantKeyPath {
		t.Fatalf("private_key_path = %q, want %q", config.PrivateKeyPath, wantKeyPath)
	}
}

func TestResolveKeyPath(t *testing.T) {
	configDir := "/etc/agent-gh"
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		input string
		want  string
	}{
		{"key.pem", filepath.Join(configDir, "key.pem")},
		{"./key.pem", filepath.Join(configDir, "key.pem")},
		{"sub/key.pem", filepath.Join(configDir, "sub", "key.pem")},
		{"/var/keys/key.pem", "/var/keys/key.pem"},
		{"~/key.pem", filepath.Join(home, "key.pem")},
	}

	for _, test := range tests {
		got, err := resolveKeyPath(configDir, test.input)
		if err != nil {
			t.Fatalf("resolveKeyPath(%q) error = %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("resolveKeyPath(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
