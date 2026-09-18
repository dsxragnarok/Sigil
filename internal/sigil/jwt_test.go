package sigil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateAppJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	token, err := CreateAppJWT(ReviewerClientID, key, now)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	decode := func(value string) []byte {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	var header map[string]string
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("unexpected header: %#v", header)
	}
	var claims struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}
	if err := json.Unmarshal(decode(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != ReviewerClientID {
		t.Fatalf("issuer = %q, want %q", claims.Issuer, ReviewerClientID)
	}
	if claims.IssuedAt != now.Add(-time.Minute).Unix() {
		t.Fatalf("iat = %d", claims.IssuedAt)
	}
	if claims.ExpiresAt != now.Add(9*time.Minute).Unix() {
		t.Fatalf("exp = %d", claims.ExpiresAt)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], decode(parts[2])); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestLoadRSAPrivateKeyPermissions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	// Write 0644 (insecure)
	if err := os.WriteFile(keyPath, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadRSAPrivateKey(keyPath)
	if err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Fatalf("expected permission error for 0644 key, got %v", err)
	}

	// Change to 0600 (secure)
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRSAPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("unexpected error loading 0600 key: %v", err)
	}
	if loaded == nil || loaded.N.Cmp(key.N) != 0 {
		t.Fatal("loaded key does not match original key")
	}
}
