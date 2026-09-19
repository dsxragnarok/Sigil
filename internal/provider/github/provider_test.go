package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigil/internal/secret"
)

type stubStore map[string][]byte

func (s stubStore) Get(_ context.Context, ref string) ([]byte, error) {
	data, ok := s[ref]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func testKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func testProvider(t *testing.T, transport http.RoundTripper) (*Provider, []byte) {
	t.Helper()
	keyPEM := testKeyPEM(t)
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Provider{
		Secrets: stubStore{"file:" + keyPath: keyPEM},
		Cache:   NewInstallationCache(t.TempDir()),
		API: &Client{BaseURL: "https://api.github.test",
			HTTPClient: &http.Client{Transport: transport}},
		Bindings: map[string]Binding{
			"reviewer": {Name: "reviewer", ClientID: "client-123", PrivateKeyRef: "file:" + keyPath},
		},
	}
	return p, keyPEM
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPrepareMintsRepositoryScopedToken(t *testing.T) {
	var postBody string
	p, _ := testProvider(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := ""
		status := http.StatusOK
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/dsxragnarok/council/installation":
			body = `{"id":12345}`
		case request.Method == http.MethodPost && request.URL.Path == "/app/installations/12345/access_tokens":
			payload, _ := io.ReadAll(request.Body)
			postBody = string(payload)
			body = `{"token":"installation-token","expires_at":"2030-01-02T03:04:05Z"}`
		default:
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
			Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
	}))

	cred, err := p.Prepare(context.Background(), CredentialRequest{Identity: "reviewer", Repository: "dsxragnarok/council"})
	if err != nil {
		t.Fatal(err)
	}
	if cred.Token != "installation-token" {
		t.Fatalf("token = %q", cred.Token)
	}
	if postBody != `{"repositories":["council"]}` {
		t.Fatalf("postBody = %q", postBody)
	}
	// Second call must reuse the cached installation ID (no discovery GET).
	calls := 0
	p.API.HTTPClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method == http.MethodGet {
			t.Errorf("unexpected discovery GET after caching: %s", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK",
			Body:   io.NopCloser(strings.NewReader(`{"token":"t2","expires_at":"2030-01-02T03:04:05Z"}`)),
			Header: make(http.Header), Request: request}, nil
	})
	if _, err := p.Prepare(context.Background(), CredentialRequest{Identity: "reviewer", Repository: "dsxragnarok/council"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 API call after caching, got %d", calls)
	}
}

func TestResolveIdentityRequiresExplicitClientID(t *testing.T) {
	p, _ := testProvider(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("must not call API")
	}))
	_, err := p.ResolveIdentity(context.Background(), Binding{Name: "reviewer", PrivateKeyRef: "file:/x"})
	if err == nil || !strings.Contains(err.Error(), "client_id is required") {
		t.Fatalf("expected explicit client_id error, got %v", err)
	}
}

func TestPrepareUnknownIdentityFailsClosed(t *testing.T) {
	p, _ := testProvider(t, nil)
	if _, err := p.Prepare(context.Background(), CredentialRequest{Identity: "admin", Repository: "o/r"}); err == nil {
		t.Fatal("expected unknown identity error")
	}
}

func TestProviderErrorsNeverIncludeToken(t *testing.T) {
	p, _ := testProvider(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized",
			Body:   io.NopCloser(strings.NewReader(`{"message":"Bad credentials","token":"must-not-leak"}`)),
			Header: make(http.Header), Request: request}, nil
	}))
	_, err := p.Prepare(context.Background(), CredentialRequest{Identity: "reviewer", Repository: "dsxragnarok/council"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("secret leaked in error: %q", err.Error())
	}
}

func TestInstallationCacheScopedByIdentityAndRepo(t *testing.T) {
	cache := NewInstallationCache(t.TempDir())
	if err := cache.Put("reviewer", "o/a", 1); err != nil {
		t.Fatal(err)
	}
	if err := cache.Put("tester", "o/a", 2); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get("reviewer", "o/a")
	if err != nil || got != 1 {
		t.Fatalf("got %d, %v", got, err)
	}
	got, err = cache.Get("tester", "o/a")
	if err != nil || got != 2 {
		t.Fatalf("got %d, %v", got, err)
	}
	got, err = cache.Get("missing", "o/a")
	if err != nil || got != 0 {
		t.Fatalf("got %d, %v", got, err)
	}
}

func TestFileSecretStorePreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (secret.FileStore{}).Get(context.Background(), "file:"+path); err != nil {
		t.Fatal(err)
	}
}
