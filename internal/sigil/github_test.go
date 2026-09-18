package sigil

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGitHubClientInstallationFlow(t *testing.T) {
	var postBody string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer app-jwt" {
			t.Errorf("authorization header = %q", request.Header.Get("Authorization"))
		}
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
		return testResponse(status, body, request), nil
	})

	client := &GitHubClient{BaseURL: "https://api.github.test", HTTPClient: &http.Client{Transport: transport}}
	id, err := client.FindInstallation(context.Background(), "app-jwt", "dsxragnarok/council")
	if err != nil {
		t.Fatal(err)
	}
	if id != 12345 {
		t.Fatalf("installation ID = %d, want 12345", id)
	}
	token, expires, err := client.CreateInstallationToken(context.Background(), "app-jwt", id, "council")
	if err != nil {
		t.Fatal(err)
	}
	if token != "installation-token" {
		t.Fatalf("token = %q", token)
	}
	wantExpiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if !expires.Equal(wantExpiry) {
		t.Fatalf("expiry = %s, want %s", expires, wantExpiry)
	}
	if postBody != `{"repositories":["council"]}` {
		t.Fatalf("postBody = %q, want %q", postBody, `{"repositories":["council"]}`)
	}

	// Also test without repository scoping
	tokenUnscoped, _, err := client.CreateInstallationToken(context.Background(), "app-jwt", id)
	if err != nil {
		t.Fatal(err)
	}
	if tokenUnscoped != "installation-token" {
		t.Fatalf("tokenUnscoped = %q", tokenUnscoped)
	}
	if postBody != `{}` {
		t.Fatalf("unscoped postBody = %q, want {}", postBody)
	}
}

func TestGitHubErrorDoesNotIncludeResponseBodySecrets(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return testResponse(http.StatusUnauthorized, `{"message":"Bad credentials","token":"must-not-leak"}`, request), nil
	})
	client := &GitHubClient{BaseURL: "https://api.github.test", HTTPClient: &http.Client{Transport: transport}}
	_, err := client.FindInstallation(context.Background(), "app-jwt", "dsxragnarok/council")
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); got == "" || contains(got, "must-not-leak") {
		t.Fatalf("unsafe error: %q", got)
	}
}

func TestSplitRepositoryValidation(t *testing.T) {
	valid := []struct {
		repo      string
		wantOwner string
		wantName  string
	}{
		{"owner/repo", "owner", "repo"},
		{"dsxragnarok/council", "dsxragnarok", "council"},
		{"a/b", "a", "b"},
		{"Org_1.Name/Repo-2.0", "Org_1.Name", "Repo-2.0"},
	}
	for _, test := range valid {
		owner, name, err := splitRepository(test.repo)
		if err != nil {
			t.Fatalf("expected %q to be valid, got %v", test.repo, err)
		}
		if owner != test.wantOwner || name != test.wantName {
			t.Fatalf("splitRepository(%q) = (%q, %q), want (%q, %q)", test.repo, owner, name, test.wantOwner, test.wantName)
		}
	}

	invalid := []string{
		"..",
		".",
		"../repo",
		"owner/..",
		"./repo",
		"owner/.",
		"owner",
		"owner/repo/extra",
		"/repo",
		"owner/",
		"",
		"-owner/repo",
		"owner/-repo",
		"owner./repo",
	}
	for _, repo := range invalid {
		if _, _, err := splitRepository(repo); err == nil {
			t.Fatalf("expected %q to be invalid, but got nil error", repo)
		}
	}
}

func TestNewGitHubClientCheckRedirect(t *testing.T) {
	client := NewGitHubClient()
	if client.HTTPClient.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be configured")
	}
	err := client.HTTPClient.CheckRedirect(nil, nil)
	if err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect returned %v, want http.ErrUseLastResponse", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testResponse(status int, body string, request *http.Request) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    request,
	}
}

func contains(value, substring string) bool {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return true
		}
	}
	return false
}
