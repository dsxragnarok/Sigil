package agentgh

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
	token, expires, err := client.CreateInstallationToken(context.Background(), "app-jwt", id)
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
