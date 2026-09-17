package agentgh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var repoComponentPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)

type GitHubClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewGitHubClient() *GitHubClient {
	return &GitHubClient{
		BaseURL: "https://api.github.com",
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (client *GitHubClient) FindInstallation(ctx context.Context, appJWT, repository string) (int64, error) {
	owner, name, err := splitRepository(repository)
	if err != nil {
		return 0, err
	}
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/installation"
	var response struct {
		ID int64 `json:"id"`
	}
	if err := client.request(ctx, http.MethodGet, path, appJWT, nil, &response); err != nil {
		return 0, fmt.Errorf("find GitHub App installation for %s: %w", repository, err)
	}
	if response.ID <= 0 {
		return 0, fmt.Errorf("GitHub returned an invalid installation ID for %s", repository)
	}
	return response.ID, nil
}

func (client *GitHubClient) CreateInstallationToken(ctx context.Context, appJWT string, installationID int64, repositories ...string) (string, time.Time, error) {
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	body := []byte("{}")
	if len(repositories) > 0 {
		var names []string
		for _, repo := range repositories {
			if repo == "" {
				continue
			}
			if _, name, err := splitRepository(repo); err == nil {
				names = append(names, name)
			} else {
				names = append(names, repo)
			}
		}
		if len(names) > 0 {
			var err error
			body, err = json.Marshal(map[string][]string{"repositories": names})
			if err != nil {
				return "", time.Time{}, fmt.Errorf("marshal installation token request: %w", err)
			}
		}
	}
	var response struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := client.request(ctx, http.MethodPost, path, appJWT, body, &response); err != nil {
		return "", time.Time{}, fmt.Errorf("mint installation token: %w", err)
	}
	if response.Token == "" {
		return "", time.Time{}, errorsFromGitHub("GitHub returned an empty installation token")
	}
	return response.Token, response.ExpiresAt, nil
}

func (client *GitHubClient) request(ctx context.Context, method, path, appJWT string, body []byte, destination any) error {
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(client.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+appJWT)
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		var githubError struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(limited, &githubError) == nil && githubError.Message != "" {
			return fmt.Errorf("GitHub API returned %s: %s", response.Status, githubError.Message)
		}
		return fmt.Errorf("GitHub API returned %s", response.Status)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(destination); err != nil {
		return fmt.Errorf("decode GitHub response: %w", err)
	}
	return nil
}

func splitRepository(repository string) (string, string, error) {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("repository must be owner/name, got %q", repository)
	}
	if parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return "", "", fmt.Errorf("repository must be owner/name, got %q", repository)
	}
	if !repoComponentPattern.MatchString(parts[0]) || !repoComponentPattern.MatchString(parts[1]) {
		return "", "", fmt.Errorf("repository must be owner/name, got %q", repository)
	}
	return parts[0], parts[1], nil
}

type githubError string

func (err githubError) Error() string { return string(err) }

func errorsFromGitHub(message string) error { return githubError(message) }
