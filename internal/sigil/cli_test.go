package sigil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	utransport "sigil/internal/transport/unix"
)

func TestParseArguments(t *testing.T) {
	request, err := parseArguments([]string{
		"exec", "reviewer", "--repo", "dsxragnarok/council", "--", "gh", "pr", "view", "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.role != "reviewer" || request.repository != "dsxragnarok/council" {
		t.Fatalf("unexpected request: %#v", request)
	}
	wantCommand := []string{"gh", "pr", "view", "1"}
	if !reflect.DeepEqual(request.command, wantCommand) {
		t.Fatalf("command = %#v, want %#v", request.command, wantCommand)
	}
}

func TestClientIgnoresConfigAndCacheOverrides(t *testing.T) {
	// The dumb client must not read role config even when overrides point at
	// a directory containing a valid-looking binding.
	evil := t.TempDir()
	if err := os.WriteFile(filepath.Join(evil, "reviewer.json"), []byte(`{"client_id":"evil"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGIL_CONFIG_DIR", evil)
	t.Setenv("SIGIL_CACHE_DIR", t.TempDir())
	t.Setenv("SIGIL_ADMIN_SOCKET", filepath.Join(t.TempDir(), "dead.sock"))

	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"exec", "reviewer", "--", "gh", "status"}, nil, nil, &stderr)
	if err == nil || !strings.Contains(err.Error(), "sigil: broker unavailable") {
		t.Fatalf("expected broker-unavailable error, got %v", err)
	}
	if strings.Contains(stderr.String(), "SIGIL_CONFIG_DIR") || strings.Contains(stderr.String(), "SIGIL_CACHE_DIR") {
		t.Fatalf("client must not act on config/cache overrides: %q", stderr.String())
	}
}

func TestBrokerDownReportsUnavailable(t *testing.T) {
	t.Setenv("SIGIL_ADMIN_SOCKET", filepath.Join(t.TempDir(), "dead.sock"))
	err := Run(context.Background(), []string{"exec", "reviewer", "--", "gh", "status"}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "sigil: broker unavailable: start sigild or configure SIGIL_SOCKET") {
		t.Fatalf("expected broker-unavailable error, got %v", err)
	}
}

func TestRunNilStreamsDoesNotPanic(t *testing.T) {
	t.Setenv("SIGIL_ADMIN_SOCKET", filepath.Join(t.TempDir(), "dead.sock"))
	_ = Run(context.Background(), []string{"exec", "reviewer", "--", "gh", "status"}, nil, nil, nil)
}

// TestExecRoundTripThroughAdminSocket proves the CLI is a pure streaming
// client: a fake broker serves the execution, the CLI renders streams and
// returns the target exit code without touching config, keys, or cache.
func TestExecRoundTripThroughAdminSocket(t *testing.T) {
	socketDir, err := os.MkdirTemp("/tmp", "sigil-cli-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socketPath := filepath.Join(socketDir, "admin.sock")

	executor := utransport.ExecutorFunc(func(ctx context.Context, meta utransport.Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if meta.Role != "reviewer" {
			t.Errorf("role = %q", meta.Role)
		}
		if len(meta.Command) == 0 || meta.Command[0] != "gh" {
			t.Errorf("command = %#v", meta.Command)
		}
		data, _ := io.ReadAll(stdin)
		if string(data) != "piped-in" {
			t.Errorf("stdin = %q", data)
		}
		_, _ = stdout.Write([]byte("fake-out"))
		_, _ = stderr.Write([]byte("fake-err"))
		return 7, nil
	})
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: utransport.AdminHandler(executor)}
	defer server.Close()
	go server.Serve(listener)

	t.Setenv("SIGIL_ADMIN_SOCKET", socketPath)
	// Even with a valid-looking config dir, the client must use the socket.
	evil := t.TempDir()
	if err := os.WriteFile(filepath.Join(evil, "reviewer.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGIL_CONFIG_DIR", evil)

	var out, errOut bytes.Buffer
	err = Run(context.Background(), []string{"exec", "reviewer", "--", "gh", "pr", "view"},
		strings.NewReader("piped-in"), &out, &errOut)
	var exitError *ExitError
	if !errors.As(err, &exitError) || exitError.Code != 7 {
		t.Fatalf("expected exit code 7, got %v", err)
	}
	if out.String() != "fake-out" || errOut.String() != "fake-err" {
		t.Fatalf("streams = %q %q", out.String(), errOut.String())
	}
}
