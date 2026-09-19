package unix

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFrameBoundsFailClosed(t *testing.T) {
	if err := ValidateCommand(nil); err == nil {
		t.Fatal("expected error for empty command")
	}
	many := make([]string, MaxCommandArgs+1)
	for i := range many {
		many[i] = "a"
	}
	if err := ValidateCommand(many); err == nil {
		t.Fatal("expected error for too many args")
	}
	big := []string{strings.Repeat("x", MaxAggregateArgBytes+1)}
	if err := ValidateCommand(big); err == nil {
		t.Fatal("expected error for oversized args")
	}
	huge := Meta{Type: TypeMeta, Command: []string{strings.Repeat("y", MaxMetaFrameBytes+1)}}
	if _, err := EncodeMeta(huge); err == nil {
		t.Fatal("expected error for oversized meta")
	}
	if _, err := DecodeFrame(bytes.Repeat([]byte("z"), MaxStreamFrameBytes+1)); err == nil {
		t.Fatal("expected error for oversized stream frame")
	}
}

func TestAdminRoundTripStreamsDistinct(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if meta.Role != "reviewer" {
			t.Errorf("role = %q", meta.Role)
		}
		data, _ := io.ReadAll(stdin)
		if string(data) != "hello-stdin" {
			t.Errorf("stdin = %q", data)
		}
		_, _ = stdout.Write([]byte("out-1"))
		_, _ = stderr.Write([]byte("err-1"))
		_, _ = stdout.Write([]byte("out-2"))
		return 0, nil
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()

	client := &Client{HTTP: server.Client(), URL: server.URL + "/v1/exec", StdinChunk: 4}
	var out, errOut bytes.Buffer
	code, err := client.Exec(context.Background(), Meta{Role: "reviewer", Command: []string{"gh", "pr", "view"}},
		strings.NewReader("hello-stdin"), &out, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if out.String() != "out-1out-2" {
		t.Fatalf("stdout = %q", out.String())
	}
	if errOut.String() != "err-1" {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestTargetNonZeroIsTransportSuccess(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 3, nil
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	client := &Client{HTTP: server.Client(), URL: server.URL + "/v1/exec", StdinChunk: 4}
	code, err := client.Exec(context.Background(), Meta{Role: "reviewer", Command: []string{"gh"}}, nil, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Fatalf("code = %d, want 3", code)
	}
}

func TestBrokerFailureIsTransportError(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 0, io.ErrUnexpectedEOF
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	client := &Client{HTTP: server.Client(), URL: server.URL + "/v1/exec", StdinChunk: 4}
	if _, err := client.Exec(context.Background(), Meta{Role: "reviewer", Command: []string{"gh"}}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected broker error")
	}
}

func TestBrokerFailureBeforeOutputIsNon2xx(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 0, io.ErrUnexpectedEOF
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	meta, _ := EncodeMeta(Meta{Role: "reviewer", Command: []string{"gh"}})
	eof, _ := EncodeFrame(Frame{Type: TypeStdinEOF})
	resp, err := server.Client().Post(server.URL+"/v1/exec", "application/x-ndjson",
		io.MultiReader(bytes.NewReader(meta), bytes.NewReader(eof)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-2xx for pre-output broker failure")
	}
}

func TestBrokerFailureAfterOutputIsErrorFrame(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		_, _ = io.WriteString(stdout, "partial")
		return 0, io.ErrUnexpectedEOF
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	client := &Client{HTTP: server.Client(), URL: server.URL + "/v1/exec", StdinChunk: 4}
	var out bytes.Buffer
	_, err := client.Exec(context.Background(), Meta{Role: "reviewer", Command: []string{"gh"}}, nil, &out, io.Discard)
	if err == nil {
		t.Fatal("expected broker error")
	}
	if out.String() != "partial" {
		t.Fatalf("partial output = %q", out.String())
	}
}

func TestMalformedStdinStreamFailsClosed(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		_, _ = io.ReadAll(stdin)
		return 0, nil
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	meta, _ := EncodeMeta(Meta{Role: "reviewer", Command: []string{"gh"}})
	bogus, _ := EncodeFrame(Frame{Type: "bogus"})
	eof, _ := EncodeFrame(Frame{Type: TypeStdinEOF})
	resp, err := server.Client().Post(server.URL+"/v1/exec", "application/x-ndjson",
		io.MultiReader(bytes.NewReader(meta), bytes.NewReader(bogus), bytes.NewReader(eof)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-2xx for malformed stdin stream")
	}
}

func TestOversizedFirstLineRejected(t *testing.T) {
	called := false
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		called = true
		return 0, nil
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	huge := append(bytes.Repeat([]byte("x"), MaxMetaFrameBytes+10), '\n')
	resp, err := server.Client().Post(server.URL+"/v1/exec", "application/x-ndjson", bytes.NewReader(huge))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-2xx for oversized metadata")
	}
	if called {
		t.Fatal("executor must not run on oversized metadata")
	}
}

func TestMalformedMetaFailsClosed(t *testing.T) {
	called := false
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		called = true
		return 0, nil
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	resp, err := server.Client().Post(server.URL+"/v1/exec", "application/x-ndjson", strings.NewReader("{bad json\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-2xx for malformed meta")
	}
	if called {
		t.Fatal("executor must not run on malformed meta")
	}
}

func TestMissingRoleFailsClosed(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 0, nil
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	client := &Client{HTTP: server.Client(), URL: server.URL + "/v1/exec", StdinChunk: 4}
	if _, err := client.Exec(context.Background(), Meta{Command: []string{"gh"}}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected error for missing role")
	}
}

func TestAgentSocketHealthAndRefusal(t *testing.T) {
	server := httptest.NewServer(AgentHandler())
	defer server.Close()
	resp, err := server.Client().Get(server.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	execResp, err := server.Client().Post(server.URL+"/v1/exec", "application/x-ndjson", strings.NewReader("{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer execResp.Body.Close()
	if execResp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent exec status = %d, want 403", execResp.StatusCode)
	}
}

func TestClientBrokerDownError(t *testing.T) {
	dir := t.TempDir()
	dead := filepath.Join("/tmp", "sigil-dead-test.sock")
	_ = dir
	_ = os.Remove(dead)
	client := NewClient(dead, "/v1/exec")
	_, err := client.Exec(context.Background(), Meta{Role: "reviewer", Command: []string{"gh"}}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "sigil: broker unavailable") {
		t.Fatalf("expected broker-unavailable error, got %v", err)
	}
}

func TestTimeoutForDefaults(t *testing.T) {
	if got := TimeoutFor(0); got != DefaultExecTimeout {
		t.Fatalf("TimeoutFor(0) = %v", got)
	}
	if got := TimeoutFor(30); got != 30*time.Second {
		t.Fatalf("TimeoutFor(30) = %v", got)
	}
	if got := TimeoutFor(1 << 30); got != MaxExecTimeout {
		t.Fatalf("TimeoutFor(huge) = %v, want clamp to %v", got, MaxExecTimeout)
	}
}
