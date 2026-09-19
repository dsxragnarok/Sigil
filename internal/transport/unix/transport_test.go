package unix

import (
	"bufio"
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

func TestInteractiveFullDuplexPromptThenAnswer(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if _, err := io.WriteString(stdout, "prompt"); err != nil {
			return 0, err
		}
		buf := make([]byte, 64)
		n, err := stdin.Read(buf)
		if err != nil {
			return 0, err
		}
		if string(buf[:n]) != "answer" {
			return 0, io.ErrUnexpectedEOF
		}
		if _, err := io.WriteString(stdout, "done"); err != nil {
			return 0, err
		}
		return 0, nil
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()

	meta, err := EncodeMeta(Meta{Role: "reviewer", Command: []string{"gh"}})
	if err != nil {
		t.Fatal(err)
	}
	promptSeen := make(chan struct{})
	bodyReader, bodyWriter := io.Pipe()
	go func() {
		if _, werr := bodyWriter.Write(meta); werr != nil {
			_ = bodyWriter.CloseWithError(werr)
			return
		}
		select {
		case <-promptSeen:
		case <-time.After(5 * time.Second):
			_ = bodyWriter.CloseWithError(io.ErrUnexpectedEOF)
			return
		}
		chunk, _ := EncodeFrame(EncodeData(TypeStdin, []byte("answer")))
		if _, werr := bodyWriter.Write(chunk); werr != nil {
			_ = bodyWriter.CloseWithError(werr)
			return
		}
		eof, _ := EncodeFrame(Frame{Type: TypeStdinEOF})
		_, _ = bodyWriter.Write(eof)
		_ = bodyWriter.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/exec", bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-ndjson")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("Do (deadlock without EnableFullDuplex?): %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 64*1024), MaxStreamFrameBytes+1024)
	var out strings.Builder
	closeOnce := false
	for scanner.Scan() {
		frame, err := DecodeFrame(append([]byte(nil), scanner.Bytes()...))
		if err != nil {
			t.Fatal(err)
		}
		switch frame.Type {
		case TypeStdout:
			data, _ := DecodeData(frame)
			out.Write(data)
			if strings.Contains(out.String(), "prompt") && !closeOnce {
				closeOnce = true
				close(promptSeen)
			}
		case TypeExit:
			if out.String() != "promptdone" {
				t.Fatalf("stdout = %q, want prompt+done interleaved", out.String())
			}
			return
		case TypeError:
			t.Fatalf("broker error: %s", frame.Message)
		}
	}
	t.Fatal("stream ended without exit (full duplex deadlock?)")
}

func TestImmediateExitWithBlockingStdin(t *testing.T) {
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 0, nil
	})
	server := httptest.NewServer(AdminHandler(exec))
	defer server.Close()
	client := &Client{HTTP: server.Client(), URL: server.URL + "/v1/exec", StdinChunk: 4}

	pr, pw := io.Pipe()
	type outcome struct {
		code int
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		var out bytes.Buffer
		code, err := client.Exec(context.Background(), Meta{Role: "reviewer", Command: []string{"gh"}}, pr, &out, io.Discard)
		done <- outcome{code, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			_ = pw.Close()
			_ = pr.Close()
			t.Fatalf("blocking stdin turned success into error: %v", res.err)
		}
		if res.code != 0 {
			_ = pw.Close()
			_ = pr.Close()
			t.Fatalf("code = %d, want 0", res.code)
		}
		// Exec returned without requiring stdin EOF (deterministic
		// lifecycle). Close the blocking stdin promptly so the request-upload
		// goroutine (still blocked in stdin.Read) can exit; for one-shot CLI
		// process exit reaps it, for reuse the caller must close.
		_ = pw.Close()
		_ = pr.Close()
	case <-time.After(3 * time.Second):
		_ = pw.Close()
		_ = pr.Close()
		t.Fatal("server waited for terminal stdin EOF (must return without EOF)")
	}
}

func TestDaemonCancelInterruptsActiveExec(t *testing.T) {
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	defer daemonCancel()
	started := make(chan struct{})
	exec := ExecutorFunc(func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	})
	dir, err := os.MkdirTemp("/tmp", "sigil-daemon-cancel-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	listener, srv, err := ServeOnSocketWithBase(sock, AdminHandler(exec), daemonCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer srv.Close()

	client := NewClient(sock, "/v1/exec")
	type outcome struct {
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		_, err := client.Exec(context.Background(), Meta{Role: "reviewer", Command: []string{"gh"}}, nil, io.Discard, io.Discard)
		done <- outcome{err}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("executor never started")
	}
	daemonCancel()
	select {
	case res := <-done:
		if res.err == nil {
			t.Fatal("expected broker error after daemon cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("active execution not cancelled by daemon context")
	}
}
