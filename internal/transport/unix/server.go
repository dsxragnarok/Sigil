package unix

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
)

// Executor runs one validated execution, streaming IO. It returns the target
// exit code; a non-nil error means broker failure (transport error), never
// ordinary target failure.
type Executor interface {
	Exec(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error)
}

// ExecutorFunc adapts a function to Executor.
type ExecutorFunc func(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error)

// Exec implements Executor.
func (f ExecutorFunc) Exec(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	return f(ctx, meta, stdin, stdout, stderr)
}

// AdminHandler serves POST /v1/exec on the admin socket only. Explicit role
// selection here is the trusted/admin compatibility path.
func AdminHandler(exec Executor) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/exec", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErrorFrame(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		serveExec(w, r, exec)
	})
	return mux
}

// AgentHandler serves the ordinary agent socket in M1: health only. It must
// not accept arbitrary role-selecting execution; session-bound execution
// arrives in M2.
func AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})
	mux.HandleFunc("/v1/exec", func(w http.ResponseWriter, r *http.Request) {
		writeErrorFrame(w, http.StatusForbidden, "role-selecting execution is not allowed on the agent socket")
	})
	return mux
}

func writeErrorFrame(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(status)
	line, _ := EncodeFrame(Frame{Type: TypeError, Message: message})
	_, _ = w.Write(line)
}

func serveExec(w http.ResponseWriter, r *http.Request, exec Executor) {
	// Full duplex is required for interactive use: the executor may write a
	// prompt and flush before the client has finished uploading stdin. Without
	// this, Go's HTTP/1 server waits for request EOF before starting the
	// response, deadlocking prompt-then-answer exchanges.
	// See https://pkg.go.dev/net/http#ResponseController.EnableFullDuplex
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.EnableFullDuplex()
	}

	// Bound the first line: the metadata frame must arrive promptly and fit
	// MaxMetaFrameBytes. Per-frame and aggregate bounds below enforce the rest.
	first, rest, err := readFirstLine(r.Body)
	if err != nil {
		writeErrorFrame(w, http.StatusBadRequest, "missing metadata frame")
		return
	}
	meta, err := DecodeMeta(trimNewline(first))
	if err != nil {
		writeErrorFrame(w, http.StatusBadRequest, err.Error())
		return
	}
	if meta.Role == "" {
		writeErrorFrame(w, http.StatusBadRequest, "role is required on the admin socket")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), TimeoutFor(meta.TimeoutSeconds))
	defer cancel()

	stdinReader, stdinWriter := io.Pipe()
	scanErr := make(chan error, 1)
	go func() {
		defer stdinWriter.Close()
		var total int64
		writeClosed := false
		scanner := bufio.NewScanner(rest)
		scanner.Buffer(make([]byte, 64*1024), MaxStreamFrameBytes+1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			frame, err := DecodeFrame(append([]byte(nil), line...))
			if err != nil {
				scanErr <- err
				_ = stdinWriter.CloseWithError(err)
				return
			}
			switch frame.Type {
			case TypeStdin:
				data, err := DecodeData(frame)
				if err != nil {
					scanErr <- err
					_ = stdinWriter.CloseWithError(err)
					return
				}
				total += int64(len(data))
				if total > MaxStdinBytes {
					err := fmt.Errorf("stdin exceeds %d byte limit", MaxStdinBytes)
					scanErr <- err
					_ = stdinWriter.CloseWithError(err)
					return
				}
				if writeClosed {
					continue
				}
				if _, err := stdinWriter.Write(data); err != nil {
					if errors.Is(err, io.ErrClosedPipe) {
						writeClosed = true
						continue
					}
					scanErr <- err
					return
				}
			case TypeStdinEOF:
				scanErr <- nil
				return
			default:
				err := fmt.Errorf("unexpected request frame %q", frame.Type)
				scanErr <- err
				_ = stdinWriter.CloseWithError(err)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			scanErr <- err
			_ = stdinWriter.CloseWithError(err)
			return
		}
		scanErr <- fmt.Errorf("request ended without stdin_eof")
	}()

	// Headers are set now, but the 200 status is written lazily on the first
	// output frame. Broker failures before any output keep a non-2xx status;
	// once streaming has started, failures are reported as error frames,
	// which the client treats as transport errors distinct from target exits.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")
	flusher, _ := w.(http.Flusher)

	var mu sync.Mutex
	var outTotal int64
	var outErr error
	var wrote bool
	ensureOK := func() {
		if !wrote {
			wrote = true
			w.WriteHeader(http.StatusOK)
		}
	}
	finishError := func(status int, err error) {
		if !wrote {
			wrote = true
			w.WriteHeader(status)
		}
		line, _ := EncodeFrame(Frame{Type: TypeError, Message: err.Error()})
		_, _ = w.Write(line)
		if flusher != nil {
			flusher.Flush()
		}
	}
	write := func(frameType string, data []byte) {
		mu.Lock()
		defer mu.Unlock()
		if outErr != nil {
			return
		}
		outTotal += int64(len(data))
		if outTotal > MaxOutputBytes {
			outErr = fmt.Errorf("stdout+stderr exceeds %d byte limit", MaxOutputBytes)
			return
		}
		line, err := EncodeFrame(EncodeData(frameType, data))
		if err != nil {
			outErr = err
			return
		}
		ensureOK()
		if _, err := w.Write(line); err != nil {
			outErr = err
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
	stdout := writerFunc(func(p []byte) (int, error) { write(TypeStdout, p); return len(p), nil })
	stderr := writerFunc(func(p []byte) (int, error) { write(TypeStderr, p); return len(p), nil })

	code, err := exec.Exec(ctx, meta, stdinReader, stdout, stderr)
	// Deterministic lifecycle: target exit terminates the request-input
	// side, so `stdin_eof` is no longer required once the child has exited.
	// Fail closed only on malformed streams already observed before exec
	// returned; a still-blocked uploader is terminal stdin still open (e.g.
	// `sigil exec ...` with a terminal that never closes), not a truncation.
	// No wall-clock grace: handler return closes the request body and
	// terminates the scanner goroutine, so late frames after exit are
	// irrelevant by definition rather than raced against a timer.
	_ = stdinReader.Close()
	var scanResult error
	select {
	case scanResult = <-scanErr:
	default:
		scanResult = nil
	}

	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		finishError(http.StatusInternalServerError, err)
		return
	}
	if outErr != nil {
		finishError(http.StatusBadGateway, outErr)
		return
	}
	// Fail closed on malformed request streams even when the executor
	// reported success: a truncated or limit-violating stdin must never
	// present as a clean run.
	if scanResult != nil {
		finishError(http.StatusBadRequest, scanResult)
		return
	}
	ensureOK()
	line, _ := EncodeFrame(Frame{Type: TypeExit, Code: &code})
	_, _ = w.Write(line)
	if flusher != nil {
		flusher.Flush()
	}
}

// readFirstLine reads one newline-terminated line bounded by
// MaxMetaFrameBytes, returning the line and a reader for the remainder.
func readFirstLine(body io.Reader) ([]byte, io.Reader, error) {
	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	for buf.Len() <= MaxMetaFrameBytes {
		n, err := body.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			if idx := bytes.IndexByte(buf.Bytes(), '\n'); idx >= 0 {
				line := append([]byte(nil), buf.Bytes()[:idx+1]...)
				rest := io.MultiReader(bytes.NewReader(buf.Bytes()[idx+1:]), body)
				return line, rest, nil
			}
		}
		if err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("metadata frame exceeds %d byte limit", MaxMetaFrameBytes)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func trimNewline(line []byte) []byte {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}

// ServeOnSocket listens on a Unix socket created under umask 0077.
func ServeOnSocket(path string, handler http.Handler) (net.Listener, *http.Server, error) {
	return ServeOnSocketWithBase(path, handler, context.Background())
}

// ServeOnSocketWithBase listens like ServeOnSocket but derives every request
// context from base (via http.Server.BaseContext). The daemon passes its
// lifetime context here so SIGINT/SIGTERM cancellation propagates to active
// executions and the runner's killTree path runs before exit.
// See https://pkg.go.dev/net/http#Server.Shutdown (Shutdown alone does not
// interrupt active connections).
func ServeOnSocketWithBase(path string, handler http.Handler, base context.Context) (net.Listener, *http.Server, error) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	server := &http.Server{
		Handler: handler,
		BaseContext: func(net.Listener) context.Context {
			return base
		},
	}
	go server.Serve(listener)
	return listener, server, nil
}

// DialContext dials a Unix socket path for an http.Client transport.
func DialContext(socketPath string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, "unix", socketPath)
	}
}
