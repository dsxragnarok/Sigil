package unix

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

// Result is the outcome of one client execution.
type Result struct {
	ExitCode int
}

// Client executes commands through a Unix-socket broker.
type Client struct {
	HTTP       *http.Client
	URL        string
	StdinChunk int
}

// NewClient dials socketPath and POSTs to endpoint (e.g. /v1/exec).
func NewClient(socketPath, endpoint string) *Client {
	transport := &http.Transport{DialContext: DialContext(socketPath)}
	return &Client{HTTP: &http.Client{Transport: transport}, URL: "http://sigil" + endpoint, StdinChunk: 512 * 1024}
}

// Exec sends meta plus streamed stdin and renders stdout/stderr. It returns
// the target exit code from the single terminal exit frame. Broker failures
// (non-2xx or error frames) are returned as errors, distinct from target
// non-zero exits.
func (c *Client) Exec(ctx context.Context, meta Meta, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	metaLine, err := EncodeMeta(meta)
	if err != nil {
		return 0, err
	}
	bodyReader, bodyWriter := io.Pipe()
	go func() {
		_, werr := bodyWriter.Write(metaLine)
		if werr != nil {
			_ = bodyWriter.CloseWithError(werr)
			return
		}
		if stdin != nil {
			buf := make([]byte, c.StdinChunk)
			var total int64
			for {
				n, rerr := stdin.Read(buf)
				if n > 0 {
					total += int64(n)
					if total > MaxStdinBytes {
						_ = bodyWriter.CloseWithError(fmt.Errorf("stdin exceeds %d byte limit", MaxStdinBytes))
						return
					}
					line, eerr := EncodeFrame(EncodeData(TypeStdin, buf[:n]))
					if eerr != nil {
						_ = bodyWriter.CloseWithError(eerr)
						return
					}
					if _, werr := bodyWriter.Write(line); werr != nil {
						_ = bodyWriter.CloseWithError(werr)
						return
					}
				}
				if rerr != nil {
					break
				}
			}
		}
		eof, _ := EncodeFrame(Frame{Type: TypeStdinEOF})
		_, _ = bodyWriter.Write(eof)
		_ = bodyWriter.Close()
	}()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bodyReader)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/x-ndjson")
	request.Header.Set("Transfer-Encoding", "chunked")

	response, err := c.HTTP.Do(request)
	if err != nil {
		return 0, fmt.Errorf("sigil: broker unavailable: start sigild or configure SIGIL_ADMIN_SOCKET: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := firstErrorMessage(response.Body)
		if message == "" {
			message = response.Status
		}
		return 0, fmt.Errorf("sigil: broker error: %s", message)
	}

	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 64*1024), MaxStreamFrameBytes+1024)
	var total int64
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		frame, err := DecodeFrame(append([]byte(nil), line...))
		if err != nil {
			return 0, fmt.Errorf("sigil: broker error: %w", err)
		}
		switch frame.Type {
		case TypeStdout, TypeStderr:
			data, err := DecodeData(frame)
			if err != nil {
				return 0, fmt.Errorf("sigil: broker error: %w", err)
			}
			total += int64(len(data))
			if total > MaxOutputBytes {
				return 0, fmt.Errorf("sigil: broker error: stdout+stderr exceeds %d byte limit", MaxOutputBytes)
			}
			target := stdout
			if frame.Type == TypeStderr {
				target = stderr
			}
			if target != nil {
				if _, err := target.Write(data); err != nil {
					return 0, err
				}
			}
		case TypeExit:
			if frame.Code == nil {
				return 0, fmt.Errorf("sigil: broker error: exit frame missing code")
			}
			return *frame.Code, nil
		case TypeError:
			return 0, fmt.Errorf("sigil: broker error: %s", frame.Message)
		default:
			return 0, fmt.Errorf("sigil: broker error: unexpected response frame %q", frame.Type)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("sigil: broker error: %w", err)
	}
	return 0, fmt.Errorf("sigil: broker error: stream ended without exit frame")
}

func firstErrorMessage(body io.Reader) string {
	limited, _ := io.ReadAll(io.LimitReader(body, 8*1024))
	line := bytes.TrimSpace(limited)
	if len(line) == 0 {
		return ""
	}
	if frame, err := DecodeFrame(line); err == nil && frame.Message != "" {
		return frame.Message
	}
	return string(limited)
}
