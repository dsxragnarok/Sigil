// Package unix implements chunked NDJSON execution transport over
// HTTP on Unix-domain sockets. Binary stream bytes are base64 encoded in
// newline-delimited JSON frames. Limits are broker policy constants, not
// client-controlled knobs.
package unix

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// MaxCommandArgs caps the number of command arguments per execution.
	MaxCommandArgs = 256
	// MaxAggregateArgBytes caps total command argument bytes.
	MaxAggregateArgBytes = 64 * 1024
	// MaxMetaFrameBytes caps a single metadata frame.
	MaxMetaFrameBytes = 64 * 1024
	// MaxStreamFrameBytes caps a single stream frame line.
	MaxStreamFrameBytes = 1 * 1024 * 1024
	// MaxStdinBytes caps stdin per execution.
	MaxStdinBytes = 64 * 1024 * 1024
	// MaxOutputBytes caps combined stdout+stderr per execution.
	MaxOutputBytes = 64 * 1024 * 1024
	// DefaultExecTimeout is the default per-execution timeout.
	DefaultExecTimeout = 120 * time.Second
	// MaxExecTimeout caps client-requested timeouts. The timeout is broker
	// policy: callers may shorten it but never extend it past this bound.
	MaxExecTimeout = 3600 * time.Second
	// TermGracePeriod is SIGTERM->SIGKILL grace for the child process group.
	TermGracePeriod = 5 * time.Second
)

// Frame types on the wire.
const (
	TypeMeta     = "meta"
	TypeStdin    = "stdin"
	TypeStdinEOF = "stdin_eof"
	TypeStdout   = "stdout"
	TypeStderr   = "stderr"
	TypeExit     = "exit"
	TypeError    = "error"
)

// Meta is the first request frame. Role is admin-socket only (M1 trusted
// compatibility path); agent sessions arrive in M2.
type Meta struct {
	Type           string   `json:"type"`
	Role           string   `json:"role,omitempty"`
	Repository     string   `json:"repository,omitempty"`
	InstallationID int64    `json:"installation_id,omitempty"`
	WorkingDir     string   `json:"working_dir,omitempty"`
	Command        []string `json:"command,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// Frame is a generic stream frame with base64 payload.
type Frame struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Code *int   `json:"code,omitempty"`
	// Message carries transport/broker errors. Never credentials.
	Message string `json:"message,omitempty"`
}

// EncodeFrame marshals one NDJSON line.
func EncodeFrame(frame Frame) ([]byte, error) {
	line, err := json.Marshal(frame)
	if err != nil {
		return nil, fmt.Errorf("encode frame: %w", err)
	}
	return append(line, '\n'), nil
}

// EncodeMeta marshals a meta frame, enforcing the metadata size bound.
func EncodeMeta(meta Meta) ([]byte, error) {
	meta.Type = TypeMeta
	line, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("encode meta: %w", err)
	}
	if len(line) > MaxMetaFrameBytes {
		return nil, fmt.Errorf("metadata frame %d bytes exceeds %d byte limit", len(line), MaxMetaFrameBytes)
	}
	return append(line, '\n'), nil
}

// DecodeFrame parses one NDJSON line, enforcing the per-frame size bound.
func DecodeFrame(line []byte) (Frame, error) {
	if len(line) > MaxStreamFrameBytes {
		return Frame{}, fmt.Errorf("stream frame %d bytes exceeds %d byte limit", len(line), MaxStreamFrameBytes)
	}
	var frame Frame
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		return Frame{}, fmt.Errorf("decode frame: %w", err)
	}
	return frame, nil
}

// DecodeMeta parses and validates a metadata frame.
func DecodeMeta(line []byte) (Meta, error) {
	if len(line) > MaxMetaFrameBytes {
		return Meta{}, fmt.Errorf("metadata frame %d bytes exceeds %d byte limit", len(line), MaxMetaFrameBytes)
	}
	var meta Meta
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&meta); err != nil {
		return Meta{}, fmt.Errorf("decode meta: %w", err)
	}
	if meta.Type != TypeMeta {
		return Meta{}, fmt.Errorf("first frame must be meta, got %q", meta.Type)
	}
	if err := ValidateCommand(meta.Command); err != nil {
		return Meta{}, err
	}
	return meta, nil
}

// ValidateCommand enforces argument count and aggregate byte bounds.
func ValidateCommand(command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("missing command")
	}
	if len(command) > MaxCommandArgs {
		return fmt.Errorf("command has %d arguments, limit is %d", len(command), MaxCommandArgs)
	}
	total := 0
	for _, arg := range command {
		total += len(arg)
	}
	if total > MaxAggregateArgBytes {
		return fmt.Errorf("command arguments total %d bytes, limit is %d", total, MaxAggregateArgBytes)
	}
	return nil
}

// EncodeData builds a base64 stream frame.
func EncodeData(frameType string, data []byte) Frame {
	return Frame{Type: frameType, Data: base64.StdEncoding.EncodeToString(data)}
}

// DecodeData decodes a base64 stream frame payload.
func DecodeData(frame Frame) ([]byte, error) {
	if frame.Data == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(frame.Data)
	if err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", frame.Type, err)
	}
	return data, nil
}

// TimeoutFor resolves the effective execution timeout: non-positive means
// the default, and client requests are clamped to the broker maximum.
func TimeoutFor(seconds int) time.Duration {
	if seconds <= 0 {
		return DefaultExecTimeout
	}
	timeout := time.Duration(seconds) * time.Second
	if timeout > MaxExecTimeout {
		return MaxExecTimeout
	}
	return timeout
}
