package easypprof

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// ErrFlightRecorderUnsupported is returned by New when FlightRecorder is
	// set but the binary was built with a Go version older than 1.25.
	ErrFlightRecorderUnsupported = errors.New("easypprof: flight recorder requires Go 1.25 or newer")

	// ErrFlightRecorderDisabled is returned by Snapshot methods when
	// Config.FlightRecorder was not set.
	ErrFlightRecorderDisabled = errors.New("easypprof: flight recorder is not enabled")

	// ErrFlightRecorderStopped is returned by Snapshot methods when the
	// flight recorder is configured but not running: before Start or Mount,
	// while the server is disabled, or after Shutdown.
	ErrFlightRecorderStopped = errors.New("easypprof: flight recorder is not running")

	// ErrSnapshotThrottled is returned by Snapshot when the previous snapshot
	// was taken less than FlightRecorderConfig.MinInterval ago.
	ErrSnapshotThrottled = errors.New("easypprof: snapshot throttled")

	// ErrNoSnapshotDir is returned by Snapshot when FlightRecorderConfig.Dir
	// is empty. Use SnapshotTo to write somewhere else.
	ErrNoSnapshotDir = errors.New("easypprof: FlightRecorderConfig.Dir is not set")
)

// FlightRecorderConfig configures the runtime/trace flight recorder. The
// recorder keeps the last few seconds of execution trace in memory so that,
// when something goes wrong (a latency spike, a timeout), you can write out
// what the scheduler, GC and goroutines were doing just before it.
type FlightRecorderConfig struct {
	// MinAge is how much recent trace history to keep. Defaults to 10s.
	MinAge time.Duration

	// MaxBytes caps the memory used by the buffer; it takes precedence over
	// MinAge. Defaults to 16 MiB.
	MaxBytes uint64

	// Dir is where Snapshot writes trace files. Created with mode 0700 if it
	// does not exist. Leave empty to use only SnapshotTo and the HTTP
	// endpoint.
	Dir string

	// MinInterval is the minimum time between two Snapshot calls that write
	// files. It makes Snapshot safe to call from a hot path. Defaults to 1m.
	MinInterval time.Duration
}

func (c FlightRecorderConfig) withDefaults() FlightRecorderConfig {
	if c.MinAge <= 0 {
		c.MinAge = 10 * time.Second
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 16 << 20
	}
	if c.MinInterval <= 0 {
		c.MinInterval = time.Minute
	}
	return c
}

type snapshotState struct {
	last atomic.Int64 // unix nanos of the last file snapshot
}

// Snapshot writes the flight recorder's buffer to a new file in
// FlightRecorderConfig.Dir and returns its path. reason ends up in the file
// name and the log, e.g. "p99-over-250ms".
//
// It is throttled by MinInterval and returns ErrSnapshotThrottled when called
// too often, so it is fine to call it every time a latency threshold trips:
//
//	if elapsed > 250*time.Millisecond {
//		go srv.Snapshot("slow-transfer")
//	}
func (s *Server) Snapshot(reason string) (string, error) {
	if s.fr == nil {
		return "", ErrFlightRecorderDisabled
	}
	// Checked before the throttle, so attempts while stopped don't use up the
	// MinInterval slot.
	if !s.fr.enabled() {
		return "", ErrFlightRecorderStopped
	}
	cfg := s.cfg.FlightRecorder
	if cfg.Dir == "" {
		return "", ErrNoSnapshotDir
	}

	now := time.Now()
	last := s.frState.last.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < cfg.MinInterval {
		return "", ErrSnapshotThrottled
	}
	if !s.frState.last.CompareAndSwap(last, now.UnixNano()) {
		return "", ErrSnapshotThrottled
	}

	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return "", fmt.Errorf("easypprof: create snapshot dir: %w", err)
	}
	name := fmt.Sprintf("trace-%s-%s.out", now.UTC().Format("20060102T150405.000Z"), sanitizeReason(reason))
	path := filepath.Join(cfg.Dir, name)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("easypprof: create snapshot: %w", err)
	}
	n, werr := s.fr.writeTo(f)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(path)
		return "", fmt.Errorf("easypprof: write snapshot: %w", errors.Join(werr, cerr))
	}

	s.log.Warn("flight recorder snapshot written", "path", path, "bytes", n, "reason", reason)
	return path, nil
}

// SnapshotTo writes the flight recorder's buffer to w, for example to upload
// it to object storage. It is not throttled.
func (s *Server) SnapshotTo(w io.Writer) (int64, error) {
	if s.fr == nil {
		return 0, ErrFlightRecorderDisabled
	}
	if !s.fr.enabled() {
		return 0, ErrFlightRecorderStopped
	}
	return s.fr.writeTo(w)
}

// serveFlightRecorder handles GET /debug/pprof/flightrecorder. The response is
// an execution trace readable with `go tool trace`.
func (s *Server) serveFlightRecorder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="flightrecorder.trace"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	cw := &countingWriter{w: w}
	if _, err := s.fr.writeTo(cw); err != nil && cw.n == 0 {
		w.Header().Del("Content-Disposition")
		http.Error(w, "flight recorder: "+err.Error(), http.StatusInternalServerError)
	}
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func sanitizeReason(reason string) string {
	var b strings.Builder
	for _, r := range reason {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "manual"
	}
	return b.String()
}
