//go:build go1.25

package easypprof

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFlightRecorder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "traces")
	s := newTestServer(t, Config{
		Addr:           "127.0.0.1:0",
		FlightRecorder: &FlightRecorderConfig{Dir: dir, MinInterval: time.Hour},
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Shutdown(context.Background())

	// Generate a little activity for the trace.
	for i := 0; i < 100; i++ {
		go func() { time.Sleep(time.Millisecond) }()
	}
	time.Sleep(50 * time.Millisecond)

	path, err := s.Snapshot("p99 over 250ms")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !strings.HasSuffix(path, "-p99_over_250ms.out") {
		t.Errorf("unexpected snapshot name %q", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("empty snapshot")
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("snapshot mode = %o, want 600", perm)
	}

	if _, err := s.Snapshot("again"); !errors.Is(err, ErrSnapshotThrottled) {
		t.Fatalf("second Snapshot err = %v, want ErrSnapshotThrottled", err)
	}

	var buf bytes.Buffer
	if n, err := s.SnapshotTo(&buf); err != nil || n == 0 {
		t.Fatalf("SnapshotTo = %d, %v", n, err)
	}

	resp, err := http.Get("http://" + s.Addr() + PathPrefix + "flightrecorder")
	if err != nil {
		t.Fatalf("GET flightrecorder: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("flightrecorder status = %d", resp.StatusCode)
	}
}
