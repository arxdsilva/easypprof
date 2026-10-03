package easypprof

import (
	"errors"
	"net/http"
	"testing"
)

func TestSnapshotWithoutFlightRecorder(t *testing.T) {
	s := newTestServer(t, Config{})
	if _, err := s.Snapshot("x"); !errors.Is(err, ErrFlightRecorderDisabled) {
		t.Fatalf("Snapshot err = %v, want ErrFlightRecorderDisabled", err)
	}
	if _, err := s.SnapshotTo(nil); !errors.Is(err, ErrFlightRecorderDisabled) {
		t.Fatalf("SnapshotTo err = %v, want ErrFlightRecorderDisabled", err)
	}
	if rec := do(s, http.MethodGet, PathPrefix+"flightrecorder", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("flightrecorder endpoint status = %d, want 404", rec.Code)
	}
}
