//go:build !go1.25

package easypprof

import (
	"errors"
	"testing"
)

func TestFlightRecorderUnsupported(t *testing.T) {
	_, err := New(Config{Logger: quietLogger(), FlightRecorder: &FlightRecorderConfig{}})
	if !errors.Is(err, ErrFlightRecorderUnsupported) {
		t.Fatalf("New err = %v, want ErrFlightRecorderUnsupported", err)
	}
}
