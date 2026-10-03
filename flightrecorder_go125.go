//go:build go1.25

package easypprof

import (
	"io"
	"runtime/trace"
	"sync"
)

const flightRecorderSupported = true

type flightRecorder struct {
	mu sync.Mutex // trace.FlightRecorder.WriteTo must not run concurrently
	fr *trace.FlightRecorder
}

func newFlightRecorder(cfg FlightRecorderConfig) *flightRecorder {
	return &flightRecorder{
		fr: trace.NewFlightRecorder(trace.FlightRecorderConfig{
			MinAge:   cfg.MinAge,
			MaxBytes: cfg.MaxBytes,
		}),
	}
}

func (f *flightRecorder) start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fr.Start()
}

func (f *flightRecorder) enabled() bool { return f.fr.Enabled() }

func (f *flightRecorder) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fr.Enabled() {
		f.fr.Stop()
	}
}

func (f *flightRecorder) writeTo(w io.Writer) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fr.WriteTo(w)
}
