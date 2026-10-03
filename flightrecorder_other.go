//go:build !go1.25

package easypprof

import "io"

const flightRecorderSupported = false

// flightRecorder is a stub on Go versions without runtime/trace.FlightRecorder.
// New refuses to create one, so these methods are never reached.
type flightRecorder struct{}

func newFlightRecorder(FlightRecorderConfig) *flightRecorder { return &flightRecorder{} }
func (*flightRecorder) start() error                         { return ErrFlightRecorderUnsupported }
func (*flightRecorder) stop()                                {}
func (*flightRecorder) writeTo(io.Writer) (int64, error)     { return 0, ErrFlightRecorderUnsupported }
