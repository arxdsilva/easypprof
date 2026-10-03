// Package easypprof exposes Go's pprof endpoints in a way that is safe to run
// against a production service.
//
// The usual one-liner, import _ "net/http/pprof", registers the profiling
// handlers on http.DefaultServeMux. If anything in the process serves that mux
// on a public port, the endpoints are public too: they leak internals and
// /debug/pprof/profile?seconds=600 is a cheap denial of service. easypprof
// instead:
//
//   - serves pprof on its own listener and mux (127.0.0.1:6060 by default),
//     never on http.DefaultServeMux;
//   - refuses to bind a non-loopback address without authentication;
//   - authenticates callers with named tokens (Bearer or Basic) or a custom
//     Authorizer, and can additionally restrict callers to CIDR ranges;
//   - caps the duration of every ?seconds= profile and limits concurrent pulls;
//   - writes an audit log entry (who, what, when, result) for every request;
//   - hides /debug/pprof/cmdline by default, because command lines often carry
//     DSNs and other secrets;
//   - turns on sampled block and mutex profiling, which are off by default in
//     the Go runtime and are the profiles that show lock and I/O contention;
//   - on Go 1.25+, runs a runtime/trace flight recorder you can snapshot when
//     something goes wrong.
//
// Typical use, on a dedicated listener:
//
//	srv, err := easypprof.New(easypprof.Config{
//		Tokens: map[string]string{"oncall": os.Getenv("PPROF_TOKEN")},
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	if err := srv.Start(); err != nil {
//		log.Fatal(err)
//	}
//	defer srv.Shutdown(context.Background())
//
// Or embedded in an existing server's mux, with no extra port. This mode
// always requires Tokens or Authorizer:
//
//	if err := srv.Mount(mux); err != nil {
//		log.Fatal(err)
//	}
//	defer srv.Shutdown(context.Background())
package easypprof

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults applied by New when the corresponding Config field is zero.
const (
	DefaultAddr                 = "127.0.0.1:6060"
	DefaultMaxProfileDuration   = 60 * time.Second
	DefaultMaxConcurrent        = 2
	DefaultBlockProfileRate     = 10_000 // sample blocking events of ~10µs and longer
	DefaultMutexProfileFraction = 100    // sample ~1% of mutex contention events
)

// PathPrefix is where the pprof endpoints are served.
const PathPrefix = "/debug/pprof/"

// minTokenLength guards against weak or accidentally empty tokens, such as an
// unset environment variable.
const minTokenLength = 16

// Config configures a Server. The zero value is valid and gives a server on
// 127.0.0.1:6060 with no authentication, which is reachable only from the same
// host or network namespace (for example through kubectl port-forward).
type Config struct {
	// Addr is the TCP address to listen on. Defaults to DefaultAddr.
	//
	// Binding to anything other than a loopback address requires Tokens or
	// Authorizer, unless AllowUnauthenticated is set. Network position is not
	// authentication.
	Addr string

	// Tokens maps a caller name to a secret token. The name is recorded in the
	// audit log. Callers authenticate with either
	//
	//	Authorization: Bearer <token>
	//
	// or HTTP Basic auth with the name as the user and the token as the
	// password. Every token must be at least 16 characters long.
	Tokens map[string]string

	// Authorizer, if set, is used instead of Tokens. It returns the identity
	// of the caller for the audit log and whether the request is allowed. Use
	// it to plug in mTLS client certificates, OIDC, or a service mesh header.
	Authorizer func(r *http.Request) (subject string, ok bool)

	// AllowedCIDRs, if non-empty, restricts callers to these networks, based
	// on the connection's remote address. X-Forwarded-For is never trusted.
	AllowedCIDRs []string

	// AllowUnauthenticated permits listening on a non-loopback address with no
	// Tokens or Authorizer. Only set it when something in front of the server
	// already authenticates callers.
	AllowUnauthenticated bool

	// MaxProfileDuration caps the ?seconds= parameter accepted by profile,
	// trace and delta profile endpoints. Defaults to DefaultMaxProfileDuration.
	MaxProfileDuration time.Duration

	// MaxConcurrent limits how many profile requests run at once. Extra
	// requests get 429 Too Many Requests. Defaults to DefaultMaxConcurrent.
	MaxConcurrent int

	// BlockProfileRate is passed to runtime.SetBlockProfileRate on Start.
	// 0 means DefaultBlockProfileRate; a negative value leaves block
	// profiling off.
	BlockProfileRate int

	// MutexProfileFraction is passed to runtime.SetMutexProfileFraction on
	// Start. 0 means DefaultMutexProfileFraction; a negative value leaves
	// mutex profiling off.
	MutexProfileFraction int

	// EnableCmdline serves /debug/pprof/cmdline. It is off by default because
	// process arguments frequently contain secrets.
	EnableCmdline bool

	// DisableFullGoroutineDump rejects /debug/pprof/goroutine?debug=2. That
	// dump stops the world for its whole duration, which can be long in a
	// process with many goroutines.
	DisableFullGoroutineDump bool

	// FlightRecorder enables the runtime/trace flight recorder (Go 1.25+).
	// On older Go versions New returns ErrFlightRecorderUnsupported.
	FlightRecorder *FlightRecorderConfig

	// Logger receives audit and lifecycle logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Server is a hardened pprof debug server. Create it with New, then call Start
// and, on the way out, Shutdown.
type Server struct {
	cfg     Config
	log     *slog.Logger
	handler http.Handler
	tokens  []tokenEntry
	allowed []netip.Prefix
	sem     chan struct{}

	fr      *flightRecorder
	frState snapshotState

	// stopped makes the handler answer 503 after Shutdown, since a route
	// mounted on someone else's mux can't be removed.
	stopped atomic.Bool

	mu        sync.Mutex
	active    bool
	srv       *http.Server
	ln        net.Listener
	prevMutex int
	setBlock  bool
	setMutex  bool
}

type tokenEntry struct {
	name string
	hash [sha256.Size]byte
}

// New validates cfg and builds a Server. It does not touch the runtime or open
// a socket; Start does that.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	if cfg.MaxProfileDuration <= 0 {
		cfg.MaxProfileDuration = DefaultMaxProfileDuration
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = DefaultMaxConcurrent
	}
	if cfg.BlockProfileRate == 0 {
		cfg.BlockProfileRate = DefaultBlockProfileRate
	}
	if cfg.MutexProfileFraction == 0 {
		cfg.MutexProfileFraction = DefaultMutexProfileFraction
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	s := &Server{
		cfg: cfg,
		log: cfg.Logger.With("component", "easypprof"),
		sem: make(chan struct{}, cfg.MaxConcurrent),
	}

	for name, tok := range cfg.Tokens {
		if name == "" {
			return nil, errors.New("easypprof: token name must not be empty")
		}
		if len(tok) < minTokenLength {
			return nil, fmt.Errorf("easypprof: token %q is shorter than %d characters (is the environment variable set?)", name, minTokenLength)
		}
		s.tokens = append(s.tokens, tokenEntry{name: name, hash: sha256.Sum256([]byte(tok))})
	}

	for _, c := range cfg.AllowedCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("easypprof: invalid CIDR %q: %w", c, err)
		}
		s.allowed = append(s.allowed, p.Masked())
	}

	hasAuth := len(s.tokens) > 0 || cfg.Authorizer != nil
	loopback, err := isLoopbackAddr(cfg.Addr)
	if err != nil {
		return nil, err
	}
	if !loopback && !hasAuth && !cfg.AllowUnauthenticated {
		return nil, fmt.Errorf("easypprof: refusing to listen on non-loopback address %q without Tokens or Authorizer (set AllowUnauthenticated to override)", cfg.Addr)
	}

	if cfg.FlightRecorder != nil {
		if !flightRecorderSupported {
			return nil, ErrFlightRecorderUnsupported
		}
		frc := cfg.FlightRecorder.withDefaults()
		s.cfg.FlightRecorder = &frc
		s.fr = newFlightRecorder(frc)
	}

	s.handler = s.buildHandler()
	return s, nil
}

// Start applies the block and mutex profiling rates, starts the flight
// recorder if configured, binds the listener and serves in the background.
// Bind errors are returned synchronously.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return errors.New("easypprof: server already started")
	}

	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("easypprof: listen %s: %w", s.cfg.Addr, err)
	}

	if err := s.activateLocked(); err != nil {
		ln.Close()
		return err
	}

	s.ln = ln
	s.srv = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// pprof refuses profiles longer than the server's WriteTimeout, so
		// leave headroom above the longest profile we allow.
		WriteTimeout:   s.cfg.MaxProfileDuration + 30*time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 8 << 10,
		ErrorLog:       slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}

	srv := s.srv
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("debug server stopped", "err", err)
		}
	}()

	s.log.Info("debug server listening",
		"addr", ln.Addr().String(),
		"auth", s.authMode(),
		"block_profile_rate", s.cfg.BlockProfileRate,
		"mutex_profile_fraction", s.cfg.MutexProfileFraction,
		"flight_recorder", s.fr != nil,
	)
	return nil
}

// Handler applies the runtime settings Start would (block and mutex rates,
// flight recorder) and returns the guarded pprof handler, for serving on an
// existing server instead of a dedicated listener. Serve it at PathPrefix; with
// a ServeMux, use Mount.
//
// The host server's address is unknown here, so Handler requires Tokens or
// Authorizer unless AllowUnauthenticated is set. Call Shutdown on the way out
// to restore the runtime; the handler then answers 503 Service Unavailable.
func (s *Server) Handler() (http.Handler, error) {
	if len(s.tokens) == 0 && s.cfg.Authorizer == nil && !s.cfg.AllowUnauthenticated {
		return nil, errors.New("easypprof: refusing to mount on a shared server without Tokens or Authorizer (set AllowUnauthenticated to override)")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return nil, errors.New("easypprof: server already started")
	}
	if err := s.activateLocked(); err != nil {
		return nil, err
	}

	s.log.Info("debug handler mounted",
		"path", PathPrefix,
		"auth", s.authMode(),
		"block_profile_rate", s.cfg.BlockProfileRate,
		"mutex_profile_fraction", s.cfg.MutexProfileFraction,
		"flight_recorder", s.fr != nil,
	)
	return s.handler, nil
}

// Mount registers the pprof endpoints on mux at PathPrefix. See Handler.
func (s *Server) Mount(mux *http.ServeMux) error {
	h, err := s.Handler()
	if err != nil {
		return err
	}
	mux.Handle(PathPrefix, h)
	return nil
}

// activateLocked starts the flight recorder and sets the runtime profiling
// rates. s.mu must be held.
func (s *Server) activateLocked() error {
	if s.fr != nil {
		if err := s.fr.start(); err != nil {
			return fmt.Errorf("easypprof: start flight recorder: %w", err)
		}
	}
	if s.cfg.BlockProfileRate > 0 {
		runtime.SetBlockProfileRate(s.cfg.BlockProfileRate)
		s.setBlock = true
	}
	if s.cfg.MutexProfileFraction > 0 {
		s.prevMutex = runtime.SetMutexProfileFraction(s.cfg.MutexProfileFraction)
		s.setMutex = true
	}
	s.active = true
	s.stopped.Store(false)
	return nil
}

// deactivateLocked undoes activateLocked. s.mu must be held.
func (s *Server) deactivateLocked() {
	if s.fr != nil {
		s.fr.stop()
	}
	if s.setBlock {
		runtime.SetBlockProfileRate(0)
		s.setBlock = false
	}
	if s.setMutex {
		runtime.SetMutexProfileFraction(s.prevMutex)
		s.setMutex = false
	}
	s.active = false
}

// Addr returns the address the server is listening on, or "" before Start.
// Useful when Config.Addr uses port 0.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Shutdown stops the server, waiting for in-flight profiles until ctx is done,
// then stops the flight recorder and restores the runtime profiling rates. In
// mounted mode there is no listener to stop; the handler starts answering 503.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return nil
	}
	srv := s.srv
	s.srv, s.ln = nil, nil
	s.mu.Unlock()
	s.stopped.Store(true)

	var err error
	if srv != nil {
		if err = srv.Shutdown(ctx); err != nil {
			srv.Close()
		}
	}

	s.mu.Lock()
	s.deactivateLocked()
	s.mu.Unlock()

	s.log.Info("debug server stopped")
	return err
}

func (s *Server) authMode() string {
	switch {
	case s.cfg.Authorizer != nil:
		return "authorizer"
	case len(s.tokens) > 0:
		return "tokens"
	default:
		return "none"
	}
}

func isLoopbackAddr(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("easypprof: invalid Addr %q: %w", addr, err)
	}
	if host == "localhost" {
		return true, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// An empty host or a hostname: we can't prove it's loopback.
		return false, nil
	}
	return ip.IsLoopback(), nil
}
