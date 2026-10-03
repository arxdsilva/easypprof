package easypprof

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// buildHandler wires the pprof handlers onto a private mux and wraps them in
// the guard middleware. Nothing is registered on http.DefaultServeMux.
func (s *Server) buildHandler() http.Handler {
	mux := http.NewServeMux()
	// serveIndex serves the listing page and every named runtime profile
	// (heap, allocs, goroutine, block, mutex, threadcreate).
	mux.HandleFunc(PathPrefix, s.serveIndex)
	mux.HandleFunc(PathPrefix+"profile", serveCPUProfile)
	mux.HandleFunc(PathPrefix+"trace", serveTrace)
	if s.cfg.EnableCmdline {
		mux.HandleFunc(PathPrefix+"cmdline", serveCmdline)
	} else {
		mux.Handle(PathPrefix+"cmdline", http.NotFoundHandler())
	}
	if s.fr != nil {
		mux.HandleFunc(PathPrefix+"flightrecorder", s.serveFlightRecorder)
	}
	return s.guard(mux)
}

// guard runs the checks in order: method, network, authentication, request
// shape, concurrency. Every request, allowed or not, gets an audit log line.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		subject, reason := "", ""

		defer func() {
			level := s.log.Info
			if rec.status >= 400 {
				level = s.log.Warn
			}
			attrs := []any{
				"subject", subject,
				"remote", r.RemoteAddr,
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"status", rec.status,
				"bytes", rec.bytes,
				"duration", time.Since(start),
			}
			if reason != "" {
				attrs = append(attrs, "reason", reason)
			}
			level("pprof request", attrs...)
		}()

		deny := func(status int, msg string) {
			reason = msg
			http.Error(rec, msg, status)
		}

		if !methodAllowed(r) {
			rec.Header().Set("Allow", "GET, HEAD")
			deny(http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if len(s.allowed) > 0 && !s.remoteAllowed(r) {
			deny(http.StatusForbidden, "remote address not in allowlist")
			return
		}

		var ok bool
		subject, ok = s.authenticate(r)
		if !ok {
			rec.Header().Set("WWW-Authenticate", `Basic realm="easypprof"`)
			deny(http.StatusUnauthorized, "unauthorized")
			return
		}

		if msg := s.checkSeconds(r); msg != "" {
			deny(http.StatusBadRequest, msg)
			return
		}

		if s.cfg.DisableFullGoroutineDump && r.URL.Path == PathPrefix+"goroutine" && r.URL.Query().Get("debug") == "2" {
			deny(http.StatusForbidden, "goroutine?debug=2 is disabled")
			return
		}

		// The index page is cheap and doesn't count against the limit.
		if r.URL.Path != PathPrefix {
			select {
			case s.sem <- struct{}{}:
				defer func() { <-s.sem }()
			default:
				rec.Header().Set("Retry-After", "5")
				deny(http.StatusTooManyRequests, "too many concurrent profile requests")
				return
			}
		}

		next.ServeHTTP(rec, r)
	})
}

func methodAllowed(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

func (s *Server) remoteAllowed(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range s.allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// authenticate returns the caller identity. With no auth configured every
// caller is "anonymous"; New only permits that on loopback or with
// AllowUnauthenticated.
func (s *Server) authenticate(r *http.Request) (string, bool) {
	if s.cfg.Authorizer != nil {
		return s.cfg.Authorizer(r)
	}
	if len(s.tokens) == 0 {
		return "anonymous", true
	}

	if user, pass, ok := r.BasicAuth(); ok {
		if name, ok := s.matchToken(pass); ok && name == user {
			return name, true
		}
		return "", false
	}
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return s.matchToken(strings.TrimSpace(tok))
	}
	return "", false
}

// matchToken compares SHA-256 digests in constant time, so neither the token
// contents nor its length leak through timing. It checks every entry rather
// than stopping at the first match.
func (s *Server) matchToken(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	h := sha256.Sum256([]byte(tok))
	match := ""
	for _, e := range s.tokens {
		if subtle.ConstantTimeCompare(h[:], e.hash[:]) == 1 {
			match = e.name
		}
	}
	return match, match != ""
}

// checkSeconds enforces MaxProfileDuration on the endpoints that hold the
// request open: profile and trace.
func (s *Server) checkSeconds(r *http.Request) string {
	raw := r.URL.Query().Get("seconds")
	if raw == "" {
		// The CPU profile defaults to 30s when seconds is missing.
		if r.URL.Path == PathPrefix+"profile" && 30*time.Second > s.cfg.MaxProfileDuration {
			return "seconds is required (max " + s.cfg.MaxProfileDuration.String() + ")"
		}
		return ""
	}
	sec, err := strconv.ParseFloat(raw, 64)
	if err != nil || sec <= 0 {
		return "invalid seconds parameter"
	}
	if time.Duration(sec*float64(time.Second)) > s.cfg.MaxProfileDuration {
		return "seconds exceeds maximum of " + s.cfg.MaxProfileDuration.String()
	}
	return ""
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
