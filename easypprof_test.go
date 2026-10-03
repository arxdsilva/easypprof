package easypprof

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

const testToken = "0123456789abcdef-test-token"

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = quietLogger()
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func do(s *Server, method, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "127.0.0.1:50000"
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func bearer(tok string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"zero value is valid", Config{}, ""},
		{"loopback v6", Config{Addr: "[::1]:6060"}, ""},
		{"localhost", Config{Addr: "localhost:6060"}, ""},
		{"all interfaces without auth", Config{Addr: ":6060"}, "refusing to listen"},
		{"pod ip without auth", Config{Addr: "10.1.2.3:6060"}, "refusing to listen"},
		{"cidr is not auth", Config{Addr: "0.0.0.0:6060", AllowedCIDRs: []string{"10.0.0.0/8"}}, "refusing to listen"},
		{"non-loopback with tokens", Config{Addr: ":6060", Tokens: map[string]string{"oncall": testToken}}, ""},
		{"non-loopback with authorizer", Config{Addr: ":6060", Authorizer: func(*http.Request) (string, bool) { return "x", true }}, ""},
		{"explicit opt out", Config{Addr: ":6060", AllowUnauthenticated: true}, ""},
		{"empty token from unset env var", Config{Tokens: map[string]string{"oncall": ""}}, "shorter than"},
		{"short token", Config{Tokens: map[string]string{"oncall": "hunter2"}}, "shorter than"},
		{"empty token name", Config{Tokens: map[string]string{"": testToken}}, "name must not be empty"},
		{"bad cidr", Config{AllowedCIDRs: []string{"10.0.0.0/33"}}, "invalid CIDR"},
		{"bad addr", Config{Addr: "nope"}, "invalid Addr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.Logger = quietLogger()
			_, err := New(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuthentication(t *testing.T) {
	s := newTestServer(t, Config{Tokens: map[string]string{"oncall": testToken, "ci": testToken + "-ci"}})

	tests := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"no credentials", nil, http.StatusUnauthorized},
		{"wrong bearer", bearer("not-the-token-at-all"), http.StatusUnauthorized},
		{"empty bearer", bearer(""), http.StatusUnauthorized},
		{"valid bearer", bearer(testToken), http.StatusOK},
		{"second token", bearer(testToken + "-ci"), http.StatusOK},
		{"valid basic", func(r *http.Request) { r.SetBasicAuth("oncall", testToken) }, http.StatusOK},
		{"basic with wrong user", func(r *http.Request) { r.SetBasicAuth("ci", testToken) }, http.StatusUnauthorized},
		{"token in query is ignored", func(r *http.Request) { r.URL.RawQuery = "token=" + testToken }, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(s, http.MethodGet, PathPrefix, tt.mutate)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tt.want, rec.Body.String())
			}
			if rec.Code == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("401 without WWW-Authenticate header")
			}
		})
	}
}

func TestAuthorizer(t *testing.T) {
	s := newTestServer(t, Config{
		Tokens: map[string]string{"oncall": testToken}, // ignored when Authorizer is set
		Authorizer: func(r *http.Request) (string, bool) {
			return "mesh", r.Header.Get("X-Mesh-Identity") == "sre"
		},
	})
	if rec := do(s, http.MethodGet, PathPrefix, bearer(testToken)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token accepted although Authorizer is set: %d", rec.Code)
	}
	rec := do(s, http.MethodGet, PathPrefix, func(r *http.Request) { r.Header.Set("X-Mesh-Identity", "sre") })
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAllowedCIDRs(t *testing.T) {
	s := newTestServer(t, Config{AllowedCIDRs: []string{"10.0.0.0/8", "fd00::/8"}})

	for remote, want := range map[string]int{
		"10.4.5.6:1234":          http.StatusOK,
		"[::ffff:10.4.5.6]:1234": http.StatusOK, // IPv4-mapped IPv6
		"[fd00::1]:1234":         http.StatusOK,
		"192.168.1.1:1234":       http.StatusForbidden,
		"garbage":                http.StatusForbidden,
	} {
		rec := do(s, http.MethodGet, PathPrefix, func(r *http.Request) {
			r.RemoteAddr = remote
			r.Header.Set("X-Forwarded-For", "10.0.0.1") // must not be trusted
		})
		if rec.Code != want {
			t.Errorf("remote %s: status = %d, want %d", remote, rec.Code, want)
		}
	}
}

func TestMaxProfileDuration(t *testing.T) {
	s := newTestServer(t, Config{MaxProfileDuration: 10 * time.Second})

	tests := []struct {
		target string
		want   int
	}{
		{PathPrefix + "profile?seconds=600", http.StatusBadRequest},
		{PathPrefix + "profile", http.StatusBadRequest}, // implicit 30s > 10s
		{PathPrefix + "trace?seconds=11", http.StatusBadRequest},
		{PathPrefix + "trace?seconds=abc", http.StatusBadRequest},
		{PathPrefix + "trace?seconds=-1", http.StatusBadRequest},
		{PathPrefix + "heap?seconds=60", http.StatusBadRequest}, // over the cap
		{PathPrefix + "heap?seconds=5", http.StatusBadRequest},  // delta profiles unsupported
		{PathPrefix + "nope", http.StatusNotFound},
		{PathPrefix + "heap", http.StatusOK},
		{PathPrefix + "trace?seconds=0.1", http.StatusOK},
	}
	for _, tt := range tests {
		rec := do(s, http.MethodGet, tt.target, nil)
		if rec.Code != tt.want {
			t.Errorf("%s: status = %d, want %d (%s)", tt.target, rec.Code, tt.want, strings.TrimSpace(rec.Body.String()))
		}
	}
}

func TestCPUProfileAndTrace(t *testing.T) {
	s := newTestServer(t, Config{})
	rec := do(s, http.MethodGet, PathPrefix+"profile?seconds=0.2", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("profile status = %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := gzip.NewReader(rec.Body); err != nil {
		t.Fatalf("CPU profile is not gzip: %v", err)
	}
	rec = do(s, http.MethodGet, PathPrefix+"trace?seconds=0.1", nil)
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("trace status = %d, %d bytes", rec.Code, rec.Body.Len())
	}
	rec = do(s, http.MethodGet, PathPrefix+"goroutine?debug=1", nil)
	if !strings.Contains(rec.Body.String(), "goroutine profile:") {
		t.Fatalf("unexpected goroutine text profile: %.200s", rec.Body.String())
	}
	rec = do(s, http.MethodGet, PathPrefix, nil)
	for _, want := range []string{"heap", "mutex", "profile", "trace"} {
		if !strings.Contains(rec.Body.String(), ">"+want+"<") {
			t.Errorf("index missing %q", want)
		}
	}
	if strings.Contains(rec.Body.String(), "cmdline") {
		t.Error("index lists cmdline although it is disabled")
	}
}

func TestCmdline(t *testing.T) {
	s := newTestServer(t, Config{})
	if rec := do(s, http.MethodGet, PathPrefix+"cmdline", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cmdline served by default: %d", rec.Code)
	}
	s = newTestServer(t, Config{EnableCmdline: true})
	if rec := do(s, http.MethodGet, PathPrefix+"cmdline", nil); rec.Code != http.StatusOK {
		t.Fatalf("cmdline not served when enabled: %d", rec.Code)
	}
}

func TestFullGoroutineDump(t *testing.T) {
	s := newTestServer(t, Config{DisableFullGoroutineDump: true})
	if rec := do(s, http.MethodGet, PathPrefix+"goroutine?debug=2", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("debug=2 status = %d, want 403", rec.Code)
	}
	if rec := do(s, http.MethodGet, PathPrefix+"goroutine?debug=1", nil); rec.Code != http.StatusOK {
		t.Fatalf("debug=1 status = %d, want 200", rec.Code)
	}
}

func TestMethods(t *testing.T) {
	s := newTestServer(t, Config{})
	if rec := do(s, http.MethodPost, PathPrefix+"heap", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST heap status = %d, want 405", rec.Code)
	}
	if rec := do(s, http.MethodDelete, PathPrefix, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE status = %d, want 405", rec.Code)
	}
	if rec := do(s, http.MethodPost, PathPrefix+"symbol", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST symbol status = %d, want 405", rec.Code)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	s := newTestServer(t, Config{MaxConcurrent: 1})
	s.sem <- struct{}{} // simulate a profile already in flight

	rec := do(s, http.MethodGet, PathPrefix+"heap", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	// The index page stays available.
	if rec := do(s, http.MethodGet, PathPrefix, nil); rec.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", rec.Code)
	}

	<-s.sem
	if rec := do(s, http.MethodGet, PathPrefix+"heap", nil); rec.Code != http.StatusOK {
		t.Fatalf("status after release = %d, want 200", rec.Code)
	}
}

func TestAuditLog(t *testing.T) {
	var buf bytes.Buffer
	s := newTestServer(t, Config{
		Tokens: map[string]string{"oncall": testToken},
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	do(s, http.MethodGet, PathPrefix+"heap?gc=1", bearer(testToken))
	do(s, http.MethodGet, PathPrefix+"heap", bearer("wrong-token-wrong-token"))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2:\n%s", len(lines), buf.String())
	}
	var ok, denied map[string]any
	json.Unmarshal([]byte(lines[0]), &ok)
	json.Unmarshal([]byte(lines[1]), &denied)

	if ok["subject"] != "oncall" || ok["status"] != float64(200) || ok["query"] != "gc=1" || ok["level"] != "INFO" {
		t.Errorf("unexpected success entry: %v", ok)
	}
	if denied["status"] != float64(401) || denied["reason"] != "unauthorized" || denied["level"] != "WARN" {
		t.Errorf("unexpected denial entry: %v", denied)
	}
	if strings.Contains(buf.String(), testToken) {
		t.Error("token leaked into the audit log")
	}
}

func TestStartShutdown(t *testing.T) {
	prevMutex := runtime.SetMutexProfileFraction(-1)

	s := newTestServer(t, Config{
		Addr:   "127.0.0.1:0",
		Tokens: map[string]string{"oncall": testToken},
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Start(); err == nil {
		t.Fatal("second Start succeeded")
	}
	if got := runtime.SetMutexProfileFraction(-1); got != DefaultMutexProfileFraction {
		t.Fatalf("mutex fraction = %d, want %d", got, DefaultMutexProfileFraction)
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+s.Addr()+PathPrefix+"heap", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET heap: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("heap profile is not gzip: %v", err)
	}
	if b, _ := io.ReadAll(zr); len(b) == 0 {
		t.Fatal("empty heap profile")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := runtime.SetMutexProfileFraction(prevMutex); got != prevMutex {
		t.Fatalf("mutex fraction not restored: got %d, want %d", got, prevMutex)
	}
	if s.Addr() != "" {
		t.Fatal("Addr non-empty after Shutdown")
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

func TestNotOnDefaultServeMux(t *testing.T) {
	newTestServer(t, Config{})
	rec := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathPrefix, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("pprof reachable on http.DefaultServeMux: %d", rec.Code)
	}
}

func TestLabels(t *testing.T) {
	Do(context.Background(), func(ctx context.Context) {
		if v, _ := pprof.Label(ctx, "op"); v != "post_entry" {
			t.Errorf("op label = %q", v)
		}
	}, "op", "post_entry")

	h := Label("transfer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, _ := pprof.Label(r.Context(), "handler"); v != "transfer" {
			t.Errorf("handler label = %q", v)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestSanitizeReason(t *testing.T) {
	for in, want := range map[string]string{
		"p99-over-250ms":   "p99-over-250ms",
		"../../etc/passwd": "______etc_passwd",
		"":                 "manual",
		"a b":              "a_b",
	} {
		if got := sanitizeReason(in); got != want {
			t.Errorf("sanitizeReason(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeReason(strings.Repeat("x", 500)); len(got) != 64 {
		t.Errorf("long reason not truncated: len %d", len(got))
	}
}

func TestMountRequiresAuth(t *testing.T) {
	s := newTestServer(t, Config{})
	if err := s.Mount(http.NewServeMux()); err == nil {
		t.Fatal("Mount without auth succeeded")
	}
	if _, err := s.Handler(); err == nil {
		t.Fatal("Handler without auth succeeded")
	}

	s = newTestServer(t, Config{AllowUnauthenticated: true})
	if err := s.Mount(http.NewServeMux()); err != nil {
		t.Fatalf("Mount with AllowUnauthenticated: %v", err)
	}
	s.Shutdown(context.Background())
}

func TestMount(t *testing.T) {
	var buf bytes.Buffer
	s := newTestServer(t, Config{
		Tokens: map[string]string{"oncall": testToken},
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hello", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hi") })
	if err := s.Mount(mux); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	ts := httptest.NewServer(mux)
	defer ts.Close()

	get := func(path, tok string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	// The host's own routes are untouched by the mount.
	if resp := get("/api/hello", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("app route status = %d", resp.StatusCode)
	}
	// The guard still applies on the shared mux: no token, no profile.
	if resp := get(PathPrefix+"heap", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("heap without token status = %d, want 401", resp.StatusCode)
	}
	if resp := get(PathPrefix+"heap", testToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("heap with token status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(buf.String(), `"msg":"pprof request"`) {
		t.Errorf("no audit log line:\n%s", buf.String())
	}
}

func TestMountRuntimeRatesAndShutdown(t *testing.T) {
	prevMutex := runtime.SetMutexProfileFraction(-1)

	s := newTestServer(t, Config{Tokens: map[string]string{"oncall": testToken}})
	h, err := s.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	if got := runtime.SetMutexProfileFraction(-1); got != DefaultMutexProfileFraction {
		t.Fatalf("mutex fraction = %d, want %d", got, DefaultMutexProfileFraction)
	}

	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if got := runtime.SetMutexProfileFraction(prevMutex); got != prevMutex {
		t.Fatalf("mutex fraction not restored: got %d, want %d", got, prevMutex)
	}

	// The route can't be removed from the host mux, so it must go inert.
	req := httptest.NewRequest(http.MethodGet, PathPrefix+"heap", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status after Shutdown = %d, want 503", rec.Code)
	}
}

func TestMountTwiceAndStartAfterMount(t *testing.T) {
	s := newTestServer(t, Config{
		Addr:   "127.0.0.1:0",
		Tokens: map[string]string{"oncall": testToken},
	})
	if err := s.Mount(http.NewServeMux()); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	if err := s.Mount(http.NewServeMux()); err == nil {
		t.Fatal("second Mount succeeded")
	}
	if err := s.Start(); err == nil {
		t.Fatal("Start after Mount succeeded")
	}
}

func TestStartThenMount(t *testing.T) {
	s := newTestServer(t, Config{
		Addr:   "127.0.0.1:0",
		Tokens: map[string]string{"oncall": testToken},
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	if _, err := s.Handler(); err == nil {
		t.Fatal("Handler after Start succeeded")
	}
}

func TestMountExtendsWriteDeadline(t *testing.T) {
	s := newTestServer(t, Config{Tokens: map[string]string{"oncall": testToken}})
	mux := http.NewServeMux()
	if err := s.Mount(mux); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })

	// A host server whose WriteTimeout is shorter than the profile.
	ts := httptest.NewUnstartedServer(mux)
	ts.Config.WriteTimeout = 500 * time.Millisecond
	ts.Start()
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+PathPrefix+"profile?seconds=1", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET profile cut off by host WriteTimeout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("CPU profile is not gzip: %v", err)
	}
	if _, err := io.ReadAll(zr); err != nil {
		t.Fatalf("truncated CPU profile: %v", err)
	}
}

// getStatus does an authenticated GET against base+path and returns the status.
func getStatus(t *testing.T, base, path, tok string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func mutexFraction() int { return runtime.SetMutexProfileFraction(-1) }

func TestDisableEnableMounted(t *testing.T) {
	prev := mutexFraction()
	var buf bytes.Buffer
	s := newTestServer(t, Config{
		Tokens: map[string]string{"oncall": testToken},
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	mux := http.NewServeMux()
	if err := s.Mount(mux); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	ts := httptest.NewServer(mux)
	defer ts.Close()

	if got := getStatus(t, ts.URL, PathPrefix+"heap", testToken); got != http.StatusOK {
		t.Fatalf("enabled heap status = %d", got)
	}
	if got := mutexFraction(); got != DefaultMutexProfileFraction {
		t.Fatalf("mutex fraction = %d, want %d", got, DefaultMutexProfileFraction)
	}

	// Off: endpoints answer 503 even to a valid token, runtime is restored.
	s.Disable()
	s.Disable()
	if s.Enabled() {
		t.Fatal("Enabled() = true after Disable")
	}
	if got := getStatus(t, ts.URL, PathPrefix+"heap", testToken); got != http.StatusServiceUnavailable {
		t.Fatalf("disabled heap status = %d, want 503", got)
	}
	if got := mutexFraction(); got != prev {
		t.Fatalf("mutex fraction while disabled = %d, want %d", got, prev)
	}
	if !strings.Contains(buf.String(), `"reason":"profiling disabled"`) {
		t.Errorf("no audit reason for disabled request:\n%s", buf.String())
	}
	if n := strings.Count(buf.String(), `"msg":"profiling disabled"`); n != 1 {
		t.Errorf("got %d 'profiling disabled' lifecycle lines, want 1", n)
	}

	// Back on: same mux, same route, no re-registration.
	for i := 0; i < 2; i++ {
		if err := s.Enable(); err != nil {
			t.Fatalf("Enable: %v", err)
		}
	}
	if !s.Enabled() {
		t.Fatal("Enabled() = false after Enable")
	}
	if got := getStatus(t, ts.URL, PathPrefix+"heap", testToken); got != http.StatusOK {
		t.Fatalf("re-enabled heap status = %d", got)
	}
	if got := mutexFraction(); got != DefaultMutexProfileFraction {
		t.Fatalf("mutex fraction after Enable = %d, want %d", got, DefaultMutexProfileFraction)
	}
	if n := strings.Count(buf.String(), `"msg":"profiling enabled"`); n != 1 {
		t.Errorf("got %d 'profiling enabled' lifecycle lines, want 1", n)
	}

	s.Shutdown(context.Background())
	if got := mutexFraction(); got != prev {
		t.Fatalf("mutex fraction after Shutdown = %d, want %d", got, prev)
	}
}

func TestDisableBeforeMount(t *testing.T) {
	prev := mutexFraction()
	s := newTestServer(t, Config{Tokens: map[string]string{"oncall": testToken}})
	s.Disable()
	mux := http.NewServeMux()
	if err := s.Mount(mux); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Mounted switched off: the runtime is not touched at all.
	if got := mutexFraction(); got != prev {
		t.Fatalf("mutex fraction = %d, want untouched %d", got, prev)
	}
	if got := getStatus(t, ts.URL, PathPrefix+"heap", testToken); got != http.StatusServiceUnavailable {
		t.Fatalf("heap status = %d, want 503", got)
	}

	if err := s.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if got := getStatus(t, ts.URL, PathPrefix+"heap", testToken); got != http.StatusOK {
		t.Fatalf("heap status after Enable = %d", got)
	}
}

func TestDisableStandalone(t *testing.T) {
	s := newTestServer(t, Config{
		Addr:   "127.0.0.1:0",
		Tokens: map[string]string{"oncall": testToken},
	})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	addr := s.Addr()
	base := "http://" + addr

	// Disable keeps the port open so Enable needs no rebind.
	s.Disable()
	if got := getStatus(t, base, PathPrefix+"heap", testToken); got != http.StatusServiceUnavailable {
		t.Fatalf("disabled heap status = %d, want 503", got)
	}
	if s.Addr() != addr {
		t.Fatalf("Addr changed after Disable: %q → %q", addr, s.Addr())
	}

	if err := s.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if got := getStatus(t, base, PathPrefix+"heap", testToken); got != http.StatusOK {
		t.Fatalf("re-enabled heap status = %d", got)
	}
}

func TestEnableAfterShutdown(t *testing.T) {
	prev := mutexFraction()
	var buf bytes.Buffer
	s := newTestServer(t, Config{
		Tokens: map[string]string{"oncall": testToken},
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	h, err := s.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	s.Shutdown(context.Background())

	// Enable on a detached server only records intent; the route stays inert.
	if err := s.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if got := mutexFraction(); got != prev {
		t.Fatalf("Enable after Shutdown touched the runtime: mutex fraction = %d, want %d", got, prev)
	}
	req := httptest.NewRequest(http.MethodGet, PathPrefix+"heap", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(buf.String(), `"reason":"debug server stopped"`) {
		t.Errorf("want reason 'debug server stopped':\n%s", buf.String())
	}
}

func TestUnauthenticatedProbeWhileDisabled(t *testing.T) {
	s := newTestServer(t, Config{Tokens: map[string]string{"oncall": testToken}})
	h, err := s.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	s.Disable()

	// The disabled check runs before auth, so a probe can't test tokens.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathPrefix+"heap", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After on disabled response")
	}
}
