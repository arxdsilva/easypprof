package easypprof

// This file deliberately does not import net/http/pprof: that package's init
// function registers its handlers on http.DefaultServeMux, so importing it,
// even only to reuse its handler functions, would expose pprof on any server
// that serves the default mux. The handlers below are built on runtime/pprof
// and runtime/trace directly.

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"time"
)

func setDownloadHeaders(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// secondsParam returns the requested duration, or def when absent. guard has
// already validated the value against MaxProfileDuration.
func secondsParam(r *http.Request, def time.Duration) time.Duration {
	sec, err := strconv.ParseFloat(r.URL.Query().Get("seconds"), 64)
	if err != nil || sec <= 0 {
		return def
	}
	return time.Duration(sec * float64(time.Second))
}

// sleep waits for d or until the client goes away.
func sleep(r *http.Request, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-r.Context().Done():
	}
}

// serveCPUProfile handles /debug/pprof/profile?seconds=N (default 30).
func serveCPUProfile(w http.ResponseWriter, r *http.Request) {
	d := secondsParam(r, 30*time.Second)
	setDownloadHeaders(w, "profile")
	if err := pprof.StartCPUProfile(w); err != nil {
		// Only one CPU profile can run per process.
		w.Header().Del("Content-Disposition")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, "could not start CPU profile: "+err.Error(), http.StatusConflict)
		return
	}
	sleep(r, d)
	pprof.StopCPUProfile()
}

// serveTrace handles /debug/pprof/trace?seconds=N (default 1).
func serveTrace(w http.ResponseWriter, r *http.Request) {
	d := secondsParam(r, time.Second)
	setDownloadHeaders(w, "trace")
	if err := trace.Start(w); err != nil {
		w.Header().Del("Content-Disposition")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, "could not start trace: "+err.Error(), http.StatusConflict)
		return
	}
	sleep(r, d)
	trace.Stop()
}

// serveCmdline handles /debug/pprof/cmdline. Only mounted when
// Config.EnableCmdline is set.
func serveCmdline(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, strings.Join(os.Args, "\x00"))
}

// serveIndex handles /debug/pprof/ (the listing page) and
// /debug/pprof/<name> for every runtime/pprof profile: heap, allocs,
// goroutine, block, mutex, threadcreate, and any custom profiles.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, PathPrefix)
	if name == "" {
		s.writeIndex(w)
		return
	}

	p := pprof.Lookup(name)
	if p == nil {
		http.Error(w, "unknown profile", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	if q.Get("seconds") != "" {
		http.Error(w, "delta profiles are not supported; take two profiles and compare them with go tool pprof -diff_base", http.StatusBadRequest)
		return
	}
	debug, _ := strconv.Atoi(q.Get("debug"))
	if name == "heap" && q.Get("gc") != "" && q.Get("gc") != "0" {
		runtime.GC()
	}
	if debug > 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	} else {
		setDownloadHeaders(w, name)
	}
	if err := p.WriteTo(w, debug); err != nil {
		s.log.Warn("writing profile failed", "profile", name, "err", err)
	}
}

var profileDescriptions = map[string]string{
	"allocs":       "A sampling of all past memory allocations.",
	"block":        "Stack traces that led to blocking on synchronization primitives.",
	"goroutine":    "Stack traces of all current goroutines. Use debug=2 for the panic-style dump.",
	"heap":         "A sampling of memory allocations of live objects. Add gc=1 to run GC first.",
	"mutex":        "Stack traces of holders of contended mutexes.",
	"threadcreate": "Stack traces that led to the creation of new OS threads.",
}

func (s *Server) writeIndex(w http.ResponseWriter) {
	type entry struct {
		name, desc string
		count      int
		links      bool
	}
	var entries []entry
	for _, p := range pprof.Profiles() {
		entries = append(entries, entry{p.Name(), profileDescriptions[p.Name()], p.Count(), true})
	}
	entries = append(entries,
		entry{"profile", "CPU profile. Use ?seconds=N (max " + s.cfg.MaxProfileDuration.String() + ").", -1, false},
		entry{"trace", "Execution trace. Use ?seconds=N (max " + s.cfg.MaxProfileDuration.String() + ").", -1, false},
	)
	if s.cfg.EnableCmdline {
		entries = append(entries, entry{"cmdline", "The process command line.", -1, false})
	}
	if s.fr != nil {
		entries = append(entries, entry{"flightrecorder", "The last " + s.cfg.FlightRecorder.MinAge.String() + " of execution trace from the flight recorder.", -1, false})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><title>easypprof</title></head><body>\n<h1>/debug/pprof/</h1>\n<table>\n")
	for _, e := range entries {
		count := ""
		if e.count >= 0 {
			count = strconv.Itoa(e.count)
		}
		n := html.EscapeString(e.name)
		link := `<a href="` + n + `">` + n + `</a>`
		if e.links {
			link += ` (<a href="` + n + `?debug=1">text</a>)`
		}
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", count, link, html.EscapeString(e.desc))
	}
	b.WriteString("</table>\n</body></html>\n")
	fmt.Fprint(w, b.String())
}
