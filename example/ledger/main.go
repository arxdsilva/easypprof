// Command ledger is a toy double-entry ledger that shows how to wire easypprof
// into a service. It has a deliberate hot lock so the mutex and block
// profiles have something to show.
//
//	export PPROF_TOKEN=$(openssl rand -hex 24)
//	go run ./example/ledger
//
//	# generate some load
//	for i in $(seq 1 2000); do
//	  curl -s -XPOST 'localhost:8080/transfers?from=a&to=b&amount=1' >/dev/null &
//	done
//
//	# pull a mutex profile and open it
//	curl -sH "Authorization: Bearer $PPROF_TOKEN" -o mutex.pb.gz localhost:6060/debug/pprof/mutex
//	go tool pprof -http=:7070 mutex.pb.gz
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/arxdsilva/easypprof"
)

type ledger struct {
	mu       sync.Mutex // one global lock: the contention we want to find
	balances map[string]int64
	entries  []entry
}

type entry struct {
	from, to string
	amount   int64
	at       time.Time
}

func (l *ledger) transfer(ctx context.Context, from, to string, amount int64) {
	easypprof.Do(ctx, func(ctx context.Context) {
		l.mu.Lock()
		defer l.mu.Unlock()
		time.Sleep(200 * time.Microsecond) // pretend to write to the database under the lock
		l.balances[from] -= amount
		l.balances[to] += amount
		l.entries = append(l.entries, entry{from, to, amount, time.Now()})
	}, "op", "post_transfer")
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg := easypprof.Config{
		Addr:                     "127.0.0.1:6060",
		Tokens:                   map[string]string{"oncall": os.Getenv("PPROF_TOKEN")},
		MaxProfileDuration:       60 * time.Second,
		DisableFullGoroutineDump: true,
		Logger:                   logger,
		FlightRecorder: &easypprof.FlightRecorderConfig{
			MinAge:      5 * time.Second,
			Dir:         os.TempDir(),
			MinInterval: 30 * time.Second,
		},
	}
	dbg, err := easypprof.New(cfg)
	if errors.Is(err, easypprof.ErrFlightRecorderUnsupported) {
		logger.Warn("flight recorder needs Go 1.25+, continuing without it")
		cfg.FlightRecorder = nil
		dbg, err = easypprof.New(cfg)
	}
	if err != nil {
		log.Fatal(err)
	}
	if err := dbg.Start(); err != nil {
		log.Fatal(err)
	}

	l := &ledger{balances: map[string]int64{}}

	mux := http.NewServeMux()
	mux.Handle("POST /transfers", easypprof.Label("transfers", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		amount, err := strconv.ParseInt(r.URL.Query().Get("amount"), 10, 64)
		if err != nil || amount <= 0 {
			http.Error(w, "invalid amount", http.StatusBadRequest)
			return
		}
		l.transfer(r.Context(), r.URL.Query().Get("from"), r.URL.Query().Get("to"), amount)
		// Capture what the runtime was doing when a request is slow.
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			go func() {
				if path, err := dbg.Snapshot("slow-transfer"); err == nil {
					logger.Warn("slow transfer, trace saved", "elapsed", elapsed, "trace", path)
				}
			}()
		}
		fmt.Fprintln(w, "ok")
	})))

	// The public server never touches http.DefaultServeMux or pprof.
	app := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info("ledger listening", "addr", app.Addr)
		if err := app.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	app.Shutdown(shutdownCtx)
	dbg.Shutdown(shutdownCtx)
}
