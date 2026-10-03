# easypprof

Production-safe `pprof` for Go services.

`import _ "net/http/pprof"` is the usual way to add profiling, and it is a common pentest finding. That import registers the handlers on `http.DefaultServeMux`. If anything in your process serves that mux on a public port, then `/debug/pprof` is public too. It leaks internals, `?seconds=600` is a free denial of service, and `/debug/pprof/cmdline` hands out whatever secrets you passed as flags.

easypprof gives you the same profiles without those problems:

| | `net/http/pprof` | easypprof |
|---|---|---|
| Listener | whatever serves `DefaultServeMux` | its own listener and mux, `127.0.0.1:6060` by default |
| Touches `DefaultServeMux` | yes, just by importing it | never (the package doesn't import `net/http/pprof`) |
| Auth | none | named tokens (Bearer or Basic) or your own `Authorizer`; non-loopback binds require one |
| Network allowlist | none | optional CIDR allowlist on the socket address (never `X-Forwarded-For`) |
| Profile duration | unbounded | capped (`MaxProfileDuration`, 60s default) |
| Concurrent pulls | unbounded | limited (`MaxConcurrent`, 2 default), extra get `429` |
| Audit trail | none | one `slog` line per request: who, what, status, bytes, duration |
| `/cmdline` | on | off unless `EnableCmdline` |
| Block / mutex profiles | off (empty) | on, sampled (`10µs` block rate, `1/100` mutex fraction) |
| Slowloris-style timeouts | yours to set | set |
| Flight recorder (Go 1.25+) | n/a | built in, with throttled `Snapshot()` |

## Install

```sh
go get github.com/arxdsilva/easypprof
```

Requires Go 1.23+. The flight recorder needs Go 1.25+.

## Quick start

```go
dbg, err := easypprof.New(easypprof.Config{
    Tokens: map[string]string{"oncall": os.Getenv("PPROF_TOKEN")},
})
if err != nil {
    log.Fatal(err) // e.g. PPROF_TOKEN unset or shorter than 16 chars
}
if err := dbg.Start(); err != nil {
    log.Fatal(err)
}
defer dbg.Shutdown(context.Background())
```

Then, from somewhere that can reach the port:

```sh
# CPU profile for 30s
curl -sH "Authorization: Bearer $PPROF_TOKEN" -o cpu.pb.gz \
  'localhost:6060/debug/pprof/profile?seconds=30'
go tool pprof -http=:7070 cpu.pb.gz

# lock contention
curl -sH "Authorization: Bearer $PPROF_TOKEN" -o mutex.pb.gz localhost:6060/debug/pprof/mutex
curl -sH "Authorization: Bearer $PPROF_TOKEN" -o block.pb.gz localhost:6060/debug/pprof/block
```

`go tool pprof` can't send a Bearer header, but it does send HTTP Basic credentials from the URL, so this works too. Note that the token ends up in your shell history:

```sh
go tool pprof -http=:7070 "http://oncall:$PPROF_TOKEN@localhost:6060/debug/pprof/heap"
```

## Embed in your existing server

If you'd rather not open another port, mount the endpoints on the mux your API already serves. You keep the same guard: tokens, CIDR allowlist, duration cap, concurrency limit and audit log.

```go
dbg, err := easypprof.New(easypprof.Config{
    Tokens: map[string]string{"oncall": os.Getenv("PPROF_TOKEN")},
})
if err != nil {
    log.Fatal(err)
}
if err := dbg.Mount(mux); err != nil { // registers /debug/pprof/
    log.Fatal(err)
}
defer dbg.Shutdown(context.Background())
```

For other routers, `Handler()` returns the `http.Handler`. Serve it at `/debug/pprof/`:

```go
h, err := dbg.Handler()
if err != nil {
    log.Fatal(err)
}
r.Handle("/debug/pprof/*", h) // chi
```

Things that differ from the standalone server:

- **Auth is mandatory.** Your API port is not loopback, so `Mount` and `Handler` refuse to run without `Tokens` or an `Authorizer`. Set `AllowUnauthenticated` only if something in front already authenticates callers.
- **Your server's `WriteTimeout` is extended** for `profile`, `trace` and `flightrecorder` responses only, up to `MaxProfileDuration + 30s`, so long profiles aren't cut off.
- **Behind a load balancer or proxy**, `AllowedCIDRs` sees the proxy's address, because `X-Forwarded-For` is never trusted. Rely on tokens.
- **`Shutdown`** restores the runtime profiling rates and stops the flight recorder. A `ServeMux` can't unregister a route, so after `Shutdown` the endpoints answer `503`.

`Start` and `Mount` are mutually exclusive on the same `Server`.

## Kubernetes

Keep the default `127.0.0.1:6060`. `kubectl port-forward` connects inside the pod's network namespace, so loopback is reachable through it and nothing else can reach it:

```sh
kubectl port-forward pod/ledger-7c9f 6060:6060
```

The access control is your Kubernetes RBAC (who may `port-forward`), and easypprof's tokens and audit log sit on top of it.

If you need the port reachable from inside the cluster (for a continuous profiler, say), bind the pod IP. easypprof will then insist on `Tokens` or an `Authorizer`. Also lock it down with a `NetworkPolicy`, and optionally `AllowedCIDRs`:

```go
easypprof.Config{
    Addr:         os.Getenv("POD_IP") + ":6060",
    Tokens:       map[string]string{"pyroscope": os.Getenv("PPROF_SCRAPER_TOKEN")},
    AllowedCIDRs: []string{"10.20.0.0/16"},
}
```

Never expose the port through a `Service` of type `LoadBalancer` or an `Ingress`.

## Configuration

| Field | Default | Notes |
|---|---|---|
| `Addr` | `127.0.0.1:6060` | Non-loopback requires `Tokens` or `Authorizer`, or `AllowUnauthenticated: true`. |
| `Tokens` | none | `map[name]token`. Name is logged; each token must be ≥16 chars. Bearer or Basic (`name:token`). Never accepted in the query string. |
| `Authorizer` | none | `func(*http.Request) (subject string, ok bool)`, replaces `Tokens`. Use for mTLS (`r.TLS.PeerCertificates`), mesh identity headers, OIDC. |
| `AllowedCIDRs` | none | Checked against the TCP peer address. |
| `MaxProfileDuration` | `60s` | Caps `?seconds=` on `profile` and `trace`. |
| `MaxConcurrent` | `2` | Profile requests in flight; extra get `429` with `Retry-After`. |
| `BlockProfileRate` | `10000` | ns; passed to `runtime.SetBlockProfileRate`. Negative disables. |
| `MutexProfileFraction` | `100` | 1 in N events; passed to `runtime.SetMutexProfileFraction`. Negative disables. |
| `EnableCmdline` | `false` | `/cmdline` returns 404 otherwise. |
| `DisableFullGoroutineDump` | `false` | Rejects `goroutine?debug=2`, which stops the world for the whole dump. |
| `FlightRecorder` | `nil` | See below. |
| `Logger` | `slog.Default()` | Audit and lifecycle logs. |

Runtime rates are applied in `Start` and restored in `Shutdown`.

## Endpoints

All under `/debug/pprof/`, `GET` only:

- `/` index page
- `heap` (`?gc=1` to collect first), `allocs`, `goroutine` (`?debug=1|2` for text), `block`, `mutex`, `threadcreate`, plus any custom `runtime/pprof` profiles
- `profile?seconds=N` CPU profile
- `trace?seconds=N` execution trace
- `flightrecorder` flight recorder snapshot (when enabled)
- `cmdline` only with `EnableCmdline`

Delta profiles (`heap?seconds=N`) aren't supported. Take two profiles and compare them with `go tool pprof -diff_base before.pb.gz after.pb.gz`.

## Labels: see which operation is burning CPU

Without labels, a CPU profile of a ledger shows `database/sql` and `encoding/json`. With labels you can ask what `post_entry` costs:

```go
easypprof.Do(ctx, func(ctx context.Context) {
    postEntry(ctx, e)
}, "op", "post_entry")

mux.Handle("POST /transfers", easypprof.Label("transfers", transfersHandler))
```

```sh
go tool pprof -tagfocus op=post_entry cpu.pb.gz
go tool pprof -tags cpu.pb.gz
```

Labels propagate to goroutines started inside `fn`. Keep values low-cardinality, such as operation names and never account IDs, because profiles leave production.

## Flight recorder (Go 1.25+)

Latency spikes don't wait for you to start a trace. The flight recorder keeps the last few seconds of execution trace in a ring buffer, and you write it out when something trips:

```go
dbg, _ := easypprof.New(easypprof.Config{
    Tokens: tokens,
    FlightRecorder: &easypprof.FlightRecorderConfig{
        MinAge:      10 * time.Second, // history to keep
        MaxBytes:    16 << 20,         // memory cap
        Dir:         "/var/tmp/traces",
        MinInterval: time.Minute,      // at most one file per minute
    },
})

// in a handler or middleware:
if elapsed > 250*time.Millisecond {
    go dbg.Snapshot("slow-post-entry") // throttled, safe to call on every slow request
}
```

```sh
go tool trace /var/tmp/traces/trace-20261003T212703.066Z-slow-post-entry.out
```

Files are created `0600` in a `0700` directory. Other options: `dbg.SnapshotTo(w)` streams to any `io.Writer` (S3 upload, etc.), or `GET /debug/pprof/flightrecorder` pulls a snapshot on demand. On Go < 1.25, `New` returns `ErrFlightRecorderUnsupported`, and the [example](example/ledger/main.go) shows falling back without it.

## Treat profiles as sensitive

Profiles contain function names, file paths and stack shapes, not variable values. Still:
- `goroutine?debug=2` and execution traces show more than you might expect, and core dumps (`GOTRACEBACK=crash`) contain memory, so leave those off in a regulated system.
- Store pulled profiles with the same access controls and retention as other production diagnostics.
- The audit log is your change-management trail, so ship it with your other logs.

## Profiling around a pentest or load test

1. **Before:** pull baseline `heap`, `goroutine` and 30s `profile`. Confirm port 6060 is not reachable from the tester's network position.
2. **During:** keep the flight recorder on, pull CPU and `mutex` profiles while the test is hot. DoS-class issues show up here: goroutine leaks from half-open connections, unbounded memory on oversized payloads, expensive regex or JSON paths, and lock convoys on hot accounts.
3. **After:** `go tool pprof -diff_base baseline-heap.pb.gz after-heap.pb.gz`. A `goroutine` count that doesn't return to baseline is a leak.

## Example

[`example/ledger`](example/ledger/main.go) is a toy ledger with a deliberately hot lock:

```sh
export PPROF_TOKEN=$(openssl rand -hex 24)
go run ./example/ledger &
for i in $(seq 1 2000); do curl -s -XPOST 'localhost:8080/transfers?from=a&to=b&amount=1' >/dev/null & done
curl -sH "Authorization: Bearer $PPROF_TOKEN" -o mutex.pb.gz localhost:6060/debug/pprof/mutex
go tool pprof -top mutex.pb.gz   # -> main.(*ledger).transfer
```

## Not included (on purpose)

- **Continuous profiling.** Use Pyroscope, Parca, Datadog or Cloud Profiler. They can scrape easypprof's endpoints with a token.
- **Runtime metrics.** Export `runtime/metrics` through your Prometheus or OpenTelemetry setup.
- **PGO.** Pull a representative production CPU profile and commit it as `default.pgo` in your main package.

## License

MIT
