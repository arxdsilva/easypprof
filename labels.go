package easypprof

import (
	"context"
	"net/http"
	"runtime/pprof"
)

// Do runs fn with the given pprof labels attached to the current goroutine
// and to every goroutine fn starts. CPU and goroutine profile samples taken
// while fn runs carry the labels, so you can filter a profile with
// `go tool pprof -tagfocus op=post_entry`.
//
// labels are key/value pairs and must have even length:
//
//	easypprof.Do(ctx, func(ctx context.Context) {
//		postEntry(ctx, entry)
//	}, "op", "post_entry", "ledger", "settlement")
//
// Keep label values low-cardinality (operation names, not account IDs): they
// end up in profiles that may leave the production environment.
func Do(ctx context.Context, fn func(context.Context), labels ...string) {
	pprof.Do(ctx, pprof.Labels(labels...), fn)
}

// Label wraps an http.Handler so that work done while serving it is labeled
// handler=name in CPU and goroutine profiles.
//
//	mux.Handle("POST /transfers", easypprof.Label("transfer", transferHandler))
func Label(name string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pprof.Do(r.Context(), pprof.Labels("handler", name), func(ctx context.Context) {
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	})
}
