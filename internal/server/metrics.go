package server

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
)

// metrics is a tiny Prometheus-compatible counter set. It avoids pulling in
// the client library: the service only needs a few labelled counters, and the
// project keeps zero third-party dependencies.
type metrics struct {
	mu       sync.Mutex
	counters map[string]uint64 // "name{labels}" -> value
}

func newMetrics() *metrics { return &metrics{counters: make(map[string]uint64)} }

func (m *metrics) inc(name, labels string) {
	key := name
	if labels != "" {
		key += "{" + labels + "}"
	}
	m.mu.Lock()
	m.counters[key]++
	m.mu.Unlock()
}

// ServeHTTP renders the counters in the Prometheus text exposition format.
func (m *metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	keys := make([]string, 0, len(m.counters))
	snapshot := make(map[string]uint64, len(m.counters))
	for k, v := range m.counters {
		keys = append(keys, k)
		snapshot[k] = v
	}
	m.mu.Unlock()
	sort.Strings(keys)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintln(w, "# HELP yiap_requests_total Requests handled, by endpoint and HTTP status.")
	fmt.Fprintln(w, "# TYPE yiap_requests_total counter")
	for _, k := range keys {
		fmt.Fprintf(w, "%s %d\n", k, snapshot[k])
	}
}

// statusRecorder remembers the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// count wraps a handler so each response increments
// yiap_requests_total{endpoint=...,code=...}.
func (m *metrics) count(endpoint string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.inc("yiap_requests_total",
			`endpoint="`+endpoint+`",code="`+strconv.Itoa(rec.status)+`"`)
	})
}

// Metrics returns the handler for the metrics listener (see METRICS_LISTEN).
// It is deliberately not part of Router: counters must not be reachable
// through the public forward-auth port.
func (s *Server) Metrics() http.Handler {
	if s.metrics == nil {
		s.metrics = newMetrics()
	}
	return s.metrics
}
