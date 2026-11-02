package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxTrackedClients bounds the limiter's memory: when the table is full, stale
// entries are dropped first and, failing that, new clients are let through
// rather than evicting someone who is being limited.
const maxTrackedClients = 10000

// rateLimiter is a fixed-window counter per client address. It protects the
// endpoints that trigger outbound calls to Yandex (login, callback) from being
// used as an amplifier or hammered by a single client.
type rateLimiter struct {
	limit    int
	window   time.Duration
	useXFF   bool
	now      func() time.Time
	mu       sync.Mutex
	counters map[string]*window
}

type window struct {
	start time.Time
	count int
}

// newRateLimiter returns a limiter allowing limit requests per window per
// client. limit <= 0 disables it.
func newRateLimiter(limit int, per time.Duration, trustXFF bool, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		limit: limit, window: per, useXFF: trustXFF, now: now,
		counters: make(map[string]*window),
	}
}

func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	if l.limit <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if retry, ok := l.allow(l.clientKey(r)); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow records a request from key and reports whether it is within the limit;
// if not, it also returns how long until the window resets.
func (l *rateLimiter) allow(key string) (retryAfter time.Duration, ok bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	c := l.counters[key]
	if c == nil || now.Sub(c.start) >= l.window {
		if c == nil && len(l.counters) >= maxTrackedClients {
			l.sweep(now)
			if len(l.counters) >= maxTrackedClients {
				return 0, true
			}
		}
		l.counters[key] = &window{start: now, count: 1}
		return 0, true
	}
	c.count++
	if c.count > l.limit {
		return l.window - now.Sub(c.start), false
	}
	return 0, true
}

func (l *rateLimiter) sweep(now time.Time) {
	for k, c := range l.counters {
		if now.Sub(c.start) >= l.window {
			delete(l.counters, k)
		}
	}
}

// clientKey identifies the caller: the last X-Forwarded-For entry when the
// operator says a trusted proxy sets it (earlier entries are client-supplied
// and spoofable), otherwise the socket peer.
func (l *rateLimiter) clientKey(r *http.Request) string {
	if l.useXFF {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
