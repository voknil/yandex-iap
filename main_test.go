package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	t.Setenv("LISTEN", ":"+port)

	if code := healthcheck(); code != 0 {
		t.Fatalf("healthy server: exit %d", code)
	}
	status = http.StatusServiceUnavailable
	if code := healthcheck(); code == 0 {
		t.Fatal("unhealthy server must fail the check")
	}
	ts.Close()
	if code := healthcheck(); code == 0 {
		t.Fatal("unreachable server must fail the check")
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]string{"debug": "DEBUG", "warn": "WARN", "error": "ERROR", "": "INFO", "x": "INFO"} {
		if got := parseLevel(in).String(); got != want {
			t.Errorf("parseLevel(%q) = %s, want %s", in, got, want)
		}
	}
}
