// yandex-iap is a small forward-auth Identity-Aware Proxy that authenticates
// users against Yandex ID and lets a downstream reverse proxy (Traefik, nginx)
// gate traffic through the /auth/verify endpoint.
//
// Configuration is via environment variables; see internal/config/config.go.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/voknil/yandex-iap/internal/config"
	"github.com/voknil/yandex-iap/internal/server"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-version", "--version", "version":
			fmt.Println("yandex-iap", version)
			return
		case "-healthcheck", "--healthcheck", "healthcheck":
			os.Exit(healthcheck())
		default:
			fmt.Fprintf(os.Stderr, "usage: yandex-iap [-version | -healthcheck]\n")
			os.Exit(2)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(2)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))
	slog.SetDefault(log)

	log.Info("starting yandex-iap",
		"version", version,
		"listen", cfg.Listen,
		"callback", cfg.CallbackURL.String(),
		"cookie_domain", cfg.CookieDomain,
		"cookie_ttl", cfg.CookieTTL,
		"whitelist_file", cfg.WhitelistFile,
		"skip_auth_regex", skipAuthDesc(cfg),
		"secret_fingerprint", cfg.SecretFingerprint(),
	)

	srv := server.New(cfg, log)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server terminated", "err", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", "err", err)
	}
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func skipAuthDesc(cfg *config.Config) string {
	if cfg.SkipAuthRegex == nil {
		return ""
	}
	return cfg.SkipAuthRegex.String()
}

// healthcheck probes the local /auth/healthz and returns a process exit code.
// It exists for container HEALTHCHECKs: the distroless image has no shell or curl.
func healthcheck() int {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":9090"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: bad LISTEN:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, //nolint:gosec // loopback probe of our own LISTEN address
		"http://"+net.JoinHostPort(host, port)+"/auth/healthz", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // see above
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
