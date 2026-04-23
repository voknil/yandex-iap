// yandex-iap is a small forward-auth Identity-Aware Proxy that authenticates
// users against Yandex ID and lets a downstream reverse proxy (Traefik, nginx)
// gate traffic through the /auth/verify endpoint.
//
// Configuration is via environment variables; see internal/config/config.go.
package main

import (
	"context"
	"errors"
	"log/slog"
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
