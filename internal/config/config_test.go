package config

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

const secret = "0123456789abcdef0123456789abcdef"

func setBase(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"YANDEX_CLIENT_ID": "cid", "YANDEX_CLIENT_SECRET": "sec",
		"CALLBACK_URL":  "https://iap.example.com/auth/callback",
		"COOKIE_DOMAIN": ".example.com", "COOKIE_SECRET": secret,
		"WHITELIST_FILE": "/tmp/wl",
	} {
		t.Setenv(k, v)
	}
	for _, k := range []string{"COOKIE_SECRET_PREVIOUS", "RATE_LIMIT", "TRUST_FORWARDED_FOR",
		"COOKIE_TTL", "COOKIE_SAMESITE", "SKIP_AUTH_REGEX", "ADMIN_EMAILS", "TOKENS_FILE"} {
		t.Setenv(k, "")
	}
}

func TestLoadDefaults(t *testing.T) {
	setBase(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CookieTTL != 24*time.Hour || cfg.CookieSameSite != http.SameSiteLaxMode ||
		cfg.RateLimit != 60 || cfg.TrustForwardedFor || cfg.Listen != ":9090" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if len(cfg.VerifyKeys()) != 1 || len(cfg.CookieSecret) != 32 || len(cfg.SecretFingerprint()) != 8 {
		t.Errorf("keys: %d, secret len %d", len(cfg.VerifyKeys()), len(cfg.CookieSecret))
	}
}

func TestLoadOptions(t *testing.T) {
	setBase(t)
	t.Setenv("COOKIE_SECRET_PREVIOUS", strings.Repeat("a", 32)+" , "+strings.Repeat("b", 40))
	t.Setenv("RATE_LIMIT", "0")
	t.Setenv("TRUST_FORWARDED_FOR", "true")
	t.Setenv("COOKIE_SAMESITE", "None")
	t.Setenv("COOKIE_TTL", "2h")
	t.Setenv("ADMIN_EMAILS", " Boss@Example.com ,, other@example.com")
	t.Setenv("SKIP_AUTH_REGEX", `^/healthz$`)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.VerifyKeys()) != 3 || cfg.RateLimit != 0 || !cfg.TrustForwardedFor ||
		cfg.CookieSameSite != http.SameSiteNoneMode || cfg.CookieTTL != 2*time.Hour ||
		cfg.SkipAuthRegex == nil {
		t.Errorf("unexpected config: %+v", cfg)
	}
	if !cfg.IsAdmin("boss@example.com") || !cfg.IsAdmin(" OTHER@example.com") || cfg.IsAdmin("x@example.com") {
		t.Error("admin matching is wrong")
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string][2]string{
		"short secret":          {"COOKIE_SECRET", "short"},
		"short previous":        {"COOKIE_SECRET_PREVIOUS", "short"},
		"bad rate limit":        {"RATE_LIMIT", "-1"},
		"non-numeric rate":      {"RATE_LIMIT", "many"},
		"bad bool":              {"TRUST_FORWARDED_FOR", "maybe"},
		"bad samesite":          {"COOKIE_SAMESITE", "sometimes"},
		"bad ttl":               {"COOKIE_TTL", "tomorrow"},
		"bad regex":             {"SKIP_AUTH_REGEX", "("},
		"callback not http":     {"CALLBACK_URL", "ftp://x/y"},
		"missing client id":     {"YANDEX_CLIENT_ID", " "},
		"missing cookie domain": {"COOKIE_DOMAIN", ""},
	}
	for name, kv := range cases {
		t.Run(name, func(t *testing.T) {
			setBase(t)
			t.Setenv(kv[0], kv[1])
			if _, err := Load(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
