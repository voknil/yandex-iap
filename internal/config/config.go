// Package config loads and validates configuration from environment variables.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config holds the runtime configuration for yandex-iap.
type Config struct {
	// Yandex OAuth application credentials from https://oauth.yandex.ru/.
	ClientID     string
	ClientSecret string

	// CallbackURL is the absolute URL Yandex redirects back to after login.
	// Must match one of the Redirect URIs registered in the Yandex OAuth app.
	CallbackURL *url.URL

	// Scopes requested from Yandex (space-joined, e.g. "login:email login:info").
	Scopes []string

	// CookieDomain is the domain attribute of the session cookie.
	// Use a parent domain (e.g. ".example.com") to share the session across subdomains.
	CookieDomain string

	// CookieName is the name of the session cookie.
	CookieName string

	// CookieSecret is the HMAC key used to sign cookies and state parameters.
	CookieSecret []byte

	// CookieTTL is how long a signed session cookie stays valid.
	CookieTTL time.Duration

	// WhitelistFile is the path to a newline-delimited list of allowed emails.
	// Re-read on every auth decision, so edits take effect without restart.
	WhitelistFile string

	// TokensFile is the path to a JSON file backing static bearer tokens for
	// non-interactive clients (CI jobs, smoke-test scripts, automation). Empty
	// disables that code path entirely — only cookie-based sessions authenticate.
	TokensFile string

	// SkipAuthRegex, when non-nil, lets requests whose original URI matches
	// bypass authentication (e.g. "^/healthz$" for uptime checks).
	SkipAuthRegex *regexp.Regexp

	// AdminEmails is the set of emails allowed to use /auth/admin.
	// Admins are the only users who can add/remove entries in the main
	// whitelist via the web UI. This list is in-memory only; edit the env
	// var and restart the process to change it.
	AdminEmails map[string]struct{}

	// LoginRedirectDefault is where /auth/logout (and post-login fallback) points
	// if no explicit `rd` parameter is supplied.
	LoginRedirectDefault string

	// Listen is the TCP address the HTTP server binds to, e.g. ":9090".
	Listen string

	// LogLevel controls verbosity: "debug", "info", "warn", "error".
	LogLevel string
}

// Load reads the configuration from environment variables.
//
// Required:
//
//	YANDEX_CLIENT_ID, YANDEX_CLIENT_SECRET, CALLBACK_URL, COOKIE_DOMAIN,
//	COOKIE_SECRET, WHITELIST_FILE
//
// Optional (with defaults):
//
//	SCOPES              (default "login:email login:info")
//	COOKIE_NAME         (default "_yiap")
//	COOKIE_TTL          (default "24h")
//	SKIP_AUTH_REGEX     (default empty — no bypass)
//	LOGIN_REDIRECT_DEFAULT (default "/")
//	LISTEN              (default ":9090")
//	LOG_LEVEL           (default "info")
func Load() (*Config, error) {
	cfg := &Config{
		Scopes:               []string{"login:email", "login:info"},
		CookieName:           "_yiap",
		CookieTTL:            24 * time.Hour,
		LoginRedirectDefault: "/",
		Listen:               ":9090",
		LogLevel:             "info",
	}

	var err error
	cfg.ClientID, err = requireEnv("YANDEX_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	cfg.ClientSecret, err = requireEnv("YANDEX_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}

	rawCallback, err := requireEnv("CALLBACK_URL")
	if err != nil {
		return nil, err
	}
	cfg.CallbackURL, err = url.Parse(rawCallback)
	if err != nil {
		return nil, fmt.Errorf("CALLBACK_URL is not a valid URL: %w", err)
	}
	if cfg.CallbackURL.Scheme != "https" && cfg.CallbackURL.Scheme != "http" {
		return nil, fmt.Errorf("CALLBACK_URL must be http(s), got %q", cfg.CallbackURL.Scheme)
	}

	cfg.CookieDomain, err = requireEnv("COOKIE_DOMAIN")
	if err != nil {
		return nil, err
	}

	rawSecret, err := requireEnv("COOKIE_SECRET")
	if err != nil {
		return nil, err
	}
	if len(rawSecret) < 32 {
		return nil, fmt.Errorf("COOKIE_SECRET must be at least 32 characters")
	}
	// Derive a 32-byte key deterministically so users can pick any shape of secret.
	sum := sha256.Sum256([]byte(rawSecret))
	cfg.CookieSecret = sum[:]

	cfg.WhitelistFile, err = requireEnv("WHITELIST_FILE")
	if err != nil {
		return nil, err
	}

	cfg.TokensFile = strings.TrimSpace(os.Getenv("TOKENS_FILE"))

	if v := os.Getenv("SCOPES"); v != "" {
		cfg.Scopes = strings.Fields(v)
	}
	if v := os.Getenv("COOKIE_NAME"); v != "" {
		cfg.CookieName = v
	}
	if v := os.Getenv("COOKIE_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("COOKIE_TTL: %w", err)
		}
		cfg.CookieTTL = d
	}
	if v := os.Getenv("SKIP_AUTH_REGEX"); v != "" {
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, fmt.Errorf("SKIP_AUTH_REGEX: %w", err)
		}
		cfg.SkipAuthRegex = re
	}
	if v := os.Getenv("LOGIN_REDIRECT_DEFAULT"); v != "" {
		cfg.LoginRedirectDefault = v
	}
	if v := os.Getenv("LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}

	if v := os.Getenv("ADMIN_EMAILS"); v != "" {
		cfg.AdminEmails = make(map[string]struct{})
		for _, raw := range strings.Split(v, ",") {
			e := strings.ToLower(strings.TrimSpace(raw))
			if e != "" {
				cfg.AdminEmails[e] = struct{}{}
			}
		}
	}

	return cfg, nil
}

// IsAdmin reports whether the given email is allowed to use /auth/admin.
// Matching is case-insensitive and whitespace-trimmed.
func (c *Config) IsAdmin(email string) bool {
	if c.AdminEmails == nil {
		return false
	}
	_, ok := c.AdminEmails[strings.ToLower(strings.TrimSpace(email))]
	return ok
}

// SecretFingerprint returns the first 8 hex chars of the cookie-secret digest,
// suitable for startup logs (useful for detecting misconfigured env vars
// without leaking the actual secret).
func (c *Config) SecretFingerprint() string {
	return hex.EncodeToString(c.CookieSecret)[:8]
}

// ScopesJoined returns scopes as a space-separated string for OAuth query params.
func (c *Config) ScopesJoined() string {
	return strings.Join(c.Scopes, " ")
}

func requireEnv(name string) (string, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return v, nil
}

