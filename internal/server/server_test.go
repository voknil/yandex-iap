package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/voknil/yandex-iap/internal/config"
)

// fakeWhitelist always accepts, so the /auth/verify tests isolate the CORS
// branch without touching the file-backed whitelist.
type fakeWhitelist struct{}

func (fakeWhitelist) Allowed(string) bool { return true }
func (fakeWhitelist) List() []string      { return nil }
func (fakeWhitelist) Add(string) error    { return nil }
func (fakeWhitelist) Remove(string) error { return nil }

func newTestServer(t *testing.T, sameSite http.SameSite) *Server {
	t.Helper()
	cb, _ := url.Parse("https://example.com/auth/callback")
	cfg := &config.Config{
		ClientID:             "cid",
		ClientSecret:         "sec",
		CallbackURL:          cb,
		Scopes:               []string{"login:email"},
		CookieDomain:         ".example.com",
		CookieName:           "_yiap",
		CookieSecret:         []byte("0123456789abcdef0123456789abcdef"),
		CookieTTL:            time.Hour,
		CookieSameSite:       sameSite,
		WhitelistFile:        "/nonexistent",
		LoginRedirectDefault: "https://example.com/",
		Listen:               ":9090",
		LogLevel:             "error",
	}
	s := &Server{
		Cfg:       cfg,
		Whitelist: fakeWhitelist{},
		Log:       slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		Now:       time.Now,
	}
	return s
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// --- CORS on unauthenticated /auth/verify ---

func TestVerifyRedirect_ReflectsSameSiteOrigin(t *testing.T) {
	s := newTestServer(t, http.SameSiteNoneMode)

	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.Header.Set("Origin", "https://staging.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "api-staging.example.com")
	req.Header.Set("X-Forwarded-Uri", "/api/vacancy/for-map/list")
	req.Header.Set("X-Forwarded-Method", "GET")

	rec := httptest.NewRecorder()
	s.handleVerify(rec, req)

	if got, want := rec.Code, http.StatusFound; got != want {
		t.Fatalf("status: got %d, want %d", got, want)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://staging.example.com" {
		t.Errorf("Allow-Origin: got %q, want reflection of Origin", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials: got %q, want true", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary: got %q, want Origin", got)
	}
}

func TestVerifyRedirect_DoesNotReflectForeignOrigin(t *testing.T) {
	s := newTestServer(t, http.SameSiteNoneMode)

	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.Header.Set("Origin", "https://evil.other.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "api-staging.example.com")
	req.Header.Set("X-Forwarded-Method", "GET")

	rec := httptest.NewRecorder()
	s.handleVerify(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("foreign Origin must not be reflected, got %q",
			rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// --- CORS preflight bypass ---

func TestVerifyPreflight_BypassesAuth(t *testing.T) {
	s := newTestServer(t, http.SameSiteNoneMode)

	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.Header.Set("Origin", "https://staging.example.com")
	req.Header.Set("X-Forwarded-Method", "OPTIONS")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type,authorization")

	rec := httptest.NewRecorder()
	s.handleVerify(rec, req)

	if got, want := rec.Code, http.StatusNoContent; got != want {
		t.Fatalf("status: got %d, want %d", got, want)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://staging.example.com" {
		t.Errorf("Allow-Origin: got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Errorf("Allow-Methods empty")
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "content-type,authorization" {
		t.Errorf("Allow-Headers: got %q, want echoed request headers", got)
	}
}

func TestVerifyPreflight_ForeignOriginStillRedirects(t *testing.T) {
	s := newTestServer(t, http.SameSiteNoneMode)

	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.Header.Set("Origin", "https://evil.other.com")
	req.Header.Set("X-Forwarded-Method", "OPTIONS")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rec := httptest.NewRecorder()
	s.handleVerify(rec, req)

	if rec.Code == http.StatusNoContent {
		t.Errorf("preflight from foreign Origin must not short-circuit auth")
	}
}

// --- Cookie SameSite reflects config ---

func TestSessionCookieHonoursSameSite(t *testing.T) {
	cases := []struct {
		name string
		mode http.SameSite
	}{
		{"lax", http.SameSiteLaxMode},
		{"none", http.SameSiteNoneMode},
		{"strict", http.SameSiteStrictMode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, tc.mode)
			rec := httptest.NewRecorder()
			s.setSessionCookie(rec, "value")
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("want 1 cookie, got %d", len(cookies))
			}
			if cookies[0].SameSite != tc.mode {
				t.Errorf("SameSite: got %v, want %v", cookies[0].SameSite, tc.mode)
			}
			if !cookies[0].Secure {
				t.Errorf("Secure must be true for cross-site safety")
			}
		})
	}
}
