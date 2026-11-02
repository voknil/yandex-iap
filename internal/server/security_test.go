package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/voknil/yandex-iap/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{CookieDomain: ".example.com"}
}

func TestSanitizeRedirect(t *testing.T) {
	cfg := testConfig()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"relative path", "/dashboard?tab=1", "/dashboard?tab=1"},
		{"root", "/", "/"},
		{"same domain", "https://example.com/a", "https://example.com/a"},
		{"subdomain", "https://app.staging.example.com/a?x=1", "https://app.staging.example.com/a?x=1"},
		{"http subdomain", "http://app.example.com/", "http://app.example.com/"},
		{"uppercase host", "https://APP.Example.COM/a", "https://APP.Example.COM/a"},

		// Open-redirect attempts. Every one of these must be dropped.
		{"protocol-relative", "//evil.com/a", ""},
		{"backslash protocol-relative", `/\evil.com`, ""},
		{"backslash in path", `/foo\bar`, ""},
		{"double backslash", `\\evil.com`, ""},
		{"foreign host", "https://evil.com/a", ""},
		{"lookalike suffix", "https://evilexample.com/a", ""},
		{"domain as subdomain of attacker", "https://example.com.evil.com/a", ""},
		{"userinfo trick", "https://example.com@evil.com/a", ""},
		{"userinfo on own domain", "https://user:pw@example.com/a", ""},
		{"javascript scheme", "javascript:alert(1)", ""},
		{"data scheme", "data:text/html,<script>alert(1)</script>", ""},
		{"ftp scheme", "ftp://example.com/a", ""},
		{"no scheme host", "example.com/a", ""},
		{"scheme only", "https://", ""},
		{"crlf injection", "/a\r\nSet-Cookie: x=y", ""},
		{"tab inside", "/a\tb", ""},
		{"newline inside", "https://example.com/a\nb", ""},
		{"nul byte", "/a\x00b", ""},
		{"del char", "/a\x7fb", ""},
		{"leading space", " https://evil.com", ""},
		{"too long", "/" + strings.Repeat("a", maxRedirectLen), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeRedirect(tc.in, cfg); got != tc.want {
				t.Errorf("sanitizeRedirect(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// FuzzSanitizeRedirect checks the security property rather than examples: for
// any input, the result is either empty or a target that stays on the site.
func FuzzSanitizeRedirect(f *testing.F) {
	for _, seed := range []string{
		"", "/", "/a", "//evil.com", `/\evil.com`, "https://example.com/",
		"https://evil.com", "javascript:alert(1)", "https://a@evil.com",
		"/a\r\nX: y", "https://example.com.evil.com", "HTTPS://EXAMPLE.COM",
		"https://example.com:8443/x", "/%2f%2fevil.com", "/a?b=//evil.com",
	} {
		f.Add(seed)
	}
	cfg := testConfig()
	f.Fuzz(func(t *testing.T, in string) {
		out := sanitizeRedirect(in, cfg)
		if out == "" {
			return
		}
		if strings.ContainsAny(out, "\\\r\n\t\x00") {
			t.Fatalf("accepted %q -> %q containing a forbidden character", in, out)
		}
		if strings.HasPrefix(out, "/") {
			if strings.HasPrefix(out, "//") {
				t.Fatalf("accepted protocol-relative %q -> %q", in, out)
			}
			return
		}
		u, err := url.Parse(out)
		if err != nil {
			t.Fatalf("accepted unparsable %q -> %q: %v", in, out, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			t.Fatalf("accepted scheme %q: %q -> %q", u.Scheme, in, out)
		}
		if u.User != nil {
			t.Fatalf("accepted credentials in URL: %q -> %q", in, out)
		}
		if !hostInDomain(u.Hostname(), cfg.CookieDomain) {
			t.Fatalf("accepted foreign host %q: %q -> %q", u.Hostname(), in, out)
		}
	})
}

func TestHostInDomain(t *testing.T) {
	cases := []struct {
		host, dom string
		want      bool
	}{
		{"example.com", ".example.com", true},
		{"example.com", "example.com", true},
		{"a.example.com", ".example.com", true},
		{"A.EXAMPLE.COM", ".example.com", true},
		{"evilexample.com", ".example.com", false},
		{"example.com.evil.com", ".example.com", false},
		{"", ".example.com", false},
		{"example.com", "", false},
	}
	for _, tc := range cases {
		if got := hostInDomain(tc.host, tc.dom); got != tc.want {
			t.Errorf("hostInDomain(%q, %q) = %v, want %v", tc.host, tc.dom, got, tc.want)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/healthz", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestHTMLHeadersCSP(t *testing.T) {
	rec := httptest.NewRecorder()
	nonce := htmlHeaders(rec)
	if len(nonce) < 20 {
		t.Fatalf("nonce too short: %q", nonce)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, must := range []string{
		"default-src 'none'",
		"style-src 'nonce-" + nonce + "'",
		"script-src 'nonce-" + nonce + "'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"base-uri 'none'",
	} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP %q does not contain %q", csp, must)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP must not weaken script/style rules: %q", csp)
	}
	if other := htmlHeaders(httptest.NewRecorder()); other == nonce {
		t.Errorf("nonce must be fresh for every response")
	}
}

func TestAccessDeniedPage(t *testing.T) {
	rec := httptest.NewRecorder()
	renderAccessDenied(rec, `<script>alert(1)</script>@evil.com`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)") {
		t.Errorf("email was not escaped in the page: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;@evil.com") {
		t.Errorf("escaped email missing from page")
	}
	nonce := between(rec.Header().Get("Content-Security-Policy"), "style-src 'nonce-", "'")
	if nonce == "" || !strings.Contains(body, `<style nonce="`+nonce+`">`) {
		t.Errorf("page <style> must carry the CSP nonce %q", nonce)
	}
}

func between(s, left, right string) string {
	i := strings.Index(s, left)
	if i < 0 {
		return ""
	}
	s = s[i+len(left):]
	j := strings.Index(s, right)
	if j < 0 {
		return ""
	}
	return s[:j]
}
