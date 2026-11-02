package server

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/voknil/yandex-iap/internal/config"
)

// maxRedirectLen bounds the size of a post-login redirect target. Anything
// longer is far outside what a browser would navigate to legitimately.
const maxRedirectLen = 2048

// sanitizeRedirect keeps only redirect targets that cannot send the user to a
// foreign site, and returns "" for everything else.
//
// Accepted:
//   - a same-origin path ("/dashboard?tab=1"), but not a protocol-relative one;
//   - an absolute http(s) URL whose host is the cookie domain or a subdomain.
//
// Rejected, among others:
//   - backslashes ("/\evil.com" is read by browsers as "//evil.com"),
//   - control characters (CR/LF header injection, tabs that browsers strip
//     out of the middle of a URL),
//   - non-http(s) schemes ("javascript:", "data:"),
//   - URLs carrying credentials ("https://trusted@evil.com").
func sanitizeRedirect(raw string, cfg *config.Config) string {
	if raw == "" || len(raw) > maxRedirectLen {
		return ""
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return ""
		}
	}
	if strings.HasPrefix(raw, "/") {
		if strings.HasPrefix(raw, "//") {
			return ""
		}
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.User != nil || u.Host == "" {
		return ""
	}
	if hostInDomain(u.Hostname(), cfg.CookieDomain) {
		return u.String()
	}
	return ""
}

// hostInDomain reports whether host equals cookieDomain or is a subdomain of
// it. A leading dot on cookieDomain (".example.com") is ignored.
func hostInDomain(host, cookieDomain string) bool {
	dom := strings.ToLower(strings.TrimPrefix(cookieDomain, "."))
	host = strings.ToLower(host)
	if dom == "" || host == "" {
		return false
	}
	return host == dom || strings.HasSuffix(host, "."+dom)
}

// securityHeaders applies the headers every response should carry. Responses
// are never cacheable: they depend on the session cookie.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// htmlHeaders prepares a response for an HTML page: content type, a strict
// Content-Security-Policy and a fresh per-response nonce, which the page must
// put on its inline <style> and <script> elements. Nothing else is allowed to
// load or execute, so a reflected value that slips past escaping still cannot
// run script.
func htmlHeaders(w http.ResponseWriter) (nonce string) {
	nonce = newNonce()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy",
		"default-src 'none'; "+
			"style-src 'nonce-"+nonce+"'; "+
			"script-src 'nonce-"+nonce+"'; "+
			"form-action 'self'; "+
			"base-uri 'none'; "+
			"frame-ancestors 'none'")
	return nonce
}

// newNonce returns 128 random bits, base64-encoded.
func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on supported platforms; refusing to serve
		// is safer than serving a predictable nonce.
		panic("server: cannot read random bytes: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}
