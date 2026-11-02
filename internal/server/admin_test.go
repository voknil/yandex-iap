package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/voknil/yandex-iap/internal/session"
	"github.com/voknil/yandex-iap/internal/tokens"
	"github.com/voknil/yandex-iap/internal/whitelist"
)

const (
	adminEmail = "admin@example.com"
	userEmail  = "user@example.com"
)

// adminFixture is a server wired to real file-backed stores in a temp dir,
// exercised through the public Router so middleware (headers) is included.
type adminFixture struct {
	srv     *Server
	handler http.Handler
	wl      *whitelist.File
	toks    *tokens.File
}

func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	s := newTestServer(t, http.SameSiteLaxMode)
	dir := t.TempDir()

	wlPath := filepath.Join(dir, "allowed.txt")
	if err := os.WriteFile(wlPath, []byte(adminEmail+"\n"+userEmail+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wl := whitelist.New(wlPath, 0)
	toks := tokens.NewFile(filepath.Join(dir, "tokens.json"), 0)

	s.Whitelist = wl
	s.Tokens = toks
	s.Cfg.AdminEmails = map[string]struct{}{adminEmail: {}}
	return &adminFixture{srv: s, handler: s.Router(), wl: wl, toks: toks}
}

func (f *adminFixture) cookieFor(t *testing.T, email string) *http.Cookie {
	t.Helper()
	v, err := session.Issue(f.srv.Cfg.CookieSecret, email, "Test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: f.srv.Cfg.CookieName, Value: v}
}

func (f *adminFixture) csrf(t *testing.T, email string) string {
	t.Helper()
	v, err := session.SignState(f.srv.Cfg.CookieSecret, email, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *adminFixture) get(t *testing.T, path string, c *http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *adminFixture) post(t *testing.T, path string, form url.Values, c *http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c != nil {
		req.AddCookie(c)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestAdmin_RequiresLogin(t *testing.T) {
	f := newAdminFixture(t)
	rec := f.get(t, "/auth/admin", nil, map[string]string{
		"X-Forwarded-Proto": "https", "X-Forwarded-Host": "iap.example.com", "X-Forwarded-Uri": "/auth/admin",
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/auth/login") {
		t.Errorf("Location = %q, want a login redirect", loc)
	}
}

func TestAdmin_NonAdminForbidden(t *testing.T) {
	f := newAdminFixture(t)
	c := f.cookieFor(t, userEmail)

	if rec := f.get(t, "/auth/admin", c, nil); rec.Code != http.StatusForbidden {
		t.Errorf("GET status = %d, want 403", rec.Code)
	}
	rec := f.post(t, "/auth/admin/add", url.Values{"email": {"evil@example.com"}, "_csrf": {f.csrf(t, userEmail)}}, c, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST status = %d, want 403", rec.Code)
	}
	if f.wl.Allowed("evil@example.com") {
		t.Errorf("non-admin managed to modify the whitelist")
	}
}

func TestAdmin_PageHasCSPAndNonce(t *testing.T) {
	f := newAdminFixture(t)
	rec := f.get(t, "/auth/admin", f.cookieFor(t, adminEmail), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	nonce := between(rec.Header().Get("Content-Security-Policy"), "script-src 'nonce-", "'")
	if nonce == "" {
		t.Fatalf("no script nonce in CSP: %q", rec.Header().Get("Content-Security-Policy"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<style nonce="`+nonce+`">`) || !strings.Contains(body, `<script nonce="`+nonce+`">`) {
		t.Errorf("inline <style>/<script> must carry the CSP nonce")
	}
	if strings.Contains(body, "onclick=") {
		t.Errorf("inline event handlers are blocked by CSP and must not be used")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestAdmin_TokenNeverInURL(t *testing.T) {
	f := newAdminFixture(t)
	c := f.cookieFor(t, adminEmail)

	rec := f.post(t, "/auth/admin/tokens/create",
		url.Values{"name": {"ci smoke"}, "_csrf": {f.csrf(t, adminEmail)}}, c, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the page is rendered in the response, not redirected)", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("a Location header would leak the token into history and logs: %q", loc)
	}
	body := rec.Body.String()
	i := strings.Index(body, "yiap_")
	if i < 0 {
		t.Fatalf("plaintext token not shown on the creation page")
	}
	plaintext := body[i : i+5+40]
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	// The token works, and is only ever shown once.
	if _, ok := f.toks.Validate(plaintext); !ok {
		t.Errorf("created token does not validate")
	}
	again := f.get(t, "/auth/admin", c, nil)
	if strings.Contains(again.Body.String(), plaintext) {
		t.Errorf("token reappeared on a later page view")
	}
	// Old-style link must not be able to inject a value into the banner.
	forged := f.get(t, "/auth/admin?new_token=yiap_forged", c, nil)
	if strings.Contains(forged.Body.String(), "yiap_forged") {
		t.Errorf("new_token query parameter must be ignored")
	}
}

func TestAdmin_RedirectsAreRelative(t *testing.T) {
	f := newAdminFixture(t)
	c := f.cookieFor(t, adminEmail)

	// Bad CSRF token forces the flash-message redirect. A forged forwarded host
	// must not influence where it points.
	rec := f.post(t, "/auth/admin/add",
		url.Values{"email": {"x@example.com"}, "_csrf": {"bogus"}}, c,
		map[string]string{"X-Forwarded-Host": "evil.com", "X-Forwarded-Proto": "https", "Host": "evil.com"})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/admin") || strings.Contains(loc, "://") || strings.Contains(loc, "evil.com") {
		t.Errorf("Location = %q, want a relative /auth/admin URL", loc)
	}
}

func TestAdmin_CSRFRequired(t *testing.T) {
	f := newAdminFixture(t)
	c := f.cookieFor(t, adminEmail)

	for _, tc := range []struct {
		name, path string
		form       url.Values
	}{
		{"add", "/auth/admin/add", url.Values{"email": {"new@example.com"}}},
		{"remove", "/auth/admin/remove", url.Values{"email": {userEmail}}},
		{"token create", "/auth/admin/tokens/create", url.Values{"name": {"x"}}},
		{"token delete", "/auth/admin/tokens/delete", url.Values{"id": {"tok_1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.post(t, tc.path, tc.form, c, nil)
			if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error=") {
				t.Errorf("status=%d Location=%q, want a 303 with an error flash", rec.Code, rec.Header().Get("Location"))
			}
		})
	}
	if f.wl.Allowed("new@example.com") || !f.wl.Allowed(userEmail) {
		t.Errorf("whitelist changed without a valid CSRF token")
	}
}

func TestAdmin_CSRFTokenIsBoundToTheAdmin(t *testing.T) {
	f := newAdminFixture(t)
	c := f.cookieFor(t, adminEmail)
	// A token minted for somebody else must be rejected.
	rec := f.post(t, "/auth/admin/add",
		url.Values{"email": {"new@example.com"}, "_csrf": {f.csrf(t, "other@example.com")}}, c, nil)
	if rec.Code != http.StatusSeeOther || f.wl.Allowed("new@example.com") {
		t.Errorf("CSRF token issued for another user was accepted")
	}
}

func TestAdmin_WhitelistAddRemove(t *testing.T) {
	f := newAdminFixture(t)
	c := f.cookieFor(t, adminEmail)
	csrf := f.csrf(t, adminEmail)

	rec := f.post(t, "/auth/admin/add", url.Values{"email": {" New@Example.com "}, "_csrf": {csrf}}, c, nil)
	if rec.Code != http.StatusSeeOther || !f.wl.Allowed("new@example.com") {
		t.Fatalf("add failed: status=%d allowed=%v", rec.Code, f.wl.Allowed("new@example.com"))
	}

	rec = f.post(t, "/auth/admin/add", url.Values{"email": {"not-an-email"}, "_csrf": {csrf}}, c, nil)
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("invalid email must produce an error flash, got %q", rec.Header().Get("Location"))
	}

	rec = f.post(t, "/auth/admin/remove", url.Values{"email": {userEmail}, "_csrf": {csrf}}, c, nil)
	if rec.Code != http.StatusSeeOther || f.wl.Allowed(userEmail) {
		t.Errorf("remove failed: status=%d", rec.Code)
	}

	rec = f.post(t, "/auth/admin/remove", url.Values{"email": {adminEmail}, "_csrf": {csrf}}, c, nil)
	if !f.wl.Allowed(adminEmail) || !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("an admin must not be able to remove themselves")
	}
}

// A token name is attacker-influenced text that ends up inside an HTML
// attribute. It must stay inert there.
func TestAdmin_TokenNameCannotInjectMarkupOrScript(t *testing.T) {
	f := newAdminFixture(t)
	c := f.cookieFor(t, adminEmail)

	payloads := []string{
		`x'+alert(1)+'`,
		`"><script>alert(1)</script>`,
		`' onmouseover='alert(1)`,
		`</button><img src=x onerror=alert(1)>`,
	}
	for _, name := range payloads {
		if _, _, err := f.toks.Create(name, adminEmail, 0); err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
	}
	rec := f.get(t, "/auth/admin", c, nil)
	body := rec.Body.String()

	// None of the raw payloads may appear verbatim: that would mean a quote or
	// an angle bracket reached the page unescaped.
	for _, raw := range payloads {
		if strings.Contains(body, raw) {
			t.Errorf("raw payload %q found in the admin page", raw)
		}
	}
	for _, bad := range []string{`<script>alert(1)`, `<img src=x`, `onclick=`} {
		if strings.Contains(body, bad) {
			t.Errorf("unescaped fragment %q found in the admin page", bad)
		}
	}
	// The escaped form is present instead (text inside the attribute, inert).
	if !strings.Contains(body, "&#39; onmouseover=&#39;alert(1)") {
		t.Errorf("expected the escaped onmouseover payload as plain attribute text")
	}
	if !strings.Contains(body, "data-confirm=") {
		t.Fatalf("confirmation text should live in data-confirm attributes")
	}
	// Quotes are escaped, so an attribute value can never be closed early.
	if strings.Contains(body, `data-confirm="Отозвать токен x'`) {
		t.Errorf("single quote must be escaped inside data-confirm")
	}
	if !strings.Contains(body, "x&#39;+alert(1)+&#39;") {
		t.Errorf("expected the escaped payload in the page")
	}
}

func TestAdmin_TokensDisabled(t *testing.T) {
	f := newAdminFixture(t)
	f.srv.Tokens = nil
	c := f.cookieFor(t, adminEmail)

	rec := f.post(t, "/auth/admin/tokens/create",
		url.Values{"name": {"x"}, "_csrf": {f.csrf(t, adminEmail)}}, c, nil)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("status=%d Location=%q, want an error flash", rec.Code, rec.Header().Get("Location"))
	}
	page := f.get(t, "/auth/admin", c, nil)
	if strings.Contains(page.Body.String(), "Статические токены") {
		t.Errorf("tokens section must be hidden when tokens are disabled")
	}
}
