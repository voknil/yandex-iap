package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/voknil/yandex-iap/internal/session"
	"github.com/voknil/yandex-iap/internal/yandex"
)

// loginFixture runs the whole OAuth dance against a fake Yandex.
type loginFixture struct {
	srv     *Server
	handler http.Handler
}

func newLoginFixture(t *testing.T, email string) *loginFixture {
	t.Helper()
	ya := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_, _ = w.Write([]byte(`{"access_token":"AT"}`))
		case "/info":
			_, _ = w.Write([]byte(`{"login":"u","default_email":"` + email + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ya.Close)

	s := newTestServer(t, http.SameSiteLaxMode)
	s.OAuth = yandex.New("cid", "sec", s.Cfg.CallbackURL.String())
	s.OAuth.TokenEndpoint = ya.URL + "/token"
	s.OAuth.UserInfoEndpoint = ya.URL + "/info"
	s.Whitelist = fakeWhitelist{}
	return &loginFixture{srv: s, handler: s.Router()}
}

func (f *loginFixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// start performs GET /auth/login and returns the state and the nonce cookie.
func (f *loginFixture) start(t *testing.T, rd string) (state string, nonce *http.Cookie) {
	t.Helper()
	rec := f.do(httptest.NewRequest(http.MethodGet, "/auth/login?rd="+url.QueryEscape(rd), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == nonceCookieName {
			nonce = c
		}
	}
	if nonce == nil {
		t.Fatal("login did not set the nonce cookie")
	}
	return loc.Query().Get("state"), nonce
}

func (f *loginFixture) callback(state string, c *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+url.QueryEscape(state), nil)
	if c != nil {
		req.AddCookie(c)
	}
	return f.do(req)
}

func TestLoginFlowHappyPath(t *testing.T) {
	f := newLoginFixture(t, "ok@example.com")
	state, nonce := f.start(t, "https://app.example.com/page")

	if !nonce.HttpOnly || !nonce.Secure || nonce.SameSite != http.SameSiteLaxMode || nonce.Path != "/auth" {
		t.Errorf("nonce cookie attributes: %+v", nonce)
	}
	rec := f.callback(state, &http.Cookie{Name: nonce.Name, Value: nonce.Value})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://app.example.com/page" {
		t.Fatalf("callback = %d -> %q", rec.Code, rec.Header().Get("Location"))
	}
	var sess, cleared bool
	for _, c := range rec.Result().Cookies() {
		switch {
		case c.Name == f.srv.Cfg.CookieName && c.Value != "":
			sess = true
			if _, err := session.Verify(f.srv.Cfg.CookieSecret, c.Value); err != nil {
				t.Errorf("session cookie does not verify: %v", err)
			}
		case c.Name == nonceCookieName && c.MaxAge < 0:
			cleared = true
		}
	}
	if !sess || !cleared {
		t.Errorf("session set = %v, nonce cleared = %v", sess, cleared)
	}
}

func TestLoginCSRFRejected(t *testing.T) {
	f := newLoginFixture(t, "ok@example.com")
	state, nonce := f.start(t, "")

	cases := map[string]*http.Cookie{
		"no cookie":    nil,
		"wrong cookie": {Name: nonceCookieName, Value: "attacker"},
		"empty cookie": {Name: nonceCookieName, Value: ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := f.callback(state, c)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == f.srv.Cfg.CookieName {
					t.Error("a session cookie was issued")
				}
			}
		})
	}
	_ = nonce
}

func TestLoginStateWithoutNonceRejected(t *testing.T) {
	f := newLoginFixture(t, "ok@example.com")
	// A state minted the old way (no nonce) must not complete a login.
	st, err := session.SignState(f.srv.Cfg.CookieSecret, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rec := f.callback(st, &http.Cookie{Name: nonceCookieName, Value: ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackRejectsForgedState(t *testing.T) {
	f := newLoginFixture(t, "ok@example.com")
	rec := f.callback("garbage.state", &http.Cookie{Name: nonceCookieName, Value: "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackProviderError(t *testing.T) {
	f := newLoginFixture(t, "ok@example.com")
	rec := f.do(httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&error_description=no", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestCallbackDeniedByWhitelist(t *testing.T) {
	f := newLoginFixture(t, "stranger@example.com")
	f.srv.Whitelist = denyAll{}
	state, nonce := f.start(t, "")
	rec := f.callback(state, &http.Cookie{Name: nonce.Name, Value: nonce.Value})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "stranger@example.com") {
		t.Fatalf("status = %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == f.srv.Cfg.CookieName {
			t.Error("denied user received a session")
		}
	}
}

func TestSecretRotation(t *testing.T) {
	f := newLoginFixture(t, "ok@example.com")
	oldKey := []byte("old-key-old-key-old-key-old-key!")
	cookie, err := session.Issue(oldKey, "ok@example.com", "N", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verify := func() int {
		req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
		req.AddCookie(&http.Cookie{Name: f.srv.Cfg.CookieName, Value: cookie})
		return f.do(req).Code
	}
	if code := verify(); code == http.StatusOK {
		t.Fatal("a session signed with an unknown key must not verify")
	}
	f.srv.Cfg.PreviousSecrets = [][]byte{oldKey}
	if code := verify(); code != http.StatusOK {
		t.Fatalf("a session signed with a previous key must verify, got %d", code)
	}
}

func TestRateLimiting(t *testing.T) {
	f := newLoginFixture(t, "ok@example.com")
	f.srv.Cfg.RateLimit = 3
	h := f.srv.Router()
	hit := func(addr string) int {
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 3; i++ {
		if c := hit("10.0.0.1:1111"); c != http.StatusFound {
			t.Fatalf("request %d = %d", i, c)
		}
	}
	if c := hit("10.0.0.1:2222"); c != http.StatusTooManyRequests {
		t.Fatalf("4th request = %d, want 429", c)
	}
	if c := hit("10.0.0.2:1111"); c != http.StatusFound {
		t.Fatalf("other client = %d, want 302", c)
	}
}

func TestRateLimiterWindowAndKey(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newRateLimiter(1, time.Minute, true, func() time.Time { return now })
	if _, ok := l.allow("a"); !ok {
		t.Fatal("first must pass")
	}
	retry, ok := l.allow("a")
	if ok || retry <= 0 {
		t.Fatalf("second must be limited with a retry hint, got %v %v", retry, ok)
	}
	now = now.Add(time.Minute)
	if _, ok := l.allow("a"); !ok {
		t.Fatal("must pass again after the window")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:99"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	if k := l.clientKey(req); k != "203.0.113.9" {
		t.Errorf("key = %q, want the last XFF entry", k)
	}
	l.useXFF = false
	if k := l.clientKey(req); k != "192.0.2.1" {
		t.Errorf("key = %q, want the socket peer", k)
	}
}

type denyAll struct{ fakeWhitelist }

func (denyAll) Allowed(string) bool { return false }

func TestMetricsCountResponses(t *testing.T) {
	f := newLoginFixture(t, "ok@example.com")
	f.srv.metrics = newMetrics()
	h := f.srv.Router()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/verify", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	rec := httptest.NewRecorder()
	f.srv.Metrics().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`yiap_requests_total{endpoint="verify",code="302"} 1`,
		`yiap_requests_total{endpoint="login",code="302"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "@") {
		t.Error("metrics must not contain identities")
	}
}
