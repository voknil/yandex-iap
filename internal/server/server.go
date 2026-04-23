// Package server wires Yandex OAuth, signed sessions and whitelist together
// into HTTP handlers suitable for use as a forward-auth proxy behind Traefik.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/voknil/yandex-iap/internal/config"
	"github.com/voknil/yandex-iap/internal/session"
	"github.com/voknil/yandex-iap/internal/tokens"
	"github.com/voknil/yandex-iap/internal/whitelist"
	"github.com/voknil/yandex-iap/internal/yandex"
)

// Server holds dependencies shared across handlers.
type Server struct {
	Cfg       *config.Config
	OAuth     *yandex.Client
	Whitelist whitelist.Store
	Tokens    tokens.Store
	Log       *slog.Logger

	// Now is injected so tests can fix the clock; production uses time.Now.
	Now func() time.Time
}

// New wires a Server.
func New(cfg *config.Config, log *slog.Logger) *Server {
	s := &Server{
		Cfg:       cfg,
		OAuth:     yandex.New(cfg.ClientID, cfg.ClientSecret, cfg.CallbackURL.String()),
		Whitelist: whitelist.New(cfg.WhitelistFile, 5*time.Second),
		Log:       log,
		Now:       time.Now,
	}
	if cfg.TokensFile != "" {
		s.Tokens = tokens.NewFile(cfg.TokensFile, 5*time.Second)
	}
	return s
}

// Router returns an http.Handler with all public routes registered.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	// Compatibility alias: oauth2-proxy and most tutorials use "/oauth2/callback"
	// as the OAuth redirect URI, so a Yandex app registered for that path keeps
	// working without having to re-register anything. The handler is the same.
	mux.HandleFunc("GET /oauth2/callback", s.handleCallback)
	mux.HandleFunc("GET /auth/verify", s.handleVerify)
	mux.HandleFunc("GET /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/healthz", s.handleHealthz)
	// Admin UI for whitelist management. The auth page itself is CORS-free
	// and only accepts requests with an IAP cookie issued for an ADMIN_EMAILS
	// user; see requireAdmin.
	mux.HandleFunc("GET /auth/admin", s.handleAdminPage)
	mux.HandleFunc("POST /auth/admin/add", s.handleAdminAdd)
	mux.HandleFunc("POST /auth/admin/remove", s.handleAdminRemove)
	mux.HandleFunc("POST /auth/admin/tokens/create", s.handleAdminTokenCreate)
	mux.HandleFunc("POST /auth/admin/tokens/delete", s.handleAdminTokenDelete)
	// Root catch-all: redirect to login, so hitting the bare IAP domain does
	// something useful rather than 404.
	mux.HandleFunc("GET /", s.handleRootFallback)
	return mux
}

// handleLogin starts the OAuth flow.
//
//	GET /auth/login?rd=<original-url>
//
// The rd parameter is embedded into the signed `state` and honoured on
// successful callback.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeRedirect(r.URL.Query().Get("rd"), s.Cfg)
	state, err := session.SignState(s.Cfg.CookieSecret, rd, 10*time.Minute)
	if err != nil {
		s.Log.Error("sign state", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	url := s.OAuth.AuthorizeURL(state, s.Cfg.ScopesJoined())
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback consumes the Yandex callback: exchanges the code, fetches
// userinfo, enforces the whitelist, and sets the session cookie.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		// Yandex returned an error (e.g. user denied consent). Show it plainly.
		s.Log.Warn("oauth provider error",
			"error", errParam, "description", q.Get("error_description"))
		renderError(w, http.StatusForbidden,
			"Login declined: "+q.Get("error_description"))
		return
	}
	code := q.Get("code")
	stateParam := q.Get("state")
	if code == "" || stateParam == "" {
		renderError(w, http.StatusBadRequest, "missing code or state")
		return
	}
	redirect, err := session.VerifyState(s.Cfg.CookieSecret, stateParam)
	if err != nil {
		s.Log.Warn("invalid state")
		renderError(w, http.StatusBadRequest, "invalid or expired login state — try again")
		return
	}

	tok, err := s.OAuth.ExchangeCode(r.Context(), code)
	if err != nil {
		s.Log.Error("exchange code", "err", err)
		renderError(w, http.StatusBadGateway, "could not contact Yandex")
		return
	}
	user, err := s.OAuth.FetchUserInfo(r.Context(), tok.AccessToken)
	if err != nil {
		s.Log.Error("fetch userinfo", "err", err)
		renderError(w, http.StatusBadGateway, "could not read Yandex account info")
		return
	}

	email := user.PrimaryEmail()
	if !s.Whitelist.Allowed(email) {
		s.Log.Info("access denied", "email", email)
		renderAccessDenied(w, email)
		return
	}

	cookieValue, err := session.Issue(s.Cfg.CookieSecret, email, user.Name(), s.Cfg.CookieTTL)
	if err != nil {
		s.Log.Error("issue session", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, cookieValue)
	s.Log.Info("login ok", "email", email, "name", user.Name())

	if redirect == "" {
		redirect = s.Cfg.LoginRedirectDefault
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// handleVerify is the forward-auth endpoint. Traefik/nginx invoke it for every
// upstream request. 2xx → let the request through; 401/302 → redirect browser
// to login.
//
// Traefik sets these headers on the subrequest:
//
//	X-Forwarded-Method
//	X-Forwarded-Proto
//	X-Forwarded-Host
//	X-Forwarded-Uri
//	X-Forwarded-For
//
// We reconstruct the original URL from those when redirecting to /auth/login
// so users land back on the exact page they tried to open.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	origURI := r.Header.Get("X-Forwarded-Uri")
	if s.Cfg.SkipAuthRegex != nil && origURI != "" && s.Cfg.SkipAuthRegex.MatchString(origURI) {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Bearer token path — used by CI jobs, smoke-test scripts and automation that
	// cannot complete an interactive OAuth flow. We probe this first so a
	// forgotten human cookie on the same curl doesn't silently take precedence.
	if s.Tokens != nil {
		if tok := bearerFromRequest(r); tok != "" {
			if rec, ok := s.Tokens.Validate(tok); ok {
				w.Header().Set("X-Auth-Email", "token:"+rec.Name)
				w.Header().Set("X-Auth-Token-Id", rec.ID)
				w.WriteHeader(http.StatusOK)
				return
			}
			s.Log.Info("bearer token rejected",
				"last4", lastN(tok, 4), "path", origURI)
			// Don't redirect a machine client to a browser login page.
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}
	}

	c, err := r.Cookie(s.Cfg.CookieName)
	if err != nil {
		s.redirectToLogin(w, r)
		return
	}
	p, err := session.Verify(s.Cfg.CookieSecret, c.Value)
	if err != nil {
		s.redirectToLogin(w, r)
		return
	}
	if !s.Whitelist.Allowed(p.Email) {
		// Whitelist was tightened while the session was active — revoke.
		s.Log.Info("session revoked (no longer in whitelist)", "email", p.Email)
		s.clearSessionCookie(w)
		s.redirectToLogin(w, r)
		return
	}
	w.Header().Set("X-Auth-Email", p.Email)
	if p.Name != "" {
		w.Header().Set("X-Auth-Name", p.Name)
	}
	w.WriteHeader(http.StatusOK)
}

// bearerFromRequest extracts a bearer token either from the Authorization
// header ("Authorization: Bearer <token>") or from a forwarded-through header
// that upstream proxies may set. Returns "" when nothing plausible is present.
func bearerFromRequest(r *http.Request) string {
	// Forward-auth subrequests get the original headers under X-Forwarded-*.
	// We check the real "Authorization" header first (some reverse proxies
	// propagate it directly) and then the forwarded variant.
	for _, name := range []string{"Authorization", "X-Forwarded-Authorization"} {
		v := r.Header.Get(name)
		if v == "" {
			continue
		}
		const prefix = "Bearer "
		if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
			return strings.TrimSpace(v[len(prefix):])
		}
	}
	return ""
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// handleLogout wipes the session cookie and returns to rd= (or root).
//
// Query parameters:
//
//	rd       — URL to return the user to (constrained to the cookie domain)
//	switch=1 — also route through Yandex Passport logout, so the user can
//	           pick a different Yandex account on the next login. Without
//	           this parameter Yandex would silently sign them back in.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)

	rd := sanitizeRedirect(r.URL.Query().Get("rd"), s.Cfg)
	if rd == "" {
		rd = s.Cfg.LoginRedirectDefault
	}

	if r.URL.Query().Get("switch") == "1" {
		// Yandex Passport honours `retpath` and sends the browser back there
		// after the session is dropped. Then our /auth/login kicks in and the
		// user sees Yandex's account-picker instead of the auto-confirm flow.
		passportLogout := "https://passport.yandex.ru/passport?mode=logout&yu=0&retpath=" +
			url.QueryEscape(rd)
		http.Redirect(w, r, passportLogout, http.StatusFound)
		return
	}

	http.Redirect(w, r, rd, http.StatusFound)
}

// handleHealthz reports liveness and the whitelist load status.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	type status struct {
		Status       string `json:"status"`
		WhitelistLen int    `json:"whitelist_entries"`
		Error        string `json:"error,omitempty"`
	}
	resp := status{Status: "ok"}
	if f, ok := s.Whitelist.(*whitelist.File); ok {
		resp.WhitelistLen = f.Size()
		if e := f.LastError(); e != nil {
			resp.Status = "degraded"
			resp.Error = e.Error()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleRootFallback(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

// --- helpers ---

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	// For forward-auth subrequests, Traefik propagates the originally-requested
	// URL via X-Forwarded-*. Reconstruct it verbatim for the `rd` parameter.
	rd := rebuildOriginalURL(r)

	// Build an absolute Location. Traefik's ForwardAuth resolves relative Locations
	// against the IAP's internal address (http://iap:9090/…), which leaks the
	// container name to the browser. Anchor on X-Forwarded-Proto + X-Forwarded-Host
	// so the browser bounces back to the same public hostname it came from.
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	if proto == "" {
		proto = "https"
	}
	loginURL := "/auth/login"
	if host != "" {
		loginURL = proto + "://" + host + "/auth/login"
	}
	if rd != "" {
		loginURL += "?rd=" + url.QueryEscape(rd)
	}
	w.Header().Set("Location", loginURL)
	w.WriteHeader(http.StatusFound)
}

func rebuildOriginalURL(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	if proto == "" || host == "" {
		return ""
	}
	if uri == "" {
		uri = "/"
	}
	return proto + "://" + host + uri
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.Cfg.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   s.Cfg.CookieDomain,
		Expires:  s.Now().Add(s.Cfg.CookieTTL),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.Cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.Cfg.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// sanitizeRedirect keeps only URLs within the cookie domain to prevent
// open-redirect abuse ("phishing via trusted IAP hostname").
func sanitizeRedirect(raw string, cfg *config.Config) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw // relative path — always safe
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	// Allow only the cookie domain and its subdomains.
	dom := strings.TrimPrefix(cfg.CookieDomain, ".")
	host := strings.ToLower(u.Hostname())
	if host == dom || strings.HasSuffix(host, "."+dom) {
		return u.String()
	}
	return ""
}

func renderError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(msg + "\n"))
}

// renderAccessDenied serves a branded 403 page that explains which email was
// rejected and offers a "Switch account" button routed through Yandex logout.
func renderAccessDenied(w http.ResponseWriter, email string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(accessDeniedHTML(email)))
}

func accessDeniedHTML(email string) string {
	// Keep this inline so the binary is still a single static file with no
	// embedded-filesystem dance. The template uses only html-safe literals
	// plus a single interpolated email which we html-escape.
	safeEmail := htmlEscape(email)
	return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access denied</title>
  <style>
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: #f4f4f5; color: #18181b;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .card {
      background: #ffffff; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.08);
      padding: 40px 36px; max-width: 420px; width: calc(100% - 32px); text-align: center;
    }
    .badge { font-size: 40px; line-height: 1; margin-bottom: 16px; }
    h1 { font-size: 20px; font-weight: 600; margin: 0 0 12px; }
    p  { margin: 0 0 12px; color: #52525b; font-size: 15px; line-height: 1.5; }
    .email { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: #f4f4f5; padding: 2px 6px; border-radius: 6px; color: #18181b; }
    .actions { display: flex; flex-direction: column; gap: 10px; margin-top: 22px; }
    .btn {
      display: inline-block; padding: 10px 16px; border-radius: 10px; font-weight: 500;
      text-decoration: none; font-size: 15px; border: 1px solid transparent; cursor: pointer;
    }
    .btn-primary { background: #18181b; color: #fafafa; }
    .btn-primary:hover { background: #27272a; }
    .btn-secondary { background: transparent; color: #18181b; border-color: #d4d4d8; }
    .btn-secondary:hover { background: #f4f4f5; }
    @media (prefers-color-scheme: dark) {
      body { background: #09090b; color: #fafafa; }
      .card { background: #18181b; box-shadow: 0 10px 30px rgba(0,0,0,.6); }
      p { color: #a1a1aa; }
      .email { background: #27272a; color: #fafafa; }
      .btn-primary { background: #fafafa; color: #09090b; }
      .btn-primary:hover { background: #e4e4e7; }
      .btn-secondary { color: #fafafa; border-color: #3f3f46; }
      .btn-secondary:hover { background: #27272a; }
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="badge">🔒</div>
    <h1>Доступ запрещён</h1>
    <p>Email <span class="email">` + safeEmail + `</span> не входит в список разрешённых для этого окружения.</p>
    <p>Если это ошибка — попросите администратора добавить вас в whitelist, либо войдите под другим аккаунтом Яндекса.</p>
    <div class="actions">
      <a class="btn btn-primary" href="/auth/logout?switch=1">Сменить аккаунт</a>
      <a class="btn btn-secondary" href="https://passport.yandex.ru/">Открыть Яндекс Паспорт</a>
    </div>
  </main>
</body>
</html>`
}

// htmlEscape replaces the five HTML-significant characters so the email can be
// safely interpolated into the response body. We avoid pulling in
// html/template just for a single string.
func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}
