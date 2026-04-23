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
	"github.com/voknil/yandex-iap/internal/whitelist"
	"github.com/voknil/yandex-iap/internal/yandex"
)

// Server holds dependencies shared across handlers.
type Server struct {
	Cfg       *config.Config
	OAuth     *yandex.Client
	Whitelist whitelist.Checker
	Log       *slog.Logger

	// Now is injected so tests can fix the clock; production uses time.Now.
	Now func() time.Time
}

// New wires a Server.
func New(cfg *config.Config, log *slog.Logger) *Server {
	return &Server{
		Cfg:       cfg,
		OAuth:     yandex.New(cfg.ClientID, cfg.ClientSecret, cfg.CallbackURL.String()),
		Whitelist: whitelist.New(cfg.WhitelistFile, 5*time.Second),
		Log:       log,
		Now:       time.Now,
	}
}

// Router returns an http.Handler with all public routes registered.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("GET /auth/verify", s.handleVerify)
	mux.HandleFunc("GET /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/healthz", s.handleHealthz)
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
		renderError(w, http.StatusForbidden,
			"Access denied: "+email+" is not on the allow-list.\n"+
				"Доступ запрещён: "+email+" не в списке разрешённых.")
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

// handleLogout wipes the session cookie and returns to rd= (or root).
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)
	rd := sanitizeRedirect(r.URL.Query().Get("rd"), s.Cfg)
	if rd == "" {
		rd = s.Cfg.LoginRedirectDefault
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
