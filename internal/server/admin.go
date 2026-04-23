package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/voknil/yandex-iap/internal/session"
	"github.com/voknil/yandex-iap/internal/whitelist"
)

// adminCSRFTTL bounds how long a form token stays valid before we expect the
// user to refresh the page.
const adminCSRFTTL = 30 * time.Minute

// requireAdmin returns the admin's email if the request carries a valid IAP
// cookie AND that email is in ADMIN_EMAILS. Otherwise it writes an appropriate
// response and returns the empty string — the caller should just `return`.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(s.Cfg.CookieName)
	if err != nil {
		// No cookie — bounce through regular login first. Preserve the URI.
		s.redirectToLogin(w, r)
		return ""
	}
	p, err := session.Verify(s.Cfg.CookieSecret, c.Value)
	if err != nil {
		s.redirectToLogin(w, r)
		return ""
	}
	if !s.Cfg.IsAdmin(p.Email) {
		s.Log.Info("admin access denied",
			"email", p.Email, "path", r.URL.Path)
		renderError(w, http.StatusForbidden,
			"This page is only accessible to administrators.")
		return ""
	}
	return p.Email
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == "" {
		return
	}
	csrf, err := session.SignState(s.Cfg.CookieSecret, admin, adminCSRFTTL)
	if err != nil {
		s.Log.Error("sign csrf", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	emails := s.Whitelist.List()

	notice := r.URL.Query().Get("notice")
	errMsg := r.URL.Query().Get("error")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(adminPageHTML(admin, csrf, emails, notice, errMsg)))
}

func (s *Server) handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == "" {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminRedirect(w, r, "", "could not parse form")
		return
	}
	if !s.csrfOK(admin, r.PostFormValue("_csrf")) {
		s.adminRedirect(w, r, "", "session expired — reload the page and try again")
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	if err := s.Whitelist.Add(email); err != nil {
		msg := "could not add: " + err.Error()
		if errors.Is(err, whitelist.ErrInvalidEmail) {
			msg = "не похоже на email: " + email
		}
		s.adminRedirect(w, r, "", msg)
		return
	}
	s.Log.Info("whitelist add",
		"admin", admin, "target", email)
	s.adminRedirect(w, r, "added "+email, "")
}

func (s *Server) handleAdminRemove(w http.ResponseWriter, r *http.Request) {
	admin := s.requireAdmin(w, r)
	if admin == "" {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminRedirect(w, r, "", "could not parse form")
		return
	}
	if !s.csrfOK(admin, r.PostFormValue("_csrf")) {
		s.adminRedirect(w, r, "", "session expired — reload the page and try again")
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	if email == admin {
		s.adminRedirect(w, r, "",
			"refusing to remove yourself — ask another admin to do it")
		return
	}
	if err := s.Whitelist.Remove(email); err != nil {
		s.adminRedirect(w, r, "", "could not remove: "+err.Error())
		return
	}
	s.Log.Info("whitelist remove",
		"admin", admin, "target", email)
	s.adminRedirect(w, r, "removed "+email, "")
}

// csrfOK verifies the posted _csrf token was issued for this admin in the last
// adminCSRFTTL. Since SignState embeds a TTL and binds the redirect param to
// the HMAC, we reuse it: the "redirect" payload is the admin's email.
func (s *Server) csrfOK(adminEmail, token string) bool {
	embedded, err := session.VerifyState(s.Cfg.CookieSecret, token)
	if err != nil {
		return false
	}
	return embedded == adminEmail
}

func (s *Server) adminRedirect(w http.ResponseWriter, r *http.Request, notice, errMsg string) {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if proto == "" {
		proto = "https"
	}
	u := proto + "://" + host + "/auth/admin"
	sep := "?"
	if notice != "" {
		u += sep + "notice=" + escapeQueryValue(notice)
		sep = "&"
	}
	if errMsg != "" {
		u += sep + "error=" + escapeQueryValue(errMsg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// escapeQueryValue is a tiny wrapper to keep the redirect URLs readable; we
// avoid url.QueryEscape turning every space into "+" when the message goes
// back into the rendered page.
func escapeQueryValue(s string) string {
	return strings.NewReplacer(
		" ", "%20",
		"&", "%26",
		"#", "%23",
		"?", "%3F",
		"=", "%3D",
	).Replace(s)
}

// adminPageHTML renders the admin UI. Kept inline to keep the binary a single
// static file (no embedded filesystem).
func adminPageHTML(admin, csrf string, emails []string, notice, errMsg string) string {
	var rows strings.Builder
	for _, e := range emails {
		rows.WriteString(`<tr><td class="email">`)
		rows.WriteString(htmlEscape(e))
		rows.WriteString(`</td><td><form method="post" action="/auth/admin/remove"><input type="hidden" name="_csrf" value="`)
		rows.WriteString(htmlEscape(csrf))
		rows.WriteString(`"><input type="hidden" name="email" value="`)
		rows.WriteString(htmlEscape(e))
		rows.WriteString(`"><button type="submit" class="btn-remove" `)
		if e == admin {
			rows.WriteString(`disabled title="refusing to remove yourself"`)
		} else {
			rows.WriteString(`onclick="return confirm('Remove ' + this.form.email.value + '?')"`)
		}
		rows.WriteString(`>удалить</button></form></td></tr>`)
	}

	return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IAP admin — whitelist</title>
  <style>
    :root {
      --bg: #f4f4f5; --card: #ffffff; --text: #18181b; --muted: #52525b;
      --border: #e4e4e7; --accent: #18181b; --danger: #dc2626; --ok: #16a34a;
    }
    @media (prefers-color-scheme: dark) {
      :root { --bg: #09090b; --card: #18181b; --text: #fafafa; --muted: #a1a1aa; --border: #27272a; --accent: #fafafa; }
    }
    body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--text);
           font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    main { max-width: 680px; margin: 40px auto; padding: 0 16px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 16px;
            padding: 24px; box-shadow: 0 4px 16px rgba(0,0,0,.04); }
    h1 { font-size: 22px; margin: 0 0 6px; }
    .sub { color: var(--muted); font-size: 14px; margin: 0 0 20px; }
    .sub a { color: var(--muted); }
    .flash { padding: 10px 14px; border-radius: 10px; font-size: 14px; margin-bottom: 16px; }
    .flash-ok { background: rgba(22,163,74,.12); color: var(--ok); }
    .flash-err { background: rgba(220,38,38,.12); color: var(--danger); }
    form.add { display: flex; gap: 8px; margin-bottom: 20px; }
    form.add input[type=email] { flex: 1; min-width: 0; padding: 10px 12px; border-radius: 10px;
                                 border: 1px solid var(--border); background: var(--bg); color: var(--text); font-size: 15px; }
    form.add button { padding: 10px 16px; border-radius: 10px; border: 0; background: var(--accent);
                      color: var(--bg); font-size: 15px; cursor: pointer; font-weight: 500; }
    form.add button:hover { opacity: .9; }
    table { width: 100%; border-collapse: collapse; }
    td { padding: 10px 8px; border-bottom: 1px solid var(--border); font-size: 15px; vertical-align: middle; }
    td.email { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    tr:last-child td { border-bottom: 0; }
    button.btn-remove { background: transparent; color: var(--danger); border: 1px solid var(--border);
                        padding: 6px 10px; border-radius: 8px; font-size: 13px; cursor: pointer; }
    button.btn-remove:hover:not(:disabled) { border-color: var(--danger); }
    button.btn-remove:disabled { opacity: .4; cursor: not-allowed; }
    .footer { margin-top: 20px; font-size: 13px; color: var(--muted); text-align: center; }
    .footer a { color: var(--muted); }
  </style>
</head>
<body>
  <main>
    <div class="card">
      <h1>Whitelist · IAP</h1>
      <p class="sub">Управление списком email-ов, которым разрешён вход.
         Вы вошли как <strong>` + htmlEscape(admin) + `</strong> · <a href="/auth/logout?switch=1">Сменить аккаунт</a></p>
` + flashes(notice, errMsg) + `
      <form class="add" method="post" action="/auth/admin/add">
        <input type="hidden" name="_csrf" value="` + htmlEscape(csrf) + `">
        <input type="email" name="email" placeholder="user@yandex.ru" required autofocus>
        <button type="submit">Добавить</button>
      </form>
      <table>
        <tbody>
` + rows.String() + `
        </tbody>
      </table>
    </div>
    <p class="footer">yandex-iap · <a href="https://github.com/voknil/yandex-iap">github</a></p>
  </main>
</body>
</html>`
}

func flashes(ok, err string) string {
	out := ""
	if ok != "" {
		out += `<div class="flash flash-ok">✓ ` + htmlEscape(ok) + `</div>`
	}
	if err != "" {
		out += `<div class="flash flash-err">✕ ` + htmlEscape(err) + `</div>`
	}
	return out
}
