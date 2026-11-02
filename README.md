# yandex-iap

A lightweight **forward-auth Identity-Aware Proxy** that authenticates users against **Yandex ID** (OAuth 2.0) and puts them through a whitelist before they reach your application.

Written because [`oauth2-proxy`](https://github.com/oauth2-proxy/oauth2-proxy) has dropped its Yandex provider and [`vouch-proxy`](https://github.com/vouch/vouch-proxy) never shipped one. Yandex ID is not a full OIDC provider (no `id_token`), so `yandex-iap` talks plain OAuth 2.0 + calls `login.yandex.ru/info` to resolve the user's email.

[![CI](https://github.com/voknil/yandex-iap/actions/workflows/ci.yml/badge.svg)](https://github.com/voknil/yandex-iap/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/voknil/yandex-iap.svg)](https://pkg.go.dev/github.com/voknil/yandex-iap)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## What it does

```
                      ┌─────────────┐
user ─── GET /page ─▶ │   Traefik   │ ── forwardAuth ─▶ yandex-iap /auth/verify
                      │   (or nginx)│                       │
                      │             │  ◀── 200 + headers ───┤ cookie valid + whitelisted
                      │             │  ◀── 302 /auth/login ─┤ no cookie
                      └──────┬──────┘
                             │ if 200
                             ▼
                        upstream app
```

On success, `/auth/verify` returns `200` with identity headers the upstream can trust:

| Header | Example |
|---|---|
| `X-Auth-Email` | `alice@yandex.ru` |
| `X-Auth-Name`  | `Alice Example`  |

On failure, the user is redirected to `/auth/login`, which starts an OAuth dance with Yandex and returns them to the page they originally tried to open.

## Features

- **Single static binary, zero third-party dependencies** — distroless, `nonroot` image for `linux/amd64` and `linux/arm64`, published to GHCR with an SBOM and build provenance.
- **Stateless sessions** — cookies are HMAC-SHA256 signed; no Redis, no database. Secret rotation without logging users out (`COOKIE_SECRET_PREVIOUS`).
- **Whitelist hot-reload** — exact addresses or whole domains (`*@example.com`); edits apply within seconds, no restart. Removing an address revokes live sessions at the next request.
- **Admin UI** at `/auth/admin` — manage the whitelist and static tokens in the browser (gated by `ADMIN_EMAILS`), served under a strict CSP.
- **Static bearer tokens** for CI and automation — shown once, stored as SHA-256 hashes, validated in constant time, optional expiry, instantly revocable.
- **Hardened login flow** — state bound to the browser (login CSRF), validated post-login redirects, per-client rate limiting, security headers on every response.
- **Operable** — structured JSON logs, `/auth/healthz`, `-healthcheck` for container probes, optional Prometheus metrics on a separate port.
- **Tested** — table, fuzz and end-to-end tests against a fake Yandex; CI runs lint, `-race` tests, `govulncheck` and a multi-arch image build.

Design notes live in [docs/architecture.md](docs/architecture.md); the threat model is in [docs/security.md](docs/security.md).

## Quick start

### 1. Register an OAuth app at Yandex

<https://oauth.yandex.ru/client/new>

- Platform: **Web services**
- Redirect URI: `https://<your-domain>/auth/callback`
- Scopes: `login:email`, `login:info`

Keep the `Client ID` and `Client secret` at hand.

### 2. Run it

```bash
docker run --rm -p 9090:9090 \
  -e YANDEX_CLIENT_ID=... \
  -e YANDEX_CLIENT_SECRET=... \
  -e CALLBACK_URL=https://app.example.com/auth/callback \
  -e COOKIE_DOMAIN=.example.com \
  -e COOKIE_SECRET="$(openssl rand -base64 32)" \
  -e WHITELIST_FILE=/etc/iap/allowed-emails.txt \
  -v $PWD/allowed-emails.txt:/etc/iap/allowed-emails.txt:ro \
  ghcr.io/voknil/yandex-iap:latest
```

`allowed-emails.txt`:
```
# one entry per line; comments and blank lines are ignored
alice@yandex.ru
bob@example.com
# everyone at a domain
*@example.org
```

### 3. Wire it into your reverse proxy

#### Traefik (docker-compose labels)

```yaml
services:
  iap:
    image: ghcr.io/voknil/yandex-iap:latest
    env_file: ./iap.env
    volumes:
      - ./allowed-emails.txt:/etc/iap/allowed-emails.txt:ro
    labels:
      - traefik.enable=true
      - traefik.http.services.iap.loadbalancer.server.port=9090
      # /auth/* must go to the IAP itself (no middleware on these!)
      - traefik.http.routers.iap.rule=Host(`app.example.com`) && PathPrefix(`/auth`)
      - traefik.http.routers.iap.entrypoints=websecure
      - traefik.http.routers.iap.tls=true
      - traefik.http.routers.iap.service=iap
      # Middleware: ForwardAuth to iap:9090/auth/verify
      - traefik.http.middlewares.iap-auth.forwardauth.address=http://iap:9090/auth/verify
      - traefik.http.middlewares.iap-auth.forwardauth.trustForwardHeader=true
      - traefik.http.middlewares.iap-auth.forwardauth.authResponseHeaders=X-Auth-Email,X-Auth-Name

  app:
    image: your/app
    labels:
      - traefik.enable=true
      - traefik.http.routers.app.rule=Host(`app.example.com`)
      - traefik.http.routers.app.entrypoints=websecure
      - traefik.http.routers.app.tls=true
      - traefik.http.routers.app.middlewares=iap-auth@docker
      - traefik.http.services.app.loadbalancer.server.port=8080
```

See [examples/traefik/](examples/traefik/) for a runnable compose file with TLS via Let's Encrypt.

#### nginx (`auth_request`)

```nginx
# Upstream IAP
upstream iap {
    server 127.0.0.1:9090;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    # OAuth endpoints: proxy to IAP unchanged
    location /auth/ {
        proxy_pass http://iap;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-Uri   $request_uri;
    }

    # Subrequest for every protected request
    location = /_iap_verify {
        internal;
        proxy_pass http://iap/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Proto  $scheme;
        proxy_set_header X-Forwarded-Host   $host;
        proxy_set_header X-Forwarded-Uri    $request_uri;
    }

    # Everything else is gated through /_iap_verify
    location / {
        auth_request /_iap_verify;
        auth_request_set $auth_email $upstream_http_x_auth_email;
        auth_request_set $auth_name  $upstream_http_x_auth_name;
        proxy_set_header X-Auth-Email $auth_email;
        proxy_set_header X-Auth-Name  $auth_name;

        # 302 redirects from /auth/verify → bounce to /auth/login
        error_page 401 = @to_login;

        proxy_pass http://127.0.0.1:8080;
    }

    location @to_login {
        return 302 /auth/login?rd=$scheme://$host$request_uri;
    }
}
```

#### Caddy

```caddyfile
app.example.com {
    handle /auth/* {
        reverse_proxy iap:9090
    }

    forward_auth iap:9090 {
        uri /auth/verify
        copy_headers X-Auth-Email X-Auth-Name
    }

    reverse_proxy app:8080
}
```

## Configuration

All knobs are environment variables.

### Required

| Var | Description |
|---|---|
| `YANDEX_CLIENT_ID` | Client ID from https://oauth.yandex.ru/client/... |
| `YANDEX_CLIENT_SECRET` | Client secret (pair with the ID) |
| `CALLBACK_URL` | Full HTTPS URL; must match a Redirect URI registered in the Yandex app (e.g. `https://app.example.com/auth/callback`) |
| `COOKIE_DOMAIN` | Cookie domain (e.g. `.example.com` to share across subdomains, or `app.example.com` to restrict) |
| `COOKIE_SECRET` | Random string ≥ 32 chars (`openssl rand -base64 32`). Changing it invalidates all sessions unless the old value is moved to `COOKIE_SECRET_PREVIOUS`. |
| `WHITELIST_FILE` | Path to the newline-delimited allow-list inside the container |
| `ADMIN_EMAILS` | Comma-separated list of admins allowed to open `/auth/admin`. Other whitelist users see 403 on that path. |

### Optional

| Var | Default | Description |
|---|---|---|
| `SCOPES` | `login:email login:info` | Space-separated OAuth scopes |
| `COOKIE_NAME` | `_yiap` | Name of the session cookie |
| `COOKIE_TTL` | `24h` | How long a session remains valid |
| `COOKIE_SAMESITE` | `lax` | `SameSite` attribute of the session cookie: `lax`, `none`, or `strict`. Use `none` for multi-subdomain deployments where the browser makes credentialed cross-origin fetches between sibling subdomains — the cookie is always marked `Secure`, so `None` is safe. |
| `SKIP_AUTH_REGEX` | *(empty)* | Regex against `X-Forwarded-Uri`; matches bypass authentication. E.g. `^/(healthz|api/health)$` |
| `LOGIN_REDIRECT_DEFAULT` | `/` | Fallback redirect when `rd` is missing or invalid |
| `COOKIE_SECRET_PREVIOUS` | *(empty)* | Comma-separated older secrets (≥ 32 chars each) still accepted for **verification**, so `COOKIE_SECRET` can be rotated without logging everyone out. Remove them after `COOKIE_TTL` has passed. |
| `RATE_LIMIT` | `60` | Login/callback requests per minute per client; `0` disables |
| `TRUST_FORWARDED_FOR` | `false` | Key the rate limit on the last `X-Forwarded-For` entry (set this behind a reverse proxy, otherwise every client looks like the proxy) |
| `METRICS_LISTEN` | *(empty)* | Address for Prometheus metrics, e.g. `127.0.0.1:9091`. Empty disables them. Served on its own port, never on `LISTEN`. |
| `TOKENS_FILE` | *(empty)* | Path to a JSON file for static bearer tokens. Empty disables tokens entirely (no Bearer probing in `/verify`, no card in `/admin`). |
| `LISTEN` | `:9090` | TCP bind address |
| `LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |

### File ownership for mounted volumes

The image runs as the distroless `nonroot` user (**UID 65532**). Writing to the
files is not enough — `allowed-emails.txt` and `tokens.json` both get
rewritten atomically (tempfile + `rename`), so yandex-iap needs write access
to the **directory that contains them** too, not just the files themselves.

**Recommended**: bind-mount a whole directory, own it by UID 65532.

```bash
mkdir -p iap-data
printf '# seed here\nalice@yandex.ru\n' > iap-data/allowed-emails.txt
printf '[]\n'                             > iap-data/tokens.json
sudo chown -R 65532:65532 iap-data
```

```yaml
volumes:
  - ./iap-data:/etc/iap:rw
```

…and point `WHITELIST_FILE=/etc/iap/allowed-emails.txt` and `TOKENS_FILE=/etc/iap/tokens.json` at them.

**Not recommended**: bind-mounting the two files individually. The container's
`/etc/iap` would belong to `root` (docker defaults), the atomic rewrite would
need to create `/etc/iap/.iap-tokens-XXXX` as UID 65532 and get `permission denied`.

## Endpoints

| Path | Purpose |
|---|---|
| `GET /auth/login?rd=<url>` | Start OAuth flow. `rd` is remembered (signed in the `state` param) and honoured after callback. |
| `GET /auth/callback` *(alias: `/oauth2/callback`)* | Yandex redirects here with `code` + `state`. Sets the session cookie and redirects back to `rd`. |
| `GET /auth/verify` | Forward-auth endpoint. `200` + identity headers = allow, `302 /auth/login` = deny for humans, `401` for bad bearer tokens. |
| `GET /auth/logout?rd=<url>&switch=1` | Clear the session cookie. `switch=1` also routes through Yandex Passport logout so the next login can pick a different account. |
| `GET /auth/healthz` | JSON liveness + whitelist size. Always public. |
| `GET /metrics` *(on `METRICS_LISTEN` only)* | Prometheus counters. |
| `GET /auth/admin` | Admin UI — whitelist table + static-tokens table. Requires a cookie from an `ADMIN_EMAILS` user. |
| `POST /auth/admin/{add,remove}` | Whitelist mutations. CSRF-protected. |
| `POST /auth/admin/tokens/{create,delete}` | Static-token mutations. CSRF-protected. |

## Static bearer tokens

For CI jobs, smoke-test scripts and any automation that can't complete an interactive
OAuth flow, admins can mint long-lived bearer tokens at `/auth/admin`.

```bash
# In the UI: name the token ("cypress smoke tests"), pick a lifetime, click "Создать". The
# plaintext value (yiap_<40 hex>) is displayed ONCE — save it immediately.

# Use it from any client:
curl -H "Authorization: Bearer yiap_abc..." https://app.example.com/

# Upstream apps see these headers on a successful token auth:
#   X-Auth-Email:    token:<name>     (prefix makes machine identities obvious in audit logs)
#   X-Auth-Token-Id: tok_<8 hex>      (stable handle for revocation)
```

Properties:

- 160-bit entropy (`crypto/rand`)
- Persisted as SHA-256 hash + last-4 fingerprint only — a leaked file does not expose active credentials
- Constant-time comparison on validate
- Invalid tokens return `401` (not `302` to a login page) — curl/Postman-friendly
- Optional expiry (7 days to 1 year, or never); an expired token stops working without any cleanup
- Revoke instantly from the UI; any in-flight request using the old token gets 401
- Forwarded through `X-Forwarded-Authorization` as well as `Authorization`, so reverse proxies that mangle the original header can re-inject it

## Security notes

The full threat model is in [docs/security.md](docs/security.md). In short:

- Cookies are `Secure`, `HttpOnly` and signed; HTTPS is mandatory in production.
- The OAuth `state` is signed, short-lived and bound to the browser that started the login, so a callback URL cannot be replayed into another browser.
- `rd` redirect targets are limited to the cookie domain; backslashes, control characters, credentials in the URL and non-http(s) schemes are refused (covered by a fuzz test).
- The admin and error pages are served with a nonce-based `Content-Security-Policy`; every response carries `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- Admin forms are CSRF-protected; a newly created token is shown only in the response to the creating `POST`, never in a URL.
- Revoke a user by removing them from the whitelist: their cookie still verifies, but is denied at the next request.
- `yandex-iap` does not use PKCE or an OIDC nonce because Yandex does not issue `id_token`s.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Development

```bash
make check      # vet + golangci-lint + tests with the race detector
make cover      # coverage summary
make build      # static binary in ./bin
go test -fuzz=FuzzSanitizeRedirect -fuzztime=30s ./internal/server
```

Go 1.22 or newer. Tagged releases publish binaries (Linux, macOS, Windows) and the container image; see the [changelog](CHANGELOG.md).

## FAQ

**Why not use OIDC?** Yandex's OAuth 2.0 endpoints don't return `id_token`, and `login.yandex.ru` doesn't expose a standards-compliant `.well-known/openid-configuration`. Generic OIDC proxies try to fetch those and fail. `yandex-iap` talks raw OAuth 2.0 + the `userinfo` endpoint, which is what Yandex actually supports.

**What about refresh tokens?** Not used. The session cookie carries the email; when it expires (`COOKIE_TTL`) the user clicks through the Yandex consent screen again — which is instant for already-granted apps.

**Can I put it behind a CDN?** Yes, as long as the CDN passes `X-Forwarded-*` headers through untouched and does not cache `/auth/*` or the forward-auth subrequest.

## Contributing

PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Ideas that would be especially useful: more reverse-proxy recipes (HAProxy, Envoy), alternative whitelist backends, and group-based access.

## License

MIT. See [LICENSE](LICENSE).

---

## По-русски (кратко)

`yandex-iap` — это сервис forward-auth для связки с Traefik / nginx / Caddy, который заставляет пользователя сначала залогиниться через Яндекс ID (OAuth 2.0), а потом проверяет его email по белому списку.

Зачем: `oauth2-proxy` выпилил провайдер Yandex, `vouch-proxy` его не поддерживал, а Яндекс не полноценный OIDC — штатные решения не работают.

Как использовать — см. «Quick start» выше. Все параметры передаются через env, белый список лежит текстовым файлом и перечитывается каждые 5 секунд, так что добавить нового пользователя — это `echo 'user@yandex.ru' >> allowed-emails.txt`, без рестарта.

Issue / PR на русском языке — тоже welcome.
