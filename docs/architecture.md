# Architecture

`yandex-iap` is a small HTTP service with three jobs: start and finish an OAuth 2.0 login with Yandex ID, decide for every forwarded request whether it may pass, and let administrators manage who is allowed.

## Components

```
main.go                  flags, config, listeners, graceful shutdown
internal/config          environment → validated Config
internal/server          HTTP handlers, security headers, rate limiter, metrics, admin UI
internal/session         HMAC-signed session cookies and OAuth state
internal/yandex          OAuth client for oauth.yandex.ru / login.yandex.ru
internal/whitelist       file-backed allow-list (emails and *@domain), hot reload
internal/tokens          file-backed static bearer tokens (SHA-256 hashes, expiry)
```

State lives in two small files (whitelist, tokens) and in the signed cookies. Nothing else is persisted, so any number of replicas can serve the same users as long as they share `COOKIE_SECRET` and see the same files.

## Login flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant P as Reverse proxy
    participant I as yandex-iap
    participant Y as Yandex

    B->>P: GET /page
    P->>I: GET /auth/verify (forwarded headers)
    I-->>P: 302 /auth/login?rd=/page
    P-->>B: 302
    B->>I: GET /auth/login?rd=…
    Note over I: nonce = random;<br/>state = HMAC(rd, nonce, exp)
    I-->>B: 302 Yandex authorize + Set-Cookie _yiap_login=nonce
    B->>Y: authorize
    Y-->>B: 302 /auth/callback?code&state
    B->>I: GET /auth/callback (+ _yiap_login cookie)
    Note over I: verify state signature and expiry;<br/>cookie must equal the nonce in state
    I->>Y: POST /token (code)
    Y-->>I: access_token
    I->>Y: GET /info
    Y-->>I: email, name
    Note over I: whitelist check
    I-->>B: 302 rd + Set-Cookie _yiap=signed session
    B->>P: GET /page (cookie)
    P->>I: GET /auth/verify
    I-->>P: 200 + X-Auth-Email, X-Auth-Name
    P-->>B: page
```

## Decisions

**Stateless sessions.** The cookie carries `{email, name, iat, exp}` and an HMAC-SHA256 signature. There is no session store to run or lose. The price is that a cookie cannot be revoked individually; instead every request is re-checked against the whitelist, so removing an address takes effect immediately.

**Whitelist re-checked on every verify.** Authorization is not baked into the cookie. The cookie proves identity; the file decides access. Reads are cached for a few seconds and the previous list is kept if the file becomes unreadable, so a bad edit does not lock everyone out.

**State bound to the browser.** The OAuth `state` is signed and contains a nonce that is also set as an `HttpOnly` cookie on `/auth`. Without this binding an attacker could start a login with their own account and trick a victim into completing it (login CSRF).

**Secret rotation.** Signing always uses `COOKIE_SECRET`; verification tries the current key and then each key in `COOKIE_SECRET_PREVIOUS`. Every key is checked on each verification so timing does not reveal which one matched.

**No dependencies.** The standard library covers HTTP, JSON, HMAC and structured logging. That keeps the supply-chain surface and the image small, and makes `govulncheck` results meaningful.

**Metrics on their own port.** Counters are served by a separate listener (`METRICS_LISTEN`) so they are never reachable through the public forward-auth route.

**File-backed stores with atomic writes.** Whitelist and token files are rewritten through a temp file and `rename`, so readers never see a partial file. The mounted directory therefore has to be writable by the container user.

## Request handling

Every response passes through a middleware that sets `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Cache-Control: no-store`. HTML pages additionally get a per-response CSP nonce. `/auth/login` and `/auth/callback` sit behind a per-client fixed-window rate limiter. `/auth/verify`, `/auth/login` and `/auth/callback` are counted by status code.
