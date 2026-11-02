# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-02

### Added
- CI: lint (golangci-lint v2), test matrix (Go 1.22 and stable) with the race
  detector and a coverage summary, `govulncheck`, multi-arch image build with
  SBOM and build provenance.
- Release automation: tagged versions publish binaries (linux, macOS, Windows;
  amd64, arm64), checksums and generated release notes.
- Dependabot for GitHub Actions, Go modules and the Docker base image.
- Documentation: restructured README, `docs/architecture.md` (login sequence diagram, design decisions),
  `docs/security.md` (threat model), `CONTRIBUTING.md`.
- `SECURITY.md`, issue and pull request templates, `Makefile`, `.editorconfig`.

### Security
- **Fixed an open redirect** in `sanitizeRedirect`: a path such as `/\evil.com` was accepted
  as "relative", but browsers read the backslash as a slash and treat it as `//evil.com`.
  Backslashes and control characters are now rejected, only `http(s)` targets are allowed and URLs
  carrying credentials are refused. Covered by a table test and a fuzz test.
- **A newly created static token is no longer passed through the URL.** It used to travel in
  `?new_token=…` (browser history, proxy and access logs). It is now shown only in the response
  to the creating `POST`, with `Cache-Control: no-store`; the query parameter is ignored.
- **Fixed script injection through a token name** in the admin UI: the name was placed inside an
  inline `onclick` handler, where HTML entities are decoded before JavaScript runs. Confirmation
  prompts now read a `data-confirm` attribute.
- Admin redirects are relative and no longer built from `X-Forwarded-Host`.
- Strict `Content-Security-Policy` (per-response nonce, `default-src 'none'`, `frame-ancestors 'none'`)
  on the admin and "access denied" pages; `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` and `Cache-Control: no-store` on every response.

- **Login CSRF protection.** The OAuth `state` now carries a random nonce that is also stored in a
  short-lived `HttpOnly` cookie on the browser that started the login; the callback rejects a
  state that comes back without the matching cookie.
- **Cookie secret rotation.** `COOKIE_SECRET_PREVIOUS` (comma-separated) lists old secrets that are
  still accepted for verification, so the secret can be changed without logging everyone out.
- **Rate limiting** of `/auth/login` and `/auth/callback` per client (`RATE_LIMIT`, default 60/min,
  `0` disables; `TRUST_FORWARDED_FOR` keys it on the proxy-supplied address).

- `*@example.com` (or `@example.com`) whitelist entries admit a whole domain.
- `yandex-iap -version` and `yandex-iap -healthcheck`; the Docker image now has a `HEALTHCHECK`.

- **Token expiry.** Static tokens get a lifetime chosen in the admin UI (7 days to 1 year, or
  never); expired tokens stop validating and are marked in the list. Records without
  `expires_at` keep working as before.
- **Prometheus metrics** (`yiap_requests_total` by endpoint and status) on a separate listener,
  enabled with `METRICS_LISTEN`; never exposed on the public port.

### Changed
- `tokens.Store.Create` takes a lifetime argument.
- Yandex endpoints are configurable on the client (used by tests against a fake server).
- Test coverage raised across `config`, `yandex`, `session` and the full login flow.
- Docker image `:latest` now points to the latest **release**; builds from `main`
  are published as `:edge`.
- Build image bumped to Go 1.24.

## [0.1.0] - baseline

The state of the project before release automation was introduced.

### Features
- Forward-auth endpoint (`/auth/verify`) for Traefik, nginx, Caddy and others.
- Yandex ID OAuth 2.0 login with a signed `state` carrying the post-login redirect.
- HMAC-SHA256 signed, stateless session cookies (`Secure`, `HttpOnly`, configurable `SameSite`).
- File-backed e-mail whitelist with hot reload (about 5 seconds) and instant revocation.
- Admin web UI (`/auth/admin`) with CSRF protection for managing the whitelist.
- Static bearer tokens for CI and automation (`yiap_…`, only a SHA-256 digest is stored).
- Open-redirect protection restricted to the cookie domain.
- CORS support for cross-origin credentialed requests between sibling subdomains.
- Branded 403 page with a "switch account" flow through Yandex Passport logout.
- Health endpoint, structured JSON logs (`log/slog`), graceful shutdown.
- Distroless, non-root, multi-arch container image.
