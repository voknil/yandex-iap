# Security model

## Assets and trust boundaries

- **Users** authenticate with Yandex ID; `yandex-iap` trusts Yandex to prove who they are and its own whitelist to decide whether they may enter.
- **The reverse proxy** is trusted to forward `X-Forwarded-*` headers faithfully and to strip identity headers (`X-Auth-*`) from incoming requests before setting its own.
- **`COOKIE_SECRET`** is the root of trust for sessions. Whoever holds it can mint a session for any address.
- **The whitelist and token files** are trusted input; they must not be writable by untrusted users.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Open redirect through `rd` | Only same-origin paths or http(s) URLs on the cookie domain are accepted; backslashes, control characters, credentials and other schemes are refused. Fuzz-tested. |
| Login CSRF (attacker signs the victim into the attacker's account) | State carries a nonce that must match an `HttpOnly` cookie on the same browser. |
| Forged or replayed state / session | HMAC-SHA256 signature, expiry (10 minutes for state, `COOKIE_TTL` for sessions), constant-time comparison. |
| Stolen session cookie | `Secure`, `HttpOnly`, configurable `SameSite`; access re-checked against the whitelist on every request; removing the address ends access. |
| Brute force or amplification of login endpoints | Per-client rate limit; Yandex is only contacted after the state verified. |
| XSS in the admin UI (e.g. through a token name) | All dynamic values are HTML-escaped; confirmation prompts use `data-` attributes instead of inline handlers; CSP with `default-src 'none'` and per-response nonces. |
| CSRF on admin actions | Signed, expiring token bound to the admin's email, required on every POST. |
| Token leakage | Shown once in a `no-store` response, never in a URL; only SHA-256 digests are stored; optional expiry; constant-time comparison. |
| Clickjacking | `X-Frame-Options: DENY` and `frame-ancestors 'none'`. |
| Secret exposure in logs | Secrets and full tokens are never logged; the startup log shows only a short fingerprint of the cookie secret, and rejected tokens are logged by their last four characters. |
| Vulnerable dependencies | None besides the standard library; `govulncheck` and Dependabot run in CI. |

## Out of scope

- Authorization beyond "is this address allowed" (roles, per-path rules) — use the identity headers in the upstream application or the proxy.
- Protecting the upstream if it is reachable without going through the proxy.
- Compromise of the host, the container runtime or Yandex ID itself.

## Operational advice

- Generate the secret with `openssl rand -base64 32` and keep it in a secret manager.
- Rotate by moving the current value to `COOKIE_SECRET_PREVIOUS`, setting a new `COOKIE_SECRET`, and removing the old one after `COOKIE_TTL`.
- Set `TRUST_FORWARDED_FOR=true` only when a proxy you control sets `X-Forwarded-For`.
- Keep `METRICS_LISTEN` on a loopback or internal interface.
- Prefer a short `COOKIE_TTL` and short token lifetimes.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).
