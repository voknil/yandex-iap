# Security policy

yandex-iap sits in front of other applications and decides who may reach them, so
security reports are taken seriously.

## Supported versions

Only the latest released minor version receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository
(<https://github.com/voknil/yandex-iap/security/advisories/new>).

Include, when you can:

- the affected version or commit, and how you deploy it (reverse proxy, cookie domain);
- a minimal reproduction or a description of the attack path;
- the impact you expect (bypass of the whitelist, session fixation, token disclosure, …).

You can expect an acknowledgement within **3 working days** and a fix or a
mitigation plan within **14 days** for confirmed issues. Credit is given in the
release notes unless you prefer to stay anonymous.

## Scope

In scope: authentication and authorisation decisions (`/auth/verify`, sessions,
static tokens, the admin UI), redirect handling, cookie and CSRF handling,
secret management.

Out of scope: vulnerabilities in the reverse proxy or in Yandex ID itself,
and deployments that ignore the hardening notes in the README (for example, serving
the IAP over plain HTTP).

## Hardening notes

See *Security* in the [README](README.md) and [docs/security.md](docs/security.md)
for the threat model and the recommended deployment settings.
