# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- CI: lint (golangci-lint v2), test matrix (Go 1.22 and stable) with the race
  detector and a coverage summary, `govulncheck`, multi-arch image build with
  SBOM and build provenance.
- Release automation: tagged versions publish binaries (linux, macOS, Windows;
  amd64, arm64), checksums and generated release notes.
- Dependabot for GitHub Actions, Go modules and the Docker base image.
- `SECURITY.md`, issue and pull request templates, `Makefile`, `.editorconfig`.

### Changed
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
