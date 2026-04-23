# Contributing

Thanks for wanting to help.

## Dev loop

```bash
go test -race ./...
go vet ./...
go build .
```

The test suite covers `internal/session`. Patches that touch `internal/server` or `internal/yandex` should add httptest-based tests alongside.

## Code style

- Standard `gofmt`.
- Keep packages single-purpose; this project deliberately avoids a framework.
- Public types get doc comments; unexported helpers don't need them unless the intent is non-obvious.
- Errors returned from public functions should wrap the underlying cause with `%w`.

## What kind of PRs are welcome

Most valuable right now:

- More reverse-proxy integration recipes in `examples/` (HAProxy, Envoy, Istio, Kubernetes Ingress).
- Unit tests for `internal/server` using `net/http/httptest`.
- A mock Yandex endpoint for end-to-end tests.
- Additional whitelist backends (HTTP, LDAP, OIDC group claim).
- Prometheus metrics (login success/fail, verify cache hits, whitelist size).

## What is deliberately out of scope

- Support for non-Yandex OAuth providers. Use `oauth2-proxy` or `vouch-proxy` for those; this project stays narrow on purpose.
- Session replication across multiple IAP replicas. The cookie is self-contained and HMAC-verified, so running more than one replica works naturally without shared state — just make sure they all see the same `COOKIE_SECRET` and `WHITELIST_FILE`.
- Dynamic configuration at runtime. Changing anything except the whitelist requires a restart — on purpose, to keep the attack surface small.

## Releasing

Maintainer workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

CI builds and pushes `ghcr.io/voknil/yandex-iap:v0.1.0` + `v0.1` + latest.
