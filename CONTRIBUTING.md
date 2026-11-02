# Contributing

Thanks for your interest. Small, focused pull requests are easiest to review.

## Setup

You need Go 1.22+ and [golangci-lint](https://golangci-lint.run/) v2.

```bash
git clone https://github.com/voknil/yandex-iap && cd yandex-iap
make check
```

`make check` runs what CI runs: `go vet`, `golangci-lint` and the tests with the race detector.

## Guidelines

- The project has no third-party dependencies. Please keep it that way unless there is a strong reason.
- Security-relevant behaviour needs a test, and input parsing (redirects, tokens) should have a fuzz or table test.
- Keep user-facing changes in `CHANGELOG.md` under *Unreleased*.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`).
- Do not report vulnerabilities in public issues; see [SECURITY.md](SECURITY.md).
