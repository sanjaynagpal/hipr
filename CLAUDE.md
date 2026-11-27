# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

hipr is an HTTP/HTTPS proxy (forward or reverse) that records the traffic passing through it. Go 1.26+, **standard library only** — do not add third-party dependencies (`go.mod` has none). User-facing docs are in [README.md](README.md); design detail is in [docs/architecture.md](docs/architecture.md); operator procedures and troubleshooting are in [docs/runbook.md](docs/runbook.md). Keep all three in sync when changing flags, request flow, or output formats.

## Commands

```
go build -o hipr .                         # build (hipr / hipr.exe are gitignored)
go test ./...                              # all tests
go test ./internal/proxy -run TestIntercept -v   # single test
go vet ./...
```

Manual check: `go run . -v` then `curl -x http://127.0.0.1:8080 http://example.com/`. With `-mitm`, pass `--cacert .hipr/ca.pem` (and `--ssl-no-revoke` with Windows schannel curl). `.hipr/` holds the generated CA and is gitignored.

## Architecture

Three internal packages wired together in [main.go](main.go) (flags, sink setup, CA loading, graceful shutdown):

- **`internal/proxy`** — `Proxy` is a single `http.Handler`. `ServeHTTP` dispatches to:
  - `forward` — the one path through which *all recorded HTTP* flows (plain forward, reverse mode, and decrypted MITM requests). It strips hop-by-hop headers, tees request/response bodies into `capture` buffers (keep first `MaxBody` bytes but count all bytes, so `Body.Size` is wire size), streams the response with a flushing writer (SSE/chunked), and emits the `Event` to the sink in a deferred func.
  - `tunnel` — blind CONNECT: hijack, `200 Connection Established`, bidirectional copy with half-close; records only byte counts.
  - `intercept` — CONNECT when `Options.CA` is set: hijack, TLS handshake with a leaf from `CA.Leaf` (SNI, else CONNECT host), then run an `http.Server` over a one-connection `connListener` whose requests are fed back into `forward`. HTTP/1.1 only.
  - Reverse mode (`Options.Upstream` set): rewrite scheme/host/path and `Host` header, then `forward`; CONNECT returns 405. `-mitm` is ignored in reverse mode (main only sets `opts.CA` when there's no upstream).
- **`internal/mitm`** — `LoadOrCreate(dir)` loads a supplied CA (any signer key type, PKCS#8/SEC 1/PKCS#1, root or intermediate) or creates an ECDSA P-256 one; `Leaf(name)` issues cached certs sharing a single key and appends the CA's non-root chain. Also used by `-tls` to serve HTTPS on the listener itself, unless `-cert`/`-key` supply a fixed certificate (loaded in `main.go`).
- **`internal/inspect`** — `Event`/`Body` types and the `Sink` interface (`Record(*Event)`, must be concurrency-safe). Implementations: `Text`, `JSONL`, `Multi`. Bodies are gzip-decoded before storage and marshal as `text` (valid UTF-8) or `base64`. New consumers (HAR, UI, filters) should be new `Sink`s added to the `Multi` in `main.go`.

- **Token injection** (`-auth-*`, flags in [auth.go](auth.go)): `proxy.Options.Modifier` (`RequestModifier`, optionally `ResponseModifier`) is called in `forward` *after* the event's headers are captured, so injected credentials never reach records. `internal/auth` has `ClientCredentials` (Entra client credentials grant, cached, single-flight refresh, re-reads the secret on `invalid_client`) and `Injector` (host allow-list, keep-or-replace, refuses plain http off loopback, invalidates on 401). `internal/secret` reads the client secret from Vault (raw HTTP API; KV v2 paths include `data/`), env or file. All recorded headers pass through `inspect.Redact`.
- **Test doubles**: `internal/entratest` (mock Entra ID) and `internal/vaulttest` (fake Vault). When changing Vault handling, keep `vaulttest` faithful to real Vault: errors are multi-line strings, and paths outside a policy give 403, not 404.

Planned but not implemented: other request/response modifications, certificate/federated credentials for `-auth-*`, WebSocket/`Upgrade`, HTTP/2 on intercepted connections, proxy auth.

## Examples

[examples/](examples/README.md) is part of the same module (so `go test ./...` runs it) but independent of hipr's code. `examples/serviceapi` is a sample Entra ID–protected API: [auth.go](examples/serviceapi/auth.go) validates JWTs and authorizes delegated callers by `scp` and app-only callers by `roles`, never mixing them. `examples/mockentra` serves the mock IdP from `internal/entratest`. `examples/serviceapi/hipr_test.go` is the end-to-end test of token injection: client without a token → hipr (secret from fake Vault) → sample API.

## Tests

[internal/proxy/proxy_test.go](internal/proxy/proxy_test.go) uses real loopback servers (`httptest`) and a `collector` sink to assert on recorded events; intercept tests use a throwaway CA in a temp dir. Follow that pattern rather than mocking the transport.
