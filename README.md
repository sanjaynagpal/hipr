# hipr

hipr is an HTTP/HTTPS proxy that sits between a client and a server and records the traffic passing through it. It is written in Go and uses only the standard library.

It runs in two modes:

| Mode | You run | Client setup |
|------|---------|--------------|
| Forward proxy (default) | `hipr` | Point the client's proxy setting at hipr |
| Reverse proxy | `hipr -upstream http://localhost:29010` | None. Connect to hipr as if it were the server |

## Build

```
go build -o hipr .
go test ./...
```

Requires Go 1.26 or later.

## Quick start

### Forward proxy

```
hipr -addr 127.0.0.1:8080 -v
curl -x http://127.0.0.1:8080 http://example.com/
```

Each exchange prints one summary line; `-v` adds headers and bodies:

```
#1 GET http://example.com/ -> 200 577B (54ms)
  > User-Agent: curl/8.21.0
  < Content-Type: text/html; charset=utf-8
  ...
```

### Reverse proxy

```
hipr -addr 127.0.0.1:29000 -upstream http://localhost:29010 -v
curl http://localhost:29000/api
```

Every request that arrives on `:29000` is relayed to `:29010`.

### Reading HTTPS

By default hipr tunnels HTTPS (`CONNECT`) without reading it and logs only the host and byte counts. To read it, add `-mitm`:

```
hipr -mitm -v
curl -x http://127.0.0.1:8080 --cacert .hipr/ca.pem https://example.com/
```

hipr creates a local certificate authority in `.hipr/` the first time. The client has to trust `.hipr/ca.pem`, otherwise its TLS handshake fails. Keep `.hipr/ca-key.pem` private: anything that trusts the CA will trust certificates signed with it.

### Using certificates from an existing CA

**A signing CA for `-mitm` (or `-tls` without `-cert`).** Put the CA certificate in `ca.pem` and its key in `ca-key.pem` in the `-ca-dir` directory, and hipr uses them instead of creating its own. Clients that already trust your organisation's CA then need no setup.

- The certificate must be a CA allowed to sign certificates (`CA:TRUE`, `keyCertSign`).
- The key may be ECDSA, RSA or Ed25519, in PKCS#8 (`PRIVATE KEY`), SEC 1 (`EC PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`) form. Encrypted keys are not supported; decrypt with `openssl pkey -in key.pem -out ca-key.pem`.
- If it is an intermediate, put it first in `ca.pem`, optionally followed by the certificates above it. hipr sends every non-root certificate with each host certificate, so clients need only trust the root.
- Both files must be present. If only one is, hipr stops rather than overwriting it.

**A server certificate for `-tls`.** In reverse mode hipr presents one certificate for its own name, so an ordinary server certificate is enough:

```
hipr -addr :443 -upstream http://localhost:29010 -cert server-chain.pem -key server.key
```

`-cert` is a PEM file holding the certificate followed by any intermediates. It implies `-tls`, and no local CA is created.

### Adding an access token (Microsoft Entra ID)

hipr can call an API as its own service principal for clients that have no token, such as automated regression tests. It gets an access token from Entra ID with the OAuth 2.0 client credentials grant and adds it to requests as `Authorization: Bearer <token>`. The client secret comes from HashiCorp Vault.

```
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_ROLE_ID=<role id>  VAULT_SECRET_ID=<secret id>     # AppRole, the usual for CI

hipr -addr 127.0.0.1:29000 -upstream https://api.corp.example \
     -auth-tenant <tenant-id> -auth-client-id <hipr's application id> \
     -auth-scope api://<api>/.default \
     -auth-secret vault:secret/data/hipr/entra#client_secret
```

The tests then call `http://127.0.0.1:29000/...` without credentials.

- **Secret.** `-auth-secret` is `vault:<path>#<field>`, `env:<NAME>` or `file:<path>`. The Vault path is the API path: for the KV version 2 engine it has `data/` after the mount, as in `secret/data/hipr/entra` for what `vault kv get secret/hipr/entra` shows.
- **Logging in to Vault.** hipr uses the first of these that is set:
  1. `VAULT_ROLE_ID` with `VAULT_SECRET_ID` or `VAULT_SECRET_ID_FILE` (AppRole). The login token is revoked after the read. Use `VAULT_APPROLE_MOUNT` if AppRole is not mounted at `approle`.
  2. `VAULT_TOKEN_FILE`, for example a Vault Agent sink. It is read on every use.
  3. `VAULT_TOKEN`.
  4. `~/.vault-token`.

  `VAULT_NAMESPACE` and `VAULT_CACERT` are honoured.
- **Token lifetime.** hipr gets a token at startup, so a wrong secret, path or scope stops it at once. It caches the token and renews it 5 minutes before it expires. Concurrent requests share one renewal.
- **Secret rotation.** The secret stays in memory. If Entra rejects it (`invalid_client`), hipr reads it from Vault again and retries once, so rotating it needs no restart.
- **Rejected tokens.** A 401 from the API drops the cached token, and the next request gets a new one. The rejected request is not retried.
- **Where the token goes.** It is sent only to `-auth-hosts`, which defaults to the `-upstream` host. To any host other than loopback it goes only over `https`.
- **Requests that already have a token.** A request that already carries `Authorization` is passed on unchanged, unless `-auth-replace` is set. This lets a real user's token through untouched.
- **Listen address.** Injection is refused on an address other than loopback, because anyone who can reach the port could call the API as hipr. `-auth-allow-remote` overrides this.
- **Records.** They note that a token was added but never contain it. `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` are always masked.

The service principal needs an app role on the API, and the API must accept app-only tokens. [examples/](examples/README.md) shows both, with a mock Entra ID to try it offline.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `127.0.0.1:8080` | Listen address |
| `-upstream` | none | Run as a reverse proxy in front of this `http://` or `https://` server |
| `-mitm` | off | Forward mode: decrypt HTTPS using the local CA |
| `-tls` | off | Serve HTTPS on the listen address with a certificate from the local CA (useful with `-upstream`) |
| `-cert`, `-key` | none | Serve HTTPS with this certificate (chain) and key instead of one from the local CA. Implies `-tls` |
| `-ca-dir` | `.hipr` | Directory holding `ca.pem` and `ca-key.pem` |
| `-insecure` | off | Do not verify the upstream server's TLS certificate (self-signed dev servers) |
| `-v` | off | Print headers and bodies |
| `-jsonl <file>` | none | Append every exchange to a file as JSON lines |
| `-max-body` | `1048576` | Bytes of each request and response body to keep for inspection |
| `-auth-client-id` | none | Add an Entra ID access token for this application to requests. Turns on token injection |
| `-auth-tenant` | none | Entra tenant ID or domain, used to build the token endpoint |
| `-auth-token-url` | from tenant | Token endpoint, overriding `-auth-tenant` (e.g. a mock) |
| `-auth-scope` | none | Scope to request, e.g. `api://my-api/.default` |
| `-auth-secret` | none | Client secret source: `vault:<path>#<field>`, `env:<NAME>` or `file:<path>` |
| `-auth-hosts` | `-upstream` host | Comma-separated `host` or `host:port` values the token may be sent to |
| `-auth-replace` | off | Replace an `Authorization` header the client sent |
| `-auth-allow-remote` | off | Allow token injection on a non-loopback `-addr` |

`-max-body` only limits what is recorded. Traffic is always forwarded in full.

## Output formats

**Text** (stdout): one line per exchange, plus headers and bodies with `-v`. CONNECT tunnels show bytes sent each way instead of a status.

**JSON lines** (`-jsonl`): one object per exchange:

```json
{"id":1,"time":"...","duration_ns":54000000,"kind":"http","client_addr":"127.0.0.1:51234",
 "method":"GET","url":"http://example.com/","req_header":{...},"req_body":{"size":0},
 "status":200,"resp_header":{...},"resp_body":{"size":577,"text":"<!doctype html>..."}}
```

Bodies appear as `text` when they are valid UTF-8 and as `base64` otherwise. `truncated` is set when a body exceeded `-max-body`. gzip bodies are decoded before they are stored. Credential headers are recorded masked, as `Bearer <redacted, 1234 bytes>`. `notes` lists what hipr changed, such as an added token.

## Limits

- WebSocket and other `Upgrade` requests are not supported over plain HTTP.
- Intercepted HTTPS is HTTP/1.1 only.
- The only change hipr makes to traffic is adding an access token (`-auth-*`).
- There is no authentication. Anyone who can reach the port can use the proxy, which is why it listens on `127.0.0.1` by default. With `-auth-*` that includes calling the API as hipr's service principal.
- Only client secrets are supported for `-auth-*`, not certificates or federated credentials.
- In reverse mode `CONNECT` is rejected, and `-mitm` has no effect.
- Windows curl (schannel) may report "revocation status is unknown" for the local CA. Add `--ssl-no-revoke`.
- Many clients skip the proxy for `localhost`. If traffic does not appear, check `NO_PROXY` and the browser's proxy bypass list.

More detail is in [docs/architecture.md](docs/architecture.md). For running hipr and diagnosing problems, see the [operator runbook](docs/runbook.md).

[examples/](examples/README.md) has a sample Service API protected by Microsoft Entra ID. It accepts tokens from signed-in users and app-only tokens from a service principal, and comes with a mock identity provider so it runs offline.
