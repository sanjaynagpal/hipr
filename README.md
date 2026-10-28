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

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `127.0.0.1:8080` | Listen address |
| `-upstream` | none | Run as a reverse proxy in front of this `http://` or `https://` server |
| `-mitm` | off | Forward mode: decrypt HTTPS using the local CA |
| `-tls` | off | Serve HTTPS on the listen address with a certificate from the local CA (useful with `-upstream`) |
| `-ca-dir` | `.hipr` | Directory holding `ca.pem` and `ca-key.pem` |
| `-insecure` | off | Do not verify the upstream server's TLS certificate (self-signed dev servers) |
| `-v` | off | Print headers and bodies |
| `-jsonl <file>` | none | Append every exchange to a file as JSON lines |
| `-max-body` | `1048576` | Bytes of each request and response body to keep for inspection |

`-max-body` only limits what is recorded. Traffic is always forwarded in full.

## Output formats

**Text** (stdout): one line per exchange, plus headers and bodies with `-v`. CONNECT tunnels show bytes sent each way instead of a status.

**JSON lines** (`-jsonl`): one object per exchange:

```json
{"id":1,"time":"...","duration_ns":54000000,"kind":"http","client_addr":"127.0.0.1:51234",
 "method":"GET","url":"http://example.com/","req_header":{...},"req_body":{"size":0},
 "status":200,"resp_header":{...},"resp_body":{"size":577,"text":"<!doctype html>..."}}
```

Bodies appear as `text` when they are valid UTF-8 and as `base64` otherwise. `truncated` is set when a body exceeded `-max-body`. gzip bodies are decoded before they are stored.

## Limits

- WebSocket and other `Upgrade` requests are not supported over plain HTTP.
- Intercepted HTTPS is HTTP/1.1 only.
- hipr observes traffic but cannot yet change it.
- There is no authentication. Anyone who can reach the port can use the proxy, which is why it listens on `127.0.0.1` by default.
- In reverse mode `CONNECT` is rejected, and `-mitm` has no effect.
- Windows curl (schannel) may report "revocation status is unknown" for the local CA. Add `--ssl-no-revoke`.
- Many clients skip the proxy for `localhost`. If traffic does not appear, check `NO_PROXY` and the browser's proxy bypass list.

More detail is in [docs/architecture.md](docs/architecture.md).
