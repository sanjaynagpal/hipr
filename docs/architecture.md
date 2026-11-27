# hipr architecture

## Background

hipr follows the design of existing Go proxies:

- **goproxy** (elazarl): a plain `net/http` handler with separate stages for CONNECT, request and response. It forwards HTTP, tunnels HTTPS blindly or decrypts it with certificates forged on the fly, and lets handlers short-circuit a request.
- **Martian** (Google): every inspection or change is a "modifier" hook on the request or response. It decrypts HTTPS with a local CA and keeps HAR logs.

Both agree that without a CA a proxy sees only the host and port of HTTPS traffic. Reading it needs a CA the client trusts. hipr uses the same ideas with the standard library only, and keeps inspection behind one small interface so other consumers can be added.

## Layout

```
main.go                     flags, wiring, graceful shutdown
internal/proxy/proxy.go     the http.Handler: forward, tunnel, intercept, reverse
internal/mitm/ca.go         local CA and per-host leaf certificates
internal/inspect/inspect.go Event, Body, Redact and the Sink implementations
auth.go                     -auth-* flags: builds the token injector
internal/auth/              Entra client credentials token source; Injector (the request modifier)
internal/secret/            secret sources: Vault (token / AppRole, KV v1 and v2), env, file
internal/entratest/         mock Entra ID (tests and examples/mockentra)
internal/vaulttest/         fake Vault HTTP API (tests)
```

## Request flow

`Proxy.ServeHTTP` picks a path:

| Request | Path |
|---------|------|
| `Upstream` set, any method but CONNECT | rewrite URL and `Host` to the upstream, then `forward` |
| `Upstream` set, CONNECT | 405 |
| CONNECT, no CA | `tunnel` |
| CONNECT, CA set | `intercept` |
| absolute-URI request | `forward` |
| anything else | 400 |

### forward

All recorded HTTP traffic goes through `forward`:

1. Build an `Event` with the request headers as received, credentials masked by `inspect.Redact`, and strip hop-by-hop headers from the outgoing request.
2. If `Options.Modifier` is set, call `ModifyRequest` on the outgoing request. Its note is added to `Event.Notes`. An error becomes a 502 and the request is not sent. Changes made here never reach the record, because the headers were captured in step 1.
3. Tee the request body into a capture buffer while the transport reads it.
4. Send it with `http.Transport.RoundTrip`. A failure becomes a 502 and an `Error` on the event. If the modifier also implements `ResponseModifier`, it sees the response next.
5. Copy response headers, then stream the body to the client, flushing on each write so SSE and chunked responses are not delayed, while teeing it into a second capture buffer.
6. A deferred function finalises the event and passes it to the `Sink`.

The capture buffers keep only the first `-max-body` bytes but count every byte, so `Body.Size` is always the wire size.

### tunnel

Dial the target, hijack the client connection, reply `200 Connection Established`, then copy bytes both ways. When one direction ends, the other side is half-closed so the peer sees EOF. The event records byte counts and is written when the tunnel closes.

### intercept

1. Hijack the connection and reply 200.
2. Run a TLS server handshake on it. The certificate comes from `CA.Leaf`, named by the client's SNI, or by the CONNECT host if SNI is empty (as it is for IP addresses). Only `http/1.1` is offered.
3. Serve the decrypted stream with an `http.Server` on a one-connection listener. Each request gets `https` and the CONNECT target filled in and goes through `forward`, so it is recorded like plain HTTP.

`connListener` hands over one connection and reports closed once that connection closes, which makes `Serve` return.

### reverse

The URL scheme and host are replaced by the upstream's, the upstream's path is prepended, and `Host` is set to the upstream host so virtual hosts work. With `-tls` the listener itself speaks HTTPS using `CA.Leaf`.

## Certificates

`mitm.LoadOrCreate` reads `ca.pem` and `ca-key.pem` from the CA directory, creating an ECDSA P-256 CA (5 years) when both are absent. If only one exists it fails rather than overwrite it. A supplied CA can use any key type the standard library signs with (PKCS#8, SEC 1 or PKCS#1 PEM); it must be a CA with `keyCertSign`, and its key must match the certificate.

The first certificate in `ca.pem` signs the leaves. Every certificate in the file that is not self-signed, including the first when it is an intermediate, is kept as the chain and sent after each leaf, so clients need only trust the root.

`CA.Leaf(name)` issues a certificate with the name as a DNS or IP SAN, valid for 30 days or until the CA expires if sooner, and caches it until an hour before it expires. All leaves share one ECDSA key, because generating a key per host is slow and the key never leaves the process.

With `-cert`/`-key`, `main.go` loads that pair with `tls.LoadX509KeyPair` and serves it on the listener; the CA is not loaded unless `-mitm` also needs it.

## Inspection

`inspect.Sink` has one method, `Record(*Event)`, and must be safe for concurrent use. Provided sinks:

- `Text`: one line per event, with headers and bodies when verbose.
- `JSONL`: one JSON object per event.
- `Multi`: fans out to several sinks.

To add a consumer (a HAR writer, a web UI, a filter), implement `Sink` and add it to the `Multi` in `main.go`.

## Token injection

`auth.Injector` is the only `RequestModifier`. For a request whose host is in `Hosts`, it asks `auth.ClientCredentials` for a token and sets `Authorization: Bearer`. A request that already has the header is left alone unless `Replace` is set, and plain `http` to a non-loopback host is refused. On a 401 from a matching host, `ModifyResponse` drops the cached token if it is still the one that was rejected.

`ClientCredentials` holds a mutex while it fetches, so concurrent requests wait for one fetch instead of each calling Entra. It caches the token until `min(5m, lifetime/2)` before expiry. If a renewal fails, it keeps serving the old token while that is still valid.

The client secret is read from its `secret.Source` once and kept. On `invalid_client` it is read again and the request retried once, which handles rotation. `secret.Vault` makes one HTTP read per call. With AppRole it logs in each time and revokes the token afterwards. Reads happen only at startup and on rotation, so no Vault token is kept.

`main.go` gets one token before it starts listening, so configuration errors stop hipr at startup.

## Testing

`internal/proxy/proxy_test.go` runs real servers on loopback and covers plain forwarding, blind tunnels, TLS interception with a throwaway CA, reverse mode, and an unreachable upstream. `modifier_test.go` covers the modifier hook and header masking.

`internal/auth` and `internal/secret` run against `internal/entratest` and `internal/vaulttest`. `examples/serviceapi/hipr_test.go` runs the whole chain in-process: a client without a token, then hipr reading from Vault with AppRole and getting a token from Entra, then the sample API validating it.

`vaulttest` mimics what real Vault does: multi-line error strings, and a 403 rather than a 404 for paths outside a policy. Both were found by checking against a real Vault dev server.

## Not yet implemented

- Other request and response changes (the Martian modifier idea). The `RequestModifier` / `ResponseModifier` hook is in place.
- Certificate and federated credentials, and managed identity, for token injection.
- WebSocket / `Upgrade`.
- HTTP/2 on intercepted connections.
- Authentication on the proxy port.
