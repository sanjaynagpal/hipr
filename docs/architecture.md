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
internal/inspect/inspect.go Event, Body and the Sink implementations
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

1. Build an `Event` and strip hop-by-hop headers from the outgoing request.
2. Tee the request body into a capture buffer while the transport reads it.
3. Send it with `http.Transport.RoundTrip`. A failure becomes a 502 and an `Error` on the event.
4. Copy response headers, then stream the body to the client, flushing on each write so SSE and chunked responses are not delayed, while teeing it into a second capture buffer.
5. A deferred function finalises the event and passes it to the `Sink`.

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

`mitm.LoadOrCreate` reads `ca.pem` and `ca-key.pem` from the CA directory, creating an ECDSA P-256 CA (5 years) on first use. `CA.Leaf(name)` issues a 30-day certificate with the name as a DNS or IP SAN and caches it until an hour before it expires. All leaves share one key, because generating a key per host is slow and the key never leaves the process.

## Inspection

`inspect.Sink` has one method, `Record(*Event)`, and must be safe for concurrent use. Provided sinks:

- `Text`: one line per event, with headers and bodies when verbose.
- `JSONL`: one JSON object per event.
- `Multi`: fans out to several sinks.

To add a consumer (a HAR writer, a web UI, a filter), implement `Sink` and add it to the `Multi` in `main.go`.

## Testing

`internal/proxy/proxy_test.go` runs real servers on loopback and covers plain forwarding, blind tunnels, TLS interception with a throwaway CA, reverse mode, and an unreachable upstream.

## Not yet implemented

- Changing requests or responses (the Martian modifier idea). A natural step is a `Modifier` interface called from `forward` before the round trip and before the response is written.
- WebSocket / `Upgrade`.
- HTTP/2 on intercepted connections.
- Authentication on the proxy port.
