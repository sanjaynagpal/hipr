# hipr operator runbook

This runbook is for people who run hipr: to record traffic, to put it in front of a service, or to let automated tests call an API protected by Microsoft Entra ID. Each use case says how to start hipr, how to check it is working, and what to watch out for. [Troubleshooting](#troubleshooting) then goes by symptom, and [Explaining hipr's behaviour](#explaining-hiprs-behaviour) answers the questions people usually ask.

For the flag list see the [README](../README.md#flags). For how it works inside see [architecture.md](architecture.md).

## Contents

1. [Before you start](#before-you-start)
2. [Reading hipr's output](#reading-hiprs-output)
3. Use cases
   - [A. Record a client's HTTP traffic (forward proxy)](#a-record-a-clients-http-traffic-forward-proxy)
   - [B. See which HTTPS hosts a client talks to (blind tunnel)](#b-see-which-https-hosts-a-client-talks-to-blind-tunnel)
   - [C. Read a client's HTTPS traffic (`-mitm`)](#c-read-a-clients-https-traffic--mitm)
   - [D. Record traffic to one service (reverse proxy)](#d-record-traffic-to-one-service-reverse-proxy)
   - [E. Serve HTTPS to clients in reverse mode (`-tls`, `-cert`/`-key`)](#e-serve-https-to-clients-in-reverse-mode--tls--cert-key)
   - [F. Use your organisation's CA](#f-use-your-organisations-ca)
   - [G. Let automated tests call an Entra ID-protected API (`-auth-*`)](#g-let-automated-tests-call-an-entra-id-protected-api--auth-)
   - [H. Rehearse G offline with the sample API](#h-rehearse-g-offline-with-the-sample-api)
4. [Troubleshooting](#troubleshooting)
5. [Explaining hipr's behaviour](#explaining-hiprs-behaviour)
6. [Security checklist](#security-checklist)

## Before you start

- **Build:** `go build -o hipr .` (Go 1.26 or later). One binary, no dependencies.
- **Port:** hipr listens on `127.0.0.1:8080` unless you pass `-addr`. It has no authentication of its own: anyone who can reach the port can use it. Keep it on `127.0.0.1` unless you have a reason not to.
- **Stopping:** Ctrl+C stops hipr cleanly and gives open requests up to 5 seconds to finish. hipr does not handle SIGTERM, so `kill`, `docker stop` or a CI job timeout ends it at once. Each record is written as soon as its exchange completes, so finished exchanges are never lost.
- **One mode per process:** hipr is either a forward proxy (the default) or a reverse proxy (`-upstream`). To do both, run two copies on different ports.

| You want to… | Mode | Use case |
|---|---|---|
| see everything one client sends anywhere | forward | A, B, C |
| see everything sent to one service | reverse | D, E |
| let a client without a token call an Entra-protected API | reverse (preferred) or forward + `-mitm` | G |

## Reading hipr's output

**At startup** hipr prints what it is doing. Check these lines before you go further:

```
Trust this CA in your client: .hipr/ca.pem                 # -mitm, or -tls without -cert
Using intermediate CA .hipr/ca.pem: clients must trust the root it chains to
warning: without -mitm, HTTPS is tunnelled unread and gets no token; ...
auth: token for client 3333… from https://login.microsoftonline.com/…/token (secret from vault https://vault…/v1/secret/data/hipr/entra#client_secret), valid until 14:05:09; sent to api.corp.example
hipr listening on 127.0.0.1:29000 (reverse proxy -> https://api.corp.example)
```

When the last line is missing, hipr has stopped, and the line above it says why.

**For each exchange** hipr prints one line:

```
#12 GET https://api.corp.example/items -> 200 1834B (87ms)
#13 POST http://api.corp.example/items -> 502 0B (1ms) error: auth: refusing to send a bearer token ...
#14 GET http://10.0.0.9/ -> 502 0B (10.001s) error: dial tcp 10.0.0.9:80: i/o timeout
#15 CONNECT login.live.com:443 tunnel up=2104B down=6011B (1.2s)
```

- `#n` numbers the exchanges in this run. The size is the full response body as sent on the wire.
- `502 0B` with an `error:` means hipr answered the client itself, because it could not send the request or got no response. The upstream never answered, so its response is not in the record.
- `tunnel` lines are HTTPS that hipr passed through without reading it (use case B).
- A line is written when the exchange **ends**. A long download, a server-sent events stream or a tunnel shows up only when it closes.

With `-v` each line is followed by its notes (`  * auth: added bearer token …`), request headers (`>`), response headers (`<`) and bodies.

**With `-jsonl file`** every exchange is also added to the file as one JSON object. The file is opened for appending and never truncated, so delete or rotate it between runs. Some useful queries:

```
jq -c 'select(.status >= 400) | {id, method, url, status, error}' run.jsonl
jq -c 'select(.error) | {id, url, error}' run.jsonl
jq -c 'select(.notes) | {id, url, notes}' run.jsonl
jq -r '.resp_body.text // empty' run.jsonl | head
```

The `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` headers are recorded masked, for example `Bearer <redacted, 1432 bytes>`. **Nothing else is masked**: bodies, URLs and query strings, and other headers such as `X-Api-Key` are kept as sent. See the [security checklist](#security-checklist).

---

## A. Record a client's HTTP traffic (forward proxy)

```
hipr -v -jsonl run.jsonl
curl -x http://127.0.0.1:8080 http://example.com/
```

Point the client at hipr as its HTTP proxy. Many tools read the `HTTP_PROXY` / `HTTPS_PROXY` environment variables; browsers and the operating system have proxy settings.

**Check:** a line like `#1 GET http://example.com/ -> 200 …` appears.

**Watch out for:**
- **`localhost` bypasses the proxy.** Many clients never send requests for `localhost` or `127.0.0.1` through a proxy, and `NO_PROXY` often lists them. If nothing shows up, check `NO_PROXY`/`no_proxy` and the browser's bypass list, or use reverse mode (D) for local services.
- **Non-proxy requests get 400.** A request sent straight to hipr's port, not as a proxy request, gets `400 hipr is a forward proxy: send absolute-URI requests`. The client is not configured to use a proxy; either configure it or use reverse mode.
- **WebSocket and other `Upgrade` connections do not work.** hipr removes the `Upgrade` header, so the server sees an ordinary request and usually refuses it.
- **hipr does not use a corporate proxy.** It connects to servers directly and ignores `HTTPS_PROXY` for the traffic it forwards. If the client normally reaches the internet through a corporate proxy, hipr cannot reach the servers either (see "upstream error" in [Troubleshooting](#troubleshooting)).

## B. See which HTTPS hosts a client talks to (blind tunnel)

This is the default for HTTPS in forward mode. Nothing is needed on the client beyond the proxy setting.

```
hipr
curl -x http://127.0.0.1:8080 https://example.com/
```

**Check:** `#1 CONNECT example.com:443 tunnel up=…B down=…B (…)`.

**Watch out for:**
- hipr sees only the host, the port and the byte counts. The URL path, headers and bodies are encrypted. To read them, use C.
- One tunnel can carry many requests, so one line is not one request.
- The line appears when the client closes the connection, which for browsers can be minutes later.

## C. Read a client's HTTPS traffic (`-mitm`)

```
hipr -mitm -v -jsonl run.jsonl
curl -x http://127.0.0.1:8080 --cacert .hipr/ca.pem https://example.com/
```

On first use hipr creates a CA in `.hipr/` (`ca.pem` and `ca-key.pem`) and prints `Trust this CA in your client`. It then presents a certificate for each host, signed by that CA. **The client has to trust `ca.pem`**, or every HTTPS request fails at the handshake.

How to make common clients trust it:

| Client | Trust the CA with |
|---|---|
| curl | `--cacert .hipr/ca.pem` (Windows curl also needs `--ssl-no-revoke`) |
| Go | the system store, or `SSL_CERT_FILE=.hipr/ca.pem` on Linux |
| Node.js | `NODE_EXTRA_CA_CERTS=.hipr/ca.pem` |
| Python requests / httpx | `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` pointing at a bundle that includes `ca.pem` |
| Java | import into a truststore with `keytool -importcert` and pass `-Djavax.net.ssl.trustStore=…` |
| browsers, .NET, most Windows apps | the operating system's trusted root store |

**Check:** the lines show `https://…` URLs with status codes, not `tunnel`.

**Watch out for:**
- **A handshake failure shows as a tunnel line with an error:** `CONNECT host:443 tunnel … error: tls handshake: remote error: tls: unknown certificate authority`. The client does not trust the CA. See [Troubleshooting](#troubleshooting).
- **Certificate pinning.** Apps that pin certificates (many mobile apps, some SDKs and update services) refuse hipr's certificate even when the CA is trusted. You cannot read them with hipr.
- **HTTP/1.1 only.** hipr offers only HTTP/1.1 to the client. Almost every client accepts that. gRPC needs HTTP/2, so it fails.
- **Protect `.hipr/ca-key.pem`.** Anyone with it can impersonate any website to every machine that trusts the CA. Do not commit it or copy it around. Remove the CA from trust stores when you no longer need it.
- **Upstream certificates are still checked.** hipr verifies the real server's certificate against the system store. For a dev server with a self-signed certificate, add `-insecure`, which turns verification off for every upstream.

## D. Record traffic to one service (reverse proxy)

```
hipr -addr 127.0.0.1:29000 -upstream http://localhost:29010 -v -jsonl run.jsonl
curl http://127.0.0.1:29000/api/health
```

Clients call hipr as if it were the service. Nothing on the client needs to change except the address. The upstream may be `http://` or `https://`, and may have a base path (`-upstream https://host/base` sends `/x` to `/base/x`).

**Check:** `#1 GET http://localhost:29010/api/health -> 200 …`. The URL shown is where hipr sent the request.

**Watch out for:**
- **The `Host` header is replaced** with the upstream's host, so virtual hosting works. A service that builds absolute links or redirects from `Host` will point clients at the upstream, not at hipr.
- **Redirects are passed back unchanged.** A `Location: https://upstream/...` sends the client straight to the upstream, past hipr. hipr does not rewrite them.
- **Cookies** set by the upstream for its own domain may not be sent back to hipr's address.
- **`CONNECT` gets 405**, and `-mitm` has no effect in reverse mode.
- **Upstream HTTPS** is verified against the system store. A service with an internal or self-signed certificate needs its CA in the system store, or `-insecure`.

## E. Serve HTTPS to clients in reverse mode (`-tls`, `-cert`/`-key`)

When clients must connect to hipr over HTTPS, choose one of these.

**A certificate you already have** (recommended when clients don't trust your CA directly):

```
hipr -addr :8443 -upstream http://localhost:29010 -cert server-chain.pem -key server.key
```

- `-cert` holds the server certificate **followed by its intermediates**, in PEM. If you leave the intermediates out, browsers may cope but curl, Go, Java and Node fail with "unable to get local issuer certificate".
- The certificate's names (SANs) must include the name clients use. `-cert` implies `-tls`, and no local CA is created.

**A certificate from the local CA:**

```
hipr -addr 127.0.0.1:8443 -upstream http://localhost:29010 -tls
curl --cacert .hipr/ca.pem https://localhost:8443/
```

- hipr issues a certificate for whatever name the client asks for (its SNI). A client connecting **by IP address** sends no name and gets a certificate for `localhost`, which fails verification. Use a host name.
- Clients must trust `.hipr/ca.pem` (see the table in C).

**Watch out for:** listening on `:443` needs elevated rights on Linux and macOS. A non-loopback `-addr` makes hipr reachable from other machines (see [Security checklist](#security-checklist)).

## F. Use your organisation's CA

Clients that already trust your organisation's CA need no setup if hipr uses it. Put the CA's certificate and key in the `-ca-dir` directory (default `.hipr`):

```
.hipr/ca.pem       the signing CA certificate first, then optionally the certificates above it
.hipr/ca-key.pem   its private key, unencrypted
```

Requirements, each checked at startup:

| Requirement | Error if not met |
|---|---|
| both files present | `mitm: .hipr needs both ca.pem and ca-key.pem, or neither to create a new CA` |
| a CA certificate allowed to sign (`CA:TRUE`, `keyCertSign`) | `mitm: .hipr/ca.pem is not a CA certificate allowed to sign certificates` |
| the key belongs to that certificate | `mitm: .hipr/ca-key.pem does not match the certificate in .hipr/ca.pem` |
| key not encrypted | `encrypted private keys are not supported; decrypt it first (openssl pkey -in key.pem -out ca-key.pem)` |
| a PEM file | `no PEM CERTIFICATE block` / `no PEM private key block` (a DER file or the wrong file) |

The key may be ECDSA, RSA or Ed25519, in PKCS#8, SEC 1 or PKCS#1 form.

**An intermediate CA** is the usual case: security teams rarely hand out the root key. Put the intermediate first in `ca.pem`. hipr sends it, and any other non-root certificates in the file, with every host certificate, so clients need only trust the root. Startup then says `Using intermediate CA … clients must trust the root it chains to`.

**Watch out for:**
- **An ordinary server certificate will not work here.** It is not allowed to sign other certificates, so hipr refuses it. A server certificate goes with `-cert`/`-key` (use case E), and that works only in reverse mode, where hipr has one name. For `-mitm`, hipr must create a certificate for every host the client visits, which only a CA can do.
- **Name constraints.** Some organisational CAs may sign only certain domains. Certificates hipr makes for other hosts are then rejected by clients, even though hipr started without complaint.
- **Lifetime.** Host certificates are valid for 30 days, or until the CA expires if that is sooner. When the CA itself expires, every handshake fails.
- **The key is the risk.** Whoever holds `ca-key.pem` can impersonate any site to the whole organisation. Agree with the CA's owner how it is stored, and prefer a dedicated intermediate with a short life and name constraints.

## G. Let automated tests call an Entra ID-protected API (`-auth-*`)

Tests send requests without credentials. hipr signs in to Entra ID as its own service principal (OAuth 2.0 client credentials), reads its client secret from HashiCorp Vault, and adds `Authorization: Bearer <token>` to each request for the API.

### One-time setup

All three must be in place, or hipr fails at startup or the API rejects the token. [examples/README.md](../examples/README.md#setting-it-up-in-entra-id) has the detail.

1. **The API** accepts app-only tokens. It has app roles (allowed member type *Applications*) and checks `roles` for app callers. A delegated-only API answers 403 to hipr's token whatever you configure in hipr.
2. **hipr's app registration** in Entra has a client secret and the *application* permission for the API's role, **with admin consent granted**.
3. **Vault** holds the secret, and hipr's CI identity has a policy that can read only that path:
   ```
   vault kv put secret/hipr/entra client_secret=<secret>
   vault policy write hipr-read - <<'EOF'
   path "secret/data/hipr/entra" { capabilities = ["read"] }
   EOF
   vault write auth/approle/role/hipr-ci token_policies=hipr-read token_ttl=10m
   ```

### Run (reverse mode, recommended)

```
export VAULT_ADDR=https://vault.corp:8200
export VAULT_ROLE_ID=<role id> VAULT_SECRET_ID=<secret id>
hipr -addr 127.0.0.1:29000 -upstream https://api.corp.example -jsonl run.jsonl \
     -auth-tenant <tenant id> -auth-client-id <hipr's application id> \
     -auth-scope api://<api>/.default \
     -auth-secret vault:secret/data/hipr/entra#client_secret
```

Then point the tests at `http://127.0.0.1:29000`.

**Check:**
1. Startup prints `auth: token for client … valid until …; sent to api.corp.example`. That line means Vault, the secret and Entra all worked. If it is missing, hipr stopped and the line above says why.
2. `curl http://127.0.0.1:29000/<an endpoint>` returns 200.
3. With `-v`, each request shows `  * auth: added bearer token for client … (expires …)`. The `notes` field in the JSONL says the same.

### Run in forward mode

Use this when the tests have to call the API by its real HTTPS URL:

```
hipr -mitm -auth-hosts api.corp.example ... (other -auth-* flags as above)
```

- `-auth-hosts` is required: hipr has no upstream to take the host from. A host without a port matches any port. `api.corp.example:8443` matches only that port.
- `-mitm` is needed, because without it HTTPS is tunnelled unread and gets no token (startup warns about this). The tests must then trust hipr's CA (use case C).

### Where the secret comes from

`-auth-secret` takes one of:

| Form | Use |
|---|---|
| `vault:<path>#<field>` | The API path. For KV version 2 it includes `data/`: `vault kv get secret/hipr/entra` is `vault:secret/data/hipr/entra#client_secret`. |
| `env:<NAME>` | an environment variable, e.g. a CI secret variable |
| `file:<path>` | a file, e.g. one mounted from a secret store |

For Vault, hipr logs in with the **first** of these that is set: `VAULT_ROLE_ID` + `VAULT_SECRET_ID`/`VAULT_SECRET_ID_FILE` (AppRole; `VAULT_APPROLE_MOUNT` if it is not mounted at `approle`), then `VAULT_TOKEN_FILE`, then `VAULT_TOKEN`, then `~/.vault-token`. `VAULT_NAMESPACE` and `VAULT_CACERT` are honoured. **If two are set, the earlier one wins.** A leftover `VAULT_ROLE_ID` in the environment beats the `VAULT_TOKEN` you meant to use.

### What hipr does while running

- **One token, reused.** It is fetched at startup and renewed about 5 minutes before it expires (halfway through, for short-lived tokens). Concurrent requests wait for a single renewal. Entra and Vault are not called for each request.
- **Vault is read** at startup, and again only if Entra rejects the secret. With AppRole, hipr logs in for that read and revokes the login token straight away, so it holds no Vault token while running.
- **Secret rotation needs no restart.** If Entra answers `invalid_client`, hipr reads the secret from Vault again and retries once. Rotate in this order: add the new secret in Entra, update Vault, then delete the old secret in Entra.
- **If renewal fails** (Entra or Vault unreachable), hipr keeps using the current token until 30 seconds before it expires. After that, requests fail with 502 until renewal works again.
- **On a 401 from the API**, hipr throws away its cached token, so the next request gets a fresh one. The rejected request is **not** retried; the test sees the 401.
- **A request that already has an `Authorization` header** is passed through untouched, with the note `auth: kept the client's own Authorization header`, unless you pass `-auth-replace`.
- **Requests to other hosts** pass through without a token.

### Watch out for

- **Listen on loopback.** hipr refuses to start token injection on an address other than `127.0.0.1`/`localhost`/`::1`, because anyone who can reach the port could then call the API as hipr. `-auth-allow-remote` overrides this. Use it only on an isolated network, such as a CI job's own container network.
- **Plain `http` upstreams other than loopback get no token.** Every request fails with `502 hipr: auth: refusing to send a bearer token to <host> over plain http`, even though hipr **starts normally**. Use `https://` for the upstream.
- **Stale tokens in test configuration.** If the tests still send an old `Authorization` header, hipr leaves it alone and the API rejects it. Remove it from the tests, or pass `-auth-replace`.
- **A 401 on every request means a new token fetch on every request.** If the API rejects hipr's tokens outright (wrong audience, wrong tenant), each request makes hipr call Entra, which can lead to throttling. Stop and fix the configuration rather than leaving it running.
- **Use a test or staging API.** The service principal's app role works on whatever data the API lets it reach.

## H. Rehearse G offline with the sample API

[examples/](../examples/README.md) has a mock Entra ID and a sample API that accepts both user and app-only tokens. Use them to try out flags or reproduce a problem without a real tenant or Vault:

```
go run ./examples/mockentra                        # prints the IDs and secrets it uses
go run ./examples/serviceapi -authority http://127.0.0.1:29100/11111111-1111-1111-1111-111111111111/v2.0 \
  -audience 22222222-2222-2222-2222-222222222222,api://hipr-sample-api
HIPR_SECRET=regression-secret hipr -addr 127.0.0.1:29000 -upstream http://127.0.0.1:29010 -v \
  -auth-client-id 33333333-3333-3333-3333-333333333333 \
  -auth-token-url http://127.0.0.1:29100/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token \
  -auth-scope api://hipr-sample-api/.default -auth-secret env:HIPR_SECRET
curl http://127.0.0.1:29000/me                     # {"kind":"app", ...}
```

`GET /me` on the sample API shows how the API sees the caller: kind, ID, roles and scopes. It is the quickest way to check what is in hipr's token. Client `44444444-…` (secret `norole-secret`) has no app role, which shows what a missing permission looks like (403).

---

## Troubleshooting

Find the symptom, then work through the causes in order.

### hipr exits at startup

The last line says why. Configuration problems:

| Message | Cause and fix |
|---|---|
| `-cert and -key must be given together` | Pass both or neither. |
| `loading -cert/-key: tls: private key does not match public key` | The key belongs to a different certificate. |
| `loading -cert/-key: tls: failed to find any PEM data …` | The file is DER or PFX/P12. Convert it to PEM with `openssl`. |
| `invalid -upstream "…": want http://host:port or https://host:port` | Include the scheme. |
| `listen tcp …: bind: address already in use` / `Only one usage of each socket address` | Another process (often an earlier hipr) holds the port. |
| `mitm: …` | The CA files: see the table in [F](#f-use-your-organisations-ca). |

Token injection (G) problems:

| Message contains | Cause and fix |
|---|---|
| `-auth-* flags need -auth-client-id` | An `-auth-*` flag was given without the client ID. |
| `needs -auth-scope` / `needs -auth-secret` / `needs -auth-tenant or -auth-token-url` | A required flag is missing. |
| `token injection on 0.0.0.0:… would let anyone who can reach it call the API` | Listen on `127.0.0.1`, or pass `-auth-allow-remote` deliberately. |
| `forward mode needs -auth-hosts` | Say which hosts get the token. |
| `secret "…": want vault:<path>#<field>` | The `-auth-secret` format is wrong. Did you forget `#field`? |
| `vault: VAULT_ADDR is not set` | Export `VAULT_ADDR`. |
| `vault: no credentials; set VAULT_ROLE_ID …` | No Vault login is configured in this environment. In CI, check that the secret variables reach the step that runs hipr. |
| `VAULT_ROLE_ID is set but neither VAULT_SECRET_ID nor VAULT_SECRET_ID_FILE is` | Half of the AppRole login is missing. |
| `vault AppRole login: … 400 …` | The role ID or secret ID is wrong or expired. AppRole secret IDs often have a use limit or TTL; issue a new one. |
| `vault: GET secret/hipr/entra: not found (if this is a KV version 2 secret, the path needs data/ …)` | Add `data/` after the mount: `secret/data/hipr/entra`. |
| `vault: GET …: 403 permission denied (if this is a KV version 2 secret …)` | Same mistake, as seen through a policy that covers only `…/data/…`. Add `data/`. |
| `vault: GET secret/data/…: 403 permission denied` (path already has `data/`) | The policy does not cover this path, the token has expired, or `VAULT_NAMESPACE` is missing or wrong. Check with `vault token lookup` and `vault policy read`. |
| `vault: GET …: not found` (path has `data/`) | Wrong mount or path, or the secret was deleted. `vault kv get` to check. |
| `vault: … has no string field "x" (fields: a, b)` | The field name after `#` is wrong. The message lists the field names that exist; it never shows their values. |
| `vault: … x509: certificate signed by unknown authority` | Vault uses an internal CA. Set `VAULT_CACERT`. |
| `vault: … connection refused` / `i/o timeout` / `no such host` | `VAULT_ADDR` is wrong or Vault is unreachable from here. Note `http` vs `https` and the port (8200). |
| `token endpoint: 400 invalid_scope: AADSTS1002012 …` | The scope must end in `/.default` for client credentials: `api://<api>/.default`. |
| `token endpoint: 400 invalid_resource: AADSTS500011 …` | The API in the scope is not found in this tenant: a wrong Application ID URI, or the wrong tenant. |
| `token endpoint: 401 invalid_client: AADSTS7000215 …` | Wrong secret. Make sure Vault holds the secret's **value**, not its ID. |
| `token endpoint: 401 invalid_client: AADSTS7000222 …` | The client secret has expired. Create a new one, put it in Vault, and restart hipr. |
| `token endpoint: 400 unauthorized_client: AADSTS700016 …` | The client ID is not an application in this tenant. Check `-auth-client-id` and `-auth-tenant`. |
| `token endpoint: 400 …: AADSTS90002 …` | The tenant is not found. Check `-auth-tenant`. |
| `token endpoint: … no such host` / `i/o timeout` | hipr cannot reach `login.microsoftonline.com`. If your network needs an outbound proxy, set `HTTPS_PROXY` for hipr: the token and Vault calls honour it, although forwarded traffic does not. |

### A request gets 502 from hipr

The body and the record's `error` begin with `hipr:`.

| Error | Cause and fix |
|---|---|
| `hipr: upstream error: dial tcp …: connection refused` | Nothing listening at the upstream address. |
| `… i/o timeout` / `no such host` | The upstream is not reachable from hipr's machine. hipr connects directly: a firewall, VPN or required corporate proxy blocks it. |
| `… tls: failed to verify certificate: x509: certificate signed by unknown authority` | The upstream's certificate is not trusted by hipr's system store. Add its CA to the system store, or `-insecure` for a dev server. |
| `… x509: certificate is valid for a, b, not c` | The upstream certificate doesn't match the name in `-upstream`. Use the name the certificate has. |
| `… timeout awaiting response headers` | The upstream took more than 60 seconds to start answering. |
| `hipr: auth: refusing to send a bearer token to … over plain http` | Use an `https://` upstream (see G). |
| `hipr: auth: no access token: …` | Renewal failed and the old token has expired. The rest of the message is one of the startup errors above, such as an expired secret or Vault/Entra unreachable. |

### The API answers 401 or 403 with hipr's token

Look at the API's `WWW-Authenticate` header and body (`-v`). Then call the API's own "who am I" endpoint, if it has one, through hipr. The sample API's `/me` shows how the API sees the caller.

- **401 `invalid_token`.** The API does not accept the token itself:
  - *Audience:* the scope asked for a different API, or the API expects its client ID where it gets its Application ID URI. If the API's manifest leaves `requestedAccessTokenVersion` unset, Entra issues v1.0 tokens, whose `aud` is the Application ID URI and whose issuer is `https://sts.windows.net/<tenant>/`. The API must accept whichever version it gets.
  - *Tenant:* hipr's app is in a different tenant from the one the API trusts.
  - *Clock:* the machine running the API (or hipr) has the wrong time, so the token looks expired or not yet valid.
- **401 although the token was valid a moment ago.** It was revoked, or the API's signing keys changed. hipr drops the token and the next request gets a new one. Only the one request fails.
- **403 `insufficient_scope`.** The token is good but lacks the permission:
  - The app role is not granted to hipr's service principal, or admin consent was not given. In Entra: *Enterprise applications* → hipr's app → *Permissions*.
  - A role granted a few minutes ago may not be in tokens yet. hipr keeps its token for up to an hour; restart hipr to pick up the new role at once.
  - The API checks scopes (`scp`) only. App-only tokens never carry `scp`. The API has to check `roles` for app callers (see examples/README.md).
- **The request did not carry hipr's token.** Look for the note in the record:
  - `kept the client's own Authorization header`: the test sent its own. Remove it, or pass `-auth-replace`.
  - no note at all: the host did not match `-auth-hosts`. Compare the record's URL host with the flag. In forward mode, HTTPS without `-mitm` never matches, because hipr cannot see inside the tunnel.

### Nothing is recorded

- The client is not using hipr. Check its proxy setting, `NO_PROXY`, and that it is not calling the service directly.
- The exchange is still open. Lines appear when an exchange ends: a stream or tunnel shows up only when it closes.
- The client sends `localhost` traffic directly (see A). Use reverse mode.

### HTTPS fails with `-mitm`

- **`tls handshake: … unknown certificate authority` or `bad certificate`** in hipr's output, and certificate errors in the client: the client does not trust hipr's CA. Find out which trust store the client uses (see the table in C). Many runtimes ignore the OS store.
- **Windows curl: "revocation status is unknown"**: add `--ssl-no-revoke`. hipr's certificates have no revocation endpoint.
- **Works in curl but not in the app:** the app pins certificates, or uses HTTP/2-only protocols such as gRPC. hipr cannot read these.
- **Broke after replacing the CA files:** clients trust the old CA. Add the new `ca.pem`, or the root of your organisation's CA, to them.
- **Broke after a long time running:** the CA has expired. A generated CA lasts 5 years; a supplied one lasts as long as it was issued for.

### Records are truncated or bodies look wrong

- `"truncated": true`: the body was larger than `-max-body` (default 1 MiB). Raise it. The traffic itself is always forwarded in full; only the record is cut. Each in-flight request can hold up to two bodies of that size in memory.
- A body shown as `base64`: it is not valid UTF-8 text (images, protobuf, other compression). gzip is decoded before storage; other encodings such as `br` are stored as received.

## Explaining hipr's behaviour

**Why does hipr's certificate show for every HTTPS site?** That is what `-mitm` does: it ends the client's TLS connection with its own certificate so it can read the traffic, then opens a separate verified connection to the real server. Without `-mitm`, HTTPS passes through untouched and unread.

**Why can't hipr use our server certificate for `-mitm`?** A server certificate is valid only for its own names, and the client visits many hosts. hipr must create a certificate for each, which needs a CA certificate. A server certificate is only right for `-tls` in reverse mode, where hipr has a single name.

**Why is the token in the record shown as `<redacted, … bytes>`?** Records are meant to be shared. Credential headers are masked, whoever sent them, and the size is kept so you can tell a token was there. The token hipr adds is never in the record at all; the record has a note instead.

**Is the token added to every request?** Only to requests for the hosts in `-auth-hosts` (default: the `-upstream` host), only over HTTPS (or to loopback), and only when the request has no `Authorization` header of its own (unless `-auth-replace`).

**Does hipr call Entra and Vault for every request?** No. Entra is called at startup, about 5 minutes before the token expires, and after a 401. Vault is read at startup and when Entra rejects the secret.

**Why does a failed request not get retried after a 401?** By the time the 401 arrives, the request body has already been sent and not kept. hipr drops the token so the next request uses a fresh one. Tests that need resilience should retry themselves.

**Why must hipr listen on `127.0.0.1` with token injection?** hipr has no authentication. With token injection, whoever can reach its port can call the API with hipr's permissions.

**Can several test jobs share one hipr?** Yes. Requests are handled concurrently and share one cached token. Because it listens on loopback, they must run on the same machine or in the same container.

## Security checklist

- [ ] hipr listens on `127.0.0.1` (the default). Any other address is deliberate, and with `-auth-*` it uses `-auth-allow-remote` only on an isolated network.
- [ ] `.hipr/ca-key.pem` and any supplied CA key are not committed, not shared, and readable only by the account that runs hipr.
- [ ] Clients trust hipr's CA only for as long as they need to.
- [ ] `-jsonl` files and console logs are treated as sensitive. Only the four credential headers are masked; bodies, URLs and other headers (API keys, session IDs in the URL, personal data) are recorded as sent. Store them like test data, and delete them when no longer needed.
- [ ] `-insecure` is used only for dev upstreams, never for real services.
- [ ] The service principal has only the app roles the tests need, and only on a test or staging API.
- [ ] The Vault policy reads only the one secret path. The AppRole secret ID is a CI secret, not a file in the repository.
- [ ] The client secret has an expiry date that someone tracks, and the rotation order (add in Entra → update Vault → remove the old one in Entra) is followed.
