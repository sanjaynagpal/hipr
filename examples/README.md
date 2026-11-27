# Sample Service API: delegated and app-only Entra ID tokens

These examples show how an API protected by Microsoft Entra ID can serve two kinds of caller:

| Caller | How it gets a token | What the token carries | What the API checks |
|---|---|---|---|
| Client application, used by a person | Authorization code + PKCE | `scp` (delegated scopes) and the user's `oid` | `scp` |
| Regression tests through hipr, no person | Client credentials, as hipr's service principal | `roles` (app roles), no `scp`; `sub` = `oid` = the service principal | `roles` |

```
examples/serviceapi        the sample API: token validation (auth.go) and endpoints (api.go)
examples/mockentra         a stand-in for Entra ID, so everything runs offline
internal/entratest         the mock's implementation, also used by the tests
```

Both use only the Go standard library, like hipr.

## The rules the sample follows

These are in [serviceapi/auth.go](serviceapi/auth.go). They are what to carry over into your API.

1. **Validate the token yourself.** Check the RS256 signature against the tenant's published keys, then `iss`, `aud`, `exp` and `nbf`. Accept only RS256, so `"alg":"none"` and similar tricks fail. Fetch the keys again when an unknown `kid` shows up, since Entra rolls keys over, but no more than once a minute.
2. **Check `aud`.** A valid Entra token for another API (Microsoft Graph, say) must be rejected. Accept this API's client ID (v2.0 tokens) and, if you still get v1.0 tokens, its Application ID URI.
3. **Tell the two kinds of caller apart.** Use the `idtyp` optional claim when it is present. Without it, a token with `scp` is delegated; one without `scp` whose `sub` equals `oid` is app-only. Reject anything else.
4. **Check scopes for users and roles for apps, never the reverse.** Users can be assigned app roles too, and their tokens then carry `roles` next to `scp`. If a user's roles counted, anyone given a role in the portal would get the application permission. The test `user's app role is ignored` covers this.
5. **Keep app-only data separate.** Here an app-only caller acts as itself: what the regression tests create belongs to the service principal, so they never see or change real users' data.
6. **Answer as RFC 6750 says.** 401 with `WWW-Authenticate: Bearer error="invalid_token"` for a bad or missing token. 403 with `error="insufficient_scope"` for a good token without the permission. The response body says which scope or role was missing.

The permissions the sample defines:

| Endpoint | Users need a scope | Apps need an app role |
|---|---|---|
| `GET /items` | `Items.Read` or `Items.ReadWrite` | `Items.Read.All` or `Items.ReadWrite.All` |
| `POST /items` | `Items.ReadWrite` | `Items.ReadWrite.All` |
| `GET /me` | any valid token; shows how the API sees the caller | same |
| `GET /healthz` | none | none |

## Run it offline

```
go run ./examples/mockentra            # terminal 1: prints IDs, secrets and ready-made commands
go run ./examples/serviceapi \
  -authority http://127.0.0.1:29100/11111111-1111-1111-1111-111111111111/v2.0 \
  -audience 22222222-2222-2222-2222-222222222222,api://hipr-sample-api     # terminal 2
hipr -addr 127.0.0.1:29000 -upstream http://127.0.0.1:29010 -v            # terminal 3 (optional)
```

Get an app-only token, as hipr will, and call the API through hipr:

```
curl -s http://127.0.0.1:29100/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token \
  -d grant_type=client_credentials -d client_id=33333333-3333-3333-3333-333333333333 \
  -d client_secret=regression-secret -d scope=api://hipr-sample-api/.default

curl -H "Authorization: Bearer <access_token>" http://127.0.0.1:29000/me
curl -H "Authorization: Bearer <access_token>" -d '{"name":"fixture"}' http://127.0.0.1:29000/items
```

The mock also registers `44444444-…` (secret `norole-secret`) with no app role, which gets 403. `POST /<tenant>/dev/user-token` with `name=alice` and `scp=Items.Read` returns a delegated token in place of a browser sign-in.

mockentra creates a new signing key each time it starts. A running serviceapi picks the new key up on its own.

### Let hipr add the token

This is the regression-test setup. Run hipr with the `-auth-*` flags instead of terminal 3 above, and the tests call the API without any credentials:

```
# the secret from mockentra, as it would be stored in Vault: vault kv put secret/hipr/entra client_secret=regression-secret
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_ROLE_ID=<role id> VAULT_SECRET_ID=<secret id>
hipr -addr 127.0.0.1:29000 -upstream http://127.0.0.1:29010 -v \
  -auth-client-id 33333333-3333-3333-3333-333333333333 \
  -auth-token-url http://127.0.0.1:29100/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token \
  -auth-scope api://hipr-sample-api/.default \
  -auth-secret vault:secret/data/hipr/entra#client_secret

curl http://127.0.0.1:29000/me                                   # {"kind":"app", ...}
curl -d '{"name":"fixture"}' http://127.0.0.1:29000/items         # 201
```

Without a Vault at hand, `HIPR_SECRET=regression-secret` with `-auth-secret env:HIPR_SECRET` does the same. Against real Entra, replace `-auth-token-url` with `-auth-tenant <tenant-id>`. [hipr_test.go](serviceapi/hipr_test.go) runs this whole chain in-process.

## Tests

```
go test ./examples/...
```

[serviceapi/serviceapi_test.go](serviceapi/serviceapi_test.go) runs the API against the mock. It covers each kind of caller and each permission. It also checks rejection of tokens that are expired, not yet valid, for another API, from another tenant, of unclear kind, tampered with, unsigned, signed with an unpublished key, or malformed. Finally it covers key rollover, the limit on key fetches, data isolation, v1.0 tokens, and the client credentials flow including its error codes.

## Setting it up in Entra ID

**1. The Service API's app registration**
- *Expose an API*: set the Application ID URI (for example `api://hipr-sample-api`). Add the delegated scopes `Items.Read` and `Items.ReadWrite` for the client application to request.
- *App roles*: add `Items.Read.All` and `Items.ReadWrite.All` with **Allowed member types: Applications**. This is what makes app-only tokens possible.
- *Manifest*: set `requestedAccessTokenVersion` to `2`, so tokens have the v2.0 issuer and the API's client ID as `aud`.
- *Token configuration* (optional, recommended): add the `idtyp` optional claim to access tokens, so rule 3 does not have to infer the caller type.

**2. The client application (PKCE)**: under *API permissions*, add the delegated `Items.Read` / `Items.ReadWrite` permissions. It requests `api://hipr-sample-api/Items.Read` at sign-in. Nothing changes for it.

**3. hipr's service principal**: register an application and give it a credential: a certificate, a federated credential for your CI, or a secret. Under *API permissions*, add **Application permissions** → `Items.ReadWrite.All` (or only `Items.Read.All`), then **Grant admin consent**. Use a test or staging environment for this, not production.

Then run the API against the real tenant:

```
go run ./examples/serviceapi -tenant <tenant-id> -audience <api-client-id>,api://hipr-sample-api
```

hipr's token request is the same as above, sent to `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token` with `scope=api://hipr-sample-api/.default`. Client credentials always use `/.default`: the app gets every app role it has been granted, not individual scopes.

**4. Vault**: store the client secret, and give hipr's CI identity a policy that can read only that path:

```
vault kv put secret/hipr/entra client_secret=<secret from step 3>
vault policy write hipr-read - <<'EOF'
path "secret/data/hipr/entra" { capabilities = ["read"] }
EOF
vault write auth/approle/role/hipr-ci token_policies=hipr-read token_ttl=10m
```

When you rotate the secret, add the new one in Entra first, then update Vault, then remove the old one in Entra. hipr re-reads Vault when Entra rejects the old secret.
