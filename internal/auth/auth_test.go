package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"hipr/internal/entratest"
	"hipr/internal/secret"
	"hipr/internal/vaulttest"
)

const (
	tenant   = "11111111-1111-1111-1111-111111111111"
	clientID = "33333333-3333-3333-3333-333333333333"
	scope    = "api://hipr-sample-api/.default"
	kvPath   = "secret/data/hipr/entra"
)

type fixture struct {
	idp   *entratest.Server
	vault *vaulttest.Server
	cc    *ClientCredentials
}

// setup wires a mock Entra and a fake Vault holding the client secret, the
// way hipr is deployed: hipr reads the secret from Vault, then asks Entra.
func setup(t *testing.T) *fixture {
	t.Helper()
	idp, err := entratest.New(tenant, entratest.API{ClientID: "22222222-2222-2222-2222-222222222222", AppIDURI: "api://hipr-sample-api"})
	if err != nil {
		t.Fatal(err)
	}
	idpSrv := httptest.NewServer(idp.Handler())
	t.Cleanup(idpSrv.Close)
	idp.BaseURL = idpSrv.URL
	idp.Clients[clientID] = entratest.Client{Secret: "secret-1", ObjectID: "sp-1", Roles: []string{"Items.ReadWrite.All"}}

	fv := vaulttest.New("hvs.root")
	fv.PutKV2(kvPath, map[string]any{"client_secret": "secret-1"})
	vSrv := httptest.NewServer(fv)
	t.Cleanup(vSrv.Close)

	src := &secret.Vault{Addr: vSrv.URL, Path: kvPath, Field: "client_secret", Auth: secret.TokenAuth{Token: "hvs.root"}, HTTP: vSrv.Client()}
	cc := &ClientCredentials{TokenURL: idp.TokenURL(), ClientID: clientID, Scope: scope, Secret: src}
	return &fixture{idp: idp, vault: fv, cc: cc}
}

func (f *fixture) token(t *testing.T) string {
	t.Helper()
	tok, _, err := f.cc.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestTokenCached(t *testing.T) {
	f := setup(t)
	first := f.token(t)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if tok, _, err := f.cc.Token(context.Background()); err != nil || tok != first {
				t.Errorf("concurrent caller got a different token or %v", err)
			}
		})
	}
	wg.Wait()
	if f.idp.Issued() != 1 || f.vault.Reads != 1 {
		t.Errorf("want 1 token request and 1 Vault read, got %d and %d", f.idp.Issued(), f.vault.Reads)
	}

	// Near expiry it is refreshed; the secret is not read again.
	f.cc.refreshAt = time.Now().Add(-time.Second)
	f.token(t)
	if f.idp.Issued() != 2 || f.vault.Reads != 1 {
		t.Errorf("after refresh: %d token requests, %d Vault reads; want 2 and 1", f.idp.Issued(), f.vault.Reads)
	}
}

func TestRefreshMargin(t *testing.T) {
	f := setup(t)
	f.idp.Lifetime = 2 * time.Minute // shorter than the usual 5-minute margin
	f.token(t)
	if left := time.Until(f.cc.refreshAt); left < 50*time.Second || left > time.Minute {
		t.Errorf("a 2-minute token should be refreshed after about 1 minute, got %v", left)
	}
}

func TestSecretRotatedInVault(t *testing.T) {
	f := setup(t)
	old := f.token(t)

	// The secret is rotated: Entra accepts only the new one, Vault holds it.
	f.idp.Clients[clientID] = entratest.Client{Secret: "secret-2", ObjectID: "sp-1", Roles: []string{"Items.ReadWrite.All"}}
	f.vault.PutKV2(kvPath, map[string]any{"client_secret": "secret-2"})
	f.cc.Invalidate(old)

	// (Compare issue counts, not tokens: within one second the mock's claims,
	// and so its deterministic RS256 signatures, come out identical.)
	f.token(t)
	if f.idp.Issued() != 2 {
		t.Errorf("tokens issued = %d, want 2", f.idp.Issued())
	}
	if f.vault.Reads != 2 {
		t.Errorf("Vault reads = %d, want 2 (re-read after invalid_client)", f.vault.Reads)
	}
}

func TestErrors(t *testing.T) {
	f := setup(t)
	f.idp.Clients[clientID] = entratest.Client{Secret: "not-what-vault-has", ObjectID: "sp-1"}
	_, _, err := f.cc.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid_client") || !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Errorf("wrong secret: %v", err)
	}
	if strings.Contains(err.Error(), "secret-1") {
		t.Errorf("error leaks the secret: %v", err)
	}

	f = setup(t)
	f.cc.Scope = "api://hipr-sample-api/Items.Read"
	if _, _, err := f.cc.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid_scope") {
		t.Errorf("bad scope: %v", err)
	}

	f = setup(t)
	f.vault.PutKV2(kvPath, map[string]any{"other": "x"})
	if _, _, err := f.cc.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "reading client secret from vault") {
		t.Errorf("missing field: %v", err)
	}
}

func TestKeepsValidTokenWhenRefreshFails(t *testing.T) {
	f := setup(t)
	tok := f.token(t)
	f.cc.TokenURL = "http://127.0.0.1:1/unreachable"
	f.cc.refreshAt = time.Now().Add(-time.Second)
	if got := f.token(t); got != tok {
		t.Error("should fall back to the still-valid cached token")
	}
	f.cc.expiry = time.Now().Add(10 * time.Second)
	if _, _, err := f.cc.Token(context.Background()); err == nil {
		t.Error("a token about to expire must not be reused when refresh fails")
	}
}

func req(t *testing.T, rawURL, authz string) *http.Request {
	r, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	return r
}

func TestInjector(t *testing.T) {
	f := setup(t)
	in := &Injector{Tokens: f.cc, Hosts: []string{"api.corp.example", "127.0.0.1:29010"}}

	cases := []struct {
		name, url, authz  string
		replace           bool
		wantAuth, wantErr string // wantAuth "token" means the injected token
	}{
		{name: "configured host", url: "https://api.corp.example/items", wantAuth: "token"},
		{name: "configured host, any port", url: "https://API.corp.example:8443/items", wantAuth: "token"},
		{name: "host with port must match the port", url: "http://127.0.0.1:29011/items"},
		{name: "loopback http with port", url: "http://127.0.0.1:29010/items", wantAuth: "token"},
		{name: "other host gets nothing", url: "https://evil.example/items"},
		{name: "suffix is not a match", url: "https://api.corp.example.evil.example/"},
		{name: "plain http off loopback", url: "http://api.corp.example/items", wantErr: "plain http"},
		{name: "client's header kept", url: "https://api.corp.example/", authz: "Bearer user-token", wantAuth: "Bearer user-token"},
		{name: "client's header replaced", url: "https://api.corp.example/", authz: "Bearer user-token", replace: true, wantAuth: "token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in.Replace = tc.replace
			r := req(t, tc.url, tc.authz)
			note, err := in.ModifyRequest(r)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := r.Header.Get("Authorization")
			switch tc.wantAuth {
			case "token":
				if !strings.HasPrefix(got, "Bearer ey") || !strings.Contains(note, "added bearer token") {
					t.Fatalf("Authorization %q, note %q", got, note)
				}
				if strings.Contains(note, got[7:]) {
					t.Fatal("note contains the token")
				}
			default:
				if got != tc.wantAuth {
					t.Fatalf("Authorization %q, want %q", got, tc.wantAuth)
				}
			}
		})
	}
}

func TestInjectorDropsRejectedToken(t *testing.T) {
	f := setup(t)
	in := &Injector{Tokens: f.cc, Hosts: []string{"api.corp.example"}}
	r := req(t, "https://api.corp.example/items", "")
	in.ModifyRequest(r)

	in.ModifyResponse(&http.Response{StatusCode: http.StatusOK, Request: r})
	if f.cc.token == "" {
		t.Fatal("token dropped after a 200")
	}
	other := req(t, "https://evil.example/", r.Header.Get("Authorization"))
	in.ModifyResponse(&http.Response{StatusCode: http.StatusUnauthorized, Request: other})
	if f.cc.token == "" {
		t.Fatal("token dropped after a 401 from a host it is not sent to")
	}
	in.ModifyResponse(&http.Response{StatusCode: http.StatusUnauthorized, Request: r})
	if f.cc.token != "" {
		t.Fatal("token kept after the API rejected it")
	}
	in.ModifyRequest(req(t, "https://api.corp.example/items", ""))
	if f.idp.Issued() != 2 {
		t.Errorf("token requests = %d, want 2", f.idp.Issued())
	}
}

func TestEntraTokenURL(t *testing.T) {
	if got := EntraTokenURL("contoso.onmicrosoft.com"); got != "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token" {
		t.Error(got)
	}
	if _, err := url.Parse(EntraTokenURL("a/b")); err != nil {
		t.Error(err)
	}
}
