package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"hipr/internal/auth"
	"hipr/internal/entratest"
	"hipr/internal/inspect"
	"hipr/internal/proxy"
	"hipr/internal/secret"
	"hipr/internal/vaulttest"
)

type events struct {
	mu  sync.Mutex
	all []*inspect.Event
}

func (s *events) Record(e *inspect.Event) { s.mu.Lock(); s.all = append(s.all, e); s.mu.Unlock() }

// TestRegressionThroughHipr is the use case end to end: a test client with no
// credentials calls the API through hipr. hipr reads its client secret from
// Vault (AppRole login), gets an app-only token from Entra, and adds it.
func TestRegressionThroughHipr(t *testing.T) {
	e := setup(t)

	fv := vaulttest.New("hvs.root")
	fv.AddAppRole("hipr-ci", "ci-secret-id")
	fv.PutKV2("secret/data/hipr/entra", map[string]any{"client_secret": "w"}) // writerApp's secret
	vault := httptest.NewServer(fv)
	t.Cleanup(vault.Close)

	cc := &auth.ClientCredentials{
		TokenURL: e.idp.TokenURL(), ClientID: writerApp, Scope: apiURI + "/.default",
		Secret: &secret.Vault{Addr: vault.URL, Path: "secret/data/hipr/entra", Field: "client_secret",
			Auth: secret.AppRoleAuth{RoleID: "hipr-ci", SecretID: "ci-secret-id"}, HTTP: vault.Client()},
	}
	apiURL, _ := url.Parse(e.api.URL)
	rec := &events{}
	hipr := httptest.NewServer(proxy.New(proxy.Options{
		Sink: rec, MaxBody: 1 << 16, Upstream: apiURL,
		Modifier: &auth.Injector{Tokens: cc, Hosts: []string{apiURL.Host}},
	}))
	t.Cleanup(hipr.Close)

	// The regression test: plain HTTP calls, no token anywhere.
	call := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, hipr.URL+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	code, body := call("GET", "/me", "")
	var me Principal
	json.Unmarshal([]byte(body), &me)
	if code != 200 || me.Kind != "app" || me.ClientID != writerApp {
		t.Fatalf("/me through hipr: %d %s", code, body)
	}
	if code, body := call("POST", "/items", `{"name":"fixture"}`); code != 201 {
		t.Fatalf("POST through hipr: %d %s", code, body)
	}
	if code, body := call("GET", "/items", ""); code != 200 || !strings.Contains(body, "fixture") {
		t.Fatalf("GET through hipr: %d %s", code, body)
	}

	// One Vault read, one token, for all three calls; the AppRole token used
	// to read Vault was revoked.
	if fv.Reads != 1 || e.idp.Issued() != 1 || fv.Revoked != 1 {
		t.Errorf("Vault reads %d, tokens issued %d, Vault tokens revoked %d; want 1, 1, 1", fv.Reads, e.idp.Issued(), fv.Revoked)
	}

	// hipr's records say a token was added, but do not contain it.
	tok, _, _ := cc.Token(t.Context())
	raw, _ := json.Marshal(rec.all)
	if strings.Contains(string(raw), tok) || !strings.Contains(string(raw), "added bearer token for client "+writerApp) {
		t.Errorf("records: token present or note missing: %s", raw)
	}

	// A real user's token passes through hipr untouched and is judged as a
	// user's: Items.Read only, so the write is refused.
	req, _ := http.NewRequest("POST", hipr.URL+"/items", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Authorization", "Bearer "+e.sign(e.idp.UserClaims(entratest.UUIDFrom("alice"), "alice", "Items.Read")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("user token through hipr: %d, want 403", resp.StatusCode)
	}
}
