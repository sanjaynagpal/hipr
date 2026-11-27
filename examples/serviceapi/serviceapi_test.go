package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hipr/internal/entratest"
)

const (
	tenant      = "11111111-1111-1111-1111-111111111111"
	apiClientID = "22222222-2222-2222-2222-222222222222"
	apiURI      = "api://hipr-sample-api"
	writerApp   = "33333333-3333-3333-3333-333333333333"
	readerApp   = "44444444-4444-4444-4444-444444444444"
	noRoleApp   = "55555555-0000-0000-0000-000000000000"
)

type env struct {
	t    *testing.T
	idp  *entratest.Server
	v    *Validator
	api  *httptest.Server
	stop func()
}

func setup(t *testing.T) *env {
	t.Helper()
	idp, err := entratest.New(tenant, entratest.API{ClientID: apiClientID, AppIDURI: apiURI})
	if err != nil {
		t.Fatal(err)
	}
	idpSrv := httptest.NewServer(idp.Handler())
	t.Cleanup(idpSrv.Close)
	idp.BaseURL = idpSrv.URL
	idp.Clients[writerApp] = entratest.Client{Secret: "w", ObjectID: "sp-writer", Roles: []string{"Items.ReadWrite.All"}}
	idp.Clients[readerApp] = entratest.Client{Secret: "r", ObjectID: "sp-reader", Roles: []string{"Items.Read.All"}}
	idp.Clients[noRoleApp] = entratest.Client{Secret: "n", ObjectID: "sp-norole"}

	issuer, jwks, err := Discover(context.Background(), idpSrv.Client(), idp.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	v := NewValidator([]string{issuer, "https://sts.windows.net/" + tenant + "/"}, []string{apiClientID, apiURI}, jwks)
	v.MinRefresh = 0 // let rotation tests refetch at once
	api := httptest.NewServer(newMux(v, newStore()))
	t.Cleanup(api.Close)
	return &env{t: t, idp: idp, v: v, api: api}
}

func (e *env) sign(c map[string]any) string {
	e.t.Helper()
	tok, err := e.idp.Sign(c)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) app(clientID string) string {
	e.t.Helper()
	c, err := e.idp.AppClaims(clientID)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.sign(c)
}

func (e *env) user(name string, scopes ...string) string {
	return e.sign(e.idp.UserClaims(entratest.UUIDFrom(name), name, scopes...))
}

// call returns the status and body of a request with an optional bearer token.
func (e *env) call(method, path, token, body string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.api.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAuthorization(t *testing.T) {
	e := setup(t)
	const item = `{"name":"x"}`

	// A user who has been assigned the app role as a user: the role must not
	// stand in for the missing scope.
	userWithRole := e.idp.UserClaims("u-role", "mallory")
	userWithRole["roles"] = []string{"Items.ReadWrite.All"}
	userWithRole["scp"] = "User.Read"

	cases := []struct {
		name, method, path, token, body string
		want                            int
	}{
		{"app with ReadWrite.All reads", "GET", "/items", e.app(writerApp), "", 200},
		{"app with ReadWrite.All writes", "POST", "/items", e.app(writerApp), item, 201},
		{"app with Read.All reads", "GET", "/items", e.app(readerApp), "", 200},
		{"app with Read.All cannot write", "POST", "/items", e.app(readerApp), item, 403},
		{"app with no role", "GET", "/items", e.app(noRoleApp), "", 403},
		{"app with no role can still call /me", "GET", "/me", e.app(noRoleApp), "", 200},
		{"user with Items.Read reads", "GET", "/items", e.user("alice", "Items.Read"), "", 200},
		{"user with Items.Read cannot write", "POST", "/items", e.user("alice", "Items.Read"), item, 403},
		{"user with Items.ReadWrite writes", "POST", "/items", e.user("alice", "Items.ReadWrite"), item, 201},
		{"user's app role is ignored", "POST", "/items", e.sign(userWithRole), item, 403},
		{"no token", "GET", "/items", "", "", 401},
		{"health needs no token", "GET", "/healthz", "", "", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, body := e.call(tc.method, tc.path, tc.token, tc.body); got != tc.want {
				t.Fatalf("got %d, want %d: %s", got, tc.want, body)
			}
		})
	}
}

func TestRejectedTokens(t *testing.T) {
	e := setup(t)
	with := func(change func(map[string]any)) string {
		c, _ := e.idp.AppClaims(writerApp)
		change(c)
		return e.sign(c)
	}
	valid := e.app(writerApp)
	parts := strings.Split(valid, ".")

	// Same claims, but roles swapped in after signing.
	forged, _ := e.idp.AppClaims(noRoleApp)
	forged["roles"] = []string{"Items.ReadWrite.All"}
	forgedBody, _ := json.Marshal(forged)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forgedBody) + "." + parts[2]

	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + parts[1] + "."

	// Right issuer and claims, signed by a key the tenant never published.
	other, _ := entratest.New(tenant, e.idp.API)
	otherClaims, _ := e.idp.AppClaims(writerApp)
	foreign, _ := other.Sign(otherClaims)

	cases := map[string]struct {
		token, want string
	}{
		"expired": {with(func(c map[string]any) {
			c["exp"] = time.Now().Add(-10 * time.Minute).Unix()
		}), "expired"},
		"not yet valid": {with(func(c map[string]any) {
			c["nbf"] = time.Now().Add(10 * time.Minute).Unix()
		}), "not yet valid"},
		"token for another API": {with(func(c map[string]any) {
			c["aud"] = "00000003-0000-0000-c000-000000000000" // Microsoft Graph
		}), "audience"},
		"other tenant": {with(func(c map[string]any) {
			c["iss"] = "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0"
		}), "untrusted issuer"},
		"ambiguous caller": {with(func(c map[string]any) {
			c["sub"] = "someone-else" // no scp, and sub != oid
		}), "cannot tell"},
		"tampered claims": {tampered, "bad signature"},
		"alg none":        {none, "unsupported alg"},
		"unknown key":     {foreign, "unknown signing key"},
		"garbage":         {"not-a-token", "not a JWT"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, body := e.call("GET", "/items", tc.token, "")
			if got != 401 || !strings.Contains(body, tc.want) {
				t.Fatalf("got %d %s, want 401 mentioning %q", got, body, tc.want)
			}
		})
	}
}

func TestTokenShapes(t *testing.T) {
	e := setup(t)
	me := func(tok string) Principal {
		t.Helper()
		code, body := e.call("GET", "/me", tok, "")
		if code != 200 {
			t.Fatalf("/me: %d %s", code, body)
		}
		var p Principal
		json.Unmarshal([]byte(body), &p)
		return p
	}

	if p := me(e.app(writerApp)); p.Kind != "app" || p.ClientID != writerApp || p.ObjectID != "sp-writer" {
		t.Errorf("app-only token seen as %+v", p)
	}
	if p := me(e.user("alice", "Items.Read")); p.Kind != "user" || p.Name != "alice" || p.ClientID != entratest.PublicClientID {
		t.Errorf("delegated token seen as %+v", p)
	}

	// idtyp, when the API registration asks for it, settles the question.
	c, _ := e.idp.AppClaims(writerApp)
	c["idtyp"], c["sub"] = "app", "different"
	if p := me(e.sign(c)); p.Kind != "app" {
		t.Errorf("idtyp=app seen as %q", p.Kind)
	}

	// v1.0 token: sts.windows.net issuer, Application ID URI audience, appid.
	c, _ = e.idp.AppClaims(writerApp)
	c["iss"], c["aud"], c["ver"], c["appid"] = "https://sts.windows.net/"+tenant+"/", apiURI, "1.0", writerApp
	delete(c, "azp")
	if p := me(e.sign(c)); p.Kind != "app" || p.ClientID != writerApp {
		t.Errorf("v1.0 token seen as %+v", p)
	}

	// aud as a list.
	c, _ = e.idp.AppClaims(writerApp)
	c["aud"] = []string{"something-else", apiClientID}
	me(e.sign(c))
}

func TestDataIsolation(t *testing.T) {
	e := setup(t)
	alice, bob := e.user("alice", "Items.ReadWrite"), e.user("bob", "Items.ReadWrite")
	tester := e.app(writerApp)

	e.call("POST", "/items", alice, `{"name":"alice's"}`)
	e.call("POST", "/items", tester, `{"name":"fixture"}`)

	count := func(tok string) int {
		_, body := e.call("GET", "/items", tok, "")
		var items []Item
		json.Unmarshal([]byte(body), &items)
		return len(items)
	}
	if n := count(alice); n != 1 {
		t.Errorf("alice sees %d items, want 1", n)
	}
	if n := count(bob); n != 0 {
		t.Errorf("bob sees %d items, want 0", n)
	}
	if n := count(tester); n != 1 {
		t.Errorf("app-only caller sees %d items, want only its own 1", n)
	}
}

func TestKeyRotation(t *testing.T) {
	e := setup(t)
	if code, _ := e.call("GET", "/items", e.app(writerApp), ""); code != 200 {
		t.Fatal("first call failed")
	}

	// Entra rolls its key over: the API must pick up the new one by itself.
	if err := e.idp.Rotate(); err != nil {
		t.Fatal(err)
	}
	if code, body := e.call("GET", "/items", e.app(writerApp), ""); code != 200 {
		t.Fatalf("after rotation: %d %s", code, body)
	}

	// Unknown kids may not trigger a fetch on every request.
	e.v.MinRefresh = time.Hour
	e.idp.Rotate()
	if code, body := e.call("GET", "/items", e.app(writerApp), ""); code != 401 || !strings.Contains(body, "unknown signing key") {
		t.Fatalf("within MinRefresh: %d %s, want 401", code, body)
	}
}

// The flow hipr will run: client credentials at the token endpoint, then the
// access token as a bearer token.
func TestClientCredentialsFlow(t *testing.T) {
	e := setup(t)
	tokenFor := func(id, secret, scope string) (int, map[string]any) {
		resp, err := http.PostForm(e.idp.TokenURL(), url.Values{
			"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {scope},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, out := tokenFor(writerApp, "w", apiURI+"/.default")
	if code != 200 {
		t.Fatalf("token endpoint: %d %v", code, out)
	}
	tok, _ := out["access_token"].(string)
	if code, body := e.call("POST", "/items", tok, `{"name":"from regression run"}`); code != 201 {
		t.Fatalf("API call with fetched token: %d %s", code, body)
	}

	for name, tc := range map[string]struct {
		id, secret, scope, wantErr string
		wantCode                   int
	}{
		"wrong secret":           {writerApp, "nope", apiURI + "/.default", "invalid_client", 401},
		"unknown client":         {"nobody", "w", apiURI + "/.default", "invalid_client", 401},
		"scope without .default": {writerApp, "w", apiURI + "/Items.Read", "invalid_scope", 400},
		"another resource":       {writerApp, "w", "https://graph.microsoft.com/.default", "invalid_scope", 400},
	} {
		t.Run(name, func(t *testing.T) {
			if code, out := tokenFor(tc.id, tc.secret, tc.scope); code != tc.wantCode || out["error"] != tc.wantErr {
				t.Fatalf("got %d %v, want %d %s", code, out, tc.wantCode, tc.wantErr)
			}
		})
	}
}
