package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"hipr/internal/inspect"
)

type fakeModifier struct {
	err       error
	responses []int
}

func (m *fakeModifier) ModifyRequest(r *http.Request) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	r.Header.Set("Authorization", "Bearer injected-secret-token")
	return "added token", nil
}

func (m *fakeModifier) ModifyResponse(resp *http.Response) {
	m.responses = append(m.responses, resp.StatusCode)
}

func TestModifier(t *testing.T) {
	var seen string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "cookie-secret"})
		w.Write([]byte("ok"))
	}))
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	sink := &collector{}
	mod := &fakeModifier{}
	px := httptest.NewServer(New(Options{Sink: sink, MaxBody: 1 << 10, Upstream: upURL, Modifier: mod}))
	defer px.Close()

	req, _ := http.NewRequest("GET", px.URL+"/items", nil)
	req.Header.Set("Cookie", "a=client-cookie")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen != "Bearer injected-secret-token" {
		t.Fatalf("upstream saw Authorization %q", seen)
	}
	if len(mod.responses) != 1 || mod.responses[0] != 200 {
		t.Fatalf("ModifyResponse calls: %v", mod.responses)
	}

	e := sink.all()[0]
	if len(e.Notes) != 1 || e.Notes[0] != "added token" {
		t.Errorf("notes %v", e.Notes)
	}
	// The injected token is not in the record (it is added after the request
	// headers are captured), and the client's credentials are masked.
	all := strings.Join(e.ReqHeader.Values("Cookie"), "") + strings.Join(e.RespHeader.Values("Set-Cookie"), "")
	if e.ReqHeader.Get("Authorization") != "" || strings.Contains(all, "secret") || strings.Contains(all, "client-cookie") {
		t.Errorf("credentials recorded: req %v resp %v", e.ReqHeader, e.RespHeader)
	}

	// A modifier error fails the request without contacting upstream.
	seen = ""
	mod.err = errors.New("no access token: vault sealed")
	resp, err = http.Get(px.URL + "/items")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "vault sealed") || seen != "" {
		t.Fatalf("got %d %q, upstream saw %q", resp.StatusCode, body, seen)
	}
	if e := sink.all()[1]; e.Status != http.StatusBadGateway || !strings.Contains(e.Error, "vault sealed") {
		t.Errorf("event %+v", e)
	}
}

func TestRedactKeepsScheme(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer abc.def.ghi")
	r.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	r.Header.Set("X-Other", "visible")
	h := inspect.Redact(r.Header)
	if h.Get("Authorization") != "Bearer <redacted, 11 bytes>" || h.Get("Proxy-Authorization") != "Basic <redacted, 12 bytes>" || h.Get("X-Other") != "visible" {
		t.Errorf("redacted: %v", h)
	}
	if r.Header.Get("Authorization") != "Bearer abc.def.ghi" {
		t.Error("Redact changed the original header")
	}
}
