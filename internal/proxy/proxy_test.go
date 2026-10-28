package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"hipr/internal/inspect"
	"hipr/internal/mitm"
)

type collector struct {
	mu     sync.Mutex
	events []*inspect.Event
}

func (c *collector) Record(e *inspect.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *collector) all() []*inspect.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*inspect.Event(nil), c.events...)
}

func echo(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	w.Header().Set("X-Seen", "1")
	w.Write([]byte("got:" + string(b)))
}

func clientVia(proxyURL string, roots *x509.CertPool) *http.Client {
	u, _ := url.Parse(proxyURL)
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}}
}

func TestForwardHTTP(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(echo))
	defer up.Close()
	sink := &collector{}
	px := httptest.NewServer(New(Options{Sink: sink, MaxBody: 1 << 10}))
	defer px.Close()

	resp, err := clientVia(px.URL, nil).Post(up.URL+"/x", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "got:hello" || resp.Header.Get("X-Seen") != "1" {
		t.Fatalf("unexpected response %q %v", body, resp.Header)
	}

	evs := sink.all()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.Method != "POST" || e.Status != 200 || string(e.ReqBody.Data) != "hello" || string(e.RespBody.Data) != "got:hello" {
		t.Fatalf("bad event: %+v", e)
	}
}

func TestTunnel(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(echo))
	defer up.Close()
	sink := &collector{}
	px := httptest.NewServer(New(Options{Sink: sink, MaxBody: 1 << 10}))
	defer px.Close()

	roots := x509.NewCertPool()
	roots.AddCert(up.Certificate())
	c := clientVia(px.URL, roots)
	resp, err := c.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c.CloseIdleConnections() // ends the tunnel, which is when its event is recorded

	var evs []*inspect.Event
	for i := 0; i < 100 && len(evs) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		evs = sink.all()
	}
	if len(evs) != 1 || evs[0].Kind != "tunnel" || evs[0].BytesUp == 0 {
		t.Fatalf("bad events: %+v", evs)
	}
}

func TestIntercept(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(echo))
	defer up.Close()
	ca, err := mitm.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sink := &collector{}
	px := httptest.NewServer(New(Options{Sink: sink, MaxBody: 1 << 10, CA: ca, Insecure: true}))
	defer px.Close()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM())
	resp, err := clientVia(px.URL, roots).Post(up.URL+"/secret", "text/plain", strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "got:hi" {
		t.Fatalf("unexpected body %q", body)
	}

	evs := sink.all()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.Kind != "http" || !strings.HasPrefix(e.URL, "https://") || string(e.ReqBody.Data) != "hi" || e.Status != 200 {
		t.Fatalf("bad event: %+v", e)
	}
}

func TestUpstreamError(t *testing.T) {
	sink := &collector{}
	px := httptest.NewServer(New(Options{Sink: sink, MaxBody: 1 << 10}))
	defer px.Close()

	resp, err := clientVia(px.URL, nil).Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", resp.StatusCode)
	}
}

func TestReverse(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Host + r.URL.RequestURI()))
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL + "/base")
	sink := &collector{}
	px := httptest.NewServer(New(Options{Sink: sink, MaxBody: 1 << 10, Upstream: u}))
	defer px.Close()

	resp, err := http.Get(px.URL + "/a?b=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := u.Host + "/base/a?b=1"; string(body) != want {
		t.Fatalf("got %q want %q", body, want)
	}
	if evs := sink.all(); len(evs) != 1 || evs[0].Status != 200 || evs[0].URL != up.URL+"/base/a?b=1" {
		t.Fatalf("bad events: %+v", evs)
	}
}
