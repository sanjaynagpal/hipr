// Package proxy implements hipr's forward proxy: plain HTTP forwarding,
// CONNECT tunnels, and optional TLS interception.
package proxy

import (
	"crypto/tls"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hipr/internal/inspect"
	"hipr/internal/mitm"
)

// Options configures a Proxy.
type Options struct {
	Sink     inspect.Sink
	MaxBody  int64         // bytes of each body kept for inspection
	CA       *mitm.CA      // when set, CONNECT tunnels are decrypted
	Insecure bool          // skip verification of upstream certificates
	Dial     time.Duration // upstream dial timeout; default 10s
	Upstream *url.URL      // when set, run as a reverse proxy to this server
}

// Proxy is an http.Handler that acts as a forward proxy, or as a reverse
// proxy when Options.Upstream is set.
type Proxy struct {
	opts      Options
	transport *http.Transport
	dialer    net.Dialer
	nextID    atomic.Uint64
}

func New(o Options) *Proxy {
	if o.Dial == 0 {
		o.Dial = 10 * time.Second
	}
	p := &Proxy{opts: o, dialer: net.Dialer{Timeout: o.Dial, KeepAlive: 30 * time.Second}}
	p.transport = &http.Transport{
		DialContext:           p.dialer.DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: o.Insecure},
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case p.opts.Upstream != nil:
		if r.Method == http.MethodConnect {
			http.Error(w, "hipr is running as a reverse proxy: CONNECT is not supported", http.StatusMethodNotAllowed)
			return
		}
		u := p.opts.Upstream
		r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
		r.URL.Path = singleJoiningSlash(u.Path, r.URL.Path)
		r.URL.RawPath = ""
		r.Host = u.Host
		p.forward(w, r)
	case r.Method == http.MethodConnect:
		p.connect(w, r)
	case r.URL.Host == "":
		http.Error(w, "hipr is a forward proxy: send absolute-URI requests", http.StatusBadRequest)
	default:
		p.forward(w, r)
	}
}

// singleJoiningSlash joins a base path and a request path with exactly one slash.
func singleJoiningSlash(base, p string) string {
	switch {
	case base == "" || base == "/":
		return p
	case strings.HasSuffix(base, "/") == strings.HasPrefix(p, "/"):
		if strings.HasSuffix(base, "/") {
			return base + p[1:]
		}
		return base + "/" + p
	}
	return base + p
}

// forward relays one request upstream and streams the response back,
// recording both sides. r.URL must be absolute.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ev := &inspect.Event{
		ID: p.nextID.Add(1), Time: start, Kind: "http", ClientAddr: r.RemoteAddr,
		Method: r.Method, URL: r.URL.String(), Proto: r.Proto, ReqHeader: r.Header.Clone(),
	}
	reqCap := &capture{max: p.opts.MaxBody}
	respCap := &capture{max: p.opts.MaxBody}
	defer func() {
		ev.Duration = time.Since(start)
		ev.ReqBody = reqCap.body(r.Header)
		if ev.RespHeader != nil {
			ev.RespBody = respCap.body(ev.RespHeader)
		}
		p.opts.Sink.Record(ev)
	}()

	out := r.Clone(r.Context())
	out.RequestURI = ""
	stripHopByHop(out.Header)
	if r.Body != nil && r.Body != http.NoBody {
		out.Body = struct {
			io.Reader
			io.Closer
		}{io.TeeReader(r.Body, reqCap), r.Body}
	}

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		ev.Error = err.Error()
		ev.Status = http.StatusBadGateway
		http.Error(w, "hipr: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	ev.Status = resp.StatusCode
	ev.RespHeader = resp.Header.Clone()
	stripHopByHop(resp.Header)
	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	fw := flushWriter{w: w}
	fw.f, _ = w.(http.Flusher)
	if _, err := io.Copy(fw, io.TeeReader(resp.Body, respCap)); err != nil {
		ev.Error = err.Error()
	}
}

// connect handles CONNECT, either tunneling bytes blindly or, with a CA, decrypting.
func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	if p.opts.CA != nil {
		p.intercept(hj, r)
		return
	}
	p.tunnel(w, hj, r)
}

func (p *Proxy) tunnel(w http.ResponseWriter, hj http.Hijacker, r *http.Request) {
	start := time.Now()
	ev := &inspect.Event{ID: p.nextID.Add(1), Time: start, Kind: "tunnel", ClientAddr: r.RemoteAddr, Method: "CONNECT", URL: r.Host}
	defer func() {
		ev.Duration = time.Since(start)
		p.opts.Sink.Record(ev)
	}()

	up, err := p.dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		ev.Error = err.Error()
		http.Error(w, "hipr: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer up.Close()
	client, _, err := hj.Hijack()
	if err != nil {
		ev.Error = err.Error()
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		ev.Error = err.Error()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ev.BytesUp = pipe(up, client) }()
	go func() { defer wg.Done(); ev.BytesDown = pipe(client, up) }()
	wg.Wait()
}

// pipe copies src to dst then half-closes dst so the peer sees EOF.
func pipe(dst, src net.Conn) int64 {
	n, _ := io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
	return n
}

// intercept terminates the client's TLS with a forged certificate, then serves
// the decrypted requests through forward, so they are recorded like plain HTTP.
func (p *Proxy) intercept(hj http.Hijacker, r *http.Request) {
	target := r.Host
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		target = net.JoinHostPort(host, "443")
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		return
	}

	tc := tls.Server(client, &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return p.opts.CA.Leaf(name)
		},
	})
	client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		p.opts.Sink.Record(&inspect.Event{
			ID: p.nextID.Add(1), Time: time.Now(), Kind: "tunnel", ClientAddr: r.RemoteAddr,
			Method: "CONNECT", URL: r.Host, Error: "tls handshake: " + err.Error(),
		})
		client.Close()
		return
	}
	client.SetDeadline(time.Time{})

	srv := &http.Server{
		IdleTimeout: 60 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = target
			p.forward(w, req)
		}),
	}
	srv.Serve(newConnListener(tc))
}

// connListener serves exactly one connection, then reports closed once that
// connection has been closed so http.Server.Serve returns.
type connListener struct {
	ch   chan net.Conn
	done chan struct{}
}

func newConnListener(c net.Conn) *connListener {
	l := &connListener{ch: make(chan net.Conn, 1), done: make(chan struct{})}
	var once sync.Once
	l.ch <- &closeNotifier{Conn: c, notify: func() { once.Do(func() { close(l.done) }) }}
	return l
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *connListener) Close() error   { return nil }
func (l *connListener) Addr() net.Addr { return &net.TCPAddr{} }

type closeNotifier struct {
	net.Conn
	notify func()
}

func (c *closeNotifier) Close() error {
	defer c.notify()
	return c.Conn.Close()
}

// capture keeps the first max bytes of whatever is written to it.
type capture struct {
	max  int64
	buf  []byte
	size int64
}

func (c *capture) Write(b []byte) (int, error) {
	n := len(b)
	c.size += int64(n)
	if room := c.max - int64(len(c.buf)); room > 0 {
		if int64(len(b)) > room {
			b = b[:room]
		}
		c.buf = append(c.buf, b...)
	}
	return n, nil
}

func (c *capture) body(h http.Header) inspect.Body {
	b := inspect.Body{Size: c.size, Truncated: c.size > int64(len(c.buf))}
	b.Data = inspect.Decode(c.buf, strings.ToLower(h.Get("Content-Encoding")))
	return b
}

// flushWriter flushes after every write so streaming responses (SSE, chunked) are not delayed.
type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw flushWriter) Write(b []byte) (int, error) {
	n, err := fw.w.Write(b)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for name := range strings.SplitSeq(v, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}
