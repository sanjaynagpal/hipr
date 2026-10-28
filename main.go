// Command hipr is an HTTP/HTTPS forward proxy that records the traffic passing through it.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"hipr/internal/inspect"
	"hipr/internal/mitm"
	"hipr/internal/proxy"
)

func main() {
	var (
		addr     = flag.String("addr", "127.0.0.1:8080", "listen address")
		verbose  = flag.Bool("v", false, "print headers and bodies")
		jsonl    = flag.String("jsonl", "", "append every exchange as JSON lines to this file")
		maxBody  = flag.Int64("max-body", 1<<20, "bytes of each body to keep for inspection")
		doMITM   = flag.Bool("mitm", false, "decrypt HTTPS using a local CA (clients must trust it)")
		caDir    = flag.String("ca-dir", ".hipr", "directory holding ca.pem and ca-key.pem")
		insecure = flag.Bool("insecure", false, "do not verify upstream TLS certificates")
		upstream = flag.String("upstream", "", "run as a reverse proxy in front of this server, e.g. http://localhost:29010")
		serveTLS = flag.Bool("tls", false, "serve HTTPS on the listen address using a certificate from the local CA")
	)
	flag.Parse()

	var upURL *url.URL
	if *upstream != "" {
		var err error
		if upURL, err = url.Parse(*upstream); err != nil || (upURL.Scheme != "http" && upURL.Scheme != "https") || upURL.Host == "" {
			log.Fatalf("invalid -upstream %q: want http://host:port or https://host:port", *upstream)
		}
	}

	sinks := inspect.Multi{&inspect.Text{W: os.Stdout, Verbose: *verbose}}
	if *jsonl != "" {
		f, err := os.OpenFile(*jsonl, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		sinks = append(sinks, inspect.NewJSONL(f))
	}

	opts := proxy.Options{Sink: sinks, MaxBody: *maxBody, Insecure: *insecure, Upstream: upURL}
	srv := &http.Server{Addr: *addr, ReadHeaderTimeout: 15 * time.Second}
	if *doMITM || *serveTLS {
		ca, err := mitm.LoadOrCreate(*caDir)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Trust this CA in your client: %s\n", ca.CertPath())
		if *doMITM && upURL == nil {
			opts.CA = ca
		}
		if *serveTLS {
			srv.TLSConfig = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := h.ServerName
				if name == "" {
					name = "localhost"
				}
				return ca.Leaf(name)
			}}
		}
	}
	srv.Handler = proxy.New(opts)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	mode := "forward proxy"
	if upURL != nil {
		mode = "reverse proxy -> " + upURL.String()
	}
	fmt.Printf("hipr listening on %s (%s)\n", *addr, mode)
	var err error
	if *serveTLS {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
