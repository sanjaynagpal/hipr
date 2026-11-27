// Command serviceapi is a sample API protected by Microsoft Entra ID. It
// accepts delegated tokens from a signed-in user (scopes) and app-only tokens
// from a service principal such as hipr (app roles). See ../README.md.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:29010", "listen address")
	tenant := flag.String("tenant", "", "Entra tenant ID; sets the default -authority and also accepts v1.0 tokens from this tenant")
	authority := flag.String("authority", "", "OpenID authority (default https://login.microsoftonline.com/<tenant>/v2.0); point at mockentra to run offline")
	audience := flag.String("audience", "", "comma-separated accepted aud values: the API's client ID (v2.0 tokens) and/or Application ID URI (v1.0 tokens)")
	flag.Parse()

	if *audience == "" || (*tenant == "" && *authority == "") {
		log.Fatal("need -audience, and -tenant or -authority")
	}
	auth := *authority
	if auth == "" {
		auth = "https://login.microsoftonline.com/" + *tenant + "/v2.0"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	issuer, jwksURI, err := Discover(ctx, http.DefaultClient, auth)
	cancel()
	if err != nil {
		log.Fatalf("OpenID discovery at %s: %v", auth, err)
	}
	issuers := []string{issuer}
	if *tenant != "" {
		// v1.0 tokens, issued when the API's manifest leaves
		// requestedAccessTokenVersion unset, use this issuer and the same keys.
		issuers = append(issuers, "https://sts.windows.net/"+*tenant+"/")
	}
	var auds []string
	for a := range strings.SplitSeq(*audience, ",") {
		if a = strings.TrimSpace(a); a != "" {
			auds = append(auds, a)
		}
	}

	v := NewValidator(issuers, auds, jwksURI)
	srv := &http.Server{Addr: *addr, Handler: newMux(v, newStore()), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("serviceapi listening on %s; issuers %q, audiences %q", *addr, issuers, auds)
	log.Fatal(srv.ListenAndServe())
}
