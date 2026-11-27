package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hipr/internal/auth"
	"hipr/internal/secret"
)

// authFlags configure adding an Entra ID access token to forwarded requests.
type authFlags struct {
	clientID, tenant, tokenURL, scope, secret, hosts string
	replace, allowRemote                             bool
}

func (a *authFlags) register() {
	flag.StringVar(&a.clientID, "auth-client-id", "", "add an Entra ID access token for this application (client) ID to requests; enables token injection")
	flag.StringVar(&a.tenant, "auth-tenant", "", "Entra tenant ID or domain")
	flag.StringVar(&a.tokenURL, "auth-token-url", "", "token endpoint (default https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token)")
	flag.StringVar(&a.scope, "auth-scope", "", "scope to request, e.g. api://my-api/.default")
	flag.StringVar(&a.secret, "auth-secret", "", "where the client secret is: vault:<path>#<field>, env:<NAME> or file:<path>")
	flag.StringVar(&a.hosts, "auth-hosts", "", "comma-separated hosts (host or host:port) to send the token to (default: the -upstream host)")
	flag.BoolVar(&a.replace, "auth-replace", false, "replace an Authorization header the client sent (default: leave such requests alone)")
	flag.BoolVar(&a.allowRemote, "auth-allow-remote", false, "allow token injection on a non-loopback -addr; anyone who can reach it can call the API as this client")
}

// setup returns the request modifier, or nil if injection is not enabled.
// It fetches a token once, so a bad secret or Vault setup fails at startup
// rather than on the first test request.
func (a *authFlags) setup(listen string, upstream *url.URL, mitm bool) (*auth.Injector, error) {
	if a.clientID == "" {
		if a.tenant != "" || a.tokenURL != "" || a.scope != "" || a.secret != "" || a.hosts != "" {
			return nil, errors.New("-auth-* flags need -auth-client-id")
		}
		return nil, nil
	}
	switch {
	case a.scope == "":
		return nil, errors.New("-auth-client-id needs -auth-scope, e.g. api://my-api/.default")
	case a.secret == "":
		return nil, errors.New("-auth-client-id needs -auth-secret, e.g. vault:secret/data/hipr/entra#client_secret")
	case a.tenant == "" && a.tokenURL == "":
		return nil, errors.New("-auth-client-id needs -auth-tenant or -auth-token-url")
	}
	if host, _, err := net.SplitHostPort(listen); err == nil && !a.allowRemote {
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("token injection on %s would let anyone who can reach it call the API as %s; listen on 127.0.0.1 or pass -auth-allow-remote", listen, a.clientID)
		}
	}

	var hosts []string
	for h := range strings.SplitSeq(a.hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		if upstream == nil {
			return nil, errors.New("forward mode needs -auth-hosts: the hosts the token may be sent to")
		}
		hosts = []string{upstream.Host}
	}
	if upstream == nil && !mitm {
		fmt.Println("warning: without -mitm, HTTPS is tunnelled unread and gets no token; only plain-http requests to -auth-hosts do")
	}

	src, err := secret.Parse(a.secret)
	if err != nil {
		return nil, err
	}
	tokenURL := a.tokenURL
	if tokenURL == "" {
		tokenURL = auth.EntraTokenURL(a.tenant)
	}
	cc := &auth.ClientCredentials{
		TokenURL: tokenURL, ClientID: a.clientID, Scope: a.scope, Secret: src,
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, exp, err := cc.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting the first access token: %w", err)
	}
	fmt.Printf("auth: token for client %s from %s (secret from %s), valid until %s; sent to %s\n",
		a.clientID, tokenURL, src, exp.Local().Format(time.TimeOnly), strings.Join(hosts, ", "))
	return &auth.Injector{Tokens: cc, Hosts: hosts, Replace: a.replace}, nil
}
