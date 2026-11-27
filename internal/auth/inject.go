package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Injector puts a bearer token on requests to the configured hosts. It
// implements proxy.RequestModifier and proxy.ResponseModifier.
type Injector struct {
	Tokens *ClientCredentials
	// Hosts the token may be sent to. An entry with a port ("api:8443")
	// matches that host and port; one without matches the host on any port.
	Hosts []string
	// Replace overwrites an Authorization header the client sent. Otherwise
	// such a request is passed on untouched.
	Replace bool
}

// ModifyRequest adds the token if r is for one of Hosts.
func (in *Injector) ModifyRequest(r *http.Request) (string, error) {
	if !in.matches(r.URL) {
		return "", nil
	}
	if r.Header.Get("Authorization") != "" && !in.Replace {
		return "auth: kept the client's own Authorization header", nil
	}
	if r.URL.Scheme != "https" && !isLoopback(r.URL.Hostname()) {
		return "", fmt.Errorf("auth: refusing to send a bearer token to %s over plain http", r.URL.Host)
	}
	tok, exp, err := in.Tokens.Token(r.Context())
	if err != nil {
		return "", fmt.Errorf("auth: no access token: %w", err)
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	return fmt.Sprintf("auth: added bearer token for client %s (expires %s)", in.Tokens.ClientID, exp.Local().Format(time.TimeOnly)), nil
}

// ModifyResponse drops the cached token when the API rejects it with 401,
// for instance because it was revoked, so the next request gets a new one.
// The rejected request itself is not retried: its body is already sent.
func (in *Injector) ModifyResponse(resp *http.Response) {
	if resp.StatusCode != http.StatusUnauthorized || resp.Request == nil || !in.matches(resp.Request.URL) {
		return
	}
	if tok, ok := strings.CutPrefix(resp.Request.Header.Get("Authorization"), "Bearer "); ok {
		in.Tokens.Invalidate(tok)
	}
}

func (in *Injector) matches(u *url.URL) bool {
	for _, h := range in.Hosts {
		if strings.EqualFold(h, u.Host) || (!strings.Contains(h, ":") && strings.EqualFold(h, u.Hostname())) {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
