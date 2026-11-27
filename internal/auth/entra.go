// Package auth adds credentials to requests hipr forwards: here, OAuth 2.0
// access tokens that hipr gets for its own service principal from Microsoft
// Entra ID with the client credentials grant.
package auth

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"hipr/internal/secret"
)

// EntraTokenURL is the v2.0 token endpoint of a tenant.
func EntraTokenURL(tenant string) string {
	return "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
}

// ClientCredentials gets and caches access tokens with the client credentials
// grant, authenticating with a client secret read from Secret.
//
// The secret is read once and kept in memory. When the token endpoint rejects
// it as invalid_client, it is read again, so rotating the secret in Vault and
// in Entra needs no restart.
type ClientCredentials struct {
	TokenURL string
	ClientID string
	Scope    string // e.g. api://hipr-sample-api/.default
	Secret   secret.Source
	HTTP     *http.Client

	mu        sync.Mutex // held while fetching, so concurrent callers share one fetch
	secret    string
	token     string
	expiry    time.Time
	refreshAt time.Time
}

// OAuthError is an error reply from the token endpoint.
type OAuthError struct {
	Status      int
	Code        string // e.g. invalid_client, invalid_scope
	Description string // Entra's AADSTS message
}

func (e *OAuthError) Error() string {
	return fmt.Sprintf("token endpoint: %d %s: %s", e.Status, e.Code, e.Description)
}

// Token returns a valid access token and when it expires. A cached token is
// used until shortly before it expires. If a refresh fails while the cached
// token is still valid, the cached one is returned.
func (c *ClientCredentials) Token(ctx context.Context) (string, time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.token != "" && now.Before(c.refreshAt) {
		return c.token, c.expiry, nil
	}
	tok, lifetime, err := c.fetch(ctx)
	if err != nil {
		if c.token != "" && now.Before(c.expiry.Add(-30*time.Second)) {
			return c.token, c.expiry, nil
		}
		return "", time.Time{}, err
	}
	// Refresh 5 minutes early, or halfway through a short-lived token.
	margin := min(5*time.Minute, lifetime/2)
	c.token, c.expiry, c.refreshAt = tok, now.Add(lifetime), now.Add(lifetime-margin)
	return c.token, c.expiry, nil
}

// Invalidate drops the cached token if it is still tok, so the next request
// fetches a new one. Call it when the API rejects tok.
func (c *ClientCredentials) Invalidate(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == tok {
		c.token = ""
	}
}

func (c *ClientCredentials) fetch(ctx context.Context) (string, time.Duration, error) {
	if c.secret == "" {
		s, err := c.Secret.Secret(ctx)
		if err != nil {
			return "", 0, fmt.Errorf("reading client secret from %s: %w", c.Secret, err)
		}
		c.secret = s
	}
	tok, lifetime, err := c.request(ctx)
	if oe, ok := errors.AsType[*OAuthError](err); ok && oe.Code == "invalid_client" {
		// Perhaps the secret was rotated: read it again and retry once.
		if s, serr := c.Secret.Secret(ctx); serr == nil && s != c.secret {
			c.secret = s
			return c.request(ctx)
		}
	}
	return tok, lifetime, err
}

func (c *ClientCredentials) request(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {c.secret},
		"scope":         {c.Scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := cmp.Or(c.HTTP, http.DefaultClient)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"` // a number, or a string from some endpoints
		Error       string          `json:"error"`
		Description string          `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("token endpoint: %s: unreadable reply: %w", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", 0, &OAuthError{Status: resp.StatusCode, Code: cmp.Or(out.Error, "no_token"), Description: out.Description}
	}
	secs, err := strconv.Atoi(strings.Trim(string(out.ExpiresIn), `"`))
	if err != nil || secs <= 0 {
		return "", 0, fmt.Errorf("token endpoint: bad expires_in %s", out.ExpiresIn)
	}
	return out.AccessToken, time.Duration(secs) * time.Second, nil
}
