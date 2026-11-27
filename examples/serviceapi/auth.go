package main

// Validation of Microsoft Entra ID access tokens, and authorization that
// accepts both kinds of caller:
//
//   - delegated: a user signed in to a client app (PKCE). The token has scp,
//     the scopes the user consented to, and the user's oid.
//   - app-only: a service principal using the client credentials grant, such
//     as hipr in front of regression tests. There is no user and no scp; the
//     token has roles, the app roles assigned to that principal on this API.
//
// The rule that matters: check scopes for delegated tokens and app roles for
// app-only tokens, never the other way round. Users can be assigned app roles
// too, and a delegated token then carries roles as well as scp.

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrKeysUnavailable means the tenant's signing keys could not be fetched, so
// no token can be checked. That is this server's problem, not the caller's.
var ErrKeysUnavailable = errors.New("signing keys unavailable")

// Principal is the authenticated caller.
type Principal struct {
	Kind     string   `json:"kind"`     // "user" (delegated) or "app" (app-only)
	ObjectID string   `json:"oid"`      // the user's, or the service principal's, object ID
	ClientID string   `json:"clientId"` // the calling application
	TenantID string   `json:"tid"`
	Name     string   `json:"name,omitempty"`
	Scopes   []string `json:"scopes,omitempty"` // delegated tokens only
	Roles    []string `json:"roles,omitempty"`
}

// Validator checks a token's signature against the tenant's published keys,
// then its issuer, audience and lifetime.
type Validator struct {
	Issuers    []string      // accepted iss values
	Audiences  []string      // accepted aud values: this API's client ID and/or Application ID URI
	JWKSURI    string        // where the signing keys are published
	HTTP       *http.Client  // used to fetch the keys
	Leeway     time.Duration // clock skew allowed on exp and nbf
	MinRefresh time.Duration // least time between key fetches caused by an unknown kid

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// NewValidator returns a Validator with production defaults.
func NewValidator(issuers, audiences []string, jwksURI string) *Validator {
	return &Validator{
		Issuers: issuers, Audiences: audiences, JWKSURI: jwksURI,
		HTTP:       &http.Client{Timeout: 10 * time.Second},
		Leeway:     2 * time.Minute,
		MinRefresh: time.Minute,
	}
}

// Discover reads the OpenID configuration of an authority such as
// https://login.microsoftonline.com/<tenant>/v2.0.
func Discover(ctx context.Context, c *http.Client, authority string) (issuer, jwksURI string, err error) {
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := getJSON(ctx, c, strings.TrimSuffix(authority, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return "", "", err
	}
	if doc.Issuer == "" || doc.JWKSURI == "" {
		return "", "", errors.New("OpenID configuration has no issuer or jwks_uri")
	}
	return doc.Issuer, doc.JWKSURI, nil
}

// claims are the parts of an Entra access token this API uses.
type claims struct {
	Iss               string   `json:"iss"`
	Aud               audience `json:"aud"`
	Exp               int64    `json:"exp"`
	Nbf               int64    `json:"nbf"`
	Tid               string   `json:"tid"`
	Oid               string   `json:"oid"`
	Sub               string   `json:"sub"`
	Azp               string   `json:"azp"`   // v2.0: client ID of the calling app
	Appid             string   `json:"appid"` // v1.0: the same
	Idtyp             string   `json:"idtyp"` // "app" or "user", if requested as an optional claim
	Scp               string   `json:"scp"`   // delegated scopes, space-separated
	Roles             []string `json:"roles"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
}

// audience accepts aud as a string (what Entra sends) or a list.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(a))
}

// Validate checks raw and returns who sent it.
func (v *Validator) Validate(ctx context.Context, raw string) (*Principal, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	var hdr struct{ Alg, Kid string }
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, fmt.Errorf("bad header: %w", err)
	}
	// Entra signs access tokens with RS256. Pinning the algorithm rules out
	// "alg":"none" and algorithm-confusion tricks.
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}
	key, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("bad signature encoding")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return nil, errors.New("bad signature")
	}

	// Only now, with the signature checked, are the claims worth reading.
	var c claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, fmt.Errorf("bad claims: %w", err)
	}
	now := time.Now()
	switch {
	case c.Exp == 0 || now.After(time.Unix(c.Exp, 0).Add(v.Leeway)):
		return nil, errors.New("token expired")
	case c.Nbf != 0 && now.Add(v.Leeway).Before(time.Unix(c.Nbf, 0)):
		return nil, errors.New("token not yet valid")
	case !slices.Contains(v.Issuers, c.Iss):
		return nil, fmt.Errorf("untrusted issuer %q", c.Iss)
	case !slices.ContainsFunc(c.Aud, func(a string) bool { return slices.Contains(v.Audiences, a) }):
		// A token for another API (Microsoft Graph, say) must not work here.
		return nil, fmt.Errorf("token is for audience %q, not this API", []string(c.Aud))
	case c.Oid == "":
		return nil, errors.New("token has no oid")
	}
	return principalOf(&c)
}

func principalOf(c *claims) (*Principal, error) {
	p := &Principal{
		ObjectID: c.Oid, TenantID: c.Tid, Roles: c.Roles,
		ClientID: cmp.Or(c.Azp, c.Appid),
		Name:     cmp.Or(c.Name, c.PreferredUsername),
	}
	switch {
	case c.Idtyp == "app" || c.Idtyp == "user":
		// The explicit answer, when the API registration asks for idtyp.
		p.Kind = c.Idtyp
	case c.Scp != "":
		p.Kind = "user"
	case c.Sub == c.Oid:
		// No scp, and the subject is the service principal itself.
		p.Kind = "app"
	default:
		return nil, errors.New("cannot tell whether the token is delegated or app-only")
	}
	if p.Kind == "user" {
		p.Scopes = strings.Fields(c.Scp)
	}
	return p, nil
}

// key returns the public key for kid, fetching the key set when kid is new.
func (v *Validator) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	// An unknown kid usually means Entra rolled its keys over. Fetch again,
	// but not so often that tokens with made-up kids can drive the fetches.
	if v.keys != nil && time.Since(v.fetched) < v.MinRefresh {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
	}
	v.keys, v.fetched = keys, time.Now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func (v *Validator) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct{ Kty, Use, Kid, N, E string } `json:"keys"`
	}
	if err := getJSON(ctx, v.HTTP, v.JWKSURI, &set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(keys) == 0 {
		return nil, errors.New("no usable keys at " + v.JWKSURI)
	}
	return keys, nil
}

// Policy says who may call an endpoint: users holding any one of Scopes, or
// applications holding any one of Roles.
type Policy struct {
	Scopes []string // delegated permissions, checked against scp
	Roles  []string // application permissions (app roles), checked against roles
	anyone bool
}

// Authenticated admits any caller with a valid token for this API.
var Authenticated = Policy{anyone: true}

// Allows reports whether p may call under this policy.
func (pol Policy) Allows(p *Principal) bool {
	switch {
	case pol.anyone:
		return true
	case p.Kind == "user":
		return slices.ContainsFunc(p.Scopes, func(s string) bool { return slices.Contains(pol.Scopes, s) })
	case p.Kind == "app":
		return slices.ContainsFunc(p.Roles, func(r string) bool { return slices.Contains(pol.Roles, r) })
	}
	return false
}

func (pol Policy) requirement(p *Principal) string {
	if p.Kind == "app" {
		return "app-only callers need one of the app roles " + strings.Join(pol.Roles, ", ")
	}
	return "delegated callers need one of the scopes " + strings.Join(pol.Scopes, ", ")
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func getJSON(ctx context.Context, c *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
