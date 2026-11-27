// Package entratest is a stand-in for Microsoft Entra ID. It publishes an
// OpenID configuration and signing keys at the same paths as Entra, issues
// app-only tokens through the client credentials grant, and mints delegated
// (user) tokens on request, all with the claims Entra puts in v2.0 access
// tokens.
//
// It exists so the sample Service API can be run and tested offline. It does
// no real authentication and must never be used outside development.
package entratest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PublicClientID is the client ID put in delegated tokens: it plays the part
// of the PKCE client application that signs users in.
const PublicClientID = "55555555-5555-5555-5555-555555555555"

// API describes the protected Service API's app registration.
type API struct {
	ClientID string // application (client) ID: the aud of v2.0 tokens
	AppIDURI string // Application ID URI, e.g. api://hipr-sample-api
}

// Client is a confidential client (a service principal) allowed to use the
// client credentials grant, such as the one hipr uses.
type Client struct {
	Secret   string
	ObjectID string   // the service principal's object ID: oid and sub of its tokens
	Roles    []string // app roles assigned to it on the API, with admin consent
}

// Server is the mock identity provider. Set BaseURL to the address it is
// served on before handing out tokens, since the issuer is derived from it.
type Server struct {
	Tenant   string
	API      API
	Clients  map[string]Client // by client ID; fill in before serving
	Lifetime time.Duration
	BaseURL  string

	mu     sync.Mutex
	keys   []signingKey // all are published; the last one signs
	issued int          // tokens issued by the token endpoint
}

// Issued reports how many tokens the client credentials endpoint has issued.
func (s *Server) Issued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issued
}

type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

// New returns a Server with one signing key and no clients.
func New(tenant string, api API) (*Server, error) {
	s := &Server{Tenant: tenant, API: api, Clients: map[string]Client{}, Lifetime: time.Hour}
	return s, s.Rotate()
}

// Rotate adds a new signing key and signs with it from now on. Older keys stay
// published, as Entra does during a rollover.
func (s *Server) Rotate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	kid := make([]byte, 8)
	rand.Read(kid)
	s.mu.Lock()
	s.keys = append(s.keys, signingKey{hex.EncodeToString(kid), key})
	s.mu.Unlock()
	return nil
}

// Issuer is the iss of every token, and the authority for OpenID discovery.
func (s *Server) Issuer() string { return s.BaseURL + "/" + s.Tenant + "/v2.0" }

// TokenURL is the OAuth 2.0 token endpoint.
func (s *Server) TokenURL() string { return s.BaseURL + "/" + s.Tenant + "/oauth2/v2.0/token" }

// Handler serves Entra's endpoints under /<tenant>/.
func (s *Server) Handler() http.Handler {
	p := "/" + s.Tenant
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+p+"/v2.0/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET "+p+"/discovery/v2.0/keys", s.jwks)
	mux.HandleFunc("POST "+p+"/oauth2/v2.0/token", s.token)
	mux.HandleFunc("POST "+p+"/dev/user-token", s.userToken)
	return mux
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.Issuer(),
		"jwks_uri":                              s.BaseURL + "/" + s.Tenant + "/discovery/v2.0/keys",
		"token_endpoint":                        s.TokenURL(),
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []map[string]string
	for _, k := range s.keys {
		keys = append(keys, map[string]string{
			"kty": "RSA", "use": "sig", "kid": k.kid,
			"n": b64(k.key.N.Bytes()),
			"e": b64(big.NewInt(int64(k.key.E)).Bytes()),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// token implements the client credentials grant with a client secret, and
// answers errors with the same codes Entra uses.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if g := r.PostForm.Get("grant_type"); g != "client_credentials" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "AADSTS70003: this mock supports only client_credentials, got "+g)
		return
	}
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		id, secret = u, p
	}
	c, ok := s.Clients[id]
	if !ok || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "AADSTS7000215: Invalid client secret provided.")
		return
	}
	if sc := r.PostForm.Get("scope"); sc != s.API.AppIDURI+"/.default" && sc != s.API.ClientID+"/.default" {
		oauthError(w, http.StatusBadRequest, "invalid_scope",
			fmt.Sprintf("AADSTS1002012: The provided value for scope %q is not valid. Client credential flows must have a scope value with /.default suffixed to the resource identifier (%s/.default).", sc, s.API.AppIDURI))
		return
	}
	claims, err := s.AppClaims(id)
	if err == nil {
		var tok string
		if tok, err = s.Sign(claims); err == nil {
			s.mu.Lock()
			s.issued++
			s.mu.Unlock()
			secs := int(s.Lifetime.Seconds())
			writeJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer", "expires_in": secs, "ext_expires_in": secs, "access_token": tok})
			return
		}
	}
	oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
}

// userToken stands in for an interactive PKCE sign-in, which needs a browser:
// POST name=alice&scp=Items.Read returns a delegated token for that user.
func (s *Server) userToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("name") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "form fields: name (required), scp (space-separated scopes), oid (optional)")
		return
	}
	name := r.PostForm.Get("name")
	oid := r.PostForm.Get("oid")
	if oid == "" {
		oid = UUIDFrom(name)
	}
	tok, err := s.Sign(s.UserClaims(oid, name, strings.Fields(r.PostForm.Get("scp"))...))
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer", "expires_in": int(s.Lifetime.Seconds()), "access_token": tok})
}

func (s *Server) base() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": s.Issuer(), "aud": s.API.ClientID, "tid": s.Tenant, "ver": "2.0",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(s.Lifetime).Unix(),
	}
}

// AppClaims returns the claims of an app-only token for a registered client:
// no scp, sub equal to oid, and the client's app roles. Entra adds idtyp only
// when the API asks for it as an optional claim, so it is left out here.
func (s *Server) AppClaims(clientID string) (map[string]any, error) {
	c, ok := s.Clients[clientID]
	if !ok {
		return nil, errors.New("entratest: unknown client " + clientID)
	}
	m := s.base()
	m["azp"], m["azpacr"] = clientID, "1"
	m["oid"], m["sub"] = c.ObjectID, c.ObjectID
	if len(c.Roles) > 0 {
		m["roles"] = c.Roles
	}
	return m, nil
}

// UserClaims returns the claims of a delegated token issued to the public
// client application for a user. sub is a pairwise ID, different from oid.
func (s *Server) UserClaims(oid, name string, scopes ...string) map[string]any {
	m := s.base()
	m["azp"], m["azpacr"] = PublicClientID, "0"
	m["oid"], m["sub"] = oid, b64(sha256Sum(oid + PublicClientID))[:43]
	m["name"], m["preferred_username"] = name, strings.ToLower(name)+"@contoso.test"
	m["scp"] = strings.Join(scopes, " ")
	return m
}

// Sign returns claims as a JWT signed with the current key. Tests use it to
// build tokens Entra would never issue (expired, wrong audience, ...).
func (s *Server) Sign(claims map[string]any) (string, error) {
	s.mu.Lock()
	k := s.keys[len(s.keys)-1]
	s.mu.Unlock()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": k.kid})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64(hdr) + "." + b64(body)
	sum := sha256Sum(in)
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum)
	if err != nil {
		return "", err
	}
	return in + "." + b64(sig), nil
}

// UUIDFrom derives a stable UUID-shaped ID from s, so a user name always maps
// to the same oid.
func UUIDFrom(s string) string {
	h := hex.EncodeToString(sha256Sum(s))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func sha256Sum(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
