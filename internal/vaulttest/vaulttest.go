// Package vaulttest is a minimal fake of HashiCorp Vault's HTTP API for
// tests: KV version 1 and 2 reads, AppRole login and token self-revocation,
// with the same paths, headers and error shapes as Vault.
package vaulttest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// Server is the fake. Its fields may be changed between requests.
type Server struct {
	mu        sync.Mutex
	tokens    map[string]bool
	secrets   map[string]kv // by API path, e.g. secret/data/hipr/entra
	appRoles  map[string]string
	Namespace string // when set, requests must carry it in X-Vault-Namespace
	// Allowed, when set, models a least-privilege policy: reads of any other
	// path get 403, whether it exists or not, as real Vault answers.
	Allowed []string
	Reads   int // secret reads served
	Revoked int // tokens revoked
}

type kv struct {
	v2   bool
	data map[string]any
}

// New returns a Server that accepts rootToken.
func New(rootToken string) *Server {
	return &Server{tokens: map[string]bool{rootToken: true}, secrets: map[string]kv{}, appRoles: map[string]string{}}
}

// PutKV2 stores data as a KV v2 secret at "<mount>/data/<path>".
func (s *Server) PutKV2(apiPath string, data map[string]any) { s.put(apiPath, kv{true, data}) }

// PutKV1 stores data as a KV v1 secret.
func (s *Server) PutKV1(apiPath string, data map[string]any) { s.put(apiPath, kv{false, data}) }

func (s *Server) put(p string, v kv) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[p] = v
}

// AddAppRole registers an AppRole login.
func (s *Server) AddAppRole(roleID, secretID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appRoles[roleID] = secretID
}

// LiveTokens reports how many tokens are currently valid.
func (s *Server) LiveTokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Namespace != "" && r.Header.Get("X-Vault-Namespace") != s.Namespace {
		fail(w, http.StatusForbidden, "permission denied")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case r.Method == http.MethodPost && path == "auth/approle/login":
		var in struct{ RoleID, SecretID string }
		var raw map[string]string
		json.NewDecoder(r.Body).Decode(&raw)
		in.RoleID, in.SecretID = raw["role_id"], raw["secret_id"]
		if want, ok := s.appRoles[in.RoleID]; !ok || want != in.SecretID {
			fail(w, http.StatusBadRequest, "invalid role or secret ID")
			return
		}
		b := make([]byte, 12)
		rand.Read(b)
		tok := "hvs." + hex.EncodeToString(b)
		s.tokens[tok] = true
		reply(w, map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": 3600}})
	case r.Method == http.MethodPost && path == "auth/token/revoke-self":
		if !s.tokens[r.Header.Get("X-Vault-Token")] {
			fail(w, http.StatusForbidden, "permission denied")
			return
		}
		delete(s.tokens, r.Header.Get("X-Vault-Token"))
		s.Revoked++
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet:
		if !s.tokens[r.Header.Get("X-Vault-Token")] {
			fail(w, http.StatusForbidden, "permission denied")
			return
		}
		if s.Allowed != nil && !slices.Contains(s.Allowed, path) {
			fail(w, http.StatusForbidden, "permission denied")
			return
		}
		sec, ok := s.secrets[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors":[]}`))
			return
		}
		s.Reads++
		if sec.v2 {
			reply(w, map[string]any{"data": map[string]any{"data": sec.data, "metadata": map[string]any{"version": 1}}})
		} else {
			reply(w, map[string]any{"data": sec.data})
		}
	default:
		fail(w, http.StatusMethodNotAllowed, "unsupported in vaulttest")
	}
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// fail answers as Vault does, including its multi-line error text.
func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"errors": []string{"1 error occurred:\n\t* " + msg + "\n\n"}})
}
