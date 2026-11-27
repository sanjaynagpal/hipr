package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Permissions this API defines in its app registration.
var (
	// Read: users with Items.Read or Items.ReadWrite; apps with
	// Items.Read.All or Items.ReadWrite.All.
	canRead = Policy{
		Scopes: []string{"Items.Read", "Items.ReadWrite"},
		Roles:  []string{"Items.Read.All", "Items.ReadWrite.All"},
	}
	canWrite = Policy{
		Scopes: []string{"Items.ReadWrite"},
		Roles:  []string{"Items.ReadWrite.All"},
	}
)

// Item is the sample resource.
type Item struct {
	ID      int       `json:"id"`
	Name    string    `json:"name"`
	Owner   string    `json:"owner"`
	Created time.Time `json:"created"`
}

// store keeps items per owner. A user owns what they create; an app-only
// caller acts as itself (its service principal), so regression tests get their
// own data set and never see or change real users' items.
type store struct {
	mu    sync.Mutex
	next  int
	items map[string][]Item
}

func newStore() *store { return &store{items: map[string][]Item{}} }

func owner(p *Principal) string { return p.Kind + ":" + p.ObjectID }

func (s *store) list(owner string) []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Item{}, s.items[owner]...)
}

func (s *store) add(owner, name string) Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	it := Item{ID: s.next, Name: name, Owner: owner, Created: time.Now().UTC()}
	s.items[owner] = append(s.items[owner], it)
	return it
}

func newMux(v *Validator, st *store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// /me shows how the API sees the caller: handy when a test gets a 403.
	mux.Handle("GET /me", v.Require(Authenticated, func(w http.ResponseWriter, r *http.Request, p *Principal) {
		writeJSON(w, http.StatusOK, p)
	}))
	mux.Handle("GET /items", v.Require(canRead, func(w http.ResponseWriter, r *http.Request, p *Principal) {
		writeJSON(w, http.StatusOK, st.list(owner(p)))
	}))
	mux.Handle("POST /items", v.Require(canWrite, func(w http.ResponseWriter, r *http.Request, p *Principal) {
		var in struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "body must be JSON: {\"name\": \"...\"}")
			return
		}
		if in.Name = strings.TrimSpace(in.Name); in.Name == "" || len(in.Name) > 200 {
			writeError(w, http.StatusBadRequest, "bad_request", "name must be 1-200 characters")
			return
		}
		writeJSON(w, http.StatusCreated, st.add(owner(p), in.Name))
	}))
	return mux
}

type authedFunc func(http.ResponseWriter, *http.Request, *Principal)

// Require wraps h so it runs only for callers with a valid token that pol
// allows. Failures follow RFC 6750: 401 for a missing or invalid token, 403
// for a valid token without the needed permission.
func (v *Validator) Require(pol Policy, h authedFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid_request", "send Authorization: Bearer <access token>")
			return
		}
		p, err := v.Validate(r.Context(), raw)
		if errors.Is(err, ErrKeysUnavailable) {
			log.Printf("%s %s: %v", r.Method, r.URL.Path, err)
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "cannot verify tokens right now")
			return
		}
		if err != nil {
			log.Printf("%s %s: rejected token: %v", r.Method, r.URL.Path, err)
			// A sample can afford to say why; a production API may prefer to
			// keep the reason in its own logs.
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}
		if !pol.Allows(p) {
			log.Printf("%s %s: %s %s lacks permission", r.Method, r.URL.Path, p.Kind, p.ObjectID)
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			writeError(w, http.StatusForbidden, "insufficient_scope", pol.requirement(p))
			return
		}
		log.Printf("%s %s by %s %s (client %s)", r.Method, r.URL.Path, p.Kind, p.ObjectID, p.ClientID)
		h(w, r, p)
	})
}

func bearer(r *http.Request) (string, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	tok = strings.TrimSpace(tok)
	return tok, ok && strings.EqualFold(scheme, "Bearer") && tok != ""
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
