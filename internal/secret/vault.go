package secret

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Vault reads one field of a secret from HashiCorp Vault's HTTP API.
//
// Path is the API path under /v1/. For the KV version 2 engine it includes
// "data/" after the mount (secret/data/hipr/entra for the secret that
// "vault kv get secret/hipr/entra" shows); for version 1 it does not. Both
// response shapes are understood.
type Vault struct {
	Addr      string // e.g. https://vault.example.com:8200
	Path      string
	Field     string
	Namespace string // Vault Enterprise / HCP namespace, if any
	Auth      VaultAuth
	HTTP      *http.Client
}

// VaultAuth gets a Vault token to read the secret with.
type VaultAuth interface {
	// token returns a Vault token, and whether it was created for this read
	// and should be revoked afterwards.
	token(ctx context.Context, v *Vault) (tok string, revoke bool, err error)
}

// TokenAuth uses an existing Vault token. With File set, the file is read on
// every use, so a token rotated by Vault Agent is picked up.
type TokenAuth struct {
	Token string
	File  string
}

func (a TokenAuth) token(context.Context, *Vault) (string, bool, error) {
	if a.File == "" {
		return a.Token, false, nil
	}
	b, err := os.ReadFile(a.File)
	if err != nil {
		return "", false, fmt.Errorf("vault token: %w", err)
	}
	return strings.TrimSpace(string(b)), false, nil
}

// AppRoleAuth logs in with a role ID and secret ID, the usual method for
// machines such as CI runners. The token it gets is revoked after the read.
type AppRoleAuth struct {
	Mount        string // default "approle"
	RoleID       string
	SecretID     string
	SecretIDFile string // read on every login, if SecretID is empty
}

func (a AppRoleAuth) token(ctx context.Context, v *Vault) (string, bool, error) {
	sid := a.SecretID
	if sid == "" {
		b, err := os.ReadFile(a.SecretIDFile)
		if err != nil {
			return "", false, fmt.Errorf("vault AppRole secret ID: %w", err)
		}
		sid = strings.TrimSpace(string(b))
	}
	body, _ := json.Marshal(map[string]string{"role_id": a.RoleID, "secret_id": sid})
	var resp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	path := "auth/" + cmp.Or(a.Mount, "approle") + "/login"
	if err := v.call(ctx, http.MethodPost, path, "", body, &resp); err != nil {
		return "", false, fmt.Errorf("vault AppRole login: %w", err)
	}
	if resp.Auth.ClientToken == "" {
		return "", false, errors.New("vault AppRole login returned no token")
	}
	return resp.Auth.ClientToken, true, nil
}

// VaultFromEnv configures a Vault source from the environment variables the
// Vault CLI uses, plus a few for machine logins:
//
//	VAULT_ADDR                       required
//	VAULT_NAMESPACE                  optional
//	VAULT_CACERT                     optional PEM file to verify Vault's certificate
//	VAULT_ROLE_ID, VAULT_SECRET_ID   AppRole login (or VAULT_SECRET_ID_FILE;
//	                                 VAULT_APPROLE_MOUNT if not "approle")
//	VAULT_TOKEN_FILE                 a token file, e.g. a Vault Agent sink
//	VAULT_TOKEN                      a token
//	~/.vault-token                   left by "vault login", used last
//
// The first credential found in that order is used.
func VaultFromEnv(path, field string) (*Vault, error) {
	addr := strings.TrimRight(os.Getenv("VAULT_ADDR"), "/")
	if addr == "" {
		return nil, errors.New("vault: VAULT_ADDR is not set")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if ca := os.Getenv("VAULT_CACERT"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("vault: VAULT_CACERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("vault: no certificates in %s", ca)
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
		client.Transport = tr
	}

	var auth VaultAuth
	home, _ := os.UserHomeDir()
	switch {
	case os.Getenv("VAULT_ROLE_ID") != "":
		a := AppRoleAuth{Mount: os.Getenv("VAULT_APPROLE_MOUNT"), RoleID: os.Getenv("VAULT_ROLE_ID"),
			SecretID: os.Getenv("VAULT_SECRET_ID"), SecretIDFile: os.Getenv("VAULT_SECRET_ID_FILE")}
		if a.SecretID == "" && a.SecretIDFile == "" {
			return nil, errors.New("vault: VAULT_ROLE_ID is set but neither VAULT_SECRET_ID nor VAULT_SECRET_ID_FILE is")
		}
		auth = a
	case os.Getenv("VAULT_TOKEN_FILE") != "":
		auth = TokenAuth{File: os.Getenv("VAULT_TOKEN_FILE")}
	case os.Getenv("VAULT_TOKEN") != "":
		auth = TokenAuth{Token: os.Getenv("VAULT_TOKEN")}
	case home != "" && fileExists(filepath.Join(home, ".vault-token")):
		auth = TokenAuth{File: filepath.Join(home, ".vault-token")}
	default:
		return nil, errors.New("vault: no credentials; set VAULT_ROLE_ID and VAULT_SECRET_ID, VAULT_TOKEN_FILE, or VAULT_TOKEN")
	}
	return &Vault{Addr: addr, Path: path, Field: field, Namespace: os.Getenv("VAULT_NAMESPACE"), Auth: auth, HTTP: client}, nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func (v *Vault) String() string { return "vault " + v.Addr + "/v1/" + v.Path + "#" + v.Field }

// Secret logs in if needed, reads the secret and returns the field.
func (v *Vault) Secret(ctx context.Context) (string, error) {
	tok, revoke, err := v.Auth.token(ctx, v)
	if err != nil {
		return "", err
	}
	if revoke {
		defer v.revoke(tok)
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := v.call(ctx, http.MethodGet, v.Path, tok, nil, &resp); err != nil {
		// A KV v2 path without data/ is the commonest mistake. Vault answers
		// it with 404, or with 403 when the policy only covers .../data/....
		if (errors.Is(err, errNotFound) || errors.Is(err, errDenied)) && !strings.Contains(v.Path, "/data/") {
			err = fmt.Errorf("%w (if this is a KV version 2 secret, the path needs data/ after the mount, e.g. secret/data/...)", err)
		}
		return "", err
	}
	data := resp.Data
	// KV v2 wraps the fields as {"data": {...}, "metadata": {...}}.
	if inner, ok := data["data"].(map[string]any); ok {
		if _, ok := data["metadata"]; ok {
			data = inner
		}
	}
	s, ok := data[v.Field].(string)
	if !ok || s == "" {
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return "", fmt.Errorf("vault: %s has no string field %q (fields: %s)", v.Path, v.Field, strings.Join(keys, ", "))
	}
	return s, nil
}

// revoke drops a token this read created, so it does not linger until its TTL.
func (v *Vault) revoke(tok string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v.call(ctx, http.MethodPost, "auth/token/revoke-self", tok, nil, nil)
}

var (
	errNotFound = errors.New("not found")
	errDenied   = errors.New("permission denied")
)

// vaultMessage flattens Vault's error strings, which can be multi-line
// ("1 error occurred:\n\t* permission denied\n\n"), into one line.
func vaultMessage(errs []string) string {
	var parts []string
	for _, e := range errs {
		for line := range strings.Lines(e) {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "* "))
			if line != "" && !strings.HasSuffix(line, "error occurred:") && !strings.HasSuffix(line, "errors occurred:") {
				parts = append(parts, line)
			}
		}
	}
	return strings.Join(parts, "; ")
}

// call sends one request to the Vault API and decodes the JSON reply into out.
func (v *Vault) call(ctx context.Context, method, path, tok string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, v.Addr+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Request", "true")
	if tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []string `json:"errors"`
		}
		json.Unmarshal(raw, &e)
		msg := cmp.Or(vaultMessage(e.Errors), http.StatusText(resp.StatusCode))
		switch resp.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("vault: %s %s: %w", method, path, errNotFound)
		case http.StatusForbidden:
			return fmt.Errorf("vault: %s %s: 403 %w", method, path, errDenied)
		}
		return fmt.Errorf("vault: %s %s: %d %s", method, path, resp.StatusCode, msg)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}
