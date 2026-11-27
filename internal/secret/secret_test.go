package secret

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hipr/internal/vaulttest"
)

const root = "hvs.root"

func fakeVault(t *testing.T) (*vaulttest.Server, string) {
	t.Helper()
	fv := vaulttest.New(root)
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	return fv, srv.URL
}

// clearVaultEnv makes the test independent of the developer's own Vault setup.
func clearVaultEnv(t *testing.T) {
	for _, k := range []string{"VAULT_ADDR", "VAULT_TOKEN", "VAULT_TOKEN_FILE", "VAULT_ROLE_ID", "VAULT_SECRET_ID",
		"VAULT_SECRET_ID_FILE", "VAULT_APPROLE_MOUNT", "VAULT_NAMESPACE", "VAULT_CACERT"} {
		t.Setenv(k, "")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
}

func get(t *testing.T, spec string) (string, error) {
	t.Helper()
	src, err := Parse(spec)
	if err != nil {
		return "", err
	}
	if strings.Contains(src.String(), "s3cr3t") {
		t.Errorf("String() leaks the secret: %s", src)
	}
	return src.Secret(context.Background())
}

func TestVaultToken(t *testing.T) {
	clearVaultEnv(t)
	fv, addr := fakeVault(t)
	fv.PutKV2("secret/data/hipr/entra", map[string]any{"client_secret": "s3cr3t", "other": "x"})
	fv.PutKV1("kv1/hipr", map[string]any{"client_secret": "s3cr3t-v1"})
	t.Setenv("VAULT_ADDR", addr+"/")
	t.Setenv("VAULT_TOKEN", root)

	if got, err := get(t, "vault:secret/data/hipr/entra#client_secret"); err != nil || got != "s3cr3t" {
		t.Errorf("KV v2: %q, %v", got, err)
	}
	if got, err := get(t, "vault:/kv1/hipr#client_secret"); err != nil || got != "s3cr3t-v1" {
		t.Errorf("KV v1: %q, %v", got, err)
	}

	for spec, want := range map[string]string{
		"vault:secret/hipr/entra#client_secret": "needs data/ after the mount",
		"vault:secret/data/hipr/entra#missing":  "fields: client_secret, other",
		"vault:secret/data/hipr/nothere#field":  "not found",
		"vault:secret/data/hipr/entra":          "want vault:<path>#<field>",
		"vault:#client_secret":                  "want vault:<path>#<field>",
		"consul:foo":                            "want vault:",
	} {
		if _, err := get(t, spec); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", spec, err, want)
		}
	}

	t.Setenv("VAULT_TOKEN", "hvs.wrong")
	_, err := get(t, "vault:secret/data/hipr/entra#client_secret")
	if err == nil || !strings.HasSuffix(err.Error(), "403 permission denied") {
		t.Errorf("bad token: %q, want one line ending in 403 permission denied", err)
	}

	// With a policy that covers only the data/ path, as it should, the
	// mistake of leaving data/ out shows up as 403, and still gets the hint.
	t.Setenv("VAULT_TOKEN", root)
	fv.Allowed = []string{"secret/data/hipr/entra"}
	if _, err := get(t, "vault:secret/hipr/entra#client_secret"); err == nil || !strings.Contains(err.Error(), "403 permission denied (if this is a KV version 2 secret") {
		t.Errorf("scoped policy, path without data/: %v", err)
	}
	if got, err := get(t, "vault:secret/data/hipr/entra#client_secret"); err != nil || got != "s3cr3t" {
		t.Errorf("scoped policy, right path: %q, %v", got, err)
	}
}

func TestVaultTokenFileAndNamespace(t *testing.T) {
	clearVaultEnv(t)
	fv, addr := fakeVault(t)
	fv.Namespace = "team-a"
	fv.PutKV2("secret/data/hipr/entra", map[string]any{"client_secret": "s3cr3t"})
	f := filepath.Join(t.TempDir(), "token")
	os.WriteFile(f, []byte(root+"\n"), 0o600)
	t.Setenv("VAULT_ADDR", addr)
	t.Setenv("VAULT_TOKEN_FILE", f)
	t.Setenv("VAULT_TOKEN", "ignored-when-a-file-is-set")

	if _, err := get(t, "vault:secret/data/hipr/entra#client_secret"); err == nil {
		t.Fatal("expected failure without the namespace")
	}
	t.Setenv("VAULT_NAMESPACE", "team-a")
	if got, err := get(t, "vault:secret/data/hipr/entra#client_secret"); err != nil || got != "s3cr3t" {
		t.Errorf("token file + namespace: %q, %v", got, err)
	}
}

func TestVaultHomeTokenFile(t *testing.T) {
	clearVaultEnv(t)
	fv, addr := fakeVault(t)
	fv.PutKV2("secret/data/hipr/entra", map[string]any{"client_secret": "s3cr3t"})
	home, _ := os.UserHomeDir()
	os.WriteFile(filepath.Join(home, ".vault-token"), []byte(root), 0o600)
	t.Setenv("VAULT_ADDR", addr)
	if got, err := get(t, "vault:secret/data/hipr/entra#client_secret"); err != nil || got != "s3cr3t" {
		t.Errorf("~/.vault-token: %q, %v", got, err)
	}
}

func TestVaultAppRole(t *testing.T) {
	clearVaultEnv(t)
	fv, addr := fakeVault(t)
	fv.PutKV2("secret/data/hipr/entra", map[string]any{"client_secret": "s3cr3t"})
	fv.AddAppRole("role-1", "sid-1")
	t.Setenv("VAULT_ADDR", addr)
	t.Setenv("VAULT_ROLE_ID", "role-1")

	if _, err := Parse("vault:secret/data/hipr/entra#client_secret"); err == nil || !strings.Contains(err.Error(), "VAULT_SECRET_ID") {
		t.Errorf("missing secret ID: %v", err)
	}

	sidFile := filepath.Join(t.TempDir(), "sid")
	os.WriteFile(sidFile, []byte("sid-1\n"), 0o600)
	t.Setenv("VAULT_SECRET_ID_FILE", sidFile)
	before := fv.LiveTokens()
	for range 2 {
		if got, err := get(t, "vault:secret/data/hipr/entra#client_secret"); err != nil || got != "s3cr3t" {
			t.Fatalf("AppRole: %q, %v", got, err)
		}
	}
	if fv.Revoked != 2 || fv.LiveTokens() != before {
		t.Errorf("AppRole tokens not revoked after use: revoked %d, live %d (was %d)", fv.Revoked, fv.LiveTokens(), before)
	}

	t.Setenv("VAULT_SECRET_ID", "wrong")
	if _, err := get(t, "vault:secret/data/hipr/entra#client_secret"); err == nil || !strings.Contains(err.Error(), "AppRole login") {
		t.Errorf("bad secret ID: %v", err)
	}
}

func TestVaultNotConfigured(t *testing.T) {
	clearVaultEnv(t)
	if _, err := Parse("vault:secret/data/x#y"); err == nil || !strings.Contains(err.Error(), "VAULT_ADDR") {
		t.Errorf("no VAULT_ADDR: %v", err)
	}
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	if _, err := Parse("vault:secret/data/x#y"); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("no credentials: %v", err)
	}
}

func TestEnvAndFile(t *testing.T) {
	t.Setenv("HIPR_TEST_SECRET", "s3cr3t")
	if got, err := get(t, "env:HIPR_TEST_SECRET"); err != nil || got != "s3cr3t" {
		t.Errorf("env: %q, %v", got, err)
	}
	if _, err := get(t, "env:HIPR_TEST_UNSET_SECRET"); err == nil {
		t.Error("unset env var should fail")
	}
	f := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(f, []byte("s3cr3t\r\n"), 0o600)
	if got, err := get(t, "file:"+f); err != nil || got != "s3cr3t" {
		t.Errorf("file: %q, %v", got, err)
	}
}
