package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// issue creates a certificate for pub signed by parent/parentKey, or a
// self-signed one when parent is nil.
func issue(t *testing.T, name string, isCA bool, lifetime time.Duration, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	serial, err := newSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func certsPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func pkcs8PEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func writeCA(t *testing.T, certPEM, keyPEM []byte) string {
	t.Helper()
	dir := t.TempDir()
	if certPEM != nil {
		if err := os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if keyPEM != nil {
		if err := os.WriteFile(filepath.Join(dir, "ca-key.pem"), keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// verifyLeaf checks the leaf for name the way a TLS client would: trusting
// only root, with whatever intermediates hipr sends.
func verifyLeaf(t *testing.T, ca *CA, name string, root *x509.Certificate) {
	t.Helper()
	leaf, err := ca.Leaf(name)
	if err != nil {
		t.Fatal(err)
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, der := range leaf.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inter}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
}

func TestKeyFormats(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)

	cases := []struct {
		name   string
		key    crypto.Signer
		keyPEM []byte
	}{
		{"EC SEC1", ecKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})},
		{"EC PKCS8", ecKey, pkcs8PEM(t, ecKey)},
		{"RSA PKCS1", rsaKey, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})},
		{"RSA PKCS8", rsaKey, pkcs8PEM(t, rsaKey)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := issue(t, "test root", true, 24*time.Hour*365, tc.key.Public(), nil, tc.key)
			ca, err := LoadOrCreate(writeCA(t, certsPEM(root), tc.keyPEM))
			if err != nil {
				t.Fatal(err)
			}
			verifyLeaf(t, ca, "example.com", root)
			if leaf, _ := ca.Leaf("example.com"); len(leaf.Certificate) != 1 {
				t.Errorf("a root CA should send no intermediates, got chain of %d", len(leaf.Certificate))
			}
		})
	}
}

// An organisation's subordinate CA: hipr holds the intermediate's key and
// clients trust only the root.
func TestIntermediateCA(t *testing.T) {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	root := issue(t, "corp root", true, 24*time.Hour*365, rootKey.Public(), nil, rootKey)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	inter := issue(t, "corp hipr CA", true, 24*time.Hour*90, interKey.Public(), root, rootKey)

	for name, bundle := range map[string][]byte{
		"intermediate only":   certsPEM(inter),
		"intermediate + root": certsPEM(inter, root),
	} {
		t.Run(name, func(t *testing.T) {
			ca, err := LoadOrCreate(writeCA(t, bundle, pkcs8PEM(t, interKey)))
			if err != nil {
				t.Fatal(err)
			}
			verifyLeaf(t, ca, "example.com", root)
			verifyLeaf(t, ca, "127.0.0.1", root)
		})
	}
}

func TestLeafNotAfterIssuer(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := issue(t, "short root", true, 48*time.Hour, key.Public(), nil, key)
	ca, err := LoadOrCreate(writeCA(t, certsPEM(root), pkcs8PEM(t, key)))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf.NotAfter.After(root.NotAfter) {
		t.Fatalf("leaf expires %v, after its CA %v", leaf.Leaf.NotAfter, root.NotAfter)
	}
}

func TestRejects(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := issue(t, "root", true, 24*time.Hour, key.Public(), nil, key)
	notCA := issue(t, "example.com", false, 24*time.Hour, key.Public(), nil, key)

	cases := []struct {
		name, want      string
		certPEM, keyPEM []byte
	}{
		{"mismatched key", "does not match", certsPEM(root), pkcs8PEM(t, other)},
		{"not a CA", "not a CA", certsPEM(notCA), pkcs8PEM(t, key)},
		{"key missing", "needs both", certsPEM(root), nil},
		{"cert missing", "needs both", nil, pkcs8PEM(t, key)},
		{"encrypted key", "encrypted private keys", certsPEM(root), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeCA(t, tc.certPEM, tc.keyPEM)
			_, err := LoadOrCreate(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
			if tc.certPEM != nil {
				if got, _ := os.ReadFile(filepath.Join(dir, "ca.pem")); string(got) != string(tc.certPEM) {
					t.Error("ca.pem was overwritten")
				}
			}
		})
	}
}

func TestCreatesAndReloads(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !a.cert.Equal(b.cert) {
		t.Fatal("second load created a different CA")
	}
	verifyLeaf(t, b, "example.com", a.cert)
}
