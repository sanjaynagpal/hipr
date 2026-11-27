// Package mitm manages the certificate authority hipr uses to decrypt HTTPS.
package mitm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const leafLifetime = 30 * 24 * time.Hour

// CA signs per-host leaf certificates on demand.
type CA struct {
	cert    *x509.Certificate
	chain   [][]byte // DER of the non-root certificates in ca.pem, sent after each leaf
	key     crypto.Signer
	leafKey *ecdsa.PrivateKey // shared by all leaves; a key per host is needlessly slow
	pemPath string

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// CertPath is where the CA certificate (to install in clients) lives.
func (c *CA) CertPath() string { return c.pemPath }

// IsRoot reports whether the CA is self-signed. When it is not, clients must
// trust the root it chains to rather than ca.pem.
func (c *CA) IsRoot() bool { return selfSigned(c.cert) }

// CertPEM returns the CA certificate in PEM form.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// LoadOrCreate reads ca.pem and ca-key.pem from dir, creating them if absent.
func LoadOrCreate(dir string) (*CA, error) {
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		if certErr != nil && !errors.Is(certErr, os.ErrNotExist) {
			return nil, certErr
		}
		if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
			return nil, keyErr
		}
		if certErr == nil || keyErr == nil {
			// Never overwrite half of a CA someone put here.
			return nil, fmt.Errorf("mitm: %s needs both ca.pem and ca-key.pem, or neither to create a new CA", dir)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		var err error
		if certPEM, keyPEM, err = generateCA(); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return nil, err
		}
	}

	certs, err := parseCerts(certPEM)
	if err != nil {
		return nil, fmt.Errorf("mitm: %s: %w", certPath, err)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("mitm: %s: %w", keyPath, err)
	}
	cert := certs[0]
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("mitm: %s is not a CA certificate allowed to sign certificates", certPath)
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, fmt.Errorf("mitm: %s does not match the certificate in %s", keyPath, certPath)
	}
	// Clients need every intermediate between the leaf and the root they trust,
	// including cert itself when it is not a root. Roots are left out: the
	// client has to have them already.
	var chain [][]byte
	for _, c := range certs {
		if !selfSigned(c) {
			chain = append(chain, c.Raw)
		}
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, chain: chain, key: key, leafKey: leafKey, pemPath: certPath, cache: map[string]*tls.Certificate{}}, nil
}

// parseCerts returns every CERTIFICATE block in data, in order. The first is
// the signing CA; any others are the intermediates above it.
func parseCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM CERTIFICATE block")
	}
	return certs, nil
}

// parseKey reads the first private key block in data, accepting PKCS#8
// ("PRIVATE KEY"), SEC 1 ("EC PRIVATE KEY") and PKCS#1 ("RSA PRIVATE KEY").
func parseKey(data []byte) (crypto.Signer, error) {
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			return nil, errors.New("no PEM private key block")
		}
		if !strings.HasSuffix(b.Type, "PRIVATE KEY") {
			continue
		}
		var key any
		var err error
		switch b.Type {
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("encrypted private keys are not supported; decrypt it first (openssl pkey -in key.pem -out ca-key.pem)")
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(b.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		default:
			key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		}
		if err != nil {
			return nil, err
		}
		s, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type %T", key)
		}
		return s, nil
	}
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// Leaf returns a certificate for name (a DNS name or IP), signed by the CA.
func (c *CA) Leaf(name string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.cache[name]; ok && time.Until(cert.Leaf.NotAfter) > time.Hour {
		return cert, nil
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	// A leaf must not outlive its issuer, which a supplied CA may well be close to.
	notAfter := time.Now().Add(leafLifetime)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Organization: []string{"hipr"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &c.leafKey.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: append([][]byte{der}, c.chain...), PrivateKey: c.leafKey, Leaf: leaf}
	c.cache[name] = cert
	return cert, nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func generateCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "hipr local CA", Organization: []string{"hipr"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
