// Package mitm manages the certificate authority hipr uses to decrypt HTTPS.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const leafLifetime = 30 * 24 * time.Hour

// CA signs per-host leaf certificates on demand.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey // shared by all leaves; a key per host is needlessly slow
	pemPath string

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// CertPath is where the CA certificate (to install in clients) lives.
func (c *CA) CertPath() string { return c.pemPath }

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

	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("mitm: invalid PEM in " + dir)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, leafKey: leafKey, pemPath: certPath, cache: map[string]*tls.Certificate{}}, nil
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
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Organization: []string{"hipr"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafLifetime),
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
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: c.leafKey, Leaf: leaf}
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
