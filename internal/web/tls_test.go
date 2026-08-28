package web

// TLS hot-reload tests (ait srg-2KY5X.3): a renewal script drops a new
// cert/key pair in place and the next connection serves it, no restart.
// Certificates are generated in the test; fictional hostnames only.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCertPair self-signs a certificate for reporter.example.test with the
// given serial and writes PEM files over certPath/keyPath, returning the
// certificate PEM so clients can trust it. The serial is how tests tell the
// certificates apart on the wire.
func writeCertPair(t *testing.T, certPath, keyPath string, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "reporter.example.test"},
		DNSNames:     []string{"reporter.example.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Some filesystems have coarse mtime granularity; make the change
	// unmissable so the reloader's mtime check always sees it.
	stamp := time.Now().Add(time.Duration(serial) * 2 * time.Second)
	if err := os.Chtimes(certPath, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return certPEM
}

// servedSerial makes one fresh, fully verified HTTPS connection and reports
// the serial of the certificate the server presented plus the response
// status. pool holds the test-generated certificates as trust roots.
func servedSerial(t *testing.T, addr string, pool *x509.CertPool) (int64, int) {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "reporter.example.test",
			},
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get(fmt.Sprintf("https://%s/", addr))
	if err != nil {
		t.Fatalf("https get: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no TLS state on response")
	}
	return resp.TLS.PeerCertificates[0].SerialNumber.Int64(), resp.StatusCode
}

func TestTLSServesAndHotReloadsCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "reporter.pem")
	keyPath := filepath.Join(dir, "reporter.key")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(writeCertPair(t, certPath, keyPath, 1))

	s := newTestServer(t, Config{
		Listen:   "127.0.0.1:0",
		CertFile: certPath,
		KeyFile:  keyPath,
	})
	ln, err := s.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	addr := ln.Addr().String()

	serial, status := servedSerial(t, addr, pool)
	if status != http.StatusOK {
		t.Errorf("HTTPS GET / = %d, want 200", status)
	}
	if serial != 1 {
		t.Fatalf("first connection got certificate serial %d, want 1", serial)
	}

	// The renewal script drops a new pair in place; no restart.
	pool.AppendCertsFromPEM(writeCertPair(t, certPath, keyPath, 2))
	if serial, _ := servedSerial(t, addr, pool); serial != 2 {
		t.Errorf("connection after renewal got certificate serial %d, want 2", serial)
	}
}

func TestListenFailsFastOnBadPair(t *testing.T) {
	s := newTestServer(t, Config{
		Listen:   "127.0.0.1:0",
		CertFile: filepath.Join(t.TempDir(), "missing.pem"),
		KeyFile:  filepath.Join(t.TempDir(), "missing.key"),
	})
	if ln, err := s.Listen(); err == nil {
		ln.Close()
		t.Error("expected an error for a missing certificate pair")
	}
}

func TestCertReloaderKeepsServingThroughABrokenSwap(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "reporter.pem")
	keyPath := filepath.Join(dir, "reporter.key")
	writeCertPair(t, certPath, keyPath, 1)

	r := newCertReloader(certPath, keyPath)
	first, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Mid-renewal the cert file is truncated: the cached pair must survive.
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := time.Now().Add(10 * time.Second)
	if err := os.Chtimes(certPath, broken, broken); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("broken swap should not error: %v", err)
	}
	if got != first {
		t.Error("broken swap should serve the cached pair")
	}
}
