package web

// Hot-reloading TLS certificate source. The deployment story: an external
// renewal script drops new cert/key files in place and the running server
// picks them up on the next handshake, no restart. GetCertificate re-reads
// the pair when either file's mtime changes and caches the parsed pair in
// between; a half-written or mismatched pair mid-renewal keeps serving the
// previous good one until both files agree.

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

type certReloader struct {
	certFile string
	keyFile  string

	mu      sync.Mutex
	cached  *tls.Certificate
	certMod time.Time
	keyMod  time.Time
}

func newCertReloader(certFile, keyFile string) *certReloader {
	return &certReloader{certFile: certFile, keyFile: keyFile}
}

func (c *certReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	certInfo, certErr := os.Stat(c.certFile)
	keyInfo, keyErr := os.Stat(c.keyFile)
	if certErr != nil || keyErr != nil {
		// A file is briefly missing mid-swap: serve the cached pair.
		if c.cached != nil {
			return c.cached, nil
		}
		if certErr != nil {
			return nil, certErr
		}
		return nil, keyErr
	}
	if c.cached != nil && certInfo.ModTime().Equal(c.certMod) && keyInfo.ModTime().Equal(c.keyMod) {
		return c.cached, nil
	}
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cached != nil {
			return c.cached, nil
		}
		return nil, err
	}
	c.cached = &pair
	c.certMod = certInfo.ModTime()
	c.keyMod = keyInfo.ModTime()
	return c.cached, nil
}
