package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Cluster TLS: the guard's certificate comes from the cluster CA of the
// edge (POST /api/guard/cert with the key; the private key never leaves
// this machine) and is renewed after 2/3 of its life, or at once when the
// CA was rotated. Clients must show a node certificate of the same CA.

// nodeSuffix ends the names of node client certificates.
const nodeSuffix = ".node.edge-guard"

type clusterTLS struct {
	cert     atomic.Pointer[tls.Certificate] // Leaf set
	pool     atomic.Pointer[x509.CertPool]   // trusted CAs
	cas      atomic.Pointer[[]*x509.Certificate]
	mu       sync.Mutex
	lastTry  time.Time
	lastErr  error
	renewals int
}

// TLSStatus is the cluster TLS part of Status.
type TLSStatus struct {
	ServerName string    `json:"server_name"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	Issuer     string    `json:"issuer,omitempty"` // fingerprint of the signing CA (16 hex)
	CAs        int       `json:"cas"`
	Renewals   int       `json:"renewals"`
	LastError  string    `json:"last_error,omitempty"`
}

func (g *Guard) tlsDir() string {
	if g.cfg.TLSDir != "" {
		return g.cfg.TLSDir
	}
	if g.cfg.CacheFile != "" {
		return filepath.Dir(g.cfg.CacheFile)
	}
	return ""
}

// tlsBase names this guard's files: one key/cert per panel and key.
func (g *Guard) tlsBase() string {
	h := sha256.Sum256([]byte(g.cfg.Panel + "\x00" + g.key()))
	return filepath.Join(g.tlsDir(), "cluster-tls-"+hex.EncodeToString(h[:6]))
}

func (g *Guard) startTLS(ctx context.Context) error {
	l := g.list.Load()
	if l == nil || l.CA == "" {
		return errors.New("guard: this edge does not offer cluster TLS (no CA in /api/guard/ips): update edge on the nodes, or do not use cluster TLS")
	}
	g.setCAs(l.CA)
	if c := g.readTLSFiles(); c != nil {
		g.tls.cert.Store(c)
	}
	if g.needRenew(time.Now()) {
		if err := g.renew(ctx); err != nil {
			if c := g.tls.cert.Load(); c != nil && time.Now().Before(c.Leaf.NotAfter) {
				g.log.Warn("guard: certificate renewal failed, the saved one is still valid", "err", err, "not_after", c.Leaf.NotAfter)
				return nil
			}
			return fmt.Errorf("guard: cannot get a cluster TLS certificate: %w", err)
		}
	}
	return nil
}

// maintainTLS runs after every list refresh: the CA bundle follows the
// panel, the certificate is renewed when due (failed attempts are retried
// every 10 minutes).
func (g *Guard) maintainTLS(ctx context.Context) {
	if l := g.list.Load(); l != nil && l.CA != "" {
		g.setCAs(l.CA)
	}
	now := time.Now()
	if !g.needRenew(now) {
		return
	}
	g.tls.mu.Lock()
	wait := g.tls.lastErr != nil && now.Sub(g.tls.lastTry) < 10*time.Minute
	g.tls.mu.Unlock()
	if wait {
		return
	}
	if err := g.renew(ctx); err != nil {
		g.log.Warn("guard: certificate renewal failed (retry in 10 minutes)", "err", err)
	}
}

// needRenew: no certificate, 2/3 of its life passed, or its CA is not the
// signing one any more (rotation).
func (g *Guard) needRenew(now time.Time) bool {
	c := g.tls.cert.Load()
	if c == nil || c.Leaf == nil {
		return true
	}
	life := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)
	if now.After(c.Leaf.NotBefore.Add(life * 2 / 3)) {
		return true
	}
	l := g.list.Load()
	if l == nil || l.CAActive == "" {
		return false
	}
	return g.issuerOf(c.Leaf) != l.CAActive
}

func (g *Guard) issuerOf(leaf *x509.Certificate) string {
	if cas := g.tls.cas.Load(); cas != nil {
		for _, ca := range *cas {
			if leaf.CheckSignatureFrom(ca) == nil {
				h := sha256.Sum256(ca.Raw)
				return hex.EncodeToString(h[:])
			}
		}
	}
	return ""
}

func (g *Guard) setCAs(bundle string) {
	pool := x509.NewCertPool()
	var cas []*x509.Certificate
	rest := []byte(bundle)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil && c.IsCA {
			pool.AddCert(c)
			cas = append(cas, c)
		}
	}
	if len(cas) == 0 {
		return
	}
	g.tls.pool.Store(pool)
	g.tls.cas.Store(&cas)
}

// renew makes a new key, asks the panel to sign it and saves both.
func (g *Guard) renew(ctx context.Context) error {
	g.tls.mu.Lock()
	g.tls.lastTry = time.Now()
	g.tls.mu.Unlock()
	err := g.doRenew(ctx)
	g.tls.mu.Lock()
	g.tls.lastErr = err
	if err == nil {
		g.tls.renewals++
	}
	g.tls.mu.Unlock()
	return err
}

func (g *Guard) doRenew(ctx context.Context) error {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		return err
	}
	in, _ := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	var errs []error
	for _, t := range g.targets() {
		body, err := g.call(ctx, t, "POST", "/api/guard/cert", in)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.label(), err))
			if errors.Is(err, errKey) {
				break
			}
			continue
		}
		var resp struct {
			Cert       string `json:"cert"`
			CA         string `json:"ca"`
			ServerName string `json:"server_name"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("bad answer: %w", err)
		}
		cb, _ := pem.Decode([]byte(resp.Cert))
		if cb == nil {
			return errors.New("the panel returned no certificate")
		}
		leaf, err := x509.ParseCertificate(cb.Bytes)
		if err != nil {
			return err
		}
		if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&k.PublicKey) {
			return errors.New("the panel returned a certificate for another key")
		}
		if resp.CA != "" {
			g.setCAs(resp.CA)
		}
		c := &tls.Certificate{Certificate: [][]byte{cb.Bytes}, PrivateKey: k, Leaf: leaf}
		g.tls.cert.Store(c)
		g.writeTLSFiles(k, cb.Bytes)
		g.log.Info("guard: cluster TLS certificate", "name", strings.Join(leaf.DNSNames, ","), "not_after", leaf.NotAfter.Format(time.RFC3339))
		return nil
	}
	return errors.Join(errs...)
}

func (g *Guard) readTLSFiles() *tls.Certificate {
	if g.tlsDir() == "" {
		return nil
	}
	c, err := tls.LoadX509KeyPair(g.tlsBase()+".crt", g.tlsBase()+".key")
	if err != nil {
		return nil
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return nil
		}
	}
	return &c
}

func (g *Guard) writeTLSFiles(k *ecdsa.PrivateKey, der []byte) {
	if g.tlsDir() == "" {
		return
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return
	}
	if err := os.MkdirAll(g.tlsDir(), 0o700); err != nil {
		g.log.Warn("guard: cannot save the certificate", "err", err)
		return
	}
	write := func(path string, data []byte, mode os.FileMode) error {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, mode); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}
	// the key first: a certificate without its key would be useless
	if err := write(g.tlsBase()+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		g.log.Warn("guard: cannot save the key", "err", err)
		return
	}
	if err := write(g.tlsBase()+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		g.log.Warn("guard: cannot save the certificate", "err", err)
	}
}

// ServerTLS is the TLS config of a listener with cluster TLS: the guard's
// certificate (renewed on the fly) and a required node client certificate.
// Add NextProtos when serving HTTP/2.
func (g *Guard) ServerTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := g.tls.cert.Load(); c != nil {
				return c, nil
			}
			return nil, errors.New("guard: no cluster TLS certificate yet")
		},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: g.verifyNode,
	}
}

// verifyNode accepts only a node client certificate of the cluster CA.
func (g *Guard) verifyNode(raw [][]byte, _ [][]*x509.Certificate) error {
	pool := g.tls.pool.Load()
	if pool == nil {
		return errors.New("guard: no cluster CA")
	}
	if len(raw) == 0 {
		return errors.New("guard: no client certificate")
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for _, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		g.denied.Add(1)
		return fmt.Errorf("guard: client certificate: %w", err)
	}
	for _, n := range leaf.DNSNames {
		if strings.HasSuffix(n, nodeSuffix) {
			return nil
		}
	}
	g.denied.Add(1)
	return errors.New("guard: the client certificate is not a node's")
}

func (g *Guard) tlsStatus() TLSStatus {
	st := TLSStatus{}
	if l := g.list.Load(); l != nil {
		st.ServerName = l.ServerName
	}
	if cas := g.tls.cas.Load(); cas != nil {
		st.CAs = len(*cas)
	}
	if c := g.tls.cert.Load(); c != nil && c.Leaf != nil {
		st.NotAfter = c.Leaf.NotAfter
		if fp := g.issuerOf(c.Leaf); len(fp) >= 16 {
			st.Issuer = fp[:16]
		}
	}
	g.tls.mu.Lock()
	st.Renewals = g.tls.renewals
	if g.tls.lastErr != nil {
		st.LastError = g.tls.lastErr.Error()
	}
	g.tls.mu.Unlock()
	return st
}
