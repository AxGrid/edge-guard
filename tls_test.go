package guard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testCA is a tiny cluster CA like the edge's.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
	fp   string
}

func newTestCA(t *testing.T) *testCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	h := sha256.Sum256(der)
	return &testCA{cert: c, key: k, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), fp: hex.EncodeToString(h[:])}
}

func (ca *testCA) sign(t *testing.T, pub any, name string, usage x509.ExtKeyUsage, life time.Duration) []byte {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(life), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// tlsPanel serves /api/guard/ips and /api/guard/cert with a switchable CA.
type tlsPanel struct {
	mu      sync.Mutex
	cas     []*testCA // active first
	issued  atomic.Int32
	life    time.Duration
	ts      *httptest.Server
	stopped atomic.Bool
}

func newTLSPanel(t *testing.T) *tlsPanel {
	p := &tlsPanel{cas: []*testCA{newTestCA(t)}, life: 30 * 24 * time.Hour}
	p.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.stopped.Load() {
			http.Error(w, "down", 503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+key {
			http.Error(w, "unknown key", 401)
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		var bundle string
		for _, c := range p.cas {
			bundle += c.pem
		}
		switch r.URL.Path {
		case "/api/guard/ips":
			_ = json.NewEncoder(w).Encode(map[string]any{"site": "shop", "ips": []string{"127.0.0.1"}, "ca": bundle, "ca_active": p.cas[0].fp, "server_name": "shop.edge-guard"})
		case "/api/guard/cert":
			var in struct{ CSR string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			b, _ := pem.Decode([]byte(in.CSR))
			csr, err := x509.ParseCertificateRequest(b.Bytes)
			if err != nil || csr.CheckSignature() != nil {
				http.Error(w, "bad csr", 400)
				return
			}
			der := p.cas[0].sign(t, csr.PublicKey, "shop.edge-guard", x509.ExtKeyUsageServerAuth, p.life)
			p.issued.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"site": "shop", "server_name": "shop.edge-guard", "ca": bundle,
				"cert": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.ts.Close)
	return p
}

func (p *tlsPanel) active() *testCA { p.mu.Lock(); defer p.mu.Unlock(); return p.cas[0] }

// nodeClient dials addr like an edge node: verifies the guard for site and
// presents a client certificate signed by ca with name.
func nodeClient(t *testing.T, ca *testCA, name string, usage x509.ExtKeyUsage, trust *testCA) func(addr string) error {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := ca.sign(t, &k.PublicKey, name, usage, time.Hour)
	roots := x509.NewCertPool()
	roots.AddCert(trust.cert)
	return func(addr string) error {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{
			RootCAs: roots, ServerName: "shop.edge-guard",
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}},
		})
		if err != nil {
			return err
		}
		defer c.Close()
		_, _ = c.Write([]byte("x"))
		b := make([]byte, 2)
		_, err = io.ReadFull(c, b)
		return err
	}
}

func serve(t *testing.T, g *Guard) string {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", g.ServerTLS())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 1)
				if _, err := c.Read(b); err == nil {
					_, _ = c.Write([]byte("ok"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestClusterTLS(t *testing.T) {
	p := newTLSPanel(t)
	dir := t.TempDir()
	cfg := Config{Panel: p.ts.URL, Key: key, CacheFile: filepath.Join(dir, "list.json"), ClusterTLS: true, Log: quiet}
	g, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, g)
	ca := p.active()

	if err := nodeClient(t, ca, "eu1.node.edge-guard", x509.ExtKeyUsageClientAuth, ca)(addr); err != nil {
		t.Fatalf("node: %v", err)
	}
	other := newTestCA(t)
	cases := map[string]func(string) error{
		"no client certificate": func(addr string) error {
			roots := x509.NewCertPool()
			roots.AddCert(ca.cert)
			c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "shop.edge-guard"})
			if err != nil {
				return err
			}
			defer c.Close()
			_, _ = c.Write([]byte("x"))
			_, err = io.ReadFull(c, make([]byte, 2))
			return err
		},
		"another CA":              nodeClient(t, other, "eu1.node.edge-guard", x509.ExtKeyUsageClientAuth, ca),
		"not a node name":         nodeClient(t, ca, "shop.edge-guard", x509.ExtKeyUsageClientAuth, ca),
		"server usage, no client": nodeClient(t, ca, "eu1.node.edge-guard", x509.ExtKeyUsageServerAuth, ca),
	}
	for name, dial := range cases {
		if err := dial(addr); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if st := g.Status(); st.TLS == nil || st.TLS.ServerName != "shop.edge-guard" || st.TLS.Issuer != ca.fp[:16] || st.TLS.Renewals != 1 {
		t.Errorf("status %+v", st.TLS)
	}

	// CA rotation at the panel: the guard renews with the new CA; nodes with
	// certificates of either CA are accepted (both trusted)
	newCA := newTestCA(t)
	p.mu.Lock()
	p.cas = []*testCA{newCA, ca}
	p.mu.Unlock()
	if err := g.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	g.maintainTLS(t.Context())
	if st := g.Status(); st.TLS.Issuer != newCA.fp[:16] || st.TLS.CAs != 2 {
		t.Fatalf("after rotation: %+v", st.TLS)
	}
	if err := nodeClient(t, newCA, "eu1.node.edge-guard", x509.ExtKeyUsageClientAuth, newCA)(addr); err != nil {
		t.Errorf("node with the new CA: %v", err)
	}
	if err := nodeClient(t, ca, "za1.node.edge-guard", x509.ExtKeyUsageClientAuth, newCA)(addr); err != nil {
		t.Errorf("node with the old CA during grace: %v", err)
	}
	if n := p.issued.Load(); n != 2 {
		t.Errorf("issued %d certificates, want 2", n)
	}
	g.maintainTLS(t.Context()) // nothing due: no new certificate
	if n := p.issued.Load(); n != 2 {
		t.Errorf("renewed without need: %d", n)
	}

	// restart while the panel is down: the saved list and certificate are enough
	p.stopped.Store(true)
	g2, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("restart without the panel: %v", err)
	}
	addr2 := serve(t, g2)
	if err := nodeClient(t, newCA, "eu1.node.edge-guard", x509.ExtKeyUsageClientAuth, newCA)(addr2); err != nil {
		t.Errorf("after restart: %v", err)
	}
}

// A certificate past 2/3 of its life is renewed.
func TestRenewDue(t *testing.T) {
	p := newTLSPanel(t)
	p.life = 3 * time.Second
	g, err := New(t.Context(), Config{Panel: p.ts.URL, Key: key, ClusterTLS: true, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond)
	g.maintainTLS(t.Context())
	if n := p.issued.Load(); n != 2 {
		t.Fatalf("issued %d, want a renewal", n)
	}
}

// An edge without cluster TLS (no CA in the list) is reported clearly.
func TestNoClusterTLSAtEdge(t *testing.T) {
	ts, _ := fakePanel(t, []string{"127.0.0.1"})
	_, err := New(t.Context(), Config{Panel: ts.URL, Key: key, ClusterTLS: true, HTTPClient: client(ts), Log: quiet})
	if err == nil || !strings.Contains(err.Error(), "does not offer cluster TLS") {
		t.Fatalf("err %v", err)
	}
}
