package guard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const key = "0123456789abcdef0123456789"

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakePanel answers /api/guard/ips like the edge admin API.
func fakePanel(t *testing.T, ips []string) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/api/guard/ips" || r.Header.Get("Authorization") != "Bearer "+key {
			http.Error(w, `{"error":"unknown key"}`, 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"site": "shop", "header": "X-Shop-Auth", "ips": ips, "refresh_seconds": 60})
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

// client trusts the test server and dials only IP addresses: a panel host
// name "does not resolve".
func client(ts *httptest.Server) *http.Client {
	c := ts.Client()
	tr := c.Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if net.ParseIP(host) == nil {
			return nil, errors.New("no such host " + host)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func req(remote, header string) *http.Request {
	r := httptest.NewRequest("GET", "/x", nil)
	r.RemoteAddr = remote
	if header != "" {
		r.Header.Set("X-Shop-Auth", header)
	}
	return r
}

func TestHandler(t *testing.T) {
	ts, _ := fakePanel(t, []string{"203.0.113.10", "2001:db8::/64"})
	g, err := New(t.Context(), Config{Panel: ts.URL, Key: key, Allow: []string{"10.1.0.0/16"}, HTTPClient: client(ts), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	h := g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Shop-Auth") + "|" + g.ClientIP(r)
		w.WriteHeader(204)
	}))
	cases := []struct {
		remote, header string
		code           int
	}{
		{"203.0.113.10:5000", key, 204},       // a node with the key
		{"[2001:db8::7]:5000", key, 204},      // a node inside an IPv6 prefix
		{"203.0.113.10:5000", "", 403},        // a node without the key: another site on the same edge
		{"203.0.113.10:5000", "wrong", 403},   // wrong key
		{"198.51.100.1:5000", key, 403},       // not a node, even with the key
		{"10.1.2.3:5000", "", 204},            // Allow: no key needed
		{"[::ffff:203.0.113.10]:1", key, 204}, // IPv4-mapped
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(c.remote, c.header))
		if w.Code != c.code {
			t.Errorf("%s key=%q: %d, want %d", c.remote, c.header, w.Code, c.code)
		}
		if c.code == 403 && strings.TrimSpace(w.Body.String()) != "Forbidden" {
			t.Errorf("body %q", w.Body.String())
		}
	}
	r := req("203.0.113.10:5000", key)
	r.Header.Set("X-Real-Ip", "192.0.2.77")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "|192.0.2.77" {
		t.Errorf("header not stripped or client IP wrong: %q", got)
	}
	if st := g.Status(); st.Site != "shop" || st.Denied != 3 {
		t.Errorf("status %+v", st)
	}
}

// The panel name does not resolve: the guard asks a node address with the
// panel's TLS name; later it keeps the cached list without the panel.
func TestNodesAndCache(t *testing.T) {
	ts, hits := fakePanel(t, []string{"203.0.113.10"})
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	cache := filepath.Join(t.TempDir(), "guard.json")
	cfg := Config{Panel: "https://example.com:" + port, Nodes: []string{"127.0.0.1"}, Key: key, CacheFile: cache, HTTPClient: client(ts), Log: quiet}
	g, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !g.AllowedAddr("203.0.113.10:1") || hits.Load() != 1 {
		t.Fatalf("via node: allowed=%v hits=%d", g.AllowedAddr("203.0.113.10:1"), hits.Load())
	}
	ts.Close()
	g2, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("from cache: %v", err)
	}
	if !g2.AllowedAddr("203.0.113.10:1") || g2.Status().LastError == "" {
		t.Errorf("cache: %+v", g2.Status())
	}
	cfg.CacheFile = filepath.Join(t.TempDir(), "none.json")
	if _, err := New(t.Context(), cfg); !errors.Is(err, ErrNoList) {
		t.Errorf("no panel, no cache: %v", err)
	}
}

func TestWrongKey(t *testing.T) {
	ts, hits := fakePanel(t, []string{"203.0.113.10"})
	_, err := New(t.Context(), Config{Panel: ts.URL, Nodes: []string{"127.0.0.1"}, Key: strings.Repeat("x", 30), HTTPClient: client(ts), Log: quiet})
	if err == nil || !strings.Contains(err.Error(), "origin-auth secret") {
		t.Fatalf("err %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("a wrong key must not be tried on every node: %d requests", hits.Load())
	}
	if _, err := New(t.Context(), Config{Panel: ts.URL, Key: "short"}); err == nil {
		t.Error("short key accepted")
	}
}

func TestListener(t *testing.T) {
	ts, _ := fakePanel(t, []string{"127.0.0.1"})
	g, err := New(t.Context(), Config{Panel: ts.URL, Key: key, HTTPClient: client(ts), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	gl := g.Listener(ln)
	defer gl.Close()
	go func() {
		c, _ := net.Dial("tcp", ln.Addr().String())
		if c != nil {
			_, _ = c.Write([]byte("hi"))
		}
	}()
	c, err := gl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// not in the list any more: refused
	g.apply(&List{IPs: []string{"203.0.113.10"}})
	go func() { _, _ = net.Dial("tcp", ln.Addr().String()) }()
	done := make(chan struct{})
	go func() { _, _ = gl.Accept(); close(done) }()
	select {
	case <-done:
		t.Fatal("a connection from outside the list was accepted")
	case <-time.After(300 * time.Millisecond):
	}
	if g.Status().Denied < 1 {
		t.Error("denied not counted")
	}
}
