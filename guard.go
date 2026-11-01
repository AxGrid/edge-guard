// Package guard lets an origin server accept traffic only from the nodes of
// an edge cluster. The list of the nodes' source addresses comes from the
// edge panel (GET /api/guard/ips) with a key: the origin-auth secret of the
// site in the panel. The guard refreshes the list every minute, keeps the
// last good one when the panel cannot be reached (also on disk, so a restart
// does not depend on the panel), and answers 403 Forbidden to everyone else.
//
// HTTP:
//
//	g, err := guard.New(ctx, guard.Config{
//		Panel:     "https://panel.example.com",
//		Nodes:     []string{"203.0.113.10", "203.0.113.20"}, // when the panel name does not answer
//		Key:       os.Getenv("EDGE_GUARD_KEY"),
//		CacheFile: "/var/lib/myapp/edge-guard.json",
//	})
//	http.ListenAndServe(":8080", g.Handler(mux))
//
// TCP (no headers there: only the source address is checked):
//
//	ln = g.Listener(ln)
//
// The guard stops refreshing when ctx ends. The package uses only the
// standard library.
package guard

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config of a Guard.
type Config struct {
	// Panel is the base URL of the edge panel, e.g. https://panel.example.com.
	Panel string
	// Nodes are addresses of edge nodes (IP or host, optionally :port). When
	// the panel's name does not answer, the guard asks the nodes directly
	// (TLS name and Host are the panel's). The node IPs learned from the
	// panel are tried as well.
	Nodes []string
	// Key is the origin-auth secret of the site in the panel (24+ characters).
	Key string
	// NextKey is accepted in the header too while the secret is rotated.
	NextKey string
	// Allow are extra addresses or prefixes always let in (127.0.0.1,
	// 10.0.0.0/8 for monitoring…).
	Allow []string
	// CacheFile keeps the last list across restarts (recommended).
	CacheFile string
	// NoHeaderCheck: accept requests from the nodes without the origin-auth
	// header. By default the HTTP handler requires it as well: an address
	// check alone lets in anyone else who proxies through the same edge.
	NoHeaderCheck bool
	// Refresh overrides the interval the panel suggests (60 s).
	Refresh time.Duration
	// HTTPClient for the panel (default: 10 s timeout).
	HTTPClient *http.Client
	Log        *slog.Logger
	// ClusterTLS: serve TLS with a certificate of the cluster's CA and
	// accept only clients with a node certificate of that CA (mutual TLS
	// between the edge and the guard). The guard makes its own key, gets the
	// certificate from the panel with Key and renews it by itself; use
	// ServerTLS() as the listener's TLS config. The site's pool in the panel
	// needs cluster_tls.
	ClusterTLS bool
	// TLSDir keeps the key and the certificate across restarts (default:
	// the directory of CacheFile; empty both: in memory only).
	TLSDir string
}

// List is what the panel returned.
type List struct {
	Site      string    `json:"site"`
	Header    string    `json:"header"`
	IPs       []string  `json:"ips"`
	Refresh   int       `json:"refresh_seconds"`
	FetchedAt time.Time `json:"fetched_at"`
	// Cluster TLS (edges that support it): the trusted CAs (PEM), the
	// fingerprint of the signing one, and the guard's TLS name.
	CA         string `json:"ca,omitempty"`
	CAActive   string `json:"ca_active,omitempty"`
	ServerName string `json:"server_name,omitempty"`
}

// Guard checks addresses against the list of edge nodes.
type Guard struct {
	cfg    Config
	log    *slog.Logger
	list   atomic.Pointer[List]
	set    atomic.Pointer[[]netip.Prefix] // nodes + Allow
	allow  []netip.Prefix
	client *http.Client
	denied atomic.Int64
	mu     sync.Mutex
	err    error // last refresh error (nil after a success)
	tls    clusterTLS
}

// ErrNoList: the panel could not be reached and there is no cached list.
var ErrNoList = errors.New("guard: no list of edge nodes (the panel did not answer and there is no cache)")

// New loads the list (from the panel, else from CacheFile) and keeps it
// fresh until ctx ends.
func New(ctx context.Context, cfg Config) (*Guard, error) {
	if cfg.Panel == "" && len(cfg.Nodes) == 0 {
		return nil, errors.New("guard: Panel or Nodes is required")
	}
	if len(cfg.Key) < 24 {
		return nil, errors.New("guard: Key must be the site's origin-auth secret (24+ characters)")
	}
	if cfg.Panel != "" && !strings.Contains(cfg.Panel, "://") {
		cfg.Panel = "https://" + cfg.Panel
	}
	g := &Guard{cfg: cfg, log: cfg.Log, client: cfg.HTTPClient}
	if g.log == nil {
		g.log = slog.Default()
	}
	if g.client == nil {
		g.client = &http.Client{Timeout: 10 * time.Second}
	}
	for _, a := range cfg.Allow {
		p, err := parsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("guard: allow %q: %w", a, err)
		}
		g.allow = append(g.allow, p)
	}
	if err := g.Refresh(ctx); err != nil {
		if l, cerr := g.readCache(); cerr == nil {
			g.log.Warn("guard: the panel did not answer, using the cached list", "err", err, "cached_at", l.FetchedAt)
			g.apply(l)
		} else {
			return nil, fmt.Errorf("%w: %v", ErrNoList, err)
		}
	}
	if cfg.ClusterTLS {
		if err := g.startTLS(ctx); err != nil {
			return nil, err
		}
	}
	go g.loop(ctx)
	return g, nil
}

func (g *Guard) loop(ctx context.Context) {
	for {
		every := g.cfg.Refresh
		if every <= 0 {
			every = time.Minute
			if l := g.list.Load(); l != nil && l.Refresh > 0 {
				every = time.Duration(l.Refresh) * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		if err := g.Refresh(ctx); err != nil && ctx.Err() == nil {
			g.log.Warn("guard: refresh failed, keeping the last list", "err", err)
		}
		if g.cfg.ClusterTLS && ctx.Err() == nil {
			g.maintainTLS(ctx)
		}
	}
}

// Refresh fetches the list now: the panel by name, then the nodes.
func (g *Guard) Refresh(ctx context.Context) error {
	var errs []error
	for _, t := range g.targets() {
		l, err := g.fetch(ctx, t)
		if err == nil {
			g.apply(l)
			g.writeCache(l)
			g.mu.Lock()
			g.err = nil
			g.mu.Unlock()
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", t.label(), err))
		if errors.Is(err, errKey) {
			break // the key is wrong everywhere
		}
	}
	err := errors.Join(errs...)
	g.mu.Lock()
	g.err = err
	g.mu.Unlock()
	return err
}

type target struct {
	base *url.URL // where to connect
	host string   // TLS name and Host header (the panel's) when base is a node
}

func (t target) label() string {
	if t.host != "" {
		return t.base.Host + " (as " + t.host + ")"
	}
	return t.base.Host
}

// targets: the panel URL, then the configured nodes and the learned IPs,
// each addressed with the panel's name.
func (g *Guard) targets() []target {
	var out []target
	var panel *url.URL
	if g.cfg.Panel != "" {
		if u, err := url.Parse(strings.TrimRight(g.cfg.Panel, "/")); err == nil && u.Host != "" {
			panel = u
			out = append(out, target{base: u})
		}
	}
	seen := map[string]bool{}
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		scheme, host := "https", ""
		if panel != nil {
			scheme, host = panel.Scheme, panel.Hostname()
		}
		hostPort := addr
		if strings.Contains(addr, "://") {
			if u, err := url.Parse(addr); err == nil {
				scheme, hostPort = u.Scheme, u.Host
			}
		}
		if _, _, err := net.SplitHostPort(hostPort); err != nil && panel != nil && panel.Port() != "" {
			hostPort = net.JoinHostPort(strings.Trim(hostPort, "[]"), panel.Port())
		} else if err != nil && strings.Contains(hostPort, ":") && !strings.HasPrefix(hostPort, "[") {
			hostPort = "[" + hostPort + "]" // bare IPv6
		}
		out = append(out, target{base: &url.URL{Scheme: scheme, Host: hostPort}, host: host})
	}
	for _, n := range g.cfg.Nodes {
		add(n)
	}
	if l := g.list.Load(); l != nil {
		for _, ip := range l.IPs {
			if !strings.Contains(ip, "/") {
				add(ip)
			}
		}
	}
	return out
}

var errKey = errors.New("the panel does not know this key (it must be the site's origin-auth secret)")

// call sends one request to the panel at t with the key; 2xx bodies only.
func (g *Guard) call(ctx context.Context, t target, method, path string, in []byte) ([]byte, error) {
	var rd io.Reader
	if in != nil {
		rd = bytes.NewReader(in)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.base.String()+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.Key)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := g.client
	if t.host != "" {
		req.Host = t.host
		client = withServerName(g.client, t.host)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errKey
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("HTTP 404: this edge has no %s yet (update edge on the nodes)", path)
	case resp.StatusCode/100 != 2:
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (g *Guard) fetch(ctx context.Context, t target) (*List, error) {
	body, err := g.call(ctx, t, "GET", "/api/guard/ips", nil)
	if err != nil {
		return nil, err
	}
	var l List
	if err := json.Unmarshal(body, &l); err != nil {
		return nil, fmt.Errorf("bad answer: %w", err)
	}
	if len(l.IPs) == 0 {
		return nil, errors.New("the panel returned no node addresses")
	}
	for _, ip := range l.IPs {
		if _, err := parsePrefix(ip); err != nil {
			return nil, fmt.Errorf("bad address %q in the answer", ip)
		}
	}
	l.FetchedAt = time.Now().UTC()
	return &l, nil
}

// withServerName is client with TLS verified against name (the panel's
// certificate) while connecting to a node address.
func withServerName(c *http.Client, name string) *http.Client {
	var tr *http.Transport
	if t, ok := c.Transport.(*http.Transport); ok {
		tr = t.Clone()
	} else {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.ServerName = name
	cc := *c
	cc.Transport = tr
	return &cc
}

func (g *Guard) apply(l *List) {
	set := slices.Clone(g.allow)
	for _, ip := range l.IPs {
		if p, err := parsePrefix(ip); err == nil {
			set = append(set, p)
		}
	}
	if old := g.list.Load(); old == nil || !slices.Equal(old.IPs, l.IPs) {
		g.log.Info("guard: edge node list", "site", l.Site, "ips", strings.Join(l.IPs, " "))
	}
	g.set.Store(&set)
	g.list.Store(l)
}

func (g *Guard) readCache() (*List, error) {
	if g.cfg.CacheFile == "" {
		return nil, errors.New("no cache file")
	}
	b, err := os.ReadFile(g.cfg.CacheFile)
	if err != nil {
		return nil, err
	}
	var l List
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	if len(l.IPs) == 0 {
		return nil, errors.New("empty cache")
	}
	return &l, nil
}

func (g *Guard) writeCache(l *List) {
	if g.cfg.CacheFile == "" {
		return
	}
	b, _ := json.MarshalIndent(l, "", "  ")
	tmp := g.cfg.CacheFile + ".tmp"
	if err := os.MkdirAll(filepath.Dir(g.cfg.CacheFile), 0o755); err == nil {
		if err = os.WriteFile(tmp, b, 0o644); err == nil {
			err = os.Rename(tmp, g.cfg.CacheFile)
		}
		if err == nil {
			return
		}
		g.log.Warn("guard: cannot write the cache", "file", g.cfg.CacheFile, "err", err)
	}
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// Allowed reports whether ip is an edge node (or in Allow).
func (g *Guard) Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if s := g.set.Load(); s != nil {
		for _, p := range *s {
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// AllowedAddr is Allowed for "ip:port" (net.Addr.String(), r.RemoteAddr).
func (g *Guard) AllowedAddr(addr string) bool {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		a, err2 := netip.ParseAddr(addr)
		if err2 != nil {
			return false
		}
		return g.Allowed(a)
	}
	return g.Allowed(ap.Addr())
}

// List returns the current list (nil before the first load).
func (g *Guard) List() *List { return g.list.Load() }

// Status is for health pages and logs.
type Status struct {
	Site      string     `json:"site"`
	IPs       []string   `json:"ips"`
	FetchedAt time.Time  `json:"fetched_at"`
	Denied    int64      `json:"denied"`
	LastError string     `json:"last_error,omitempty"`
	TLS       *TLSStatus `json:"tls,omitempty"` // cluster TLS
}

// Status of the guard.
func (g *Guard) Status() Status {
	st := Status{Denied: g.denied.Load()}
	if l := g.list.Load(); l != nil {
		st.Site, st.IPs, st.FetchedAt = l.Site, l.IPs, l.FetchedAt
	}
	g.mu.Lock()
	if g.err != nil {
		st.LastError = g.err.Error()
	}
	g.mu.Unlock()
	if g.cfg.ClusterTLS {
		ts := g.tlsStatus()
		st.TLS = &ts
	}
	return st
}

// headerName is the origin-auth header (from the panel; X-Edge-Auth by default).
func (g *Guard) headerName() string {
	if l := g.list.Load(); l != nil && l.Header != "" {
		return l.Header
	}
	return "X-Edge-Auth"
}

// Handler lets through only requests from the edge nodes (and Allow) that
// carry the origin-auth header; the header is removed before next. Others
// get 403 Forbidden.
func (g *Guard) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.Check(r) {
			g.denied.Add(1)
			g.log.Debug("guard: forbidden", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		r.Header.Del(g.headerName())
		next.ServeHTTP(w, r)
	})
}

// Check is the decision of Handler without answering: the source address
// is a node (or in Allow), and the header carries the key unless the
// address is in Allow or NoHeaderCheck is set.
func (g *Guard) Check(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range g.allow {
		if p.Contains(ip) {
			return true
		}
	}
	if !g.Allowed(ip) {
		return false
	}
	if g.cfg.NoHeaderCheck {
		return true
	}
	v := r.Header.Get(g.headerName())
	return v != "" && (eq(v, g.cfg.Key) || (g.cfg.NextKey != "" && eq(v, g.cfg.NextKey)))
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// ClientIP is the visitor's address: X-Real-Ip set by the edge when the
// request came from a node, else the peer address.
func (g *Guard) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if g.AllowedAddr(r.RemoteAddr) {
		if v := strings.TrimSpace(r.Header.Get("X-Real-Ip")); v != "" {
			if _, err := netip.ParseAddr(v); err == nil {
				return v
			}
		}
	}
	return host
}

// AcceptAddr is the check of Listener for one connection's remote address
// ("ip:port"): a refused one is counted in Status().Denied.
func (g *Guard) AcceptAddr(addr string) bool {
	if g.AllowedAddr(addr) {
		return true
	}
	g.denied.Add(1)
	g.log.Debug("guard: connection refused", "remote", addr)
	return false
}

// Listener closes connections whose source is not an edge node (or in
// Allow) right after accepting them.
func (g *Guard) Listener(ln net.Listener) net.Listener { return &listener{Listener: ln, g: g} }

type listener struct {
	net.Listener
	g *Guard
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.g.AcceptAddr(c.RemoteAddr().String()) {
			return c, nil
		}
		_ = c.Close()
	}
}
