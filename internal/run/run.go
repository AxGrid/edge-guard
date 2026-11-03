// Package run applies an edge-guard config: listeners, the node lists and
// the routes to the services, and replaces them on a reload without
// dropping the listening sockets that stay.
package run

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	guard "github.com/axgrid/edge-guard"
	"github.com/axgrid/edge-guard/internal/config"
	"github.com/axgrid/edge-guard/internal/tunnel"
)

// Manager runs one config at a time.
type Manager struct {
	Version string
	Path    string // the config file ("" in flags mode: no reload)
	Log     *slog.Logger
	Level   *slog.LevelVar

	mu        sync.Mutex
	cur       *config.Resolved
	guards    map[string]*guardEntry
	listeners map[string]*listener
	apps      []*app
	status    *http.Server
	statusAt  string
	loadedAt  time.Time
	cfgErr    string
	cfgErrAt  time.Time
	unknown   atomic.Int64 // HTTP requests for a host no app serves
}

type guardEntry struct {
	g      *guard.Guard
	cancel context.CancelFunc
	used   bool
	client *clientConn // client mode
	report string      // guard mode: the apps last reported (JSON)
}

func (e *guardEntry) setReport(apps []guard.App) {
	b, _ := json.Marshal(apps)
	e.report = string(b)
}

func (e *guardEntry) reported(apps []guard.App) bool {
	b, _ := json.Marshal(apps)
	return e.report == string(b)
}

type app struct {
	cfg     config.ResolvedApp
	g       *guard.Guard
	handler http.Handler
	client  *clientConn // client mode: served through these connections
}

// clientConn is client mode for one cluster: connections to every node
// (the tunnel protocol, the guard key) and an HTTP server on them that
// routes by the app the node names.
type clientConn struct {
	ln     *tunnel.Listener
	srv    *http.Server
	routes atomic.Pointer[map[string]*app]
}

// startClient connects to the nodes: the panel's name first, then the
// configured nodes with the panel's TLS name.
func (m *Manager) startClient(ctx context.Context, a config.ResolvedApp) (*clientConn, error) {
	u, err := url.Parse(a.ClusterDef.Panel)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("client mode needs the panel URL (https://…)")
	}
	port := u.Port()
	if port == "" || u.Scheme != "https" {
		port = "443"
	}
	tc := &tls.Config{ServerName: u.Hostname()}
	if a.ClusterDef.CAFile != "" {
		tc.RootCAs = caPool(a.ClusterDef.CAFile)
	}
	hostname, _ := os.Hostname()
	targets := []string{net.JoinHostPort(u.Hostname(), port)}
	for _, n := range a.ClusterDef.Nodes {
		if _, _, err := net.SplitHostPort(n); err == nil {
			targets = append(targets, n)
		} else {
			targets = append(targets, net.JoinHostPort(strings.Trim(n, "[]"), port))
		}
	}
	var errs []error
	for _, t := range targets {
		ln, err := tunnel.Listen(ctx, tunnel.Config{Edge: t, Token: a.GuardKey, Instance: hostname + "/" + a.Cluster, Version: m.Version,
			TLSConfig: tc, Logger: m.Log.With("guard", a.Cluster, "client", true)})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t, err))
			if errors.Is(err, tunnel.ErrUnauthorized) {
				break // the key is wrong everywhere
			}
			continue
		}
		c := &clientConn{ln: ln}
		empty := map[string]*app{}
		c.routes.Store(&empty)
		p := new(http.Protocols)
		p.SetHTTP1(true)
		c.srv = &http.Server{ReadHeaderTimeout: 30 * time.Second, Protocols: p, ErrorLog: slog.NewLogLogger(m.Log.Handler(), slog.LevelDebug),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// only nodes open streams on these connections: the app they name is trusted
				name := r.Header.Get(guardAppHeader)
				r.Header.Del(guardAppHeader)
				if ap := (*c.routes.Load())[name]; ap != nil {
					ap.handler.ServeHTTP(w, r)
					return
				}
				m.unknown.Add(1)
				m.Log.Warn("client mode: the node asked for an app that this guard does not serve", "app", name)
				http.Error(w, "Forbidden", http.StatusForbidden)
			})}
		go func() { _ = c.srv.Serve(ln) }()
		go func() { <-ctx.Done(); _ = c.srv.Close(); _ = ln.Close() }()
		m.Log.Info("client mode: connected to the nodes", "cluster", a.Cluster, "via", t)
		return c, nil
	}
	return nil, errors.Join(errs...)
}

func caPool(file string) *x509.CertPool {
	pool := x509.NewCertPool()
	if b, err := os.ReadFile(file); err == nil {
		pool.AppendCertsFromPEM(b)
	}
	return pool
}

// guardAppHeader names the app in requests from a node (guard mode).
const guardAppHeader = "X-Edge-Guard-App"

type routes struct {
	guard map[string]*app // guard mode: by app name
	exact map[string]*app
	wild  []wildRoute // longest suffix first
	def   *app
}

type wildRoute struct {
	suffix string // ".example.com"
	app    *app
}

type listener struct {
	addr   string
	kind   string // http or tcp
	ln     net.Listener
	srv    *http.Server
	routes atomic.Pointer[routes]
	tcp    atomic.Pointer[app]
	tlsCfg atomic.Pointer[tls.Config]
	tlsID  string
	conns  sync.WaitGroup
}

// Apply makes r the running config. On any error nothing of r is kept and
// the previous config keeps running.
func (m *Manager) Apply(ctx context.Context, r *config.Resolved) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.guards == nil {
		m.guards, m.listeners = map[string]*guardEntry{}, map[string]*listener{}
	}
	if m.Level != nil {
		lv := slog.LevelInfo
		if r.LogLevel == "debug" {
			lv = slog.LevelDebug
		}
		m.Level.Set(lv)
	}
	stateDir := stateDir(r.StateDir, m.Path)

	// 1. node lists: reuse the ones with the same cluster and key
	for _, e := range m.guards {
		e.used = false
	}
	var fresh []string
	undo := func() {
		for _, id := range fresh {
			m.guards[id].cancel()
			delete(m.guards, id)
		}
	}
	apps := make([]*app, 0, len(r.Apps))
	// guard mode: one guard per cluster, reporting all its apps
	reports := map[string][]guard.App{}
	for _, a := range r.Apps {
		if a.GuardMode {
			ga := guard.App{Name: a.Name, Kind: a.Kind, Listen: a.Report, Hosts: append([]string{}, a.Hosts...)}
			if a.Client {
				ga.Listen, ga.Via = []string{}, "tunnel"
			}
			reports[guardID(a)] = append(reports[guardID(a)], ga)
		}
	}
	hostname, _ := os.Hostname()
	for _, a := range r.Apps {
		id := guardID(a)
		e := m.guards[id]
		if e != nil && a.GuardMode && !e.reported(reports[id]) {
			e.setReport(reports[id])
			e.g.SetApps(context.Background(), reports[id])
		}
		if e == nil {
			gctx, cancel := context.WithCancel(context.Background())
			gc := guard.Config{
				Panel: a.ClusterDef.Panel, Nodes: a.ClusterDef.Nodes, Key: a.KeyValue, NextKey: a.NextKey,
				Allow: a.Allow, NoHeaderCheck: !a.HeaderCheck,
				CacheFile:  filepath.Join(stateDir, cacheName(a)),
				ClusterTLS: a.TLS != nil && a.TLS.Cluster,
				Log:        m.Log.With("app", a.Name, "cluster", a.Cluster),
			}
			if a.GuardMode {
				gc.Key, gc.NextKey, gc.Allow = "", "", nil
				gc.GuardKey, gc.Apps, gc.Hostname, gc.Version, gc.Client = a.GuardKey, reports[id], hostname, m.Version, a.Client
				gc.Log = m.Log.With("guard", a.Cluster)
			}
			if a.ClusterDef.CAFile != "" {
				gc.HTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool(a.ClusterDef.CAFile)}}}
			}
			g, err := guard.New(gctx, gc)
			if err != nil {
				cancel()
				undo()
				return fmt.Errorf("app %s: %w", a.Name, err)
			}
			e = &guardEntry{g: g, cancel: cancel}
			e.setReport(reports[id])
			if a.Client {
				// client mode: the guard's own connections to the nodes
				ct, err := m.startClient(gctx, a)
				if err != nil {
					cancel()
					undo()
					return fmt.Errorf("cluster %s (client mode): %w", a.Cluster, err)
				}
				e.client = ct
			}
			m.guards[id] = e
			fresh = append(fresh, id)
		}
		e.used = true
		ap := &app{cfg: a, g: e.g, client: e.client}
		switch {
		case a.Client:
			ap.handler = redirects(a.Redirects, m.proxy(a)) // the connection itself is the node's: no address check
		case a.Kind == "http":
			ap.handler = e.g.Handler(redirects(a.Redirects, m.proxy(a))) // checked first: only nodes get redirects
		}
		apps = append(apps, ap)
	}
	// client mode: the apps each connection routes to
	for _, e := range m.guards {
		if e.client == nil {
			continue
		}
		rt := map[string]*app{}
		for _, ap := range apps {
			if ap.client == e.client {
				rt[ap.cfg.Name] = ap
			}
		}
		e.client.routes.Store(&rt)
	}

	// 2. listeners: open the new addresses first, so a busy port fails the
	// reload before anything changes
	addrs, byAddr := r.Listens()
	opened := map[string]*listener{}
	closeOpened := func() {
		for _, l := range opened {
			_ = l.ln.Close()
		}
	}
	type swap struct{ old, new *listener }
	var reopen []swap
	for _, addr := range addrs {
		list := byAddr[addr]
		kind, tlsID := list[0].Kind, tlsKey(list[0])
		if old := m.listeners[addr]; old != nil {
			if old.kind == kind {
				continue // same socket, new routes and certificate below
			}
			reopen = append(reopen, swap{old: old})
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			closeOpened()
			undo()
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		opened[addr] = &listener{addr: addr, kind: kind, ln: ln, tlsID: tlsID}
	}
	// certificates are loaded before the switch too
	certs := map[string]*tls.Config{}
	for _, addr := range addrs {
		a := byAddr[addr][0]
		if a.TLS == nil {
			continue
		}
		if a.TLS.Cluster {
			certs[addr] = m.clusterTLS(byAddr[addr], apps)
			continue
		}
		c, err := tls.LoadX509KeyPair(a.TLS.Cert, a.TLS.Key)
		if err != nil {
			closeOpened()
			undo()
			return fmt.Errorf("listen %s: tls: %w", addr, err)
		}
		certs[addr] = &tls.Config{Certificates: []tls.Certificate{c}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}
	}

	// --- from here on the new config is applied ---
	// listeners whose kind or TLS on/off changed: closed and opened again
	for _, s := range reopen {
		m.stopListener(s.old, false)
		delete(m.listeners, s.old.addr)
		ln, err := net.Listen("tcp", s.old.addr)
		if err != nil {
			m.Log.Error("cannot listen again", "addr", s.old.addr, "err", err)
			continue
		}
		list := byAddr[s.old.addr]
		opened[s.old.addr] = &listener{addr: s.old.addr, kind: list[0].Kind, ln: ln, tlsID: tlsKey(list[0])}
	}
	byName := map[string]*app{}
	for _, ap := range apps {
		byName[ap.cfg.Name] = ap
	}
	for _, addr := range addrs {
		l := m.listeners[addr]
		if l == nil {
			l = opened[addr]
			if l == nil {
				continue // could not listen again (logged)
			}
		}
		l.tlsID = tlsKey(byAddr[addr][0])
		l.tlsCfg.Store(certs[addr])
		if l.kind == "tcp" {
			l.tcp.Store(byName[byAddr[addr][0].Name])
		} else {
			l.routes.Store(buildRoutes(byAddr[addr], byName))
		}
		if m.listeners[addr] == nil {
			m.listeners[addr] = l
			m.start(l)
		}
	}
	for addr, l := range m.listeners {
		if _, ok := byAddr[addr]; !ok {
			m.Log.Info("listener closed", "addr", addr)
			delete(m.listeners, addr)
			go m.stopListener(l, true)
		}
	}
	for id, e := range m.guards {
		if !e.used {
			e.cancel()
			delete(m.guards, id)
		}
	}
	m.apps = apps
	m.cur = r
	m.loadedAt = time.Now()
	m.cfgErr = ""
	m.startStatus(r.Status)
	return nil
}

// Reload reads the file again and applies it when it changed. A broken
// file is reported and the running config stays.
func (m *Manager) Reload(ctx context.Context, why string) {
	r, err := config.Load(m.Path)
	if err == nil {
		m.mu.Lock()
		same := m.cur != nil && m.cur.Hash == r.Hash
		m.mu.Unlock()
		if same {
			return
		}
		err = m.Apply(ctx, r)
	}
	if err != nil {
		m.mu.Lock()
		m.cfgErr, m.cfgErrAt = err.Error(), time.Now()
		m.mu.Unlock()
		m.Log.Error("config NOT applied, the previous one keeps running", "file", m.Path, "reason", why, "err", err.Error())
		return
	}
	m.Log.Info("config applied", "file", m.Path, "reason", why, "apps", len(r.Apps), "listen", strings.Join(listenList(r), " "))
}

// Watch reloads when the config or a key file changes (checked every 2 s).
func (m *Manager) Watch(ctx context.Context) {
	sig := func() string {
		m.mu.Lock()
		files := []string{m.Path}
		if m.cur != nil {
			files = m.cur.Files
		}
		m.mu.Unlock()
		var b strings.Builder
		for _, f := range files {
			if st, err := os.Stat(f); err == nil {
				fmt.Fprintf(&b, "%s %d %d;", f, st.Size(), st.ModTime().UnixNano())
			} else {
				fmt.Fprintf(&b, "%s missing;", f)
			}
		}
		return b.String()
	}
	last := sig()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s := sig(); s != last {
			last = s
			time.Sleep(200 * time.Millisecond) // let an editor finish writing
			m.Reload(ctx, "file changed")
		}
	}
}

// Close stops everything (graceful: up to 10 s for open requests).
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var wg sync.WaitGroup
	for _, l := range m.listeners {
		wg.Add(1)
		go func() { defer wg.Done(); m.stopListener(l, true) }()
	}
	wg.Wait()
	for _, e := range m.guards {
		e.cancel()
	}
	if m.status != nil {
		_ = m.status.Close()
	}
}

func (m *Manager) start(l *listener) {
	m.Log.Info("listening", "addr", l.addr, "kind", l.kind, "tls", l.tlsID != "")
	ln := &tlsSwitch{Listener: l.ln, l: l}
	if l.kind == "tcp" {
		go m.serveTCP(l)
		return
	}
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	p.SetUnencryptedHTTP2(true) // gRPC from the edge over h2c
	l.srv = &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.route(l, w, r) }),
		ReadHeaderTimeout: 30 * time.Second,
		Protocols:         p,
		ErrorLog:          slog.NewLogLogger(m.Log.Handler(), slog.LevelDebug),
	}
	go func() {
		if err := l.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			m.Log.Error("server stopped", "addr", l.addr, "err", err)
		}
	}()
}

// tlsSwitch wraps accepted connections in TLS when the listener has a
// certificate (swapped on reload).
type tlsSwitch struct {
	net.Listener
	l *listener
}

func (t *tlsSwitch) Accept() (net.Conn, error) {
	c, err := t.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if cfg := t.l.tlsCfg.Load(); cfg != nil {
		return tls.Server(c, cfg), nil
	}
	return c, nil
}

func (m *Manager) stopListener(l *listener, graceful bool) {
	if l.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if !graceful {
			ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()
		}
		_ = l.srv.Shutdown(ctx)
		return
	}
	_ = l.ln.Close()
	if graceful {
		done := make(chan struct{})
		go func() { l.conns.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	}
}

func (m *Manager) route(l *listener, w http.ResponseWriter, r *http.Request) {
	rt := l.routes.Load()
	// guard mode: the node names the app; trusted only from a verified node
	// (cluster TLS required a node client certificate for this connection)
	if name := r.Header.Get(guardAppHeader); name != "" {
		r.Header.Del(guardAppHeader)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if ap := rt.guard[name]; ap != nil {
				ap.handler.ServeHTTP(w, r)
				return
			}
			m.unknown.Add(1)
			m.Log.Warn("guard: the node asked for an app that is not on this address", "app", name, "addr", l.addr)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	ap := rt.exact[host]
	if ap == nil {
		for _, wr := range rt.wild {
			if strings.HasSuffix(host, wr.suffix) {
				ap = wr.app
				break
			}
		}
	}
	if ap == nil {
		ap = rt.def
	}
	if ap == nil {
		m.unknown.Add(1)
		m.Log.Debug("no app for this host", "addr", l.addr, "host", host, "remote", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	ap.handler.ServeHTTP(w, r)
}

func buildRoutes(list []config.ResolvedApp, byName map[string]*app) *routes {
	rt := &routes{exact: map[string]*app{}, guard: map[string]*app{}}
	for _, a := range list {
		ap := byName[a.Name]
		if a.GuardMode {
			rt.guard[a.Name] = ap
		}
		if len(a.Hosts) == 0 {
			rt.def = ap
		}
		for _, h := range a.Hosts {
			if strings.HasPrefix(h, "*.") {
				rt.wild = append(rt.wild, wildRoute{suffix: h[1:], app: ap})
			} else {
				rt.exact[h] = ap
			}
		}
	}
	slices.SortFunc(rt.wild, func(a, b wildRoute) int { return len(b.suffix) - len(a.suffix) })
	return rt
}

func (m *Manager) proxy(a config.ResolvedApp) http.Handler {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if a.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	switch a.Protocol {
	case "auto":
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP1(true)
		tr.Protocols.SetHTTP2(true)
	case "h2":
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP2(true)
		tr.Protocols.SetUnencryptedHTTP2(true)
	}
	target := a.Target
	log := m.Log.With("app", a.Name)
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // the site's name, as the edge sent it
			if a.HostHeader != "" {
				pr.Out.Host = a.HostHeader
			}
			// X-Forwarded-For / X-Real-Ip come from the edge unchanged
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
		},
		Transport:     tr,
		FlushInterval: -1, // stream (SSE, gRPC, long polling)
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Warn("the service did not answer", "to", target.String(), "err", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
}

func (m *Manager) serveTCP(l *listener) {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			m.Log.Error("accept failed", "addr", l.addr, "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		ap := l.tcp.Load()
		if ap == nil || !ap.g.AcceptAddr(c.RemoteAddr().String()) {
			_ = c.Close()
			continue
		}
		l.conns.Add(1)
		go func() {
			defer l.conns.Done()
			defer c.Close()
			up, err := net.DialTimeout("tcp", ap.cfg.Target.Host, 10*time.Second)
			if err != nil {
				m.Log.Warn("the service did not answer", "app", ap.cfg.Name, "to", ap.cfg.Target.Host, "err", err)
				return
			}
			defer up.Close()
			done := make(chan struct{}, 2)
			cp := func(dst, src net.Conn) {
				_, _ = io.Copy(dst, src)
				if tc, ok := dst.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				done <- struct{}{}
			}
			go cp(up, c)
			go cp(c, up)
			<-done
			<-done
		}()
	}
}

// ---- status ----

// AppStatus is one app in the status.
type AppStatus struct {
	Name    string   `json:"name"`
	Listen  []string `json:"listen"`
	Hosts   []string `json:"hosts,omitempty"`
	To      string   `json:"to"`
	Cluster string   `json:"cluster"`
	// Client mode: the nodes this guard is connected to.
	Via   string             `json:"via,omitempty"`
	Nodes []tunnel.NodeState `json:"nodes,omitempty"`
	guard.Status
}

// Status is the JSON status page.
type Status struct {
	Version string `json:"version"`
	Config  struct {
		File     string    `json:"file,omitempty"`
		LoadedAt time.Time `json:"loaded_at"`
		Hash     string    `json:"hash"`
		Error    string    `json:"error,omitempty"` // the last reload failed: the previous config runs
		ErrorAt  time.Time `json:"error_at,omitzero"`
	} `json:"config"`
	Apps        []AppStatus `json:"apps"`
	UnknownHost int64       `json:"unknown_host"`
}

// Status of everything.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	var st Status
	st.Version = m.Version
	st.Config.File, st.Config.LoadedAt, st.Config.Error, st.Config.ErrorAt = m.Path, m.loadedAt, m.cfgErr, m.cfgErrAt
	if m.cur != nil {
		st.Config.Hash = m.cur.Hash[:12]
	}
	st.Apps = []AppStatus{}
	for _, ap := range m.apps {
		as := AppStatus{Name: ap.cfg.Name, Listen: ap.cfg.Listen, Hosts: ap.cfg.Hosts, To: ap.cfg.To, Cluster: ap.cfg.Cluster, Status: ap.g.Status()}
		if ap.client != nil {
			as.Via, as.Nodes = "tunnel", ap.client.ln.Nodes()
		}
		st.Apps = append(st.Apps, as)
	}
	st.UnknownHost = m.unknown.Load()
	return st
}

// startStatus (re)starts the status server when its address changed. Call with m.mu held.
func (m *Manager) startStatus(addr string) {
	if addr == m.statusAt {
		return
	}
	if m.status != nil {
		_ = m.status.Close()
		m.status = nil
	}
	m.statusAt = addr
	if addr == "" {
		return
	}
	srv := &http.Server{Addr: addr, ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(m.Status())
	})}
	m.status = srv
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.Log.Error("status server stopped", "addr", addr, "err", err)
		}
	}()
}

// ---- helpers ----

// clusterTLS is the TLS of a listener whose apps use cluster TLS: the
// certificate by SNI (<site>.edge-guard; apps of several sites may share an
// address), and node client certificates required.
func (m *Manager) clusterTLS(list []config.ResolvedApp, apps []*app) *tls.Config {
	var gs []*guard.Guard
	for _, a := range list {
		for _, ap := range apps {
			if ap.cfg.Name == a.Name {
				gs = append(gs, ap.g)
			}
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			for _, g := range gs {
				if l := g.List(); l != nil && strings.EqualFold(l.ServerName, hello.ServerName) {
					return withALPN(g.ServerTLS()), nil
				}
			}
			if len(gs) == 1 {
				return withALPN(gs[0].ServerTLS()), nil
			}
			m.Log.Debug("cluster TLS: unknown server name", "sni", hello.ServerName, "remote", hello.Conn.RemoteAddr().String())
			return nil, fmt.Errorf("unknown server name %q", hello.ServerName)
		},
	}
}

func withALPN(c *tls.Config) *tls.Config {
	c.NextProtos = []string{"h2", "http/1.1"}
	return c
}

func guardID(a config.ResolvedApp) string {
	h := sha256.New()
	if a.GuardMode { // one guard per cluster: its apps change without a new guard
		fmt.Fprintf(h, "guard\x00%s\x00%s\x00%s", a.ClusterDef.Panel, strings.Join(a.ClusterDef.Nodes, ","), a.GuardKey)
		return hex.EncodeToString(h.Sum(nil))
	}
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%v\x00%v", a.ClusterDef.Panel, strings.Join(a.ClusterDef.Nodes, ","), a.KeyValue, a.NextKey, strings.Join(a.Allow, ","), a.HeaderCheck, a.TLS != nil && a.TLS.Cluster)
	return hex.EncodeToString(h.Sum(nil))
}

// cacheName: the list file of a cluster and key (the key itself is not in it).
func cacheName(a config.ResolvedApp) string {
	key := a.KeyValue
	if a.GuardMode {
		key = a.GuardKey
	}
	k := sha256.Sum256([]byte(a.ClusterDef.Panel + "\x00" + key))
	return a.Cluster + "-" + hex.EncodeToString(k[:6]) + ".json"
}

func tlsKey(a config.ResolvedApp) string { return a.TLSKind() }

func listenList(r *config.Resolved) []string {
	addrs, _ := r.Listens()
	return addrs
}

// stateDir: the configured one, $STATE_DIRECTORY (systemd), /var/lib/edge-guard
// when writable, else next to the config file.
func stateDir(cfg, cfgPath string) string {
	if cfg != "" {
		return cfg
	}
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return strings.Split(d, ":")[0]
	}
	if err := os.MkdirAll("/var/lib/edge-guard", 0o755); err == nil {
		if f, err := os.CreateTemp("/var/lib/edge-guard", ".w"); err == nil {
			f.Close()
			os.Remove(f.Name())
			return "/var/lib/edge-guard"
		}
	}
	if cfgPath != "" {
		return filepath.Dir(cfgPath)
	}
	return "."
}
