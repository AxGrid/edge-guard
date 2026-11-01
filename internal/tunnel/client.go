// Copied from github.com/axgrid/edge-tunnel (the edge repo's tunnel/
// module, commit d6656f4 + a 2 MB stream window), Apache-2.0: edge-guard's
// client mode connects to the nodes with this protocol.

package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Config of a tunnel instance.
type Config struct {
	// Edge is a host name of the edge cluster with a valid certificate
	// (e.g. the panel's), optionally with ":port" (default 443). The
	// instance connects there first and learns the other nodes.
	Edge string
	// Token of the tunnel: "edgt.<tunnel>.<id>.<secret>" from the panel.
	Token string
	// Instance identifies this process (default: random). A reconnect with
	// the same ID replaces the old session on the node.
	Instance string
	// Version is shown in the panel.
	Version string
	// TLSConfig for the connection to the nodes (RootCAs for a private CA;
	// ServerName defaults to Edge's host).
	TLSConfig *tls.Config
	Logger    *slog.Logger
	// ReconnectMin / ReconnectMax bound the reconnect backoff (default 1s, 30s).
	ReconnectMin, ReconnectMax time.Duration
	// NodesEvery: how often the node list is refreshed (default 30s).
	NodesEvery time.Duration
}

// ErrUnauthorized: the edge rejected the token (it does not retry).
var ErrUnauthorized = errors.New("tunnel: the edge rejected the token")

// NodeState is the instance's view of one node connection.
type NodeState struct {
	ID        string        `json:"id"`
	Addr      string        `json:"addr"`
	Connected bool          `json:"connected"`
	RTT       time.Duration `json:"-"`
	RTTMs     float64       `json:"rtt_ms"`
	Error     string        `json:"error,omitempty"`
}

// Listener accepts the connections the edge sends through the tunnel, from
// all nodes. It reconnects by itself until Close or the context ends.
type Listener struct {
	cfg    Config
	host   string // TLS server name
	port   string
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc
	conns  chan net.Conn
	tunnel string

	mu    sync.Mutex
	nodes map[string]*nodeConn // node ID → connection loop
	wg    sync.WaitGroup
	err   error // why the listener stopped by itself (token revoked)
}

type nodeConn struct {
	id, addr string
	cancel   context.CancelFunc
	mu       sync.Mutex
	sess     *yamux.Session
	err      string
}

// Listen connects to the edge and returns once the first node accepted the
// token. Network errors on the first attempt are returned too, so a wrong
// address is noticed at once; later failures are retried forever.
func Listen(ctx context.Context, cfg Config) (*Listener, error) {
	if cfg.Edge == "" || cfg.Token == "" {
		return nil, errors.New("tunnel: Edge and Token are required")
	}
	host, port, err := net.SplitHostPort(cfg.Edge)
	if err != nil {
		host, port = cfg.Edge, "443"
	}
	if cfg.Instance == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		cfg.Instance = hex.EncodeToString(b)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.ReconnectMin <= 0 {
		cfg.ReconnectMin = time.Second
	}
	if cfg.ReconnectMax <= 0 {
		cfg.ReconnectMax = 30 * time.Second
	}
	if cfg.NodesEvery <= 0 {
		cfg.NodesEvery = 30 * time.Second
	}
	l := &Listener{cfg: cfg, host: host, port: port, log: cfg.Logger, conns: make(chan net.Conn), nodes: map[string]*nodeConn{}}
	l.ctx, l.cancel = context.WithCancel(ctx)

	// Bootstrap through the name; the welcome says which node answered.
	sess, w, err := l.connect(l.ctx, net.JoinHostPort(host, port))
	if err != nil {
		l.cancel()
		return nil, err
	}
	l.tunnel = w.Tunnel
	l.log.Info("tunnel connected", "tunnel", w.Tunnel, "node", w.Node)
	l.addNode(NodeAddr{ID: w.Node, Addr: net.JoinHostPort(host, port)}, sess)
	l.setNodes(w.Nodes)
	l.wg.Go(l.refreshNodes)
	return l, nil
}

// Tunnel is the tunnel name (from the token).
func (l *Listener) Tunnel() string { return l.tunnel }

// Accept waits for the next connection from the edge. After the token is
// revoked it returns an error wrapping ErrUnauthorized.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.ctx.Done():
		l.mu.Lock()
		err := l.err
		l.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
}

// fail stops the listener for good (the edge rejected the token).
func (l *Listener) fail(err error) {
	l.mu.Lock()
	if l.err == nil {
		l.err = err
	}
	l.mu.Unlock()
	l.log.Error("tunnel: the edge rejected the token, stopping", "err", err)
	l.cancel()
}

// Close disconnects from every node.
func (l *Listener) Close() error {
	l.cancel()
	l.mu.Lock()
	for _, n := range l.nodes {
		n.cancel()
	}
	l.mu.Unlock()
	l.wg.Wait()
	return nil
}

func (l *Listener) Addr() net.Addr { return Addr("tunnel:" + l.tunnel) }

// Nodes reports the connection to each node.
func (l *Listener) Nodes() []NodeState {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]NodeState, 0, len(l.nodes))
	for _, n := range l.nodes {
		n.mu.Lock()
		st := NodeState{ID: n.id, Addr: n.addr, Error: n.err}
		if n.sess != nil && !n.sess.IsClosed() {
			st.Connected = true
			if rtt, err := n.sess.Ping(); err == nil {
				st.RTT, st.RTTMs = rtt, float64(rtt.Microseconds())/1000
			}
		}
		n.mu.Unlock()
		out = append(out, st)
	}
	slices.SortFunc(out, func(a, b NodeState) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// connect dials one address, authenticates and starts the yamux session.
func (l *Listener) connect(ctx context.Context, addr string) (*yamux.Session, Welcome, error) {
	var w Welcome
	tc := &tls.Config{}
	if l.cfg.TLSConfig != nil {
		tc = l.cfg.TLSConfig.Clone()
	}
	if tc.ServerName == "" {
		tc.ServerName = l.host
	}
	tc.NextProtos = []string{ALPN}
	if tc.MinVersion == 0 {
		tc.MinVersion = tls.VersionTLS12
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: handshakeTimeout, KeepAlive: 30 * time.Second}, Config: tc}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, w, err
	}
	c := raw.(*tls.Conn)
	if c.ConnectionState().NegotiatedProtocol != ALPN {
		c.Close()
		return nil, w, fmt.Errorf("tunnel: %s does not accept tunnels (an edge node of version 0.9 or later is needed)", addr)
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	host, _ := os.Hostname()
	if err := WriteHello(c, Hello{Token: l.cfg.Token, Instance: l.cfg.Instance, Hostname: host, Version: l.cfg.Version, OS: runtime.GOOS + "/" + runtime.GOARCH}); err != nil {
		c.Close()
		return nil, w, err
	}
	if w, err = ReadWelcome(c); err != nil {
		c.Close()
		return nil, w, fmt.Errorf("tunnel: handshake with %s: %w", addr, err)
	}
	if !w.OK {
		c.Close()
		return nil, w, fmt.Errorf("%w: %s", ErrUnauthorized, w.Error)
	}
	_ = c.SetDeadline(time.Time{})
	yc := yamux.DefaultConfig()
	yc.MaxStreamWindowSize = 2 << 20 // long responses are not held to 256 KB per round trip
	yc.LogOutput, yc.KeepAliveInterval = io.Discard, 15*time.Second
	yc.StreamOpenTimeout = 30 * time.Second
	sess, err := yamux.Server(c, yc)
	if err != nil {
		c.Close()
		return nil, w, err
	}
	return sess, w, nil
}

// addNode starts the connection loop for a node (sess: already connected).
func (l *Listener) addNode(n NodeAddr, sess *yamux.Session) *nodeConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	if nc, ok := l.nodes[n.ID]; ok {
		if sess != nil {
			sess.Close()
		}
		return nc
	}
	ctx, cancel := context.WithCancel(l.ctx)
	nc := &nodeConn{id: n.ID, addr: n.Addr, cancel: cancel}
	l.nodes[n.ID] = nc
	l.wg.Go(func() { l.nodeLoop(ctx, nc, sess) })
	return nc
}

// setNodes connects to new nodes and drops the ones gone from the list.
func (l *Listener) setNodes(list []NodeAddr) {
	if len(list) == 0 {
		return
	}
	want := map[string]NodeAddr{}
	for _, n := range list {
		addr := n.Addr
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, l.port) // an IP: the cluster's port
		}
		want[n.ID] = NodeAddr{ID: n.ID, Addr: addr}
	}
	l.mu.Lock()
	for id, nc := range l.nodes {
		if _, ok := want[id]; !ok {
			nc.cancel()
			delete(l.nodes, id)
			l.log.Info("tunnel: node left the cluster", "node", id)
		}
	}
	var add []NodeAddr
	for id, n := range want {
		if nc, ok := l.nodes[id]; ok {
			nc.mu.Lock()
			nc.addr = n.Addr // the bootstrap entry carries the name; use the IP from now on
			nc.mu.Unlock()
			continue
		}
		add = append(add, n)
	}
	l.mu.Unlock()
	for _, n := range add {
		l.addNode(n, nil)
	}
}

func (l *Listener) nodeLoop(ctx context.Context, nc *nodeConn, sess *yamux.Session) {
	backoff := l.cfg.ReconnectMin
	for ctx.Err() == nil {
		if sess == nil {
			nc.mu.Lock()
			addr := nc.addr
			nc.mu.Unlock()
			s, w, err := l.connect(ctx, addr)
			if errors.Is(err, ErrUnauthorized) {
				// Revoked (or the tunnel deleted): retrying cannot help.
				l.fail(err)
				return
			}
			if err != nil {
				nc.mu.Lock()
				nc.err = err.Error()
				nc.mu.Unlock()
				if ctx.Err() == nil {
					l.log.Warn("tunnel: node connection failed", "node", nc.id, "addr", addr, "err", err, "retry_in", backoff)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff = min(backoff*2, l.cfg.ReconnectMax)
				continue
			}
			if w.Node != nc.id {
				// The address now belongs to another node: the list refresh fixes it.
				l.log.Warn("tunnel: unexpected node", "want", nc.id, "got", w.Node)
			}
			sess = s
		}
		nc.mu.Lock()
		nc.sess, nc.err = sess, ""
		nc.mu.Unlock()
		backoff = l.cfg.ReconnectMin
		l.log.Info("tunnel: node connected", "node", nc.id)
		l.serve(ctx, sess)
		nc.mu.Lock()
		nc.sess = nil
		nc.mu.Unlock()
		if ctx.Err() == nil {
			l.log.Warn("tunnel: node disconnected", "node", nc.id)
		}
		sess = nil
	}
}

// serve accepts the node's streams until the session ends.
func (l *Listener) serve(ctx context.Context, sess *yamux.Session) {
	stop := context.AfterFunc(ctx, func() { sess.Close() })
	defer stop()
	defer sess.Close()
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			_ = st.SetReadDeadline(time.Now().Add(handshakeTimeout))
			h, err := ReadHeader(st)
			_ = st.SetReadDeadline(time.Time{})
			if err != nil {
				st.Close()
				return
			}
			c := &streamConn{Stream: st, remote: Addr(h.Client), kind: h.Kind}
			select {
			case l.conns <- c:
			case <-ctx.Done():
				st.Close()
			}
		}()
	}
}

// refreshNodes asks a connected node for the node list now and then.
func (l *Listener) refreshNodes() {
	t := time.NewTicker(l.cfg.NodesEvery)
	defer t.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-t.C:
		}
		var sess *yamux.Session
		l.mu.Lock()
		for _, nc := range l.nodes {
			nc.mu.Lock()
			if nc.sess != nil && !nc.sess.IsClosed() {
				sess = nc.sess
			}
			nc.mu.Unlock()
			if sess != nil {
				break
			}
		}
		l.mu.Unlock()
		if sess == nil {
			continue
		}
		if list, err := askNodes(sess); err == nil {
			l.setNodes(list)
		}
	}
}

func askNodes(sess *yamux.Session) ([]NodeAddr, error) {
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := WriteControl(st, ControlNodes); err != nil {
		return nil, err
	}
	return ReadNodes(st)
}

// streamConn is a tunnel stream as a net.Conn with the client's address.
type streamConn struct {
	*yamux.Stream
	remote Addr
	kind   string
}

func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

// Kind is "http" or "tcp": what the edge uses the stream for.
func (c *streamConn) Kind() string { return c.kind }

// ServeHTTP serves handler through the tunnel until ctx ends.
func ServeHTTP(ctx context.Context, cfg Config, handler http.Handler) error {
	ln, err := Listen(ctx, cfg)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second}
	stop := context.AfterFunc(ctx, func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		ln.Close()
	})
	defer stop()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return ctx.Err()
	}
	return err
}

// Forward sends every connection from the tunnel to a local address:
// "127.0.0.1:5432", "http://127.0.0.1:8080" or "https://127.0.0.1:8443"
// (TLS to the local server; insecure skips its certificate check).
func Forward(ctx context.Context, ln net.Listener, target string, insecure bool, log *slog.Logger) error {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	addr, useTLS, serverName, err := parseTarget(target)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func() {
			defer c.Close()
			d := &net.Dialer{Timeout: 10 * time.Second}
			var bc net.Conn
			var err error
			if useTLS {
				bc, err = (&tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure}}).DialContext(ctx, "tcp", addr) //nolint:gosec // opt-in
			} else {
				bc, err = d.DialContext(ctx, "tcp", addr)
			}
			if err != nil {
				log.Warn("tunnel: local target unreachable", "target", target, "err", err)
				return
			}
			defer bc.Close()
			pipe(c, bc)
		}()
	}
}

func parseTarget(t string) (addr string, useTLS bool, serverName string, err error) {
	scheme, rest, ok := strings.Cut(t, "://")
	if !ok {
		scheme, rest = "tcp", t
	}
	rest = strings.TrimSuffix(rest, "/")
	switch scheme {
	case "tcp", "http", "ws":
	case "https", "wss", "tls":
		useTLS = true
	default:
		return "", false, "", fmt.Errorf("tunnel: unsupported target %q (tcp, http, https)", t)
	}
	if _, _, err := net.SplitHostPort(rest); err != nil {
		port := "80"
		if useTLS {
			port = "443"
		}
		if scheme == "tcp" {
			return "", false, "", fmt.Errorf("tunnel: target %q needs a port", t)
		}
		rest = net.JoinHostPort(rest, port)
	}
	host, _, _ := net.SplitHostPort(rest)
	return rest, useTLS, host, nil
}

// pipe copies both ways and half-closes each side when the other is done.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Go(func() { cp(a, b) })
	wg.Go(func() { cp(b, a) })
	wg.Wait()
}
