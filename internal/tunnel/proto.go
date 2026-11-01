// Copied from github.com/axgrid/edge-tunnel (see client.go), Apache-2.0.

// Package tunnel connects a server without a public address to an edge
// cluster: it dials out to every edge node over TLS (port 443) and serves
// the requests and TCP connections the edge sends back.
//
// Embed it in a Go program:
//
//	tunnel.ServeHTTP(ctx, tunnel.Config{Edge: "cf.example.com", Token: tok}, mux)
//
// or take a net.Listener and serve anything on it (gRPC, a TCP protocol):
//
//	ln, _ := tunnel.Listen(ctx, cfg)
//	srv.Serve(ln)
//
// The edge-connector binary uses the same package to expose local
// addresses without changing the program.
package tunnel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ALPN is the TLS protocol name that tells an edge node this connection is
// a tunnel and not HTTPS.
const ALPN = "edge-tunnel/1"

// Hello is the first line the instance sends after the TLS handshake.
type Hello struct {
	Token    string `json:"token"`
	Instance string `json:"instance"` // stable per process: reconnects replace the old session
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	OS       string `json:"os,omitempty"`
}

// Welcome is the node's answer; then the connection becomes a yamux
// session in which the node opens one stream per request / TCP connection.
type Welcome struct {
	OK     bool       `json:"ok"`
	Error  string     `json:"error,omitempty"`
	Node   string     `json:"node,omitempty"`
	Tunnel string     `json:"tunnel,omitempty"`
	Nodes  []NodeAddr `json:"nodes,omitempty"`
}

// NodeAddr is a node the instance should keep a connection to.
type NodeAddr struct {
	ID   string `json:"id"`
	Addr string `json:"addr"` // IP or host (the bootstrap port), or host:port
}

// StreamHeader starts every stream the node opens.
type StreamHeader struct {
	Client string `json:"c,omitempty"` // client address (ip:port)
	Node   string `json:"n,omitempty"`
	Kind   string `json:"k,omitempty"` // http | tcp
}

// ControlNodes, written by the instance on a stream it opens, asks for the
// current node list (answered with a JSON []NodeAddr line).
const ControlNodes = "nodes"

const maxLine = 16 << 10

func writeJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// readJSONLine reads one line (at most maxLine bytes) without reading past it.
func readJSONLine(r io.Reader, v any) error {
	var buf []byte
	one := make([]byte, 1)
	for len(buf) < maxLine {
		if _, err := io.ReadFull(r, one); err != nil {
			return err
		}
		if one[0] == '\n' {
			return json.Unmarshal(buf, v)
		}
		buf = append(buf, one[0])
	}
	return errors.New("tunnel: line too long")
}

// WriteHello / ReadHello / WriteWelcome / ReadWelcome / WriteHeader /
// ReadHeader are the wire format, shared with the edge node.
func WriteHello(w io.Writer, h Hello) error          { return writeJSONLine(w, h) }
func ReadHello(r io.Reader) (h Hello, err error)     { err = readJSONLine(r, &h); return }
func WriteWelcome(w io.Writer, m Welcome) error      { return writeJSONLine(w, m) }
func ReadWelcome(r io.Reader) (m Welcome, err error) { err = readJSONLine(r, &m); return }
func WriteHeader(w io.Writer, h StreamHeader) error  { return writeJSONLine(w, h) }
func ReadHeader(r io.Reader) (h StreamHeader, err error) {
	err = readJSONLine(r, &h)
	return
}

// WriteNodes / ReadNodes answer ControlNodes.
func WriteNodes(w io.Writer, list []NodeAddr) error      { return writeJSONLine(w, list) }
func ReadNodes(r io.Reader) (list []NodeAddr, err error) { err = readJSONLine(r, &list); return }

// WriteControl / ReadControl carry a control request on an
// instance-opened stream.
func WriteControl(w io.Writer, cmd string) error { _, err := fmt.Fprintf(w, "%s\n", cmd); return err }
func ReadControl(r io.Reader) (string, error) {
	line, err := bufio.NewReaderSize(io.LimitReader(r, 256), 64).ReadString('\n')
	if err != nil {
		return "", err
	}
	return line[:len(line)-1], nil
}

// Addr is the address type of tunnel streams.
type Addr string

func (a Addr) Network() string { return "tunnel" }
func (a Addr) String() string  { return string(a) }

var _ net.Addr = Addr("")

// handshakeTimeout bounds the hello/welcome exchange.
const handshakeTimeout = 10 * time.Second
