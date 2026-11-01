// Package config reads and checks the edge-guard config file.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the whole file.
type Config struct {
	// StateDir keeps the last node lists (default: $STATE_DIRECTORY, else
	// /var/lib/edge-guard when writable, else the config file's directory).
	StateDir string `yaml:"state_dir"`
	// Status serves a JSON status (apps, lists, the config state), e.g. 127.0.0.1:9102.
	Status string `yaml:"status"`
	// LogLevel: info (default) or debug (every refused request).
	LogLevel string `yaml:"log_level"`
	// Clusters by name: where the node lists come from.
	Clusters map[string]Cluster `yaml:"clusters"`
	// Apps: what to listen on and where to send it.
	Apps []App `yaml:"apps"`
}

// Cluster is one edge cluster.
type Cluster struct {
	// Panel URL, e.g. https://panel.example.com.
	Panel string `yaml:"panel"`
	// Nodes: node addresses, asked directly when the panel name does not answer.
	Nodes []string `yaml:"nodes"`
	// Guard mode: a key from the panel's Guards page (edgg.…). This server
	// then reports the cluster's apps to the panel and sites are bound to
	// them there; the apps need no key of their own, use cluster TLS and
	// trust the nodes by their client certificates.
	GuardKey     string `yaml:"guard_key"`
	GuardKeyEnv  string `yaml:"guard_key_env"`
	GuardKeyFile string `yaml:"guard_key_file"`
}

// App is one protected service.
type App struct {
	Name string `yaml:"name"`
	// Cluster name (may be left out when there is one cluster).
	Cluster string `yaml:"cluster"`
	// Listen: the server's IP and port, e.g. "203.0.113.5:8080", or a list of
	// them. The IP is required: on a server with many addresses the guard
	// must take only the one the edge connects to (all addresses —
	// 0.0.0.0, [::] — only with bind_any). Several HTTP apps may share an
	// address when they list their Hosts (one of them may have none: the default).
	Listen Addrs `yaml:"listen"`
	// BindAny allows listen on every address of the server (0.0.0.0:port, [::]:port).
	BindAny bool `yaml:"bind_any"`
	// Hosts this app answers on a shared listen address (exact or *.example.com).
	Hosts []string `yaml:"hosts"`
	// To: http://host:port, https://host:port or tcp://host:port.
	To string `yaml:"to"`
	// The key: the site's origin-auth secret. One of key_env (recommended),
	// key_file or key (discouraged: the file must then be mode 600).
	Key     string `yaml:"key"`
	KeyEnv  string `yaml:"key_env"`
	KeyFile string `yaml:"key_file"`
	// The next secret while it is rotated (accepted in the header too).
	NextKeyEnv  string `yaml:"next_key_env"`
	NextKeyFile string `yaml:"next_key_file"`
	// Allow: addresses or prefixes always let in, without the header.
	Allow []string `yaml:"allow"`
	// HeaderCheck: require the origin-auth header (default true; TCP: never).
	HeaderCheck *bool `yaml:"header_check"`
	// TLS serves HTTPS on Listen: "cluster" (a certificate of the edge
	// cluster's CA, obtained and renewed by itself, and mutual TLS: only
	// node client certificates — the site's pool needs cluster_tls), or
	// {cert, key} files. Every app on an address uses the same kind.
	TLS *TLS `yaml:"tls"`
	// Insecure: do not verify the certificate of an https:// service.
	Insecure bool `yaml:"insecure"`
	// HostHeader sent to the service (default: the one the edge sent).
	HostHeader string `yaml:"host_header"`
	// Public: the addresses the nodes reach this app at, when they differ
	// from listen (behind NAT); reported in guard mode instead of listen.
	Public Addrs `yaml:"public"`
	// Protocol to the service: h1 (default), auto (https: HTTP/2 when
	// offered) or h2 (HTTP/2 only: TLS for https, cleartext h2c for http — gRPC).
	Protocol string `yaml:"protocol"`
}

// TLS: cluster TLS or files (PEM).
type TLS struct {
	Cluster bool   `yaml:"-"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// Resolved is a checked config with the keys read.
type Resolved struct {
	Config
	Apps []ResolvedApp
	// Hash of the file and the key files: a reload without changes does nothing.
	Hash string
	// Files the config depends on (the config and the key files), for the watcher.
	Files []string
}

// ResolvedApp is an app with its cluster and keys.
type ResolvedApp struct {
	App
	ClusterDef  Cluster
	KeyValue    string
	NextKey     string
	Kind        string // "http" or "tcp"
	Target      *url.URL
	HeaderCheck bool
	// GuardMode: the cluster has a guard key; GuardKey is it.
	GuardMode bool
	GuardKey  string
	// Report: the addresses reported in guard mode (public, else listen).
	Report []string
}

// Problems is every error found in a config.
type Problems []string

func (p Problems) Error() string {
	if len(p) == 1 {
		return p[0]
	}
	return fmt.Sprintf("%d problems:\n  - %s", len(p), strings.Join(p, "\n  - "))
}

var unknownRe = regexp.MustCompile(`^(line \d+): field (\S+) not found in type config\.(\w+)$`)

var where = map[string]string{"Config": "the top level", "Cluster": "a cluster", "App": "an app", "TLS": "tls"}

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// Load reads, parses and checks the file. Unknown fields are errors (a typo
// must not silently turn protection off). Syntax errors name the line.
func Load(path string) (*Resolved, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, path, os.Getenv)
}

// Parse is Load for bytes; getenv reads the key variables.
func Parse(b []byte, path string, getenv func(string) string) (*Resolved, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, Problems{"the config is empty"}
		}
		var te *yaml.TypeError
		if errors.As(err, &te) {
			// one line per field: "line 4: unknown field "nodez" (in a cluster)"
			var p Problems
			for _, e := range te.Errors {
				if m := unknownRe.FindStringSubmatch(e); m != nil {
					e = fmt.Sprintf("%s: unknown field %q (in %s)", m[1], m[2], where[m[3]])
				}
				p = append(p, e)
			}
			return nil, p
		}
		return nil, Problems{"syntax: " + strings.TrimPrefix(err.Error(), "yaml: ")}
	}
	h := sha256.New()
	h.Write(b)
	r := &Resolved{Config: c, Files: []string{path}}
	var p Problems
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }

	switch c.LogLevel {
	case "", "info", "debug":
	default:
		add("log_level: info or debug, not %q", c.LogLevel)
	}
	if c.Status != "" {
		if _, _, err := net.SplitHostPort(c.Status); err != nil {
			add("status: %q is not host:port", c.Status)
		}
	}
	if len(c.Clusters) == 0 {
		add("clusters: at least one cluster is required")
	}
	guardKeys := map[string]string{}
	names := make([]string, 0, len(c.Clusters))
	for n := range c.Clusters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		cl := c.Clusters[n]
		if !nameRe.MatchString(n) {
			add("clusters.%s: the name may contain letters, digits, '.', '-' and '_'", n)
		}
		if cl.Panel == "" && len(cl.Nodes) == 0 {
			add("clusters.%s: panel or nodes is required", n)
		}
		if cl.Panel != "" {
			u, err := url.Parse(cl.Panel)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				add("clusters.%s.panel: %q is not an http(s) URL", n, cl.Panel)
			}
		}
		for i, nd := range cl.Nodes {
			if strings.TrimSpace(nd) == "" {
				add("clusters.%s.nodes[%d]: empty", n, i)
			}
		}
		gsrc := 0
		for _, v := range []string{cl.GuardKey, cl.GuardKeyEnv, cl.GuardKeyFile} {
			if v != "" {
				gsrc++
			}
		}
		if gsrc > 1 {
			add("clusters.%s: give only one of guard_key_env, guard_key_file, guard_key", n)
		}
		gk := strings.TrimSpace(cl.GuardKey)
		switch {
		case cl.GuardKeyEnv != "":
			if gk = strings.TrimSpace(getenv(cl.GuardKeyEnv)); gk == "" {
				add("clusters.%s.guard_key_env: the environment variable %s is empty or not set", n, cl.GuardKeyEnv)
			}
		case cl.GuardKeyFile != "":
			r.Files = append(r.Files, cl.GuardKeyFile)
			kb, err := os.ReadFile(cl.GuardKeyFile)
			if err != nil {
				add("clusters.%s.guard_key_file: %v", n, err)
			}
			h.Write(kb)
			gk = strings.TrimSpace(string(kb))
		}
		if gk != "" && !strings.HasPrefix(gk, "edgg.") {
			add("clusters.%s: the guard key is a key from the panel's Guards page (edgg.…)", n)
		}
		h.Write([]byte(gk + "\x00"))
		guardKeys[n] = gk
	}
	if len(c.Apps) == 0 {
		add("apps: at least one app is required")
	}

	type lsn struct {
		kind     string
		tls      string
		apps     []string
		defaults int
		hosts    map[string]string
	}
	listens := map[string]*lsn{}
	seenApp := map[string]bool{}
	for i, a := range c.Apps {
		f := fmt.Sprintf("apps[%d]", i)
		if a.Name != "" {
			f = fmt.Sprintf("apps[%d] (%s)", i, a.Name)
		}
		if !nameRe.MatchString(a.Name) {
			add("%s.name: required; letters, digits, '.', '-' and '_'", f)
		} else if seenApp[a.Name] {
			add("%s.name: %q is used twice", f, a.Name)
		}
		seenApp[a.Name] = true
		ra := ResolvedApp{App: a}
		ra.Hosts = slices.Clone(a.Hosts)
		// cluster
		cn := a.Cluster
		if cn == "" && len(c.Clusters) == 1 {
			cn = names[0]
		}
		if cl, ok := c.Clusters[cn]; ok {
			ra.ClusterDef, ra.Cluster = cl, cn
		} else if cn == "" {
			add("%s.cluster: required when there are several clusters (%s)", f, strings.Join(names, ", "))
		} else {
			add("%s.cluster: no cluster %q (have: %s)", f, cn, strings.Join(names, ", "))
		}
		// target
		u, err := url.Parse(a.To)
		switch {
		case a.To == "":
			add("%s.to: required (http://host:port, https://host:port or tcp://host:port)", f)
		case err != nil || u.Host == "":
			add("%s.to: %q is not a URL like http://127.0.0.1:3000", f, a.To)
		case u.Scheme == "http" || u.Scheme == "https":
			ra.Kind, ra.Target = "http", u
		case u.Scheme == "tcp":
			ra.Kind, ra.Target = "tcp", u
			if _, port, err := net.SplitHostPort(u.Host); err != nil || port == "" {
				add("%s.to: a tcp target needs a port", f)
			}
		default:
			add("%s.to: unknown scheme %q (http, https, tcp)", f, u.Scheme)
		}
		switch a.Protocol {
		case "", "h1", "auto", "h2":
		default:
			add("%s.protocol: h1, auto or h2, not %q", f, a.Protocol)
		}
		// listen: explicit IPs only
		if len(a.Listen) == 0 {
			add("%s.listen: required: the server's IP and port the edge connects to, e.g. 203.0.113.5:8080", f)
		}
		var addrs []string
		for _, l := range a.Listen {
			n, err := normListen(l)
			switch {
			case errors.Is(err, errAnyAddr) && a.BindAny:
			case errors.Is(err, errAnyAddr):
				add("%s.listen: %q takes every address of the server; give the IP the edge connects to (e.g. 203.0.113.5:%s), or set bind_any: true", f, l, portOf(l))
				continue
			case err != nil:
				add("%s.listen: %q: %v", f, l, err)
				continue
			}
			if slices.Contains(addrs, n) {
				add("%s.listen: %s is listed twice", f, n)
				continue
			}
			addrs = append(addrs, n)
		}
		ra.Listen = addrs
		// keys
		srcs := 0
		for _, s := range []string{a.Key, a.KeyEnv, a.KeyFile} {
			if s != "" {
				srcs++
			}
		}
		if gk := guardKeys[ra.Cluster]; gk != "" && srcs == 0 {
			// guard mode: the cluster's guard key, cluster TLS, nodes by certificate
			ra.GuardMode, ra.GuardKey = true, gk
			switch {
			case ra.Kind == "http" && a.TLS == nil:
				ra.TLS = &TLS{Cluster: true}
			case ra.Kind == "http" && !a.TLS.Cluster:
				add("%s.tls: in guard mode the app uses cluster TLS (leave tls out)", f)
			}
		}
		for _, p := range a.Public {
			n, err := normListen(p)
			if err != nil {
				add("%s.public: %q: an IP:port the nodes reach this app at", f, p)
				continue
			}
			ra.Report = append(ra.Report, n)
		}
		if len(ra.Report) == 0 {
			ra.Report = ra.Listen
		}
		switch {
		case ra.GuardMode:
		case srcs == 0:
			add("%s: the key is required: key_env, key_file or key (the site's origin-auth secret)", f)
		case srcs > 1:
			add("%s: give only one of key_env, key_file, key", f)
		}
		read := func(field, env, file string) string {
			switch {
			case env != "":
				v := strings.TrimSpace(getenv(env))
				if v == "" {
					add("%s.%s: the environment variable %s is empty or not set", f, field, env)
				}
				return v
			case file != "":
				r.Files = append(r.Files, file)
				kb, err := os.ReadFile(file)
				if err != nil {
					add("%s.%s: %v", f, field, err)
					return ""
				}
				h.Write(kb)
				return strings.TrimSpace(string(kb))
			}
			return ""
		}
		if a.Key != "" {
			ra.KeyValue = strings.TrimSpace(a.Key)
		} else {
			ra.KeyValue = read(map[bool]string{true: "key_env", false: "key_file"}[a.KeyEnv != ""], a.KeyEnv, a.KeyFile)
		}
		if ra.KeyValue != "" && len(ra.KeyValue) < 24 {
			add("%s: the key is shorter than 24 characters: it must be the site's origin-auth secret", f)
		}
		if a.NextKeyEnv != "" && a.NextKeyFile != "" {
			add("%s: give only one of next_key_env, next_key_file", f)
		}
		if a.NextKeyEnv != "" || a.NextKeyFile != "" {
			if a.NextKeyEnv != "" && strings.TrimSpace(getenv(a.NextKeyEnv)) == "" {
				// an empty next key is normal between rotations
			} else {
				ra.NextKey = read(map[bool]string{true: "next_key_env", false: "next_key_file"}[a.NextKeyEnv != ""], a.NextKeyEnv, a.NextKeyFile)
			}
		}
		h.Write([]byte(ra.KeyValue + "\x00" + ra.NextKey + "\x00"))
		for j, al := range a.Allow {
			if _, err := parsePrefix(al); err != nil {
				add("%s.allow[%d]: %q is not an IP address or prefix", f, j, al)
			}
		}
		ra.HeaderCheck = (a.HeaderCheck == nil || *a.HeaderCheck) && !ra.GuardMode
		if a.TLS != nil && !a.TLS.Cluster {
			if a.TLS.Cert == "" || a.TLS.Key == "" {
				add("%s.tls: cert and key are both required", f)
			} else {
				for _, tf := range []string{a.TLS.Cert, a.TLS.Key} {
					if _, err := os.Stat(tf); err != nil {
						add("%s.tls: %v", f, err)
					}
				}
			}
		}
		for j, host := range a.Hosts {
			hn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
			if hn == "" || strings.ContainsAny(hn, " /:") || strings.Contains(hn[min(1, len(hn)):], "*") {
				add("%s.hosts[%d]: %q is not a host name (exact or *.example.com)", f, j, host)
			}
			ra.Hosts[j] = hn
		}
		if ra.Kind == "tcp" {
			if len(a.Hosts) > 0 {
				add("%s.hosts: a TCP app has no host names (one TCP app per listen address)", f)
			}
			if a.TLS != nil {
				add("%s.tls: not for TCP apps yet (the TLS of the service passes through)", f)
			}
			ra.HeaderCheck = false
		}
		// listen sharing
		for _, addr := range ra.Listen {
			if ra.Kind == "" {
				break
			}
			l := listens[addr]
			tlsID := ra.TLSKind()
			if l == nil {
				l = &lsn{kind: ra.Kind, tls: tlsID, hosts: map[string]string{}}
				listens[addr] = l
			} else {
				switch {
				case l.kind == "tcp" || ra.Kind == "tcp":
					add("%s.listen: %s is used by %s; a TCP app needs its own address", f, addr, strings.Join(l.apps, ", "))
				case l.tls != tlsID:
					add("%s.tls: every app on %s must use the same tls (cluster, or the same files) (%s)", f, addr, strings.Join(l.apps, ", "))
				}
			}
			l.apps = append(l.apps, a.Name)
			if len(ra.Hosts) == 0 && !ra.GuardMode { // guard mode: the node names the app
				l.defaults++
				if l.defaults > 1 {
					add("%s.hosts: %s is shared: list the hosts of each app (only one app may have none)", f, addr)
				}
			}
			for _, hn := range ra.Hosts {
				if other, ok := l.hosts[hn]; ok {
					add("%s.hosts: %s on %s is already in %s", f, hn, addr, other)
				}
				l.hosts[hn] = a.Name
			}
		}
		r.Apps = append(r.Apps, ra)
	}
	// 0.0.0.0:8080 and 203.0.113.5:8080 cannot both be bound
	for addr := range listens {
		host, port, _ := net.SplitHostPort(addr)
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsUnspecified() {
			for other := range listens {
				if oh, op, _ := net.SplitHostPort(other); op == port && oh != host {
					add("listen: %s and %s overlap (every address and one of them, same port)", addr, other)
				}
			}
		}
	}
	if len(p) > 0 {
		return nil, p
	}
	r.Hash = hex.EncodeToString(h.Sum(nil))
	return r, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Listens groups the apps by listen address, in config order.
func (r *Resolved) Listens() (addrs []string, apps map[string][]ResolvedApp) {
	apps = map[string][]ResolvedApp{}
	for _, a := range r.Apps {
		for _, l := range a.Listen {
			if !slices.Contains(addrs, l) {
				addrs = append(addrs, l)
			}
			apps[l] = append(apps[l], a)
		}
	}
	return addrs, apps
}

// UnmarshalYAML accepts "cluster" or {cert, key}.
func (t *TLS) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		if n.Value != "cluster" {
			return fmt.Errorf("line %d: tls is \"cluster\" or {cert: …, key: …}", n.Line)
		}
		*t = TLS{Cluster: true}
		return nil
	}
	type plain TLS
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*t = TLS(p)
	return nil
}

// MarshalYAML writes "cluster" back as a scalar (flags mode).
func (t TLS) MarshalYAML() (any, error) {
	if t.Cluster {
		return "cluster", nil
	}
	return map[string]string{"cert": t.Cert, "key": t.Key}, nil
}

// TLSKind: "", "cluster" or "files:<cert>|<key>".
func (a App) TLSKind() string {
	switch {
	case a.TLS == nil:
		return ""
	case a.TLS.Cluster:
		return "cluster"
	}
	return "files:" + a.TLS.Cert + "|" + a.TLS.Key
}

// Addrs is one address or a list of them in YAML.
type Addrs []string

// UnmarshalYAML accepts "ip:port" and [ip:port, …].
func (a *Addrs) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*a = Addrs{n.Value}
		return nil
	case yaml.SequenceNode:
		var l []string
		if err := n.Decode(&l); err != nil {
			return err
		}
		*a = l
		return nil
	}
	return fmt.Errorf("line %d: listen must be an address or a list of addresses", n.Line)
}

var errAnyAddr = errors.New("every address")

// normListen checks "ip:port" and returns it in canonical form; errAnyAddr
// (with the canonical form) for no IP, 0.0.0.0 or [::].
func normListen(s string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return "", errors.New("not an address like 203.0.113.5:8080")
	}
	if n, err := net.LookupPort("tcp", port); err != nil || n == 0 {
		return "", errors.New("bad port")
	}
	if host == "" {
		return ":" + port, errAnyAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", errors.New("the host must be an IP address of this server, not a name")
	}
	ip = ip.Unmap()
	n := net.JoinHostPort(ip.String(), port)
	if ip.IsUnspecified() {
		return n, errAnyAddr
	}
	return n, nil
}

func portOf(s string) string {
	if _, p, err := net.SplitHostPort(s); err == nil {
		return p
	}
	return "8080"
}
