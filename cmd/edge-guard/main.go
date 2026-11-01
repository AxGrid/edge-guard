// edge-guard stands in front of services and lets in only the nodes of an
// edge cluster: everyone else gets 403 Forbidden. The list of the nodes'
// addresses comes from the edge panel with a key (the site's origin-auth
// secret), is refreshed every minute and kept on disk.
//
// With a config file (several clusters and apps; reloaded on change or
// SIGHUP without a restart, a broken file is reported and the running
// config stays):
//
//	edge-guard -config /etc/edge-guard/config.yaml
//	edge-guard -check -config /etc/edge-guard/config.yaml   # check only
//
// One app from flags:
//
//	EDGE_GUARD_KEY=… edge-guard -panel https://panel.example.com \
//	  -nodes 203.0.113.10,203.0.113.20 -listen 198.51.100.5:8080 -to http://127.0.0.1:3000
//
// The listen address must name this server's IP (on a server with many
// addresses only that one is taken); every address only with -bind-any.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	guard "github.com/axgrid/edge-guard"
	"github.com/axgrid/edge-guard/internal/config"
	"github.com/axgrid/edge-guard/internal/run"
)

var version = "dev"

func main() {
	var (
		cfgPath  = flag.String("config", "", "config file (YAML): several clusters and apps, reloaded on change")
		check    = flag.Bool("check", false, "check the config and exit (1 on errors)")
		online   = flag.Bool("online", false, "with -check: also fetch every app's node list from its panel")
		panel    = flag.String("panel", "", "one app: edge panel URL, e.g. https://panel.example.com")
		nodes    = flag.String("nodes", "", "one app: edge node addresses, comma separated")
		listen   = flag.String("listen", "", "one app: this server's IP and port the edge connects to, e.g. 203.0.113.5:8080 (several: comma separated)")
		bindAny  = flag.Bool("bind-any", false, "one app: allow -listen on every address of the server (:8080, 0.0.0.0:8080)")
		to       = flag.String("to", "", "one app: the service, http://host:port, https://host:port or tcp://host:port")
		keyEnv   = flag.String("key-env", "EDGE_GUARD_KEY", "one app: environment variable with the key (the site's origin-auth secret)")
		keyFile  = flag.String("key-file", "", "one app: file with the key")
		nextEnv  = flag.String("next-key-env", "EDGE_GUARD_NEXT_KEY", "one app: the next key during a rotation (optional)")
		allow    = flag.String("allow", "", "one app: addresses or prefixes always let in, comma separated")
		noHeader = flag.Bool("no-header-check", false, "one app: accept requests from the nodes without the origin-auth header")
		tlsMode  = flag.String("tls", "", `one app: "cluster" — TLS with a certificate of the edge cluster's CA (got and renewed by itself) and only node client certificates; the site's pool needs cluster_tls`)
		tlsCert  = flag.String("tls-cert", "", "one app: serve HTTPS with this certificate (PEM)")
		tlsKey   = flag.String("tls-key", "", "one app: key of -tls-cert")
		insecure = flag.Bool("insecure", false, "one app: do not verify the certificate of an https:// service")
		proto    = flag.String("protocol", "", "one app: to the service h1 (default), auto or h2 (gRPC)")
		state    = flag.String("state-dir", "", "one app: directory for the last node list")
		status   = flag.String("status", "", "one app: JSON status address, e.g. 127.0.0.1:9102")
		debug    = flag.Bool("debug", false, "one app: log every refused request")
		showVer  = flag.Bool("version", false, "print the version")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("edge-guard", version)
		return
	}
	level := new(slog.LevelVar)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	var (
		r   *config.Resolved
		err error
	)
	if *cfgPath != "" {
		r, err = config.Load(*cfgPath)
	} else {
		if *to == "" {
			fmt.Fprintln(os.Stderr, "edge-guard: -config or -to is required (edge-guard -h for help)")
			os.Exit(2)
		}
		c := config.Config{StateDir: *state, Status: *status, LogLevel: map[bool]string{true: "debug", false: "info"}[*debug],
			Clusters: map[string]config.Cluster{"edge": {Panel: *panel, Nodes: split(*nodes)}},
			Apps: []config.App{{Name: "app", Listen: split(*listen), BindAny: *bindAny, To: *to, Allow: split(*allow), Insecure: *insecure, Protocol: *proto,
				NextKeyEnv: *nextEnv}}}
		if *keyFile != "" {
			c.Apps[0].KeyFile = *keyFile
		} else {
			c.Apps[0].KeyEnv = *keyEnv
		}
		if *noHeader {
			f := false
			c.Apps[0].HeaderCheck = &f
		}
		switch {
		case *tlsMode == "cluster":
			c.Apps[0].TLS = &config.TLS{Cluster: true}
		case *tlsMode != "":
			fmt.Fprintln(os.Stderr, `edge-guard: -tls takes "cluster" (or use -tls-cert and -tls-key)`)
			os.Exit(2)
		case *tlsCert != "" || *tlsKey != "":
			c.Apps[0].TLS = &config.TLS{Cert: *tlsCert, Key: *tlsKey}
		}
		b, _ := yaml.Marshal(c)
		r, err = config.Parse(b, "", os.Getenv)
	}
	if err != nil {
		if *cfgPath != "" {
			fmt.Fprintf(os.Stderr, "edge-guard: config %s: %v\n", *cfgPath, err)
		} else {
			fmt.Fprintf(os.Stderr, "edge-guard: %v\n(flags: -listen IP:port, -to, -panel/-nodes, the key in $%s or -key-file)\n", err, *keyEnv)
		}
		os.Exit(1)
	}
	if *check {
		os.Exit(checkOnly(r, *online))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	m := &run.Manager{Version: version, Path: *cfgPath, Log: log, Level: level}
	if err := m.Apply(ctx, r); err != nil {
		log.Error("cannot start", "err", err)
		os.Exit(1)
	}
	log.Info("edge-guard started", "version", version, "config", *cfgPath, "apps", len(r.Apps))
	if *cfgPath != "" {
		go m.Watch(ctx)
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				m.Reload(ctx, "SIGHUP")
			}
		}()
	}
	<-ctx.Done()
	log.Info("stopping")
	m.Close()
}

// checkOnly prints what the config sets up; online: fetches each list.
func checkOnly(r *config.Resolved, online bool) int {
	fmt.Printf("config OK: %d cluster(s), %d app(s)\n", len(r.Clusters), len(r.Apps))
	code := 0
	// an IP that is not on this server fails at start ("cannot assign requested address")
	local := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				local[p.Addr().Unmap().String()] = true
			}
		}
	}
	warned := map[string]bool{}
	for _, a := range r.Apps {
		for _, l := range a.Listen {
			host, _, _ := net.SplitHostPort(l)
			ip, err := netip.ParseAddr(host)
			if err != nil || ip.IsUnspecified() || local[ip.Unmap().String()] || warned[host] {
				continue
			}
			warned[host] = true
			fmt.Printf("warning: %s is not an address of this machine (listen of %s): it can be used only on the server that has it\n", host, a.Name)
		}
	}
	for _, a := range r.Apps {
		hosts := ""
		if len(a.Hosts) > 0 {
			hosts = " hosts=" + strings.Join(a.Hosts, ",")
		}
		mode := ""
		if a.GuardMode {
			mode = " guard-mode"
		}
		line := fmt.Sprintf("  %-16s %-8s %s → %s cluster=%s%s%s", a.Name, a.Kind, strings.Join(a.Listen, ","), a.To, a.Cluster, hosts, mode)
		if online {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			gc := guard.Config{Panel: a.ClusterDef.Panel, Nodes: a.ClusterDef.Nodes, Key: a.KeyValue, Log: slog.New(slog.DiscardHandler)}
			if a.GuardMode {
				// registers all apps of the cluster, as the running guard does
				hostname, _ := os.Hostname()
				gc.Key, gc.GuardKey, gc.Hostname, gc.Version = "", a.GuardKey, hostname, version
				for _, b := range r.Apps {
					if b.GuardMode && b.Cluster == a.Cluster {
						gc.Apps = append(gc.Apps, guard.App{Name: b.Name, Kind: b.Kind, Listen: b.Report, Hosts: append([]string{}, b.Hosts...)})
					}
				}
			}
			g, err := guard.New(ctx, gc)
			switch {
			case err != nil:
				line += "\n      panel: " + strings.ReplaceAll(err.Error(), "\n", "\n      ")
				code = 1
			default:
				l := g.List()
				what := "site"
				if a.GuardMode {
					what = "guard"
				}
				line += fmt.Sprintf("\n      panel: %s %s, %d node address(es): %s", what, l.Site, len(l.IPs), strings.Join(l.IPs, " "))
				switch {
				case a.GuardMode:
					line += "\n      reported to the panel: bind a domain to it there (Guards → " + l.Site + " → " + a.Name + ")"
				case a.TLS != nil && a.TLS.Cluster && l.CA == "":
					line += "\n      cluster TLS: NOT offered by this edge (update edge on the nodes)"
					code = 1
				case a.TLS != nil && a.TLS.Cluster:
					line += "\n      cluster TLS: available, server name " + l.ServerName + "; the site's pool needs https:// servers and cluster_tls"
				}
			}
			cancel()
		}
		fmt.Println(line)
	}
	return code
}

func split(s string) []string {
	var out []string
	for x := range strings.SplitSeq(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
