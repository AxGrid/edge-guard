package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const key = "0123456789abcdef0123456789"

func env(k string) string {
	return map[string]string{"SHOP_KEY": key, "DB_KEY": key + "x", "SHORT": "short"}[k]
}

const good = `
state_dir: /tmp/eg
status: 127.0.0.1:9102
clusters:
  prod:
    panel: https://panel.example.com
    nodes: [203.0.113.10, 203.0.113.20]
  staging:
    panel: https://panel.staging.example.com
apps:
  - name: shop
    cluster: prod
    listen: [203.0.113.5:8080, "[2001:db8::5]:8080"]
    hosts: [shop.example.com, "*.shop.example.com"]
    to: http://127.0.0.1:3000
    key_env: SHOP_KEY
    allow: [127.0.0.1, 10.0.0.0/8]
  - name: blog
    cluster: staging
    listen: 203.0.113.5:8080
    to: http://127.0.0.1:3001
    key_env: SHOP_KEY
  - name: db
    cluster: prod
    listen: 203.0.113.5:5432
    to: tcp://127.0.0.1:5433
    key_env: DB_KEY
`

func TestGood(t *testing.T) {
	r, err := Parse([]byte(good), "x.yaml", env)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Apps) != 3 || r.Apps[0].KeyValue != key || r.Apps[2].Kind != "tcp" || r.Apps[2].HeaderCheck || !r.Apps[0].HeaderCheck {
		t.Fatalf("%+v", r.Apps)
	}
	if r.Apps[1].ClusterDef.Panel != "https://panel.staging.example.com" {
		t.Errorf("cluster of blog: %+v", r.Apps[1].ClusterDef)
	}
	addrs, by := r.Listens()
	if strings.Join(addrs, " ") != "203.0.113.5:8080 [2001:db8::5]:8080 203.0.113.5:5432" || len(by["203.0.113.5:8080"]) != 2 || len(by["[2001:db8::5]:8080"]) != 1 {
		t.Errorf("listens %v %v", addrs, by)
	}
	r2, _ := Parse([]byte(good), "x.yaml", env)
	if r.Hash != r2.Hash {
		t.Error("hash is not stable")
	}
	r3, _ := Parse([]byte(good), "x.yaml", func(k string) string { return env(k) + "changed" })
	if r.Hash == r3.Hash {
		t.Error("a changed key must change the hash")
	}
}

// Every mistake is reported at once, syntax errors with the line.
func TestProblems(t *testing.T) {
	cases := map[string][]string{
		"clusters: {a: {panel: x}\napps: [":                                       {"syntax: line"},
		"clusters:\n  a:\n    panel: https://p\n    nodez: [1.2.3.4]\napps: []\n": {`line 4: unknown field "nodez" (in a cluster)`},
		"": {"the config is empty"},
		`
clusters:
  a: {panel: https://p.example}
  b: {panel: "ftp://x"}
apps:
  - name: one
    listen: 192.0.2.1:80
    to: http://127.0.0.1:1
    key_env: SHORT
  - name: one
    cluster: zz
    listen: "80"
    to: tcp://127.0.0.1
    key_env: NOPE
    key: x
  - name: three
    cluster: a
    listen: 192.0.2.1:80
    to: http://127.0.0.1:2
    key_env: SHOP_KEY
    allow: [nonsense]
    protocol: h3
`: {
			`clusters.b.panel: "ftp://x" is not an http(s) URL`,
			"apps[0] (one).cluster: required when there are several clusters",
			"apps[0] (one): the key is shorter than 24 characters",
			`apps[1] (one).name: "one" is used twice`,
			`apps[1] (one).cluster: no cluster "zz"`,
			"apps[1] (one).to: a tcp target needs a port",
			`apps[1] (one).listen: "80": not an address like 203.0.113.5:8080`,
			"apps[1] (one): give only one of key_env, key_file, key",
			"apps[2] (three).allow[0]",
			"apps[2] (three).protocol: h1, auto or h2",
			"apps[2] (three).hosts: 192.0.2.1:80 is shared: list the hosts of each app",
		},
		`
clusters: {a: {nodes: [1.2.3.4]}}
apps:
  - {name: t, listen: "192.0.2.1:9", to: "tcp://127.0.0.1:9", key_env: SHOP_KEY, hosts: [x.com]}
  - {name: h, listen: "192.0.2.1:9", to: "http://127.0.0.1:9", key_env: SHOP_KEY, hosts: [y.com]}
  - {name: h1, listen: "192.0.2.1:7", to: "http://127.0.0.1:9", key_env: SHOP_KEY, hosts: [y.com]}
  - {name: h2, listen: "192.0.2.1:7", to: "http://127.0.0.1:9", key_env: SHOP_KEY, hosts: [Y.com.]}
  - {name: e, listen: "192.0.2.1:6", to: "http://127.0.0.1:9", key_env: NOT_SET}
`: {
			"apps[0] (t).hosts: a TCP app has no host names",
			"apps[1] (h).listen: 192.0.2.1:9 is used by t; a TCP app needs its own address",
			"apps[3] (h2).hosts: y.com on 192.0.2.1:7 is already in h1",
			"apps[4] (e).key_env: the environment variable NOT_SET is empty or not set",
		},
		`
clusters: {a: {nodes: [1.2.3.4]}}
apps:
  - {name: a, listen: ":8080", to: "http://127.0.0.1:9", key_env: SHOP_KEY}
  - {name: b, listen: "0.0.0.0:8081", to: "http://127.0.0.1:9", key_env: SHOP_KEY}
  - {name: c, listen: "[::]:8082", to: "http://127.0.0.1:9", key_env: SHOP_KEY}
  - {name: d, listen: "myhost.example.com:8083", to: "http://127.0.0.1:9", key_env: SHOP_KEY}
  - {name: e, listen: [192.0.2.1:8084, 192.0.2.1:8084], to: "http://127.0.0.1:9", key_env: SHOP_KEY}
  - {name: f, listen: "0.0.0.0:8085", bind_any: true, to: "http://127.0.0.1:9", key_env: SHOP_KEY}
  - {name: g, listen: "192.0.2.1:8085", to: "http://127.0.0.1:9", key_env: SHOP_KEY}
  - {name: h, to: "http://127.0.0.1:9", key_env: SHOP_KEY}
`: {
			`apps[0] (a).listen: ":8080" takes every address of the server; give the IP the edge connects to (e.g. 203.0.113.5:8080), or set bind_any: true`,
			`apps[1] (b).listen: "0.0.0.0:8081" takes every address`,
			`apps[2] (c).listen: "[::]:8082" takes every address`,
			`apps[3] (d).listen: "myhost.example.com:8083": the host must be an IP address of this server`,
			"apps[4] (e).listen: 192.0.2.1:8084 is listed twice",
			"listen: 0.0.0.0:8085 and 192.0.2.1:8085 overlap",
			"apps[7] (h).listen: required",
		},
		"clusters: {a: {nodes: [1.2.3.4]}}\napps:\n  - {name: i, listen: {x: 1}, to: \"http://127.0.0.1:9\", key_env: SHOP_KEY}\n": {
			"line 3: listen must be an address or a list of addresses",
		},
	}
	for in, want := range cases {
		_, err := Parse([]byte(in), "x.yaml", env)
		if err == nil {
			t.Errorf("no error for:\n%s", in)
			continue
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("missing %q in:\n%v", w, err)
			}
		}
	}
}

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	kf := filepath.Join(dir, "shop.key")
	os.WriteFile(kf, []byte(key+"\n"), 0o600)
	in := "clusters: {a: {panel: https://p.example}}\napps:\n  - {name: s, listen: '127.0.0.1:1', to: 'http://127.0.0.1:2', key_file: " + kf + "}\n"
	r, err := Parse([]byte(in), "x.yaml", env)
	if err != nil {
		t.Fatal(err)
	}
	if r.Apps[0].KeyValue != key || len(r.Files) != 2 || r.Files[1] != kf {
		t.Errorf("%+v %v", r.Apps[0].KeyValue, r.Files)
	}
}

func TestClusterTLSConfig(t *testing.T) {
	in := `
clusters: {a: {panel: https://p.example}}
apps:
  - {name: s, listen: "192.0.2.1:8443", hosts: [s.example.com], to: "http://127.0.0.1:2", key_env: SHOP_KEY, tls: cluster}
  - {name: b, listen: "192.0.2.1:8443", hosts: [b.example.com], to: "http://127.0.0.1:3", key_env: DB_KEY, tls: cluster}
`
	r, err := Parse([]byte(in), "x.yaml", env)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Apps[0].TLS.Cluster || r.Apps[0].TLSKind() != "cluster" {
		t.Fatalf("%+v", r.Apps[0].TLS)
	}
	bad := map[string]string{
		`tls: clusterr`: `tls is "cluster" or {cert: …, key: …}`,
		`tls: cluster
  - {name: x, listen: "192.0.2.1:8443", hosts: [x.example.com], to: "http://127.0.0.1:2", key_env: SHOP_KEY, tls: {cert: /nope.pem, key: /nope.key}}`: "every app on 192.0.2.1:8443 must use the same tls",
	}
	for tail, want := range bad {
		in := "clusters: {a: {panel: https://p.example}}\napps:\n  - {name: s, listen: \"192.0.2.1:8443\", hosts: [s.example.com], to: \"http://127.0.0.1:2\", key_env: SHOP_KEY}\n"
		in = strings.Replace(in, "key_env: SHOP_KEY}", "key_env: SHOP_KEY, "+strings.SplitN(tail, "\n", 2)[0]+"}", 1)
		if parts := strings.SplitN(tail, "\n", 2); len(parts) == 2 {
			in += parts[1] + "\n"
		}
		if _, err := Parse([]byte(in), "x.yaml", env); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", tail, err)
		}
	}
	tcp := "clusters: {a: {panel: https://p.example}}\napps:\n  - {name: d, listen: \"192.0.2.1:5432\", to: \"tcp://127.0.0.1:5433\", key_env: SHOP_KEY, tls: cluster}\n"
	if _, err := Parse([]byte(tcp), "x.yaml", env); err == nil || !strings.Contains(err.Error(), "not for TCP apps yet") {
		t.Errorf("tcp: %v", err)
	}
}
