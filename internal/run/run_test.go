package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axgrid/edge-guard/internal/config"
)

const key = "0123456789abcdef0123456789"

// panel answers like the edge: 127.0.0.1 is the only node.
func panel(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key {
			http.Error(w, "unknown key", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"site": "s", "ips": []string{"127.0.0.1"}})
	}))
	t.Cleanup(ts.Close)
	return ts
}

func service(t *testing.T, name string) string {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", name, r.Host)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func freePort(t *testing.T) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	return ln.Addr().String()
}

func get(t *testing.T, addr, host string, withKey bool) (int, string) {
	t.Helper()
	r, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	r.Host = host
	if withKey {
		r.Header.Set("X-Edge-Auth", key)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAppsHostsTCPAndReload(t *testing.T) {
	t.Setenv("K", key)
	p := panel(t)
	a, b, c := service(t, "a"), service(t, "b"), service(t, "c")
	echo, _ := net.Listen("tcp", "127.0.0.1:0") // TCP service: echoes one line
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	web, tcp, status := freePort(t), freePort(t), freePort(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := func(extra string) string {
		return fmt.Sprintf(`
state_dir: %s
status: %s
clusters:
  edge: {panel: %s}
apps:
  - {name: a, listen: "%s", hosts: [a.example.com], to: "%s", key_env: K}
  - {name: b, listen: "%s", hosts: ["*.b.example.com"], to: "%s", key_env: K}
  - {name: db, listen: "%s", to: "tcp://%s", key_env: K}
%s`, dir, status, p.URL, web, a, web, b, tcp, echo.Addr(), extra)
	}
	write(t, path, cfg(""))
	m := &Manager{Path: path, Log: slog.New(slog.DiscardHandler), Level: new(slog.LevelVar)}
	r, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := m.Apply(ctx, r); err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if code, body := get(t, web, "a.example.com", true); code != 200 || body != "a a.example.com" {
		t.Fatalf("a: %d %q", code, body)
	}
	if code, body := get(t, web, "x.b.example.com:8080", true); code != 200 || body != "b x.b.example.com:8080" {
		t.Fatalf("b by wildcard: %d %q", code, body)
	}
	if code, body := get(t, web, "a.example.com", false); code != 403 || body != "Forbidden" {
		t.Fatalf("no key: %d %q", code, body)
	}
	if code, _ := get(t, web, "other.example.com", true); code != 403 {
		t.Fatalf("unknown host: %d", code)
	}
	conn, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "ping\n")
	line := make([]byte, 5)
	if _, err := io.ReadFull(conn, line); err != nil || string(line) != "ping\n" {
		t.Fatalf("tcp: %q %v", line, err)
	}
	conn.Close()

	// reload: a new app on the shared address, b moves to another service;
	// the listening socket of :web stays the same
	before := m.listeners[web].ln
	write(t, path, strings.Replace(cfg(fmt.Sprintf(`  - {name: c, listen: "%s", hosts: [c.example.com], to: "%s", key_env: K}`, web, c)), `to: "`+b+`"`, `to: "`+c+`"`, 1))
	m.Reload(ctx, "test")
	if code, body := get(t, web, "c.example.com", true); code != 200 || body != "c c.example.com" {
		t.Fatalf("after reload, c: %d %q", code, body)
	}
	if _, body := get(t, web, "x.b.example.com", true); body != "c x.b.example.com" {
		t.Fatalf("after reload, b → c: %q", body)
	}
	if m.listeners[web].ln != before {
		t.Error("the shared socket was reopened")
	}

	// a broken file: reported, the running config stays
	write(t, path, cfg("  - {name: d, listen: [oops")) // syntax error
	m.Reload(ctx, "test")
	if code, _ := get(t, web, "c.example.com", true); code != 200 {
		t.Fatalf("broken file stopped the service: %d", code)
	}
	resp, err := http.Get("http://" + status)
	if err != nil {
		t.Fatal(err)
	}
	var st Status
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if !strings.Contains(st.Config.Error, "syntax: line") || len(st.Apps) != 4 || st.Apps[0].Site != "s" || st.UnknownHost != 1 {
		t.Fatalf("status: %+v", st)
	}

	// a port taken by someone else: the reload fails as a whole
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	write(t, path, cfg(fmt.Sprintf(`  - {name: e, listen: "%s", to: "%s", key_env: K}`, busy.Addr(), a)))
	m.Reload(ctx, "test")
	if st := m.Status(); !strings.Contains(st.Config.Error, "listen "+busy.Addr().String()) || len(st.Apps) != 4 {
		t.Fatalf("busy port: %+v", st.Config)
	}

	// fixed again: the error is gone; the TCP app removed closes its port
	write(t, path, strings.Replace(cfg(""), fmt.Sprintf(`  - {name: db, listen: "%s", to: "tcp://%s", key_env: K}`, tcp, echo.Addr()), "", 1))
	m.Reload(ctx, "test")
	if st := m.Status(); st.Config.Error != "" || len(st.Apps) != 2 {
		t.Fatalf("fixed: %+v", st)
	}
	time.Sleep(100 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", tcp, time.Second); err == nil {
		c.Close()
		t.Error("the removed TCP app still listens")
	}
}

// The watcher picks a change of the file by itself.
func TestWatch(t *testing.T) {
	t.Setenv("K", key)
	p := panel(t)
	a, b := service(t, "a"), service(t, "b")
	web := freePort(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := func(to string) string {
		return fmt.Sprintf("state_dir: %s\nclusters: {edge: {panel: %s}}\napps:\n  - {name: a, listen: %q, to: %q, key_env: K}\n", dir, p.URL, web, to)
	}
	write(t, path, cfg(a))
	m := &Manager{Path: path, Log: slog.New(slog.DiscardHandler)}
	r, _ := config.Load(path)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := m.Apply(ctx, r); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	go m.Watch(ctx)
	time.Sleep(50 * time.Millisecond)
	write(t, path, cfg(b)+"# changed\n")
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if _, body := get(t, web, "x", true); strings.HasPrefix(body, "b ") {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the change was not picked up")
}
