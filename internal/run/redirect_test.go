package run

import (
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/axgrid/edge-guard/internal/config"
)

// Redirects by host and path, answered by the guard after the check.
func TestRedirects(t *testing.T) {
	t.Setenv("K", key)
	p := panel(t)
	svc := service(t, "app")
	web := freePort(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	write(t, path, fmt.Sprintf(`
state_dir: %s
clusters:
  edge: {panel: %s}
apps:
  - name: kiosk
    listen: "%s"
    hosts: [kiosk.example.com, admin.kiosk.example.com, "*.shop.example.com"]
    to: "%s"
    key_env: K
    redirects:
      - {host: admin.kiosk.example.com, path: /, to: /admin/}
      - {host: kiosk.example.com, path: /, to: /kiosk/, code: 308}
      - {path: /old/*, to: "/new/{rest}", code: 301}
      - {host: "*.shop.example.com", path: /, to: "https://{host}/store/"}
`, dir, p.URL, web, svc))
	r, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Path: path, Log: slog.New(slog.DiscardHandler), Level: new(slog.LevelVar)}
	if err := m.Apply(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	try := func(host, p string, withKey bool) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+web+p, nil)
		req.Host = host
		if withKey {
			req.Header.Set("X-Edge-Auth", key)
		}
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Location")
	}
	for _, c := range []struct {
		host, path string
		code       int
		loc        string
	}{
		{"admin.kiosk.example.com", "/", 302, "/admin/"},
		{"admin.kiosk.example.com", "/?a=1", 302, "/admin/?a=1"},
		{"kiosk.example.com", "/", 308, "/kiosk/"},
		{"kiosk.example.com", "/old/x/y", 301, "/new/x/y"},
		{"kiosk.example.com", "/old/a%20b", 301, "/new/a%20b"},
		{"a.shop.example.com", "/", 302, "https://a.shop.example.com/store/"},
		{"admin.kiosk.example.com", "/admin/", 200, ""}, // not the root: to the service
		{"kiosk.example.com", "/other", 200, ""},
	} {
		if code, loc := try(c.host, c.path, true); code != c.code || loc != c.loc {
			t.Errorf("%s%s: %d %q, want %d %q", c.host, c.path, code, loc, c.code, c.loc)
		}
	}
	// without the edge's key: Forbidden, never the redirect
	if code, loc := try("admin.kiosk.example.com", "/", false); code != 403 || loc != "" {
		t.Fatalf("no key: %d %q", code, loc)
	}
}
