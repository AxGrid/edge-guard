package run

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/axgrid/edge-guard/internal/config"
)

// The edge's X-Forwarded-* reach the service (httputil's Rewrite drops them).
func TestForwardedHeaders(t *testing.T) {
	t.Setenv("K", key)
	p := panel(t)
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"xff": r.Header.Get("X-Forwarded-For"), "proto": r.Header.Get("X-Forwarded-Proto"),
			"host": r.Header.Get("X-Forwarded-Host"), "real": r.Header.Get("X-Real-Ip"), "ja4": r.Header.Get("X-Ja4"),
		})
	}))
	defer echo.Close()
	web := freePort(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	write(t, path, fmt.Sprintf(`
state_dir: %s
clusters:
  edge: {panel: %s}
apps:
  - {name: a, listen: "%s", to: "%s", key_env: K}
`, dir, p.URL, web, echo.URL))
	r, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Path: path, Log: slog.New(slog.DiscardHandler), Level: new(slog.LevelVar)}
	if err := m.Apply(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ask := func(hdr map[string]string) map[string]string {
		req, _ := http.NewRequest("GET", "http://"+web+"/", nil)
		req.Host = "app.example.com"
		req.Header.Set("X-Edge-Auth", key)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	// as the edge sends them
	got := ask(map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https",
		"X-Forwarded-Host": "app.example.com", "X-Real-Ip": "203.0.113.7", "X-JA4": "t13d1516h2_8daaf6152771_e5627efa2ab1"})
	want := map[string]string{"xff": "203.0.113.7", "proto": "https", "host": "app.example.com", "real": "203.0.113.7", "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	// nothing from the edge (an allow: source): the guard's own view
	got = ask(nil)
	if got["proto"] != "http" || got["host"] != "app.example.com" {
		t.Errorf("defaults: %v", got)
	}
}
