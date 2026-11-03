package run

import (
	"net"
	"net/http"
	"strings"

	"github.com/axgrid/edge-guard/internal/config"
)

// redirects answers the app's redirects itself and passes every other
// request to next.
func redirects(list []config.Redirect, next http.Handler) http.Handler {
	if len(list) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		for _, rd := range list {
			rest, ok := matchRedirect(rd, host, r.URL.EscapedPath())
			if !ok {
				continue
			}
			to := strings.NewReplacer("{host}", host, "{rest}", rest).Replace(rd.To)
			if r.URL.RawQuery != "" && !strings.Contains(to, "?") {
				to += "?" + r.URL.RawQuery
			}
			code := rd.Code
			if code == 0 {
				code = http.StatusFound
			}
			w.Header().Set("Location", to)
			w.Header().Set("Cache-Control", "no-store") // a changed redirect takes effect at once
			w.WriteHeader(code)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func matchRedirect(rd config.Redirect, host, path string) (rest string, ok bool) {
	if h := strings.ToLower(rd.Host); h != "" {
		if suf, wild := strings.CutPrefix(h, "*."); wild {
			if !strings.HasSuffix(host, "."+suf) {
				return "", false
			}
		} else if host != h {
			return "", false
		}
	}
	if prefix, wild := strings.CutSuffix(rd.Path, "*"); wild {
		if !strings.HasPrefix(path, prefix) {
			return "", false
		}
		return strings.TrimPrefix(path, prefix), true // as escaped in the request
	}
	return "", path == rd.Path
}
