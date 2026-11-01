# edge-guard

Only your edge may reach your servers. `edge-guard` stands in front of a service and lets in only the nodes
of an **edge** cluster (a self-hosted Cloudflare-like proxy). Everyone else gets **403 Forbidden**. The list
of the nodes' addresses comes from the edge panel with a key and follows the cluster: a new node is let in
within a minute, and a removed one is dropped.

```
 visitors ──▶ edge nodes ──▶ edge-guard :8080 ──▶ your service 127.0.0.1:3000
 anyone else ─────────────▶ edge-guard: 403 Forbidden
```

Use it as a **standalone program** next to a service in any language, or embed it in a **Go program** as a
library. The library uses only the standard library.

- **One key per site.** The key is the site's origin-auth secret in the panel (Sites → the site → Backend
  protection → Current secret). The key is used twice:
  - to fetch the node list (`GET /api/guard/ips`, `Authorization: Bearer <key>`);
  - to check the origin-auth header (`X-Edge-Auth`, or the site's own header name) on every request.

  The header check matters: another site on the same edge comes from the same addresses but does not know
  your secret.
- **No single point of failure.**
  - If the panel's name does not answer, the guard asks the nodes directly by address, using the panel's
    TLS name.
  - The last list is kept on disk, so a restart works while the panel is unreachable.
  - A failed refresh keeps the last list; it is never emptied.
- **Explicit bind.** A guard listens only on the IP addresses you name (`198.51.100.5:8080`, or a list),
  never on every address of a server by accident: `:8080` and `0.0.0.0` are refused unless `bind_any:
  true`. This matters on servers with many addresses.
- **Several clusters, apps and hosts** in one config file:
  - several HTTP apps can share a port and are chosen by `Host`, including `*.example.com`;
  - TCP apps are checked by source address only.
- **Reload without a restart.**
  - The config and key files are watched, and `SIGHUP` works too.
  - Sockets that stay are not reopened.
  - A broken file is reported with its line in the log and in the status, and the running config stays.
    The same happens to a config that cannot be applied, for example a busy port.
- **HTTP/1.1, HTTP/2, h2c (gRPC), WebSocket, streaming, TCP.** The visitor's address arrives from the edge
  in `X-Real-Ip` and `X-Forwarded-For`, unchanged.

Behind an edge tunnel (`tunnel://name`) you don't need a guard: the server has no open port at all.

## Requirements

The edge must serve `GET /api/guard/ips` (edge after 2026-11). In the panel, the site must have **Backend
protection** on, and the site must be saved before the guard starts: the edge then sends the header, and
the panel knows the key.

## Install

```sh
# Linux with systemd (amd64, arm64): the binary, a user, /etc/edge-guard with an example config, the unit
curl -fsSL https://raw.githubusercontent.com/axgrid/edge-guard/main/install.sh | sudo sh
```

Other ways:

- **Binaries.** Download from [Releases](https://github.com/axgrid/edge-guard/releases):
  `edge-guard-<linux|darwin>-<amd64|arm64>` with `SHA256SUMS`. For other systems, use `go install` or
  `GOOS=… GOARCH=… make build`.
- **Go.** `go install github.com/axgrid/edge-guard/cmd/edge-guard@latest`.
- **Docker.** `ghcr.io/axgrid/edge-guard` (see [Docker](#docker)).
- **The edge panel** also serves builds at `https://<panel>/download/edge-guard-linux-amd64`.

## Run

### One app, from flags

```sh
EDGE_GUARD_KEY='<origin-auth secret>' edge-guard \
  -panel https://panel.example.com -nodes 203.0.113.10,203.0.113.20 \
  -listen 198.51.100.5:8080 -to http://127.0.0.1:3000
```

`-listen` takes this server's IP (the one the edge connects to; `ip -4 -o addr show` lists them), several
comma separated; every address only with `-bind-any`. Make the service itself listen on `127.0.0.1`, then
point the site's pool server in the panel at exactly `198.51.100.5:8080`. Run `edge-guard -h` for all flags. They match the config fields below.

### A config file

```sh
edge-guard -check -config /etc/edge-guard/config.yaml           # check the file
edge-guard -check -online -config /etc/edge-guard/config.yaml   # + fetch every list from its panel
edge-guard -config /etc/edge-guard/config.yaml
```

```yaml
state_dir: /var/lib/edge-guard     # last node lists (default: $STATE_DIRECTORY, else /var/lib/edge-guard)
status: 127.0.0.1:9102             # JSON status
log_level: info                    # or debug: every refused request

clusters:
  prod:
    panel: https://panel.example.com
    nodes: [203.0.113.10, 203.0.113.20]   # fallback when the panel name does not answer
  staging:
    panel: https://panel.staging.example.com

apps:
  - name: shop
    cluster: prod
    listen: 198.51.100.5:8080        # this server's IP the edge connects to (or a list)
    hosts: [shop.example.com, "*.shop.example.com"]   # several apps share it by Host
    to: http://127.0.0.1:3000
    key_env: SHOP_KEY                # or key_file: /etc/edge-guard/shop.key
  - name: blog
    cluster: staging
    listen: 198.51.100.5:8080
    hosts: [blog.example.com]
    to: http://127.0.0.1:3001
    key_env: BLOG_KEY
  - name: db                         # TCP: address check only
    cluster: prod
    listen: 198.51.100.5:5432
    to: tcp://127.0.0.1:5433
    key_env: SHOP_KEY
```

The full reference with comments is in [`examples/config.yaml`](examples/config.yaml).

**Top level:**

| Field | Meaning |
|---|---|
| `state_dir`, `status`, `log_level` | As in the example above. |
| `clusters.<name>.panel` / `.nodes` | Where the lists come from. At least one of the two. |

**App fields:**

| Field | Meaning |
|---|---|
| `name` | Required and unique. |
| `cluster` | May be left out when there is one cluster. |
| `listen` | This server's IP and port, e.g. `198.51.100.5:8080` or `[2001:db8::5]:443`; a list for several addresses. No host names. `:8080`, `0.0.0.0:…` and `[::]:…` (every address) only with `bind_any: true`. `-check` warns about an IP that is not on the machine. |
| `bind_any` | Allow `listen` on every address of the server. |
| `hosts` | Exact names or `*.example.com`. Needed when apps share `listen`; one app per address may have none (the default). An unknown host gets 403. |
| `to` | `http://`, `https://` or `tcp://host:port`. |
| `key_env` / `key_file` / `key` | The site's origin-auth secret. Use exactly one; prefer `key_env`. |
| `next_key_env` / `next_key_file` | The next secret during a rotation: both are accepted. |
| `allow` | Addresses or prefixes always let in, without the header (monitoring). |
| `header_check` | `false`: check only the address. This is weaker. |
| `tls: {cert, key}` | Serve HTTPS on `listen`; all apps on that address must use the same files. |
| `protocol` | To the service: `h1` (default), `auto`, or `h2` (gRPC; h2c for `http://`). |
| `insecure` | Do not verify an `https://` service's certificate. |
| `host_header` | `Host` sent to the service (default: as the edge sent it). |

**Validation and reload:**
- Unknown fields are errors: a typo must not silently turn protection off.
- Keys are read when the config is loaded. Changing a key file triggers a reload. Changing a key in the
  environment needs a restart.

**Reload:**
- It happens on saving the file (checked every 2 s), or on `systemctl reload edge-guard` (`SIGHUP`).
- **If the new config cannot be applied, nothing of it is applied.** Causes: a syntax error, an unknown
  field, a missing key, a busy port, or no node list from the panel and no cache. The previous config keeps
  running. The error is logged (`config NOT applied, the previous one keeps running`) and shown in the
  status as `config.error` until a good file is applied.

### Status

`status: 127.0.0.1:9102` → `GET /` returns:

```json
{ "version": "v1.0.0",
  "config": { "file": "/etc/edge-guard/config.yaml", "loaded_at": "…", "hash": "3f2a…", "error": "" },
  "apps": [ { "name": "shop", "listen": ["198.51.100.5:8080"], "to": "http://127.0.0.1:3000", "cluster": "prod",
              "site": "shop", "ips": ["203.0.113.10", "203.0.113.20"], "fetched_at": "…",
              "denied": 12, "last_error": "" } ],
  "unknown_host": 0 }
```

### systemd

[`deploy/edge-guard.service`](deploy/edge-guard.service) is the unit that `install.sh` installs.
- It runs as the `edge-guard` user.
- Keys go in `/etc/edge-guard/env` (mode 600): systemd reads it as root.
- `key_file` and TLS keys must be readable by the `edge-guard` user: `root:edge-guard`, mode 640.

### Docker

```sh
docker run -d --name edge-guard --network host --restart unless-stopped \
  -v /etc/edge-guard:/etc/edge-guard:ro -v edge-guard:/var/lib/edge-guard \
  --env-file /etc/edge-guard/env ghcr.io/axgrid/edge-guard
```

Use `--network host`: with published ports, rootless Docker, Docker Desktop and other userland-proxy setups
show the bridge gateway as the source, and every request is refused. If you run it as a compose sidecar
with published ports, check `log_level: debug`. Refused lines show `remote=`, and it must be the node's
address.

## Go library

```sh
go get github.com/axgrid/edge-guard
```

```go
import guard "github.com/axgrid/edge-guard"

g, err := guard.New(ctx, guard.Config{
	Panel:     "https://panel.example.com",
	Nodes:     []string{"203.0.113.10", "203.0.113.20"},
	Key:       os.Getenv("EDGE_GUARD_KEY"),
	NextKey:   os.Getenv("EDGE_GUARD_NEXT_KEY"), // during a rotation
	CacheFile: "/var/lib/myapp/edge-guard.json",
	Allow:     []string{"127.0.0.1"},
})
if err != nil {
	log.Fatal(err) // no panel and no cached list: do not start open
}
srv := &http.Server{Addr: "198.51.100.5:8080", Handler: g.Handler(mux)} // the IP the edge connects to; 403 Forbidden to others
```

| API | |
|---|---|
| `g.Handler(next)` | HTTP: address + header check, 403 otherwise. |
| `g.Check(r)` | The same decision, without answering. |
| `g.Listener(ln)` | TCP: closes connections from other addresses. |
| `g.AcceptAddr(addr)` | The same check for one connection's `ip:port`. |
| `g.ClientIP(r)` | The visitor's address (`X-Real-Ip` from a node, else the peer). |
| `g.Status()` | `site`, `ips`, `fetched_at`, `denied`, `last_error`. |
| `g.Refresh(ctx)` | Fetch now (it runs every minute by itself until `ctx` ends). |

## Claude Code skill

[`skills/edge-guard/SKILL.md`](skills/edge-guard/SKILL.md) teaches Claude Code to install, configure,
embed and check edge-guard. It asks for the cluster (panel and node addresses), the key of each app, and
the IP of the server to listen on. Install it once per machine:

```sh
mkdir -p ~/.claude/skills/edge-guard && curl -fsSL \
  https://raw.githubusercontent.com/AxGrid/edge-guard/main/skills/edge-guard/SKILL.md \
  -o ~/.claude/skills/edge-guard/SKILL.md
```

Then ask Claude Code, for example, "закрой этот сервис через edge-guard" or "protect this origin with
edge-guard". You can put your clusters in the skill's table so it offers them.

## The panel API

```
GET /api/guard/ips
Authorization: Bearer <a site's origin-auth secret or its next secret>

200 { "site": "shop", "header": "X-Edge-Auth", "ips": ["203.0.113.10", …], "refresh_seconds": 60 }
401 unknown key (failed attempts are limited per address: 30 / 10 min → 429)
```

## Building

```sh
make test     # gofmt, vet, tests with -race
make build    # bin/edge-guard
make dist     # Linux and macOS (amd64, arm64) + SHA256SUMS into dist/
```

A tag `v*` runs [`release.yml`](.github/workflows/release.yml), which publishes:
- the binaries on the GitHub release;
- the image `ghcr.io/axgrid/edge-guard:<tag>` and `latest`.

## License

[Apache License 2.0](LICENSE).
