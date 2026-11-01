---
name: edge-guard
description: Use this skill when the user wants a service (any language) to accept traffic only from the nodes of their edge cluster (the self-hosted Cloudflare-like proxy, panel.example.com / panel.staging.example.com) and answer 403 Forbidden to everyone else — by running the standalone edge-guard (github.com/axgrid/edge-guard; binary, systemd, Docker; a YAML config with several clusters, apps and hosts, reloaded without a restart) next to it, or by embedding the Go library github.com/axgrid/edge-guard. The allow-list comes from the edge panel API by a key (the site's origin-auth secret) and follows the cluster. Triggers on phrases like "edge-guard", "пускать только с нод edge", "белый список нод", "закрыть бэкенд от прямого доступа", "только через наш прокси", "403 если не с edge", "allow only edge nodes", "origin allowlist", "protect origin behind edge", "встрой edge-guard", "подключи guard", "чтобы бэкенд не был доступен напрямую", "конфиг edge-guard", "добавь приложение в edge-guard".
---

# edge-guard

`edge-guard` (repo `github.com/axgrid/edge-guard`, Apache-2.0; local checkout `<checkout>`)
lets in only the **edge nodes** and answers **403 Forbidden** to everyone else.

- **Where the list comes from:** the panel, `GET /api/guard/ips` with `Authorization: Bearer <key>`.
- **How it stays fresh:**
  - refreshed every minute;
  - kept on disk, so a restart works without the panel;
  - never emptied by a failed refresh;
  - if the panel's name does not answer, the nodes are asked by IP with the panel's TLS name.
- **HTTP is checked twice:** the source address, and the site's origin-auth header (`X-Edge-Auth` or the
  site's own name) carrying the same key. Another site on the same edge comes from the same addresses but
  does not know this secret.
- **TCP:** address only.

There are two ways to use it:
- **Standalone program**, any language. One app from flags, or a YAML config with several clusters, apps
  and hosts (`Host` routing on a shared port). The config is reloaded on file change or SIGHUP without a
  restart. A broken config is reported with its line, and the running config stays.
- **Go library:** `import guard "github.com/axgrid/edge-guard"`. It uses only the standard library.

Read the repo's `README.md` and `examples/config.yaml` when you need a detail that is not here.

## Workflow

Do the steps in order. Skip a question that is already answered, but **never skip steps 1 and 2**.

### 1 · Ask: the cluster — panel URL and node addresses (mandatory)

Use `AskUserQuestion`. Both are required:
- the **panel URL** is where the list comes from;
- the **node addresses** are the fallback when the panel's name does not answer. Nodes added later are
  learned from the panel by themselves.

Offer the known clusters, plus "Other" for a new one. Several apps may use different clusters: ask per app
when it matters.

<!-- Put your own clusters in this table when you install the skill. -->

| Option | Panel | Nodes |
|---|---|---|
| prod | `https://panel.example.com` | `203.0.113.10, 203.0.113.20, 203.0.113.30` |
| staging | `https://panel.staging.example.com` | `198.51.100.10, 198.51.100.20, 198.51.100.30` |

These lists can be outdated. When the network allows, check that the panel serves the API:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer x' https://<panel>/api/guard/ips
```

- **401:** OK (the key is wrong on purpose).
- **404:** the edge on the nodes is too old. Tell the user that the edge must be updated first.

### 2 · Ask: the key of each app (mandatory) and where it is kept

The key is the **origin-auth secret of the site** that proxies to this service. In the panel: Sites → the
site → "Backend protection" → "Sign requests to the backend with a secret header" → "Current secret" (24+
characters, "Copy"). Each app is one site, so each has its own key. A TCP app may use any key of its
cluster: it only needs the list.

Ask with `AskUserQuestion`:
1. **Is backend protection already on and saved for each site?** If not, the user turns it on and saves
   the site **before** the guard starts. Otherwise:
   - the panel answers 401 to the key;
   - the edge does not send the header, so every request gets 403.
2. **Where are keys kept in this project?** Options: an env file (`/etc/edge-guard/env`, mode 600, read by
   systemd), a key file (`key_file`, `root:edge-guard` 640), a Docker `--env-file` or secret, a Kubernetes
   Secret, or the project's secret manager.

Rules:
- Never put a key in code, in a command line, in a config committed to git, or in chat output.
- Do not ask the user to paste a secret into the chat. Write placeholders (`SHOP_KEY=<origin-auth secret of
  site shop>`) and say where the real value goes.
- **Rotation:**
  1. In the panel: "Prepare a new secret".
  2. Put it in `next_key_env` / `next_key_file`: both keys are accepted.
  3. In the panel: "Switch to the new one".
  4. Move it to the main key and remove the next one. A key file change is picked up without a restart;
     an environment change needs `systemctl restart edge-guard`.

### 3 · Ask: how to run it, and the apps

Recommend from the project:
- **A config file**: several services or sites on one server, or likely to grow. Recommended for servers.
- **Flags**: one service, quick start.
- **Go library**: the service is Go and owns its `http.Handler` / `net.Listener`. No extra process.

For each app, ask what the code does not show:
- the **name**;
- the **cluster**;
- the **port the edge connects to**: the site's pool server is `<server>:<port>`;
- **`hosts`**, when several sites share a port;
- the **service address**: `to: http://127.0.0.1:3000`, `https://…` (with `insecure` for a self-signed
  backend), or `tcp://…`;
- `protocol: h2` for gRPC;
- **TLS towards the edge** (`tls: {cert, key}`): the pool server is then `https://`;
- **extra always-allowed sources** (`allow`, e.g. monitoring addresses; they need no header).

### 4 · Generate

**Install** (Linux, systemd). This installs the binary, the `edge-guard` user, `/etc/edge-guard` with an
example config and the unit:

```sh
curl -fsSL https://raw.githubusercontent.com/axgrid/edge-guard/main/install.sh | sudo sh
```

Other sources:
- Releases: `edge-guard-<os>-<arch>` with `SHA256SUMS`.
- `go install github.com/axgrid/edge-guard/cmd/edge-guard@latest`.
- The image `ghcr.io/axgrid/edge-guard`.
- The panel: `https://<panel>/download/edge-guard-linux-amd64`.

If the GitHub repo is not public yet, build from the checkout:
```sh
cd <checkout> && make dist   # dist/edge-guard-*
```

**Config** `/etc/edge-guard/config.yaml` (mode 640, group `edge-guard`). Write only the fields needed:

```yaml
state_dir: /var/lib/edge-guard
status: 127.0.0.1:9102
clusters:
  prod:
    panel: https://panel.example.com
    nodes: [203.0.113.10, 203.0.113.20, 203.0.113.30]
apps:
  - name: shop
    cluster: prod
    listen: ":8080"
    hosts: [shop.example.com]        # only when apps share the port
    to: http://127.0.0.1:3000
    key_env: SHOP_KEY                # /etc/edge-guard/env: SHOP_KEY=<origin-auth secret>
  - name: db
    cluster: prod
    listen: ":5432"
    to: tcp://127.0.0.1:5433
    key_env: SHOP_KEY
```

Config rules:
- **Unknown fields are errors.**
- **Keys:** exactly one of `key_env`, `key_file`, `key`.
- **Shared ports:** each app on a shared HTTP port lists its `hosts` (exact names or `*.example.com`); one
  app per port may have none (the default).
- **TCP apps** need their own port, with no `hosts` and no `tls`.
- **TLS:** apps on one port use the same `tls` files.

Always validate what you wrote:

```sh
edge-guard -check -config /etc/edge-guard/config.yaml          # syntax, fields, keys present
edge-guard -check -online -config /etc/edge-guard/config.yaml  # + fetch each list (site name, IPs)
```

**Reload:**
- How: saving the file is enough (it is checked every 2 s), or `systemctl reload edge-guard`.
- **A broken file does not stop anything.** The log says `config NOT applied, the previous one keeps
  running` with the line and the reason. The status shows `config.error`.
- **Ports that stay are not reopened.**
- **All or nothing.** A reload that cannot be applied changes nothing: a busy port, or no list from the
  panel and no cache.

**systemd:**
- The unit is `deploy/edge-guard.service` (installed by `install.sh`): user `edge-guard`,
  `EnvironmentFile=-/etc/edge-guard/env`, `StateDirectory=edge-guard`, `ExecReload` = HUP,
  `CAP_NET_BIND_SERVICE` for ports below 1024.
- Start it: `systemctl enable --now edge-guard`.

**Docker:**

```sh
docker run -d --name edge-guard --network host --restart unless-stopped \
  -v /etc/edge-guard:/etc/edge-guard:ro -v edge-guard:/var/lib/edge-guard \
  --env-file /etc/edge-guard/env ghcr.io/axgrid/edge-guard
```

- Prefer `--network host`. With published ports, rootless Docker, Docker Desktop and userland-proxy setups
  show the bridge gateway as the source, and then every request is refused.
- In compose with published ports, check `log_level: debug`: refused lines show `remote=`, and it must be
  the node's address.
- The service then listens only inside the compose network, with no published port of its own.

**Flags** (one app):

```sh
EDGE_GUARD_KEY=… edge-guard -panel https://panel.example.com \
  -nodes 203.0.113.10,203.0.113.20,203.0.113.30 \
  -listen :8080 -to http://127.0.0.1:3000
```

Other flags: `-key-file`, `-allow`, `-tls-cert`/`-tls-key`, `-protocol h2`, `-status`, `-debug`.

**Go library:**

```go
import guard "github.com/axgrid/edge-guard"

g, err := guard.New(ctx, guard.Config{
	Panel:     "https://panel.example.com",
	Nodes:     []string{"203.0.113.10", "203.0.113.20", "203.0.113.30"},
	Key:       os.Getenv("EDGE_GUARD_KEY"),
	NextKey:   os.Getenv("EDGE_GUARD_NEXT_KEY"),
	CacheFile: "/var/lib/<app>/edge-guard.json",
	Allow:     []string{"127.0.0.1"},
	Log:       logger,
})
if err != nil { return err } // no panel and no cache: refuse to start open
srv := &http.Server{Addr: ":8080", Handler: g.Handler(mux)} // 403 Forbidden to others, header removed
```

- **TCP:** `ln = g.Listener(ln)`.
- **The visitor's address:** `g.ClientIP(r)`.
- **Health:** `g.Status()` returns `site`, `ips`, `fetched_at`, `denied`, `last_error`.
- **Module not fetchable** (repo private or not published; `go list -m github.com/axgrid/edge-guard@latest`
  fails): copy `guard.go` (stdlib only; keep the license header) into the project as
  `internal/edgeguard/guard.go`, rename the package to `edgeguard`, and note the source commit in a comment.
  Never add a `replace` that points outside the project.

**Health checks from other sources** (a load balancer or monitoring) go through `allow` with their exact
addresses, or to a separate port. Never exempt URL paths from the guard.

### 5 · Verify

Tell the user these commands, and run them if you have access:

1. `edge-guard -check -online -config …` shows each app's site name and node IPs.
2. The status at `curl -s 127.0.0.1:9102`:
   - `config.error` is empty;
   - each app has `ips` and no `last_error`.
3. From a machine that is not a node, `curl -i http://<server>:<port>/` returns `403 Forbidden`.
4. Through the edge, `curl -i https://<site host>/` returns the service's answer.
5. In the panel:
   - the site's pool server is `<server>:<port>`;
   - its health dots are green (checks come from the nodes with the header).
6. The service listens only on `127.0.0.1` (or only inside the compose network), so the guard cannot be
   bypassed on another port.

## Troubleshooting

- **Everything gets 403 right after the start.** Check:
  - the key: the log shows a panel 401;
  - backend protection is saved for the site, so the edge sends the header;
  - `log_level: debug`: refused lines show `remote=`. A gateway address there is the Docker issue above.
- **A panel 404.** The edge is older than `/api/guard/ips`: update the edge on the nodes.
- **Behind an edge tunnel (`tunnel://name`)** you don't need the guard: the server has no open port.
