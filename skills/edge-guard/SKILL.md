---
name: edge-guard
description: Use this skill when the user wants a service (any language) to accept traffic only from the nodes of their edge cluster (a self-hosted Cloudflare-like proxy with a panel) and answer 403 Forbidden to everyone else — by installing and configuring the standalone edge-guard (github.com/AxGrid/edge-guard; Linux/macOS binaries, systemd, Docker; a YAML config with several clusters, apps, hosts and explicit IP binding, reloaded without a restart) next to the service, or by embedding the Go library github.com/axgrid/edge-guard. The allow-list comes from the edge panel API by a key (the site's origin-auth secret) and follows the cluster. Triggers on phrases like "edge-guard", "пускать только с нод edge", "белый список нод", "закрыть бэкенд от прямого доступа", "только через наш прокси", "403 если не с edge", "allow only edge nodes", "origin allowlist", "protect origin behind edge", "встрой edge-guard", "подключи guard", "поставь edge-guard", "чтобы бэкенд не был доступен напрямую", "конфиг edge-guard", "добавь приложение в edge-guard".
---

# edge-guard

[edge-guard](https://github.com/AxGrid/edge-guard) (Apache-2.0) lets in only the **edge nodes** and answers
**403 Forbidden** to everyone else.

**Where the node list comes from and how it stays fresh:**
- The panel serves it: `GET /api/guard/ips` with `Authorization: Bearer <key>`.
- The guard refreshes it every minute.
- It is kept on disk, so a restart works without the panel.
- A failed refresh never empties it.
- When the panel's name does not answer, the guard asks the nodes by IP with the panel's TLS name.

**What is checked:**
- **HTTP:** the source address, and the site's origin-auth header (`X-Edge-Auth` or the site's own name)
  carrying the same key. Another site on the same edge comes from the same addresses but does not know this
  secret.
- **TCP:** the address only.

**Ways to use it:**
- **Standalone program** next to a service in any language. One app from flags, or a YAML config with
  several clusters, apps and hosts (`Host` routing on a shared port). It is reloaded on file change or
  SIGHUP without a restart. A broken config is reported with its line, and the running config stays.
- **Go library:** `import guard "github.com/axgrid/edge-guard"`. It uses only the standard library.

**The hop edge → guard is encrypted with cluster TLS** (`tls: cluster`, the default to offer):
- **What it is:** mutual TLS 1.3 under the edge cluster's own CA.
- **The guard's certificate:** the guard makes its own key and gets a certificate for its site from the panel
  by the key. It renews it by itself after 2/3 of its 30 days, or at once after a CA rotation.
- **Who can connect:** only edge nodes, which show a node client certificate. The nodes accept only the
  guard of exactly this site.
- **What it protects against:** a man in the middle can neither read nor impersonate either side.

Plain HTTP on that hop is only for a private network or a VPN.

**It listens only on the IP addresses that are named.** `:8080`, `0.0.0.0` and `[::]` are refused unless
`bind_any: true`. This matters: the servers usually have many addresses.

When something is not covered here, read the repo's `README.md` and `examples/config.yaml`:
`https://raw.githubusercontent.com/AxGrid/edge-guard/main/README.md`.

## Workflow

Do the steps in order. Skip a question that is already answered, but **never skip steps 1, 2 and 3**. Ask
with `AskUserQuestion`.

### 0 · Look around (no questions)

- **Where the service runs:** this machine, or a server reached over SSH (then run the commands there).
- **The OS and CPU:** `uname -sm`. Releases exist for Linux and macOS, amd64 and arm64.
- **Is edge-guard already installed?**
  - The version: `edge-guard -version`.
  - A config: `/etc/edge-guard/config.yaml`.
  - The service state: `systemctl status edge-guard`.

  If a config exists, **add** an app to it rather than writing a new one.
- **How the service runs and listens:**
  - in the project: the port and the bind address;
  - on the server: `ss -tlnp`.
- **The server's addresses** (needed in step 3):
  - Linux: `ip -o addr show scope global`;
  - macOS: `ifconfig | grep 'inet '`.

### 1 · Ask: the cluster — panel URL and node addresses (mandatory)

Both are required:
- the **panel URL** is where the list comes from;
- the **node addresses** are the fallback when the panel's name does not resolve. Nodes added later are
  learned by themselves.

Offer the clusters from the table, plus "Other". Several apps may use different clusters: ask per app when
it matters.

<!-- Put your own clusters in this table when you install the skill. -->

| Option | Panel | Nodes |
|---|---|---|
| prod | `https://panel.example.com` | `203.0.113.10, 203.0.113.20, 203.0.113.30` |

**Check that the panel serves the API**, from the server where the guard will run:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer x' https://<panel>/api/guard/ips
```

- **401:** good (the key is wrong on purpose).
- **404:** the edge on the nodes is too old. Stop, and tell the user that the edge must be updated first.
- **No answer:** try a node by IP:
  `curl -sk --resolve <panel host>:443:<node IP> https://<panel host>/api/guard/ips -o /dev/null -w '%{http_code}'`.

### 2 · Ask: guard mode or a site key (mandatory), and the key

**Recommend guard mode.** The server first, domains later, all by wizards in the panel:
1. Panel → **Guards → «Добавить guard»**: a name gives the key `edgg.<guard>.…`, shown once, and a ready
   setup.
2. In the config, the **cluster** gets `guard_key_env: EDGE_GUARD_KEY`. The key goes into
   `/etc/edge-guard/env`, and the apps need no keys.
3. The guard registers itself and reports its apps.
4. The user binds domains in the panel: guard page → app → **«Привязать домен»**. This creates the site,
   with which nodes serve it, Let's Encrypt and the DNS record, and the pool server
   `guard://<guard>/<app>`.

What changes in guard mode:
- **TLS:** cluster TLS is implied, so no `tls:` is needed.
- **Trust:** nodes are trusted by their client certificate, so no origin-auth header.
- **Shared ports:** apps may share one IP:port without `hosts`, because the node names the app.
- **`hosts`:** only suggestions for the wizard.
- **Behind NAT:** `public: <ip:port>` per app reports the address the nodes reach.

Guard mode needs edge-guard **v0.3.0 or later** (`edge-guard -version`) and an edge that serves
`POST /api/guard/register`. `-check -online` already registers the apps, so the guard shows up in the
panel before the service is started.

**What the panel accepts in a guard's report** (otherwise the report is refused and the guard keeps the
previous one; the error is in the guard's log):
- **No local-only addresses.** `listen` (or `public`) must be an address the nodes can reach. Loopback
  (`127.0.0.1`, `::1`), link-local (`169.254.x`, `fe80::`) and multicast are refused. To try a guard on
  one machine with the panel, use the machine's LAN or public IP, not 127.0.0.1.
- **A staff user's guard** may report only addresses inside the networks that user may use for upstream
  servers (Settings → staff networks, or the user's own list), the same as servers they type into a pool.
  An admin's guard may report any reachable address.
- **At most 64 apps per guard.**
- **At most 20 changes of the apps or addresses in 10 minutes.** Every change rewrites the cluster's config.
  Do not script frequent config edits; an unchanged report costs nothing.
- **No flood of requests:** at most 120 requests a minute from one source address to `/api/guard/*`. A
  normal guard makes one a minute per cluster.

Ask whether a guard already exists in the panel. If not, the user creates one on the Guards page; Claude
cannot create it, because creating it needs a panel login. Then go to step 3.

**A site key** (only when the site already exists and the user prefers it): the rest of this step.

#### The key of each app (site-key mode) and where it is kept

The key is the **origin-auth secret of the site** that proxies to this service. In the panel: Sites → the
site → "Backend protection" → "Sign requests to the backend with a secret header" → "Current secret" (24+
characters, "Copy"). Each app is one site, so each has its own key. A TCP app may use any key of its
cluster: it only needs the list.

Ask:
1. **Is backend protection on and saved for the site?** If not, the user turns it on and saves it **before**
   the guard starts. Otherwise:
   - the panel answers 401 to the key;
   - the edge does not send the header, so every request gets 403.
2. **Where are keys kept?** Options:
   - `/etc/edge-guard/env` (mode 600, read by systemd; recommended);
   - a key file (`key_file`, `root:edge-guard`, mode 640);
   - a Docker `--env-file` or secret;
   - a Kubernetes Secret;
   - the project's secret manager.

Rules:
- Never put a key in code, in a command line, in a config committed to git, or in chat output.
- Do not ask the user to paste a secret into the chat. Write placeholders (`SHOP_KEY=<origin-auth secret of
  site shop>`) and tell them which file to put the value in.
- If the user pastes one anyway, write it only into the env file, and do not repeat it.

### 3 · Ask: which IP of the server to listen on (mandatory)

The guard takes **only the IPs it is told**. Show the addresses from step 0 and ask:
- **Which address does the edge connect to?** It is the address the site's pool server in the panel points
  at. Several can be chosen (a list). Usually it is the public IPv4 that the user gave this service.
  Private addresses (10.x, 192.168.x) fit only when the edge reaches the server through a VPN.
- **The port:**
  - The default suggestion is `8443` with cluster TLS, or `8080` for plain HTTP.
  - Check it is free on that IP: `ss -tlnH 'sport = :<port>'`.
  - The same port can be reused on another IP of the same server.

Rules:
- Never write `:8080`, `0.0.0.0:…` or `[::]:…`. Use `bind_any: true` only when the user explicitly wants
  every address, and then warn that other addresses of the server will take the port too.
- The address must exist on the server, or the guard will not start: `edge-guard -check` warns about this.

### 4 · Ask: how to run it, and the apps

**Recommend a mode from the project:**
- **A config file:** a server, several services or sites, or likely to grow. Recommended.
- **Flags:** one service, quick start.
- **Go library:** the service is Go and owns its `http.Handler` / `net.Listener`. No extra process.

**TLS towards the edge.** Recommend **cluster TLS** (`tls: cluster`). Plain HTTP fits only when the edge
reaches the server over a private network or a VPN; say that the hop is then unencrypted. Cluster TLS needs:
- the panel to offer it: `edge-guard -check -online` prints `cluster TLS: available`;
- an HTTP app (TCP apps cannot use it yet).

**For each app, ask what the code does not show:**
- the **name**;
- the **cluster**;
- **`hosts`**, when several sites share an IP:port;
- the **service address**:
  - `to: http://127.0.0.1:<port>`;
  - `https://…`, with `insecure: true` for a self-signed backend;
  - `tcp://…`;
  - `protocol: h2` for gRPC;
- **own certificate files instead of the cluster CA** (`tls: {cert, key}`), only if the user asks: then
  the pool verifies them itself (a public CA, or `tls_ca_file` on every node);
- **always-allowed sources** (`allow: [monitoring IPs]`; they need no header).

### 5 · Install

**Linux with systemd** (amd64, arm64). The installer puts in:
- the binary, after checking `SHA256SUMS`;
- the `edge-guard` user;
- `/etc/edge-guard` with an example config and an empty `env` file (mode 600);
- the unit.

It does not start the service.

```sh
curl -fsSL https://raw.githubusercontent.com/AxGrid/edge-guard/main/install.sh | sudo sh
# a fixed version: curl … | sudo VERSION=v0.1.0 sh
```

**macOS, or Linux by hand:**

```sh
OS=$(uname -s | tr A-Z a-z); ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
BASE=https://github.com/AxGrid/edge-guard/releases/latest/download
curl -fsSLO "$BASE/edge-guard-$OS-$ARCH" && curl -fsSLO "$BASE/SHA256SUMS"
grep " edge-guard-$OS-$ARCH\$" SHA256SUMS | shasum -a 256 -c -
sudo install -m 755 "edge-guard-$OS-$ARCH" /usr/local/bin/edge-guard
edge-guard -version
```

On macOS, if the downloaded binary is blocked: `xattr -d com.apple.quarantine /usr/local/bin/edge-guard`.

**Other sources:**
- Go: `go install github.com/axgrid/edge-guard/cmd/edge-guard@latest`.
- Docker: `ghcr.io/axgrid/edge-guard`.
- Some panels also serve builds at `https://<panel>/download/edge-guard-linux-amd64`.

### 6 · Configure

**Config** `/etc/edge-guard/config.yaml` (owner `root:edge-guard`, mode 640). Write only the fields
needed. When the file exists, add to `clusters` and `apps` and keep the rest.

Guard mode (recommended):

```yaml
state_dir: /var/lib/edge-guard
status: 127.0.0.1:9102
clusters:
  prod:
    panel: https://panel.example.com
    nodes: [203.0.113.10, 203.0.113.20, 203.0.113.30]
    guard_key_env: EDGE_GUARD_KEY      # /etc/edge-guard/env: EDGE_GUARD_KEY=edgg.<guard>.…
apps:
  - name: shop
    cluster: prod
    listen: 198.51.100.5:8443          # the IP from step 3
    hosts: [shop.example.com]          # suggestions for «Привязать домен»
    to: http://127.0.0.1:3000
  - name: api
    cluster: prod
    listen: 198.51.100.5:8443          # same address: the node names the app
    to: http://127.0.0.1:9000
```

Then tell the user to bind domains in the panel: Guards → the guard → app → «Привязать домен».

Site-key mode:

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
    listen: 198.51.100.5:8443          # the IP from step 3 (a list for several)
    tls: cluster                       # mutual TLS with the edge (recommended)
    hosts: [shop.example.com]          # only when apps share an IP:port
    to: http://127.0.0.1:3000
    key_env: SHOP_KEY                  # /etc/edge-guard/env: SHOP_KEY=<origin-auth secret>
  - name: db
    cluster: prod
    listen: 198.51.100.5:5432
    to: tcp://127.0.0.1:5433
    key_env: SHOP_KEY
```

**Config rules:**
- Unknown fields are errors.
- **Keys:** exactly one of `key_env`, `key_file`, `key`.
- **Shared addresses:** each app on a shared HTTP IP:port lists its `hosts` (exact names or
  `*.example.com`); one app per address may have none (the default).
- **TCP apps** need their own IP:port, with no `hosts` and no `tls`.
- **TLS:** apps on one IP:port use the same `tls`: all `cluster` (several sites can share it, chosen by SNI
  `<site>.edge-guard`), or the same files.
- **Cluster TLS files:** the guard keeps its key and certificate in `state_dir`
  (`cluster-tls-*.key` mode 600, `.crt`). Never copy them to another server: a new guard gets its own.
- `0.0.0.0:8085` with `bind_any` and `198.51.100.5:8085` together overlap, and are refused.

**Validate, and fix until clean:**

```sh
# the keys come from the env file into the environment, never into the command line
sudo sh -c 'set -a; . /etc/edge-guard/env; exec runuser -u edge-guard -- edge-guard -check -config /etc/edge-guard/config.yaml'
sudo sh -c 'set -a; . /etc/edge-guard/env; exec runuser -u edge-guard -- edge-guard -check -online -config /etc/edge-guard/config.yaml'
```

- `-check` checks the syntax, the fields, that the keys are present, and that the IPs are on the machine
  (a warning).
- `-online` also fetches each app's list and prints the site name and node IPs.
- Running it as `edge-guard` also proves that the user can read the key files.

**The service itself** must listen only on `127.0.0.1`, or only inside the compose network, so nobody
reaches it around the guard. Change its bind if needed, and tell the user.

**Start:** `sudo systemctl enable --now edge-guard`, then `journalctl -u edge-guard -n 20`. Expect:
- `guard: cluster TLS certificate name=<site>.edge-guard`;
- `listening addr=198.51.100.5:8443 tls=true`;
- `edge-guard started`.

**Changes later:**
- Saving the config is enough: it is checked every 2 s. `systemctl reload edge-guard` works too.
- **A broken file does not stop anything.** The log says `config NOT applied, the previous one keeps
  running` with the line. The status shows `config.error`.
- **All or nothing.** A reload that cannot be applied changes nothing: a busy port, an IP that is not on the
  server, or no list and no cache.
- **Key changes:** a key-file change is picked up by itself; an env-file change needs
  `systemctl restart edge-guard`.
- **Rotation:**
  1. In the panel: "Prepare a new secret".
  2. Put it in `next_key_env` or `next_key_file`: both keys are accepted.
  3. In the panel: "Switch to the new one".
  4. Make it the main key and remove the next one.

**Docker** (instead of systemd):

```sh
docker run -d --name edge-guard --network host --restart unless-stopped \
  -v /etc/edge-guard:/etc/edge-guard:ro -v edge-guard:/var/lib/edge-guard \
  --env-file /etc/edge-guard/env ghcr.io/axgrid/edge-guard
```

- Use `--network host`: the guard binds the server's IP itself, and sees the real source address.
- With published ports, rootless Docker, Docker Desktop and userland-proxy setups show the bridge gateway
  as the source, and then every request is refused.

**Flags** (one app):

```sh
EDGE_GUARD_KEY=… edge-guard -panel https://panel.example.com -nodes 203.0.113.10,203.0.113.20 \
  -tls cluster -listen 198.51.100.5:8443 -to http://127.0.0.1:3000 -state-dir /var/lib/edge-guard
```

Other flags: `-key-file`, `-allow`, `-tls-cert`/`-tls-key`, `-protocol h2`, `-status`, `-debug`.

**Go library:**

```go
import guard "github.com/axgrid/edge-guard"

g, err := guard.New(ctx, guard.Config{
	Panel:     "https://panel.example.com",
	Nodes:     []string{"203.0.113.10", "203.0.113.20"},
	Key:       os.Getenv("EDGE_GUARD_KEY"),
	NextKey:   os.Getenv("EDGE_GUARD_NEXT_KEY"),
	CacheFile: "/var/lib/<app>/edge-guard.json",
	Allow:     []string{"127.0.0.1"},
	Log:       logger,
})
if err != nil { return err } // no panel and no cache: refuse to start open
srv := &http.Server{Addr: "198.51.100.5:8080", Handler: g.Handler(mux)} // the IP from step 3
```

**Go library with cluster TLS:** add `ClusterTLS: true` to the config, then serve TLS with the guard's
config:

```go
ln, _ := tls.Listen("tcp", "198.51.100.5:8443", g.ServerTLS()) // add NextProtos for HTTP/2
http.Serve(ln, g.Handler(mux))
```

- **TCP:** `ln = g.Listener(ln)`.
- **The visitor's address:** `g.ClientIP(r)`.
- **Health:** `g.Status()` returns `site`, `ips`, `fetched_at`, `denied`, `last_error`.
- **Bind address in code:** put it in the app's own config with the same rule (an explicit IP), not
  `":8080"`.
- **Module not fetchable** (`go list -m github.com/axgrid/edge-guard@latest` fails, for example behind an
  offline proxy): copy `guard.go` from the repo (stdlib only; keep the license header) into the project as
  `internal/edgeguard/guard.go`, rename the package to `edgeguard`, and note the source commit. Never add a
  `replace` that points outside the project.

**Health checks from other sources** (a load balancer or monitoring) go through `allow` with their exact
addresses, or to a separate IP:port. Never exempt URL paths.

### 7 · Panel and verification

Tell the user what to do in the panel, and run the checks you can:

1. **In the panel:**
   - With cluster TLS:
     - the site's pool server is exactly `https://<IP from step 3>:<port>`;
     - the pool's «TLS к edge-guard через CA кластера» is on (section «Протокол, проверки здоровья…»).

     The «Защита бэкенда» snippet has a «Настроить пул» button that does both.
   - Plain HTTP: the pool server is `http://<IP>:<port>`.

   Save. The health dots for that server turn green: checks come from the nodes with the header and, with
   cluster TLS, with their client certificate.
2. **The status:** `curl -s 127.0.0.1:9102`.
   - `config.error` is empty;
   - every app has `ips` and no `last_error`.
3. **From a machine that is not a node:**
   - cluster TLS: `curl -vk https://<IP>:<port>/` fails in the TLS handshake (no client certificate);
   - plain HTTP: `curl -i http://<IP>:<port>/` returns `403 Forbidden`.

   The status shows `tls.not_after` and `tls.issuer`.
4. **Through the edge:** `curl -i https://<site host>/` returns the service's answer.
5. **Nothing else listens on that port on other addresses:** `ss -tlnp | grep :<port>` shows only the
   chosen IPs.

## Troubleshooting

- **The service does not start, "cannot assign requested address".** The IP in `listen` is not on this
  server. Compare with `ip -o addr show`.
- **Everything gets 403 right after the start.** Check:
  - the key: the log shows a panel 401;
  - backend protection is saved for the site, so the edge sends the header;
  - `log_level: debug`: refused lines show `remote=`. A gateway address there is the Docker issue above.
- **A panel 404.** The edge is older than `/api/guard/ips` (or `/api/guard/cert`): update the edge on the
  nodes.
- **Cluster TLS: 502 at the edge, or `bad certificate` in the guard log.** Check:
  - the pool has `cluster_tls` on and its server is `https://IP:port`;
  - the guard runs with `tls: cluster`;
  - the guard's status: `tls.last_error`, `tls.not_after`.

  After a CA rotation the guard renews within a minute, and the old CA stays trusted 37 days.
- **A busy port.** Another program holds that IP:port, or something listens on `0.0.0.0:<port>`. Choose
  another port, or ask the user.
- **Guard mode, "not reachable from the nodes (loopback, link-local or multicast)".** The app's `listen`
  is 127.0.0.1 or similar. Use the server's real IP, or set `public: <ip:port>` to the address the nodes
  reach.
- **Guard mode, "the guard's owner may not use this address".** The guard belongs to a staff user, and the
  address is outside that user's allowed networks. An admin either widens the user's networks, or takes
  over the guard (Guards → the guard → access → owner).
- **Guard mode, "the guard's apps change too often" (HTTP 429).** More than 20 changes in 10 minutes. Wait,
  and stop whatever rewrites the config in a loop.
- **"too many requests" (HTTP 429)** on `/api/guard/*`: more than 120 a minute from this address, for
  example many guards behind one NAT address restarting at once. It clears within a minute.
- **Behind an edge tunnel (`tunnel://name`)** you don't need the guard: the server has no open port.
