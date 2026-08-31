# Guide: Replicate Caddy metrics locally (monitor running in Docker)

This guide configures a **local Caddy** instance so the **server-monitor container**
can scrape real `caddy_http_*` metrics and store them in the `caddy_metrics` table.

It follows the general approach recommended by the production sysadmin (a
dedicated metrics-only listener, keeping the config/admin API safe), adapted to
work reliably on a local laptop with the monitor running in Docker.

---

## What we are building

| Piece | Local value | Why |
|---|---|---|
| Caddy | v2.11.x, systemd `caddy.service` | Already installed and running |
| Metrics enabled | global `metrics` option | Required to expose `caddy_http_*` families |
| Metrics-only listener | `192.168.1.17:2020` with `bind` + `metrics` handler | Scoped to the host's LAN interface (not `0.0.0.0`), plain HTTP, dedicated metrics port that *serves* the metrics |
| Monitor `metrics_url` | `http://192.168.1.17:2020/metrics` | Container reaches the host's LAN IP directly (verifiable, no gateway quirk) |
| Admin API | stays on `127.0.0.1:2019` | Keep the config API loopback-only (security) |

The monitor's scraper needs these three Prometheus families (see
`collectors/caddy_scraper.py:20-22`):

- `caddy_http_requests_total`
- `caddy_http_request_duration_seconds`
- `caddy_http_requests_in_flight`

Without the `metrics` option, `/metrics` only serves Go/process metrics and
`caddy_metrics` stays empty — exactly the situation on the production edge proxy.

---

## Why scope to the LAN IP + `bind`, and why plain HTTP (important background)

Several things silently break a naive setup on a laptop:

1. **The compose bridge gateway IP is not a stable host address.**
   The monitor's compose bridge (`server-monitor_monitor-net`) uses `172.18.0.1`
   as its gateway, but that IP is **not** a bound interface on the host
   (especially with Docker Desktop / Daemon-in-VM setups). Binding Caddy to
   `172.18.0.1:2020` and curling `http://172.18.0.1:2020` gave a **timeout**
   routed out over Wi-Fi. Reach the host through its **real LAN IP** (e.g.
   `192.168.1.17` on `wlo1`) instead.

2. **Caddy auto-HTTPS turns a custom-port listener into TLS.**
   A plain site block on a non-80/443 port makes Caddy serve **HTTPS** there, so
   a plain-`http://` scrape gets `400 Bad Request: Client sent an HTTP request to
   an HTTPS server`. You must force **plain HTTP** with an `http://` prefix.

3. **An IP site address is a Host-header match, not a bind — unless you `bind`.**
   Writing `192.168.1.17:2020` makes Caddy answer only requests with
   `Host: 192.168.1.17` and still listens on all interfaces. Adding
   `bind 192.168.1.17` scopes the actual socket to that interface while matching
   any Host on the port. This is the secure way to expose metrics on one address
   without opening `0.0.0.0`.

4. **The global `metrics` option exposes, but doesn't serve.**
   A `metrics` site-block **handler** is what actually serves `/metrics` on your
   port; without it the site returns an empty `200` (see Step 2b).

The robust fix used in this guide: a plain-HTTP metrics site on the host's LAN IP,
scoped with `bind` and the `metrics` handler, and the monitor points directly at
that LAN IP — verifiable from inside the container with plain `curl`.

---

## Prerequisites

```bash
# 1. Caddy installed and running
caddy version
systemctl status caddy --no-pager | head -5

# 2. Docker stack up
cd "your/server-monitor/working/dir"
docker compose ps
```

> `sudo` is required for every Caddy step (it runs as root and `/etc/caddy` is
> root-owned). Run `sudo -v` once to cache credentials.

---

## Step 1 — Back up the current Caddyfile

```bash
sudo cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak
cat /etc/caddy/Caddyfile
```

On a fresh install this is the default template (static site on `:80`). You will
keep that site and add metrics around it.

---

## Step 2 — Edit `/etc/caddy/Caddyfile`

Open with sudo:

```bash
sudo nano /etc/caddy/Caddyfile
```

### 2a. Add the global options block at the VERY TOP

A global block must be the **first** thing in the file (before any site block).
Prepend it above the existing `:80 { ... }` site:

```caddy
{
	metrics
}

:80 {
	root * /usr/share/caddy
	file_server
}
```

> On Caddy v2.11 **you must use the top-level `metrics` option** as shown. The
> nested `servers { metrics }` form is **deprecated** in v2.11 and can produce an
> **empty** `/metrics` body (200 OK with no `caddy_http_*` families) instead of
> the metrics you need — see Troubleshooting. Always use the flat `metrics` form.

### 2b. Add a metrics-only listener at the END of the file

Append this at the bottom. It has four parts — get each right:

1. An **IP address** as the host (here the host's Wi‑Fi/LAN IP `192.168.1.17`)
   **plus** the `bind` directive. The `bind` directive tells Caddy *which socket
   interface(s)* to listen on, keeping it scoped to that one LAN address instead
   of `0.0.0.0` (all interfaces). Without `bind`, writing an IP site address
   makes Caddy match **only** the matching Host header (see note below).
2. The **`http://` scheme** disables auto-HTTPS so it serves **plain HTTP**
   (fixes the `400 ... HTTPS server` error).
3. The **`metrics` handler** inside the block actually *serves* the Prometheus
   metrics on this site.

```caddy
http://192.168.1.17:2020 {
	bind 192.168.1.17
	metrics
}
```

> **Why the IP + `bind` combo:** Caddy treats a bare IP in a site address as a
> **Host-header match**, not a socket bind — so `192.168.1.17:2020` alone only
> answers requests whose `Host:` is `192.168.1.17` and still listens on all
> interfaces. Adding `bind 192.168.1.17` makes it an **IP‑snipped socket** bound
> only to that interface, while remaining a catch-all for any Host on that port.
> Use your machine's real LAN IP (find it with `ip -brief addr` → the
> `192.168.1.x` on your Wi‑Fi/`wlo1` interface).

> **Two distinct things (easy to confuse):**
> - The **global `metrics` option** (Step 2a) *enables* HTTP metric collection.
>   By itself it only exposes them at the admin API's `/metrics` (`:2019`) —
>   which is loopback-only and unreachable from the container.
> - The **`metrics` handler** *serves/exposes* those collected metrics at the
>   `/metrics` path of the site that contains it. Without this handler the site
>   is **empty** and returns `200` with **0 bytes** — no `caddy_http_*` at all.
>
> You need **both**: the global option to enable, and the handler to expose.

Your file should now look like (swap in your own LAN IP):

```caddy
{
	metrics
}

:80 {
	root * /usr/share/caddy
	file_server
}

http://192.168.1.17:2020 {
	bind 192.168.1.17
	metrics
}
```

**Why this shape:**
- The `bind` directive scopes the listener to the LAN IP only — it is **not**
  open on all interfaces. (Anyone on the same Wi‑Fi can still reach that LAN IP,
  so this is not "off the network" — it's just not globally bound. For full
  loopback-only security you'd need the proxy approach; see Security below.)
- An **IP site address without `bind`** matches only that Host header and
  returns an empty `200` for the container's real Host. `bind` fixes that.
- `http://` forces plain HTTP (fixes the `400 ... HTTPS server` error).
- Port `2020` is separate from the admin API `:2019`, which stays loopback-only.
- The `metrics` handler serves `caddy_http_*` at `/metrics`, off the admin API.

> **Security (local only):** `bind 192.168.1.17` keeps Caddy off `0.0.0.0` and
> off other interfaces (e.g. tailscale), but the LAN IP is still reachable by
> anything on your Wi‑Fi. Acceptable for a dev laptop on a trusted network. For a
> shared/public network, prefer the loopback-only + reverse-proxy option in
> Troubleshooting, and **never** expose metrics or the admin API in production
> without auth/firewalling.

---

## Step 3 — Validate and reload (no restart, no downtime)

```bash
sudo caddy fmt --overwrite /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

- `fmt` cleans up indentation (silences the "not formatted" warning).
- `validate` checks the config; if it reports an error, fix it before reloading.
- `reload` swaps config gracefully (Caddy's `ExecReload`). **Do not** use
  `restart`, which would drop the existing site listeners momentarily.

**Only proceed to Step 4 after `caddy validate` prints `Valid configuration`.**

---

## Step 4 — Update the monitor to reach the host (repo changes)

Because the Caddy listener is already bound to the host's **LAN IP** (`192.168.1.17`
in this guide), the monitor can point straight at that reachable address — no
name resolution needed. Find your LAN IP with `ip -brief addr` and substitute it.

### 4a. `config.yaml` — set the caddy `metrics_url`

```yaml
collectors:
  caddy:
    instance_id: edge-01
    metrics_url: http://192.168.1.17:2020/metrics
```

### 4b. (Optional) `compose.yaml` — add `extra_hosts` as a fallback

If you'd rather reach the host by name (and the listener were a catch-all) you
could use `host.docker.internal`, but with an IP-scoped bind the direct LAN IP
above is the reliable path. Adding the mapping is harmless if you want the name
available too:

```yaml
  monitor:
    build:
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped
    networks: [monitor-net]
    extra_hosts:
      - "host.docker.internal:host-gateway"
    # ...rest of the service unchanged
```

### 4c. Recreate the monitor so the change takes effect

```bash
docker compose up -d --build monitor
```

---

## Step 5 — Verify the endpoint works

### 5a. From the host (use the bound LAN IP, not `localhost`)

Because the listener is `bind`-scoped to `192.168.1.17`, `curl localhost:2020`
will not connect — you must hit the bound address:

```bash
curl -s -m 8 http://192.168.1.17:2020/metrics | grep -c "^caddy_http"
```

Expected: a number **greater than 0**. You should also see the three families:

```bash
curl -s http://192.168.1.17:2020/metrics | grep -E "^# (HELP|TYPE) caddy_http"
```

### 5b. From inside the monitor's network (exactly what the container sees)

```bash
docker run --rm --network server-monitor_monitor-net \
  curlimages/curl \
  curl -s -m 8 http://192.168.1.17:2020/metrics | grep -c "^caddy_http"
```

This must also return > 0. If it is 0 here, the container cannot scrape the
endpoint (see Troubleshooting).

---

## Step 6 — Generate traffic so the counters are non-zero

The scrape computes rates from **deltas** of `caddy_http_requests_total`. Hit the
default local site a few times so the counters move:

```bash
for i in 1 2 3 4 5; do curl -s -o /dev/null http://localhost/; done
```

---

## Step 7 — Confirm the monitor ingests it

### 7a. Watch the monitor logs live

```bash
docker compose logs -f monitor
```

You should start seeing lines like:

```
[caddy] 2xx=5 4xx=0 5xx=0 rps=0.3 p99=0.0ms error_rate=0.00% conns=0
```

### 7b. Query the live database table

```bash
docker compose exec -T monitor sh -c \
  'uv run --no-sync python -c "
import sqlite3
con = sqlite3.connect(\"/data/monitoring.db\")
print(con.execute(\"SELECT COUNT(*) FROM caddy_metrics\").fetchone()[0], \"rows\")
for r in con.execute(\"SELECT created_at, requests_per_sec, error_rate, p99_latency_ms, active_conns FROM caddy_metrics ORDER BY id DESC LIMIT 5\"):
    print(r)
"'
```

Expected: `caddy_metrics` now has rows (previously `0`).

---

## Step 8 — View it in Beekeeper (with the WAL caveat)

The DB is in **WAL mode**: the newest rows live in `monitoring.db-wal`, not the
`.db` file. `docker cp` of only `monitoring.db` yields an **empty** file.

**Best option — clean SQLite backup into a self-contained file:**

```bash
docker compose exec -T monitor sh -c \
  'uv run --no-sync python -c "
import sqlite3
src = sqlite3.connect(\"/data/monitoring.db\")
dst = sqlite3.connect(\"/tmp/export.db\")
src.backup(dst)
dst.close()
"'
docker cp server-monitor-monitor-1:/tmp/export.db ./exported.db
```

Open `./exported.db` in Beekeeper — it contains all tables and current rows.

> Only the **Docker volume** (`server-monitor_monitor-data`) is the live DB. A
> `monitoring.db` sitting in the repo working directory is a stale leftover and
> will never be updated by the container.

---

## Troubleshooting

### `caddy validate` says "unrecognized global option: servers{"
- The brace is glued to the option: `servers{` instead of `servers {`. Add a
  space: `servers {`. (Or better, use the flat `metrics` form in Step 2a, which
  avoids the deprecated nested syntax entirely.)

### `caddy validate` warns "nested 'metrics' inside servers is deprecated"
- Prefer the top-level `metrics` option (Step 2a) instead of `servers { metrics }`.

### `/metrics` returns `200 OK` but the body is EMPTY (0 lines, no `caddy_http`)
Two possible causes — check both:

1. **Missing the `metrics` handler.** The site has the global `metrics`
   **option** enabled but no `metrics` **handler**, so it serves nothing. The
   global option only *collects* metrics (exposed at the loopback admin API
   `:2019/metrics`); it does **not** serve them on your site's port. An empty
   site `192.168.1.17:2020 { bind 192.168.1.17 }` returns `200` with **0 bytes**.
   Fix: add the handler (Step 2b):
   ```caddy
   http://192.168.1.17:2020 {
   	bind 192.168.1.17
   	metrics
   }
   ```
   (If you instead relied on the deprecated nested `servers { metrics }`, replace
   it with the flat top-level `metrics` option too. You need the global option to
   *enable* collection and the handler to *expose* it — both.)

2. **IP site address matches only that Host header (missing `bind`).** Writing
   `192.168.1.17:2020` without `bind` makes Caddy match **only** requests with
   `Host: 192.168.1.17`; a curl with any other Host falls through to an empty
   `200`. Add `bind 192.168.1.17` so the socket is scoped to that interface while
   matching any Host on the port.

After fixing, `sudo systemctl reload caddy`, then verify (use the bound LAN IP,
**not** `localhost`, since `bind` scopes the socket to that address):
`curl -s http://192.168.1.17:2020/metrics | grep -c "^caddy_http"` should be
**> 0** and emit `caddy_http_requests_total`,
`caddy_http_request_duration_seconds`, `caddy_http_requests_in_flight`.

### `caddy validate` warns "Site block has an unspecified IP address ... you probably want the 'bind' directive"
- You wrote an IP as the site address without a `bind` directive. Caddy then
  matches **only** that Host header and still listens on all interfaces. Add
  `bind <that-ip>` inside the site block to scope the socket to that address and
  match any Host on the port.

### `curl http://<bridge-ip>:2020/metrics` times out
- The compose bridge gateway IP (`172.18.0.1`) is often **not** a real host
  interface on laptops/Docker Desktop; the route escapes over Wi-Fi and times
  out. Don't bind Caddy to that IP. Bind to the host's **real LAN IP**
  (`ip -brief addr`, e.g. `192.168.1.17` on `wlo1`) and point the monitor at it.

### `curl http://localhost:2020/metrics` fails / connection refused (but the LAN IP works)
- The listener is `bind`-scoped to the LAN IP, so it is **not** on `127.0.0.1`.
  Test with the bound address instead: `curl http://192.168.1.17:2020/metrics`.

### `400 Bad Request: Client sent an HTTP request to an HTTPS server`
- Caddy applied auto-HTTPS to the listener. Add the **`http://` prefix** to the
  site address (`http://192.168.1.17:2020`) to force plain HTTP.

### `grep -c "^caddy_http"` returns 0
- The `metrics` option is missing, the `metrics` handler is absent, or the
  listener is serving TLS. Re-check Steps 2a/2b and that validate + reload
  succeeded (Step 3). Confirm the families exist:
  `curl -s http://192.168.1.17:2020/metrics | grep caddy_http`.

### "No route to host" / connection refused from the container
- Confirm the container got the `extra_hosts` mapping (Step 4c) and that Caddy
  is listening: `sudo ss -tlnp | grep 2020`. Ensure the reload happened.

### The `.db` file I copied is empty
- WAL mode: you copied only `monitoring.db`, not the rows in `-wal`. Use the
  clean backup method in Step 8, or copy all three files
  (`monitoring.db`, `monitoring.db-wal`, `monitoring.db-shm`) together.

### Restoring to original state (local only)
```bash
sudo cp /etc/caddy/Caddyfile.bak /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

---

## Summary of what changed

| File | Change |
|---|---|
| `/etc/caddy/Caddyfile` | Added global `metrics` block (top) to *enable* collection + `http://192.168.1.17:2020 { bind 192.168.1.17; metrics }` scoped plain-HTTP listener that *serves* the metrics (end) |
| `compose.yaml` | `extra_hosts: ["host.docker.internal:host-gateway"]` on the monitor service (optional fallback) |
| `config.yaml` | `metrics_url: http://192.168.1.17:2020/metrics` |
| `caddy_metrics` table | Now populates (was 0 rows) |

This reproduces the production idea locally — a dedicated metrics-only listener
on a non-admin port with plain HTTP — while keeping the config/admin API
(`:2019`) loopback-only. The listener is `bind`-scoped to the host's LAN IP so
it is reachable from the monitor container without exposing the socket on `0.0.0.0`
or relying on the volatile compose bridge-IP / `host.docker.internal` gateway.
