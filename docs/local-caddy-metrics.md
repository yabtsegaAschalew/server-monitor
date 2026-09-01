# Guide: Enable Caddy metrics for the monitor container

This guide configures a **local Caddy** instance so the **server-monitor container**
can scrape real `caddy_http_*` metrics and store them in the `caddy_metrics` table.

It follows the general approach recommended by the production sysadmin (a
dedicated metrics-only listener, keeping the config/admin API safe), adapted to
work reliably on a local laptop with the monitor running in Docker.

> **The shipped config uses `host.docker.internal`.** `config.yaml` already points
> at `http://host.docker.internal:2020/metrics` and `compose.yaml` already maps
> `host.docker.internal` to the Docker bridge gateway. This guide explains the
> one host-side change (a metrics listener on Caddy) that makes that work, and why
> a Caddy `bind` directive silently breaks it.

---

## What we are building

| Piece | Local value | Why |
|---|---|---|
| Caddy | v2.11.x, systemd `caddy.service` | Already installed and running |
| Metrics enabled | global `metrics` option | Required to expose `caddy_http_*` families |
| Metrics-only listener | `http://:2020 { metrics }` | Plain-HTTP metrics listener on a dedicated non-admin port |
| Monitor `metrics_url` | `http://host.docker.internal:2020/metrics` | Container reaches the listener through the compose `extra_hosts` mapping |
| Admin API | stays on `127.0.0.1:2019` | Keep the config API loopback-only (security) |

The monitor's scraper needs these three Prometheus families (see
`collectors/caddy_scraper.py`):

- `caddy_http_requests_total`
- `caddy_http_request_duration_seconds`
- `caddy_http_requests_in_flight`

Without the `metrics` option, `/metrics` only serves Go/process metrics and
`caddy_metrics` stays empty — exactly the situation on the production edge proxy.

---

## Why no `bind`, and why plain HTTP (important background)

Several things silently break a naive setup on a laptop:

1. **The compose bridge gateway IP is not a stable host address.**
   The monitor's compose bridge uses the host as its gateway (that is what
   `host.docker.internal` resolves to via `extra_hosts: ["host.docker.internal:host-gateway"]`).
   Binding Caddy to a LAN/bridge IP and curling it directly is fragile: on Docker
   Desktop the "host" is a lightweight VM, not the laptop, so raw bridge-gateway
   curls can time out. Reach the host through the **mapped name**
   (`host.docker.internal`) instead — Docker rewrites it to the correct gateway
   for your platform.

2. **Caddy auto-HTTPS turns a custom-port listener into TLS.**
   A plain site block on a non-80/443 port makes Caddy serve **HTTPS** there, so a
   plain-`http://` scrape gets `400 Bad Request: Client sent an HTTP request to an
   HTTPS server`. You must force **plain HTTP** with an `http://` prefix.

3. **A `bind` directive is the classic scrape-killer.**
   `bind 192.168.1.17` scopes the socket to that one host interface. The monitor
   container's traffic arrives on the **bridge interface**, so a `bind`-scoped
   listener rejects it — connection refused from inside the container even though
   `curl` on the host works. Do **not** add a `bind` directive to the metrics
   listener if the container must reach it.

4. **The global `metrics` option exposes, but doesn't serve.**
   A metrics site-block **handler** is what actually serves `/metrics` on your
   port; without it the site returns an empty `200` (see Troubleshooting).

The robust setup used here: a plain-HTTP metrics site on port 2020 (no `bind`),
and the monitor points at that port through `host.docker.internal` — verifiable
from inside the container with plain `curl`.

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
keep that site and add metrics around it. If your existing Caddyfile already has a
metrics listener with a `bind` directive, you will want to remove that `bind` (see
Step 2b).

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

Append this at the bottom:

```caddy
http://:2020 {
	metrics
}
```

- The **`http://` scheme** disables auto-HTTPS so it serves **plain HTTP**
  (fixes the `400 ... HTTPS server` error).
- The **`metrics` handler** inside the block actually *serves* the Prometheus
  metrics on this site.
- **No `bind` directive.** The monitor reaches this listener from inside the
  container via the Docker bridge; a `bind <lan-ip>` would scope the socket to one
  host interface and refuse the container's connections (see the box below).

> **Why `:2020` with no `bind`:** listening on all interfaces on a dedicated
> non-admin port is the safe way for the container to reach Caddy on the host.
> The concern that motivates `bind` — keeping metrics off a shared network — is
> addressed here by the fact that this is a dev laptop on a trusted network. If
> you need loopback-only exposure, reach the listener by IP from the host and
> reverse-proxy it; see Troubleshooting.

> **Two distinct things (easy to confuse):**
> - The **global `metrics` option** (Step 2a) *enables* HTTP metric collection.
>   By itself it only exposes them at the admin API's `/metrics` (`:2019`) —
>   which is loopback-only and unreachable from the container.
> - The **`metrics` handler** *serves/exposes* those collected metrics at the
>   `/metrics` path of the site that contains it. Without this handler the site
>   is **empty** and returns `200` with **0 bytes** — no `caddy_http_*` at all.
>
> You need **both**: the global option to enable, and the handler to expose.

Your file should now look like:

```caddy
{
	metrics
}

:80 {
	root * /usr/share/caddy
	file_server
}

http://:2020 {
	metrics
}
```

**Why this shape:**
- No `bind`, so the listener accepts connections on the Docker bridge interface
  from the monitor container.
- `http://` forces plain HTTP (fixes the `400 ... HTTPS server` error).
- Port `2020` is separate from the admin API `:2019`, which stays loopback-only.
- The `metrics` handler serves `caddy_http_*` at `/metrics`, off the admin API.

> **Security (local only):** listening on all interfaces on port `2020` means
> anything on your LAN can fetch the metrics, and the admin API stays on
> `127.0.0.1:2019`. Acceptable for a dev laptop on a trusted network. On a
> shared/public network, firewall port 2020 and **never** expose metrics or the
> admin API in production without auth/firewalling.

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

## Step 4 — Point the monitor at the host (verify the shipped config)

The shipped `config.yaml` already targets `host.docker.internal:2020`, so no
config change is normally needed — this step is about confirming it is in place.

### 4a. `config.yaml` — the caddy `metrics_url`

```yaml
collectors:
  caddy:
    instance_id: edge-01
    metrics_url: http://host.docker.internal:2020/metrics
```

### 4b. `compose.yaml` — `extra_hosts` (required)

The `monitor` service must map `host.docker.internal` to the Docker bridge
gateway. This is already shipped:

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

### 5a. From the host

```bash
curl -s -m 8 http://localhost:2020/metrics | grep -c "^caddy_http"
```

Expected: a number **greater than 0**. You should also see the three families:

```bash
curl -s http://localhost:2020/metrics | grep -E "^# (HELP|TYPE) caddy_http"
```

### 5b. From inside the monitor's network (exactly what the container sees)

```bash
docker run --rm --network server-monitor_monitor-net \
  curlimages/curl \
  curl -s -m 8 http://host.docker.internal:2020/metrics | grep -c "^caddy_http"
```

This must also return > 0. If it is 0 here, the container cannot scrape the
endpoint (see Troubleshooting).

> If a previous setup bound Caddy to a LAN IP, `curl http://localhost:2020/metrics`
> may fail while `curl http://<lan-ip>:2020/metrics` works — that was the `bind`
> scoping the socket; after Step 2b it listens on all interfaces instead.

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
   site `http://:2020 { }` returns `200` with **0 bytes**.
   Fix: add the handler (Step 2b): `http://:2020 { metrics }`.
   (If you instead relied on the deprecated nested `servers { metrics }`, replace
   it with the flat top-level `metrics` option too. You need the global option to
   *enable* collection and the handler to *expose* it — both.)

2. **Deprecated nested `servers { metrics }` syntax.** Under Caddy v2.11 this can
   yield an empty `/metrics` even with a handler present. Use the flat top-level
   `metrics` option.

After fixing, `sudo systemctl reload caddy`, then verify:
`curl -s http://localhost:2020/metrics | grep -c "^caddy_http"` should be **> 0**
and emit `caddy_http_requests_total`, `caddy_http_request_duration_seconds`,
`caddy_http_requests_in_flight`.

### Connection refused from the container (but `curl` works on the host)
- Most likely a leftover **`bind <lan-ip>` directive** on the metrics listener.
  It scopes the socket to one host interface; the container's traffic arrives on
  the Docker bridge interface and is refused. Remove the `bind` line (Step 2b),
  then `sudo systemctl reload caddy`.

### `curl http://localhost:2020/metrics` fails / connection refused (but a LAN IP works)
- Same root cause as above: a `bind` directive scoped the listener off loopback.
  Remove it; the shipped config needs an all-interfaces listener.

### `400 Bad Request: Client sent an HTTP request to an HTTPS server`
- Caddy applied auto-HTTPS to the listener. Add the **`http://` prefix** to the
  site address (`http://:2020`) to force plain HTTP.

### `curl http://<bridge-ip>:2020/metrics` times out
- The compose bridge gateway IP is often **not** a real host interface on
  laptops/Docker Desktop; the route escapes over Wi-Fi and times out. Don't bind
  to that IP. Rely on the `host.docker.internal` mapping in `compose.yaml`
  (Docker resolves it to the correct gateway for your platform).

### `grep -c "^caddy_http"` returns 0
- The `metrics` option is missing, the `metrics` handler is absent, or a `bind`
  directive is scoping the socket. Re-check Steps 2a/2b and that validate +
  reload succeeded (Step 3). Confirm the families exist:
  `curl -s http://localhost:2020/metrics | grep caddy_http`.

### "No route to host" / connection refused from the container
- Confirm the monitor got the `extra_hosts` mapping (Step 4b/4c), that the
  listener has no `bind` directive, and that Caddy is listening:
  `sudo ss -tlnp | grep 2020`. Ensure the reload happened.

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
| `/etc/caddy/Caddyfile` | Added global `metrics` block (top) to *enable* collection + `http://:2020 { metrics }` plain-HTTP listener that *serves* the metrics (end); no `bind` directive so the container can reach it |
| `compose.yaml` | `extra_hosts: ["host.docker.internal:host-gateway"]` on the monitor service (shipped) |
| `config.yaml` | `metrics_url: http://host.docker.internal:2020/metrics` (shipped) |
| `caddy_metrics` table | Now populates (was 0 rows) |

This reproduces the production idea locally — a dedicated metrics-only listener
on a non-admin port with plain HTTP — while keeping the config/admin API
(`:2019`) loopback-only. The monitor reaches the listener through the Docker
gateway mapping, so no machine-specific LAN/bridge IP is baked into the config,
and the Caddy listener stays free of `bind` so it accepts the container's
connections.