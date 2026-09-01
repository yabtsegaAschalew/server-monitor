# Server Monitor

An asynchronous, low-overhead server monitoring system built with Python 3.12+ and `asyncio`. Collects host metrics, Caddy reverse-proxy telemetry, Docker container events, and network probes (ICMP/SNMP), then persists everything to SQLite via a single-writer queue architecture.

Includes a **central diagnostic agent** — a LangGraph orchestrator that detects threshold breaches, invokes a pluggable LLM provider (Gemini by default) for root-cause analysis, and produces human-approved remediation proposals without ever executing commands automatically.

Includes **multi-burn-rate SLO alerting** — a fast + slow burn-rate pair with a short canary window, plus Discord / Slack / SMTP notification dispatchers.

## Architecture

```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  SystemHealth     │  │  CaddyScraper     │  │  DockerMonitor   │
│  Daemon           │  │  (streaming)      │  │  (event stream)  │
│  (host + caddy)   │  │                   │  │                  │
└────────┬─────────┘  └────────┬──────────┘  └────────┬─────────┘
         │  write()            │  write()              │  write()
         └─────────────┬───────┴──────────────┬────────┘
                       ▼                      ▼
              ┌──────────────────────────────────┐
              │       asyncio.Queue (bounded)    │
              └──────────────┬───────────────────┘
                             ▼  drain (up to batch_size)
              ┌──────────────────────────────────┐
              │   Single _WriterWorker task       │
              │   BEGIN IMMEDIATE → executemany   │
              │   → COMMIT  (WAL mode SQLite)     │
              └──────────────┬───────────────────┘
                             ▼  every hour
              ┌──────────────────────────────────┐
              │   _PruneWorker task               │
              │   DELETE WHERE created_at < -7d   │
              └──────────────────────────────────┘
```

### Central Diagnostic Agent

```
┌──────────────────────────────────────────────────────────────┐
│                     DiagnosticAgent (LangGraph)              │
├──────────────────────────────────────────────────────────────┤
│  evaluate_metrics → run_diagnostics → human_in_the_loop      │
│       │                  │                  │                │
│       ▼                  ▼                  ▼                │
│  SQLite threshold    AIProvider (Gemini)   write proposed    │
│  breach detection    sanitized telemetry   rule to SQLite    │
│                                             (NEVER execute)  │
└──────────────────────┬───────────────────────────────────────┘
                       │  Guardrails
                       │  • 15-min cooldown per anomaly type
                       │  • 10 AI calls/hour global cap
                       │  • token-usage logging (FinOps)
                       ▼
            proposed_remediation_rules (pending queue)
```

The provider is a pluggable adapter (`AIProvider`). Only `GeminiProvider` ships today, but an `AnthropicProvider` (or any other) can be dropped in with zero changes to the LangGraph orchestration.

### Key Design Decisions

| Concern | Solution |
|---------|----------|
| **SQLITE_BUSY contention** | Telemetry writes go through a single `_WriterWorker` task fed by an `asyncio.Queue`, serialised with `BEGIN IMMEDIATE`. Diagnostic writes (cooldown, call log, proposed rules) and all reads open short-lived connections, which carry the same `busy_timeout` so they wait out a flush instead of failing |
| **WAL mode** | `PRAGMA journal_mode=WAL` enables concurrent reads while the writer holds the lock |
| **Memory bounded** | Bounded `asyncio.Queue(maxsize=1000)` + batched `executemany` flushes (default batch=256). SLI aggregation for alerting runs as `SUM()` in SQL, so a 6-hour burn window costs the same memory as a 5-minute one |
| **Queue overflow** | Drop with warning — telemetry is lossy by nature, no backpressure to collector daemons |
| **Data retention** | Background `_PruneWorker` deletes rows older than 7 days across all tables |
| **CPU overhead** | No `psutil` — host metrics read directly from `/proc` (`/proc/stat`, `/proc/meminfo`, `/proc/diskstats`, `/proc/net/dev`, `/proc/loadavg`, `/proc/pressure/*`) |
| **Metric streaming** | Caddy scraper uses `httpx.stream()` with a cardinality filter — only parses the 3 known metric families, discards everything else in-stream |
| **Provider abstraction** | `AIProvider` adapter interface — swap LLM providers via config (`diagnostic.provider`) with no orchestration changes |
| **No auto-execution** | The diagnostic agent only proposes remediation. `requires_human_approval` is always `True`; even `approve` merely flips a DB status — nothing is ever shell-executed |
| **FinOps guardrails** | 15-min cooldown per anomaly type + 10 AI calls/hour global cap (counting failures as well as successes, so an erroring provider cannot retry unmetered), both persisted to SQLite; token usage logged on every call. The model is only invoked when a configured threshold has actually been breached |
| **Prompt injection** | Telemetry carries attacker-controllable strings (container names, image tags, labels). They are escaped, truncated and wrapped in a `<telemetry>` block that the system prompt declares untrusted; the model's reply is re-validated against `ActionPlan`, which bounds each suggested command to one line under 500 chars |
| **Small memory footprint** | Stateless single-shot LLM calls (no conversation history), `__slots__` on the agent/guardrail state, bounded caches |

## Modules

| Module | Purpose |
|--------|---------|
| `main.py` | CLI entry point — parses args, loads config, wires daemons to the database sink |
| `config.py` | Pydantic configuration models with YAML loading and env-var interpolation |
| `models.py` | Pydantic metric models (`HostMetric`, `CaddyMetric`, `DockerEvent`, etc.) |
| `database.py` | Single-writer persistence engine — `DatabaseEngine` with queue ingest, batched writes, pruning, and query methods |
| `alert_engine.py` | Multi-burn-rate SLO evaluation, alert state machine, and notification dispatchers |
| `collectors/` | Collector daemon package |
| `collectors/system_health.py` | Host telemetry from `/proc` + Caddy scrape orchestrator |
| `collectors/caddy_scraper.py` | Streaming Prometheus scraper with cardinality filtering |
| `collectors/docker_monitor.py` | Docker event stream with crash-loop detection |
| `providers/` | Pluggable AI provider adapters (vendor-lock-in avoidance) |
| `providers/base.py` | `AIProvider` abstract interface |
| `providers/gemini.py` | `GeminiProvider` — Google GenAI SDK implementation |
| `diagnostic/` | Central diagnostic agent (LangGraph) |
| `diagnostic/agent.py` | `DiagnosticAgent` — daemon + CLI wrapper around the compiled graph |
| `diagnostic/nodes.py` | Three graph nodes: evaluate_metrics, run_diagnostics, human_in_the_loop |
| `diagnostic/guardrails.py` | Cooldown, rate limiting, and token-usage tracking |
| `diagnostic/schema.py` | SQLite DDL for diagnostic tables |

## Database Schema

### Tables

| Table | Description |
|-------|-------------|
| `system_metrics` | CPU, memory, disk, load, network I/O, PSI (Pressure Stall Information) |
| `caddy_metrics` | Requests/sec, error rate, p99 latency, active connections |
| `docker_metrics` | Container events (die, kill, oom, restart, etc.) with exit codes |
| `network_probes` | Endpoint uptime checks, response times, SSL expiry (no collector writes this yet — `EndpointMetric` has no producer) |
| `icmp_probes` | ICMP ping probes — RTT, packet loss, min/max/avg |
| `snmp_interfaces` / `snmp_hosts` | SNMPv3 IF-MIB and HOST-RESOURCES-MIB polling |
| `ai_diagnostic_logs` | Structured diagnostic log entries |
| `cooldown_state` | Per-anomaly-type cooldown timestamps (survives restarts) |
| `ai_call_log` | AI provider call audit + token-usage accounting (FinOps) |
| `proposed_remediation_rules` | Human review queue — pending, approved, rejected, expired |
| `active_alerts` | Firing/resolved SLO burn alerts, with suppression and resolve timestamps |

### Configuration

All database settings live under `collectors.database` in `config.yaml`:

```yaml
collectors:
  database:
    db_path: "${MONITOR_DB_PATH:monitoring.db}"  # overridable for containers
    queue_maxsize: 1000            # Max items in ingest queue (≥100)
    batch_size: 256                # Items per INSERT transaction (1–10000)
    prune_interval_seconds: 3600   # How often to run retention pruning
    retention_days: 7              # Delete data older than N days
```

`${VAR}` / `${VAR:default}` placeholders are expanded **after** the YAML is
parsed, so an environment variable can only change the value of an existing
leaf — never the structure of the document. A placeholder that is unset and has
no default is a hard error at load time.

### SQLite Pragmas

```sql
PRAGMA journal_mode=WAL;       -- concurrent readers + single writer
PRAGMA synchronous=NORMAL;     -- fsync only on checkpoints (safe with WAL)
PRAGMA busy_timeout=5000;      -- wait up to 5s if DB is locked
```

## Getting Started

### Prerequisites

- Python 3.12+
- `uv` (recommended) or `pip`

### Install

```bash
# Clone the repository
git clone <repo-url> && cd server-monitor

# Install with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

### Configure

Copy the environment template and fill in your secrets, then edit `config.yaml` to point at your actual services:

```bash
cp .env.example .env
# then fill in .env with your secrets
```

Environment variables are interpolated into `config.yaml` messages like `${VAR}` or with a default `${VAR:default}`. The full set is documented in `.env.example`:

| Variable | Purpose | Required |
|----------|---------|----------|
| `GEMINI_API_KEY` | Google Gemini key for the diagnostic agent | Only if using the diagnostic module |
| `SNMP_AUTH_PASSWORD` | SNMPv3 auth password (`auth_password`) | If SNMP auth enabled |
| `SNMP_PRIV_PASSWORD` | SNMPv3 priv password (`priv_password`) | If SNMP priv enabled |
| `DISCORD_WEBHOOK_URL` | Discord webhook for alert dispatch | If alerting to Discord |
| `SLACK_WEBHOOK_URL` | Slack webhook for alert dispatch | If alerting to Slack |
| `SMTP_HOST` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` | SMTP relay settings for email fallback (all four needed, plus `alerting.smtp.to_addrs` in `config.yaml`) | If alerting by email |
| `MONITOR_DB_PATH` | SQLite database path (the container image sets this to `/data`); also settable via `collectors.database.db_path` | Only for overriding the default (`monitoring.db`) |
| `DOCKER_BASE_URL` | Docker API base URL (default `http://docker-socket-proxy:2375`) | Only if overriding the default transport |
| `DOCKER_SOCKET_PATH` | Direct Unix-socket mode, bypassing the docker-socket-proxy restrictions | Development only

SNMP is opt-in: `snmp_targets` ships empty. A target that declares
`auth_protocol`/`priv_protocol` with an empty password fails config validation
by design — SNMPv3 must never silently downgrade to cleartext — and a config
load failure stops every collector, not just SNMP.

Example `config.yaml` for the collectors:

```yaml
polling:
  interval_seconds: 5.0

thresholds:
  host:
    cpu:
      warning: 80.0
      critical: 95.0
    memory:
      warning: 85.0
      critical: 95.0

collectors:
  host:
    host_id: localhost
    # disk_path: /   # leave unset: "/" on the host, or /host/root when HOST_ROOT is set

  caddy:
    instance_id: edge-01
    metrics_url: http://host.docker.internal:2020/metrics

  docker:
    transport_mode: tcp_proxy       # tcp_proxy | unix_socket
    base_url: http://docker-socket-proxy:2375

  database:
    db_path: "${MONITOR_DB_PATH:monitoring.db}"
    queue_maxsize: 1000
    batch_size: 256
    prune_interval_seconds: 3600
    retention_days: 7

  network:
    icmp_interval_seconds: 30
    snmp_interval_seconds: 60
    icmp_targets:
      - host: 8.8.8.8
        count: 5
        interval_seconds: 1.0
        timeout_seconds: 2.0
        payload_size: 64
      - host: 1.1.1.1
        count: 5
        interval_seconds: 1.0
        timeout_seconds: 2.0
        payload_size: 64
    snmp_targets: []
```

#### Diagnostic agent configuration

The diagnostic agent is configured under the top-level `diagnostic` block:

```yaml
diagnostic:
  enabled: true
  provider: gemini
  gemini_model: "gemini-1.5-flash"
  gemini_api_key: "${GEMINI_API_KEY:}"
  cooldown_minutes: 15
  max_calls_per_hour: 10
  evaluation_window_minutes: 10
  evaluation_interval_seconds: 60
  enabled_metric_sources: [host, caddy, docker, network]
```

| Setting | Description |
|---------|-------------|
| `provider` | AI provider adapter (currently only `gemini`) |
| `gemini_api_key` | Interpolated from `GEMINI_API_KEY`; the `:}` default means an unset key degrades gracefully rather than failing config load |
| `cooldown_minutes` | Mandatory cooldown per anomaly type before another LLM call (circuit breaker) |
| `max_calls_per_hour` | Hard global cap on AI calls per hour |
| `evaluation_window_minutes` | Historical window (from SQLite) used to evaluate breaches |
| `evaluation_interval_seconds` | How often the daemon scans for anomalies (default 60s) |
| `enabled_metric_sources` | Which metric types the daemon scans (cross-layer context is always gathered) |

> **Note on graceful degradation:** if the diagnostic module is enabled but no `GEMINI_API_KEY` is configured, the diagnostic daemon logs a warning and exits cleanly (exit code 0). The system-wide collectors are unaffected and continue running normally.

#### Thresholds

The daemon detects anomalies by comparing latest metric values against thresholds in `config.yaml`. Thresholds are keyed by metric type and field:

```yaml
thresholds:
  host:
    cpu:
      warning: 80.0
      critical: 95.0
    memory:
      warning: 85.0
      critical: 95.0
    disk:
      warning: 80.0
      critical: 90.0
    load_avg:
      warning: 4.0
      critical: 8.0
  caddy:
    error_rate:
      warning: 0.05
      critical: 0.15
    p99_latency_ms:
      warning: 500.0
      critical: 2000.0
  network:
    packet_loss_pct:
      warning: 5.0
      critical: 25.0
    avg_rtt_ms:
      warning: 150.0
      critical: 500.0
```

### Run

The CLI is organised into subcommands:

```bash
# Run the telemetry collectors (host + caddy + docker + network)
uv run python -m main collectors

# Run specific collectors
uv run python -m main collectors --collectors host,caddy

# Override scrape interval
uv run python -m main collectors --interval 2.0

# Use a different config file
uv run python -m main collectors --config /etc/server-monitor/config.yaml
```

#### Diagnostic agent CLI

```bash
# Run the diagnostic agent as a continuous daemon (scans every 60s)
uv run python -m main diagnostic daemon

# Override the daemon evaluation interval (seconds)
uv run python -m main diagnostic daemon --interval 120

# Run a single ad-hoc anomaly analysis
uv run python -m main diagnostic analyze --type host --entity localhost --window 10

# List proposed remediation rules (optionally filtered by status)
uv run python -m main diagnostic list-rules
uv run python -m main diagnostic list-rules --status pending

# Mark a rule as approved / rejected
# IMPORTANT: this only updates the database status — it never executes commands.
uv run python -m main diagnostic approve 12
uv run python -m main diagnostic reject 12
```

The full workflow: collectors write metrics → the diagnostic daemon detects a threshold breach → `GeminiProvider` produces an `ActionPlan` → the plan is stored in `proposed_remediation_rules` with status `pending` → a human reviews and approves/rejects via the CLI.

### Docker

The shipped `compose.yaml` runs two services on an internal bridge (`monitor-net`):

- **`docker-socket-proxy`** — a read-only proxy for the Docker API. It publishes **no host port**; the monitor reaches it by service name at `http://docker-socket-proxy:2375`. The proxy only grants the GET verbs the monitor needs (`CONTAINERS`, `EVENTS`, `PING`, `VERSION`) and explicitly denies the write verbs (`POST=0`, `EXEC=0`).
- **`monitor`** — the application itself, hardened (UID 10001, `read_only`, `cap_drop: [ALL]`, 128 MB memory limit). It bind-mounts the host filesystems read-only under `HOST_ROOT=/host` so host metrics report the real machine rather than the container's own view, and maps `host.docker.internal` to the Docker bridge gateway for the Caddy scrape.

```bash
docker compose up --build          # build + run both services
docker compose up -d --build monitor  # rebuild just the monitor
docker compose logs -f monitor     # follow collector + daemon logs
```

The Caddy collector reaches a Caddy running *on the host* via `http://host.docker.internal:2020/metrics` (configured in `config.yaml` and covered in `docs/local-caddy-metrics.md`).

## Running Tests

```bash
# Run full test suite (237 passed)
uv run pytest -v

# Run with coverage
uv run pytest --cov=. --cov-report=term-missing

# Lint
uv run ruff check .

# Format check
uv run ruff format --check .
```

## Memory Constraints

The system is designed to operate under 100 MB RAM:

| Component | Memory |
|-----------|--------|
| Ingest queue (max 1,000 items) | ~450 KB worst case |
| Batch buffer (256 items) | ~119 KB |
| SQLite page cache (WAL) | ~2 MB |
| Host metrics collector | ~2 KB per snapshot |
| Diagnostic cooldown cache (≤1000 entries) | ~100 KB |
| Diagnostic rate-limit window (≤10,000 timestamps) | ~100 KB |
| **Total overhead** | **~3 MB** |

The diagnostic agent adds only ~200 KB of state on top of the collectors — single-shot LLM calls mean there is no growing conversation/history buffer on the hot path.

### How Memory is Bounded

- **Queue**: `asyncio.Queue(maxsize=1000)` — bounded, drops on overflow
- **Batch flush**: Drains up to `batch_size` items per `get_nowait()` loop — no accumulation
- **`__slots__`**: `_CounterSnapshot` uses `@dataclass(slots=True)`; `DiagnosticAgent` and `Guardrails` declare explicit `__slots__` to avoid per-instance `__dict__`
- **No `psutil`**: Direct `/proc` reads avoid C-extension namedtuple allocations
- **Streaming scraper**: Caddy `/metrics` is processed line-by-line via `httpx.stream()`, never buffered in full
- **Stateless AI calls**: `analyze_incident()` is single-shot — no conversational history is retained between incidents; LangGraph `DiagnosticState` is ephemeral per invocation
- **Bounded caches**: Cooldown cache (≤1000 entries) and rate-limit window (≤10,000 timestamps) are auto-pruned

## Constraints & Limitations

- **Single SQLite writer**: All writes are serialised through one `BEGIN IMMEDIATE` transaction. This is intentional — SQLite does not handle concurrent writers well, and WAL mode gives us fast reads without locking.
- **Telemetry is lossy**: If the ingest queue fills up (e.g., disk I/O stalls), items are dropped with a warning. This is acceptable for monitoring workloads where occasional gaps are tolerable.
- **Linux only**: Host metrics read from `/proc` (CPU, memory, disk I/O, network, load average, PSI). Not portable to macOS/Windows.
- **No encryption at rest**: SQLite database is unencrypted. For sensitive deployments, consider SQLCipher or filesystem-level encryption.
- **7-day default retention**: Old data is automatically pruned. Adjust `retention_days` in config if you need longer history.
- **Diagnostic agent never executes commands**: The AI provider only proposes remediation. Approval (`approve`) flips the SQLite status only — wiring approved rules to an actual executor is intentionally out of scope for safety.
- **Graceful LLM degradation**: If no `GEMINI_API_KEY` is configured, the diagnostic daemon disables itself cleanly; collectors keep running.

## Project Structure

```
server-monitor/
├── main.py                  # CLI entry point (collectors + diagnostic subcommands)
├── config.py                # Pydantic config models + YAML loader
├── config.yaml              # Default configuration
├── database.py              # Single-writer SQLite persistence engine
├── models.py                # Pydantic metric models
├── .env.example             # Environment variable template (copy to .env)
├── docs/
│   └── local-caddy-metrics.md  # Local Caddy setup for the monitored edge proxy
├── pyproject.toml           # Project metadata + dependencies
├── compose.yaml             # Docker Compose for containerised deployment
├── Dockerfile               # Container build
├── collectors/
│   ├── __init__.py          # Public collector API
│   ├── errors.py            # Base CollectorError exception
│   ├── system_health.py     # Host /proc reader + Caddy scraper orchestrator
│   ├── caddy_scraper.py     # Streaming Prometheus metrics scraper
│   ├── docker_monitor.py    # Docker event stream + crash-loop detector
│   └── network_collector.py # ICMP + SNMPv3 network polling
├── providers/
│   ├── __init__.py          # Provider exports
│   ├── base.py              # AIProvider abstract interface (adapter)
│   ├── gemini.py            # GeminiProvider (Google GenAI SDK)
│   └── models.py            # ActionPlan, Severity, TokenUsage (Pydantic)
├── alert_engine.py          # Burn-rate evaluation + dispatchers
├── diagnostic/
│   ├── __init__.py          # Lazy package exports
│   ├── __main__.py          # `python -m diagnostic` entry point
│   ├── agent.py             # DiagnosticAgent + LangGraph graph compilation
│   ├── cli.py               # Shared inspection commands (both entry points)
│   ├── nodes.py             # Three graph nodes + telemetry sanitization
│   ├── guardrails.py        # Cooldown, rate limiting, token tracking
│   ├── schema.py            # SQLite DDL for diagnostic tables
│   └── state.py             # DiagnosticState TypedDict
└── tests/
    ├── test_caddy_scraper.py
    ├── test_docker_monitor.py
    ├── test_database.py
    ├── test_main.py
    ├── test_network_collector.py
    ├── test_system_health.py
    ├── test_providers.py
    ├── test_guardrails.py
    ├── test_diagnostic_nodes.py
    ├── test_diagnostic_graph.py
    ├── test_diagnostic_cli.py       # review path is status-only
    ├── test_alert_engine.py         # burn-rate math, suppression, dispatchers
    ├── test_memory_footprint.py     # tracemalloc benchmark (opt-in)
    ├── test_audit_regressions.py    # silent-failure regressions from the audit
    └── test_execution_boundary.py   # asserts the no-execution guarantee
```

## Multi-Burn-Rate Alerting

```
┌──────────────────────────────────────────────────────────────┐
│                       AlertEngine (60s tick)                 │
├──────────────────────────────────────────────────────────────┤
│  per SLO, per burn class:                                    │
│    long window ──┐                                           │
│                  ├── BOTH over threshold ──> fire            │
│    short canary ─┘                                           │
│                                                              │
│  burn_rate = failure_ratio / (1 - slo_target)                │
│    fast: 2% of budget in 1h  -> 14.4x -> critical (page)      │
│    slow: 5% of budget in 6h  ->  6.0x -> high     (ticket)    │
└──────────────────────┬───────────────────────────────────────┘
                       │  suppression: 15-min gap per alert key
                       │  flapping:    300s below threshold to resolve
                       ▼
              active_alerts ──> Discord / Slack / SMTP
```

The short canary window is what makes this *multi-window*. Without it, a
five-minute incident keeps the one-hour window elevated — and the alert firing —
for a full hour after service has recovered.

**Why only `caddy` and `icmp` SLO sources?** An SLI has to be a ratio of good
events to total events. Caddy gives request counts and error rates; ICMP gives
probes sent and received. A host CPU percentage is not a ratio of anything, so
dividing it by an error budget produces a number with no meaning. `SloSource`
is an enum of exactly those two, so the mistake fails config validation instead
of producing confident nonsense.

Caddy's ratio is **request-weighted** (`Σ(rps × error_rate) / Σ(rps)`): an
unweighted mean would let a quiet 3am scrape with one failed request outweigh a
busy afternoon with none. A window with no traffic yields `0.0` — no traffic is
not an outage.

### Alert configuration

```yaml
alerting:
  enabled: true
  evaluation_interval_seconds: 60
  cooldown_minutes: 15        # suppression: gap between notifications
  resolve_after_seconds: 300  # flapping: quiet period before resolving
  slo_window_days: 30
  fast_burn_budget_fraction: 0.02
  fast_burn_long_window_minutes: 60
  fast_burn_short_window_minutes: 5
  slow_burn_budget_fraction: 0.05
  slow_burn_long_window_minutes: 360
  slow_burn_short_window_minutes: 30
  discord_webhook_url: "${DISCORD_WEBHOOK_URL:}"
  slack_webhook_url: "${SLACK_WEBHOOK_URL:}"
  smtp:
    host: "${SMTP_HOST:}"
    port: 587
    username: "${SMTP_USERNAME:}"
    password: "${SMTP_PASSWORD:}"
    from_addr: "${SMTP_FROM:}"
    to_addrs: []
    security: starttls
  slos:
    - name: caddy-availability
      source: caddy           # caddy | icmp
      entity_id: edge-01
      target: 0.999
```

> **Dispatch is enabled by default.** Setting a webhook URL and starting the
> engine will post to that channel. The engine only runs under `--alert-engine`
> or `--all`. With no channel configured it still evaluates and records alerts
> in `active_alerts`, logging once that nothing can be sent.

## Running

```bash
# Everything: collectors + diagnostic agent + alert engine, one shared database
uv run python -m main --all

# Individual daemons; combine freely
uv run python -m main --collectors --only host,caddy
uv run python -m main --diagnostic
uv run python -m main --alert-engine

# Compatibility aliases (used by compose.yaml) remain valid
uv run python -m main collectors --collectors docker
```

SIGINT/SIGTERM trigger a graceful shutdown: daemon tasks are cancelled and
drained, then each daemon's connection pools close, then the database last so
in-flight writes land. A second signal forces immediate exit.

### Inspecting proposals

```bash
uv run python -m diagnostic list-rules --status pending
uv run python -m diagnostic analyze --anomaly host:localhost
uv run python -m diagnostic approve 12     # status only — runs nothing
uv run python -m diagnostic reject 13
```

Both `python -m diagnostic <cmd>` and `python -m main diagnostic <cmd>` call the
same implementation in `diagnostic/cli.py`, so they cannot drift apart.

## Security Model

The central claim is that this system **observes and proposes, but never acts**.
That is enforced at several layers rather than left to convention:

| Boundary | How it is held |
|----------|----------------|
| **No execution** | No `subprocess`, `os.system`, `shlex`, `eval`/`exec`, or `shell=True` anywhere in the tree. `tests/test_execution_boundary.py` walks the AST of every shipped module and fails CI if one appears, and separately asserts that the `approve`/`reject` review path contains no execution primitive |
| **No consumer for proposals** | An `ActionPlan` is serialised to `proposed_remediation_rules` with `status='pending'`. `approve` flips a status column; nothing reads that table to act on it, and the boundary test asserts no module outside the CLI review path touches it |
| **Approval cannot be waived** | `ActionPlan.requires_human_approval` is `frozen=True`, rejected if false by a `mode="before"` validator, and re-checked in both the provider and the graph node |
| **Docker is read-only** | Every Docker call is a `GET`. In `tcp_proxy` mode the proxy sets `POST=0`/`EXEC=0`; in `unix_socket` mode httpx connects to the socket natively — no socat, no root helper. Container IDs are validated as hex before entering a request path |
| **Outbound POSTs are alerts only** | The alert dispatchers are the only `POST` requests in the codebase. They carry alert metadata to a webhook you configured and nothing else; no telemetry, no credentials, no command text |
| **No privileged sockets** | ICMP prefers unprivileged `SOCK_DGRAM`, falls back to `SOCK_RAW`, and disables itself with a clear log line if neither is permitted. The process never requires root |
| **Untrusted telemetry** | Container names, image tags and labels are attacker-controllable. They are escaped, truncated, wrapped in a `<telemetry>` block the system prompt declares as data, and the model's reply is re-validated against `ActionPlan` |
| **Secrets** | No credential appears in code or defaults; all come from `${ENV_VAR}`. `.dockerignore` excludes `.env` and `*.db*` so `COPY . .` cannot bake them into an image layer |

### Container hardening

`compose.yaml` runs the monitor as UID 10001 with `cap_drop: [ALL]`,
`read_only: true`, `no-new-privileges`, and a 128 MB memory limit; `/data` is
the only writable path. The `docker-socket-proxy` publishes **no host port** —
it is reachable only over the internal `monitor-net` bridge. Do not add a
`ports:` mapping to it: even read-only, it exposes a complete unauthenticated
inventory of the host's containers.

## License

Proprietary — Asymmetrica Internship.
