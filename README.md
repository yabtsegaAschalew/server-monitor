# Server Monitor

An asynchronous, low-overhead server monitoring system built with Python 3.12+ and `asyncio`. Collects host metrics, Caddy reverse-proxy telemetry, and Docker container events, then persists everything to SQLite via a single-writer queue architecture.

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

### Key Design Decisions

| Concern | Solution |
|---------|----------|
| **SQLITE_BUSY contention** | Single-writer pattern — all collectors push to an `asyncio.Queue`, one `_WriterWorker` task serialises all writes with `BEGIN IMMEDIATE` |
| **WAL mode** | `PRAGMA journal_mode=WAL` enables concurrent reads while the writer holds the lock |
| **Memory bounded** | Bounded `asyncio.Queue(maxsize=10000)` + batched `executemany` flushes (default batch=256). Worst-case queue memory: ~4.5 MB |
| **Queue overflow** | Drop with warning — telemetry is lossy by nature, no backpressure to collector daemons |
| **Data retention** | Background `_PruneWorker` deletes rows older than 7 days across all5 tables |
| **CPU overhead** | No `psutil` — host metrics read directly from `/proc` (`/proc/stat`, `/proc/meminfo`, `/proc/diskstats`, `/proc/net/dev`, `/proc/loadavg`, `/proc/pressure/*`) |
| **Metric streaming** | Caddy scraper uses `httpx.stream()` with a cardinality filter — only parses the 3 known metric families, discards everything else in-stream |

## Modules

| Module | Purpose |
|--------|---------|
| `main.py` | CLI entry point — parses args, loads config, wires daemons to the database sink |
| `config.py` | Pydantic configuration models with YAML loading and env-var interpolation |
| `models.py` | Pydantic metric models (`HostMetric`, `CaddyMetric`, `DockerEvent`, etc.) |
| `database.py` | Single-writer persistence engine — `DatabaseEngine` with queue ingest, batched writes, pruning, and query methods |
| `collectors/` | Collector daemon package |
| `collectors/system_health.py` | Host telemetry from `/proc` + Caddy scrape orchestrator |
| `collectors/caddy_scraper.py` | Streaming Prometheus scraper with cardinality filtering |
| `collectors/docker_monitor.py` | Docker event stream with crash-loop detection |

## Database Schema

### Tables

| Table | Description |
|-------|-------------|
| `system_metrics` | CPU, memory, disk, load, network I/O, PSI (Pressure Stall Information) |
| `caddy_metrics` | Requests/sec, error rate, p99 latency, active connections |
| `docker_metrics` | Container events (die, kill, oom, restart, etc.) with exit codes |
| `network_probes` | Endpoint uptime checks, response times, SSL expiry (for future use) |
| `ai_diagnostic_logs` | Structured diagnostic entries for AI-driven analysis (for future use) |

### Configuration

All database settings live under `collectors.database` in `config.yaml`:

```yaml
collectors:
  database:
    db_path: monitoring.db        # SQLite file path
    queue_maxsize: 10000          # Max items in ingest queue (≥100)
    batch_size: 256               # Items per INSERT transaction (1–10000)
    prune_interval_seconds: 3600  # How often to run retention pruning
    retention_days: 7             # Delete data older than N days
```

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

Edit `config.yaml` to point at your actual services:

```yaml
polling:
  interval_seconds: 5.0

thresholds: {}

collectors:
  host:
    host_id: localhost

  caddy:
    instance_id: edge-01
    metrics_url: http://localhost:2019/metrics

  docker:
    events_url: http://localhost:2375/events

  database:
    db_path: monitoring.db
    queue_maxsize: 10000
    batch_size: 256
    prune_interval_seconds: 3600
    retention_days: 7
```

### Run

```bash
# Run all collectors (host + caddy + docker)
uv run python main.py

# Run specific collectors
uv run python main.py --collectors host,caddy

# Override scrape interval
uv run python main.py --interval 2.0

# Use a different config file
uv run python main.py --config /etc/server-monitor/config.yaml
```

### Docker

```bash
docker compose up --build
```

Note: Docker monitoring requires the Docker daemon to be reachable over TCP. On Linux, add to `/etc/docker/daemon.json`:

```json
{"hosts": ["tcp://0.0.0.0:2375"]}
```

## Running Tests

```bash
# Run full test suite (62 tests)
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
| Ingest queue (max 10,000 items) | ~4.5 MB worst case |
| Batch buffer (256 items) | ~119 KB |
| SQLite page cache (WAL) | ~2 MB |
| Host metrics collector | ~2 KB per snapshot |
| **Total overhead** | **~7 MB** |

### How Memory is Bounded

- **Queue**: `asyncio.Queue(maxsize=10000)` — bounded, drops on overflow
- **Batch flush**: Drains up to `batch_size` items per `get_nowait()` loop — no accumulation
- **`__slots__`**: `_CounterSnapshot` uses `@dataclass(slots=True)` to avoid per-instance `__dict__`
- **No `psutil`**: Direct `/proc` reads avoid C-extension namedtuple allocations
- **Streaming scraper**: Caddy `/metrics` is processed line-by-line via `httpx.stream()`, never buffered in full

## Constraints & Limitations

- **Single SQLite writer**: All writes are serialised through one `BEGIN IMMEDIATE` transaction. This is intentional — SQLite does not handle concurrent writers well, and WAL mode gives us fast reads without locking.
- **Telemetry is lossy**: If the ingest queue fills up (e.g., disk I/O stalls), items are dropped with a warning. This is acceptable for monitoring workloads where occasional gaps are tolerable.
- **Linux only**: Host metrics read from `/proc` (CPU, memory, disk I/O, network, load average, PSI). Not portable to macOS/Windows.
- **No encryption at rest**: SQLite database is unencrypted. For sensitive deployments, consider SQLCipher or filesystem-level encryption.
- **7-day default retention**: Old data is automatically pruned. Adjust `retention_days` in config if you need longer history.

## Project Structure

```
server-monitor/
├── main.py                  # CLI entry point
├── config.py                # Pydantic config models + YAML loader
├── config.yaml              # Default configuration
├── database.py              # Single-writer SQLite persistence engine
├── models.py                # Pydantic metric models
├── pyproject.toml           # Project metadata + dependencies
├── compose.yaml             # Docker Compose for containerised deployment
├── Dockerfile               # Container build
├── collectors/
│   ├── __init__.py          # Public collector API
│   ├── errors.py            # Base CollectorError exception
│   ├── system_health.py     # Host /proc reader + Caddy scraper orchestrator
│   ├── caddy_scraper.py     # Streaming Prometheus metrics scraper
│   └── docker_monitor.py    # Docker event stream + crash-loop detector
└── tests/
    ├── test_caddy_scraper.py
    ├── test_docker_monitor.py
    ├── test_database.py
    ├── test_main.py
    └── test_system_health.py
```

## License

Proprietary — Asymmetrica Internship.
