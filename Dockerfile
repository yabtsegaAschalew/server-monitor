FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --no-dev

ENV PYTHONUNBUFFERED=1

# SECURITY: run as an unprivileged user. The monitor only reads telemetry —
# /proc, an HTTP metrics endpoint, a read-only Docker socket proxy, and
# unprivileged ICMP DGRAM sockets. None of that needs UID 0.
#
# /data is the only writable path the process needs (SQLite + WAL). Mount a
# volume there and point MONITOR_DB_PATH at it so the image can run with
# read_only: true. See compose.yaml.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin monitor \
    && mkdir -p /data \
    && chown 10001:10001 /data

ENV MONITOR_DB_PATH=/data/monitoring.db

USER 10001:10001

ENTRYPOINT ["uv", "run", "--no-dev", "--no-sync", "python", "-m", "main"]
