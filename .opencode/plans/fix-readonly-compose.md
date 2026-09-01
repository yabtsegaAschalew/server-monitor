# Fix: read-only container write failures in compose.yaml

## Problem
`docker compose up --build` crash-loops because both containers run with `read_only: true` but need a writable path their runtime writes to:

1. **docker-socket-proxy** — `can't create /tmp/haproxy.cfg: Read-only file system`
2. **monitor** — `Failed to initialize cache at /home/monitor/.cache/uv ... Read-only file system`

## Fixes (in compose.yaml)

### 1. docker-socket-proxy service
Add a tmpfs for `/tmp` so its entrypoint can write the haproxy config:

```yaml
    read_only: true
    tmpfs:
      - /tmp
    security_opt: [no-new-privileges:true]
```

### 2. monitor service
Point uv's cache dir at the already-mounted `/tmp` tmpfs (the Dockerfile uses `--no-create-home`, so no home dir exists and the rootfs is read-only):

```yaml
    environment:
      DOCKER_BASE_URL: http://docker-socket-proxy:2375
      MONITOR_DB_PATH: /data/monitoring.db
      UV_CACHE_DIR: /tmp/uv-cache
```

## Verify
Re-run `docker compose up --build` — both containers should start without crash-looping.
