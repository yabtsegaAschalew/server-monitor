FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --no-dev

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["uv", "run", "--no-dev", "--no-sync", "python", "-m", "main"]
