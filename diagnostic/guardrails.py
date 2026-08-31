from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta

from database import DatabaseEngine
from providers.models import TokenUsage

logger = logging.getLogger(__name__)

_cooldown_cache_max = 1000
_call_timestamps_max = 10000


def _now() -> datetime:
    return datetime.now(UTC)


class Guardrails:
    """Cooldown and rate-limit enforcement for AI diagnostics.

    Uses a bounded in-memory cache for fast checks (avoids DB queries on the
    hot path) with SQLite persistence for durability across restarts.
    """

    __slots__ = (
        "_cd_minutes",
        "_cooldown_cache",
        "_db",
        "_max_calls",
        "_timestamps",
    )

    def __init__(
        self,
        db: DatabaseEngine,
        cooldown_minutes: int = 15,
        max_calls_per_hour: int = 10,
    ) -> None:
        self._db = db
        self._cd_minutes = cooldown_minutes
        self._max_calls = max_calls_per_hour
        self._cooldown_cache: dict[str, float] = {}
        self._timestamps: list[float] = []

    async def warm_cache(self) -> None:
        """Preload cooldown state and recent call history from SQLite."""
        try:
            rows = await self._db.query_cooldown_all()
        except Exception:
            logger.warning("failed to warm cooldown cache", exc_info=True)
            return
        cutoff = (now := _now()) - timedelta(seconds=self._cd_minutes * 60)
        for anomaly_type, last_iso in rows:
            try:
                ts = datetime.fromisoformat(last_iso)
            except ValueError:
                continue
            if ts > cutoff:
                self._cooldown_cache[anomaly_type] = ts.timestamp()
        del now

        try:
            log = await self._db.query_recent_ai_calls(minutes=60)
        except Exception:
            logger.warning("failed to warm rate-limit cache", exc_info=True)
            return
        for row in log:
            try:
                self._timestamps.append(datetime.fromisoformat(row["created_at"]).timestamp())
            except (ValueError, KeyError):
                continue
        self._trim_timestamps()

    def is_cooldown_active(self, anomaly_type: str) -> bool:
        last = self._cooldown_cache.get(anomaly_type)
        if last is None:
            return False
        if time.time() - last < self._cd_minutes * 60:
            return True
        self._cooldown_cache.pop(anomaly_type, None)
        return False

    async def check_cooldown(self, anomaly_type: str) -> bool:
        """Return True if a cooldown is active for this anomaly type."""
        if self.is_cooldown_active(anomaly_type):
            return True
        last = await self._db.get_cooldown(anomaly_type)
        if last is None:
            return False
        if _now() - last < timedelta(seconds=self._cd_minutes * 60):
            self._cooldown_cache[anomaly_type] = last.timestamp()
            if len(self._cooldown_cache) > _cooldown_cache_max:
                self._evict_cooldown()
            return True
        return False

    async def record_trigger(self, anomaly_type: str) -> None:
        """Mark an anomaly as triggered, starting its cooldown window."""
        now = _now()
        self._cooldown_cache[anomaly_type] = now.timestamp()
        if len(self._cooldown_cache) > _cooldown_cache_max:
            self._evict_cooldown()
        await self._db.set_cooldown(anomaly_type, now)

    def is_rate_limit_exceeded(self, now: float | None = None) -> bool:
        """Return True if the global hourly AI call cap has been exceeded."""
        self._trim_timestamps()
        return len(self._timestamps) >= self._max_calls

    async def check_rate_limit(self) -> bool:
        """Return True if the rate limit is currently exceeded."""
        try:
            count = await self._db.count_ai_calls_last_hour()
        except Exception:
            logger.warning("rate-limit DB query failed, falling back to cache", exc_info=True)
            count = len(self._timestamps)
        return count >= self._max_calls

    async def log_call(
        self,
        anomaly_type: str,
        provider: str,
        model: str,
        usage: TokenUsage,
        *,
        success: bool,
        error: str | None = None,
    ) -> None:
        self._timestamps.append(time.time())
        self._trim_timestamps()
        await self._db.insert_ai_call_log(
            anomaly_type=anomaly_type,
            provider=provider,
            model=model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            success=success,
            error=error,
        )

    def _trim_timestamps(self) -> None:
        cutoff = time.time() - 3600.0
        i = 0
        while i < len(self._timestamps) and self._timestamps[i] < cutoff:
            i += 1
        if i:
            del self._timestamps[:i]
        if len(self._timestamps) > _call_timestamps_max:
            del self._timestamps[: len(self._timestamps) - _call_timestamps_max]

    def _evict_cooldown(self) -> None:
        overflow = len(self._cooldown_cache) - _cooldown_cache_max
        if overflow > 0:
            for key in list(self._cooldown_cache)[:overflow]:
                self._cooldown_cache.pop(key, None)
