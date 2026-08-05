"""Standalone Caddy Prometheus scraper package.

This branch extracts only the Caddy scraper from the full server monitor, so
the package re-exports just what the scraper needs to run on its own.
"""

from __future__ import annotations

from .caddy_scraper import CaddyScrapeError, CaddyScraper
from .errors import CollectorError

__all__ = ["CaddyScrapeError", "CaddyScraper", "CollectorError"]
