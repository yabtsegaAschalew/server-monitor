"""Shared exception types for the metric collection daemons."""


class CollectorError(Exception):
    """Base class for failures raised by a metric collector."""
