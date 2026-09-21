"""Low-overhead, process-local aggregate telemetry for the web service.

The counters deliberately retain only route templates and numeric aggregates.
Request bodies, headers, query strings, tokens and response contents are never
stored. Each Gunicorn worker emits its own periodic aggregate log entry.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Iterable, Iterator

from flask import g, has_request_context
from sqlalchemy import event
from sqlalchemy.engine import Engine


EMIT_INTERVAL_SECONDS = 60.0


def _new_endpoint_metrics() -> dict:
    return {
        "requests": 0,
        "request_bytes": 0,
        "response_bytes": 0,
        "duration_ms_total": 0.0,
        "duration_ms_max": 0.0,
        "sql_queries": 0,
        "status_codes": defaultdict(int),
    }


class AggregateTelemetry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._window_started_at = datetime.now(timezone.utc)
        self._last_emit_monotonic = time.monotonic()
        self._endpoints = defaultdict(_new_endpoint_metrics)
        self._release_downloads = defaultdict(lambda: {"requests": 0, "backend_bytes": 0})

    def reset(self) -> None:
        with self._lock:
            self._window_started_at = datetime.now(timezone.utc)
            self._last_emit_monotonic = time.monotonic()
            self._endpoints.clear()
            self._release_downloads.clear()

    def record_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        request_bytes: int,
        response_bytes: int,
        duration_ms: float,
        sql_queries: int,
    ) -> None:
        key = f"{method.upper()} {endpoint}"
        with self._lock:
            item = self._endpoints[key]
            item["requests"] += 1
            item["request_bytes"] += max(0, int(request_bytes or 0))
            item["response_bytes"] += max(0, int(response_bytes or 0))
            item["duration_ms_total"] += max(0.0, float(duration_ms or 0.0))
            item["duration_ms_max"] = max(item["duration_ms_max"], float(duration_ms or 0.0))
            item["sql_queries"] += max(0, int(sql_queries or 0))
            item["status_codes"][str(status_code)] += 1

    def record_release_attempt(self, mode: str) -> None:
        with self._lock:
            self._release_downloads[mode]["requests"] += 1

    def record_release_bytes(self, mode: str, byte_count: int) -> None:
        with self._lock:
            self._release_downloads[mode]["backend_bytes"] += max(0, int(byte_count or 0))

    def snapshot(self, reset: bool = False) -> dict:
        with self._lock:
            now = datetime.now(timezone.utc)
            endpoints = deepcopy(dict(self._endpoints))
            releases = deepcopy(dict(self._release_downloads))

            for item in endpoints.values():
                requests = item["requests"]
                item["duration_ms_total"] = round(item["duration_ms_total"], 3)
                item["duration_ms_max"] = round(item["duration_ms_max"], 3)
                item["duration_ms_avg"] = round(
                    item["duration_ms_total"] / requests, 3
                ) if requests else 0.0
                item["status_codes"] = dict(item["status_codes"])

            result = {
                "window_started_at": self._window_started_at.isoformat(),
                "window_ended_at": now.isoformat(),
                "endpoints": endpoints,
                "release_downloads": releases,
            }

            if reset:
                self._window_started_at = now
                self._last_emit_monotonic = time.monotonic()
                self._endpoints.clear()
                self._release_downloads.clear()

            return result

    def maybe_emit(self, logger) -> None:
        if (time.monotonic() - self._last_emit_monotonic) < EMIT_INTERVAL_SECONDS:
            return
        snapshot = self.snapshot(reset=True)
        logger.info(
            "[TELEMETRY_AGGREGATE] %s",
            json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")),
        )


telemetry = AggregateTelemetry()


def _count_sql_query(*_args, **_kwargs) -> None:
    if has_request_context():
        g.telemetry_sql_queries = int(getattr(g, "telemetry_sql_queries", 0)) + 1


def install_sql_query_counter() -> None:
    """Installs one global SQLAlchemy listener, even if modules are re-imported."""
    if not event.contains(Engine, "before_cursor_execute", _count_sql_query):
        event.listen(Engine, "before_cursor_execute", _count_sql_query)


def response_size_bytes(response) -> int:
    header_value = response.headers.get("Content-Length")
    if header_value:
        try:
            return max(0, int(header_value))
        except (TypeError, ValueError):
            pass
    if response.is_streamed or response.direct_passthrough:
        return 0
    calculated = response.calculate_content_length()
    return max(0, int(calculated or 0))


def track_release_stream(chunks: Iterable[bytes], mode: str = "stream") -> Iterator[bytes]:
    """Counts bytes actually yielded without retaining binary content in memory."""
    byte_count = 0
    try:
        for chunk in chunks:
            if chunk:
                byte_count += len(chunk)
            yield chunk
    finally:
        telemetry.record_release_bytes(mode, byte_count)
