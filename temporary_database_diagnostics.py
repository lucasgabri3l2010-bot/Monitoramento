"""TEMPORARY, secret-safe database startup diagnostics.

Delete this module and the marked calls in ``migrate.py`` after the Railway
environment mismatch has been identified.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import unquote, urlsplit


DATABASE_VARIABLES = ("DATABASE_URL", "AIVEN_DATABASE_URL")


@dataclass(frozen=True)
class RawDatabaseEnvironment:
    """Raw values captured before config.py can load a dotenv file."""

    values: Mapping[str, Optional[str]]


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _candidate_for_parsing(raw_url: str) -> tuple[str, bool]:
    stripped = raw_url.strip()
    quoted = (
        len(stripped) >= 2
        and stripped[0] in ("'", '"')
        and stripped[-1] == stripped[0]
    )
    # This unwrapping is only for metadata parsing. The connection probe always
    # receives the complete, untouched value.
    return (stripped[1:-1] if quoted else stripped), quoted


def _safe_parsed_fields(raw_url: str) -> tuple[Optional[str], Optional[int], Optional[str], Optional[str], Optional[int]]:
    try:
        candidate, _ = _candidate_for_parsing(raw_url)
        parsed = urlsplit(candidate)
        host = parsed.hostname
        port = parsed.port
        username = unquote(parsed.username) if parsed.username is not None else None
        database = unquote(parsed.path[1:]) if parsed.path.startswith("/") else unquote(parsed.path)
        password_length = len(unquote(parsed.password)) if parsed.password is not None else None
        return host, port, username, database or None, password_length
    except (TypeError, ValueError, UnicodeError):
        return None, None, None, None, None


def capture_and_log_raw_environment(logger) -> RawDatabaseEnvironment:
    """Log only explicitly allowlisted metadata for both raw environment URLs."""
    values = {name: os.environ.get(name) for name in DATABASE_VARIABLES}

    for name in DATABASE_VARIABLES:
        raw_url = values[name]
        if raw_url is None:
            logger.info(
                "[TEMP DB DIAGNOSTIC] %s exists=no raw_length=0 "
                "password_length=unavailable leading_or_trailing_whitespace=no "
                "surrounding_quotes=no parsed_host=%r parsed_port=%r "
                "parsed_username=%r parsed_database=%r sha256=unavailable",
                name, None, None, None, None,
            )
            continue

        _, quoted = _candidate_for_parsing(raw_url)
        host, port, username, database, password_length = _safe_parsed_fields(raw_url)
        has_outer_whitespace = raw_url != raw_url.strip()
        logger.info(
            "[TEMP DB DIAGNOSTIC] %s exists=yes raw_length=%d "
            "password_length=%s leading_or_trailing_whitespace=%s "
            "surrounding_quotes=%s parsed_host=%r parsed_port=%r "
            "parsed_username=%r parsed_database=%r sha256=%s",
            name,
            len(raw_url),
            password_length if password_length is not None else "unavailable",
            _yes_no(has_outer_whitespace),
            _yes_no(quoted),
            host,
            port,
            username,
            database,
            _fingerprint(raw_url),
        )

    return RawDatabaseEnvironment(values=values)


def log_direct_connection_results(logger, snapshot: RawDatabaseEnvironment, timeout_seconds: int = 5) -> None:
    """Probe each untouched URL without logging connection exception details."""
    import psycopg2

    for name in DATABASE_VARIABLES:
        connection = None
        try:
            raw_url = snapshot.values[name]
            if raw_url is None:
                raise ValueError("missing database URL")
            connection = psycopg2.connect(raw_url, connect_timeout=timeout_seconds)
        except Exception:
            logger.info("[TEMP DB DIAGNOSTIC] %s direct connection: FAILED", name)
        else:
            logger.info("[TEMP DB DIAGNOSTIC] %s direct connection: OK", name)
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def _normalized_config_value(raw_url: str) -> str:
    value = raw_url.strip()
    if value.startswith("postgres://"):
        value = value.replace("postgres://", "postgresql://", 1)
    return value


def log_flask_sqlalchemy_selection(logger, app, snapshot: RawDatabaseEnvironment) -> None:
    """Identify the selected URI source and fingerprint, never the URI itself."""
    selected = app.config.get("SQLALCHEMY_DATABASE_URI")
    selected_text = str(selected) if selected is not None else ""
    original_database_url = snapshot.values.get("DATABASE_URL")
    current_database_url = os.environ.get("DATABASE_URL")

    if original_database_url is not None and selected_text == _normalized_config_value(original_database_url):
        source = "DATABASE_URL (process environment)"
    elif current_database_url is not None and selected_text == _normalized_config_value(current_database_url):
        source = "DATABASE_URL (loaded after initial environment capture; possible dotenv)"
    elif selected_text == "sqlite:///monitoramento.db":
        source = "Config built-in SQLite fallback"
    else:
        source = "another or overridden value"

    fingerprint = _fingerprint(selected_text) if selected is not None else "unavailable"
    logger.info(
        "[TEMP DB DIAGNOSTIC] SQLALCHEMY_DATABASE_URI source=%r sha256=%s",
        source,
        fingerprint,
    )
