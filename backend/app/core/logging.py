"""Structured logging.

JSON in production so logs are machine-parseable; human-readable colourless
console output in development. A redaction processor runs on every record —
this is a security project, and a stray `password=` in a log line is exactly
the kind of finding that discredits one.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

# Keys whose values are replaced before a record is rendered, at any depth.
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "hashed_password",
        "password_hash",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "secret",
        "secret_key",
        "api_key",
        "ingest_api_key",
        "cookie",
        "set-cookie",
    }
)

_REDACTED = "***redacted***"


def _redact(_logger: Any, _name: str, event_dict: dict) -> dict:
    """Recursively blank out sensitive values in the event dict."""

    def scrub(value: Any, depth: int = 0) -> Any:
        if depth > 6:  # guard against pathological nesting
            return value
        if isinstance(value, dict):
            return {
                k: (_REDACTED if k.lower() in _SENSITIVE_KEYS else scrub(v, depth + 1))
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [scrub(v, depth + 1) for v in value]
        return value

    return scrub(event_dict)  # type: ignore[return-value]


def configure_logging(level: str = "INFO", json_output: bool = False) -> None:
    """Install the structlog pipeline. Safe to call more than once."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
        force=True,
    )
    # uvicorn installs its own handlers; let them propagate into ours instead
    # of duplicating every line.
    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = True

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact,
    ]
    processors.append(
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
