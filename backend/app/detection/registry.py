"""Detection rule registry.

Rules self-register via the `@register` decorator, which only runs when the
module defining the rule is imported. That import is therefore load-bearing,
and forgetting it is silent: the registry simply comes up empty and every
configured rule is reported as unimplemented.

That is exactly what happened in this project. `app.detection.rules` was
imported by the seeding CLI and by the test conftest, but by nothing in the
import graph that `uvicorn app.main:app` walks. The seed process (which had the
rules) wrote eight database rows; the API process (which did not) then logged
`detection.rule_not_implemented` for every one of them and evaluated none. The
test suite passed throughout, because the fixture performed the import the
application had forgotten.

The registry is now self-populating: any caller that asks for rules triggers the
import first. Registration can no longer depend on some other module having
been imported in the right order.
"""

from __future__ import annotations

import threading

from app.core.logging import get_logger
from app.detection.base import DetectionRule

logger = get_logger(__name__)

_REGISTRY: dict[str, type[DetectionRule]] = {}

# Guarded because the first request in a threadpool worker could otherwise race
# a concurrent import and observe a half-populated registry.
_LOAD_LOCK = threading.Lock()
_rules_loaded = False


def register(rule_cls: type[DetectionRule]) -> type[DetectionRule]:
    key = rule_cls.key
    existing = _REGISTRY.get(key)
    if existing is not None and existing is not rule_cls:
        raise ValueError(f"Duplicate detection rule key: {key!r}")
    _REGISTRY[key] = rule_cls
    return rule_cls


def load_rules() -> None:
    """Import every rule module so its `@register` decorator runs.

    Idempotent and safe to call from anywhere. The import is deferred to call
    time rather than module scope so this module stays free of a cycle with the
    rule modules, which import `register` from here.
    """
    global _rules_loaded
    if _rules_loaded:
        return
    with _LOAD_LOCK:
        if _rules_loaded:
            return
        # Set before importing: the rule modules call register() during their
        # own import, and must not re-enter this function.
        _rules_loaded = True
        import app.detection.rules  # noqa: F401  - importing runs @register

        logger.info("detection.rules_loaded", count=len(_REGISTRY),
                    keys=sorted(_REGISTRY))


def all_rules() -> dict[str, type[DetectionRule]]:
    load_rules()
    return dict(_REGISTRY)


def get_rule(key: str) -> type[DetectionRule] | None:
    load_rules()
    return _REGISTRY.get(key)


def registered_keys() -> frozenset[str]:
    """The keys the running process can actually evaluate."""
    load_rules()
    return frozenset(_REGISTRY)

