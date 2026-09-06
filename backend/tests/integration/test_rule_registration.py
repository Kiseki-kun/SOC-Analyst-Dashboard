"""Regression tests for detection-rule registration in the RUNTIME import path.

Why these exist
---------------
Every rule was implemented, tested and passing, yet the running API evaluated
none of them. `app.detection.rules` — the import whose side effect is running
each `@register` decorator — was imported by the seeding CLI and by
`tests/conftest.py`, but by nothing in the graph that `uvicorn app.main:app`
loads. The seed process wrote eight rule rows; the API process had an empty
registry and logged `detection.rule_not_implemented` once per rule per batch.

The existing suite could not catch this: the `seeded_rules` fixture performs the
import itself, so the tests exercised a registry the application never had.

These tests deliberately avoid that fixture. Several run in a SUBPROCESS with a
clean interpreter, so nothing a previous import did can mask the result.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from sqlalchemy import select

from app.detection.registry import all_rules, registered_keys
from app.models.detection import DetectionRule as DetectionRuleModel

BACKEND_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_KEYS = {
    "brute_force_authentication",
    "impossible_travel",
    "malicious_file_hash",
    "port_scan",
    "privilege_escalation",
    "suspicious_login_after_failures",
    "suspicious_powershell",
    "web_attack_indicators",
}


def _run_in_clean_interpreter(body: str) -> str:
    """Execute `body` in a fresh interpreter with the app importable.

    A subprocess is the only way to prove what a cold process sees: inside
    pytest, conftest has already imported the rules.
    """
    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": str(BACKEND_ROOT),
            "PYTHONDONTWRITEBYTECODE": "1",
            "SECRET_KEY": "x" * 64,
            "INGEST_API_KEY": "y" * 48,
            "POSTGRES_PASSWORD": "not-used-by-this-test",
            "ENVIRONMENT": "test",
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(body)],
        cwd=str(BACKEND_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"clean interpreter failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result.stdout


# --------------------------------------------------------------- the core case
def test_importing_app_main_registers_every_rule():
    """The exact import uvicorn performs must populate the registry.

    This is the test that would have caught the original defect.
    """
    output = _run_in_clean_interpreter(
        """
        import importlib
        module = importlib.import_module("app.main")
        getattr(module, "app")              # PEP 562 hook, as uvicorn does
        from app.detection.registry import all_rules
        print(",".join(sorted(all_rules())))
        """
    )
    keys = set(output.strip().splitlines()[-1].split(","))
    assert keys == EXPECTED_KEYS, f"uvicorn's import path registers {keys or 'nothing'}"


def test_importing_only_the_registry_registers_every_rule():
    """The registry must be self-populating, not dependent on import order."""
    output = _run_in_clean_interpreter(
        """
        from app.detection.registry import all_rules
        print(",".join(sorted(all_rules())))
        """
    )
    assert set(output.strip().splitlines()[-1].split(",")) == EXPECTED_KEYS


def test_importing_only_the_detection_engine_registers_every_rule():
    output = _run_in_clean_interpreter(
        """
        import app.services.detection_engine  # noqa: F401
        from app.detection.registry import all_rules
        print(",".join(sorted(all_rules())))
        """
    )
    assert set(output.strip().splitlines()[-1].split(",")) == EXPECTED_KEYS


def test_ingest_router_import_path_registers_every_rule():
    """The ingest endpoint is what evaluates events; its chain must load rules."""
    output = _run_in_clean_interpreter(
        """
        import app.api.v1.routers.ingest  # noqa: F401
        from app.detection.registry import all_rules
        print(",".join(sorted(all_rules())))
        """
    )
    assert set(output.strip().splitlines()[-1].split(",")) == EXPECTED_KEYS


def test_detections_router_reports_rules_as_implemented():
    """The admin API's `implemented` flag comes from the same registry."""
    output = _run_in_clean_interpreter(
        """
        import app.api.v1.routers.detections  # noqa: F401
        from app.detection.registry import get_rule
        print(get_rule("brute_force_authentication") is not None)
        """
    )
    assert output.strip().splitlines()[-1] == "True"


# ---------------------------------------------------------------- cold start
def test_registry_self_loads_in_a_process_that_imports_nothing_else():
    """The lazy-load path, proven from a genuinely cold interpreter.

    Done in a subprocess rather than by clearing the registry in-process:
    clearing it does not re-run the decorators, because the rule modules stay
    in sys.modules. An in-process "reset" would silently test nothing.
    """
    output = _run_in_clean_interpreter(
        """
        import sys
        assert "app.detection.rules" not in sys.modules
        from app.detection.registry import registered_keys
        keys = registered_keys()
        assert "app.detection.rules" in sys.modules, "lazy import did not happen"
        print(",".join(sorted(keys)))
        """
    )
    assert set(output.strip().splitlines()[-1].split(",")) == EXPECTED_KEYS


# ------------------------------------------------------------- key agreement
def test_seeded_database_keys_all_have_implementations(seeded_rules):
    """Catches drift between the rule rows and the code that implements them."""
    db = seeded_rules
    seeded = set(db.execute(select(DetectionRuleModel.rule_key)).scalars().all())
    implemented = registered_keys()
    unimplemented = sorted(seeded - implemented)
    assert not unimplemented, (
        f"database has rules with no implementation: {unimplemented}"
    )
    assert seeded == EXPECTED_KEYS


def test_every_implemented_rule_gets_a_database_row(seeded_rules):
    db = seeded_rules
    seeded = set(db.execute(select(DetectionRuleModel.rule_key)).scalars().all())
    assert registered_keys() - seeded == set()


def test_rule_keys_are_unique_and_non_empty():
    for key, cls in all_rules().items():
        assert key, f"{cls.__name__} has an empty key"
        assert cls.key == key, f"{cls.__name__} key mismatch: {cls.key!r} != {key!r}"


# ------------------------------------------- the behaviour behind the symptom
def test_ingest_evaluates_every_enabled_rule(seeded_rules):
    """The engine must actually RUN all eight rules, not skip them.

    `rules_run` is incremented only after a rule's implementation is found and
    evaluated; an unimplemented rule short-circuits before it. Asserting on this
    counter is stronger than asserting on a log line, and does not depend on
    logging configuration - an earlier version of this test asserted the absence
    of a log record and passed vacuously because nothing was being captured.
    """
    from app.models.event import SecurityEvent
    from app.schemas.event import RawEventIn
    from app.services.detection_engine import run_detections
    from app.services.normalization import normalize
    from tests import factories

    db = seeded_rules
    events = []
    for raw in [factories.failed_login("203.0.113.201", "victim") for _ in range(12)]:
        normalized = normalize(RawEventIn(**raw))
        event = SecurityEvent(
            event_uid=normalized.event_uid,
            timestamp=normalized.timestamp,
            source=normalized.source,
            event_type=normalized.event_type.value,
            action=normalized.action,
            outcome=normalized.outcome.value,
            severity=normalized.severity.value,
            message=normalized.message,
            src_ip=normalized.src_ip,
            username=normalized.username,
            raw=normalized.raw,
        )
        db.add(event)
        events.append(event)
    db.flush()

    outcome = run_detections(db, events)
    assert outcome.rules_run == len(EXPECTED_KEYS), (
        f"only {outcome.rules_run} of {len(EXPECTED_KEYS)} rules were evaluated"
    )
    assert outcome.rules_failed == 0
    assert outcome.alerts_created == 1


def test_ingest_pipeline_creates_an_alert(seeded_rules):
    """The consequence: with the registry populated, ingest produces alerts."""
    from app.models.alert import Alert
    from app.schemas.event import RawEventIn
    from app.services.ingest import ingest_events
    from tests import factories

    outcome = ingest_events(
        seeded_rules,
        [RawEventIn(**factories.failed_login("203.0.113.202", "victim")) for _ in range(12)],
    )
    assert outcome.alerts_created == 1
    alert = seeded_rules.execute(
        select(Alert).where(Alert.src_ip == "203.0.113.202")
    ).scalar_one()
    assert alert.rule_key == "brute_force_authentication"


# ------------------------------------------------------------ startup coverage
def test_startup_coverage_reports_every_rule_as_registered():
    """Startup states coverage explicitly, so zero rules is impossible to miss."""
    from app.core.config import build_test_settings
    from app.main import check_detection_coverage

    coverage = check_detection_coverage(build_test_settings())
    assert set(coverage.registered) == EXPECTED_KEYS
    assert coverage.healthy


def test_startup_coverage_is_unhealthy_when_the_registry_is_empty(monkeypatch):
    """An empty registry is an outage, and the check must say so."""
    from app.core.config import build_test_settings
    from app.main import check_detection_coverage

    monkeypatch.setattr(
        "app.detection.registry.registered_keys", lambda: frozenset(), raising=True
    )
    coverage = check_detection_coverage(build_test_settings())
    assert coverage.registered == ()
    assert not coverage.healthy


def test_startup_coverage_flags_a_database_rule_with_no_implementation():
    """The exact production failure mode, asserted on directly."""
    from app.main import DetectionCoverage

    registered = frozenset({"brute_force_authentication"})
    enabled = frozenset({"brute_force_authentication", "a_rule_nobody_wrote"})
    coverage = DetectionCoverage(
        registered=tuple(sorted(registered)),
        enabled_in_database=tuple(sorted(enabled)),
        missing_implementations=tuple(sorted(enabled - registered)),
        implemented_but_not_enabled=tuple(sorted(registered - enabled)),
    )
    assert coverage.missing_implementations == ("a_rule_nobody_wrote",)
    assert not coverage.healthy


@pytest.mark.parametrize("expected_key", sorted(EXPECTED_KEYS))
def test_each_documented_rule_is_registered(expected_key):
    assert expected_key in registered_keys()
