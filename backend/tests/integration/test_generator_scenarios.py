"""End-to-end: generator scenario -> ingest -> normalization -> detection -> alert.

This is the test that proves the four services agree with each other. It
imports the generator package directly and pushes its output through the real
backend pipeline, so a change to either side that breaks the contract fails
here rather than being discovered by hand after `docker compose up`.

The generator lives in a sibling service directory, so it is added to sys.path
explicitly. In the running system these communicate over HTTP; the wire format
is identical.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models.alert import Alert
from app.schemas.event import RawEventIn
from app.services.ingest import ingest_events

GENERATOR_ROOT = Path(__file__).resolve().parents[3] / "generator"
if str(GENERATOR_ROOT) not in sys.path:
    sys.path.insert(0, str(GENERATOR_ROOT))

generator_available = GENERATOR_ROOT.exists()
pytestmark = pytest.mark.skipif(
    not generator_available, reason="generator service directory not found"
)

if generator_available:
    from generator import scenarios as gen_scenarios


# Scenario -> the detection rule it is designed to trigger. This mapping is the
# contract documented in docs/demo-scenarios.md.
EXPECTED_DETECTIONS: dict[str, str] = {
    "brute_force": "brute_force_authentication",
    "password_spray": "brute_force_authentication",
    "credential_compromise": "suspicious_login_after_failures",
    "port_scan": "port_scan",
    "network_sweep": "port_scan",
    "web_attack": "web_attack_indicators",
    "impossible_travel": "impossible_travel",
    "suspicious_powershell": "suspicious_powershell",
    "malware_execution": "malicious_file_hash",
    "privilege_escalation": "privilege_escalation",
}


def _ingest(db, raw_events: list[dict]):
    return ingest_events(db, [RawEventIn(**e) for e in raw_events])


def _alert_keys(db) -> set[str]:
    return set(db.execute(select(Alert.rule_key)).scalars().all())


@pytest.fixture
def seeded_all(seeded_rules):
    """Rules plus the synthetic IOC watchlist, exactly as the entrypoint seeds."""
    from app.cli.seed_detections import seed_iocs

    seed_iocs(seeded_rules)
    seeded_rules.commit()
    return seeded_rules


def test_every_scenario_has_a_documented_expected_detection():
    """A scenario nobody can demo is a scenario that will rot."""
    assert set(gen_scenarios.SCENARIOS) == set(EXPECTED_DETECTIONS), (
        "SCENARIOS and EXPECTED_DETECTIONS have drifted apart"
    )


@pytest.mark.parametrize("scenario_name", sorted(EXPECTED_DETECTIONS))
def test_scenario_triggers_its_detection(seeded_all, scenario_name):
    db = seeded_all
    expected_rule = EXPECTED_DETECTIONS[scenario_name]

    # Fixed seed so a failure is reproducible rather than a coin flip.
    rng = random.Random(f"test-{scenario_name}")
    events = gen_scenarios.SCENARIOS[scenario_name](rng)
    assert events, f"scenario {scenario_name} produced no events"

    outcome = _ingest(db, events)
    assert outcome.rejected == 0, f"{outcome.rejected} events failed normalization"
    assert outcome.stored == len(events)

    fired = _alert_keys(db)
    assert expected_rule in fired, (
        f"scenario '{scenario_name}' did not trigger '{expected_rule}'. "
        f"Rules that fired: {sorted(fired) or 'none'}"
    )


@pytest.mark.parametrize("seed", ["quiet-1", "quiet-2", "quiet-3", "quiet-4", "quiet-5"])
def test_benign_traffic_produces_no_alerts(seeded_all, seed):
    """The false-positive test.

    Ordinary activity must stay silent. A detection set that alerts on normal
    traffic is worse than none: analysts learn to ignore it.
    """
    db = seeded_all
    rng = random.Random(seed)
    outcome = _ingest(db, gen_scenarios.benign_batch(rng, 120))
    assert outcome.rejected == 0
    assert outcome.alerts_created == 0, (
        f"benign traffic raised alerts: {sorted(_alert_keys(db))}"
    )


def test_all_generator_events_survive_normalization(seeded_all):
    """Every source dialect the generator emits must have a working normalizer."""
    db = seeded_all
    rng = random.Random("coverage")
    batch = gen_scenarios.benign_batch(rng, 200)
    for scenario in gen_scenarios.SCENARIOS.values():
        batch.extend(scenario(rng))

    outcome = _ingest(db, batch)
    assert outcome.rejected == 0, f"{outcome.rejected} events could not be normalized"
    assert outcome.stored == len(batch)


def test_replayed_batch_does_not_duplicate_or_inflate(seeded_all):
    """The generator retries on timeout; a replay must be a no-op."""
    db = seeded_all
    rng = random.Random("replay")
    events = gen_scenarios.brute_force(rng)

    first = _ingest(db, events)
    second = _ingest(db, events)

    assert first.stored == len(events)
    assert second.stored == 0
    assert second.duplicates == len(events)

    alert = db.execute(
        select(Alert).where(Alert.rule_key == "brute_force_authentication")
    ).scalar_one()
    assert alert.event_count == len(events), "replay inflated the evidence count"
