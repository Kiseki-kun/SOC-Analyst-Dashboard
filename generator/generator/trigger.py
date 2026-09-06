"""Fire one scenario on demand.

    docker compose exec generator python -m generator.trigger brute_force

Used for demonstrations, so a specific detection can be shown on cue instead of
waiting for the random loop to pick it.
"""

from __future__ import annotations

import sys

import structlog

from generator.client import IngestClient
from generator.config import GeneratorSettings
from generator.runner import build_rng, configure_logging
from generator.scenarios import SCENARIOS

logger = structlog.get_logger(__name__)


def main(argv: list[str]) -> int:
    settings = GeneratorSettings()  # type: ignore[call-arg]
    configure_logging(settings.LOG_LEVEL)

    if len(argv) < 2 or argv[1] in {"-h", "--help", "list"}:
        print("Usage: python -m generator.trigger <scenario> [repeat]")
        print("\nAvailable scenarios:")
        for name, fn in sorted(SCENARIOS.items()):
            summary = (fn.__doc__ or "").strip().splitlines()[0]
            print(f"  {name:24} {summary}")
        return 0 if len(argv) >= 2 else 1

    name = argv[1]
    if name not in SCENARIOS:
        print(f"Unknown scenario: {name}", file=sys.stderr)
        print(f"Available: {', '.join(sorted(SCENARIOS))}", file=sys.stderr)
        return 1

    repeat = int(argv[2]) if len(argv) > 2 else 1
    rng = build_rng(settings.GENERATOR_SEED)
    client = IngestClient(settings.ingest_url, settings.INGEST_API_KEY)

    total_alerts = 0
    for run_index in range(repeat):
        events = SCENARIOS[name](rng)
        result = client.send(events)
        if result is None:
            print(f"Run {run_index + 1}: ingest failed - see logs", file=sys.stderr)
            client.close()
            return 1
        total_alerts += result.get("alerts_created", 0)
        print(
            f"Run {run_index + 1}: sent {len(events)} events, "
            f"stored {result.get('stored')}, "
            f"alerts created {result.get('alerts_created')}, "
            f"alerts updated {result.get('alerts_updated')}"
        )

    client.close()
    print(f"\nScenario '{name}' complete. Total new alerts: {total_alerts}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
