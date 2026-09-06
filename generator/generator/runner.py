"""Generator main loop."""

from __future__ import annotations

import logging
import random
import signal
import sys
import time
from types import FrameType

import structlog

from generator.client import IngestClient
from generator.config import GeneratorSettings
from generator.scenarios import SCENARIOS, benign_batch

logger = structlog.get_logger(__name__)

_shutdown = False


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    global _shutdown
    logger.info("generator.shutdown_requested", signal=signum)
    _shutdown = True


def configure_logging(level: str) -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout,
                        level=getattr(logging, level.upper(), logging.INFO))
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )


def build_rng(seed: str) -> random.Random:
    """Seeded RNG makes a demo reproducible; empty seed makes it varied."""
    return random.Random(seed) if seed else random.Random()


def run() -> int:
    settings = GeneratorSettings()  # type: ignore[call-arg]
    configure_logging(settings.LOG_LEVEL)

    if not settings.GENERATOR_ENABLED:
        logger.info("generator.disabled")
        # Sleep rather than exit: an exiting container under `restart:
        # unless-stopped` would loop forever and look like a crash.
        while not _shutdown:
            time.sleep(5)
        return 0

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    rng = build_rng(settings.GENERATOR_SEED)
    client = IngestClient(settings.ingest_url, settings.INGEST_API_KEY)

    health_url = f"{settings.GENERATOR_BACKEND_URL.rstrip('/')}/api/v1/health"
    logger.info("generator.waiting_for_backend", url=health_url)
    if not client.wait_for_backend(health_url):
        logger.error("generator.backend_unreachable", url=health_url)
        return 1

    logger.info(
        "generator.started",
        events_per_batch=settings.events_per_batch,
        interval_seconds=settings.GENERATOR_BATCH_INTERVAL_SECONDS,
        attack_probability=settings.GENERATOR_ATTACK_PROBABILITY,
        seeded=bool(settings.GENERATOR_SEED),
    )

    batches = 0
    while not _shutdown:
        started = time.monotonic()
        batch = benign_batch(rng, settings.events_per_batch)

        scenario_name = None
        if rng.random() < settings.GENERATOR_ATTACK_PROBABILITY:
            scenario_name = rng.choice(list(SCENARIOS))
            batch.extend(SCENARIOS[scenario_name](rng))

        result = client.send(batch)
        batches += 1
        if result:
            logger.info(
                "generator.batch_sent",
                batch=batches,
                events=len(batch),
                scenario=scenario_name,
                stored=result.get("stored"),
                alerts_created=result.get("alerts_created"),
            )

        elapsed = time.monotonic() - started
        remaining = settings.GENERATOR_BATCH_INTERVAL_SECONDS - elapsed
        # Sleep in slices so SIGTERM is honoured promptly instead of after a
        # full interval, which would make `docker compose down` feel hung.
        while remaining > 0 and not _shutdown:
            nap = min(0.5, remaining)
            time.sleep(nap)
            remaining -= nap

    client.close()
    logger.info("generator.stopped", batches_sent=batches)
    return 0
