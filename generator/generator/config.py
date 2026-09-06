"""Generator configuration."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class GeneratorSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    GENERATOR_ENABLED: bool = True
    GENERATOR_BACKEND_URL: str = "http://backend:8000"
    INGEST_API_KEY: str

    # Baseline benign events per second. Deliberately modest: this project
    # targets machines with limited disk, and an unthrottled generator will
    # fill a database far faster than anyone will look at it.
    GENERATOR_EVENTS_PER_SECOND: float = Field(default=2.0, gt=0, le=200)
    GENERATOR_BATCH_INTERVAL_SECONDS: float = Field(default=5.0, ge=1, le=300)
    GENERATOR_ATTACK_PROBABILITY: float = Field(default=0.12, ge=0.0, le=1.0)

    # Empty means non-deterministic. Set it to make a demo reproducible.
    GENERATOR_SEED: str = ""

    LOG_LEVEL: str = "INFO"

    @property
    def ingest_url(self) -> str:
        return f"{self.GENERATOR_BACKEND_URL.rstrip('/')}/api/v1/ingest/events"

    @property
    def events_per_batch(self) -> int:
        return max(1, int(self.GENERATOR_EVENTS_PER_SECOND * self.GENERATOR_BATCH_INTERVAL_SECONDS))
