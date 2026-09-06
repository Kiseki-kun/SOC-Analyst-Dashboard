"""Application configuration.

Every value is sourced from the environment. Nothing here carries a usable
default for a secret: `SECRET_KEY` and `INGEST_API_KEY` have no default at all,
so a misconfigured deployment fails loudly at import time instead of silently
running on a predictable key.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The demo passwords documented in .env.example. That file is committed, so
# these are public the moment the repository is. Kept at module level and not
# as a class attribute: pydantic converts leading-underscore class attributes
# into private-attribute descriptors, which a drift test cannot read.
PUBLISHED_DEMO_PASSWORDS = frozenset({
    "ChangeMe_Admin_123!",
    "ChangeMe_Analyst_123!",
    "ChangeMe_Responder_123!",
    "ChangeMe_Viewer_123!",
})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ---------------------------------------------------------------- app
    ENVIRONMENT: Literal["development", "test", "production"] = "development"
    LOG_LEVEL: str = "INFO"
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "SOC Analyst Dashboard"

    # ----------------------------------------------------------- database
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "soc"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "socdb"

    # Set directly only by the test suite (SQLite). In every other context the
    # URL is assembled from the POSTGRES_* parts above.
    DATABASE_URL_OVERRIDE: str | None = None

    # ----------------------------------------------------------- security
    SECRET_KEY: str
    INGEST_API_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    BCRYPT_ROUNDS: int = 12
    COOKIE_SECURE: bool = False
    REFRESH_COOKIE_NAME: str = "soc_refresh_token"

    CORS_ORIGINS: str = "http://localhost:54173"

    # ------------------------------------------------------------ tuning
    EVENT_RETENTION_DAYS: int = 7
    MAX_INGEST_BATCH_SIZE: int = 500
    # Hard ceiling on request bodies. Schema limits alone are not enough: the
    # ingest schema permits 500 events x 64 keys x 4096 characters, roughly
    # 125 MB, and Pydantic only rejects that AFTER the whole body has been
    # read and parsed into memory. A realistic 500-event batch is well under
    # 1 MB, so 4 MB is generous.
    MAX_REQUEST_BODY_BYTES: int = 4 * 1024 * 1024
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 200

    # --------------------------------------------------------- demo seed
    SEED_DEMO_USERS: bool = False
    DEMO_ADMIN_EMAIL: str = "admin@soc.example.com"
    DEMO_ADMIN_PASSWORD: str = ""
    DEMO_ANALYST_EMAIL: str = "analyst@soc.example.com"
    DEMO_ANALYST_PASSWORD: str = ""
    DEMO_RESPONDER_EMAIL: str = "responder@soc.example.com"
    DEMO_RESPONDER_PASSWORD: str = ""
    DEMO_VIEWER_EMAIL: str = "viewer@soc.example.com"
    DEMO_VIEWER_PASSWORD: str = ""

    # ------------------------------------------------------------ checks
    @field_validator("SECRET_KEY", "INGEST_API_KEY")
    @classmethod
    def _reject_placeholder_secrets(cls, value: str, info) -> str:
        """Refuse to boot on a shipped placeholder or a trivially short key.

        A weak signing key is not a cosmetic problem: anyone who guesses it can
        mint a valid admin token. Failing at startup is the correct behaviour.
        """
        if len(value) < 32:
            raise ValueError(
                f"{info.field_name} must be at least 32 characters. "
                "Generate one with: python -c \"import secrets; "
                "print(secrets.token_urlsafe(64))\""
            )
        if value.startswith("CHANGE_ME"):
            raise ValueError(
                f"{info.field_name} is still the placeholder from .env.example. "
                "Generate a real value before starting the stack."
            )
        return value

    @field_validator("POSTGRES_PASSWORD")
    @classmethod
    def _require_database_password(cls, value: str, info) -> str:
        """Refuse an empty database password outside the test environment.

        An empty value here means .env was not loaded. Failing at startup with
        a clear message beats the alternative: a connection attempt that fails
        later with an authentication error nobody traces back to configuration.
        """
        if not value.strip():
            raise ValueError(
                "POSTGRES_PASSWORD is empty. This almost always means .env was "
                "not created or not loaded - run scripts/init-env.ps1."
            )
        if value.startswith("change_me"):
            raise ValueError(
                "POSTGRES_PASSWORD is still the placeholder from .env.example."
            )
        return value

    @field_validator("BCRYPT_ROUNDS")
    @classmethod
    def _sane_bcrypt_cost(cls, value: int) -> int:
        if not 10 <= value <= 16:
            raise ValueError("BCRYPT_ROUNDS must be between 10 and 16")
        return value

    @computed_field  # type: ignore[prop-decorator]
    @property
    def DATABASE_URL(self) -> str:
        if self.DATABASE_URL_OVERRIDE:
            return self.DATABASE_URL_OVERRIDE
        return (
            f"postgresql+psycopg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cors_origin_list(self) -> list[str]:
        """Explicit origin allow-list.

        Never a wildcard: the API sends credentialed requests (the refresh
        cookie), and `Access-Control-Allow-Origin: *` is invalid with
        credentials — browsers reject it, and permitting it would expose the
        API to any origin.
        """
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @model_validator(mode="after")
    def _no_published_demo_credentials_in_production(self) -> Settings:
        if self.ENVIRONMENT != "production" or not self.SEED_DEMO_USERS:
            return self
        offenders = [
            name
            for name in (
                "DEMO_ADMIN_PASSWORD",
                "DEMO_ANALYST_PASSWORD",
                "DEMO_RESPONDER_PASSWORD",
                "DEMO_VIEWER_PASSWORD",
            )
            if getattr(self, name) in PUBLISHED_DEMO_PASSWORDS
        ]
        if offenders:
            raise ValueError(
                "Refusing to start: ENVIRONMENT=production with SEED_DEMO_USERS=true "
                f"and the published .env.example password still set for {', '.join(offenders)}. "
                "These passwords are in a public repository. Change them, or set "
                "SEED_DEMO_USERS=false."
            )
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    """Cached accessor so configuration is parsed and validated exactly once."""
    return Settings()  # type: ignore[call-arg]


def build_test_settings(**overrides) -> Settings:
    """Settings for the test suite: in-memory-ish SQLite, throwaway secrets."""
    base = {
        "ENVIRONMENT": "test",
        "SECRET_KEY": secrets.token_urlsafe(48),
        "INGEST_API_KEY": secrets.token_urlsafe(48),
        # Lowest cost the validator permits. Tests hash many passwords and
        # cost 12 would add minutes of pure CPU for no added assurance.
        "BCRYPT_ROUNDS": 10,
        "DATABASE_URL_OVERRIDE": "sqlite+pysqlite:///:memory:",
        # Never used - the SQLite override wins - but the validator requires a
        # non-empty value, and that requirement is the point.
        "POSTGRES_PASSWORD": "test-only-not-used",
        "SEED_DEMO_USERS": False,
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]
