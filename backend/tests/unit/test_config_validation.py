"""Configuration must fail loudly, never silently start misconfigured.

These exist because a missing .env once produced an empty POSTGRES_PASSWORD,
which surfaced as an opaque PostgreSQL initdb error several layers away from
the actual cause.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def _base(**overrides) -> dict:
    values = {
        "SECRET_KEY": "s" * 64,
        "INGEST_API_KEY": "i" * 48,
        "POSTGRES_PASSWORD": "pytest-fixture-value-not-a-secret",
    }
    values.update(overrides)
    return values


def test_valid_configuration_is_accepted():
    settings = Settings(**_base())
    assert settings.POSTGRES_PASSWORD == "pytest-fixture-value-not-a-secret"


@pytest.mark.parametrize("blank", ["", "   "])
def test_empty_database_password_is_rejected(blank):
    with pytest.raises(ValidationError) as exc:
        Settings(**_base(POSTGRES_PASSWORD=blank))
    assert "POSTGRES_PASSWORD" in str(exc.value)


def test_placeholder_database_password_is_rejected():
    with pytest.raises(ValidationError):
        Settings(**_base(POSTGRES_PASSWORD="change_me_in_your_local_env_file"))


@pytest.mark.parametrize("field", ["SECRET_KEY", "INGEST_API_KEY"])
def test_short_secrets_are_rejected(field):
    with pytest.raises(ValidationError) as exc:
        Settings(**_base(**{field: "too-short"}))
    assert field in str(exc.value)


@pytest.mark.parametrize("field", ["SECRET_KEY", "INGEST_API_KEY"])
def test_placeholder_secrets_are_rejected(field):
    with pytest.raises(ValidationError):
        Settings(**_base(**{field: "CHANGE_ME_generate_a_64_byte_urlsafe_random_string"}))


def test_database_url_is_assembled_from_the_parts():
    settings = Settings(**_base(POSTGRES_USER="soc", POSTGRES_DB="socdb",
                                POSTGRES_HOST="postgres", POSTGRES_PORT=5432))
    assert settings.DATABASE_URL == "postgresql+psycopg://soc:pytest-fixture-value-not-a-secret@postgres:5432/socdb"


def test_override_wins_for_tests():
    settings = Settings(**_base(DATABASE_URL_OVERRIDE="sqlite+pysqlite:///:memory:"))
    assert settings.DATABASE_URL.startswith("sqlite")


def test_cors_origins_are_split_and_never_wildcarded():
    settings = Settings(**_base(CORS_ORIGINS="http://a.example, http://b.example"))
    assert settings.cors_origin_list == ["http://a.example", "http://b.example"]
    assert "*" not in settings.cors_origin_list


class TestPublishedDemoCredentialsInProduction:
    """The demo passwords are committed in .env.example, so they are public.

    Seeding them into a production deployment would hand anyone who reads the
    repository an administrator account. Neither `ENVIRONMENT=production` nor
    `SEED_DEMO_USERS=true` is wrong alone, so only the combination is refused —
    a guard that fired on either half would be turned off rather than obeyed.
    """

    PUBLISHED = "ChangeMe_Admin_123!"

    def test_production_seeding_with_a_published_password_is_refused(self):
        with pytest.raises(ValidationError) as exc:
            Settings(**_base(
                ENVIRONMENT="production",
                SEED_DEMO_USERS=True,
                DEMO_ADMIN_PASSWORD=self.PUBLISHED,
            ))
        message = str(exc.value)
        assert "DEMO_ADMIN_PASSWORD" in message
        assert "public repository" in message

    def test_every_published_demo_password_is_caught(self):
        published = {
            "DEMO_ADMIN_PASSWORD": "ChangeMe_Admin_123!",
            "DEMO_ANALYST_PASSWORD": "ChangeMe_Analyst_123!",
            "DEMO_RESPONDER_PASSWORD": "ChangeMe_Responder_123!",
            "DEMO_VIEWER_PASSWORD": "ChangeMe_Viewer_123!",
        }
        for field, value in published.items():
            with pytest.raises(ValidationError) as exc:
                Settings(**_base(
                    ENVIRONMENT="production", SEED_DEMO_USERS=True, **{field: value},
                ))
            assert field in str(exc.value)

    def test_the_guard_names_every_offending_field_at_once(self):
        with pytest.raises(ValidationError) as exc:
            Settings(**_base(
                ENVIRONMENT="production",
                SEED_DEMO_USERS=True,
                DEMO_ADMIN_PASSWORD="ChangeMe_Admin_123!",
                DEMO_VIEWER_PASSWORD="ChangeMe_Viewer_123!",
            ))
        message = str(exc.value)
        assert "DEMO_ADMIN_PASSWORD" in message
        assert "DEMO_VIEWER_PASSWORD" in message

    def test_development_may_still_use_the_documented_defaults(self):
        settings = Settings(**_base(
            ENVIRONMENT="development",
            SEED_DEMO_USERS=True,
            DEMO_ADMIN_PASSWORD=self.PUBLISHED,
        ))
        assert settings.SEED_DEMO_USERS is True

    def test_production_without_seeding_is_unaffected(self):
        settings = Settings(**_base(
            ENVIRONMENT="production",
            SEED_DEMO_USERS=False,
            DEMO_ADMIN_PASSWORD=self.PUBLISHED,
        ))
        assert settings.is_production is True

    def test_production_seeding_with_changed_passwords_is_allowed(self):
        settings = Settings(**_base(
            ENVIRONMENT="production",
            SEED_DEMO_USERS=True,
            DEMO_ADMIN_PASSWORD="something-the-operator-actually-chose",
        ))
        assert settings.SEED_DEMO_USERS is True

    def test_the_guard_list_matches_the_committed_env_example(self):
        """If .env.example changes a demo password, this guard goes stale.

        The check is only as good as its list, and nothing else would notice
        the two drifting apart.
        """
        from pathlib import Path

        from app.core.config import PUBLISHED_DEMO_PASSWORDS

        env_example = Path(__file__).resolve().parents[2].parent / ".env.example"
        if not env_example.exists():  # pragma: no cover - repo layout guard
            pytest.skip(f"{env_example} not found")

        documented = set()
        for line in env_example.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("DEMO_") and "PASSWORD" in line and "=" in line:
                documented.add(line.split("=", 1)[1].strip())

        assert documented, "no demo passwords found in .env.example"
        guarded = set(PUBLISHED_DEMO_PASSWORDS)
        assert documented <= guarded, (
            f".env.example documents passwords the guard does not know: "
            f"{documented - guarded}"
        )
