-- Runs once, only when the postgres_data volume is first created.
-- Schema itself is owned by Alembic; this file is only for things a migration
-- cannot do portably (extensions need superuser at creation time).

-- pg_trgm powers fast case-insensitive substring search over event text
-- (usernames, hostnames, raw payload fields) via GIN trigram indexes.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- btree_gin lets a single GIN index mix scalar columns (severity, event_type)
-- with trigram/JSONB columns, which is what the event explorer filters on.
CREATE EXTENSION IF NOT EXISTS btree_gin;
