# SOC Analyst Dashboard

A working Security Operations Center platform that reproduces the daily workflow
of a junior-to-mid-level SOC analyst: synthetic telemetry is ingested,
normalized, evaluated by a rule-based detection engine, raised as alerts,
investigated, escalated into incidents, and closed with a documented resolution
— under role-based access control, with an append-only audit trail throughout.

> **Everything here is synthetic.** No real credentials, hosts, IP addresses,
> malware, or personal data appear anywhere. All addresses come from ranges IANA
> reserves for documentation (RFC 5737) or RFC 1918 private space; malicious
> domains use the reserved `.invalid` TLD; every file hash is invented. Every
> "response action" is simulated and recorded only inside this application's own
> database — there is no code path from this system to a firewall, a directory
> service, or an endpoint agent.

## Why this project exists

Most cybersecurity portfolio projects are dashboards: they render a chart of
numbers someone made up. This one is built the other way round — the data model,
the detection engine and the workflow came first, and the interface displays
what they produce. Every figure on the dashboard traces to a row in the
database. When no incident has been resolved yet, the mean-time-to-resolve tile
reads "Not yet measured" rather than a fabricated zero.

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript (strict), Vite, Tailwind CSS, TanStack Query, Recharts |
| Backend | Python 3.13, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic |
| Database | PostgreSQL 16 |
| Telemetry | Purpose-built synthetic generator service |
| Runtime | Docker + Docker Compose |

## Quick start

Requires Docker Desktop. Nothing else — Python and Node run in containers.

```powershell
git clone <your-repo-url>
cd SOC-Analyst-Dashboard
.\scripts\init-env.ps1        # generates .env with real random secrets, then verifies it
.\scripts\start.ps1           # validates .env, then builds and starts
```

Run these as **two separate commands** and check that `init-env.ps1` printed
"Created .env and verified it." If it did not, stop — starting the stack without
a valid `.env` produces a confusing PostgreSQL error rather than a useful one.
`.\scripts\check-env.ps1` diagnoses the environment without starting anything.

| Service | URL |
|---------|-----|
| Frontend | http://localhost:54173 |
| API docs | http://localhost:58000/docs |
| Database | localhost:55432 |

Ports sit above 49152 deliberately — see [docs/development.md](docs/development.md).

### Demo accounts

Created on first start from `.env`. **Change these passwords before showing the
project to anyone**; they are documented defaults, which makes them public.

| Role | Email | Can do |
|------|-------|--------|
| Admin | `admin@soc.example.com` | Everything, plus users, rules and the audit log |
| Responder | `responder@soc.example.com` | Analyst work, plus assign, close, simulated response |
| Analyst | `analyst@soc.example.com` | Triage alerts, investigate, open incidents, take notes |
| Viewer | `viewer@soc.example.com` | Read-only |

Signing in as each of these is the fastest way to see RBAC working.

## Features

**Ingestion and normalization** — seven source types, each with its own field
vocabulary, mapped onto one internal schema. Detection rules never see a source
dialect. Duplicate events are rejected by a unique constraint, so a retried
batch cannot inflate a brute-force count into a false positive.

**Detection engine** — eight rules, each a registered class with a validated
config schema. Logic lives in code; thresholds live in the database and are
tunable at runtime without a redeploy. See
[docs/detection-rules.md](docs/detection-rules.md).

**Alert triage** — severity- and confidence-ranked queue, filterable and
shareable by URL. Every alert carries the events that justify it and the
evidence the rule derived, so triage does not mean re-deriving the detection.
Closing one requires a resolution note.

**Sortable, shareable tables** — every column an analyst would order by is
sortable, and the sort lives in the URL alongside the filters, so a triage view
can be pasted into a ticket and reopened exactly as it was. Severity sorts by
real severity rather than alphabetically (`critical` before `high`, not after),
because the alphabetical version is a bug that looks like a feature. Sorting is
server-side against an allow-list of columns and preserves every active filter.
Headers are real buttons: reachable by Tab, operable by Enter or Space, and each
announces its state and what activating it will do.

**Incident management** — case workflow with an assembling timeline, notes,
lifecycle timestamps (so mean-time metrics are computed from recorded fact), and
simulated response actions.

**IP investigation** — pivot on any address across events, alerts and incidents,
with a locally-derived reputation verdict that always shows its reasoning.

**Analytics** — event and alert volume, authentication success/failure trend,
severity distribution, top sources, most-triggered rules, ATT&CK coverage, and
mean time to acknowledge / contain / resolve.

**RBAC** — four roles over an explicit permission model, enforced server-side on
every request and re-checked against the database rather than trusted from the
token.

**Audit trail** — append-only, admin-only, covering sign-ins, failed sign-ins,
denied access attempts, status changes, notes, role changes, rule edits and
every simulated response action.

## Screenshots

> Add screenshots here before publishing. Suggested set: the dashboard with a
> live alert, an alert detail page showing evidence, an incident timeline with a
> simulated response action, and the audit log.

```
docs/images/dashboard.png
docs/images/alert-detail.png
docs/images/incident-timeline.png
docs/images/audit-log.png
```

## Documentation

| Document | Contents |
|----------|----------|
| [portfolio.md](docs/portfolio.md) | **Start here.** What the system does, the bugs worth discussing, and the roadmap |
| [architecture.md](docs/architecture.md) | System shape, ingest path, design decisions and their costs |
| [detection-rules.md](docs/detection-rules.md) | All eight rules, thresholds, ATT&CK mapping |
| [security.md](docs/security.md) | Controls implemented, and known weaknesses stated plainly |
| [api.md](docs/api.md) | REST reference and conventions |
| [demo-scenarios.md](docs/demo-scenarios.md) | How to trigger each scenario; a ten-minute interview walkthrough |
| [development.md](docs/development.md) | Setup, Windows/Docker specifics, troubleshooting |
| [final-audit.md](docs/final-audit.md) | Pre-release audit: findings, fixes, and what was not verified |

## Demo scenarios

```powershell
.\scripts\trigger-scenario.ps1 -List
.\scripts\trigger-scenario.ps1 brute_force
```

Ten scenarios, each mapped to the detection it triggers, each covered by a test
that pushes it through the real pipeline. Full walkthrough in
[docs/demo-scenarios.md](docs/demo-scenarios.md).

## Testing

```powershell
.\scripts\run-tests.ps1
```

| Suite | Count | Covers |
|-------|-------|--------|
| Backend | 332 | Auth, RBAC, detection rules, normalization, ingest, alert and incident workflow, analytics, audit, sorting, security hardening |
| Frontend | 50 | API client (token refresh, error handling), permission gate, formatting, components, table sorting and its accessibility |

Notable tests, because they are the ones worth discussing:

- **Route coverage** — walks the live OpenAPI schema and asserts no endpoint
  outside a documented allow-list is reachable without credentials. A router
  added later without auth fails automatically.
- **False positives** — 5,000 benign events across 25 runs must produce zero
  alerts. A detection set that cries wolf is worse than none.
- **Scenario coverage** — every generator scenario must trigger its intended
  rule, through the real pipeline.
- **Account enumeration** — an unknown account and a wrong password must return
  byte-identical responses, *and* a timing test measures both paths and fails if
  one is more than 3x the other. The byte-identical test passed for weeks while
  the timing gap was 4.5x; see [docs/security.md](docs/security.md).
- **Sort-field allow-listing** — asserts that `hashed_password`, and a sort
  parameter containing SQL, are rejected rather than interpolated.
- **Runtime rule registration** — several tests spawn a clean interpreter and
  assert that the exact import `uvicorn` performs populates the detection
  registry. Added after a defect where every rule was implemented and tested but
  none were registered in the running API; the suite passed because the test
  fixture performed an import the application did not.

Backend tests run on SQLite, so they need no database container.

## Detection rules and ATT&CK

| Rule | Technique | Tactic |
|------|-----------|--------|
| Brute force / password spray | [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Access |
| Port scan | [T1046](https://attack.mitre.org/techniques/T1046/) | Discovery |
| Login after repeated failures | [T1078](https://attack.mitre.org/techniques/T1078/) | Initial Access |
| Impossible travel | [T1078](https://attack.mitre.org/techniques/T1078/) | Initial Access |
| Web attack indicators | [T1190](https://attack.mitre.org/techniques/T1190/) | Initial Access |
| Malicious file hash | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Execution |
| Privilege escalation | [T1548](https://attack.mitre.org/techniques/T1548/) | Privilege Escalation |
| Suspicious PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Execution |

Every identifier is a real published technique. None are invented.

## Security

Summarised in [docs/security.md](docs/security.md), including a frank list of
weaknesses. The short version of what is implemented: bcrypt password hashing
with the 72-byte truncation guarded, algorithm-pinned JWTs with typed tokens,
access tokens held in memory and refresh tokens in httpOnly cookies,
timing-equalised login responses, token invalidation on credential change,
server-side RBAC that fails closed, parameterised queries throughout,
allow-listed sort and audit fields, a request-body ceiling enforced before
buffering, published ports bound to loopback rather than every interface,
a startup refusal to seed the published demo passwords into a production
deployment, redacted logging, non-root containers, and no hard-coded secrets.

The weaknesses are stated too — in-process rate limiting, revocation that is
per-user rather than per-session, no MFA, and a development-grade Docker
configuration.

## Environment variables

Full annotated list in `.env.example`. The ones that matter:

| Variable | Purpose |
|----------|---------|
| `SECRET_KEY` | JWT signing key. No default; must be 32+ characters. |
| `INGEST_API_KEY` | Shared secret for the generator. No default. |
| `POSTGRES_PASSWORD` | Database password. |
| `FRONTEND_PORT` / `BACKEND_PORT` / `POSTGRES_PORT` | Host port mapping. |
| `CORS_ORIGINS` | Explicit browser origin allow-list. No wildcards. |
| `GENERATOR_EVENTS_PER_SECOND` | Baseline telemetry rate. |
| `GENERATOR_ATTACK_PROBABILITY` | Chance a batch includes an attack scenario. |
| `GENERATOR_SEED` | Set for a reproducible demo; leave empty for varied output. |
| `EVENT_RETENTION_DAYS` | Retention window. |

The backend refuses to start on a placeholder or short key. That is deliberate:
a weak signing key is not cosmetic — anyone who guesses it can mint an admin
token.

## Limitations

Worth knowing before you discuss this project, because being asked about a
limitation you have already thought about is an opportunity.

1. **Detection is synchronous.** It runs inside the ingest request. Deterministic
   and testable at this scale; a production system at real volume would move it
   behind a queue.
2. **PostgreSQL, not a search cluster.** Fine here with targeted indexes. At
   genuine SOC volume — hundreds of millions of events — full-text search over
   raw payloads wants OpenSearch.
3. **Rate limiting is per-process.** Needs Redis to be meaningful across workers.
4. **Revocation is per-user, not per-session.** Changing a password invalidates
   every outstanding token for that user immediately, via a `ver` claim checked
   on each request. What is missing is revoking one stolen token while leaving
   that user's other sessions alive; that needs a `jti` deny list in Redis.
5. **No MFA.**
6. **Development Docker configuration.** Bind mounts, Vite dev server, uvicorn
   `--reload`. A production build needs a multi-stage image serving static assets.
7. **Single-node.** No horizontal scaling, no replication, no backups.
8. **Simulated response only** — by design, and permanently.

## Future improvements

Move detection behind a task queue; add a per-session `jti` deny list so a
single stolen token can be revoked without ending a user's other sessions; MFA; a real production Compose profile with a multi-stage
frontend build; alert correlation across rules (one incident from several
related detections); scheduled retention and archival; and a rules-as-config
loader so simple threshold detections can be added without code.

## Licence and intent

Educational and portfolio use. All telemetry, indicators, credentials and
response actions are simulated. Do not point this at real infrastructure — and
it could not reach any if you tried, since it has no client for anything
external.
