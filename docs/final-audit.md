# Final audit

Record of the pre-release audit: what was checked, what was found, what was
changed, and — as importantly — what was *not* verified and why.

**Date:** 2026-09-05
**Scope:** security review, full test execution, table sorting, secret scan,
documentation accuracy, release readiness.

---

## Where this audit was run, and what that limits

This matters more than any individual finding, so it goes first.

The audit ran in a **Linux environment with the project folder bind-mounted from
Windows**. That environment has Python 3.10 and Node 22. It has **no Docker
daemon**. Consequently:

| Verified by execution | Not verified here |
|---|---|
| Full backend suite (332 tests) on SQLite | Any run against PostgreSQL 16 |
| Full frontend suite (50 tests), typecheck, production build | Browser rendering of any page |
| Lint (`ruff check`) across the backend | `docker compose up` end to end |
| Alembic migration loads and emits complete DDL | Migration applied to a real PostgreSQL |
| `docker-compose.yml` parses; all 29 interpolations resolve | Containers actually starting |
| Secret scan across all 181 committable files | — |

**Nothing in this document claims Docker or browser verification.** The
statements below about container behaviour are statements about configuration
that was read and parsed, not about containers that were run. The earlier
runtime verification of the detection pipeline — real uvicorn, real HTTP, the
generator's own client, 250 benign events producing zero alerts and five attack
scenarios producing five alerts — was performed against **SQLite, not
PostgreSQL**, and is labelled that way wherever it is referenced.

---

## Findings

Seven issues. Three were security defects, one of which was a control that
existed, was tested, and did nothing.

### 1. Login timing oracle — the enumeration control was inert

**Severity: high.** The account-enumeration defence was present and covered by a
test asserting that an unknown account and a wrong password return
byte-identical responses. That test passed. The control was still broken: the
dummy bcrypt hash burned on the unknown-account path was generated at cost 10,
while real accounts hash at the configured cost 12. Bcrypt cost is a power of
two, so the "equalising" work did roughly a quarter of the real work.

Measured: **75.9 ms for an unknown address, 344.4 ms for a known one — 4.5x.**
That gap is trivially measurable over a network and is precisely the oracle the
control was written to remove.

*Fix:* dummy hashes are generated lazily per cost factor and matched to the
configured `BCRYPT_ROUNDS`, under a lock, cached per cost.
*Tests:* the byte-identical assertion was kept, and a second test now measures
both paths and fails if the ratio exceeds 3x. The equality test alone could
never have caught this.

### 2. `token_version` was a column that looked like a revocation mechanism

**Severity: high.** The `token_version` column and a `jti` claim existed, and
the documentation described revocation as available. Nothing compared the
token's version against the user's. A token minted before a password change
stayed valid for its full lifetime.

*Fix:* tokens carry a `ver` claim; `deps.py` rejects any token whose `ver` does
not match the user's current `token_version`; the refresh path enforces the same.
Decoding now *requires* the claim, so a legacy token without one is rejected
rather than silently accepted.
*Tests:* access token and refresh cookie both invalidated by a password change;
legacy tokens lacking `ver` rejected.

### 3. Demo credentials could be seeded into a production deployment

**Severity: high (for anyone deploying it), found during the secret scan.** The
four demo passwords are committed in `.env.example` — deliberately, so the
project is demonstrable on a clean checkout. That makes them public the moment
the repository is. Nothing prevented `ENVIRONMENT=production` with
`SEED_DEMO_USERS=true`, which would create four accounts with publicly-known
passwords, one of them an administrator.

*Fix:* a `model_validator` refuses to construct settings on that combination.
The guard fires only on the combination — a guard that fired on either half
alone would be switched off rather than obeyed.
*Tests:* seven, including one that reads `.env.example` and fails if it
documents a password the guard does not recognise, so the list cannot go stale
silently. That drift test was confirmed non-vacuous.

### 4. Published ports bound to every interface

**Severity: medium.** Docker publishes to `0.0.0.0` by default. PostgreSQL and
an API with no transport-layer encryption were therefore reachable from whatever
network the host was attached to.

*Fix:* all three published ports are now `${BIND_ADDRESS:-127.0.0.1}:...`. The
default is in the Compose file itself, so the safe value applies even when
`.env` omits the key — which it did, and which was corrected for parity.

### 5. No ceiling on request body size

**Severity: medium.** The ingest schema permits 500 events x 64 keys x 4096
characters — roughly 125 MB — and Pydantic rejects an oversized body only after
the whole thing has been read into memory.

*Fix:* middleware refuses bodies over 4 MB from the `Content-Length` header,
before buffering; a chunked request declaring no length is refused outright on
any body-bearing method. The decision logic is a pure function
(`evaluate_request_size`) because the chunked branch is unreachable through a
test client — `httpx` always sets `Content-Length`.

### 6. Severity sorted alphabetically

**Severity: low, but user-visible and wrong.** Sorting a queue by severity
ordered `critical, high, info, low, medium` — alphabetical order presented as
priority order. This is the kind of bug that looks like a feature.

*Fix:* a shared `severity_ordering` helper ranks severity properly
(`critical=4 … info=0`) via a SQL `CASE`. Two routers had independently
duplicated the ordering logic; both now use the shared helper.

### 7. A stray Linux artifact and a lint typo

**Severity: cosmetic.** A binary `.coverage` file from my own test runs, plus
`__pycache__` directories and an empty `frontend/node_modules`, had accumulated
in the mounted folder. All were git-ignored, so none would have been committed,
but they were mine to clean up and are now removed. A typo in `.gitignore`
(`lib60/` for `lib64/`) was corrected.

---

## Table sorting

The highest-priority item of this phase. Implemented server-side and
client-side, with the accessibility requirements treated as requirements rather
than as a nice-to-have.

**Backend.** A shared `app/api/v1/sorting.py` provides allow-listed ordering.
Sortable fields are a fixed `Literal` per router — a column name from a query
string is never interpolated into SQL. Severity is ranked, not alphabetised.
Two routers that had duplicated the ordering logic were consolidated onto the
shared helper.

**Frontend.** `SortableHeader.tsx` renders each sortable column as a real
`<button>` inside a `<th scope="col">` carrying `aria-sort`. Headers are
reachable by Tab and operable by Enter or Space, because they are buttons rather
than click handlers on a `<th>`. Each has an accessible name stating the current
state and what activating it will do — "Time, sorted newest first. Activate to
sort oldest first." A direction indicator is rendered `aria-hidden`, so screen
reader users get the sentence rather than a bare triangle.

**Sort state lives in the URL** alongside the filters, so a sorted, filtered
triage view can be pasted into a ticket. Re-sorting resets to page 1 and
**preserves every filter and search term** — re-ordering a result set must never
widen it. Returning to page 1 is deliberate: staying on page 7 of a re-sorted
list shows rows unrelated to what the analyst was just looking at.

**Tests: 32 backend, 22 frontend.** The backend set covers every allow-listed
field, rejection of non-allow-listed input (including `hashed_password` and a
value containing SQL), pagination stability, and severity-rank correctness. The
frontend set covers keyboard operation, `aria-sort` on active and inactive
columns, accessible-name wording, nulls-last in both directions, non-mutation of
the input array, and that a client-side sort survives a filter change.

One bug was found by these tests, in my own code: negating the comparator to
reverse the sort also negated the missing-value handling, so null rows sorted
*first* when descending — the top of the queue. Missing values are now placed
before the direction flip.

---

## Test execution

Every number below was produced by running the suite in this session, not read
from documentation.

| Suite | Result | Command |
|---|---|---|
| Backend | **332 passed, 0 failed** (exit 0) | `pytest` |
| Frontend | **50 passed, 0 failed** | `vitest run` |
| Typecheck | **clean** (exit 0) | `tsc --noEmit` |
| Production build | **succeeded**, 1206 modules | `vite build` |
| Backend lint | **All checks passed** | `ruff check .` |

The README previously claimed 213 backend and 28 frontend tests. Both were
stale and have been corrected.

`ruff check` reported seven issues at the start of this phase — two introduced
by my changes, five pre-existing in `alembic/env.py`. All were fixed. Before
removing the `# noqa: E402` directives I confirmed empirically that ruff does
not raise E402 there (it permits imports following `sys.path` manipulation),
rather than assuming the directives were redundant. After the import reordering
I verified that `alembic history` and `alembic upgrade head --sql` still work,
since a broken migration environment would not be caught by the test suite.

---

## Secret scan

**181 files** would be committed. The scan covered **exactly those 181** — the
file list was diffed against `git add -A` in a throwaway repository, with zero
files in either direction, so there is no coverage gap.

Three scans were run:

1. **Keyed leak scan.** The three machine-unique secrets in the real `.env`
   (`SECRET_KEY`, `INGEST_API_KEY`, `POSTGRES_PASSWORD`) were searched for
   literally across all 181 files. **Zero occurrences.**
2. **Entropy sweep.** Every token of 28+ characters at ≥4.2 bits/character.
   **Zero hits** after cleanup. The only prior hits were inside the stray binary
   coverage file, which was removed.
3. **Pattern rules.** AWS keys, GitHub and Slack tokens, Google and Stripe keys,
   private key blocks, JWT literals, bcrypt hashes, connection strings with
   embedded passwords, and generic `secret =` assignments. **One hit**, a test
   fixture asserting database-URL assembly. It is not a secret; the literal was
   renamed from `a-real-password` to `pytest-fixture-value-not-a-secret` so a
   scanner run on the public repository does not produce an alarming
   false positive. A repository that trips gitleaks looks bad even when it is
   clean.

**`.gitignore` was verified behaviourally**, not by reading it: a throwaway git
repository was initialised, `git add -A` run, and `.env` confirmed absent from
the index. Directory patterns were tested by creating the actual directories,
because `git check-ignore` reports a trailing-slash pattern as non-matching for
a path that does not exist — an easy way to convince yourself a working
`.gitignore` is broken.

The four demo passwords now appear as literals in `app/core/config.py`, in the
guard's list. This is not new exposure: they are already committed in
`.env.example`, and the guard cannot work without knowing them.

---

## Documentation corrections

Documentation that describes controls the code does not have is worse than no
documentation, so this phase treated stale claims as defects.

| File | Was | Now |
|---|---|---|
| `README.md` | "Backend 213 / Frontend 28" | 332 / 50, measured |
| `README.md` | "No token revocation. The hooks exist; the check does not." | Revocation is per-user via the `ver` claim; what is missing is per-session |
| `README.md` | Security summary omitted this phase's controls | Body ceiling, loopback binding, seed guard, sort allow-listing added |
| `docs/security.md` | "No token revocation list … that check is not implemented" | Rewritten to describe what exists and name the real remaining gap |
| `docs/security.md` | Enumeration described as working | Now records that it was inert, with the measured numbers |
| `docs/security.md` | No mention of body limit, port binding, seed guard | All three documented |

New: **`docs/portfolio.md`** — architecture at a glance, the analyst workflow,
the detection-engine and security-architecture explanations, the defect history
worth discussing in an interview, and a roadmap ordered by what I would actually
do next.

Both `docs/architecture.md` diagrams are now Mermaid, so they render on GitHub.
**They were validated by rendering**, not by inspection: extracted, run through
`mermaid-cli`, and the resulting images examined. The first layout was
rejected — an edge crossed the database node and the subgraph edge emerged from
the wrong element — and replaced with one that reads correctly.

---

## Compose configuration

Parsed and checked programmatically; **not started**, because this environment
has no Docker daemon.

- Parses as valid YAML. Four services: `postgres`, `backend`, `generator`,
  `frontend`. One named volume, `postgres_data`.
- All **29** `${VAR}` interpolations resolve — every one is either present in
  `.env` or carries an inline default.
- All three published ports go through `${BIND_ADDRESS:-127.0.0.1}`.
- `no-new-privileges:true` on every service; no service is privileged.
- **No literal secret** from `.env` appears anywhere in the file.
- `POSTGRES_HOST_AUTH_METHOD` is absent — `trust` is not used.

---

## Deliberately not done

- **Multi-select of related alerts during incident creation.** Alerts can be
  attached to an existing incident one at a time, which covers the workflow;
  bulk selection is a convenience, and this phase was not the place to add
  surface area.
- **Suppressing the remaining connection-string scanner hit.** It is a test
  fixture. Adding an inline suppression to make a scan look clean is how real
  findings get hidden later.
- **`ruff format`.** It would reformat 52 of 90 files. That is a large diff with
  no behavioural content, and it would bury this phase's actual changes in a
  Git history the reader is about to see for the first time.
- **Git operations.** No repository was initialised, nothing was committed, no
  remote was configured — as instructed. The `git init` runs described above
  were on throwaway *copies* outside the project folder, and were deleted.

---

## Release readiness

| Check | Status |
|---|---|
| Backend tests | 332 passed |
| Frontend tests | 50 passed |
| Typecheck | Clean |
| Production build | Succeeds |
| Lint | Clean |
| Real secrets in committable files | None |
| `.env` excluded from git | Verified behaviourally |
| Demo credentials marked as demo | Yes, and enforced at startup |
| Docs match implementation | Corrected where they did not |
| Compose parses, no hardcoded secrets | Verified by parsing |
| Docker stack starts | **Not verified — no Docker in this environment** |
| UI renders in a browser | **Not verified — no browser in this environment** |
| Ethical boundary | Unchanged: synthetic telemetry, simulated response only |

The two unverified rows are the reason to run `.\scripts\start.ps1` on Windows
before publishing, and to capture the four screenshots the README reserves
placeholders for.
