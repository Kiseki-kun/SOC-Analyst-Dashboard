# Security

This project is about security, so its own security posture is part of the
deliverable. What follows is what was actually implemented, what was
deliberately left out, and where the weaknesses are.

## Authentication

**Password storage.** bcrypt, cost 12 by default, called directly rather than
through passlib — passlib 1.7.4 predates bcrypt 4.x and raises on its version
probe, and pinning around that is a maintenance trap for a dependency doing one
function's worth of work. Input longer than bcrypt's 72-byte limit is rejected
rather than silently truncated, because truncation lets two different passwords
share a hash.

**Tokens.** Short-lived JWT access tokens (15 minutes) plus a refresh token
valid for 7 days.

- The signing algorithm is pinned to a single value. Accepting a list, or
  trusting the header's `alg`, is how `alg: none` and HS/RS confusion attacks
  get in.
- Every token carries a `typ` claim and is rejected if presented in the wrong
  place. A refresh token — long-lived, sitting in a cookie — is not accepted as
  an access token even though its signature is perfectly valid.
- Required claims (`exp`, `iat`, `nbf`, `sub`, `typ`, `jti`) are enforced at
  decode time.

**Token storage.** The access token lives in a JavaScript variable, never
`localStorage`. A token in `localStorage` is readable by any script on the page,
so one XSS yields a bearer credential usable from anywhere. The refresh token is
an httpOnly, SameSite=Lax cookie scoped to `/api/v1/auth`, so JavaScript cannot
read it at all and it is not attached to unrelated API calls. Refresh tokens
rotate on every use.

**Account enumeration.** Every credential failure — unknown account, wrong
password, deactivated account — returns the same status and the same message.
When the account does not exist, the server still burns comparable CPU on a
dummy bcrypt comparison, so response timing does not leak which addresses are
registered.

This control was present but broken until the final audit. The dummy hash was
generated at bcrypt cost 10 while real accounts hash at cost 12 — bcrypt cost is
a power of two, so the "equalising" path did a quarter of the work of the real
one. Measured, an unknown address answered in 75.9 ms against 344.4 ms for a
known one: a 4.5x gap, trivially measurable over a network, which is exactly the
oracle the control was supposed to remove. The dummy hashes are now generated
lazily per cost factor and matched to the configured `BCRYPT_ROUNDS`. Two tests
cover it: one asserts the two responses are byte-identical, and one measures
both paths and fails if the ratio exceeds 3x. A control that looks right and
does nothing is worse than no control, because it stops anyone from looking.

**Rate limiting.** Failed logins are throttled per email+IP: five failures in
five minutes triggers a five-minute lockout. **This is the weakest control in
the project.** State lives in process memory, so it is per-worker and resets on
restart. It is adequate for a single-container development deployment and is not
sufficient for a real one, where it belongs in Redis so every worker shares a
view. It is included because an authentication endpoint with no rate limit is a
finding in any review, and an honest partial control with its limitation stated
is better than none.

**No public registration.** Accounts are provisioned by an administrator. In a
SOC platform, self-registration would let anyone who can reach the login page
create themselves a viewer account and read security telemetry.

## Authorization

Roles are what a user is assigned. Permissions are what an endpoint requires.
Endpoints never test a role name — they require a permission, and a mapping
decides which roles hold it.

A pure hierarchy cannot express "a responder may close an incident but may not
create users", and every real SOC has capabilities that do not nest. The
explicit map also makes the whole authorisation model reviewable in one screen.

**Enforcement is server-side, always.** The frontend hides controls the user
cannot use, and that is a usability nicety, not a control. Every permission is
re-checked on the server for every request. A user who edits their way past a
route guard gets a 403 and an entry in the audit log.

**Fail closed.** An unrecognised role string — a stale row, a hand-edited
database — grants zero permissions, never a default set.

**The role is re-read from the database on every request**, not trusted from the
token. An administrator demoted five minutes ago loses access immediately rather
than when their access token happens to expire.

**A route-coverage test** walks the live OpenAPI schema and asserts that no
endpoint outside a small documented allow-list can be reached without
credentials. A router added later without an auth dependency fails that test
automatically. Reviewers forget; tests do not.

## Injection

**SQL injection.** Every query goes through SQLAlchemy with bound parameters.
No string interpolation into SQL anywhere. Search terms additionally have `%`
and `_` escaped so a user searching for "50%" does not accidentally issue a
wildcard query. Sort columns come from a fixed allow-list — accepting a column
name from the query string would be both a performance trap and a small
injection surface.

**Cross-site scripting.** React escapes interpolated values by default, and
`dangerouslySetInnerHTML` appears nowhere in the codebase. Hostile content in
event data — a URL path containing `<script>` — is displayed as text, which is
exactly right: it is evidence, and sanitising it would destroy the thing the
web-attack rule matches on.

**Command injection.** The application never invokes a shell. There is no
`subprocess`, no `os.system`, no `eval` anywhere in the backend.

**Path traversal.** No endpoint accepts a filesystem path. Nothing is read from
or written to disk based on user input.

## Input validation

Every request body and query parameter is a Pydantic model. Specific bounds
worth naming:

- Ingest batches are capped at 500 events; payloads at 64 keys and 4096
  characters per string field.
- Request bodies are refused above 4 MB by middleware, from the `Content-Length`
  header, before anything is buffered. Schema limits alone are not enough here:
  500 events x 64 keys x 4096 characters is roughly 125 MB, and Pydantic only
  rejects that after the whole body is in memory. A chunked request with no
  declared length is refused outright on any body-bearing method.
- Pagination is capped server-side at 200 per page. An unbounded limit is a
  denial-of-service primitive — one request for ten million events would exhaust
  memory.
- IP addresses are validated with `ipaddress` before use. `src_ip` feeds alert
  dedup keys and is displayed to analysts; accepting arbitrary text would let a
  malformed source inject content into both.
- File hashes must be hexadecimal MD5/SHA-1/SHA-256. An indicator that can never
  match is worse than none: it looks like coverage.
- Control characters are stripped from normalized text fields. A newline in a
  username is how a log line gets forged.
- Passwords require 12+ characters with mixed case, a digit and a symbol.

## Secrets

Nothing is hard-coded. `SECRET_KEY` and `INGEST_API_KEY` have **no defaults at
all** — a misconfigured deployment fails loudly at import rather than silently
running on a predictable key. Both are rejected if shorter than 32 characters or
still carrying the `CHANGE_ME` placeholder from `.env.example`.

`.env` is git-ignored; `.env.example` is the committed template and contains no
real values.

The four demo passwords are the exception that proves the rule: they *are* in
`.env.example`, deliberately, so the project is demonstrable on a clean
checkout. That makes them public. The application therefore refuses to start
when `ENVIRONMENT=production` and `SEED_DEMO_USERS=true` while any demo password
is still the committed value — otherwise a deployment would hand anyone who read
the repository an administrator login. The guard fires only on that combination:
one that fired on either half alone would be switched off rather than obeyed. A
drift test reads `.env.example` and fails if it documents a password the guard
does not recognise, so the two cannot diverge silently.

## Logging

Structured logging with a redaction processor that recursively blanks any field
named like a credential (`password`, `token`, `authorization`, `secret`,
`api_key`, `cookie`, and others) before a record is rendered. A stray
`password=` in a log line is exactly the kind of finding that discredits a
security project.

The audit trail uses an **allow-list** of permitted detail keys rather than a
deny-list, so a field added elsewhere in the codebase cannot leak into it
because nobody remembered to block it. There is a test asserting no audit entry
contains a submitted password.

## Error handling

Unhandled exceptions return a generic message and a correlation ID. Full detail
goes to the log. A stack trace in an HTTP response tells an attacker the
framework, the file layout and often the database schema.

Validation errors return field names and messages but never echo the submitted
value, so a payload containing a password cannot end up in an error body or a
browser console.

## Transport and headers

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
a restrictive `Content-Security-Policy`, and `Cache-Control: no-store`. HSTS is
added when `COOKIE_SECURE` is on.

CORS uses an explicit origin allow-list. A wildcard is invalid with credentialed
requests and would be wrong here regardless, since the refresh cookie is
credentialed.

## Container security

- Both Python images run as an unprivileged user (UID 10001/10002). A container
  escape or an RCE then lands on a user with no package-manager rights and no
  filesystem write access outside `/app`.
- `no-new-privileges:true` on every service, so a setuid binary cannot elevate.
- No service is privileged; no host paths are mounted beyond the source bind
  mounts needed for development reload.
- **Published ports bind to `127.0.0.1`, not `0.0.0.0`.** Docker's default is to
  publish on every interface, which would put PostgreSQL and an unauthenticated-
  at-the-transport-layer HTTP API on whatever network the host is attached to —
  a coffee-shop Wi-Fi included. The interface is `${BIND_ADDRESS:-127.0.0.1}`,
  so the safe value applies even when `.env` omits it entirely.
- PostgreSQL data lives in a named volume, never a bind mount.
- Secrets arrive as environment variables from `.env`, which is never committed
  and never baked into an image.

## Simulated response actions

Every containment action records a row and does nothing else. There is no code
path from a response action to a firewall, a directory service, an endpoint
agent or any external system — verifiable by the absence of any such client in
the dependency list. The `simulated` flag is stored explicitly and returned in
every API response so a consumer cannot mistake recorded intent for real
containment. The single action with any effect is adding an indicator to the
local watchlist, which affects future detections inside this application only.

## Known weaknesses

Stated plainly, because a security project that claims to have none is not
credible.

1. **Rate limiting is in-process.** Per-worker and lost on restart. Needs Redis.
2. **Revocation is coarse, and there is no per-token deny list.** Every token
   carries a `ver` claim, and every authenticated request compares it against
   the user's current `token_version`; changing a password increments that
   column, so all of that user's outstanding access and refresh tokens stop
   working immediately. What is missing is finer granularity: an administrator
   cannot revoke one stolen token while leaving that user's other sessions
   alive, because the counter is per-user, not per-session. A `jti` deny list
   in Redis would give that, and would also cover "log out this one device".
3. **No multi-factor authentication.** A real SOC platform would require it for
   every analyst account.
4. **No CSRF token on the refresh endpoint.** It relies on SameSite=Lax alone.
   That blocks the common cross-site POST, but defence in depth would add an
   explicit anti-CSRF token.
5. **Development Docker configuration.** Source is bind-mounted, the frontend
   runs Vite's dev server, and `--reload` is on. A production deployment needs a
   multi-stage build serving static assets, no bind mounts, and a real ASGI
   worker configuration.
6. **No secrets manager.** `.env` on disk is appropriate for local development
   and not for anything else.
7. **The IP reputation score is local-only.** It is derived from this
   application's own data and means nothing outside it. Every response labels it
   `local_synthetic_data_only` and shows the reasoning behind the verdict.
