# API reference

Interactive documentation is generated from the code and served at
http://localhost:58000/docs while the stack is running. It is authoritative —
this page is orientation.

Base path: `/api/v1`. Docs are disabled when `ENVIRONMENT=production`, since an
open schema is free reconnaissance.

## Authenticating

```bash
curl -X POST http://localhost:58000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -c cookies.txt \
  -d '{"email":"analyst@soc.example.com","password":"..."}'
```

The response body carries `access_token`, `expires_in` and the user with their
permission list. The refresh token is set as an httpOnly cookie and never
appears in the body — `-c cookies.txt` is what captures it.

```bash
curl http://localhost:58000/api/v1/alerts \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

When the access token expires, `POST /auth/refresh` with the cookie mints a new
one and rotates the cookie.

## Conventions

**Pagination.** Every list endpoint returns the same envelope:

```json
{ "items": [...], "total": 1243, "page": 1, "page_size": 50, "pages": 25 }
```

`total` is a real count, not `len(items)`. `page_size` is capped at 200
server-side.

**Errors.** One shape everywhere:

```json
{ "detail": "You do not have permission to perform this action.",
  "correlation_id": "a3f9c21b8e04" }
```

The correlation ID also comes back in the `X-Correlation-ID` header and appears
in the server log. Validation failures add an `errors` array of
`{field, message}` — never the submitted value.

**Status codes.** `401` no or invalid credentials · `403` authenticated but not
permitted · `404` not found · `409` conflict (duplicate) · `422` validation
failed · `429` rate limited.

**Filters** repeat the key: `?severity=critical&severity=high`.

## Endpoints

### auth
| Method | Path | Permission |
|---|---|---|
| POST | `/auth/login` | public |
| POST | `/auth/refresh` | refresh cookie |
| POST | `/auth/logout` | authenticated |
| GET | `/auth/me` | authenticated |
| POST | `/auth/change-password` | authenticated |

### events
| Method | Path | Permission |
|---|---|---|
| GET | `/events` | `event:read` |
| GET | `/events/{id}` | `event:read` |

Filters: `start`, `end`, `severity`, `event_type`, `outcome`, `source`,
`src_ip`, `dst_ip`, `username`, `hostname`, `search`, `sort_by`, `sort_dir`.

### alerts
| Method | Path | Permission |
|---|---|---|
| GET | `/alerts` | `alert:read` |
| GET | `/alerts/{id}` | `alert:read` |
| PATCH | `/alerts/{id}/status` | `alert:triage` |
| PATCH | `/alerts/{id}/assign` | `alert:triage` |
| POST | `/alerts/{id}/notes` | `alert:note:create` |
| PATCH | `/alerts/{id}/incident` | `incident:update` |

Moving an alert to `resolved` or `false_positive` requires a non-empty
`resolution_note`; the request is rejected without one.

### incidents
| Method | Path | Permission |
|---|---|---|
| GET | `/incidents` | `incident:read` |
| POST | `/incidents` | `incident:create` |
| GET | `/incidents/{id}` | `incident:read` |
| PATCH | `/incidents/{id}` | `incident:update` (+ `incident:close` for resolved/closed) |
| PATCH | `/incidents/{id}/assign` | `incident:assign` |
| POST | `/incidents/{id}/notes` | `incident:note:create` |
| POST | `/incidents/{id}/response-actions` | `response:execute` |

Response actions are **simulated**. Every one returns `"simulated": true`, and
nothing outside this database is contacted.

### investigations / analytics
| Method | Path | Permission |
|---|---|---|
| GET | `/investigations/ip/{ip}` | `investigation:read` |
| GET | `/analytics/summary` | `dashboard:read` |
| GET | `/analytics/overview` | `analytics:read` |

`/analytics/overview` is one composite response rather than ten endpoints: the
page renders them together, and ten parallel requests would each re-scan
overlapping windows of the same table.

### detections / audit / users
| Method | Path | Permission |
|---|---|---|
| GET | `/detections/rules` | `detection:read` |
| PATCH | `/detections/rules/{id}` | `detection:manage` |
| GET | `/detections/iocs` | `detection:read` |
| POST | `/detections/iocs` | `ioc:manage` |
| PATCH | `/detections/iocs/{id}` | `ioc:manage` |
| GET | `/audit` | `audit:read` |
| GET | `/audit/actions` | `audit:read` |
| GET | `/users` | `user:read` |
| POST | `/users` | `user:manage` |
| PATCH | `/users/{id}` | `user:manage` |

The audit log exposes no write method anywhere, by design.

### ingest
| Method | Path | Auth |
|---|---|---|
| POST | `/ingest/events` | `X-Ingest-Key` header |

A shared service key, not a user session: the generator is a machine with one
capability and should not hold a user account that could be assigned incidents.
A user JWT is rejected here.

```json
{ "events": [ { "event_uid": "evt-0001",
                "source": "auth",
                "timestamp": "2026-09-03T09:00:00Z",
                "payload": { "action": "login", "result": "failure",
                             "user": "j.doe", "src_ip": "203.0.113.10" } } ] }
```

`payload` is intentionally source-shaped, not normalized — reconciling dialects
is the backend's job. Response reports `received`, `stored`, `duplicates`,
`rejected`, `alerts_created`, `alerts_updated`, so the caller can tell that its
events are being dropped rather than silently filling a void.

### health
| Method | Path | Auth |
|---|---|---|
| GET | `/health` | public |
| GET | `/health/ready` | public |

Public because the container healthcheck runs before anyone can log in. Reports
only liveness and database reachability — never a version, hostname or
configuration value.
