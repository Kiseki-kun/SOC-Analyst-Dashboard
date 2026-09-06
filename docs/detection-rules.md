# Detection rules

Eight rules. Each one has a positive test, a negative test, and a threshold
test — a rule with only a positive test is a rule that might fire on everything.

## MITRE ATT&CK mapping

Every identifier below is a real, published ATT&CK technique. None are invented.
An invented technique ID is worse than none: it looks authoritative and cannot
be cross-referenced by anyone who checks.

| Rule key | Technique | Name | Tactic |
|----------|-----------|------|--------|
| `brute_force_authentication` | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |
| `port_scan` | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | Discovery |
| `suspicious_login_after_failures` | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Initial Access |
| `impossible_travel` | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Initial Access |
| `web_attack_indicators` | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |
| `malicious_file_hash` | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Execution |
| `privilege_escalation` | [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation |
| `suspicious_powershell` | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Execution |

## How a rule is built

```python
@register
class BruteForceRule(DetectionRule):
    key = "brute_force_authentication"
    name = "Brute Force Authentication"
    default_severity = Severity.HIGH
    mitre_technique_id = "T1110"
    config_model = BruteForceConfig      # a Pydantic schema

    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        ...
```

The framework handles config loading, deduplication, alert construction and
ATT&CK mapping. A rule expresses only its detection logic.

This is deliberately not one growing `if/elif` over event types. That shape
makes rules untestable in isolation, impossible to enable or tune individually,
and guarantees a merge conflict every time two people add a detection.

Rules self-register via the decorator, so adding a detection is one new module
plus an import in `rules/__init__.py`. `app/detection/rules/__init__.py` is
therefore the authoritative inventory: a rule not imported there does not exist
as far as the engine is concerned.

### The registration invariant

Registration is a **side effect of importing** the rule module. That makes the
import load-bearing, and forgetting it fails silently — the registry simply
comes up empty.

This bit the project in production. `app.detection.rules` was imported by the
seeding CLI and by `tests/conftest.py`, but by nothing in the graph that
`uvicorn app.main:app` walks. The seed process (a separate, short-lived process
that *had* the rules) wrote eight rule rows and exited; the API process then
started with an empty registry and logged `detection.rule_not_implemented` once
per rule per ingest batch, evaluating nothing. Every test passed throughout,
because the fixture performed the import the application had forgotten.

Two changes make it structural rather than a matter of remembering:

1. **The registry is self-populating.** `all_rules()`, `get_rule()` and
   `registered_keys()` each call `load_rules()` first, which imports the rules
   package once. Registration can no longer depend on import order or on some
   other module having been loaded.
2. **Startup reports coverage.** `check_detection_coverage()` returns what is
   registered, compares it against the rules the database has enabled, and logs
   one explicit line. Zero rules is an ERROR; a database rule with no
   implementation is an ERROR naming the rule.

`tests/integration/test_rule_registration.py` guards this, and several of its
tests run in a **subprocess** — inside pytest, conftest has already performed
the import, so only a clean interpreter can prove what a cold process sees.

## The rules

### Brute force authentication — T1110
Counts failed authentications per source address in a sliding window.

| Setting | Default | Meaning |
|---------|---------|---------|
| `threshold` | 8 | Failures before firing |
| `window_minutes` | 5 | Window length |
| `spray_account_threshold` | 5 | Distinct accounts that reclassify this as password spraying |

Breadth across accounts rather than depth against one is characteristic of
spraying, so crossing that second threshold raises severity to critical and
changes the alert title. Failures from *different* sources do not aggregate:
ten users each mistyping once is not an attack.

### Port scan — T1046
Counts distinct destination ports and hosts per source.

| Setting | Default |
|---------|---------|
| `distinct_port_threshold` | 15 |
| `distinct_host_threshold` | 10 |
| `window_minutes` | 5 |

Catches both shapes: a vertical scan of many ports on one host, and a horizontal
sweep of one port across many hosts. Triggering both raises severity.

### Successful login after repeated failures — T1078
The one that matters most after a brute-force alert: the failures are noise
until one of them succeeds.

| Setting | Default |
|---------|---------|
| `preceding_failure_threshold` | 5 |
| `window_minutes` | 15 |

A success from an address that was *also* generating failures scores 90
confidence and critical severity. A success from elsewhere scores 70 and high —
the hypothesis is weaker but not eliminated. One typo followed by a success does
not fire, because that is the everyday case, and a detection that alerts on it
teaches analysts to ignore the queue.

### Impossible travel — T1078
Compares consecutive successful logins for one account and computes the speed
required to cover the distance.

| Setting | Default |
|---------|---------|
| `max_speed_kmh` | 900 (roughly airliner cruise) |
| `min_distance_km` | 500 |
| `window_minutes` | 720 |

The distance floor exists because below it geolocation error dominates and the
speed figure is meaningless — without it, two offices in the same region alert
constantly. All geolocation is synthetic and generated locally; nothing is
looked up externally.

### Web attack indicators — T1190
Scores HTTP request paths against weighted signatures across five categories:
SQL injection, path traversal, command injection, cross-site scripting and file
inclusion. Weight reflects specificity — a single quote is weak evidence,
`UNION SELECT` is not.

| Setting | Default |
|---------|---------|
| `min_score` | 35 |
| `window_minutes` | 10 |
| `escalate_at_request_count` | 5 |

Requests are URL-decoded **twice** before matching, because attackers
double-encode specifically to defeat single-pass decoding: `%252e%252e%252f`
still looks innocent after one pass.

### Malicious file hash — T1204.002
Matches observed file hashes against active entries in the IOC watchlist. The
watchlist is live detection input, not a passive list — an indicator added by a
responder during an investigation affects the very next matching event. There is
a test asserting exactly that.

### Privilege escalation — T1548
Flags privilege-change events, escalating when the affected group is one that
confers administrative control (Domain Admins, Enterprise Admins, sudo, wheel
and similar). Failed attempts against a sensitive group are still reported: they
may indicate probing.

### Suspicious PowerShell — T1059.001
Scores command lines against ten weighted indicators: encoded commands, hidden
windows, execution-policy bypass, download cradles, in-memory execution,
reflection, credential-access tooling, defence evasion and persistence.

| Setting | Default |
|---------|---------|
| `min_score` | 45 |
| `window_minutes` | 30 |

Individually several of these are legitimate. It is the *combination* that
separates an administrator from an intruder, which is why this is a weighted
score and not a keyword list. `Get-Service -Name Spooler` does not fire.

## Tuning

Thresholds are editable through the UI (Detections page) or the API by a user
holding `detection:manage`. Values are validated against the rule's own Pydantic
schema, which rejects unknown keys and out-of-range numbers. An invalid config
is refused rather than stored — a typo cannot silently disable a detection.

If a stored config is somehow invalid anyway, the rule falls back to its coded
defaults rather than raising. A detection engine that stops on malformed config
is a denial-of-service against the whole platform.

## False positives

The suite includes an explicit false-positive test: 5,000 benign synthetic
events across 25 independent runs must produce **zero** alerts. That test caught
a real problem during development — impossible travel fired on ordinary traffic
because the generator was randomising each user's location on every login. The
rule was right; the data was wrong. Users now have a stable home office.
