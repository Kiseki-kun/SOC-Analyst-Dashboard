# Demo scenarios

Ten scenarios, each designed to trigger a specific detection. Every one is
covered by a test that pushes it through the real pipeline and asserts the
expected rule fires — so if a scenario stops working, the suite fails rather
than the demo.

All activity is synthetic. Addresses come from ranges IANA reserves for
documentation (TEST-NET-1/2/3, RFC 5737) and RFC 1918 private space; malicious
domains use the reserved `.invalid` TLD; every file hash is invented. Nothing
here can route or resolve.

## Firing one on demand

```powershell
.\scripts\trigger-scenario.ps1 -List           # show all scenarios
.\scripts\trigger-scenario.ps1 brute_force     # fire one
.\scripts\trigger-scenario.ps1 port_scan -Repeat 3
```

Or directly:

```powershell
docker compose exec generator python -m generator.trigger brute_force
```

The generator also fires a random scenario roughly every eighth batch on its
own, so the dashboard fills naturally while you talk.

## The four the brief asks for

### 1. Brute force → T1110

```powershell
.\scripts\trigger-scenario.ps1 brute_force
```

12–20 failed authentications against one account from a single hostile address,
spread over two minutes.

**Walk through it:** Dashboard shows the alert count rise → open **Alerts** →
the alert is high severity, mapped to T1110 → open it → the *Why this fired*
panel shows the failure count, window and targeted account → the evidence table
lists the exact events → click the source address to reach **IP investigation**
→ the address scores as suspicious or malicious with its reasoning listed →
back on the alert, **Escalate to incident** → on the incident, record a
simulated IP block → resolve with a summary.

That is the full loop: event → detection → alert → investigation → incident →
response → resolution.

### 2. Port scan → T1046

```powershell
.\scripts\trigger-scenario.ps1 port_scan
```

25–45 distinct destination ports on one host inside a minute, all denied.

**Point out:** the alert's evidence carries `distinct_ports` and
`distinct_hosts`, so the analyst does not have to re-derive the shape of the
scan. Try `network_sweep` for the horizontal variant — one port across many
hosts, same rule, different evidence.

### 3. Suspicious login → T1078

```powershell
.\scripts\trigger-scenario.ps1 credential_compromise
```

Nine to fourteen failures against one account, then a **success from the same
address**.

**Point out:** this produces *two* alerts — the brute force, and the successful
login after failures. The second is critical, because the success came from an
address that was also generating failures. Run `impossible_travel` next to show
the same account then appearing on another continent.

### 4. Web attack → T1190

```powershell
.\scripts\trigger-scenario.ps1 web_attack
```

Four or more hostile request paths spanning SQL injection, path traversal,
command injection, XSS and file inclusion — including a double-encoded traversal
that a single-pass decoder would miss.

**Point out:** the alert lists which categories matched. Open the linked event
and look at the raw document: the hostile URL is displayed as text, never
interpreted. That is the correct handling — it is evidence.

## The rest

| Scenario | Fires | What it demonstrates |
|----------|-------|----------------------|
| `password_spray` | T1110 (critical) | One source, eight accounts. Reclassified as spraying, severity raised. |
| `network_sweep` | T1046 | Horizontal scan: one port, many hosts. |
| `impossible_travel` | T1078 | Same account, two continents, minutes apart. |
| `suspicious_powershell` | T1059.001 | Encoded command, hidden window, download cradle. |
| `malware_execution` | T1204.002 | Watchlisted hash executes, then beacons out. |
| `privilege_escalation` | T1548 | Account added to Domain Admins. |

## A ten-minute interview walkthrough

1. **Sign in as the analyst account.** Mention that the access token is held in
   memory and the refresh token is an httpOnly cookie, so an XSS cannot steal a
   long-lived credential.
2. **Dashboard.** Point at the open-alert and critical/high tiles. Note that
   every figure is computed from stored rows — mean-time metrics show "Not yet
   measured" rather than a fabricated zero when no incident has reached that
   stage.
3. **Fire `credential_compromise`.** Wait for the batch, refresh.
4. **Triage the critical alert.** Show the evidence panel, the linked events,
   the ATT&CK link out to attack.mitre.org.
5. **Investigate the source address.** Show the reputation verdict *with its
   reasoning* — and say out loud that it is derived from local data only, no
   external threat intelligence.
6. **Escalate to an incident.** Show the timeline assembling itself.
7. **Record a simulated response action.** Point at the SIMULATED badge and the
   dialog text stating that no external system is contacted.
8. **Resolve the incident** with a summary. Show that the API refuses to close
   it without one.
9. **Sign in as the viewer account** in a second browser. Show the triage
   controls are gone — then explain that hiding them is not the control, and
   demonstrate the 403 by hitting the API directly.
10. **As admin, open the Audit log.** Every action from the walkthrough is
    there, including the viewer's denied attempt.

Step 9 is the one worth rehearsing. Being able to say "the button is hidden for
usability, the 403 is the actual control, and here is the audit entry proving
the denial was recorded" is what separates someone who implemented RBAC from
someone who understands it.
