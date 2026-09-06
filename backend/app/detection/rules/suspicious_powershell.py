"""Suspicious PowerShell command lines.

MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell),
tactic Execution.

These are detection signatures for recognising hostile command lines in
synthetic endpoint telemetry. No command is ever executed by this system.
"""

from __future__ import annotations

import re

from pydantic import Field

from app.core.enums import EventType, Severity
from app.detection.base import (
    AlertCandidate,
    DetectionContext,
    DetectionRule,
    RuleConfig,
    time_bucket,
)
from app.detection.registry import register

# (label, pattern, weight). Individually several of these are legitimate; it is
# the combination that distinguishes an administrator from an intruder.
_INDICATORS: list[tuple[str, re.Pattern[str], int]] = [
    ("encoded_command", re.compile(r"-e(nc|ncoded(command)?)?\s+[A-Za-z0-9+/=]{40,}", re.I), 45),
    ("hidden_window", re.compile(r"-w(indowstyle)?\s+hidden", re.I), 25),
    ("execution_policy_bypass", re.compile(r"-ep\s+bypass|-executionpolicy\s+bypass", re.I), 25),
    ("no_profile", re.compile(r"-nop(rofile)?\b", re.I), 10),
    ("download_cradle", re.compile(r"(downloadstring|downloadfile|invoke-webrequest|\bwget\b|\bcurl\b|net\.webclient)", re.I), 40),
    ("in_memory_execution", re.compile(r"(invoke-expression|\biex\b|invoke-command)", re.I), 30),
    ("reflection", re.compile(r"(reflection\.assembly|\[system\.reflection|frombase64string)", re.I), 35),
    ("credential_access", re.compile(r"(mimikatz|invoke-mimikatz|sekurlsa|lsass)", re.I), 50),
    ("defence_evasion", re.compile(r"(set-mppreference|add-mppreference|disablerealtimemonitoring)", re.I), 45),
    ("persistence", re.compile(r"(new-scheduledtask|register-scheduledtask|schtasks\s+/create)", re.I), 30),
]

_POWERSHELL_PROCESS = re.compile(r"(powershell(\.exe)?|pwsh(\.exe)?)$", re.I)


class SuspiciousPowerShellConfig(RuleConfig):
    min_score: int = Field(default=45, ge=5, le=500)
    window_minutes: int = Field(default=30, ge=1, le=1440)


@register
class SuspiciousPowerShellRule(DetectionRule):
    key = "suspicious_powershell"
    name = "Suspicious PowerShell Execution"
    description = (
        "A PowerShell command line combines indicators associated with hostile "
        "use: encoded commands, download cradles, in-memory execution or "
        "defence evasion."
    )
    default_severity = Severity.HIGH
    default_confidence = 80
    mitre_tactic = "Execution"
    mitre_technique_id = "T1059.001"
    mitre_technique_name = "Command and Scripting Interpreter: PowerShell"
    config_model = SuspiciousPowerShellConfig

    @staticmethod
    def score_command(command_line: str) -> tuple[int, list[str]]:
        score = 0
        labels: list[str] = []
        for label, pattern, weight in _INDICATORS:
            if pattern.search(command_line):
                score += weight
                labels.append(label)
        return score, labels

    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        cfg = SuspiciousPowerShellConfig(**ctx.config)

        candidates: list[AlertCandidate] = []
        for event in ctx.events:
            if event.event_type != EventType.PROCESS_EXECUTION.value:
                continue
            command_line = event.command_line or ""
            process = event.process_name or ""
            if not command_line:
                continue
            # Match on the process OR the command line, so a renamed binary
            # invoking PowerShell syntax is still caught.
            if not (
                _POWERSHELL_PROCESS.search(process)
                or re.search(r"powershell|pwsh", command_line, re.I)
            ):
                continue

            score, labels = self.score_command(command_line)
            if score < cfg.min_score:
                continue

            severity = Severity.CRITICAL if score >= 90 else Severity.HIGH
            candidates.append(
                AlertCandidate(
                    dedup_key=(
                        f"{self.key}|{event.hostname or 'unknown'}|"
                        f"{event.username or 'unknown'}|"
                        f"{time_bucket(event.timestamp, cfg.window_minutes)}"
                    ),
                    title=(
                        f"Suspicious PowerShell on {event.hostname or 'unknown host'} "
                        f"({', '.join(labels[:3]).replace('_', ' ')})"
                    ),
                    description=(
                        f"PowerShell executed by '{event.username or 'unknown'}' on "
                        f"{event.hostname or 'an unknown host'} matched {len(labels)} "
                        f"hostile-use indicator(s): {', '.join(labels)}. "
                        f"Combined score {score} exceeds the threshold of {cfg.min_score}."
                    ),
                    severity=severity,
                    confidence=min(95, 50 + score // 3),
                    event_ids=[event.id],
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    src_ip=event.src_ip,
                    username=event.username,
                    hostname=event.hostname,
                    evidence={
                        "indicators": labels,
                        "score": score,
                        "process_name": event.process_name,
                        "command_line": command_line[:1000],
                    },
                )
            )
        return candidates
