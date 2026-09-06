"""Web attack indicators in HTTP request paths.

MITRE ATT&CK: T1190 (Exploit Public-Facing Application), tactic Initial Access.

The patterns below detect *attempts* recorded in synthetic proxy logs. They are
signatures for spotting hostile requests in telemetry, not exploit code, and
nothing here is executed — the request string is only ever matched against a
regex and rendered as escaped text.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import unquote_plus

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

# (category, compiled pattern, weight). Weight feeds alert confidence: a
# single quote is weak on its own, `UNION SELECT` is not.
_SIGNATURES: list[tuple[str, re.Pattern[str], int]] = [
    ("sql_injection", re.compile(r"\bunion\s+(all\s+)?select\b", re.I), 40),
    ("sql_injection", re.compile(r"\bor\s+1\s*=\s*1\b", re.I), 35),
    ("sql_injection", re.compile(r"'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+", re.I), 30),
    ("sql_injection", re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.I), 35),
    ("sql_injection", re.compile(r"\b(information_schema|sysobjects)\b", re.I), 30),
    ("path_traversal", re.compile(r"(\.\./){2,}"), 35),
    ("path_traversal", re.compile(r"/etc/(passwd|shadow)\b", re.I), 40),
    ("path_traversal", re.compile(r"\\windows\\system32", re.I), 35),
    ("command_injection", re.compile(r"[;&|`]\s*(cat|ls|id|whoami|uname|curl|wget|nc)\b", re.I), 40),
    ("command_injection", re.compile(r"\$\(\s*\w+\s*\)"), 30),
    ("xss", re.compile(r"<script[\s>]", re.I), 35),
    ("xss", re.compile(r"javascript:\s*\w", re.I), 25),
    ("xss", re.compile(r"\bon(error|load|click)\s*=", re.I), 30),
    ("file_inclusion", re.compile(r"\b(php|data|expect)://", re.I), 35),
]


class WebAttackConfig(RuleConfig):
    min_score: int = Field(default=35, ge=5, le=500)
    window_minutes: int = Field(default=10, ge=1, le=1440)
    # A source producing many distinct hostile requests is being systematic.
    escalate_at_request_count: int = Field(default=5, ge=2, le=1000)


@register
class WebAttackRule(DetectionRule):
    key = "web_attack_indicators"
    name = "Web Attack Indicators"
    description = (
        "HTTP requests containing SQL injection, path traversal, command "
        "injection, cross-site scripting or file-inclusion patterns."
    )
    default_severity = Severity.HIGH
    default_confidence = 70
    mitre_tactic = "Initial Access"
    mitre_technique_id = "T1190"
    mitre_technique_name = "Exploit Public-Facing Application"
    config_model = WebAttackConfig

    @staticmethod
    def score_request(target: str) -> tuple[int, list[str], list[str]]:
        """Score one request string. Returns (score, categories, matched patterns).

        The target is URL-decoded twice: attackers double-encode specifically to
        slip past naive signature matching, and decoding once still leaves
        `%252e%252e%252f` looking innocent.
        """
        decoded = target
        for _ in range(2):
            try:
                decoded = unquote_plus(decoded)
            except Exception:
                break

        score = 0
        categories: list[str] = []
        matched: list[str] = []
        for category, pattern, weight in _SIGNATURES:
            if pattern.search(decoded):
                score += weight
                if category not in categories:
                    categories.append(category)
                matched.append(pattern.pattern)
        return score, categories, matched

    def evaluate(self, ctx: DetectionContext) -> list[AlertCandidate]:
        cfg = WebAttackConfig(**ctx.config)

        hits: dict[str, list] = defaultdict(list)
        for event in ctx.events:
            if event.event_type != EventType.HTTP_REQUEST.value:
                continue
            target = event.url_path or ""
            if not target:
                continue
            score, categories, matched = self.score_request(target)
            if score < cfg.min_score:
                continue
            hits[event.src_ip or "unknown"].append((event, score, categories, matched))

        candidates: list[AlertCandidate] = []
        for src_ip, entries in hits.items():
            events = [e for e, _, _, _ in entries]
            total_score = sum(s for _, s, _, _ in entries)
            categories = sorted({c for _, _, cats, _ in entries for c in cats})
            systematic = len(entries) >= cfg.escalate_at_request_count

            confidence = min(95, 55 + total_score // 4)
            severity = Severity.CRITICAL if systematic and len(categories) > 1 else Severity.HIGH

            timestamps = sorted(e.timestamp for e in events)
            candidates.append(
                AlertCandidate(
                    dedup_key=(
                        f"{self.key}|{src_ip}|{time_bucket(timestamps[-1], cfg.window_minutes)}"
                    ),
                    title=(
                        f"Web attack indicators from {src_ip} "
                        f"({', '.join(c.replace('_', ' ') for c in categories)})"
                    ),
                    description=(
                        f"{len(entries)} request(s) from {src_ip} matched web attack "
                        f"signatures across {len(categories)} categor"
                        f"{'ies' if len(categories) != 1 else 'y'}: "
                        f"{', '.join(categories)}."
                        + (
                            " The volume and variety suggest systematic probing rather "
                            "than an isolated malformed request."
                            if systematic
                            else ""
                        )
                    ),
                    severity=severity,
                    confidence=confidence,
                    event_ids=[e.id for e in events],
                    first_seen=timestamps[0],
                    last_seen=timestamps[-1],
                    src_ip=None if src_ip == "unknown" else src_ip,
                    dst_ip=events[0].dst_ip,
                    hostname=events[0].hostname,
                    evidence={
                        "categories": categories,
                        "request_count": len(entries),
                        "total_score": total_score,
                        # Truncated so a very long hostile URL cannot bloat the
                        # alert record or the UI.
                        "sample_requests": [
                            (e.url_path or "")[:200] for e in events[:5]
                        ],
                        "window_minutes": cfg.window_minutes,
                    },
                )
            )
        return candidates
