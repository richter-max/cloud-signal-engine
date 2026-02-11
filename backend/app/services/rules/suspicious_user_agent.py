"""Suspicious user-agent detection rule."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import and_
from sqlalchemy.orm import Session

from ...models import Event
from .base import DetectionRule


class SuspiciousUserAgentRule(DetectionRule):
    """
    Detect suspicious user agents.

    Triggers when:
    - Empty user agent strings
    - Known automation tools (curl, wget, python-requests)
    - Suspicious patterns indicating bots or scrapers

    MITRE ATT&CK: T1071 (Application Layer Protocol)
    """

    @property
    def rule_id(self) -> str:
        return "suspicious_user_agent"

    @property
    def name(self) -> str:
        return "Suspicious User-Agent Detection"

    @property
    def description(self) -> str:
        return "Detects requests with suspicious or automated user agent strings"

    @property
    def severity(self) -> str:
        return "medium"

    @property
    def window_minutes(self) -> int:
        return 15  # 15-minute window

    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        r"^$",  # Empty
        r"curl",
        r"wget",
        r"python-requests",
        r"python-urllib",
        r"scrapy",
        r"bot",
        r"crawler",
        r"spider",
        r"httpx",
        r"http\.client",
        r"libwww",
        r"^-$",  # Single dash
    ]

    def detect(
        self, db: Session, window_start: datetime, window_end: datetime
    ) -> List[Dict[str, Any]]:
        """Detect suspicious user agents."""
        # Get events with user agents
        events = (
            db.query(Event)
            .filter(
                and_(
                    Event.timestamp >= window_start,
                    Event.timestamp <= window_end,
                    Event.user_agent.isnot(None),
                )
            )
            .all()
        )

        # Group by user agent and check patterns
        suspicious_groups = {}

        for event in events:
            ua = event.user_agent or ""

            # Check if user agent matches suspicious patterns
            if self._is_suspicious(ua):
                if ua not in suspicious_groups:
                    suspicious_groups[ua] = {
                        "user_agent": ua,
                        "event_ids": [],
                        "actors": set(),
                        "source_ips": set(),
                        "count": 0,
                    }

                suspicious_groups[ua]["event_ids"].append(event.id)
                suspicious_groups[ua]["count"] += 1
                if event.actor:
                    suspicious_groups[ua]["actors"].add(event.actor)
                if event.source_ip:
                    suspicious_groups[ua]["source_ips"].add(event.source_ip)

        # Generate alerts for groups with multiple requests
        alerts = []
        threshold = 5  # 5+ requests with suspicious UA

        for ua, data in suspicious_groups.items():
            if data["count"] >= threshold:
                evidence = {
                    "user_agent": ua,
                    "request_count": data["count"],
                    "actors": list(data["actors"]),
                    "source_ips": list(data["source_ips"]),
                    "event_ids": data["event_ids"],
                    "pattern_matched": self._get_matched_pattern(ua),
                }

                alerts.append(
                    {
                        "rule_id": self.rule_id,
                        "severity": self.severity,
                        "summary": f"Suspicious user agent detected: {data['count']} requests with automated/suspicious UA",
                        "evidence": evidence,
                        "alert_time": window_end,
                        "window_start": window_start,
                        "window_end": window_end,
                    }
                )

        return alerts

    def _is_suspicious(self, user_agent: str) -> bool:
        """Check if user agent matches suspicious patterns."""
        ua_lower = user_agent.lower()

        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, ua_lower, re.IGNORECASE):
                return True

        return False

    def _get_matched_pattern(self, user_agent: str) -> str:
        """Get the pattern that matched the suspicious UA."""
        ua_lower = user_agent.lower()

        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, ua_lower, re.IGNORECASE):
                return pattern

        return "unknown"
