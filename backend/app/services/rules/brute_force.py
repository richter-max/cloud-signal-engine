"""Brute force login detection rule."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from ...models import Event
from .base import DetectionRule


class BruteForceRule(DetectionRule):
    """
    Detect brute force login attempts.

    Triggers when:
    - Multiple failed login attempts from the same source IP
    - Within a short time window

    MITRE ATT&CK: T1110 (Brute Force)
    """

    @property
    def rule_id(self) -> str:
        return "brute_force_login"

    @property
    def name(self) -> str:
        return "Brute Force Login Detection"

    @property
    def description(self) -> str:
        return "Detects multiple failed login attempts from the same IP address"

    @property
    def severity(self) -> str:
        return "high"

    @property
    def window_minutes(self) -> int:
        return 15  # 15-minute window

    def detect(
        self, db: Session, window_start: datetime, window_end: datetime
    ) -> List[Dict[str, Any]]:
        """Detect brute force attacks."""
        threshold = 5  # 5+ failed attempts triggers alert

        # Query failed login attempts
        results = (
            db.query(
                Event.source_ip,
                func.count(Event.id).label("attempt_count"),
                func.group_concat(Event.id).label("event_ids"),
                func.group_concat(Event.actor).label("actors"),
                func.min(Event.timestamp).label("first_attempt"),
                func.max(Event.timestamp).label("last_attempt"),
            )
            .filter(
                and_(
                    Event.timestamp >= window_start,
                    Event.timestamp <= window_end,
                    Event.action.in_(["user.login", "login", "signin", "authenticate"]),
                    Event.outcome == "failure",
                    Event.source_ip.isnot(None),
                )
            )
            .group_by(Event.source_ip)
            .having(func.count(Event.id) >= threshold)
            .all()
        )

        alerts = []
        for result in results:
            # Parse event IDs and actors
            event_ids = [int(x) for x in result.event_ids.split(",")]
            actors = list(set(result.actors.split(","))) if result.actors else []

            evidence = {
                "source_ip": result.source_ip,
                "attempt_count": result.attempt_count,
                "targeted_users": actors,
                "event_ids": event_ids,
                "first_attempt": result.first_attempt.isoformat(),
                "last_attempt": result.last_attempt.isoformat(),
                "time_span_seconds": (result.last_attempt - result.first_attempt).total_seconds(),
            }

            alerts.append(
                {
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "summary": f"Brute force attack detected: {result.attempt_count} failed login attempts from {result.source_ip}",
                    "evidence": evidence,
                    "alert_time": window_end,
                    "window_start": window_start,
                    "window_end": window_end,
                }
            )

        return alerts
