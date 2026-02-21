"""Password spraying detection rule."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from ...models import Event
from .base import DetectionRule


class PasswordSprayRule(DetectionRule):
    """
    Detect password spraying attacks.

    Triggers when:
    - Single IP attempts to login as many different users
    - Indicates attacker trying common passwords across many accounts

    MITRE ATT&CK: T1110.003 (Password Spraying)
    """

    @property
    def rule_id(self) -> str:
        return "password_spray"

    @property
    def name(self) -> str:
        return "Password Spray Detection"

    @property
    def description(self) -> str:
        return "Detects login attempts targeting multiple users from a single IP"

    @property
    def severity(self) -> str:
        return "critical"

    @property
    def window_minutes(self) -> int:
        return 30  # 30-minute window

    def detect(
        self, db: Session, window_start: datetime, window_end: datetime
    ) -> List[Dict[str, Any]]:
        """Detect password spray attacks."""
        threshold = 10  # 10+ unique users targeted

        # Query login attempts grouped by source IP
        results = (
            db.query(
                Event.source_ip,
                func.count(func.distinct(Event.actor)).label("unique_users"),
                func.count(Event.id).label("total_attempts"),
                func.group_concat(Event.id).label("event_ids"),
                func.group_concat(func.distinct(Event.actor)).label("actors"),
                func.min(Event.timestamp).label("first_attempt"),
                func.max(Event.timestamp).label("last_attempt"),
            )
            .filter(
                and_(
                    Event.timestamp >= window_start,
                    Event.timestamp <= window_end,
                    Event.action.in_(["user.login", "login", "signin", "authenticate"]),
                    Event.source_ip.isnot(None),
                    Event.actor.isnot(None),
                )
            )
            .group_by(Event.source_ip)
            .having(func.count(func.distinct(Event.actor)) >= threshold)
            .all()
        )

        alerts = []
        for result in results:
            # Parse event IDs and actors
            event_ids = [int(x) for x in result.event_ids.split(",")]
            actors = result.actors.split(",") if result.actors else []

            evidence = {
                "source_ip": result.source_ip,
                "unique_users_targeted": result.unique_users,
                "total_attempts": result.total_attempts,
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
                    "summary": f"Password spray attack detected: {result.source_ip} targeted {result.unique_users} different users",
                    "evidence": evidence,
                    "alert_time": window_end,
                    "window_start": window_start,
                    "window_end": window_end,
                }
            )

        return alerts
