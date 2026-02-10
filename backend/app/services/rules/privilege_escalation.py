"""Privilege escalation / IAM elevation detection rule."""

from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from ...models import Event
from .base import DetectionRule


class PrivilegeEscalationRule(DetectionRule):
    """
    Detect privilege escalation attempts.

    Triggers when:
    - IAM role/permission changes
    - User privilege elevations
    - Administrative actions

    MITRE ATT&CK: T1078.004 (Cloud Accounts), T1548 (Abuse Elevation Control Mechanism)
    """

    @property
    def rule_id(self) -> str:
        return "privilege_escalation"

    @property
    def name(self) -> str:
        return "Privilege Escalation Detection"

    @property
    def description(self) -> str:
        return "Detects IAM privilege changes and role elevations"

    @property
    def severity(self) -> str:
        return "critical"

    @property
    def window_minutes(self) -> int:
        return 60  # 1-hour window

    # Suspicious IAM actions
    PRIVILEGE_ACTIONS = [
        "iam.role.create",
        "iam.role.update",
        "iam.role.delete",
        "iam.role.attach_policy",
        "iam.role.detach_policy",
        "iam.user.create",
        "iam.user.update",
        "iam.user.promote",
        "iam.user.add_to_group",
        "iam.policy.create",
        "iam.policy.attach",
        "permissions.grant",
        "permissions.modify",
        "admin.action",
        "createrole",
        "updaterole",
        "attachrolepolicy",
        "createuser",
        "addusertogroup",
    ]

    def detect(
        self, db: Session, window_start: datetime, window_end: datetime
    ) -> List[Dict[str, Any]]:
        """Detect privilege escalation."""
        # Query privilege-related events
        events = (
            db.query(Event)
            .filter(
                and_(
                    Event.timestamp >= window_start,
                    Event.timestamp <= window_end,
                    or_(*[Event.action.like(f"%{action}%") for action in self.PRIVILEGE_ACTIONS]),
                )
            )
            .order_by(Event.timestamp)
            .all()
        )

        alerts = []

        # Each privilege change is potentially critical
        for event in events:
            evidence = {
                "actor": event.actor,
                "action": event.action,
                "resource": event.resource,
                "outcome": event.outcome,
                "source_ip": event.source_ip,
                "timestamp": event.timestamp.isoformat(),
                "event_id": event.id,
                "user_agent": event.user_agent,
            }

            # Determine severity based on action
            severity = "critical" if "admin" in event.action.lower() else "high"

            alerts.append(
                {
                    "rule_id": self.rule_id,
                    "severity": severity,
                    "summary": f"Privilege escalation detected: {event.actor or 'unknown'} performed {event.action} on {event.resource or 'unknown resource'}",
                    "evidence": evidence,
                    "alert_time": window_end,
                    "window_start": window_start,
                    "window_end": window_end,
                }
            )

        return alerts
