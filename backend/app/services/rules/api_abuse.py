"""API abuse / rate spike detection rule."""

from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from ...models import Event
from .base import DetectionRule


class ApiAbuseRule(DetectionRule):
    """
    Detect API abuse through rate spikes.

    Triggers when:
    - Unusually high request rate from single IP or actor
    - Potential DoS, scraping, or credential stuffing

    MITRE ATT&CK: T1498 (Network Denial of Service)
    """

    @property
    def rule_id(self) -> str:
        return "api_abuse"

    @property
    def name(self) -> str:
        return "API Abuse / Rate Spike Detection"

    @property
    def description(self) -> str:
        return "Detects abnormally high API request rates indicating abuse"

    @property
    def severity(self) -> str:
        return "medium"

    @property
    def window_minutes(self) -> int:
        return 5  # 5-minute window

    def detect(
        self, db: Session, window_start: datetime, window_end: datetime
    ) -> List[Dict[str, Any]]:
        """Detect API abuse."""
        threshold = 100  # 100+ requests in 5 minutes

        alerts = []

        # Check by source IP
        ip_results = (
            db.query(
                Event.source_ip,
                func.count(Event.id).label("request_count"),
                func.group_concat(Event.action).label("actions"),
                func.count(func.distinct(Event.action)).label("unique_actions"),
                func.min(Event.timestamp).label("first_request"),
                func.max(Event.timestamp).label("last_request"),
            )
            .filter(
                and_(
                    Event.timestamp >= window_start,
                    Event.timestamp <= window_end,
                    Event.source_ip.isnot(None),
                )
            )
            .group_by(Event.source_ip)
            .having(func.count(Event.id) >= threshold)
            .all()
        )

        for result in ip_results:
            evidence = {
                "source_ip": result.source_ip,
                "request_count": result.request_count,
                "unique_actions": result.unique_actions,
                "requests_per_second": round(
                    result.request_count
                    / max((result.last_request - result.first_request).total_seconds(), 1),
                    2,
                ),
                "first_request": result.first_request.isoformat(),
                "last_request": result.last_request.isoformat(),
            }

            alerts.append(
                {
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "summary": f"API abuse detected: {result.request_count} requests from {result.source_ip} in {self.window_minutes} minutes",
                    "evidence": evidence,
                    "alert_time": window_end,
                    "window_start": window_start,
                    "window_end": window_end,
                }
            )

        # Check by actor (authenticated abuse)
        actor_results = (
            db.query(
                Event.actor,
                func.count(Event.id).label("request_count"),
                func.group_concat(func.distinct(Event.source_ip)).label("source_ips"),
                func.count(func.distinct(Event.action)).label("unique_actions"),
                func.min(Event.timestamp).label("first_request"),
                func.max(Event.timestamp).label("last_request"),
            )
            .filter(
                and_(
                    Event.timestamp >= window_start,
                    Event.timestamp <= window_end,
                    Event.actor.isnot(None),
                )
            )
            .group_by(Event.actor)
            .having(func.count(Event.id) >= threshold)
            .all()
        )

        for result in actor_results:
            source_ips = result.source_ips.split(",") if result.source_ips else []

            evidence = {
                "actor": result.actor,
                "request_count": result.request_count,
                "unique_actions": result.unique_actions,
                "source_ips": source_ips,
                "requests_per_second": round(
                    result.request_count
                    / max((result.last_request - result.first_request).total_seconds(), 1),
                    2,
                ),
                "first_request": result.first_request.isoformat(),
                "last_request": result.last_request.isoformat(),
            }

            alerts.append(
                {
                    "rule_id": self.rule_id,
                    "severity": self.severity,
                    "summary": f"API abuse detected: {result.request_count} requests from user {result.actor} in {self.window_minutes} minutes",
                    "evidence": evidence,
                    "alert_time": window_end,
                    "window_start": window_start,
                    "window_end": window_end,
                }
            )

        return alerts
