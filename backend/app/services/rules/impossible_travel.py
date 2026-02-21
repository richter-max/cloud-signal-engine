"""Impossible travel detection rule."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy import and_
from sqlalchemy.orm import Session

from ...models import Event
from .base import DetectionRule


class ImpossibleTravelRule(DetectionRule):
    """
    Detect impossible travel scenarios.

    Triggers when:
    - Same user logs in from geographically distant locations
    - Within a timeframe that makes physical travel impossible

    MITRE ATT&CK: T1078 (Valid Accounts - credential compromise)
    """

    @property
    def rule_id(self) -> str:
        return "impossible_travel"

    @property
    def name(self) -> str:
        return "Impossible Travel Detection"

    @property
    def description(self) -> str:
        return "Detects logins from geographically impossible locations within short timeframes"

    @property
    def severity(self) -> str:
        return "high"

    @property
    def window_minutes(self) -> int:
        return 60  # 1-hour window

    def detect(
        self, db: Session, window_start: datetime, window_end: datetime
    ) -> List[Dict[str, Any]]:
        """Detect impossible travel."""
        # Get login events grouped by user
        events = (
            db.query(Event)
            .filter(
                and_(
                    Event.timestamp >= window_start,
                    Event.timestamp <= window_end,
                    Event.action.in_(["user.login", "login", "signin", "authenticate"]),
                    Event.outcome == "success",
                    Event.actor.isnot(None),
                    Event.source_ip.isnot(None),
                )
            )
            .order_by(Event.actor, Event.timestamp)
            .all()
        )

        # Group events by actor
        user_events = {}
        for event in events:
            if event.actor not in user_events:
                user_events[event.actor] = []
            user_events[event.actor].append(event)

        alerts = []

        # Check for impossible travel per user
        for actor, actor_events in user_events.items():
            if len(actor_events) < 2:
                continue

            # Check consecutive logins
            for i in range(len(actor_events) - 1):
                event1 = actor_events[i]
                event2 = actor_events[i + 1]

                # Simple heuristic: different IP prefixes indicate different locations
                # In production, use GeoIP database
                distance_km = self._estimate_distance(event1.source_ip, event2.source_ip)
                time_delta = (event2.timestamp - event1.timestamp).total_seconds() / 3600  # hours

                # If locations are far apart and time is short
                if distance_km > 500 and time_delta < 2:  # 500km in < 2 hours
                    evidence = {
                        "actor": actor,
                        "location1": {
                            "ip": event1.source_ip,
                            "timestamp": event1.timestamp.isoformat(),
                            "event_id": event1.id,
                        },
                        "location2": {
                            "ip": event2.source_ip,
                            "timestamp": event2.timestamp.isoformat(),
                            "event_id": event2.id,
                        },
                        "estimated_distance_km": distance_km,
                        "time_delta_hours": round(time_delta, 2),
                        "impossible_speed_kmh": round(distance_km / time_delta, 2)
                        if time_delta > 0
                        else 0,
                    }

                    alerts.append(
                        {
                            "rule_id": self.rule_id,
                            "severity": self.severity,
                            "summary": f"Impossible travel detected: {actor} logged in from {event1.source_ip} and {event2.source_ip} within {round(time_delta, 1)} hours",
                            "evidence": evidence,
                            "alert_time": window_end,
                            "window_start": window_start,
                            "window_end": window_end,
                        }
                    )

        return alerts

    def _estimate_distance(self, ip1: str, ip2: str) -> float:
        """
        Estimate distance between two IPs.

        MVP: Simple heuristic based on IP prefix differences.
        Production: Use GeoIP2 database for actual geolocation.
        """
        if ip1 == ip2:
            return 0.0

        # Parse IP prefixes
        parts1 = ip1.split(".")
        parts2 = ip2.split(".")

        # Count differing octets (very rough heuristic)
        diffs = sum(1 for i in range(min(len(parts1), len(parts2))) if parts1[i] != parts2[i])

        # Heuristic distance estimation
        # Same /8: 0-100km, /16: 100-500km, /24: 500-2000km, different: 2000+km
        distance_map = {0: 0, 1: 50, 2: 300, 3: 1000, 4: 2500}

        return distance_map.get(diffs, 2500)
