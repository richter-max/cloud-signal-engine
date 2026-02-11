"""Core detection engine."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_
from sqlalchemy.orm import Session

from ..models import Alert, AlertStatus, AllowlistEntry
from .rules.api_abuse import ApiAbuseRule
from .rules.brute_force import BruteForceRule
from .rules.impossible_travel import ImpossibleTravelRule
from .rules.password_spray import PasswordSprayRule
from .rules.privilege_escalation import PrivilegeEscalationRule
from .rules.suspicious_user_agent import SuspiciousUserAgentRule

# Registry of all detection rules
DETECTION_RULES = [
    BruteForceRule(),
    PasswordSprayRule(),
    ImpossibleTravelRule(),
    SuspiciousUserAgentRule(),
    ApiAbuseRule(),
    PrivilegeEscalationRule(),
]


def run_detections(db: Session) -> dict:
    """
    Execute all detection rules and generate alerts.

    Args:
        db: Database session

    Returns:
        Dictionary with execution statistics
    """
    start_time = time.time()
    alerts_generated = 0
    rules_executed = []

    for rule in DETECTION_RULES:
        try:
            # Calculate time window for this rule
            window_end = datetime.now(UTC)
            window_start = window_end - timedelta(minutes=rule.window_minutes)

            # Execute detection
            detections = rule.detect(db, window_start, window_end)

            # Create alerts
            for detection in detections:
                # Check if alert should be suppressed by allowlist
                if _is_allowlisted(db, detection):
                    continue

                # Check for duplicate alerts (same rule + similar evidence in recent window)
                if _is_duplicate(db, detection):
                    continue

                # Create alert
                alert = Alert(
                    rule_id=detection["rule_id"],
                    severity=detection["severity"],
                    status=AlertStatus.OPEN.value,
                    summary=detection["summary"],
                    evidence=detection["evidence"],
                    alert_time=detection["alert_time"],
                    window_start=detection.get("window_start"),
                    window_end=detection.get("window_end"),
                )
                db.add(alert)
                alerts_generated += 1

            db.commit()
            rules_executed.append(rule.rule_id)

        except Exception as e:
            # Log error but continue with other rules
            print(f"Error executing rule {rule.rule_id}: {str(e)}")
            db.rollback()
            continue

    execution_time = (time.time() - start_time) * 1000  # milliseconds

    return {
        "alerts_generated": alerts_generated,
        "rules_executed": rules_executed,
        "execution_time_ms": round(execution_time, 2),
    }


def _is_allowlisted(db: Session, detection: dict) -> bool:
    """Check if detection should be suppressed by allowlist."""
    evidence = detection.get("evidence", {})
    rule_id = detection["rule_id"]

    # Extract potential allowlist targets from evidence
    source_ip = evidence.get("source_ip")
    actor = evidence.get("actor")

    # Check allowlist
    now = datetime.now(UTC)

    # Check IP allowlist
    if source_ip:
        ip_allowed = (
            db.query(AllowlistEntry)
            .filter(
                and_(
                    AllowlistEntry.entry_type == "ip",
                    AllowlistEntry.entry_value == source_ip,
                    or_(
                        AllowlistEntry.rule_id.is_(None),
                        AllowlistEntry.rule_id == rule_id,
                    ),
                    or_(
                        AllowlistEntry.expires_at.is_(None),
                        AllowlistEntry.expires_at > now,
                    ),
                )
            )
            .first()
        )
        if ip_allowed:
            return True

    # Check actor allowlist
    if actor:
        actor_allowed = (
            db.query(AllowlistEntry)
            .filter(
                and_(
                    AllowlistEntry.entry_type == "actor",
                    AllowlistEntry.entry_value == actor,
                    or_(
                        AllowlistEntry.rule_id.is_(None),
                        AllowlistEntry.rule_id == rule_id,
                    ),
                    or_(
                        AllowlistEntry.expires_at.is_(None),
                        AllowlistEntry.expires_at > now,
                    ),
                )
            )
            .first()
        )
        if actor_allowed:
            return True

    return False


def _is_duplicate(db: Session, detection: dict) -> bool:
    """Check if similar alert was recently created."""
    rule_id = detection["rule_id"]


    # Look for recent alerts (last 1 hour) with same rule
    recent_cutoff = datetime.now(UTC) - timedelta(hours=1)

    recent_alert = (
        db.query(Alert)
        .filter(
            and_(
                Alert.rule_id == rule_id,
                Alert.alert_time >= recent_cutoff,
            )
        )
        .first()
    )

    if recent_alert:
        # Simple deduplication: if same rule triggered recently, suppress
        # In production, compare evidence fingerprints
        return True

    return False


def or_(*clauses):
    """Helper for OR clauses in SQLAlchemy."""
    from sqlalchemy import or_ as sqlalchemy_or

    return sqlalchemy_or(*clauses)
