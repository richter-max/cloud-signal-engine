"""Tests for detection rules."""

from datetime import UTC, datetime, timedelta

import pytest
from app.database import Base
from app.models import Event
from app.services.rules.api_abuse import ApiAbuseRule
from app.services.rules.brute_force import BruteForceRule
from app.services.rules.impossible_travel import ImpossibleTravelRule
from app.services.rules.password_spray import PasswordSprayRule
from app.services.rules.privilege_escalation import PrivilegeEscalationRule
from app.services.rules.suspicious_user_agent import SuspiciousUserAgentRule
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def db_session():
    """Create test database session."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_brute_force_rule(db_session):
    """Test brute force detection."""
    rule = BruteForceRule()
    now = datetime.now(UTC)
    window_start = now - timedelta(minutes=15)

    # Create 10 failed login attempts from same IP
    for i in range(10):
        event = Event(
            timestamp=now - timedelta(minutes=i),
            actor="test_user",
            source_ip="192.168.1.100",
            action="user.login",
            outcome="failure",
        )
        db_session.add(event)

    db_session.commit()

    # Run detection
    alerts = rule.detect(db_session, window_start, now)

    # Should trigger alert (threshold is 5)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "brute_force_login"
    assert alerts[0]["severity"] == "high"
    assert "192.168.1.100" in alerts[0]["summary"]


def test_password_spray_rule(db_session):
    """Test password spray detection."""
    rule = PasswordSprayRule()
    now = datetime.now(UTC)
    window_start = now - timedelta(minutes=30)

    # Create login attempts to 15 different users from same IP
    for i in range(15):
        event = Event(
            timestamp=now - timedelta(minutes=i * 2),
            actor=f"user_{i}",
            source_ip="10.0.0.50",
            action="user.login",
            outcome="failure",
        )
        db_session.add(event)

    db_session.commit()

    # Run detection
    alerts = rule.detect(db_session, window_start, now)

    # Should trigger alert (threshold is 10 users)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "password_spray"
    assert alerts[0]["severity"] == "critical"
    assert "10.0.0.50" in alerts[0]["summary"]


def test_impossible_travel_rule(db_session):
    """Test impossible travel detection."""
    rule = ImpossibleTravelRule()
    now = datetime.now(UTC)
    window_start = now - timedelta(hours=1)

    # Login from US IP
    event1 = Event(
        timestamp=now - timedelta(minutes=45),
        actor="alice",
        source_ip="192.168.1.1",
        action="user.login",
        outcome="success",
    )

    # Login from very different IP 30 minutes later (should trigger)
    event2 = Event(
        timestamp=now - timedelta(minutes=15),
        actor="alice",
        source_ip="85.123.45.67",
        action="user.login",
        outcome="success",
    )

    db_session.add_all([event1, event2])
    db_session.commit()

    # Run detection
    alerts = rule.detect(db_session, window_start, now)

    # Should trigger alert
    assert len(alerts) >= 1
    assert any(a["rule_id"] == "impossible_travel" for a in alerts)


def test_suspicious_user_agent_rule(db_session):
    """Test suspicious user-agent detection."""
    rule = SuspiciousUserAgentRule()
    now = datetime.now(UTC)
    window_start = now - timedelta(minutes=15)

    # Create 10 requests with curl user agent
    for i in range(10):
        event = Event(
            timestamp=now - timedelta(minutes=i),
            actor="bot_user",
            source_ip="45.76.123.98",
            user_agent="curl/7.68.0",
            action="storage.object.read",
            outcome="success",
        )
        db_session.add(event)

    db_session.commit()

    # Run detection
    alerts = rule.detect(db_session, window_start, now)

    # Should trigger alert (threshold is 5)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "suspicious_user_agent"
    assert "curl" in alerts[0]["evidence"]["user_agent"]


def test_api_abuse_rule(db_session):
    """Test API abuse detection."""
    rule = ApiAbuseRule()
    now = datetime.now(UTC)
    window_start = now - timedelta(minutes=5)

    # Create 150 requests from same IP in 5 minutes
    for i in range(150):
        event = Event(
            timestamp=now - timedelta(seconds=i * 2),
            actor="scraper",
            source_ip="203.0.113.45",
            action="storage.object.read",
            outcome="success",
        )
        db_session.add(event)

    db_session.commit()

    # Run detection
    alerts = rule.detect(db_session, window_start, now)

    # Should trigger alert (threshold is 100)
    assert len(alerts) >= 1
    assert any(a["rule_id"] == "api_abuse" for a in alerts)


def test_privilege_escalation_rule(db_session):
    """Test privilege escalation detection."""
    rule = PrivilegeEscalationRule()
    now = datetime.now(UTC)
    window_start = now - timedelta(hours=1)

    # Create IAM role change event
    event = Event(
        timestamp=now - timedelta(minutes=10),
        actor="admin_user",
        source_ip="192.168.1.10",
        action="iam.role.attach_policy",
        resource="admin-role",
        outcome="success",
    )

    db_session.add(event)
    db_session.commit()

    # Run detection
    alerts = rule.detect(db_session, window_start, now)

    # Should trigger alert (any IAM action triggers)
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "privilege_escalation"
    assert alerts[0]["severity"] in ["high", "critical"]


def test_brute_force_no_alert_below_threshold(db_session):
    """Test that brute force doesn't trigger below threshold."""
    rule = BruteForceRule()
    now = datetime.now(UTC)
    window_start = now - timedelta(minutes=15)

    # Create only 3 failed attempts (below threshold of 5)
    for i in range(3):
        event = Event(
            timestamp=now - timedelta(minutes=i),
            actor="test_user",
            source_ip="192.168.1.100",
            action="user.login",
            outcome="failure",
        )
        db_session.add(event)

    db_session.commit()

    # Run detection
    alerts = rule.detect(db_session, window_start, now)

    # Should NOT trigger alert
    assert len(alerts) == 0
