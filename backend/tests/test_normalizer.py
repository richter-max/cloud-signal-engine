"""Tests for event normalization."""

from datetime import UTC, datetime

from app.services.normalizer import normalize_event


def test_normalize_timestamp_iso8601():
    """Test ISO8601 timestamp parsing."""
    event = {"timestamp": "2024-02-09T20:00:00Z", "action": "user.login"}

    normalized = normalize_event(event)

    assert isinstance(normalized["timestamp"], datetime)
    assert normalized["timestamp"].tzinfo == UTC


def test_normalize_timestamp_unix():
    """Test Unix timestamp parsing."""
    event = {"timestamp": 1707508800, "action": "user.login"}  # 2024-02-09 20:00:00 UTC

    normalized = normalize_event(event)

    assert isinstance(normalized["timestamp"], datetime)
    assert normalized["timestamp"].tzinfo == UTC


def test_normalize_actor_variations():
    """Test actor field normalization from various field names."""
    # Test 'user' field
    event1 = {"timestamp": "2024-02-09T20:00:00Z", "user": "alice", "action": "login"}
    assert normalize_event(event1)["actor"] == "alice"

    # Test 'username' field
    event2 = {"timestamp": "2024-02-09T20:00:00Z", "username": "bob", "action": "login"}
    assert normalize_event(event2)["actor"] == "bob"

    # Test 'actor' field (direct)
    event3 = {"timestamp": "2024-02-09T20:00:00Z", "actor": "charlie", "action": "login"}
    assert normalize_event(event3)["actor"] == "charlie"


def test_normalize_source_ip_variations():
    """Test source IP normalization from various field names."""
    # Test 'source_ip'
    event1 = {"timestamp": "2024-02-09T20:00:00Z", "source_ip": "192.168.1.1", "action": "login"}
    assert normalize_event(event1)["source_ip"] == "192.168.1.1"

    # Test 'sourceIP'
    event2 = {"timestamp": "2024-02-09T20:00:00Z", "sourceIP": "10.0.0.1", "action": "login"}
    assert normalize_event(event2)["source_ip"] == "10.0.0.1"

    # Test nested 'source.ip'
    event3 = {
        "timestamp": "2024-02-09T20:00:00Z",
        "source": {"ip": "172.16.0.1"},
        "action": "login",
    }
    assert normalize_event(event3)["source_ip"] == "172.16.0.1"


def test_normalize_action():
    """Test action normalization."""
    event = {"timestamp": "2024-02-09T20:00:00Z", "action": "login"}

    normalized = normalize_event(event)

    # 'login' should be normalized to 'user.login'
    assert normalized["action"] == "user.login"


def test_normalize_outcome():
    """Test outcome normalization."""
    # Test 'success'
    event1 = {"timestamp": "2024-02-09T20:00:00Z", "action": "login", "outcome": "success"}
    assert normalize_event(event1)["outcome"] == "success"

    # Test HTTP 200
    event2 = {"timestamp": "2024-02-09T20:00:00Z", "action": "login", "status": "200"}
    assert normalize_event(event2)["outcome"] == "success"

    # Test 'failure'
    event3 = {"timestamp": "2024-02-09T20:00:00Z", "action": "login", "outcome": "failure"}
    assert normalize_event(event3)["outcome"] == "failure"

    # Test HTTP 401
    event4 = {"timestamp": "2024-02-09T20:00:00Z", "action": "login", "status": "401"}
    assert normalize_event(event4)["outcome"] == "failure"


def test_normalize_generates_request_id():
    """Test that request_id is generated if not provided."""
    event = {"timestamp": "2024-02-09T20:00:00Z", "action": "login"}

    normalized = normalize_event(event)

    assert "request_id" in normalized
    assert normalized["request_id"] is not None


def test_normalize_stores_raw_data():
    """Test that raw event data is stored."""
    event = {
        "timestamp": "2024-02-09T20:00:00Z",
        "actor": "test",
        "action": "login",
        "custom_field": "custom_value",
    }

    normalized = normalize_event(event)

    assert normalized["raw_data"] == event
    assert normalized["raw_data"]["custom_field"] == "custom_value"
