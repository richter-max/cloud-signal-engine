"""Tests for API endpoints."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine


@pytest.fixture
def client():
    """Create test client."""
    # Reset database
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_ingest_single_event(client):
    """Test ingesting a single event."""
    event = {
        "timestamp": "2024-02-09T20:00:00Z",
        "actor": "test_user",
        "source.ip": "192.168.1.1",
        "action": "user.login",
        "outcome": "success",
    }

    response = client.post("/api/v1/ingest", json=event)
    assert response.status_code == 200

    data = response.json()
    assert data["ingested"] == 1
    assert len(data["event_ids"]) == 1


def test_ingest_batch_events(client):
    """Test ingesting multiple events."""
    events = [
        {
            "timestamp": "2024-02-09T20:00:00Z",
            "actor": "user1",
            "action": "user.login",
        },
        {
            "timestamp": "2024-02-09T20:01:00Z",
            "actor": "user2",
            "action": "user.login",
        },
    ]

    response = client.post("/api/v1/ingest", json=events)
    assert response.status_code == 200

    data = response.json()
    assert data["ingested"] == 2
    assert len(data["event_ids"]) == 2


def test_list_alerts_empty(client):
    """Test listing alerts when none exist."""
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert response.json() == []


def test_run_detections(client):
    """Test manual detection trigger."""
    response = client.post("/api/v1/detections/run")
    assert response.status_code == 200

    data = response.json()
    assert "alerts_generated" in data
    assert "rules_executed" in data
    assert "execution_time_ms" in data


def test_update_alert_status(client):
    """Test updating alert status."""
    # First, create an event and generate an alert
    events = [
        {
            "timestamp": "2024-02-09T20:00:00Z",
            "actor": "test_user",
            "source.ip": "192.168.1.100",
            "action": "user.login",
            "outcome": "failure",
        }
        for _ in range(10)
    ]

    client.post("/api/v1/ingest", json=events)
    client.post("/api/v1/detections/run")

    # Get alerts
    alerts_response = client.get("/api/v1/alerts")
    alerts = alerts_response.json()

    if len(alerts) > 0:
        alert_id = alerts[0]["id"]

        # Update status
        response = client.patch(
            f"/api/v1/alerts/{alert_id}/status",
            json={"status": "triaged"},
        )
        assert response.status_code == 200

        updated_alert = response.json()
        assert updated_alert["status"] == "triaged"


def test_add_to_allowlist(client):
    """Test adding entry to allowlist."""
    entry = {
        "entry_type": "ip",
        "entry_value": "192.168.1.1",
        "reason": "Corporate VPN",
    }

    response = client.post("/api/v1/allowlist", json=entry)
    assert response.status_code == 200

    data = response.json()
    assert data["entry_type"] == "ip"
    assert data["entry_value"] == "192.168.1.1"


def test_list_allowlist(client):
    """Test listing allowlist entries."""
    # Add an entry
    client.post(
        "/api/v1/allowlist",
        json={
            "entry_type": "actor",
            "entry_value": "service_account",
            "reason": "Automated service",
        },
    )

    # List
    response = client.get("/api/v1/allowlist")
    assert response.status_code == 200

    entries = response.json()
    assert len(entries) >= 1
