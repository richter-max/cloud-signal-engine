"""Quick test to see the actual error."""
import sys
sys.path.insert(0, ".")

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database import Base, engine

# Reset database
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

client = TestClient(app)

event = {
    "timestamp": "2024-02-09T20:00:00Z",
    "actor": "test_user",
    "source.ip": "192.168.1.1",
    "action": "user.login",
    "outcome": "success",
}

response = client.post("/api/v1/ingest", json=event)
print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")
