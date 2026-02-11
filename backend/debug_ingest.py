from datetime import datetime

import requests

url = "http://localhost:8000/api/v1/ingest"
event = {
    "timestamp": datetime.utcnow().isoformat(),
    "action": "test.action",
    "source_ip": "127.0.0.1",
    "outcome": "success",
}

print(f"Sending event: {event}")
try:
    resp = requests.post(url, json=event)
    print(f"Status: {resp.status_code}")
    print(f"Response: {resp.text}")
except Exception as e:
    print(f"Error: {e}")
