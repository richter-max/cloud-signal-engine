"""Script to populate test data for SignalForge dashboard."""

import requests
from datetime import datetime, timedelta
import random

BASE_URL = "http://localhost:8000/api/v1"

# Test event data - various security scenarios
test_events = []

# 1. Brute force attack from suspicious IP
now = datetime.utcnow()
attacker_ip = "203.0.113.42"
for i in range(15):
    test_events.append({
        "timestamp": (now - timedelta(minutes=30 - i)).isoformat(),
        "actor": "admin",
        "source_ip": attacker_ip,
        "user_agent": "Mozilla/5.0",
        "action": "user.login",
        "outcome": "failure",
        "request_id": f"req-brute-{i}"
    })

# 2. Successful login after brute force
test_events.append({
    "timestamp": (now - timedelta(minutes=10)).isoformat(),
    "actor": "admin",
    "source_ip": attacker_ip,
    "user_agent": "Mozilla/5.0",
    "action": "user.login",
    "outcome": "success",
    "request_id": "req-brute-success"
})

# 3. Password spray attack (different users)
spray_ip = "198.51.100.85"
users = ["alice", "bob", "charlie", "david", "emma", "frank", "grace"]
for i, user in enumerate(users):
    test_events.append({
        "timestamp": (now - timedelta(minutes=45 - i*2)).isoformat(),
        "actor": user,
        "source_ip": spray_ip,
        "user_agent": "curl/7.68.0",
        "action": "user.login",
        "outcome": "failure",
        "request_id": f"req-spray-{i}"
    })

# 4. Suspicious user agent (SQL injection attempt)
test_events.append({
    "timestamp": (now - timedelta(minutes=20)).isoformat(),
    "actor": "guest",
    "source_ip": "192.0.2.15",
    "user_agent": "python-requests/2.25.1",
    "action": "api.query",
    "resource": "/api/users?id=1' OR '1'='1",
    "outcome": "failure",
    "request_id": "req-sqli-1"
})

# 5. API abuse (rate limit violation)
api_abuser_ip = "198.51.100.200"
for i in range(120):
    test_events.append({
        "timestamp": (now - timedelta(seconds=60 - i/2)).isoformat(),
        "actor": "api_user_123",
        "source_ip": api_abuser_ip,
        "user_agent": "PostmanRuntime/7.28.4",
        "action": "api.request",
        "resource": "/api/v1/data",
        "outcome": "success" if i < 100 else "failure",
        "request_id": f"req-api-{i}"
    })

# 6. Privilege escalation attempt
test_events.extend([
    {
        "timestamp": (now - timedelta(minutes=15)).isoformat(),
        "actor": "lowpriv_user",
        "source_ip": "192.0.2.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "action": "iam.role.create",
        "resource": "AdminRole",
        "outcome": "failure",
        "request_id": "req-privesc-1"
    },
    {
        "timestamp": (now - timedelta(minutes=14)).isoformat(),
        "actor": "lowpriv_user",
        "source_ip": "192.0.2.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "action": "iam.role.attach_policy",
        "resource": "AdminAccess",
        "outcome": "failure",
        "request_id": "req-privesc-2"
    },
    {
        "timestamp": (now - timedelta(minutes=13)).isoformat(),
        "actor": "lowpriv_user",
        "source_ip": "192.0.2.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "action": "iam.user.update",
        "resource": "permissions",
        "outcome": "failure",
        "request_id": "req-privesc-3"
    }
])

# 7. Impossible travel (login from different continents)
test_events.extend([
    {
        "timestamp": (now - timedelta(minutes=35)).isoformat(),
        "actor": "traveling_user",
        "source_ip": "185.220.101.50",  # Europe
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
        "action": "user.login",
        "outcome": "success",
        "request_id": "req-travel-1"
    },
    {
        "timestamp": (now - timedelta(minutes=30)).isoformat(),
        "actor": "traveling_user",
        "source_ip": "54.240.197.233",  # US East Coast
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)",
        "action": "user.login",
        "outcome": "success",
        "request_id": "req-travel-2"
    }
])

# 8. Normal activity (to make it realistic)
normal_users = ["sarah", "mike", "jenny", "tom"]
for i in range(20):
    user = random.choice(normal_users)
    test_events.append({
        "timestamp": (now - timedelta(minutes=random.randint(5, 60))).isoformat(),
        "actor": user,
        "source_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "action": random.choice(["api.request", "user.login", "storage.object.read"]),
        "outcome": "success",
        "request_id": f"req-normal-{i}"
    })

print(f"Created {len(test_events)} test events")

# Ingest events
print("\n📥 Ingesting events...")
response = requests.post(f"{BASE_URL}/ingest", json=test_events)
if response.ok:
    result = response.json()
    print(f"✅ Ingested {result['ingested']} events")
    if result.get('errors'):
        print(f"⚠️  Errors: {result['errors']}")
else:
    print(f"❌ Failed to ingest: {response.status_code} - {response.text}")
    exit(1)

# Run detection engine
print("\n🔍 Running detection engine...")
response = requests.post(f"{BASE_URL}/detections/run")
if response.ok:
    result = response.json()
    print(f"✅ Generated {result['alerts_generated']} alerts")
    print(f"📋 Rules executed: {', '.join(result['rules_executed'])}")
    print(f"⏱️  Execution time: {result['execution_time_ms']:.2f}ms")
else:
    print(f"❌ Failed to run detections: {response.status_code} - {response.text}")
    exit(1)

# Fetch and display alerts
print("\n📊 Fetching generated alerts...")
response = requests.get(f"{BASE_URL}/alerts?limit=100")
if response.ok:
    alerts = response.json()
    print(f"\n🚨 {len(alerts)} total alerts generated:")
    for alert in alerts[:10]:  # Show first 10
        print(f"  - [{alert['severity'].upper()}] {alert['summary']}")
    if len(alerts) > 10:
        print(f"  ... and {len(alerts) - 10} more")
else:
    print(f"❌ Failed to fetch alerts: {response.status_code}")

print("\n✨ Test data loaded! Refresh your browser to see the dashboard.")
