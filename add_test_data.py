"""Simplified script to add test security alerts to SignalForge."""

import requests
from datetime import datetime, timedelta

BASE_URL = "http://localhost:8000/api/v1"
now = datetime.utcnow()

print("🔥 Adding test security events to SignalForge...\n")

# Helper function to ingest a single event
def ingest_event(event):
    response = requests.post(f"{BASE_URL}/ingest", json=event)
    return response.ok

# Event counter
total_ingested = 0

# 1. Brute Force Attack - 15 failed logins
print("📍 Creating brute force attack...")
attacker_ip = "203.0.113.42"
for i in range(15):
    event = {
        "timestamp": (now - timedelta(minutes=30 - i)).isoformat() + "Z",
        "actor": "admin",
        "source_ip": attacker_ip,
        "action": "user.login",
        "outcome": "failure"
    }
    if ingest_event(event):
        total_ingested += 1

# 2. Password Spray - Multiple users, same IP
print("📍 Creating password spray attack...")
spray_ip = "198.51.100.85"
for i, user in enumerate(["alice", "bob", "charlie", "david", "emma", "frank"]):
    event = {
        "timestamp": (now - timedelta(minutes=25 - i)).isoformat() + "Z",
        "actor": user,
        "source_ip": spray_ip,
        "action": "user.login",
        "outcome": "failure"  
    }
    if ingest_event(event):
        total_ingested += 1

# 3. API Abuse - 100 requests in 1 minute
print("📍 Creating API abuse...")
api_ip = "198.51.100.200"
for i in range(100):
    event = {
        "timestamp": (now - timedelta(seconds=60 - i*0.5)).isoformat() + "Z",
        "actor": "api_user_123",
        "source_ip": api_ip,
        "action": "api.request",
        "outcome": "success"
    }
    if ingest_event(event):
        total_ingested += 1

# 4. Privilege Escalation Attempts
print("📍 Creating privilege escalation attempts...")
for i, action in enumerate(["iam.role.create", "iam.role.attach_policy", "iam.user.update"]):
    event = {
        "timestamp": (now - timedelta(minutes=15 - i)).isoformat() + "Z",
        "actor": "lowpriv_user",
        "source_ip": "192.0.2.100",
        "action": action,
        "outcome": "failure"
    }
    if ingest_event(event):
        total_ingested += 1

# 5. Suspicious User Agent
print("📍 Creating suspicious user agent activity...")
for i in range(5):
    event = {
        "timestamp": (now - timedelta(minutes=20 - i)).isoformat() + "Z",
        "actor": "guest",
        "source_ip": "192.0.2.15",
        "user_agent": "sqlmap/1.0",
        "action": "api.query",
        "outcome": "failure"
    }
    if ingest_event(event):
        total_ingested += 1

print(f"\n✅ Ingested {total_ingested} events successfully!")

# Run detection engine
print("\n🔍 Running detection engine...")
response = requests.post(f"{BASE_URL}/detections/run")
if response.ok:
    result = response.json()
    print(f"✅ Generated {result['alerts_generated']} alerts")
    print(f"⏱️  Execution time: {result['execution_time_ms']:.2f}ms\n")
    
    # Show the alerts
    response = requests.get(f"{BASE_URL}/alerts?limit=20")
    if response.ok:
        alerts = response.json()
        print(f"🚨 Total Alerts: {len(alerts)}\n")
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in alerts:
            severity_counts[alert['severity']] += 1
            print(f"  [{alert['severity'].upper():8s}] {alert['summary']}")
        
        print(f"\n📊 Breakdown:")
        print(f"   Critical: {severity_counts['critical']}")
        print(f"   High:     {severity_counts['high']}")
        print(f"   Medium:   {severity_counts['medium']}")
        print(f"   Low:      {severity_counts['low']}")
else:
    print(f"❌ Detection run failed: {response.text}")

print("\n✨ Dashboard is ready! Open http://localhost:3000 in your browser.")
