"""Generate realistic demo logs for SignalForge."""

import json
import random
from datetime import datetime, timedelta, timezone

# Realistic user names
USERS = [
    "alice.smith",
    "bob.jones",
    "charlie.davis",
    "diana.wilson",
    "eve.miller",
    "frank.thomas",
    "grace.anderson",
    "henry.martin",
    "iris.taylor",
    "jack.brown",
]

# Realistic IP addresses
NORMAL_IPS = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "10.0.0.5",
    "10.0.0.6",
    "172.16.0.10",
]

ATTACK_IPS = [
    "203.0.113.45",  # Brute force attacker
    "198.51.100.50",  # Password spray
    "45.76.123.98",  # API abuse
]

ACTIONS = [
    "user.login",
    "user.logout",
    "storage.object.read",
    "storage.object.create",
    "storage.object.delete",
    "iam.user.list",
    "iam.role.list",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

SUSPICIOUS_USER_AGENTS = [
    "curl/7.68.0",
    "python-requests/2.28.1",
    "wget/1.20.3",
    "",
]


def generate_normal_activity(count=1000, start_time=None):
    """Generate normal user activity logs."""
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(hours=2)

    events = []

    for i in range(count):
        timestamp = start_time + timedelta(seconds=random.randint(0, 7200))
        user = random.choice(USERS)
        ip = random.choice(NORMAL_IPS)
        action = random.choice(ACTIONS)
        ua = random.choice(USER_AGENTS)

        # Most actions succeed
        outcome = "success" if random.random() > 0.05 else "failure"

        event = {
            "timestamp": timestamp.isoformat(),
            "actor": user,
            "source.ip": ip,
            "user_agent": ua,
            "action": action,
            "resource": f"resource-{random.randint(1, 100)}",
            "outcome": outcome,
            "request_id": f"req-{i:06d}",
        }

        events.append(event)

    return events


def generate_brute_force_attack(target_user="alice.smith", start_time=None):
    """Generate brute force attack logs."""
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(minutes=30)

    events = []
    attacker_ip = "203.0.113.45"

    # 15 failed login attempts in 10 minutes
    for i in range(15):
        timestamp = start_time + timedelta(seconds=random.randint(0, 600))

        event = {
            "timestamp": timestamp.isoformat(),
            "actor": target_user,
            "source.ip": attacker_ip,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "action": "user.login",
            "resource": "authentication_service",
            "outcome": "failure",
            "request_id": f"brute-{i:03d}",
        }

        events.append(event)

    return events


def generate_password_spray(start_time=None):
    """Generate password spray attack logs."""
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(minutes=25)

    events = []
    attacker_ip = "198.51.100.50"

    # Attacker tries same password against 15 different users
    for i, user in enumerate(USERS + ["test.user", "admin.user", "service.account", "guest.user", "demo.user"]):
        timestamp = start_time + timedelta(seconds=random.randint(0, 1500))

        event = {
            "timestamp": timestamp.isoformat(),
            "actor": user,
            "source.ip": attacker_ip,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "action": "user.login",
            "resource": "authentication_service",
            "outcome": "failure" if random.random() > 0.1 else "success",
            "request_id": f"spray-{i:03d}",
        }

        events.append(event)

    return events


def generate_impossible_travel(user="bob.jones", start_time=None):
    """Generate impossible travel scenario."""
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(minutes=45)

    events = []

    # Login from US (192.168.1.11)
    event1 = {
        "timestamp": start_time.isoformat(),
        "actor": user,
        "source.ip": "192.168.1.11",  # US /24 prefix
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "action": "user.login",
        "resource": "authentication_service",
        "outcome": "success",
        "request_id": "travel-001",
    }

    # Login from EU 30 minutes later (completely different /8)
    event2_time = start_time + timedelta(minutes=30)
    event2 = {
        "timestamp": event2_time.isoformat(),
        "actor": user,
        "source.ip": "85.123.45.67",  # EU IP (different /8)
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "action": "user.login",
        "resource": "authentication_service",
        "outcome": "success",
        "request_id": "travel-002",
    }

    events.append(event1)
    events.append(event2)

    return events


def generate_suspicious_user_agent(start_time=None):
    """Generate suspicious user-agent activity."""
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(minutes=10)

    events = []
    suspicious_ip = "45.76.123.98"

    # 20 requests with curl user agent
    for i in range(20):
        timestamp = start_time + timedelta(seconds=random.randint(0, 600))

        event = {
            "timestamp": timestamp.isoformat(),
            "actor": "api.bot.user",
            "source.ip": suspicious_ip,
            "user_agent": "curl/7.68.0",
            "action": "storage.object.read",
            "resource": f"data-file-{i}.json",
            "outcome": "success",
            "request_id": f"curl-{i:03d}",
        }

        events.append(event)

    return events


def generate_api_abuse(start_time=None):
    """Generate API abuse / rate spike."""
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(minutes=3)

    events = []
    abuser_ip = "45.76.123.98"

    # 150 requests in 3 minutes
    for i in range(150):
        timestamp = start_time + timedelta(seconds=random.randint(0, 180))

        event = {
            "timestamp": timestamp.isoformat(),
            "actor": "scraper.account",
            "source.ip": abuser_ip,
            "user_agent": "python-requests/2.28.1",
            "action": random.choice(["storage.object.read", "iam.user.list", "storage.object.list"]),
            "resource": f"resource-{random.randint(1, 50)}",
            "outcome": "success",
            "request_id": f"abuse-{i:04d}",
        }

        events.append(event)

    return events


def generate_privilege_escalation(start_time=None):
    """Generate privilege escalation events."""
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(minutes=20)

    events = []

    # Admin creates new role
    event1 = {
        "timestamp": start_time.isoformat(),
        "actor": "admin.user",
        "source.ip": "192.168.1.10",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "action": "iam.role.create",
        "resource": "super-admin-role",
        "outcome": "success",
        "request_id": "priv-001",
    }

    # Attach admin policy
    event2_time = start_time + timedelta(minutes=2)
    event2 = {
        "timestamp": event2_time.isoformat(),
        "actor": "admin.user",
        "source.ip": "192.168.1.10",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "action": "iam.role.attach_policy",
        "resource": "super-admin-role",
        "outcome": "success",
        "request_id": "priv-002",
    }

    # Promote user
    event3_time = start_time + timedelta(minutes=5)
    event3 = {
        "timestamp": event3_time.isoformat(),
        "actor": "admin.user",
        "source.ip": "192.168.1.10",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "action": "iam.user.add_to_group",
        "resource": "regular.user -> admins",
        "outcome": "success",
        "request_id": "priv-003",
    }

    events.extend([event1, event2, event3])

    return events


def main():
    """Generate complete demo dataset."""
    print("🔨 Generating demo logs for SignalForge...")

    base_time = datetime.now(timezone.utc) - timedelta(hours=1)

    # Combine all events
    all_events = []

    # Normal activity (baseline)
    print("  → Generating normal user activity...")
    all_events.extend(generate_normal_activity(800, base_time))

    # Attack scenarios
    print("  → Generating brute force attack...")
    all_events.extend(generate_brute_force_attack(start_time=base_time + timedelta(minutes=10)))

    print("  → Generating password spray attack...")
    all_events.extend(generate_password_spray(start_time=base_time + timedelta(minutes=20)))

    print("  → Generating impossible travel...")
    all_events.extend(generate_impossible_travel(start_time=base_time + timedelta(minutes=15)))

    print("  → Generating suspicious user-agent activity...")
    all_events.extend(generate_suspicious_user_agent(start_time=base_time + timedelta(minutes=40)))

    print("  → Generating API abuse...")
    all_events.extend(generate_api_abuse(start_time=base_time + timedelta(minutes=50)))

    print("  → Generating privilege escalation...")
    all_events.extend(generate_privilege_escalation(start_time=base_time + timedelta(minutes=30)))

    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"])

    # Write to JSONL file
    output_file = "examples/sample_logs/demo_logs.jsonl"
    print(f"\n📝 Writing {len(all_events)} events to {output_file}...")

    with open(output_file, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    print(f"✅ Demo logs generated successfully!")
    print(f"\n📊 Summary:")
    print(f"   Total events: {len(all_events)}")
    print(f"   Attack scenarios: 6")
    print(f"   Expected alerts:")
    print(f"     • Brute force: 1 alert")
    print(f"     • Password spray: 1 alert")
    print(f"     • Impossible travel: 1 alert")
    print(f"     • Suspicious UA: 1+ alerts")
    print(f"     • API abuse: 1+ alerts")
    print(f"     • Privilege escalation: 3 alerts")
    print(f"\n🚀 Next steps:")
    print(f"   1. Start backend: uvicorn backend.app.main:app --reload")
    print(f"   2. Ingest logs: Use /api/v1/ingest endpoint")
    print(f"   3. Run detections: curl -X POST http://localhost:8000/api/v1/detections/run")
    print(f"   4. View alerts: http://localhost:3000")


if __name__ == "__main__":
    main()
