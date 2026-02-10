"""
Directly insert test data into the database for screenshots.
Bypasses the API to avoid current 500 errors.
"""

from datetime import datetime, timedelta, timezone
import random
import json
from sqlalchemy.orm import Session

from app.database import SessionLocal, engine, Base
from app.models import Event, Alert, AlertSeverity, AlertStatus, AllowlistEntry

# Ensure tables exist
Base.metadata.create_all(bind=engine)


def create_test_data():
    db = SessionLocal()
    try:
        print("🧹 Cleaning up old test data...")
        db.query(Alert).delete()
        db.query(Event).delete()
        db.commit()

        print("🌱 Inserting new test data...")

        now = datetime.now(timezone.utc)
        events = []
        alerts = []

        # 1. Brute Force Attack (Critical)
        attacker_ip = "203.0.113.42"
        target_user = "admin"

        # Create events
        for i in range(20):
            events.append(
                Event(
                    timestamp=now - timedelta(minutes=60 - i),
                    actor=target_user,
                    source_ip=attacker_ip,
                    action="user.login",
                    outcome="failure",
                    user_agent="Mozilla/5.0",
                    raw_data={"ip": attacker_ip, "user": target_user},
                )
            )

        # Create Alert
        alerts.append(
            Alert(
                rule_id="brute_force",
                severity=AlertSeverity.CRITICAL.value,
                status=AlertStatus.OPEN.value,
                summary=f"Brute force attack detected against user '{target_user}' from {attacker_ip}",
                evidence={
                    "ip": attacker_ip,
                    "failed_attempts": 20,
                    "users_targeted": [target_user],
                },
                alert_time=now - timedelta(minutes=40),
                window_start=now - timedelta(minutes=60),
                window_end=now - timedelta(minutes=40),
            )
        )

        # 2. Password Spray (High)
        spray_ip = "198.51.100.85"
        users = ["alice", "bob", "charlie", "david", "emma"]

        for i, user in enumerate(users):
            events.append(
                Event(
                    timestamp=now - timedelta(minutes=120 - i * 5),
                    actor=user,
                    source_ip=spray_ip,
                    action="user.login",
                    outcome="failure",
                    user_agent="curl/7.68.0",
                    raw_data={"ip": spray_ip, "user": user},
                )
            )

        alerts.append(
            Alert(
                rule_id="password_spray",
                severity=AlertSeverity.HIGH.value,
                status=AlertStatus.OPEN.value,
                summary=f"Password spray attack detected from {spray_ip} targeting {len(users)} users",
                evidence={"ip": spray_ip, "unique_users": len(users), "users": users},
                alert_time=now - timedelta(minutes=100),
                window_start=now - timedelta(minutes=120),
                window_end=now - timedelta(minutes=90),
            )
        )

        # 3. Impossible Travel (Medium)
        travel_user = "global_admin"

        # Login from London
        events.append(
            Event(
                timestamp=now - timedelta(hours=2),
                actor=travel_user,
                source_ip="185.220.101.50",  # London
                action="user.login",
                outcome="success",
                user_agent="Mozilla/5.0 (Macintosh)",
                raw_data={"location": "London, UK"},
            )
        )

        # Login from New York (1 hour later)
        events.append(
            Event(
                timestamp=now - timedelta(hours=1),
                actor=travel_user,
                source_ip="54.240.197.233",  # NY
                action="user.login",
                outcome="success",
                user_agent="Mozilla/5.0 (Macintosh)",
                raw_data={"location": "New York, USA"},
            )
        )

        alerts.append(
            Alert(
                rule_id="impossible_travel",
                severity=AlertSeverity.MEDIUM.value,
                status=AlertStatus.TRIAGED.value,
                summary=f"Impossible travel detected for user '{travel_user}' (London -> New York)",
                evidence={
                    "actor": travel_user,
                    "locations": ["London, UK", "New York, USA"],
                    "speed_mph": 3500,
                },
                alert_time=now - timedelta(hours=1),
                window_start=now - timedelta(hours=2),
                window_end=now - timedelta(hours=1),
            )
        )

        # 4. Privilege Escalation (Critical)
        priv_user = "bob"
        events.append(
            Event(
                timestamp=now - timedelta(minutes=15),
                actor=priv_user,
                source_ip="10.0.1.50",
                action="iam.role.attach_policy",
                resource="AdministratorAccess",
                outcome="success",
                user_agent="aws-cli/2.0",
                raw_data={"policy": "AdministratorAccess"},
            )
        )

        alerts.append(
            Alert(
                rule_id="privilege_escalation",
                severity=AlertSeverity.CRITICAL.value,
                status=AlertStatus.OPEN.value,
                summary=f"Sensitive permission 'AdministratorAccess' granted by {priv_user}",
                evidence={
                    "actor": priv_user,
                    "action": "iam.role.attach_policy",
                    "resource": "AdministratorAccess",
                },
                alert_time=now - timedelta(minutes=15),
                window_start=now - timedelta(minutes=20),
                window_end=now,
            )
        )

        # 5. Suspicious User Agent (Low)
        events.append(
            Event(
                timestamp=now - timedelta(minutes=5),
                actor="unknown",
                source_ip="45.33.32.156",
                action="api.query",
                outcome="failure",
                user_agent="sqlmap/1.4",
                raw_data={"full_ua": "sqlmap/1.4.11.1#dev"},
            )
        )

        alerts.append(
            Alert(
                rule_id="suspicious_user_agent",
                severity=AlertSeverity.LOW.value,
                status=AlertStatus.CLOSED.value,
                summary="Suspicious user agent 'sqlmap/1.4' detected",
                evidence={"user_agent": "sqlmap/1.4", "ip": "45.33.32.156"},
                alert_time=now - timedelta(minutes=5),
                window_start=now - timedelta(minutes=10),
                window_end=now,
            )
        )

        # Add all objects
        db.add_all(events)
        db.add_all(alerts)

        db.commit()
        print(f"✅ inserted {len(events)} events and {len(alerts)} alerts.")
        print("Current Alerts in DB:")
        for a in db.query(Alert).all():
            print(f"- [{a.severity}] {a.summary}")

    except Exception as e:
        print(f"❌ Error inserting data: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    create_test_data()
