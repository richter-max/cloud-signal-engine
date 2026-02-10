from app.database import SessionLocal
from app.models import Event, Alert

db = SessionLocal()
try:
    event_count = db.query(Event).count()
    alert_count = db.query(Alert).count()
    print(f"Events: {event_count}")
    print(f"Alerts: {alert_count}")

    # Print first event if exists
    if event_count > 0:
        event = db.query(Event).first()
        print(f"First event: {event.timestamp} - {event.action}")
finally:
    db.close()
