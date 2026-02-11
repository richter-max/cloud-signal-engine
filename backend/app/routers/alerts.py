"""Alert management endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, AllowlistEntry, FalsePositive
from ..schemas import (
    AlertResponse,
    AlertStatusUpdate,
    AllowlistCreate,
    AllowlistResponse,
    FalsePositiveCreate,
)

router = APIRouter()



@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    status: str | None = Query(None, description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    rule_id: str | None = Query(None, description="Filter by rule ID"),
    limit: int = Query(50, le=500, description="Maximum number of alerts to return"),
    db: Session = Depends(get_db),
):

    """
    List alerts with optional filters.

    Query parameters:
    - status: open, triaged, closed, false_positive
    - severity: low, medium, high, critical
    - rule_id: specific detection rule
    - limit: max results (default 50, max 500)

    Returns alerts ordered by most recent first.
    """
    query = db.query(Alert)

    # Apply filters
    filters = []
    if status:
        filters.append(Alert.status == status)
    if severity:
        filters.append(Alert.severity == severity)
    if rule_id:
        filters.append(Alert.rule_id == rule_id)

    if filters:
        query = query.filter(and_(*filters))

    # Order by most recent
    query = query.order_by(Alert.alert_time.desc())

    # Limit results
    alerts = query.limit(limit).all()

    return alerts


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get detailed information about a specific alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert


@router.patch("/alerts/{alert_id}/status", response_model=AlertResponse)
async def update_alert_status(
    alert_id: int,
    status_update: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    """
    Update alert status.

    Valid transitions:
    - open -> triaged, closed, false_positive
    - triaged -> closed, false_positive
    - Any status -> open (reopen)
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = status_update.status.value
    alert.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(alert)

    return alert


@router.post("/alerts/{alert_id}/false-positive")
async def mark_false_positive(
    alert_id: int,
    fp_data: FalsePositiveCreate,
    db: Session = Depends(get_db),
):
    """
    Mark alert as false positive with reason.

    This:
    1. Updates alert status to false_positive
    2. Records the reason for tuning
    3. Can be used to improve detection rules
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Update alert status
    alert.status = "false_positive"
    alert.updated_at = datetime.utcnow()

    # Record false positive
    fp = FalsePositive(
        alert_id=alert_id,
        reason=fp_data.reason,
        marked_by=fp_data.marked_by,
    )
    db.add(fp)

    db.commit()

    return {"status": "success", "message": "Alert marked as false positive"}


@router.get("/allowlist", response_model=list[AllowlistResponse])
async def list_allowlist(db: Session = Depends(get_db)):
    """List all active allowlist entries."""
    now = datetime.now(UTC)

    # Get entries that haven't expired
    entries = (
        db.query(AllowlistEntry)
        .filter(or_(AllowlistEntry.expires_at.is_(None), AllowlistEntry.expires_at > now))
        .order_by(AllowlistEntry.created_at.desc())
        .all()
    )

    return entries


@router.post("/allowlist", response_model=AllowlistResponse)
async def add_to_allowlist(
    entry: AllowlistCreate,
    db: Session = Depends(get_db),
):
    """
    Add IP or actor to allowlist.

    This suppresses future alerts for the specified entity.
    Useful for known safe IPs (corporate VPN, trusted services)
    or automated accounts.

    Set expires_at for temporary allowlisting (e.g., 24 hours).
    """
    allowlist_entry = AllowlistEntry(
        entry_type=entry.entry_type,
        entry_value=entry.entry_value,
        reason=entry.reason,
        rule_id=entry.rule_id,
        expires_at=entry.expires_at,
        created_by=entry.created_by,
    )

    db.add(allowlist_entry)
    db.commit()
    db.refresh(allowlist_entry)

    return allowlist_entry


@router.delete("/allowlist/{entry_id}")
async def remove_from_allowlist(entry_id: int, db: Session = Depends(get_db)):
    """Remove entry from allowlist."""
    entry = db.query(AllowlistEntry).filter(AllowlistEntry.id == entry_id).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Allowlist entry not found")

    db.delete(entry)
    db.commit()

    return {"status": "success", "message": "Entry removed from allowlist"}
