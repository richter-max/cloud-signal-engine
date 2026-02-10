"""Event ingestion endpoints."""

from typing import List, Union

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Event
from ..schemas import EventCreate, IngestResponse
from ..services.normalizer import normalize_event

router = APIRouter()


@router.post("/ingest", response_model=IngestResponse)
async def ingest_events(
    events: Union[List[EventCreate], EventCreate],
    db: Session = Depends(get_db),
):
    """
    Ingest security events (single or batch).

    Accepts:
    - Single event: JSON object
    - Batch events: JSON array
    - NDJSON: newline-delimited JSON (handled by parsing as array)

    Returns:
        IngestResponse with ingested count and event IDs
    """
    # Normalize to list
    if not isinstance(events, list):
        events = [events]

    event_ids = []
    errors = []

    for idx, event_data in enumerate(events):
        try:
            # Convert Pydantic model to dict
            raw_event = event_data.model_dump(by_alias=True)

            # Normalize event
            normalized = normalize_event(raw_event)

            # Create database model
            event = Event(**normalized)
            db.add(event)
            db.flush()  # Get ID without committing

            event_ids.append(event.id)

        except Exception as e:
            errors.append(f"Event {idx}: {str(e)}")
            continue

    # Commit all events
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    return IngestResponse(
        ingested=len(event_ids),
        event_ids=event_ids,
        errors=errors,
    )
