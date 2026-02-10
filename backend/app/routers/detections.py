"""Detection engine endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import DetectionRunResponse
from ..services.detection_engine import run_detections

router = APIRouter()


@router.post("/detections/run", response_model=DetectionRunResponse)
async def trigger_detection_run(db: Session = Depends(get_db)):
    """
    Manually trigger detection rule execution.

    In production, this runs automatically on a schedule.
    This endpoint allows manual execution for testing and demos.

    Returns:
        DetectionRunResponse with alerts generated and execution stats
    """
    result = run_detections(db)
    return result
