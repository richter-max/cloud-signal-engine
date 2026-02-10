"""Pydantic schemas for request/response validation."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from .models import AlertSeverity, AlertStatus


class EventCreate(BaseModel):
    """Schema for creating a new event."""

    timestamp: datetime
    actor: Optional[str] = None
    source_ip: Optional[str] = Field(None, alias="source.ip")
    user_agent: Optional[str] = None
    action: str
    resource: Optional[str] = None
    outcome: Optional[str] = None
    request_id: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None

    model_config = {"populate_by_name": True}

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        """Parse various timestamp formats."""
        if isinstance(v, datetime):
            return v
        if isinstance(v, (int, float)):
            # Unix timestamp
            return datetime.fromtimestamp(v, tz=timezone.utc)
        if isinstance(v, str):
            from dateutil import parser

            return parser.parse(v)
        return v


class EventResponse(BaseModel):
    """Schema for event response."""

    id: int
    timestamp: datetime
    actor: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    action: str
    resource: Optional[str]
    outcome: Optional[str]
    request_id: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertResponse(BaseModel):
    """Schema for alert response."""

    id: int
    rule_id: str
    severity: str
    status: str
    summary: str
    evidence: Dict[str, Any]
    alert_time: datetime
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertStatusUpdate(BaseModel):
    """Schema for updating alert status."""

    status: AlertStatus


class FalsePositiveCreate(BaseModel):
    """Schema for marking alert as false positive."""

    reason: str
    marked_by: Optional[str] = None


class AllowlistCreate(BaseModel):
    """Schema for creating allowlist entry."""

    entry_type: str = Field(..., pattern="^(ip|actor)$")
    entry_value: str
    reason: str
    rule_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_by: Optional[str] = None


class AllowlistResponse(BaseModel):
    """Schema for allowlist response."""

    id: int
    entry_type: str
    entry_value: str
    reason: str
    rule_id: Optional[str]
    expires_at: Optional[datetime]
    created_by: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class IngestResponse(BaseModel):
    """Schema for ingest endpoint response."""

    ingested: int
    event_ids: List[int]
    errors: List[str] = []


class DetectionRunResponse(BaseModel):
    """Schema for detection run response."""

    alerts_generated: int
    rules_executed: List[str]
    execution_time_ms: float
