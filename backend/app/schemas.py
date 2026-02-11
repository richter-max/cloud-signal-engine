"""Pydantic schemas for request/response validation."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .models import AlertStatus


class EventCreate(BaseModel):
    """Schema for creating a new event."""

    timestamp: datetime
    actor: str | None = None
    source_ip: str | None = Field(None, alias="source.ip")
    user_agent: str | None = None
    action: str
    resource: str | None = None
    outcome: str | None = None
    request_id: str | None = None
    raw_data: dict[str, Any] | None = None

    model_config = {"populate_by_name": True}

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        """Parse various timestamp formats."""
        if isinstance(v, datetime):
            return v
        if isinstance(v, (int, float)):
            # Unix timestamp
            return datetime.fromtimestamp(v, tz=UTC)
        if isinstance(v, str):
            from dateutil import parser

            return parser.parse(v)
        return v


class EventResponse(BaseModel):
    """Schema for event response."""

    id: int
    timestamp: datetime
    actor: str | None
    source_ip: str | None
    user_agent: str | None
    action: str
    resource: str | None
    outcome: str | None
    request_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertResponse(BaseModel):
    """Schema for alert response."""

    id: int
    rule_id: str
    severity: str
    status: str
    summary: str
    evidence: dict[str, Any]
    alert_time: datetime
    window_start: datetime | None
    window_end: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertStatusUpdate(BaseModel):
    """Schema for updating alert status."""

    status: AlertStatus


class FalsePositiveCreate(BaseModel):
    """Schema for marking alert as false positive."""

    reason: str
    marked_by: str | None = None


class AllowlistCreate(BaseModel):
    """Schema for creating allowlist entry."""

    entry_type: str = Field(..., pattern="^(ip|actor)$")
    entry_value: str
    reason: str
    rule_id: str | None = None
    expires_at: datetime | None = None
    created_by: str | None = None


class AllowlistResponse(BaseModel):
    """Schema for allowlist response."""

    id: int
    entry_type: str
    entry_value: str
    reason: str
    rule_id: str | None
    expires_at: datetime | None
    created_by: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class IngestResponse(BaseModel):
    """Schema for ingest endpoint response."""

    ingested: int
    event_ids: list[int]
    errors: list[str] = []


class DetectionRunResponse(BaseModel):
    """Schema for detection run response."""

    alerts_generated: int
    rules_executed: list[str]
    execution_time_ms: float
