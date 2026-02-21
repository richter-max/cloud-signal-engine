"""Event normalization service."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dateutil import parser


def normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize raw event data into canonical schema.

    Handles various timestamp formats, field name variations,
    and missing/null fields gracefully.

    Args:
        raw_event: Raw event dictionary

    Returns:
        Normalized event dictionary matching canonical schema
    """

    normalized = {}

    # Normalize timestamp to UTC datetime
    timestamp = raw_event.get("timestamp") or raw_event.get("@timestamp") or raw_event.get("time")
    if timestamp:
        normalized["timestamp"] = _normalize_timestamp(timestamp)
    else:
        # Default to now if no timestamp
        normalized["timestamp"] = datetime.now(timezone.utc)

    # Normalize actor (user, username, identity)
    normalized["actor"] = (
        raw_event.get("actor")
        or raw_event.get("user")
        or raw_event.get("username")
        or raw_event.get("identity", {}).get("principalId")
    )

    # Normalize source IP (various field names)
    normalized["source_ip"] = (
        raw_event.get("source_ip")
        or raw_event.get("sourceIP")
        or raw_event.get("client_ip")
        or raw_event.get("clientIP")
        or raw_event.get("source", {}).get("ip")
        or raw_event.get("network", {}).get("client_ip")
    )

    # User agent
    normalized["user_agent"] = raw_event.get("user_agent") or raw_event.get("userAgent")

    # Normalize action
    action = raw_event.get("action") or raw_event.get("event") or raw_event.get("eventName")
    normalized["action"] = _normalize_action(action) if action else "unknown"

    # Resource
    normalized["resource"] = (
        raw_event.get("resource")
        or raw_event.get("target")
        or raw_event.get("object")
        or raw_event.get("requestParameters", {}).get("resource")
    )

    # Outcome (success, failure, error)
    normalized["outcome"] = _normalize_outcome(
        raw_event.get("outcome")
        or raw_event.get("result")
        or raw_event.get("status")
        or raw_event.get("responseElements", {}).get("status")
    )

    # Request ID
    normalized["request_id"] = (
        raw_event.get("request_id")
        or raw_event.get("requestId")
        or raw_event.get("trace_id")
        or raw_event.get("traceId")
        or str(uuid.uuid4())  # Generate if not provided
    )

    # Store raw data for forensics (convert datetime objects to strings for JSON)
    normalized["raw_data"] = _serialize_for_json(raw_event)

    return normalized


def _serialize_for_json(data: Any) -> Any:
    """Convert datetime objects to ISO format strings for JSON serialization."""
    if isinstance(data, datetime):
        return data.isoformat()
    elif isinstance(data, dict):
        return {k: _serialize_for_json(v) for k, v in data.items()}
    elif isinstance(data, (list, tuple)):
        return [_serialize_for_json(item) for item in data]
    return data


def _normalize_timestamp(timestamp: Any) -> datetime:
    """Parse various timestamp formats to timezone.utc datetime."""
    if isinstance(timestamp, datetime):
        # Ensure timezone.utc
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)

    if isinstance(timestamp, (int, float)):
        # Unix timestamp (seconds or milliseconds)
        if timestamp > 1e10:  # Likely milliseconds
            timestamp = timestamp / 1000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    if isinstance(timestamp, str):
        # ISO8601 or other string format
        dt = parser.parse(timestamp)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    # Fallback to now
    return datetime.now(timezone.utc)


def _normalize_action(action: str) -> str:
    """
    Normalize action names to consistent format.

    Examples:
        login -> user.login
        CreateUser -> iam.user.create
        s3:PutObject -> storage.object.create
    """
    action = action.lower().strip()

    # Map common action patterns
    action_mappings = {
        "login": "user.login",
        "logout": "user.logout",
        "signin": "user.login",
        "signout": "user.logout",
        "authenticate": "user.login",
        "createuser": "iam.user.create",
        "deleteuser": "iam.user.delete",
        "updateuser": "iam.user.update",
        "createrole": "iam.role.create",
        "deleterole": "iam.role.delete",
        "updaterole": "iam.role.update",
        "attachrolepolicy": "iam.role.attach_policy",
        "detachrolepolicy": "iam.role.detach_policy",
        "putobject": "storage.object.create",
        "getobject": "storage.object.read",
        "deleteobject": "storage.object.delete",
    }

    # Remove common prefixes (AWS style: s3:PutObject)
    if ":" in action:
        action = action.split(":")[-1]

    # Check mappings
    normalized = action_mappings.get(action.replace("_", "").replace("-", ""))

    return normalized or action


def _normalize_outcome(outcome: Any) -> Optional[str]:
    """Normalize outcome to success, failure, or error."""
    if not outcome:
        return None

    outcome_str = str(outcome).lower()

    if outcome_str in ("success", "succeeded", "ok", "200", "201", "204"):
        return "success"
    elif outcome_str in ("failure", "failed", "denied", "unauthorized", "401", "403"):
        return "failure"
    elif outcome_str in ("error", "exception", "500", "503"):
        return "error"

    # Try to infer from HTTP status codes
    if outcome_str.isdigit():
        code = int(outcome_str)
        if 200 <= code < 300:
            return "success"
        elif 400 <= code < 500:
            return "failure"
        elif 500 <= code < 600:
            return "error"

    return outcome_str
