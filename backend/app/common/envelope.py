from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import Request


def normalize_utc_naive(dt: datetime) -> datetime:
    """Convert an aware or naive datetime to UTC-naive."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def format_utc_ms(dt: datetime) -> str:
    """Format a datetime as UTC ISO-8601 with millisecond precision and trailing 'Z'."""
    return normalize_utc_naive(dt).isoformat(timespec="milliseconds") + "Z"


def format_optional_utc_ms(dt: datetime | None) -> str | None:
    """Format an optional datetime as UTC millisecond ISO-8601, preserving None."""
    return None if dt is None else format_utc_ms(dt)


def generate_request_id() -> str:
    return f"req_{uuid4().hex[:16]}"


def get_request_id(request: Request | None = None) -> str:
    if request is not None:
        req_id = getattr(request.state, "request_id", "")
        if req_id:
            return str(req_id)
    return generate_request_id()


def ok_response(
    data: Any = None,
    request: Request | None = None,
    message: str = "ok",
) -> dict[str, Any]:
    return {
        "code": 200,
        "message": message,
        "request_id": get_request_id(request),
        "data": data if data is not None else {},
    }
