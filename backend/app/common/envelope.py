from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import Request


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
