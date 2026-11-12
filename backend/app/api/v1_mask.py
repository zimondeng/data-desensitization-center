from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, StrictStr
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_api_key
from app.common.envelope import ok_response
from app.common.errors import BadRequestError
from app.db.models import ApiKey
from app.db.session import get_session
from app.engine import EphemeralScopeDict, MaskedSpanOut
from app.telemetry import record_sync_api_usage, resolve_request_engine

router = APIRouter(prefix="/api/v1/mask", tags=["v1-mask"])


class MaskTextRequest(BaseModel):
    text: StrictStr
    policy_code: str | None = Field(default=None, max_length=64)
    policy_version: int | None = Field(default=None, ge=1)
    return_spans: bool = False


class BatchInlineItemRequest(BaseModel):
    item_id: str = Field(min_length=1, max_length=256)
    payload: dict[str, Any]


class BatchInlineMaskRequest(BaseModel):
    policy_code: str | None = Field(default=None, max_length=64)
    policy_version: int | None = Field(default=None, ge=1)
    items: list[BatchInlineItemRequest] = Field(min_length=1, max_length=100)


def _serialize_masked_span(span: MaskedSpanOut) -> dict[str, Any]:
    return {
        "label": span.label,
        "start": span.masked_start,
        "end": span.masked_end,
        "masked_start": span.masked_start,
        "masked_end": span.masked_end,
        "placeholder": span.placeholder,
        "detector": span.detector,
        "score": round(float(span.score), 4),
    }


@router.post("/text")
def mask_single_text(
    body: MaskTextRequest,
    request: Request,
    session: Session = Depends(get_session),
    api_key: ApiKey = Depends(get_current_api_key),
) -> dict[str, Any]:
    engine = resolve_request_engine(request)
    effective_policy_code = (body.policy_code or "").strip() or api_key.default_policy_code
    snapshot = engine.resolve_policy(
        session,
        effective_policy_code,
        body.policy_version,
    )

    t0 = time.perf_counter()
    try:
        result = engine.mask_text(
            body.text,
            snapshot,
            return_spans=body.return_spans,
            sandbox_trace=False,
        )
    except Exception:
        err_elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
        record_sync_api_usage(
            session,
            api_key_id=api_key.id,
            policy_id=snapshot.policy_id,
            request_count=1,
            item_count=0,
            total_chars=0,
            elapsed_ms=err_elapsed_ms,
            error_count=1,
            hit_counts=None,
        )
        raise

    record_sync_api_usage(
        session,
        api_key_id=api_key.id,
        policy_id=snapshot.policy_id,
        request_count=1,
        item_count=1,
        total_chars=len(body.text),
        elapsed_ms=result.elapsed_ms,
        error_count=0,
        hit_counts=result.hit_counts,
    )

    payload: dict[str, Any] = {
        "masked_text": result.masked_text,
        "policy_code": snapshot.policy_code,
        "policy_version": snapshot.version,
        "hit_counts": result.hit_counts,
        "elapsed_ms": result.elapsed_ms,
    }
    if body.return_spans:
        payload["spans"] = [_serialize_masked_span(s) for s in result.masked_spans]

    return ok_response(payload, request=request)


@router.post("/batch-inline")
def mask_batch_inline(
    body: BatchInlineMaskRequest,
    request: Request,
    session: Session = Depends(get_session),
    api_key: ApiKey = Depends(get_current_api_key),
) -> dict[str, Any]:
    if not (1 <= len(body.items) <= 100):
        raise BadRequestError("items count must be between 1 and 100")

    engine = resolve_request_engine(request)
    effective_policy_code = (body.policy_code or "").strip() or api_key.default_policy_code
    snapshot = engine.resolve_policy(
        session,
        effective_policy_code,
        body.policy_version,
    )

    batch_t0 = time.perf_counter()
    results_out: list[dict[str, Any]] = []
    total_chars = 0
    merged_hits: dict[str, int] = {}

    try:
        for item in body.items:
            item_t0 = time.perf_counter()
            item_scope = EphemeralScopeDict(mode=snapshot.scope_mode)
            try:
                rec_res = engine.mask_structured_record(
                    item.payload,
                    snapshot,
                    scope=item_scope,
                    sandbox_trace=False,
                )
            finally:
                item_scope.clear()

            item_elapsed_ms = max(0, int(round((time.perf_counter() - item_t0) * 1000)))
            total_chars += rec_res.char_count
            for lbl, cnt in rec_res.hit_counts.items():
                merged_hits[lbl] = merged_hits.get(lbl, 0) + cnt

            results_out.append(
                {
                    "item_id": item.item_id,
                    "masked_payload": rec_res.masked_payload,
                    "hit_counts": rec_res.hit_counts,
                    "elapsed_ms": item_elapsed_ms,
                }
            )
    except Exception:
        err_elapsed_ms = max(0, int(round((time.perf_counter() - batch_t0) * 1000)))
        record_sync_api_usage(
            session,
            api_key_id=api_key.id,
            policy_id=snapshot.policy_id,
            request_count=1,
            item_count=0,
            total_chars=0,
            elapsed_ms=err_elapsed_ms,
            error_count=1,
            hit_counts=None,
        )
        raise

    batch_elapsed_ms = max(0, int(round((time.perf_counter() - batch_t0) * 1000)))
    record_sync_api_usage(
        session,
        api_key_id=api_key.id,
        policy_id=snapshot.policy_id,
        request_count=1,
        item_count=len(body.items),
        total_chars=total_chars,
        elapsed_ms=batch_elapsed_ms,
        error_count=0,
        hit_counts=merged_hits,
    )

    return ok_response(
        {
            "policy_code": snapshot.policy_code,
            "policy_version": snapshot.version,
            "total_items": len(body.items),
            "elapsed_ms": batch_elapsed_ms,
            "results": results_out,
        },
        request=request,
    )
