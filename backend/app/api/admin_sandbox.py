from __future__ import annotations

import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, StrictStr
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.common.envelope import ok_response
from app.common.errors import BadRequestError
from app.db.models import AdminUser
from app.db.session import get_session
from app.engine import SandboxSpanDetail
from app.engine.field_router import collect_string_leaves
from app.telemetry import resolve_request_engine

router = APIRouter(prefix="/api/admin/sandbox", tags=["admin-sandbox"])


class PolicyDraftOverride(BaseModel):
    scope_mode: str | None = Field(default=None, max_length=24)
    onnx_variant: str | None = Field(default=None, max_length=16)
    entity_rules: dict[str, dict[str, Any]] | None = None
    entity_rules_json: dict[str, dict[str, Any]] | None = None
    field_role_rules: dict[str, Any] | None = None
    field_role_rules_json: dict[str, Any] | None = None
    allowlist_groups: list[str] | None = None
    allowlist_groups_json: list[str] | None = None


class SandboxPreviewRequest(BaseModel):
    mode: str | None = Field(default=None, max_length=24)
    text: StrictStr | None = None
    payload: dict[str, Any] | None = None
    policy_code: str | None = Field(default=None, max_length=64)
    policy_version: int | None = Field(default=None, ge=1)
    scope_mode: str | None = Field(default=None, max_length=24)
    onnx_variant: str | None = Field(default=None, max_length=16)
    entity_rules: dict[str, dict[str, Any]] | None = None
    entity_rules_json: dict[str, dict[str, Any]] | None = None
    field_role_rules: dict[str, Any] | None = None
    field_role_rules_json: dict[str, Any] | None = None
    allowlist_groups: list[str] | None = None
    allowlist_groups_json: list[str] | None = None
    column_role_override: dict[str, str] | None = None
    policy_override: PolicyDraftOverride | None = None
    draft_policy: PolicyDraftOverride | None = None


def _resolve_mode(body: SandboxPreviewRequest) -> Literal["TEXT", "STRUCTURED"]:
    if body.mode is not None and body.mode.strip():
        clean_mode = body.mode.strip().upper()
        if clean_mode not in ("TEXT", "STRUCTURED"):
            raise BadRequestError("Invalid mode: must be TEXT or STRUCTURED")
        resolved: Literal["TEXT", "STRUCTURED"] = clean_mode  # type: ignore[assignment]
    elif body.text is not None and body.payload is None:
        resolved = "TEXT"
    elif body.payload is not None and body.text is None:
        resolved = "STRUCTURED"
    else:
        raise BadRequestError(
            "Provide 'text' for TEXT mode or 'payload' for STRUCTURED mode"
        )

    if resolved == "TEXT":
        if body.text is None:
            raise BadRequestError("'text' is required when mode is TEXT")
    else:
        if body.payload is None or not isinstance(body.payload, dict):
            raise BadRequestError("'payload' object is required when mode is STRUCTURED")
    return resolved


def _pick_override(body: SandboxPreviewRequest, attr_primary: str, attr_alt: str | None = None) -> Any:
    val = getattr(body, attr_primary, None)
    if val is not None:
        return val
    if attr_alt is not None:
        alt_val = getattr(body, attr_alt, None)
        if alt_val is not None:
            return alt_val
    nested = body.policy_override or body.draft_policy
    if nested is not None:
        n_val = getattr(nested, attr_primary, None)
        if n_val is not None:
            return n_val
        if attr_alt is not None:
            n_alt = getattr(nested, attr_alt, None)
            if n_alt is not None:
                return n_alt
    return None


def _serialize_sandbox_span(
    detail: SandboxSpanDetail,
    raw_text: str,
    *,
    field_path: str | None = None,
) -> dict[str, Any]:
    state: Literal["onnx", "regex", "allowlist"] = (
        "allowlist" if detail.kind == "exempted" else detail.detector
    )
    out: dict[str, Any] = {
        "kind": detail.kind,
        "state": state,
        "source": state,
        "detector": detail.detector,
        "label": detail.label,
        "start": detail.orig_start,
        "end": detail.orig_end,
        "orig_start": detail.orig_start,
        "orig_end": detail.orig_end,
        "text": raw_text[detail.orig_start : detail.orig_end],
        "replacement": detail.replacement if detail.kind == "masked" else None,
        "score": round(float(detail.score), 4),
        "exempted": detail.kind == "exempted",
        "allowlist_group": detail.allowlist_group,
        "allowlist_rule": detail.allowlist_rule,
    }
    if field_path is not None:
        out["field_path"] = field_path
    return out


@router.post("/preview")
def sandbox_preview(
    body: SandboxPreviewRequest,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    """Pure in-memory interactive sandbox preview.

    SECURITY INVARIANT: Zero DB writes (read-only snapshot + rollback guard) and zero logs.
    """
    try:
        mode = _resolve_mode(body)
        raw_scope = _pick_override(body, "scope_mode")
        raw_variant = _pick_override(body, "onnx_variant")
        raw_entity_rules = _pick_override(body, "entity_rules", "entity_rules_json")
        raw_field_rules = _pick_override(body, "field_role_rules", "field_role_rules_json")
        raw_allowlist_groups = _pick_override(
            body, "allowlist_groups", "allowlist_groups_json"
        )

        engine = resolve_request_engine(request)
        snapshot = engine.resolve_sandbox_snapshot(
            session,
            policy_code=body.policy_code,
            policy_version=body.policy_version,
            scope_mode=raw_scope.strip().upper() if isinstance(raw_scope, str) else raw_scope,
            onnx_variant=(
                raw_variant.strip().lower() if isinstance(raw_variant, str) else raw_variant
            ),
            entity_rules=raw_entity_rules,
            field_role_rules=raw_field_rules,
            allowlist_groups=raw_allowlist_groups,
        )

        if mode == "TEXT":
            assert body.text is not None
            text_res = engine.mask_text(
                body.text,
                snapshot,
                return_spans=True,
                sandbox_trace=True,
            )
            serialized_spans = [
                _serialize_sandbox_span(sp, body.text) for sp in text_res.sandbox_spans
            ]
            masked_spans = [
                {
                    "label": ms.label,
                    "start": ms.masked_start,
                    "end": ms.masked_end,
                    "masked_start": ms.masked_start,
                    "masked_end": ms.masked_end,
                    "placeholder": ms.placeholder,
                    "detector": ms.detector,
                    "state": ms.detector,
                    "score": round(float(ms.score), 4),
                }
                for ms in text_res.masked_spans
            ]
            exempted_spans = [sp for sp in serialized_spans if sp["exempted"]]
            return ok_response(
                {
                    "mode": "TEXT",
                    "policy_code": snapshot.policy_code,
                    "policy_version": snapshot.version,
                    "scope_mode": snapshot.scope_mode,
                    "onnx_variant": snapshot.onnx_variant,
                    "masked_text": text_res.masked_text,
                    "masked_payload": None,
                    "spans": serialized_spans,
                    "masked_spans": masked_spans,
                    "exempted_spans": exempted_spans,
                    "exempted_count": len(exempted_spans),
                    "field_traces": {},
                    "hit_counts": text_res.hit_counts,
                    "elapsed_ms": text_res.elapsed_ms,
                },
                request=request,
            )

        assert body.payload is not None
        leaf_text_by_path = {
            leaf.canonical_path: leaf.value for leaf in collect_string_leaves(body.payload)
        }
        t0 = time.perf_counter()
        rec_res = engine.mask_structured_record(
            body.payload,
            snapshot,
            column_role_override=body.column_role_override,
            sandbox_trace=True,
        )
        elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))

        field_traces_out: dict[str, list[dict[str, Any]]] = {}
        flat_spans: list[dict[str, Any]] = []
        for path, details in rec_res.sandbox_field_traces.items():
            orig_leaf = leaf_text_by_path.get(path, "")
            path_spans = [
                _serialize_sandbox_span(det, orig_leaf, field_path=path) for det in details
            ]
            field_traces_out[path] = path_spans
            flat_spans.extend(path_spans)

        exempted_spans = [sp for sp in flat_spans if sp["exempted"]]
        return ok_response(
            {
                "mode": "STRUCTURED",
                "policy_code": snapshot.policy_code,
                "policy_version": snapshot.version,
                "scope_mode": snapshot.scope_mode,
                "onnx_variant": snapshot.onnx_variant,
                "masked_text": None,
                "masked_payload": rec_res.masked_payload,
                "spans": flat_spans,
                "masked_spans": [],
                "exempted_spans": exempted_spans,
                "exempted_count": len(exempted_spans),
                "field_traces": field_traces_out,
                "hit_counts": rec_res.hit_counts,
                "elapsed_ms": elapsed_ms,
            },
            request=request,
        )
    finally:
        session.rollback()
