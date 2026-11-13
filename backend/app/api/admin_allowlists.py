from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.common.envelope import format_optional_utc_ms, ok_response
from app.common.errors import BadRequestError, NotFoundError
from app.db.base import new_uuid, utcnow
from app.db.models import AdminUser, AllowlistDict
from app.db.session import get_session
from app.detectors import (
    ALL_ENTITY_LABELS,
    AllowlistEntry,
    InvalidAllowlistPatternError,
    match_allowlist_entry,
    validate_allowlist_pattern,
)

router = APIRouter(prefix="/api/admin/allowlists", tags=["admin-allowlists"])

_GROUP_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _serialize_allowlist_item(row: AllowlistDict) -> dict[str, Any]:
    labels = list(row.apply_labels_json or [])
    return {
        "id": row.id,
        "uuid": row.uuid,
        "group_code": row.group_code,
        "item_name": row.item_name,
        "match_mode": row.match_mode,
        "pattern_text": row.pattern_text,
        "apply_labels": labels,
        "apply_labels_json": list(labels),
        "is_enabled": bool(row.is_enabled),
        "remark": row.remark,
        "created_by": row.created_by,
        "create_time": format_optional_utc_ms(row.create_time),
        "update_time": format_optional_utc_ms(row.update_time),
    }


def _validate_apply_labels(raw_labels: list[str] | None) -> list[str]:
    if not raw_labels:
        raise BadRequestError("apply_labels must be a non-empty list of entity labels")
    cleaned: list[str] = []
    seen: set[str] = set()
    for lbl in raw_labels:
        if not isinstance(lbl, str) or lbl.strip() not in ALL_ENTITY_LABELS:
            raise BadRequestError("Unsupported entity label in apply_labels")
        norm = lbl.strip()
        if norm not in seen:
            seen.add(norm)
            cleaned.append(norm)
    return cleaned


def _validate_mode_and_pattern(match_mode: str, pattern_text: str) -> tuple[str, str]:
    clean_mode = match_mode.strip().upper()
    if not pattern_text:
        raise BadRequestError("pattern_text must not be empty")
    try:
        validate_allowlist_pattern(clean_mode, pattern_text)
    except InvalidAllowlistPatternError as exc:
        raise BadRequestError(str(exc)) from None
    return clean_mode, pattern_text


def _find_allowlist_row(session: Session, item_id: str) -> AllowlistDict:
    target = item_id.strip()
    if target.isdigit():
        cond = or_(AllowlistDict.id == int(target), AllowlistDict.uuid == target)
    else:
        cond = AllowlistDict.uuid == target
    row = session.scalar(
        select(AllowlistDict).where(cond, AllowlistDict.is_deleted == 0)
    )
    if row is None:
        raise NotFoundError("Allowlist item not found")
    return row


class CreateAllowlistRequest(BaseModel):
    group_code: str = Field(min_length=1, max_length=64)
    item_name: str = Field(min_length=1, max_length=128)
    match_mode: str = Field(default="EXACT", min_length=1, max_length=16)
    pattern_text: str = Field(min_length=1, max_length=500)
    apply_labels: list[str] | None = None
    apply_labels_json: list[str] | None = None
    is_enabled: bool | int = True
    remark: str | None = Field(default=None, max_length=255)


class UpdateAllowlistRequest(BaseModel):
    group_code: str | None = Field(default=None, min_length=1, max_length=64)
    item_name: str | None = Field(default=None, min_length=1, max_length=128)
    match_mode: str | None = Field(default=None, min_length=1, max_length=16)
    pattern_text: str | None = Field(default=None, min_length=1, max_length=500)
    apply_labels: list[str] | None = None
    apply_labels_json: list[str] | None = None
    is_enabled: bool | int | None = None
    remark: str | None = Field(default=None, max_length=255)


class TestAllowlistRequest(BaseModel):
    text: str = Field(min_length=1, max_length=4096)
    label: str = Field(default="phone", min_length=1, max_length=64)
    group_codes: list[str] | None = None
    group_code: str | None = None
    match_mode: str | None = None
    pattern_text: str | None = None
    apply_labels: list[str] | None = None
    item_name: str | None = None
    include_saved: bool = False


@router.get("")
def list_allowlists(
    request: Request,
    group_code: str | None = None,
    is_enabled: bool | None = None,
    keyword: str | None = None,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    all_rows = session.scalars(
        select(AllowlistDict)
        .where(AllowlistDict.is_deleted == 0)
        .order_by(AllowlistDict.group_code.asc(), AllowlistDict.id.asc())
    ).all()

    group_stats: dict[str, dict[str, Any]] = {}
    for row in all_rows:
        g = group_stats.get(row.group_code)
        if g is None:
            g = {
                "group_code": row.group_code,
                "total_count": 0,
                "enabled_count": 0,
            }
            group_stats[row.group_code] = g
        g["total_count"] += 1
        if row.is_enabled == 1:
            g["enabled_count"] += 1

    filtered = all_rows
    if group_code is not None and group_code.strip():
        clean_group = group_code.strip()
        filtered = [r for r in filtered if r.group_code == clean_group]
    if is_enabled is not None:
        flag = 1 if is_enabled else 0
        filtered = [r for r in filtered if r.is_enabled == flag]
    if keyword is not None and keyword.strip():
        kw = keyword.strip().lower()
        filtered = [
            r
            for r in filtered
            if kw in r.item_name.lower()
            or kw in r.pattern_text.lower()
            or kw in r.group_code.lower()
        ]

    items = [_serialize_allowlist_item(r) for r in filtered]
    return ok_response(
        {
            "items": items,
            "total": len(items),
            "groups": list(group_stats.values()),
        },
        request=request,
    )


@router.post("/test")
def test_allowlist_inline(
    body: TestAllowlistRequest,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    """Zero-plaintext inline allowlist tester (never logs or persists body.text)."""
    clean_label = body.label.strip()
    if clean_label not in ALL_ENTITY_LABELS:
        raise BadRequestError("Unsupported entity label for allowlist test")

    matched_rules: list[dict[str, Any]] = []

    # 1. Optional ad-hoc rule evaluation (before saving in drawer)
    has_adhoc = body.pattern_text is not None
    if has_adhoc:
        mode, pat = _validate_mode_and_pattern(
            body.match_mode or "REGEX",
            body.pattern_text or "",
        )
        adhoc_labels = (
            _validate_apply_labels(body.apply_labels)
            if body.apply_labels is not None
            else [clean_label]
        )
        adhoc_entry = AllowlistEntry(
            group_code=(body.group_code or "inline_test").strip() or "inline_test",
            item_name=(body.item_name or "即时测试规则").strip() or "即时测试规则",
            match_mode=mode,  # type: ignore[arg-type]
            pattern_text=pat,
            apply_labels=tuple(adhoc_labels),
            is_enabled=True,
        )
        if match_allowlist_entry(body.text, clean_label, adhoc_entry):
            matched_rules.append(
                {
                    "id": None,
                    "uuid": None,
                    "group_code": adhoc_entry.group_code,
                    "item_name": adhoc_entry.item_name,
                    "match_mode": adhoc_entry.match_mode,
                    "pattern_text": adhoc_entry.pattern_text,
                    "apply_labels": list(adhoc_entry.apply_labels),
                }
            )

    # 2. Saved DB allowlist evaluation (read-only SELECT)
    if not has_adhoc or body.include_saved:
        target_groups: list[str] = []
        if body.group_codes:
            target_groups.extend(g.strip() for g in body.group_codes if g and g.strip())
        if body.group_code and body.group_code.strip():
            target_groups.append(body.group_code.strip())

        stmt = select(AllowlistDict).where(
            AllowlistDict.is_deleted == 0,
            AllowlistDict.is_enabled == 1,
        )
        if target_groups:
            stmt = stmt.where(AllowlistDict.group_code.in_(target_groups))

        saved_rows = session.scalars(stmt.order_by(AllowlistDict.id.asc())).all()
        for row in saved_rows:
            entry = AllowlistEntry(
                group_code=row.group_code,
                item_name=row.item_name,
                match_mode=row.match_mode,  # type: ignore[arg-type]
                pattern_text=row.pattern_text,
                apply_labels=tuple(row.apply_labels_json or ()),
                is_enabled=True,
            )
            try:
                hit = match_allowlist_entry(body.text, clean_label, entry)
            except InvalidAllowlistPatternError as exc:
                raise BadRequestError(str(exc)) from None
            if hit:
                matched_rules.append(
                    {
                        "id": row.id,
                        "uuid": row.uuid,
                        "group_code": row.group_code,
                        "item_name": row.item_name,
                        "match_mode": row.match_mode,
                        "pattern_text": row.pattern_text,
                        "apply_labels": list(row.apply_labels_json or []),
                    }
                )

    return ok_response(
        {
            "matched": len(matched_rules) > 0,
            "matched_count": len(matched_rules),
            "matched_rules": matched_rules,
        },
        request=request,
    )


@router.post("")
def create_allowlist_item(
    body: CreateAllowlistRequest,
    request: Request,
    session: Session = Depends(get_session),
    admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR")),
) -> dict[str, Any]:
    clean_group = body.group_code.strip()
    if not _GROUP_CODE_RE.match(clean_group):
        raise BadRequestError(
            "Invalid group_code: use 1-64 alphanumeric, underscore, or hyphen characters"
        )
    clean_name = body.item_name.strip()
    if not clean_name:
        raise BadRequestError("item_name cannot be blank")

    clean_mode, clean_pattern = _validate_mode_and_pattern(
        body.match_mode, body.pattern_text
    )
    raw_labels = (
        body.apply_labels
        if body.apply_labels is not None
        else body.apply_labels_json
    )
    validated_labels = _validate_apply_labels(raw_labels)

    row = AllowlistDict(
        uuid=new_uuid(),
        group_code=clean_group,
        item_name=clean_name,
        match_mode=clean_mode,
        pattern_text=clean_pattern,
        apply_labels_json=validated_labels,
        is_enabled=1 if bool(body.is_enabled) else 0,
        remark=body.remark.strip() if body.remark else None,
        created_by=admin.username,
        is_deleted=0,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return ok_response(_serialize_allowlist_item(row), request=request)


@router.put("/{item_id}")
def update_allowlist_item(
    item_id: str,
    body: UpdateAllowlistRequest,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR")),
) -> dict[str, Any]:
    row = _find_allowlist_row(session, item_id)

    next_group = row.group_code
    if body.group_code is not None:
        next_group = body.group_code.strip()
        if not _GROUP_CODE_RE.match(next_group):
            raise BadRequestError("Invalid group_code format")

    next_name = row.item_name
    if body.item_name is not None:
        next_name = body.item_name.strip()
        if not next_name:
            raise BadRequestError("item_name cannot be blank")

    eff_mode = body.match_mode if body.match_mode is not None else row.match_mode
    eff_pattern = body.pattern_text if body.pattern_text is not None else row.pattern_text
    clean_mode, clean_pattern = _validate_mode_and_pattern(eff_mode, eff_pattern)

    raw_labels = (
        body.apply_labels
        if body.apply_labels is not None
        else body.apply_labels_json
    )
    next_labels = (
        _validate_apply_labels(raw_labels)
        if raw_labels is not None
        else list(row.apply_labels_json or [])
    )

    row.group_code = next_group
    row.item_name = next_name
    row.match_mode = clean_mode
    row.pattern_text = clean_pattern
    row.apply_labels_json = next_labels
    if body.is_enabled is not None:
        row.is_enabled = 1 if bool(body.is_enabled) else 0
    if "remark" in body.model_fields_set:
        row.remark = body.remark.strip() if body.remark else None
    row.update_time = utcnow()

    session.commit()
    session.refresh(row)
    return ok_response(_serialize_allowlist_item(row), request=request)


@router.delete("/{item_id}")
def delete_allowlist_item(
    item_id: str,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR")),
) -> dict[str, Any]:
    row = _find_allowlist_row(session, item_id)
    row.is_deleted = 1
    row.update_time = utcnow()
    session.commit()
    return ok_response(
        {"id": row.id, "uuid": row.uuid, "deleted": True},
        request=request,
    )
