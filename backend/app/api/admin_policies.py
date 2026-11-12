from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import re
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.common.envelope import ok_response
from app.common.errors import BadRequestError, NotFoundError
from app.db.base import new_uuid, utcnow
from app.db.models import AdminUser, PolicyProfile
from app.db.session import get_session
from app.engine.service import (
    validate_allowlist_groups_list,
    validate_entity_rules,
    validate_field_role_rules_dict,
    validate_onnx_variant,
    validate_scope_mode,
)

router = APIRouter(prefix="/api/admin/policies", tags=["admin-policies"])

POLICY_STATUSES: frozenset[str] = frozenset({"DRAFT", "ACTIVE", "ARCHIVED"})
_POLICY_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _fmt_dt(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="milliseconds") + "Z"


def _serialize_policy(row: PolicyProfile) -> dict[str, Any]:
    entity_rules = deepcopy(row.entity_rules_json or {})
    field_role_rules = deepcopy(
        row.field_role_rules_json
        or {"default_role": "FULL_MASK_WRITE_SCOPE", "rules": []}
    )
    allowlist_groups = list(row.allowlist_groups_json or [])
    return {
        "id": row.id,
        "uuid": row.uuid,
        "policy_code": row.policy_code,
        "version": row.version,
        "policy_name": row.policy_name,
        "scope_mode": row.scope_mode,
        "onnx_variant": row.onnx_variant,
        "entity_rules": entity_rules,
        "entity_rules_json": deepcopy(entity_rules),
        "field_role_rules": field_role_rules,
        "field_role_rules_json": deepcopy(field_role_rules),
        "allowlist_groups": allowlist_groups,
        "allowlist_groups_json": list(allowlist_groups),
        "is_default": bool(row.is_default),
        "status": row.status,
        "description": row.description,
        "created_by": row.created_by,
        "create_time": _fmt_dt(row.create_time),
        "update_time": _fmt_dt(row.update_time),
    }


class CreatePolicyVersionRequest(BaseModel):
    policy_code: str = Field(min_length=1, max_length=64)
    policy_name: str = Field(min_length=1, max_length=128)
    scope_mode: str = Field(default="CONVERSATION", min_length=1, max_length=24)
    onnx_variant: str = Field(default="int8", min_length=1, max_length=16)
    entity_rules: dict[str, dict[str, Any]] | None = None
    entity_rules_json: dict[str, dict[str, Any]] | None = None
    field_role_rules: dict[str, Any] | None = None
    field_role_rules_json: dict[str, Any] | None = None
    allowlist_groups: list[str] | None = None
    allowlist_groups_json: list[str] | None = None
    set_as_default: bool | None = None
    is_default: bool | int | None = None
    status: str = Field(default="ACTIVE", min_length=1, max_length=16)
    description: str | None = Field(default=None, max_length=500)


@router.get("")
def list_policies(
    request: Request,
    policy_code: str | None = None,
    status: str | None = None,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    stmt = select(PolicyProfile).where(PolicyProfile.is_deleted == 0)
    if policy_code is not None and policy_code.strip():
        stmt = stmt.where(PolicyProfile.policy_code == policy_code.strip())
    if status is not None and status.strip():
        stmt = stmt.where(PolicyProfile.status == status.strip().upper())

    rows = session.scalars(
        stmt.order_by(PolicyProfile.policy_code.asc(), PolicyProfile.version.desc())
    ).all()
    items = [_serialize_policy(row) for row in rows]

    grouped_map: dict[str, dict[str, Any]] = {}
    for item in items:
        code = item["policy_code"]
        grp = grouped_map.get(code)
        if grp is None:
            grp = {
                "policy_code": code,
                "policy_name": item["policy_name"],
                "default_version": item["version"] if item["is_default"] else None,
                "latest_version": item["version"],
                "versions": [],
            }
            grouped_map[code] = grp
        elif item["is_default"]:
            grp["default_version"] = item["version"]
            grp["policy_name"] = item["policy_name"]
        grp["versions"].append(item)

    return ok_response(
        {
            "items": items,
            "total": len(items),
            "policies": list(grouped_map.values()),
        },
        request=request,
    )


@router.get("/{policy_code}/versions/{ver}")
def get_policy_version(
    policy_code: str,
    ver: int,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    row = session.scalar(
        select(PolicyProfile).where(
            PolicyProfile.policy_code == policy_code.strip(),
            PolicyProfile.version == ver,
            PolicyProfile.is_deleted == 0,
        )
    )
    if row is None:
        raise NotFoundError(f"Policy '{policy_code}' version {ver} not found")
    return ok_response(_serialize_policy(row), request=request)


@router.post("")
def create_or_bump_policy_version(
    body: CreatePolicyVersionRequest,
    request: Request,
    session: Session = Depends(get_session),
    admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR")),
) -> dict[str, Any]:
    clean_code = body.policy_code.strip()
    if not _POLICY_CODE_RE.match(clean_code):
        raise BadRequestError(
            "Invalid policy_code: use 1-64 alphanumeric, underscore, or hyphen characters"
        )
    clean_name = body.policy_name.strip()
    if not clean_name:
        raise BadRequestError("policy_name cannot be blank")

    clean_status = body.status.strip().upper()
    if clean_status not in POLICY_STATUSES:
        raise BadRequestError("Invalid status: must be DRAFT, ACTIVE, or ARCHIVED")

    scope_mode = validate_scope_mode(body.scope_mode.strip().upper())
    onnx_variant = validate_onnx_variant(body.onnx_variant.strip().lower())

    raw_entity_rules = (
        body.entity_rules
        if body.entity_rules is not None
        else body.entity_rules_json
    )
    if raw_entity_rules is None:
        raise BadRequestError("entity_rules is required")
    validated_entity_rules = validate_entity_rules(
        raw_entity_rules, fill_missing_disabled=True
    )

    raw_field_rules = (
        body.field_role_rules
        if body.field_role_rules is not None
        else body.field_role_rules_json
    )
    validated_field_rules = validate_field_role_rules_dict(raw_field_rules)

    raw_groups = (
        body.allowlist_groups
        if body.allowlist_groups is not None
        else body.allowlist_groups_json
    )
    validated_groups = validate_allowlist_groups_list(raw_groups)

    max_ver = session.scalar(
        select(func.max(PolicyProfile.version)).where(
            PolicyProfile.policy_code == clean_code
        )
    )
    next_version = 1 if max_ver is None else int(max_ver) + 1

    existing_active_rows = session.scalars(
        select(PolicyProfile).where(
            PolicyProfile.policy_code == clean_code,
            PolicyProfile.is_deleted == 0,
        )
    ).all()

    explicit_default_flag = (
        body.set_as_default
        if body.set_as_default is not None
        else (bool(body.is_default) if body.is_default is not None else None)
    )
    if not existing_active_rows:
        make_default = (
            explicit_default_flag
            if explicit_default_flag is not None
            else (clean_status == "ACTIVE")
        )
    else:
        make_default = bool(explicit_default_flag)

    if make_default:
        clean_status = "ACTIVE"
        for sibling in existing_active_rows:
            if sibling.is_default != 0:
                sibling.is_default = 0

    new_row = PolicyProfile(
        uuid=new_uuid(),
        policy_code=clean_code,
        version=next_version,
        policy_name=clean_name,
        scope_mode=scope_mode,
        onnx_variant=onnx_variant,
        entity_rules_json=validated_entity_rules,
        field_role_rules_json=validated_field_rules,
        allowlist_groups_json=validated_groups,
        is_default=1 if make_default else 0,
        status=clean_status,
        description=body.description.strip() if body.description else None,
        created_by=admin.username,
        is_deleted=0,
    )
    session.add(new_row)
    session.commit()
    session.refresh(new_row)

    return ok_response(_serialize_policy(new_row), request=request)


@router.post("/{policy_code}/versions/{ver}/set-default")
def set_default_policy_version(
    policy_code: str,
    ver: int,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR")),
) -> dict[str, Any]:
    clean_code = policy_code.strip()
    target = session.scalar(
        select(PolicyProfile).where(
            PolicyProfile.policy_code == clean_code,
            PolicyProfile.version == ver,
            PolicyProfile.is_deleted == 0,
        )
    )
    if target is None:
        raise NotFoundError(f"Policy '{clean_code}' version {ver} not found")

    siblings = session.scalars(
        select(PolicyProfile).where(
            PolicyProfile.policy_code == clean_code,
            PolicyProfile.is_deleted == 0,
        )
    ).all()

    now = utcnow()
    for row in siblings:
        if row.id == target.id:
            row.is_default = 1
            row.status = "ACTIVE"
            row.update_time = now
        elif row.is_default != 0:
            row.is_default = 0
            row.update_time = now

    session.commit()
    session.refresh(target)
    return ok_response(_serialize_policy(target), request=request)
