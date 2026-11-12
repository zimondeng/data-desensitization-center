from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.auth.security import generate_api_key, validate_allowed_ips_config
from app.common.envelope import ok_response
from app.common.errors import BadRequestError, NotFoundError
from app.db.base import new_uuid, utcnow
from app.db.models import AdminUser, ApiKey
from app.db.session import get_session

router = APIRouter(prefix="/api/admin/api-keys", tags=["admin-api-keys"])


def _fmt_dt(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="milliseconds") + "Z"


def _normalize_utc_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _serialize_api_key(row: ApiKey) -> dict[str, Any]:
    return {
        "id": row.id,
        "uuid": row.uuid,
        "key_name": row.key_name,
        "key_prefix": row.key_prefix,
        "default_policy_code": row.default_policy_code,
        "rate_limit_rpm": row.rate_limit_rpm,
        "allowed_ips": row.allowed_ips_json,
        "status": row.status,
        "expires_at": _fmt_dt(row.expires_at),
        "last_used_at": _fmt_dt(row.last_used_at),
        "created_by": row.created_by,
        "create_time": _fmt_dt(row.create_time),
        "update_time": _fmt_dt(row.update_time),
    }


class CreateApiKeyRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=128)
    default_policy_code: str = Field(default="strict_general", min_length=1, max_length=64)
    rate_limit_rpm: int = Field(default=600, ge=1, le=100000)
    allowed_ips: list[str] | None = None
    allowed_ips_json: list[str] | None = None
    expires_at: datetime | None = None
    env_tag: Literal["live", "test"] = "live"


@router.get("")
def list_api_keys(
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict:
    rows = session.scalars(
        select(ApiKey)
        .where(ApiKey.is_deleted == 0)
        .order_by(ApiKey.id.desc())
    ).all()
    items = [_serialize_api_key(row) for row in rows]
    return ok_response({"items": items, "total": len(items)}, request=request)


@router.post("")
def create_api_key(
    body: CreateApiKeyRequest,
    request: Request,
    session: Session = Depends(get_session),
    admin: AdminUser = Depends(require_roles("ADMIN")),
) -> dict:
    clean_name = body.key_name.strip()
    clean_policy = body.default_policy_code.strip()
    if not clean_name:
        raise BadRequestError("key_name cannot be blank")
    if not clean_policy:
        raise BadRequestError("default_policy_code cannot be blank")

    raw_ips = body.allowed_ips if body.allowed_ips is not None else body.allowed_ips_json
    validated_ips = validate_allowed_ips_config(raw_ips)
    plain_key, key_prefix, key_sha256 = generate_api_key(body.env_tag)

    row = ApiKey(
        uuid=new_uuid(),
        key_name=clean_name,
        key_prefix=key_prefix,
        key_sha256=key_sha256,
        default_policy_code=clean_policy,
        rate_limit_rpm=body.rate_limit_rpm,
        allowed_ips_json=validated_ips,
        status="ACTIVE",
        expires_at=_normalize_utc_naive(body.expires_at),
        created_by=admin.username,
        is_deleted=0,
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    result = _serialize_api_key(row)
    result["plain_key"] = plain_key
    return ok_response(result, request=request)


@router.delete("/{uuid_or_id}")
def revoke_api_key(
    uuid_or_id: str,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN")),
) -> dict:
    target = uuid_or_id.strip()
    if target.isdigit():
        cond = or_(ApiKey.id == int(target), ApiKey.uuid == target)
    else:
        cond = ApiKey.uuid == target

    row = session.scalar(
        select(ApiKey).where(cond, ApiKey.is_deleted == 0)
    )
    if row is None:
        raise NotFoundError("API Key not found")

    row.status = "REVOKED"
    row.update_time = utcnow()
    session.commit()
    return ok_response(
        {"id": row.id, "uuid": row.uuid, "status": row.status},
        request=request,
    )
