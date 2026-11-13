from __future__ import annotations

from datetime import datetime, timezone
import re
import time
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.common.envelope import ok_response
from app.common.errors import BadRequestError, NotFoundError
from app.config import get_request_settings
from app.db.base import new_uuid, utcnow
from app.db.models import AdminUser, DatasourceConn
from app.db.session import get_session
from app.jobs.crypto import decrypt_secret, encrypt_secret
from app.jobs.mysql_sampler import (
    validate_allowed_tables,
    validate_db_name,
    verify_readonly_mysql_connection,
)

router = APIRouter(prefix="/api/admin/datasources", tags=["admin-datasources"])

_CONN_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_DATASOURCE_STATUSES = frozenset({"ACTIVE", "DISABLED"})


def _fmt_dt(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="milliseconds") + "Z"


def _serialize_datasource(row: DatasourceConn) -> dict[str, Any]:
    tables = list(row.allowed_tables_json or [])
    return {
        "id": row.id,
        "uuid": row.uuid,
        "conn_code": row.conn_code,
        "conn_name": row.conn_name,
        "db_type": row.db_type,
        "db_host": row.db_host,
        "db_port": row.db_port,
        "db_name": row.db_name,
        "db_user": row.db_user,
        "has_password": bool(row.password_cipher),
        "allowed_tables": tables,
        "allowed_tables_json": list(tables),
        "status": row.status,
        "last_test_ok": None if row.last_test_ok is None else bool(row.last_test_ok),
        "last_tested_at": _fmt_dt(row.last_tested_at),
        "created_by": row.created_by,
        "create_time": _fmt_dt(row.create_time),
        "update_time": _fmt_dt(row.update_time),
    }


def _find_datasource(session: Session, code_or_id: str) -> DatasourceConn:
    target = code_or_id.strip()
    if target.isdigit():
        cond = or_(
            DatasourceConn.id == int(target),
            DatasourceConn.conn_code == target,
            DatasourceConn.uuid == target,
        )
    else:
        cond = or_(
            DatasourceConn.conn_code == target,
            DatasourceConn.uuid == target,
        )
    row = session.scalar(
        select(DatasourceConn).where(cond, DatasourceConn.is_deleted == 0)
    )
    if row is None:
        raise NotFoundError("Datasource not found")
    return row


class CreateDatasourceRequest(BaseModel):
    conn_code: str = Field(min_length=1, max_length=64)
    conn_name: str = Field(min_length=1, max_length=128)
    db_type: str = Field(default="MYSQL", min_length=1, max_length=16)
    db_host: str = Field(min_length=1, max_length=128)
    db_port: int = Field(default=3306, ge=1, le=65535)
    db_name: str = Field(min_length=1, max_length=64)
    db_user: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    allowed_tables: list[str] | None = None
    allowed_tables_json: list[str] | None = None
    status: str = Field(default="ACTIVE", min_length=1, max_length=16)


class UpdateDatasourceRequest(BaseModel):
    conn_name: str | None = Field(default=None, min_length=1, max_length=128)
    db_host: str | None = Field(default=None, min_length=1, max_length=128)
    db_port: int | None = Field(default=None, ge=1, le=65535)
    db_name: str | None = Field(default=None, min_length=1, max_length=64)
    db_user: str | None = Field(default=None, min_length=1, max_length=64)
    password: str | None = Field(default=None, max_length=256)
    allowed_tables: list[str] | None = None
    allowed_tables_json: list[str] | None = None
    status: str | None = Field(default=None, min_length=1, max_length=16)


@router.get("")
def list_datasources(
    request: Request,
    status: str | None = None,
    keyword: str | None = None,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    stmt = select(DatasourceConn).where(DatasourceConn.is_deleted == 0)
    if status is not None and status.strip():
        stmt = stmt.where(DatasourceConn.status == status.strip().upper())

    rows = session.scalars(stmt.order_by(DatasourceConn.id.desc())).all()
    if keyword is not None and keyword.strip():
        kw = keyword.strip().lower()
        rows = [
            r
            for r in rows
            if kw in r.conn_code.lower()
            or kw in r.conn_name.lower()
            or kw in r.db_host.lower()
            or kw in r.db_name.lower()
        ]
    items = [_serialize_datasource(r) for r in rows]
    return ok_response({"items": items, "total": len(items)}, request=request)


@router.post("")
def create_datasource(
    body: CreateDatasourceRequest,
    request: Request,
    session: Session = Depends(get_session),
    admin: AdminUser = Depends(require_roles("ADMIN")),
) -> dict[str, Any]:
    clean_code = body.conn_code.strip()
    if not _CONN_CODE_RE.match(clean_code):
        raise BadRequestError(
            "Invalid conn_code: use 1-64 alphanumeric, underscore, or hyphen characters"
        )
    clean_name = body.conn_name.strip()
    if not clean_name:
        raise BadRequestError("conn_name cannot be blank")

    clean_type = body.db_type.strip().upper()
    if clean_type != "MYSQL":
        raise BadRequestError("Only MYSQL read-only datasources are supported")

    clean_host = body.db_host.strip()
    clean_user = body.db_user.strip()
    if not clean_host or not clean_user:
        raise BadRequestError("db_host and db_user cannot be blank")
    clean_db = validate_db_name(body.db_name)

    clean_status = body.status.strip().upper()
    if clean_status not in _DATASOURCE_STATUSES:
        raise BadRequestError("Invalid status: must be ACTIVE or DISABLED")

    raw_tables = (
        body.allowed_tables
        if body.allowed_tables is not None
        else body.allowed_tables_json
    )
    validated_tables = validate_allowed_tables(raw_tables)

    settings = get_request_settings(request)
    cipher = encrypt_secret(body.password, settings.master_aes_key_bytes)

    existing = session.scalar(
        select(DatasourceConn).where(DatasourceConn.conn_code == clean_code)
    )
    if existing is not None:
        if existing.is_deleted == 0:
            raise BadRequestError(f"Datasource '{clean_code}' already exists")
        existing.uuid = new_uuid()
        existing.conn_name = clean_name
        existing.db_type = clean_type
        existing.db_host = clean_host
        existing.db_port = body.db_port
        existing.db_name = clean_db
        existing.db_user = clean_user
        existing.password_cipher = cipher
        existing.allowed_tables_json = validated_tables
        existing.status = clean_status
        existing.last_test_ok = None
        existing.last_tested_at = None
        existing.created_by = admin.username
        existing.is_deleted = 0
        existing.update_time = utcnow()
        row = existing
    else:
        row = DatasourceConn(
            uuid=new_uuid(),
            conn_code=clean_code,
            conn_name=clean_name,
            db_type=clean_type,
            db_host=clean_host,
            db_port=body.db_port,
            db_name=clean_db,
            db_user=clean_user,
            password_cipher=cipher,
            allowed_tables_json=validated_tables,
            status=clean_status,
            created_by=admin.username,
            is_deleted=0,
        )
        session.add(row)

    session.flush()
    session.refresh(row)
    session.commit()
    return ok_response(_serialize_datasource(row), request=request)


@router.put("/{code_or_id}")
def update_datasource(
    code_or_id: str,
    body: UpdateDatasourceRequest,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN")),
) -> dict[str, Any]:
    row = _find_datasource(session, code_or_id)
    settings = get_request_settings(request)
    conn_changed = False

    if body.conn_name is not None:
        clean_name = body.conn_name.strip()
        if not clean_name:
            raise BadRequestError("conn_name cannot be blank")
        row.conn_name = clean_name

    if body.db_host is not None:
        clean_host = body.db_host.strip()
        if not clean_host:
            raise BadRequestError("db_host cannot be blank")
        if clean_host != row.db_host:
            conn_changed = True
        row.db_host = clean_host

    if body.db_port is not None:
        if body.db_port != row.db_port:
            conn_changed = True
        row.db_port = body.db_port

    if body.db_name is not None:
        clean_db = validate_db_name(body.db_name)
        if clean_db != row.db_name:
            conn_changed = True
        row.db_name = clean_db

    if body.db_user is not None:
        clean_user = body.db_user.strip()
        if not clean_user:
            raise BadRequestError("db_user cannot be blank")
        if clean_user != row.db_user:
            conn_changed = True
        row.db_user = clean_user

    if body.password is not None and body.password != "":
        row.password_cipher = encrypt_secret(body.password, settings.master_aes_key_bytes)
        conn_changed = True

    raw_tables = (
        body.allowed_tables
        if body.allowed_tables is not None
        else body.allowed_tables_json
    )
    if raw_tables is not None:
        row.allowed_tables_json = validate_allowed_tables(raw_tables)

    if body.status is not None:
        clean_status = body.status.strip().upper()
        if clean_status not in _DATASOURCE_STATUSES:
            raise BadRequestError("Invalid status: must be ACTIVE or DISABLED")
        row.status = clean_status

    if conn_changed:
        row.last_test_ok = None
        row.last_tested_at = None

    row.update_time = utcnow()
    session.flush()
    session.refresh(row)
    session.commit()
    return ok_response(_serialize_datasource(row), request=request)


@router.delete("/{code_or_id}")
def delete_datasource(
    code_or_id: str,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN")),
) -> dict[str, Any]:
    row = _find_datasource(session, code_or_id)
    row.is_deleted = 1
    row.status = "DISABLED"
    row.update_time = utcnow()
    session.commit()
    return ok_response(
        {
            "id": row.id,
            "uuid": row.uuid,
            "conn_code": row.conn_code,
            "deleted": True,
        },
        request=request,
    )


@router.post("/{code}/test")
def test_datasource_connectivity(
    code: str,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN")),
) -> dict[str, Any]:
    row = _find_datasource(session, code)
    settings = get_request_settings(request)
    connector_factory = getattr(request.app.state, "mysql_connector_factory", None)

    t0 = time.perf_counter()
    try:
        plain_pwd = decrypt_secret(row.password_cipher, settings.master_aes_key_bytes)
    except ValueError:
        row.last_test_ok = 0
        row.last_tested_at = utcnow()
        row.update_time = row.last_tested_at
        session.commit()
        return ok_response(
            {
                "conn_code": row.conn_code,
                "ok": False,
                "read_only_verified": False,
                "last_test_ok": False,
                "last_tested_at": _fmt_dt(row.last_tested_at),
                "latency_ms": 0,
                "message": "Stored datasource credential decryption failed",
            },
            request=request,
        )

    try:
        latency_ms = verify_readonly_mysql_connection(
            host=row.db_host,
            port=row.db_port,
            user=row.db_user,
            password=plain_pwd,
            database=row.db_name,
            connector_factory=connector_factory,
        )
        row.last_test_ok = 1
        row.last_tested_at = utcnow()
        row.update_time = row.last_tested_at
        session.commit()
        return ok_response(
            {
                "conn_code": row.conn_code,
                "ok": True,
                "read_only_verified": True,
                "last_test_ok": True,
                "last_tested_at": _fmt_dt(row.last_tested_at),
                "latency_ms": latency_ms,
                "message": "Read-only session verified (SET SESSION TRANSACTION READ ONLY + SELECT 1)",
            },
            request=request,
        )
    except Exception as exc:
        elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
        row.last_test_ok = 0
        row.last_tested_at = utcnow()
        row.update_time = row.last_tested_at
        session.commit()
        return ok_response(
            {
                "conn_code": row.conn_code,
                "ok": False,
                "read_only_verified": False,
                "last_test_ok": False,
                "last_tested_at": _fmt_dt(row.last_tested_at),
                "latency_ms": elapsed_ms,
                "message": f"Read-only connectivity check failed ({exc.__class__.__name__})",
            },
            request=request,
        )
    finally:
        plain_pwd = ""
