from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.common.envelope import ok_response
from app.common.errors import (
    ArtifactExpiredError,
    BadRequestError,
    NotFoundError,
)
from app.config import Settings, get_request_settings
from app.db.base import new_uuid, utcnow
from app.db.models import AdminUser, BatchJob, DatasourceConn
from app.db.session import get_session
from app.jobs.file_readers import preview_masked_artifact, validate_output_format
from app.jobs.mysql_sampler import (
    build_readonly_sample_query,
    redact_where_clause_literals,
    validate_column_role_mapping,
    validate_sql_identifier,
)
from app.jobs.runner import (
    MysqlSampleTaskSpec,
    cleanup_unsubmitted_job,
    find_job_by_no,
    fmt_job_dt,
    generate_job_no,
    get_or_create_job_runner,
    serialize_batch_job,
)
from app.jobs.ttl_cleaner import (
    safe_resolve_artifact_path,
    unlink_job_artifacts_on_disk,
)
from app.telemetry import resolve_request_engine

router = APIRouter(prefix="/api/admin/jobs", tags=["admin-jobs"])

SPOT_CHECK_DECISIONS: frozenset[str] = frozenset(
    {"PASSED", "FLAGGED_LEAK", "FLAGGED_OVERMASK"}
)


class CreateMysqlSampleJobRequest(BaseModel):
    job_name: str = Field(min_length=1, max_length=128)
    datasource_code: str = Field(min_length=1, max_length=64)
    table_name: str = Field(min_length=1, max_length=64)
    select_columns: list[str] = Field(min_length=1, max_length=128)
    where_clause: str | None = Field(default=None, max_length=2000)
    limit_rows: int = Field(default=1000, ge=1, le=100000)
    column_role_mapping: dict[str, str] | None = None
    policy_code: str = Field(default="strict_general", min_length=1, max_length=64)
    policy_version: int | None = None
    output_format: str = Field(default="JSONL", min_length=1, max_length=16)
    ttl_hours: int | None = Field(default=None, ge=1, le=8760)


class SpotCheckJobRequest(BaseModel):
    spot_check_status: str = Field(min_length=1, max_length=24)
    spot_check_note: str | None = Field(default=None, max_length=500)


@router.get("")
def list_admin_batch_jobs(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    status: str | None = None,
    source_type: str | None = None,
    spot_check_status: str | None = None,
    keyword: str | None = None,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    settings = get_request_settings(request)
    conditions = [BatchJob.is_deleted == 0]

    if status is not None and status.strip():
        conditions.append(BatchJob.status == status.strip().upper())
    if source_type is not None and source_type.strip():
        conditions.append(BatchJob.source_type == source_type.strip().upper())
    if spot_check_status is not None and spot_check_status.strip():
        conditions.append(
            BatchJob.spot_check_status == spot_check_status.strip().upper()
        )
    if keyword is not None and keyword.strip():
        kw = f"%{keyword.strip()}%"
        conditions.append(
            or_(
                BatchJob.job_no.like(kw),
                BatchJob.job_name.like(kw),
                BatchJob.policy_code_snapshot.like(kw),
            )
        )

    total = int(
        session.scalar(select(func.count(BatchJob.id)).where(*conditions)) or 0
    )
    offset = (page - 1) * page_size
    rows = session.scalars(
        select(BatchJob)
        .where(*conditions)
        .order_by(BatchJob.id.desc())
        .offset(offset)
        .limit(page_size)
    ).all()

    items = [serialize_batch_job(r, settings) for r in rows]
    return ok_response(
        {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
        },
        request=request,
    )


@router.post("/mysql-sample")
def create_mysql_sample_job(
    body: CreateMysqlSampleJobRequest,
    request: Request,
    session: Session = Depends(get_session),
    admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR")),
) -> dict[str, Any]:
    settings: Settings = get_request_settings(request)
    engine = resolve_request_engine(request)

    clean_job_name = body.job_name.strip()
    if not clean_job_name:
        raise BadRequestError("job_name cannot be blank")

    clean_ds_code = body.datasource_code.strip()
    datasource = session.scalar(
        select(DatasourceConn).where(
            DatasourceConn.conn_code == clean_ds_code,
            DatasourceConn.is_deleted == 0,
        )
    )
    if datasource is None:
        raise NotFoundError(f"Datasource '{clean_ds_code}' not found")
    if datasource.status != "ACTIVE":
        raise BadRequestError(f"Datasource '{clean_ds_code}' is disabled")

    clean_cols: list[str] = []
    seen_cols: set[str] = set()
    for col in body.select_columns:
        valid_col = validate_sql_identifier(col, kind="column")
        if valid_col not in seen_cols:
            seen_cols.add(valid_col)
            clean_cols.append(valid_col)

    sql, params = build_readonly_sample_query(
        table_name=body.table_name,
        select_columns=clean_cols,
        allowed_tables=datasource.allowed_tables_json or [],
        where_clause=body.where_clause,
        limit_rows=body.limit_rows,
    )
    validated_col_roles = validate_column_role_mapping(
        body.column_role_mapping,
        allowed_columns=clean_cols,
    )
    out_fmt = validate_output_format(body.output_format, default="JSONL")
    snapshot = engine.resolve_policy(
        session, body.policy_code.strip(), body.policy_version
    )
    clean_job_name = engine.mask_text(clean_job_name[:128], snapshot).masked_text[:128]

    eff_ttl = (
        settings.default_artifact_ttl_hours
        if body.ttl_hours is None
        else int(body.ttl_hours)
    )
    now = utcnow()
    expires_at = now + timedelta(hours=eff_ttl)
    job_no = generate_job_no(session)

    # Zero-plaintext audit metadata: literal filter values in where_clause are redacted before DB persistence
    safe_sampling_cfg = {
        "datasource_code": datasource.conn_code,
        "table_name": body.table_name.strip(),
        "select_columns": clean_cols,
        "where_clause_template": redact_where_clause_literals(body.where_clause),
        "limit_rows": body.limit_rows,
        "column_role_mapping": validated_col_roles,
    }

    job_row = BatchJob(
        uuid=new_uuid(),
        job_no=job_no,
        job_name=clean_job_name,
        source_type="MYSQL_READONLY",
        input_format="SQL_CURSOR",
        source_filename_masked=None,
        datasource_id=datasource.id,
        sampling_config_json=safe_sampling_cfg,
        policy_id=snapshot.policy_id,
        policy_code_snapshot=snapshot.policy_code,
        policy_version_snapshot=snapshot.version,
        status="PENDING",
        total_records=0,
        processed_records=0,
        failed_records=0,
        total_chars=0,
        entity_hit_stats_json={},
        output_format=out_fmt,
        spot_check_status="UNCHECKED",
        expires_at=expires_at,
        triggered_by=admin.username,
        is_deleted=0,
    )
    session.add(job_row)
    session.flush()
    session.refresh(job_row)
    session.commit()
    job_id = job_row.id

    runner = get_or_create_job_runner(request.app)
    try:
        runner.submit_mysql_job(
            MysqlSampleTaskSpec(
                job_id=job_id,
                job_no=job_row.job_no,
                datasource_id=datasource.id,
                sql=sql,
                params=params,
                select_columns=clean_cols,
                output_format=out_fmt,
                snapshot=snapshot,
                column_role_mapping=validated_col_roles,
            )
        )
    except Exception:
        cleanup_unsubmitted_job(session, job_id)
        raise

    return ok_response(
        {
            "id": job_row.id,
            "uuid": job_row.uuid,
            "job_no": job_row.job_no,
            "job_name": job_row.job_name,
            "source_type": job_row.source_type,
            "input_format": job_row.input_format,
            "output_format": job_row.output_format,
            "status": job_row.status,
            "policy_code": job_row.policy_code_snapshot,
            "policy_version": job_row.policy_version_snapshot,
            "spot_check_status": job_row.spot_check_status,
            "expires_at": fmt_job_dt(job_row.expires_at),
            "create_time": fmt_job_dt(job_row.create_time),
        },
        request=request,
    )


@router.get("/{job_no}/preview-masked")
def preview_batch_job_masked_artifact(
    job_no: str,
    request: Request,
    limit: int = Query(default=20, ge=1, le=200),
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    settings = get_request_settings(request)
    row = find_job_by_no(session, job_no)

    now = utcnow()
    if row.status == "ARTIFACT_EXPIRED":
        raise ArtifactExpiredError()
    if (
        row.status == "COMPLETED"
        and row.expires_at is not None
        and row.expires_at <= now
    ):
        unlink_job_artifacts_on_disk(
            settings.artifacts_dir,
            row.job_no,
            row.output_artifact_relpath,
        )
        row.status = "ARTIFACT_EXPIRED"
        row.update_time = now
        session.commit()
        raise ArtifactExpiredError()

    if row.status != "COMPLETED":
        raise BadRequestError(
            f"Masked preview is only available for COMPLETED jobs (current={row.status})"
        )

    artifact_path = safe_resolve_artifact_path(
        settings.artifacts_dir, row.output_artifact_relpath
    )
    if artifact_path is None or not artifact_path.is_file():
        raise ArtifactExpiredError("Masked artifact file is no longer available on disk")

    preview_data = preview_masked_artifact(
        artifact_path, row.output_format, limit=limit
    )
    return ok_response(
        {
            "job_no": row.job_no,
            "policy_code": row.policy_code_snapshot,
            "policy_version": row.policy_version_snapshot,
            "spot_check_status": row.spot_check_status,
            "spot_check_note": row.spot_check_note,
            "output_sha256": row.output_sha256,
            "expires_at": fmt_job_dt(row.expires_at),
            **preview_data,
        },
        request=request,
    )


@router.post("/{job_no}/spot-check")
def submit_job_spot_check(
    job_no: str,
    body: SpotCheckJobRequest,
    request: Request,
    session: Session = Depends(get_session),
    admin: AdminUser = Depends(require_roles("ADMIN", "AUDITOR")),
) -> dict[str, Any]:
    settings = get_request_settings(request)
    row = find_job_by_no(session, job_no)

    decision = body.spot_check_status.strip().upper()
    if decision not in SPOT_CHECK_DECISIONS:
        raise BadRequestError(
            "Invalid spot_check_status: must be PASSED, FLAGGED_LEAK, or FLAGGED_OVERMASK"
        )

    if row.status not in ("COMPLETED", "ARTIFACT_EXPIRED"):
        raise BadRequestError(
            f"Cannot submit spot-check for job in status '{row.status}'"
        )

    clean_note = body.spot_check_note.strip() if body.spot_check_note else None
    now = utcnow()
    row.spot_check_status = decision
    row.spot_checked_by = admin.username
    row.spot_checked_at = now
    row.spot_check_note = clean_note
    row.update_time = now
    session.flush()
    session.refresh(row)
    session.commit()

    return ok_response(serialize_batch_job(row, settings), request=request)


@router.get("/{job_no}")
def get_admin_batch_job_detail(
    job_no: str,
    request: Request,
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    settings = get_request_settings(request)
    row = find_job_by_no(session, job_no)
    return ok_response(serialize_batch_job(row, settings), request=request)
