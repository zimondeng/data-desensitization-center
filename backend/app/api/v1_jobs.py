from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.auth.dependencies import CallerPrincipal, require_job_caller
from app.common.envelope import ok_response
from app.common.errors import (
    ArtifactExpiredError,
    BadRequestError,
    ConflictLeakBlockedError,
)
from app.config import Settings, get_request_settings
from app.db.base import new_uuid, utcnow
from app.db.models import BatchJob
from app.db.session import get_session
from app.engine import PolicyEngineService
from app.jobs.file_readers import OUTPUT_MEDIA_TYPES, resolve_file_formats
from app.jobs.mysql_sampler import validate_column_role_mapping
from app.jobs.runner import (
    FileJobTaskSpec,
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

router = APIRouter(prefix="/api/v1/jobs", tags=["v1-jobs"])


async def _stream_upload_to_tmp(
    upload: UploadFile,
    dest_path: Path,
    max_bytes: int,
) -> int:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    try:
        with dest_path.open("wb") as out:
            while chunk := await upload.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise BadRequestError(
                        f"Uploaded file exceeds maximum size limit ({max_bytes} bytes)"
                    )
                out.write(chunk)
        return total
    except Exception:
        dest_path.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()


def _sanitize_masked_filename(
    raw_filename: str,
    ext_lower: str,
    engine: PolicyEngineService,
    snapshot: Any,
) -> str:
    safe_base = Path(raw_filename.replace("\\", "/")).name
    stem = safe_base[: -len(ext_lower)] if safe_base.lower().endswith(ext_lower) else safe_base
    stem = stem.strip() or "uploaded_file"
    masked_stem = engine.mask_text(stem[:120], snapshot).masked_text
    return f"{masked_stem}{ext_lower}"[:255]


@router.post("/file")
async def create_file_batch_job(
    request: Request,
    file: UploadFile = File(...),
    job_name: str | None = Form(default=None),
    policy_code: str | None = Form(default=None),
    policy_version: int | None = Form(default=None),
    output_format: str | None = Form(default=None),
    ttl_hours: int | None = Form(default=None),
    column_role_mapping: str | None = Form(default=None),
    session: Session = Depends(get_session),
    caller: CallerPrincipal = Depends(require_job_caller("ADMIN", "OPERATOR")),
) -> dict[str, Any]:
    settings: Settings = get_request_settings(request)
    engine = resolve_request_engine(request)

    try:
        input_fmt, out_fmt, ext_lower = resolve_file_formats(
            file.filename, output_format
        )
    except Exception:
        await file.close()
        raise

    eff_ttl = (
        settings.default_artifact_ttl_hours if ttl_hours is None else int(ttl_hours)
    )
    if eff_ttl < 1 or eff_ttl > 8760:
        await file.close()
        raise BadRequestError("ttl_hours must be between 1 and 8760")

    parsed_col_mapping: dict[str, str] | None = None
    if column_role_mapping is not None and column_role_mapping.strip():
        try:
            raw_map = json.loads(column_role_mapping)
        except json.JSONDecodeError:
            await file.close()
            raise BadRequestError("column_role_mapping must be valid JSON") from None
        try:
            parsed_col_mapping = validate_column_role_mapping(raw_map)
        except Exception:
            await file.close()
            raise

    eff_policy_code = (
        policy_code.strip()
        if policy_code and policy_code.strip()
        else caller.default_policy_code
    )
    try:
        snapshot = engine.resolve_policy(session, eff_policy_code, policy_version)
    except Exception:
        await file.close()
        raise

    job_no = generate_job_no(session)
    tmp_path = settings.tmp_uploads_dir / f"tmp_{job_no}_{uuid4().hex[:8]}{ext_lower}"

    await _stream_upload_to_tmp(file, tmp_path, settings.max_upload_bytes)

    try:
        masked_filename = _sanitize_masked_filename(
            file.filename or f"upload{ext_lower}",
            ext_lower,
            engine,
            snapshot,
        )
        raw_job_name = (job_name or "").strip()
        if raw_job_name:
            clean_job_name = engine.mask_text(raw_job_name[:128], snapshot).masked_text
        else:
            clean_job_name = masked_filename
        if len(clean_job_name) > 128:
            clean_job_name = clean_job_name[:128]

        now = utcnow()
        expires_at = now + timedelta(hours=eff_ttl)

        job_row = BatchJob(
            uuid=new_uuid(),
            job_no=job_no,
            job_name=clean_job_name,
            source_type="FILE_UPLOAD",
            input_format=input_fmt,
            source_filename_masked=masked_filename,
            datasource_id=None,
            sampling_config_json=None,
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
            triggered_by=caller.triggered_by,
            is_deleted=0,
        )
        session.add(job_row)
        session.flush()
        session.refresh(job_row)
        session.commit()
        job_id = job_row.id

        runner = get_or_create_job_runner(request.app)
        try:
            runner.submit_file_job(
                FileJobTaskSpec(
                    job_id=job_id,
                    job_no=job_row.job_no,
                    src_tmp_path=tmp_path,
                    input_format=input_fmt,
                    output_format=out_fmt,
                    snapshot=snapshot,
                    column_role_mapping=parsed_col_mapping,
                )
            )
        except Exception:
            cleanup_unsubmitted_job(session, job_id)
            raise
    except Exception:
        tmp_path.unlink(missing_ok=True)
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


@router.get("/{job_no}")
def get_batch_job_detail(
    job_no: str,
    request: Request,
    session: Session = Depends(get_session),
    _caller: CallerPrincipal = Depends(
        require_job_caller("ADMIN", "OPERATOR", "AUDITOR")
    ),
) -> dict[str, Any]:
    settings = get_request_settings(request)
    row = find_job_by_no(session, job_no)
    return ok_response(serialize_batch_job(row, settings), request=request)


@router.post("/{job_no}/cancel")
def cancel_batch_job(
    job_no: str,
    request: Request,
    session: Session = Depends(get_session),
    _caller: CallerPrincipal = Depends(require_job_caller("ADMIN", "OPERATOR")),
) -> dict[str, Any]:
    settings = get_request_settings(request)
    row = find_job_by_no(session, job_no)

    if row.status in ("COMPLETED", "FAILED", "ARTIFACT_EXPIRED"):
        raise BadRequestError(
            f"Cannot cancel batch job in terminal status '{row.status}'"
        )

    runner = get_or_create_job_runner(request.app)
    runner.request_cancel(row.job_no)
    unlink_job_artifacts_on_disk(
        settings.artifacts_dir,
        row.job_no,
        row.output_artifact_relpath,
        allow_busy_defer=True,
    )

    if row.status != "CANCELLED":
        now = utcnow()
        row.status = "CANCELLED"
        row.output_artifact_relpath = None
        row.output_size_bytes = None
        row.output_sha256 = None
        row.finished_at = row.finished_at or now
        row.update_time = now
        session.flush()
        session.refresh(row)
        session.commit()

    payload = serialize_batch_job(row, settings)
    session.close()
    return ok_response(payload, request=request)


@router.get("/{job_no}/download")
def download_batch_job_artifact(
    job_no: str,
    request: Request,
    session: Session = Depends(get_session),
    _caller: CallerPrincipal = Depends(
        require_job_caller("ADMIN", "OPERATOR", "AUDITOR")
    ),
) -> FileResponse:
    settings = get_request_settings(request)
    row = find_job_by_no(session, job_no)

    # Gate 1: Spot-check leak block -> 409 / 40901
    if row.spot_check_status == "FLAGGED_LEAK":
        raise ConflictLeakBlockedError(
            "Artifact has been flagged for potential leak during spot-check; download blocked"
        )

    # Gate 2: TTL expired -> 410 / 41001
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
            f"Job artifact is not available for download in status '{row.status}'"
        )

    artifact_path = safe_resolve_artifact_path(
        settings.artifacts_dir,
        row.output_artifact_relpath,
    )
    if artifact_path is None or not artifact_path.is_file():
        raise ArtifactExpiredError("Artifact file is no longer available on disk")

    media_type = OUTPUT_MEDIA_TYPES.get(
        row.output_format.upper(), "application/octet-stream"
    )
    headers: dict[str, str] = {}
    if row.output_sha256:
        headers["X-Content-SHA256"] = row.output_sha256

    session.close()
    return FileResponse(
        path=artifact_path,
        filename=artifact_path.name,
        media_type=media_type,
        headers=headers,
    )
