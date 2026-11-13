from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import time

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common.logging import get_safe_logger
from app.config import Settings, get_settings
from app.db.base import utcnow
from app.db.models import BatchJob

logger = get_safe_logger("ds_center.ttl_cleaner")


def _normalize_utc_naive(dt: datetime | None) -> datetime:
    if dt is None:
        return utcnow()
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def safe_resolve_artifact_path(artifacts_dir: Path, relpath: str | None) -> Path | None:
    if not relpath or not relpath.strip():
        return None
    base_resolved = artifacts_dir.resolve()
    candidate = (artifacts_dir / relpath.strip()).resolve()
    if not candidate.is_relative_to(base_resolved) or candidate == base_resolved:
        return None
    return candidate


def _unlink_safe(path: Path, *, allow_busy_defer: bool = False) -> None:
    for attempt in range(3):
        try:
            path.unlink(missing_ok=True)
            return
        except PermissionError:
            if allow_busy_defer:
                return
            if attempt < 2:
                time.sleep(0.02)
            else:
                raise


def unlink_job_artifacts_on_disk(
    artifacts_dir: Path,
    job_no: str,
    relpath: str | None = None,
    *,
    allow_busy_defer: bool = False,
) -> None:
    resolved = safe_resolve_artifact_path(artifacts_dir, relpath)
    if resolved is not None:
        _unlink_safe(resolved, allow_busy_defer=allow_busy_defer)
        _unlink_safe(
            resolved.with_name(resolved.name + ".part"),
            allow_busy_defer=allow_busy_defer,
        )

    if artifacts_dir.is_dir():
        prefix = f"{job_no}."
        for entry in artifacts_dir.iterdir():
            if entry.is_file() and entry.name.startswith(prefix):
                _unlink_safe(entry, allow_busy_defer=allow_busy_defer)


def cleanup_expired_artifacts(
    session: Session,
    settings: Settings | None = None,
    *,
    now: datetime | None = None,
) -> int:
    """Physically delete expired masked artifacts and transition jobs to ARTIFACT_EXPIRED.

    Zero-plaintext audit statistics (record counts, char counts, entity_hit_stats_json,
    output_sha256, output_size_bytes, spot_check_status) are preserved intact.
    """
    cfg = settings or get_settings()
    cutoff = _normalize_utc_naive(now)

    expired_jobs = session.scalars(
        select(BatchJob).where(
            BatchJob.is_deleted == 0,
            BatchJob.status == "COMPLETED",
            BatchJob.expires_at.is_not(None),
            BatchJob.expires_at <= cutoff,
        )
    ).all()

    if not expired_jobs:
        return 0

    for job in expired_jobs:
        unlink_job_artifacts_on_disk(
            cfg.artifacts_dir,
            job.job_no,
            job.output_artifact_relpath,
        )
        job.status = "ARTIFACT_EXPIRED"
        job.update_time = cutoff

    session.commit()
    return len(expired_jobs)


async def _periodic_ttl_loop(app: FastAPI, stop_event: asyncio.Event) -> None:
    settings: Settings = getattr(app.state, "settings", None) or get_settings()
    interval = max(5, int(settings.ttl_cleanup_interval_seconds))
    session_factory = getattr(app.state, "session_factory", None)

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break
        except TimeoutError:
            pass

        if session_factory is None:
            continue
        try:
            def _run_once() -> int:
                with session_factory() as session:
                    return cleanup_expired_artifacts(session, settings)

            cleaned = await asyncio.to_thread(_run_once)
            if cleaned > 0:
                logger.info("TTL cleaner expired_jobs_cleaned=%d", cleaned)
        except Exception as exc:
            logger.error("TTL cleaner iteration failed type=%s", exc.__class__.__name__)


async def start_ttl_cleaner(app: FastAPI) -> None:
    from app.jobs.runner import ensure_static_pool_thread_safe

    ensure_static_pool_thread_safe(app)
    stop_event = asyncio.Event()
    task = asyncio.create_task(_periodic_ttl_loop(app, stop_event))
    app.state.ttl_cleaner_stop_event = stop_event
    app.state.ttl_cleaner_task = task


async def stop_ttl_cleaner(app: FastAPI) -> None:
    stop_event: asyncio.Event | None = getattr(
        app.state, "ttl_cleaner_stop_event", None
    )
    task: asyncio.Task[None] | None = getattr(app.state, "ttl_cleaner_task", None)
    if stop_event is not None:
        stop_event.set()
    if task is not None:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    app.state.ttl_cleaner_task = None
    app.state.ttl_cleaner_stop_event = None
