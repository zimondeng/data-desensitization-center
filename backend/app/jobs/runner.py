from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import secrets
import threading
import time
from typing import Any
import weakref

from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.common.envelope import format_optional_utc_ms
from app.common.errors import BadRequestError, NotFoundError
from app.common.logging import get_safe_logger
from app.config import Settings, get_settings
from app.db.base import utcnow
from app.db.models import BatchJob, DatasourceConn
from app.detectors.types import DetectorNotReadyError
from app.engine import PolicyEngineService, ResolvedPolicySnapshot, get_policy_engine
from app.jobs.crypto import decrypt_secret
from app.jobs.file_readers import (
    OUTPUT_FORMAT_EXTENSIONS,
    FileParseError,
    JobCancelledError,
    process_record_stream_to_artifact,
    process_uploaded_file_and_unlink,
)
from app.jobs.mysql_sampler import (
    MysqlConnectorFactory,
    stream_readonly_mysql_rows,
)
from app.jobs.ttl_cleaner import (
    safe_resolve_artifact_path,
    unlink_job_artifacts_on_disk,
)

logger = get_safe_logger("ds_center.job_runner")

_JOB_SEQ_LOCK = threading.Lock()
_JOB_SEQ_COUNTER = 0


def fmt_job_dt(dt: datetime | None) -> str | None:
    return format_optional_utc_ms(dt)


def find_job_by_no(session: Session, job_no: str) -> BatchJob:
    clean_no = job_no.strip()
    row = session.scalar(
        select(BatchJob).where(
            BatchJob.job_no == clean_no,
            BatchJob.is_deleted == 0,
        )
    )
    if row is None:
        raise NotFoundError(f"Batch job '{clean_no}' not found")
    return row


def cleanup_unsubmitted_job(session: Session, job_id: int) -> None:
    """Remove a freshly committed PENDING BatchJob if background submission fails."""
    session.rollback()
    row = session.get(BatchJob, job_id)
    if row is not None:
        session.delete(row)
        session.commit()


def generate_job_no(session: Session) -> str:
    global _JOB_SEQ_COUNTER
    day_str = utcnow().strftime("%Y%m%d")
    with _JOB_SEQ_LOCK:
        _JOB_SEQ_COUNTER += 1
        base_count = int(session.scalar(select(func.count(BatchJob.id))) or 0)
        seq = base_count + _JOB_SEQ_COUNTER

    candidate = f"DSJ_{day_str}_{seq:04d}"
    exists = session.scalar(select(BatchJob.id).where(BatchJob.job_no == candidate))
    if exists is not None:
        candidate = f"DSJ_{day_str}_{seq:04d}_{secrets.token_hex(2)}"
    return candidate


def serialize_batch_job(
    row: BatchJob,
    settings: Settings | None = None,
) -> dict[str, Any]:
    cfg = settings or get_settings()
    hit_stats = deepcopy(row.entity_hit_stats_json or {})
    sampling_cfg = deepcopy(row.sampling_config_json) if row.sampling_config_json else None

    if row.status == "COMPLETED":
        progress_pct = 100.0
    elif row.total_records and row.total_records > 0:
        progress_pct = round(
            min(100.0, (row.processed_records / row.total_records) * 100.0), 2
        )
    else:
        progress_pct = 0.0

    artifact_path = safe_resolve_artifact_path(
        cfg.artifacts_dir, row.output_artifact_relpath
    )
    has_artifact = bool(
        row.status == "COMPLETED"
        and artifact_path is not None
        and artifact_path.is_file()
    )

    return {
        "id": row.id,
        "uuid": row.uuid,
        "job_no": row.job_no,
        "job_name": row.job_name,
        "source_type": row.source_type,
        "input_format": row.input_format,
        "source_filename_masked": row.source_filename_masked,
        "datasource_id": row.datasource_id,
        "sampling_config": sampling_cfg,
        "sampling_config_json": deepcopy(sampling_cfg) if sampling_cfg else None,
        "policy_id": row.policy_id,
        "policy_code": row.policy_code_snapshot,
        "policy_version": row.policy_version_snapshot,
        "policy_code_snapshot": row.policy_code_snapshot,
        "policy_version_snapshot": row.policy_version_snapshot,
        "status": row.status,
        "total_records": row.total_records,
        "processed_records": row.processed_records,
        "failed_records": row.failed_records,
        "total_chars": row.total_chars,
        "progress_pct": progress_pct,
        "entity_hit_stats": hit_stats,
        "entity_hit_stats_json": deepcopy(hit_stats),
        "output_format": row.output_format,
        "output_size_bytes": row.output_size_bytes,
        "output_sha256": row.output_sha256,
        "has_artifact": has_artifact,
        "expires_at": fmt_job_dt(row.expires_at),
        "spot_check_status": row.spot_check_status,
        "spot_checked_by": row.spot_checked_by,
        "spot_checked_at": fmt_job_dt(row.spot_checked_at),
        "spot_check_note": row.spot_check_note,
        "elapsed_ms": row.elapsed_ms,
        "error_summary": row.error_summary,
        "started_at": fmt_job_dt(row.started_at),
        "finished_at": fmt_job_dt(row.finished_at),
        "triggered_by": row.triggered_by,
        "create_time": fmt_job_dt(row.create_time),
        "update_time": fmt_job_dt(row.update_time),
    }


@dataclass(slots=True)
class FileJobTaskSpec:
    job_id: int
    job_no: str
    src_tmp_path: Path
    input_format: str
    output_format: str
    snapshot: ResolvedPolicySnapshot
    column_role_mapping: dict[str, str] | None = None


@dataclass(slots=True)
class MysqlSampleTaskSpec:
    job_id: int
    job_no: str
    datasource_id: int
    sql: str
    params: tuple[Any, ...]
    select_columns: list[str]
    output_format: str
    snapshot: ResolvedPolicySnapshot
    column_role_mapping: dict[str, str] | None = None


class JobRunner:
    """In-process async worker pool for file-upload and MySQL read-only batch jobs."""

    def __init__(
        self,
        *,
        app: FastAPI,
        max_workers: int = 2,
    ) -> None:
        self._app = app
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, max_workers),
            thread_name_prefix="ds-batch-worker",
        )
        self._lock = threading.RLock()
        self._db_write_lock = threading.RLock()
        self._cancel_events: dict[str, threading.Event] = {}
        self._futures: dict[str, Future[None]] = {}
        self._tmp_paths: dict[str, Path] = {}
        self._shutdown = False

    def _settings(self) -> Settings:
        return getattr(self._app.state, "settings", None) or get_settings()

    def _session_factory(self) -> sessionmaker[Session]:
        return self._app.state.session_factory

    def _engine(self) -> PolicyEngineService:
        return getattr(self._app.state, "policy_engine", None) or get_policy_engine()

    def _mysql_connector_factory(self) -> MysqlConnectorFactory | None:
        return getattr(self._app.state, "mysql_connector_factory", None)

    def _execution_hook(self) -> Callable[[str, threading.Event], Any] | None:
        return getattr(self._app.state, "job_execution_hook", None)

    def request_cancel(self, job_no: str) -> None:
        tmp_to_unlink: Path | None = None
        with self._lock:
            ev = self._cancel_events.get(job_no)
            if ev is None:
                ev = threading.Event()
                self._cancel_events[job_no] = ev
            ev.set()
            fut = self._futures.get(job_no)
            if fut is not None and fut.cancel():
                self._futures.pop(job_no, None)
                self._cancel_events.pop(job_no, None)
                tmp_to_unlink = self._tmp_paths.pop(job_no, None)
        if tmp_to_unlink is not None:
            tmp_to_unlink.unlink(missing_ok=True)

    def submit_file_job(self, spec: FileJobTaskSpec) -> None:
        with self._lock:
            if self._shutdown:
                spec.src_tmp_path.unlink(missing_ok=True)
                raise BadRequestError("Batch job runner is shutting down")
            cancel_ev = self._cancel_events.setdefault(spec.job_no, threading.Event())
            try:
                fut = self._executor.submit(self._run_file_job, spec, cancel_ev)
            except Exception:
                self._cancel_events.pop(spec.job_no, None)
                raise
            self._tmp_paths[spec.job_no] = spec.src_tmp_path
            self._futures[spec.job_no] = fut

    def submit_mysql_job(self, spec: MysqlSampleTaskSpec) -> None:
        with self._lock:
            if self._shutdown:
                raise BadRequestError("Batch job runner is shutting down")
            cancel_ev = self._cancel_events.setdefault(spec.job_no, threading.Event())
            try:
                fut = self._executor.submit(self._run_mysql_job, spec, cancel_ev)
            except Exception:
                self._cancel_events.pop(spec.job_no, None)
                raise
            self._futures[spec.job_no] = fut

    def _mark_running_if_pending(
        self, job_id: int, cancel_ev: threading.Event
    ) -> bool:
        with self._db_write_lock, self._session_factory()() as session:
            job = session.get(BatchJob, job_id)
            if job is None or job.is_deleted != 0:
                return False
            if cancel_ev.is_set() or job.status == "CANCELLED":
                job.status = "CANCELLED"
                job.finished_at = job.finished_at or utcnow()
                job.update_time = utcnow()
                session.commit()
                return False
            job.status = "RUNNING"
            job.started_at = utcnow()
            job.update_time = job.started_at
            session.commit()
            return True

    def _finalize_completed(
        self,
        job_id: int,
        job_no: str,
        relpath: str,
        summary: Any,
        elapsed_ms: int,
        cancel_ev: threading.Event,
    ) -> None:
        settings = self._settings()
        with self._db_write_lock, self._session_factory()() as session:
            job = session.get(BatchJob, job_id)
            if job is None:
                unlink_job_artifacts_on_disk(settings.artifacts_dir, job_no, relpath)
                return
            if cancel_ev.is_set() or job.status == "CANCELLED":
                unlink_job_artifacts_on_disk(settings.artifacts_dir, job_no, relpath)
                job.status = "CANCELLED"
                job.output_artifact_relpath = None
                job.output_size_bytes = None
                job.output_sha256 = None
                job.finished_at = job.finished_at or utcnow()
                job.update_time = utcnow()
                session.commit()
                return

            now = utcnow()
            job.status = "COMPLETED"
            job.total_records = summary.total_records
            job.processed_records = summary.processed_records
            job.failed_records = summary.failed_records
            job.total_chars = summary.total_chars
            job.entity_hit_stats_json = summary.hit_counts
            job.output_artifact_relpath = relpath
            job.output_size_bytes = summary.output_size_bytes
            job.output_sha256 = summary.output_sha256
            job.elapsed_ms = elapsed_ms
            job.finished_at = now
            job.update_time = now
            session.commit()

    def _finalize_cancelled(self, job_id: int, job_no: str, relpath: str) -> None:
        settings = self._settings()
        unlink_job_artifacts_on_disk(settings.artifacts_dir, job_no, relpath)
        with self._db_write_lock, self._session_factory()() as session:
            job = session.get(BatchJob, job_id)
            if job is None:
                return
            now = utcnow()
            job.status = "CANCELLED"
            job.output_artifact_relpath = None
            job.output_size_bytes = None
            job.output_sha256 = None
            job.finished_at = job.finished_at or now
            job.update_time = now
            session.commit()

    def _finalize_failed(
        self,
        job_id: int,
        job_no: str,
        relpath: str,
        safe_error_summary: str,
        elapsed_ms: int,
    ) -> None:
        settings = self._settings()
        unlink_job_artifacts_on_disk(settings.artifacts_dir, job_no, relpath)
        with self._db_write_lock, self._session_factory()() as session:
            job = session.get(BatchJob, job_id)
            if job is None:
                return
            if job.status == "CANCELLED":
                return
            now = utcnow()
            job.status = "FAILED"
            job.output_artifact_relpath = None
            job.output_size_bytes = None
            job.output_sha256 = None
            job.elapsed_ms = elapsed_ms
            job.error_summary = safe_error_summary[:500]
            job.finished_at = now
            job.update_time = now
            session.commit()

    def _run_file_job(
        self, spec: FileJobTaskSpec, cancel_ev: threading.Event
    ) -> None:
        settings = self._settings()
        ext = OUTPUT_FORMAT_EXTENSIONS[spec.output_format]
        relpath = f"{spec.job_no}.{ext}"
        dest_final = settings.artifacts_dir / relpath
        t0 = time.perf_counter()

        try:
            if not self._mark_running_if_pending(spec.job_id, cancel_ev):
                return

            hook = self._execution_hook()
            if callable(hook):
                hook(spec.job_no, cancel_ev)

            summary = process_uploaded_file_and_unlink(
                src_tmp_path=spec.src_tmp_path,
                dest_final_path=dest_final,
                input_format=spec.input_format,
                output_format=spec.output_format,
                snapshot=spec.snapshot,
                engine=self._engine(),
                column_role_mapping=spec.column_role_mapping,
                should_cancel=cancel_ev.is_set,
            )
            elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
            self._finalize_completed(
                spec.job_id, spec.job_no, relpath, summary, elapsed_ms, cancel_ev
            )
        except JobCancelledError:
            self._finalize_cancelled(spec.job_id, spec.job_no, relpath)
        except FileParseError as exc:
            elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
            self._finalize_failed(
                spec.job_id, spec.job_no, relpath, str(exc), elapsed_ms
            )
        except DetectorNotReadyError:
            elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
            self._finalize_failed(
                spec.job_id,
                spec.job_no,
                relpath,
                "Local AstrLink Guard ONNX model is not ready",
                elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
            logger.error(
                "Batch file job failed job_no=%s err_type=%s",
                spec.job_no,
                exc.__class__.__name__,
            )
            self._finalize_failed(
                spec.job_id,
                spec.job_no,
                relpath,
                f"Batch file processing failed ({exc.__class__.__name__})",
                elapsed_ms,
            )
        finally:
            spec.src_tmp_path.unlink(missing_ok=True)
            with self._lock:
                self._futures.pop(spec.job_no, None)
                self._cancel_events.pop(spec.job_no, None)
                self._tmp_paths.pop(spec.job_no, None)

    def _run_mysql_job(
        self, spec: MysqlSampleTaskSpec, cancel_ev: threading.Event
    ) -> None:
        settings = self._settings()
        ext = OUTPUT_FORMAT_EXTENSIONS[spec.output_format]
        relpath = f"{spec.job_no}.{ext}"
        dest_final = settings.artifacts_dir / relpath
        t0 = time.perf_counter()
        plain_pwd = ""

        try:
            if not self._mark_running_if_pending(spec.job_id, cancel_ev):
                return

            hook = self._execution_hook()
            if callable(hook):
                hook(spec.job_no, cancel_ev)

            with self._db_write_lock, self._session_factory()() as session:
                ds = session.get(DatasourceConn, spec.datasource_id)
                if ds is None or ds.is_deleted != 0 or ds.status != "ACTIVE":
                    raise RuntimeError("Datasource is unavailable or disabled")
                db_host = ds.db_host
                db_port = ds.db_port
                db_user = ds.db_user
                db_name = ds.db_name
                cipher = ds.password_cipher

            plain_pwd = decrypt_secret(cipher, settings.master_aes_key_bytes)
            row_iter = stream_readonly_mysql_rows(
                host=db_host,
                port=db_port,
                user=db_user,
                password=plain_pwd,
                database=db_name,
                sql=spec.sql,
                params=spec.params,
                select_columns=spec.select_columns,
                connector_factory=self._mysql_connector_factory(),
            )
            plain_pwd = ""

            records_with_order = (
                (row, list(spec.select_columns)) for row in row_iter
            )
            summary = process_record_stream_to_artifact(
                records=records_with_order,
                dest_final_path=dest_final,
                output_format=spec.output_format,
                snapshot=spec.snapshot,
                engine=self._engine(),
                column_role_mapping=spec.column_role_mapping,
                preserve_sql_types=True,
                should_cancel=cancel_ev.is_set,
            )
            elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
            self._finalize_completed(
                spec.job_id, spec.job_no, relpath, summary, elapsed_ms, cancel_ev
            )
        except JobCancelledError:
            self._finalize_cancelled(spec.job_id, spec.job_no, relpath)
        except DetectorNotReadyError:
            elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
            self._finalize_failed(
                spec.job_id,
                spec.job_no,
                relpath,
                "Local AstrLink Guard ONNX model is not ready",
                elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
            logger.error(
                "Batch MySQL sample job failed job_no=%s err_type=%s",
                spec.job_no,
                exc.__class__.__name__,
            )
            self._finalize_failed(
                spec.job_id,
                spec.job_no,
                relpath,
                f"Read-only MySQL sampling failed ({exc.__class__.__name__})",
                elapsed_ms,
            )
        finally:
            plain_pwd = ""
            with self._lock:
                self._futures.pop(spec.job_no, None)
                self._cancel_events.pop(spec.job_no, None)

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True
            for ev in self._cancel_events.values():
                ev.set()
        self._executor.shutdown(wait=True, cancel_futures=True)
        with self._lock:
            remaining_tmps = list(self._tmp_paths.values())
            self._tmp_paths.clear()
            self._futures.clear()
            self._cancel_events.clear()
        for p in remaining_tmps:
            p.unlink(missing_ok=True)


def ensure_static_pool_thread_safe(app: FastAPI) -> None:
    """Serialize StaticPool single-connection checkouts across threads (reentrant & nested-safe per thread)."""
    db_engine = getattr(app.state, "db_engine", None)
    pool = getattr(db_engine, "pool", None)
    if not isinstance(pool, StaticPool) or getattr(pool, "_ds_serialized", False):
        return

    cond = threading.Condition()
    state: dict[str, int | None] = {"owner": None, "count": 0}
    orig_connect = pool.connect

    def _acquire() -> None:
        tid = threading.get_ident()
        with cond:
            while (state["count"] or 0) > 0 and state["owner"] != tid:
                cond.wait()
            state["owner"] = tid
            state["count"] = (state["count"] or 0) + 1

    def _release_once(flag: list[bool]) -> None:
        with cond:
            if flag[0]:
                return
            flag[0] = True
            rem = max(0, (state["count"] or 0) - 1)
            state["count"] = rem
            if rem == 0:
                state["owner"] = None
                cond.notify_all()

    def _locked_connect() -> Any:
        _acquire()
        flag = [False]
        try:
            fairy = orig_connect()
        except BaseException:
            _release_once(flag)
            raise

        orig_checkin = fairy._checkin
        fin = weakref.finalize(fairy, _release_once, flag)

        def _wrapped_checkin(transaction_was_reset: bool = False) -> None:
            try:
                orig_checkin(transaction_was_reset=transaction_was_reset)
            finally:
                fin.detach()
                _release_once(flag)

        fairy._checkin = _wrapped_checkin  # type: ignore[method-assign]
        return fairy

    pool.connect = _locked_connect  # type: ignore[method-assign]
    setattr(pool, "_ds_serialized", True)


def get_or_create_job_runner(app: FastAPI) -> JobRunner:
    ensure_static_pool_thread_safe(app)
    runner: JobRunner | None = getattr(app.state, "job_runner", None)
    if runner is None:
        settings: Settings = getattr(app.state, "settings", None) or get_settings()
        is_sqlite_mem = settings.database_url in ("sqlite://", "sqlite:///") or ":memory:" in settings.database_url
        workers = 1 if is_sqlite_mem else 2
        runner = JobRunner(app=app, max_workers=workers)
        app.state.job_runner = runner
    return runner


async def shutdown_job_runner(app: FastAPI) -> None:
    runner: JobRunner | None = getattr(app.state, "job_runner", None)
    if runner is not None:
        await asyncio.to_thread(runner.shutdown)
        app.state.job_runner = None
