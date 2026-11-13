from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import require_roles
from app.common.envelope import format_utc_ms, normalize_utc_naive, ok_response
from app.db.base import utcnow
from app.db.models import AdminUser, ApiUsageHourly, BatchJob
from app.db.session import get_session
from app.telemetry import CANONICAL_ENTITY_METADATA, truncate_to_hour

router = APIRouter(prefix="/api/admin/metrics", tags=["admin-metrics"])


def _fmt_hour_bucket(dt: datetime) -> str:
    return (
        normalize_utc_naive(dt)
        .replace(minute=0, second=0, microsecond=0)
        .isoformat(timespec="seconds")
        + "Z"
    )


@router.get("/hourly")
def get_hourly_metrics(
    request: Request,
    hours: int = Query(default=24, ge=1, le=720),
    include_sandbox: bool = Query(default=False),
    api_key_id: int | None = Query(default=None, ge=0),
    policy_id: int | None = Query(default=None, ge=1),
    session: Session = Depends(get_session),
    _admin: AdminUser = Depends(require_roles("ADMIN", "OPERATOR", "AUDITOR")),
) -> dict[str, Any]:
    now = utcnow()
    current_hour = truncate_to_hour(now)
    window_start = current_hour - timedelta(hours=hours - 1)

    stmt = select(ApiUsageHourly).where(ApiUsageHourly.hour_bucket >= window_start)
    if not include_sandbox:
        stmt = stmt.where(ApiUsageHourly.api_key_id != 0)
    if api_key_id is not None:
        stmt = stmt.where(ApiUsageHourly.api_key_id == api_key_id)
    if policy_id is not None:
        stmt = stmt.where(ApiUsageHourly.policy_id == policy_id)

    rows = session.scalars(
        stmt.order_by(ApiUsageHourly.hour_bucket.asc(), ApiUsageHourly.id.asc())
    ).all()

    total_requests = 0
    total_items = 0
    total_chars = 0
    total_elapsed_ms = 0
    error_count = 0

    bucket_map: dict[datetime, dict[str, int]] = {}
    entity_totals: dict[str, int] = {
        label: 0 for label, _zh, _det in CANONICAL_ENTITY_METADATA
    }

    for row in rows:
        req_c = int(row.request_count or 0)
        item_c = int(row.item_count or 0)
        char_c = int(row.total_chars or 0)
        elap_ms = int(row.total_elapsed_ms or 0)
        err_c = int(row.error_count or 0)

        total_requests += req_c
        total_items += item_c
        total_chars += char_c
        total_elapsed_ms += elap_ms
        error_count += err_c

        b_key = truncate_to_hour(row.hour_bucket)
        b_acc = bucket_map.get(b_key)
        if b_acc is None:
            b_acc = {
                "request_count": 0,
                "item_count": 0,
                "total_chars": 0,
                "total_elapsed_ms": 0,
                "error_count": 0,
            }
            bucket_map[b_key] = b_acc
        b_acc["request_count"] += req_c
        b_acc["item_count"] += item_c
        b_acc["total_chars"] += char_c
        b_acc["total_elapsed_ms"] += elap_ms
        b_acc["error_count"] += err_c

        if isinstance(row.entity_hit_stats_json, dict):
            for lbl, cnt in row.entity_hit_stats_json.items():
                if lbl in entity_totals and int(cnt) > 0:
                    entity_totals[lbl] += int(cnt)

    avg_elapsed_ms = (
        round(total_elapsed_ms / total_requests, 2) if total_requests > 0 else 0.0
    )

    buckets_out: list[dict[str, Any]] = []
    for b_dt in sorted(bucket_map.keys()):
        acc = bucket_map[b_dt]
        b_req = acc["request_count"]
        b_avg = round(acc["total_elapsed_ms"] / b_req, 2) if b_req > 0 else 0.0
        buckets_out.append(
            {
                "hour_bucket": _fmt_hour_bucket(b_dt),
                "request_count": b_req,
                "item_count": acc["item_count"],
                "total_chars": acc["total_chars"],
                "total_elapsed_ms": acc["total_elapsed_ms"],
                "avg_elapsed_ms": b_avg,
                "error_count": acc["error_count"],
            }
        )

    total_entity_hits = sum(entity_totals.values())
    indexed_entities = [
        (idx, label, label_zh, detector, entity_totals[label])
        for idx, (label, label_zh, detector) in enumerate(CANONICAL_ENTITY_METADATA)
    ]
    indexed_entities.sort(key=lambda item: (-item[4], item[0]))

    entity_distribution: list[dict[str, Any]] = [
        {
            "label": label,
            "label_zh": label_zh,
            "display_name": f"{label_zh} ({label})",
            "detector": detector,
            "count": cnt,
            "ratio": round(cnt / total_entity_hits, 4) if total_entity_hits > 0 else 0.0,
            "percentage": (
                round(cnt * 100.0 / total_entity_hits, 2)
                if total_entity_hits > 0
                else 0.0
            ),
        }
        for _idx, label, label_zh, detector, cnt in indexed_entities
    ]

    job_rows = session.scalars(
        select(BatchJob).where(
            BatchJob.is_deleted == 0,
            BatchJob.create_time >= window_start,
        )
    ).all()
    batch_jobs_summary = {
        "total_jobs": len(job_rows),
        "completed_jobs": sum(1 for j in job_rows if j.status == "COMPLETED"),
        "processed_records": sum(int(j.processed_records or 0) for j in job_rows),
        "total_chars": sum(int(j.total_chars or 0) for j in job_rows),
    }

    summary = {
        "total_requests": total_requests,
        "total_items": total_items,
        "total_chars": total_chars,
        "total_elapsed_ms": total_elapsed_ms,
        "avg_elapsed_ms": avg_elapsed_ms,
        "error_count": error_count,
    }

    return ok_response(
        {
            "hours": hours,
            "include_sandbox": include_sandbox,
            "window_start": _fmt_hour_bucket(window_start),
            "updated_at": format_utc_ms(now),
            "total_requests": total_requests,
            "total_items": total_items,
            "total_chars": total_chars,
            "total_elapsed_ms": total_elapsed_ms,
            "avg_elapsed_ms": avg_elapsed_ms,
            "error_count": error_count,
            "total_entity_hits": total_entity_hits,
            "summary": summary,
            "buckets": buckets_out,
            "entity_distribution": entity_distribution,
            "batch_jobs_summary": batch_jobs_summary,
        },
        request=request,
    )
