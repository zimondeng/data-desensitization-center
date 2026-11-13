from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_request_settings
from app.db.base import utcnow
from app.db.models import ApiUsageHourly
from app.detectors import ALL_ENTITY_LABELS, HybridDetectorPipeline
import app.detectors.pipeline as detector_pipeline_mod
from app.engine import PolicyEngineService
import app.engine.service as engine_service_mod

CANONICAL_ENTITY_METADATA: tuple[tuple[str, str, str], ...] = (
    ("private_person", "个人姓名", "onnx"),
    ("cn_id_card", "二代居民身份证号", "regex"),
    ("cn_mobile", "中国大陆手机号", "regex"),
    ("phone", "电话/固话号码", "onnx"),
    ("bank_card_luhn", "银行卡号 (Luhn)", "regex"),
    ("payment_card", "支付卡号", "onnx"),
    ("private_address", "个人详细地址", "onnx"),
    ("email", "电子邮箱", "onnx"),
    ("account", "账号标识", "onnx"),
    ("common_secret", "敏感密钥与口令", "onnx"),
    ("cn_uscc", "统一社会信用代码", "regex"),
    ("private_date", "个人关联日期", "onnx"),
    ("ip_address", "IP 地址", "onnx"),
    ("url", "网址链接 (URL)", "onnx"),
)


def truncate_to_hour(dt: datetime | None = None) -> datetime:
    base = dt if dt is not None else utcnow()
    if base.tzinfo is not None:
        base = base.astimezone(timezone.utc).replace(tzinfo=None)
    return base.replace(minute=0, second=0, microsecond=0)


def _merge_hit_stats(
    existing: Mapping[str, int] | None,
    delta: Mapping[str, int] | None,
) -> dict[str, int]:
    merged: dict[str, int] = {}
    if existing:
        for k, v in existing.items():
            if k in ALL_ENTITY_LABELS and int(v) > 0:
                merged[k] = int(v)
    if delta:
        for k, v in delta.items():
            if k in ALL_ENTITY_LABELS and int(v) > 0:
                merged[k] = merged.get(k, 0) + int(v)
    return merged


def _apply_increment(
    row: ApiUsageHourly,
    *,
    request_count: int,
    item_count: int,
    total_chars: int,
    elapsed_ms: int,
    error_count: int,
    hit_counts: Mapping[str, int] | None,
    now: datetime,
) -> None:
    row.request_count = int(row.request_count or 0) + max(0, int(request_count))
    row.item_count = int(row.item_count or 0) + max(0, int(item_count))
    row.total_chars = int(row.total_chars or 0) + max(0, int(total_chars))
    row.total_elapsed_ms = int(row.total_elapsed_ms or 0) + max(0, int(elapsed_ms))
    row.error_count = int(row.error_count or 0) + max(0, int(error_count))
    row.entity_hit_stats_json = _merge_hit_stats(row.entity_hit_stats_json, hit_counts)
    row.update_time = now


def record_sync_api_usage(
    session: Session,
    *,
    api_key_id: int,
    policy_id: int,
    request_count: int = 1,
    item_count: int = 0,
    total_chars: int = 0,
    elapsed_ms: int = 0,
    error_count: int = 0,
    hit_counts: Mapping[str, int] | None = None,
    occurred_at: datetime | None = None,
) -> ApiUsageHourly:
    """Idempotently accumulate zero-plaintext sync API metrics into ds_api_usage_hourly."""
    now = occurred_at if occurred_at is not None else utcnow()
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc).replace(tzinfo=None)
    bucket = truncate_to_hour(now)

    stmt = select(ApiUsageHourly).where(
        ApiUsageHourly.hour_bucket == bucket,
        ApiUsageHourly.api_key_id == int(api_key_id),
        ApiUsageHourly.policy_id == int(policy_id),
    )
    row = session.scalar(stmt)
    if row is not None:
        _apply_increment(
            row,
            request_count=request_count,
            item_count=item_count,
            total_chars=total_chars,
            elapsed_ms=elapsed_ms,
            error_count=error_count,
            hit_counts=hit_counts,
            now=now,
        )
        session.commit()
        return row

    try:
        with session.begin_nested():
            created = ApiUsageHourly(
                hour_bucket=bucket,
                api_key_id=int(api_key_id),
                policy_id=int(policy_id),
                request_count=max(0, int(request_count)),
                item_count=max(0, int(item_count)),
                total_chars=max(0, int(total_chars)),
                total_elapsed_ms=max(0, int(elapsed_ms)),
                error_count=max(0, int(error_count)),
                entity_hit_stats_json=_merge_hit_stats(None, hit_counts),
                create_time=now,
                update_time=now,
            )
            session.add(created)
            session.flush()
        session.commit()
        return created
    except IntegrityError:
        row = session.scalar(stmt)
        if row is None:
            raise
        _apply_increment(
            row,
            request_count=request_count,
            item_count=item_count,
            total_chars=total_chars,
            elapsed_ms=elapsed_ms,
            error_count=error_count,
            hit_counts=hit_counts,
            now=now,
        )
        session.commit()
        return row


def resolve_request_engine(request: Request) -> PolicyEngineService:
    """Resolve PolicyEngineService honoring app.state overrides, test fixtures, and settings.models_dir."""
    req_settings = get_request_settings(request)

    state_engine = getattr(request.app.state, "policy_engine", None)
    if isinstance(state_engine, PolicyEngineService):
        return state_engine

    state_pipeline = getattr(request.app.state, "detector_pipeline", None)
    if state_pipeline is not None:
        return PolicyEngineService(
            pipeline=state_pipeline,
            hash_salt=req_settings.hash_mask_salt,
        )

    global_pipe = detector_pipeline_mod._default_pipeline
    if global_pipe is not None and not getattr(global_pipe, "_owns_onnx", True):
        return PolicyEngineService(
            pipeline=global_pipe,
            hash_salt=req_settings.hash_mask_salt,
        )

    global_eng = engine_service_mod._default_engine_service
    if global_eng is not None and getattr(global_eng, "_pipeline", None) is not None:
        return global_eng

    cache_key = (
        str(req_settings.models_dir),
        int(req_settings.onnx_pool_workers),
        req_settings.hash_mask_salt,
    )
    cached_pair = getattr(request.app.state, "_scoped_policy_engine_pair", None)
    if isinstance(cached_pair, tuple) and len(cached_pair) == 2 and cached_pair[0] == cache_key:
        return cached_pair[1]

    scoped_pipeline = HybridDetectorPipeline(
        models_dir=req_settings.models_dir,
        max_workers=req_settings.onnx_pool_workers,
    )
    scoped_engine = PolicyEngineService(
        pipeline=scoped_pipeline,
        hash_salt=req_settings.hash_mask_salt,
    )
    request.app.state._scoped_policy_engine_pair = (cache_key, scoped_engine)
    return scoped_engine
