from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, BigIntFK, BigIntPK, new_uuid, utcnow


class AdminUser(Base):
    __tablename__ = "ds_admin_user"
    __table_args__ = (
        UniqueConstraint("uuid", name="uk_ds_user_uuid"),
        UniqueConstraint("username", name="uk_ds_username"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(32), nullable=False, default=new_uuid)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ADMIN", server_default="ADMIN"
    )
    is_enabled: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_deleted: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    create_time: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    update_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )


class ApiKey(Base):
    __tablename__ = "ds_api_key"
    __table_args__ = (
        UniqueConstraint("uuid", name="uk_ds_apikey_uuid"),
        UniqueConstraint("key_sha256", name="uk_ds_apikey_sha256"),
        Index("idx_ds_apikey_status", "status", "is_deleted"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(32), nullable=False, default=new_uuid)
    key_name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    key_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    default_policy_code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="strict_general",
        server_default="strict_general",
    )
    rate_limit_rpm: Mapped[int] = mapped_column(
        Integer, nullable=False, default=600, server_default="600"
    )
    allowed_ips_json: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="ACTIVE", server_default="ACTIVE"
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_deleted: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    create_time: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    update_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )


class AllowlistDict(Base):
    __tablename__ = "ds_allowlist_dict"
    __table_args__ = (
        UniqueConstraint("uuid", name="uk_ds_allowlist_uuid"),
        Index("idx_ds_allowlist_group", "group_code", "is_enabled", "is_deleted"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(32), nullable=False, default=new_uuid)
    group_code: Mapped[str] = mapped_column(String(64), nullable=False)
    item_name: Mapped[str] = mapped_column(String(128), nullable=False)
    match_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="EXACT", server_default="EXACT"
    )
    pattern_text: Mapped[str] = mapped_column(String(500), nullable=False)
    apply_labels_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    is_enabled: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    remark: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_deleted: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    create_time: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    update_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )


class PolicyProfile(Base):
    __tablename__ = "ds_policy_profile"
    __table_args__ = (
        UniqueConstraint("uuid", name="uk_ds_policy_uuid"),
        UniqueConstraint("policy_code", "version", name="uk_ds_policy_code_ver"),
        Index("idx_ds_policy_active", "policy_code", "is_default", "status", "is_deleted"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(32), nullable=False, default=new_uuid)
    policy_code: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    policy_name: Mapped[str] = mapped_column(String(128), nullable=False)
    scope_mode: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default="CONVERSATION",
        server_default="CONVERSATION",
    )
    onnx_variant: Mapped[str] = mapped_column(
        String(16), nullable=False, default="int8", server_default="int8"
    )
    entity_rules_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    field_role_rules_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    allowlist_groups_json: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    is_default: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="ACTIVE", server_default="ACTIVE"
    )
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_deleted: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    create_time: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    update_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )


class DatasourceConn(Base):
    __tablename__ = "ds_datasource_conn"
    __table_args__ = (
        UniqueConstraint("uuid", name="uk_ds_conn_uuid"),
        UniqueConstraint("conn_code", name="uk_ds_conn_code"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(32), nullable=False, default=new_uuid)
    conn_code: Mapped[str] = mapped_column(String(64), nullable=False)
    conn_name: Mapped[str] = mapped_column(String(128), nullable=False)
    db_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default="MYSQL", server_default="MYSQL"
    )
    db_host: Mapped[str] = mapped_column(String(128), nullable=False)
    db_port: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3306, server_default="3306"
    )
    db_name: Mapped[str] = mapped_column(String(64), nullable=False)
    db_user: Mapped[str] = mapped_column(String(64), nullable=False)
    password_cipher: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_tables_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="ACTIVE", server_default="ACTIVE"
    )
    last_test_ok: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_deleted: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    create_time: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    update_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )


class BatchJob(Base):
    __tablename__ = "ds_batch_job"
    __table_args__ = (
        UniqueConstraint("uuid", name="uk_ds_job_uuid"),
        UniqueConstraint("job_no", name="uk_ds_job_no"),
        Index("idx_ds_job_status_time", "status", "create_time"),
        Index("idx_ds_job_expires", "status", "expires_at"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(32), nullable=False, default=new_uuid)
    job_no: Mapped[str] = mapped_column(String(64), nullable=False)
    job_name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(24), nullable=False)
    input_format: Mapped[str] = mapped_column(String(16), nullable=False)
    source_filename_masked: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    datasource_id: Mapped[int | None] = mapped_column(BigIntFK, nullable=True)
    sampling_config_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    policy_id: Mapped[int] = mapped_column(BigIntFK, nullable=False)
    policy_code_snapshot: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version_snapshot: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PENDING", server_default="PENDING"
    )
    total_records: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    processed_records: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    failed_records: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    total_chars: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    entity_hit_stats_json: Mapped[dict[str, int] | None] = mapped_column(
        JSON, nullable=True
    )
    output_format: Mapped[str] = mapped_column(
        String(16), nullable=False, default="JSONL", server_default="JSONL"
    )
    output_artifact_relpath: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    output_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    spot_check_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="UNCHECKED", server_default="UNCHECKED"
    )
    spot_checked_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    spot_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    spot_check_note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    elapsed_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    triggered_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_deleted: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    create_time: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    update_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )


class ApiUsageHourly(Base):
    __tablename__ = "ds_api_usage_hourly"
    __table_args__ = (
        UniqueConstraint(
            "hour_bucket",
            "api_key_id",
            "policy_id",
            name="uk_ds_usage_bucket_key_pol",
        ),
        Index("idx_ds_usage_bucket", "hour_bucket"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    hour_bucket: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    api_key_id: Mapped[int] = mapped_column(
        BigIntFK, nullable=False, default=0, server_default="0"
    )
    policy_id: Mapped[int] = mapped_column(BigIntFK, nullable=False)
    request_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    item_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    total_chars: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    total_elapsed_ms: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    error_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    entity_hit_stats_json: Mapped[dict[str, int] | None] = mapped_column(
        JSON, nullable=True
    )
    create_time: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow, server_default=func.now()
    )
    update_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
        server_default=func.now(),
    )
