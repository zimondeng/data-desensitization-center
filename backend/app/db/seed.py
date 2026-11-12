from __future__ import annotations

from copy import deepcopy
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import Settings, get_settings
from app.db.base import new_uuid
from app.db.models import AdminUser, AllowlistDict, PolicyProfile

DEFAULT_ALLOWLIST_SEED_ITEMS: tuple[dict[str, Any], ...] = (
    {
        "group_code": "gov_public_hotline",
        "item_name": "全国政务与公共服务5位短号",
        "match_mode": "REGEX",
        "pattern_text": r"^(12345|12333|12329|12366|12315|12348|12123|110|119|120|122)$",
        "apply_labels_json": ["phone"],
        "remark": "保留政务服务便民热线及应急短号",
        "created_by": "system",
    },
    {
        "group_code": "gov_public_hotline",
        "item_name": "400/800公共服务热线与带区号政务固话",
        "match_mode": "REGEX",
        "pattern_text": r"^(0\d{2,3}-?\d{7,8}|[48]00-?\d{3}-?\d{4})$",
        "apply_labels_json": ["phone"],
        "remark": "保留带区号公开办公固话，11位个人手机仍由cn_mobile严格拦截",
        "created_by": "system",
    },
    {
        "group_code": "gov_public_domain",
        "item_name": "中国政府网及各级政务域名",
        "match_mode": "REGEX",
        "pattern_text": r"^https?://([a-zA-Z0-9-]+\.)*gov\.cn(/.*)?$",
        "apply_labels_json": ["url"],
        "remark": "保留各级政府门户与在线办事大厅链接",
        "created_by": "system",
    },
    {
        "group_code": "gov_public_hall",
        "item_name": "政务服务中心与便民中心通用办公地址特征",
        "match_mode": "REGEX",
        "pattern_text": r"(政务服务中心|行政审批局|市民中心|便民服务中心|公积金管理中心|社保中心|车管所|不动产登记交易中心)",
        "apply_labels_json": ["private_address"],
        "remark": "保留公开办事窗口与大厅地址不被误标为私人住址",
        "created_by": "system",
    },
)

STRICT_GENERAL_ENTITY_RULES: dict[str, dict[str, Any]] = {
    "private_person": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "PERSON"},
    "phone": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "PHONE"},
    "email": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "EMAIL"},
    "private_address": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "ADDR"},
    "private_date": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "DATE"},
    "account": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "ACCOUNT"},
    "payment_card": {"enabled": True, "min_score": 0.80, "action": "PARTIAL", "keep_head": 4, "keep_tail": 4},
    "ip_address": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "IP"},
    "url": {"enabled": True, "min_score": 0.82, "action": "PLACEHOLDER", "prefix": "URL"},
    "common_secret": {"enabled": True, "min_score": 0.80, "action": "FIXED", "replacement": "[REDACTED_SECRET]"},
    "cn_id_card": {"enabled": True, "min_score": 1.00, "action": "PLACEHOLDER", "prefix": "IDCARD"},
    "cn_uscc": {"enabled": True, "min_score": 1.00, "action": "PLACEHOLDER", "prefix": "USCC"},
    "cn_mobile": {"enabled": True, "min_score": 1.00, "action": "PLACEHOLDER", "prefix": "PHONE"},
    "bank_card_luhn": {"enabled": True, "min_score": 1.00, "action": "PARTIAL", "keep_head": 4, "keep_tail": 4},
}

GOV_EVAL_CORPUS_ENTITY_RULES: dict[str, dict[str, Any]] = {
    "private_person": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "PERSON"},
    "phone": {"enabled": True, "min_score": 0.82, "action": "PLACEHOLDER", "prefix": "PHONE"},
    "email": {"enabled": True, "min_score": 0.80, "action": "PLACEHOLDER", "prefix": "EMAIL"},
    "private_address": {"enabled": True, "min_score": 0.82, "action": "PLACEHOLDER", "prefix": "ADDR"},
    "private_date": {"enabled": True, "min_score": 0.82, "action": "PLACEHOLDER", "prefix": "DATE"},
    "account": {"enabled": True, "min_score": 0.82, "action": "PLACEHOLDER", "prefix": "ACCOUNT"},
    "payment_card": {"enabled": True, "min_score": 0.80, "action": "PARTIAL", "keep_head": 4, "keep_tail": 4},
    "ip_address": {"enabled": False, "min_score": 0.85, "action": "PLACEHOLDER", "prefix": "IP"},
    "url": {"enabled": False, "min_score": 0.85, "action": "PLACEHOLDER", "prefix": "URL"},
    "common_secret": {"enabled": True, "min_score": 0.80, "action": "FIXED", "replacement": "[REDACTED_SECRET]"},
    "cn_id_card": {"enabled": True, "min_score": 1.00, "action": "PLACEHOLDER", "prefix": "IDCARD"},
    "cn_uscc": {"enabled": True, "min_score": 1.00, "action": "PLACEHOLDER", "prefix": "USCC"},
    "cn_mobile": {"enabled": True, "min_score": 1.00, "action": "PLACEHOLDER", "prefix": "PHONE"},
    "bank_card_luhn": {"enabled": True, "min_score": 1.00, "action": "PARTIAL", "keep_head": 4, "keep_tail": 4},
}

GOV_EVAL_CORPUS_FIELD_ROLE_RULES: dict[str, Any] = {
    "default_role": "FULL_MASK_WRITE_SCOPE",
    "high_risk_only_labels": [
        "cn_id_card",
        "cn_mobile",
        "bank_card_luhn",
        "payment_card",
        "common_secret",
    ],
    "rules": [
        {"jsonpath": "$.input_text", "role": "FULL_MASK_WRITE_SCOPE"},
        {"jsonpath": "$.turns[?(@.role=='user')].content", "role": "FULL_MASK_WRITE_SCOPE"},
        {"jsonpath": "$.expected_output", "role": "REPLAY_SCOPE_AND_HIGH_RISK"},
        {"jsonpath": "$.actual_output", "role": "REPLAY_SCOPE_AND_HIGH_RISK"},
        {"jsonpath": "$.turns[?(@.role=='assistant')].content", "role": "REPLAY_SCOPE_AND_HIGH_RISK"},
        {"jsonpath": "$.references[*].content", "role": "REPLAY_SCOPE_AND_HIGH_RISK"},
        {"jsonpath": "$.case_code", "role": "PASSTHROUGH"},
        {"jsonpath": "$.turn_mode", "role": "PASSTHROUGH"},
    ],
}

DEFAULT_POLICY_SEEDS: tuple[dict[str, Any], ...] = (
    {
        "policy_code": "strict_general",
        "version": 1,
        "policy_name": "通用全量严格脱敏策略 v1",
        "scope_mode": "RECORD",
        "onnx_variant": "int8",
        "entity_rules_json": STRICT_GENERAL_ENTITY_RULES,
        "field_role_rules_json": {"default_role": "FULL_MASK_WRITE_SCOPE", "rules": []},
        "allowlist_groups_json": [],
        "is_default": 1,
        "status": "ACTIVE",
        "description": "适用于普通日志导出、外部文本清洗与微调语料预处理，全标签严格遮蔽",
        "created_by": "system",
    },
    {
        "policy_code": "gov_eval_corpus",
        "version": 1,
        "policy_name": "政务问答与评测语料差异化脱敏策略 v1",
        "scope_mode": "CONVERSATION",
        "onnx_variant": "int8",
        "entity_rules_json": GOV_EVAL_CORPUS_ENTITY_RULES,
        "field_role_rules_json": GOV_EVAL_CORPUS_FIELD_ROLE_RULES,
        "allowlist_groups_json": [
            "gov_public_hotline",
            "gov_public_domain",
            "gov_public_hall",
        ],
        "is_default": 1,
        "status": "ACTIVE",
        "description": (
            "专为政务客服会话与知识库评测入库设计：用户侧全脱敏并建立临时指代映射，"
            "回答与引用侧重放映射并保留政务热线、公开大厅地址及.gov.cn链接"
        ),
        "created_by": "system",
    },
)


def seed_defaults(session: Session, settings: Settings | None = None) -> None:
    cfg = settings or get_settings()

    existing_admin = session.scalar(
        select(AdminUser).where(AdminUser.username == cfg.default_admin_username)
    )
    if existing_admin is None:
        session.add(
            AdminUser(
                uuid=new_uuid(),
                username=cfg.default_admin_username,
                display_name=cfg.default_admin_display_name,
                password_hash=hash_password(
                    cfg.default_admin_password,
                    rounds=cfg.bcrypt_rounds,
                ),
                role="ADMIN",
                is_enabled=1,
                is_deleted=0,
            )
        )

    for item in DEFAULT_ALLOWLIST_SEED_ITEMS:
        exists = session.scalar(
            select(AllowlistDict).where(
                AllowlistDict.group_code == item["group_code"],
                AllowlistDict.item_name == item["item_name"],
            )
        )
        if exists is None:
            session.add(
                AllowlistDict(
                    uuid=new_uuid(),
                    group_code=item["group_code"],
                    item_name=item["item_name"],
                    match_mode=item["match_mode"],
                    pattern_text=item["pattern_text"],
                    apply_labels_json=list(item["apply_labels_json"]),
                    is_enabled=1,
                    remark=item["remark"],
                    created_by=item["created_by"],
                    is_deleted=0,
                )
            )

    for pol in DEFAULT_POLICY_SEEDS:
        exists = session.scalar(
            select(PolicyProfile).where(
                PolicyProfile.policy_code == pol["policy_code"],
                PolicyProfile.version == pol["version"],
            )
        )
        if exists is None:
            session.add(
                PolicyProfile(
                    uuid=new_uuid(),
                    policy_code=pol["policy_code"],
                    version=pol["version"],
                    policy_name=pol["policy_name"],
                    scope_mode=pol["scope_mode"],
                    onnx_variant=pol["onnx_variant"],
                    entity_rules_json=deepcopy(pol["entity_rules_json"]),
                    field_role_rules_json=deepcopy(pol["field_role_rules_json"]),
                    allowlist_groups_json=list(pol["allowlist_groups_json"]),
                    is_default=pol["is_default"],
                    status=pol["status"],
                    description=pol["description"],
                    created_by=pol["created_by"],
                    is_deleted=0,
                )
            )

    session.commit()
