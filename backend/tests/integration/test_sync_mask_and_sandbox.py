from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
import numpy as np
import pytest

from app.auth.security import hash_password
from app.db.base import new_uuid
from app.db.models import AdminUser
from app.detectors import (
    DEFAULT_ID2LABEL,
    HybridDetectorPipeline,
    OnnxNerDetector,
    set_default_pipeline,
)


def _build_fake_onnx_pipeline() -> HybridDetectorPipeline:
    """Deterministic fake ONNX pipeline at the InferenceSession/Tokenizer boundary."""
    label2id = {lbl: idx for idx, lbl in DEFAULT_ID2LABEL.items()}
    mentions: list[tuple[str, str, float]] = [
        ("张三", "private_person", 0.96),
        ("李四", "private_person", 0.95),
        ("王五", "private_person", 0.94),
        ("12345", "phone", 0.91),
        ("12329", "phone", 0.91),
        ("0519-85681234", "phone", 0.94),
        ("0519-69661800", "phone", 0.93),
        ("0519-12329", "phone", 0.92),
        ("常州市政务服务中心（锦绣路2号）", "private_address", 0.93),
        ("天宁区政务服务中心", "private_address", 0.92),
        ("钟楼区星港花园12栋301室", "private_address", 0.95),
        ("https://www.changzhou.gov.cn", "url", 0.95),
        ("https://gjj.changzhou.gov.cn", "url", 0.95),
        ("sk-prod-9988776655443322", "common_secret", 0.97),
    ]
    state = {"text": ""}

    class _FakeTokenizer:
        def encode(self, text: str):
            state["text"] = text

            class _Enc:
                ids = [0, *[100 + i for i in range(len(text))], 2]
                offsets = [(0, 0), *[(i, i + 1) for i in range(len(text))], (0, 0)]

            return _Enc()

    class _FakeSession:
        def run(self, output_names, input_feed):
            ids = input_feed["input_ids"]
            logits = np.zeros((1, ids.shape[1], 21), dtype=np.float32)
            tag_at: dict[int, tuple[str, float]] = {}
            txt = state["text"]
            for substr, lbl, prob in sorted(mentions, key=lambda m: -len(m[0])):
                pos_cursor = 0
                while True:
                    idx = txt.find(substr, pos_cursor)
                    if idx < 0:
                        break
                    if any((idx + k) in tag_at for k in range(len(substr))):
                        pos_cursor = idx + 1
                        continue
                    for k in range(len(substr)):
                        tag_at[idx + k] = (f"B-{lbl}" if k == 0 else f"I-{lbl}", prob)
                    pos_cursor = idx + len(substr)
            for pos in range(ids.shape[1]):
                c_idx = int(ids[0, pos]) - 100
                if c_idx in tag_at:
                    bio, prob = tag_at[c_idx]
                    logits[0, pos, label2id[bio]] = float(
                        np.log(prob * 20.0 / (1.0 - prob))
                    )
                else:
                    logits[0, pos, label2id["O"]] = 12.0
            return [logits]

    return HybridDetectorPipeline(
        onnx_detector=OnnxNerDetector(session=_FakeSession(), tokenizer=_FakeTokenizer())
    )


@pytest.fixture
def fake_onnx_pipeline():
    pipeline = _build_fake_onnx_pipeline()
    set_default_pipeline(pipeline)
    try:
        yield pipeline
    finally:
        set_default_pipeline(None)
        pipeline.shutdown()


def _login_admin_roles(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
) -> dict[str, str]:
    with app.state.session_factory() as session:
        session.add_all(
            [
                AdminUser(
                    uuid=new_uuid(),
                    username="sync_operator",
                    display_name="运营人员",
                    password_hash=hash_password(
                        "OpPass@123", rounds=test_settings.bcrypt_rounds
                    ),
                    role="OPERATOR",
                    is_enabled=1,
                    is_deleted=0,
                ),
                AdminUser(
                    uuid=new_uuid(),
                    username="sync_auditor",
                    display_name="审核人员",
                    password_hash=hash_password(
                        "AuditPass@123", rounds=test_settings.bcrypt_rounds
                    ),
                    role="AUDITOR",
                    is_enabled=1,
                    is_deleted=0,
                ),
            ]
        )
        session.commit()

    def _login(username: str, password: str) -> str:
        res = client.post(
            "/api/admin/auth/login",
            json={"username": username, "password": password},
        )
        assert res.status_code == 200
        return res.json()["data"]["access_token"]

    return {
        "ADMIN": _login(
            test_settings.default_admin_username,
            test_settings.default_admin_password,
        ),
        "OPERATOR": _login("sync_operator", "OpPass@123"),
        "AUDITOR": _login("sync_auditor", "AuditPass@123"),
    }


def _issue_api_key(
    client: TestClient,
    admin_jwt: str,
    *,
    key_name: str = "eval-center-sync",
    default_policy_code: str = "gov_eval_corpus",
) -> dict[str, Any]:
    resp = client.post(
        "/api/admin/api-keys",
        headers={"Authorization": f"Bearer {admin_jwt}"},
        json={
            "key_name": key_name,
            "default_policy_code": default_policy_code,
            "rate_limit_rpm": 600,
        },
    )
    assert resp.status_code == 200
    return resp.json()["data"]


def test_sync_mask_text_auth_default_policy_return_spans_and_not_found(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
    fake_onnx_pipeline: HybridDetectorPipeline,
) -> None:
    tokens = _login_admin_roles(client, app, test_settings)
    key_info = _issue_api_key(
        client,
        tokens["ADMIN"],
        default_policy_code="gov_eval_corpus",
    )
    plain_key = key_info["plain_key"]

    # 1. Missing API key or Console JWT on /api/v1/mask/text -> 401 / 40101
    for bad_headers in (
        {},
        {"Authorization": f"Bearer {tokens['ADMIN']}"},
        {"X-API-Key": "dsk_live_invalid_nonexistent_token"},
    ):
        unauth = client.post(
            "/api/v1/mask/text",
            headers=bad_headers,
            json={"text": "我是张三"},
        )
        assert unauth.status_code == 401
        assert unauth.json()["code"] == 40101
        assert "张三" not in unauth.text

    # 2. Omitted policy_code falls back to api_key.default_policy_code ("gov_eval_corpus"),
    #    policy_version=None resolves active default version (v1), return_spans=False omits spans
    raw_text = (
        "我是张三，身份证 32040219900307118X，手机号 13812345678，"
        "请问天宁区政务服务中心电话是 0519-69661800 吗？"
    )
    res_default = client.post(
        "/api/v1/mask/text",
        headers={"X-API-Key": plain_key},
        json={"text": raw_text},
    )
    assert res_default.status_code == 200
    body_default = res_default.json()
    assert body_default["code"] == 200
    data_default = body_default["data"]
    assert data_default["masked_text"] == (
        "我是<PERSON_1>，身份证 <IDCARD_1>，手机号 <PHONE_1>，"
        "请问天宁区政务服务中心电话是 0519-69661800 吗？"
    )
    assert data_default["policy_code"] == "gov_eval_corpus"
    assert data_default["policy_version"] == 1
    assert data_default["hit_counts"] == {
        "private_person": 1,
        "cn_id_card": 1,
        "cn_mobile": 1,
    }
    assert isinstance(data_default["elapsed_ms"], int)
    assert data_default["elapsed_ms"] >= 0
    assert "spans" not in data_default

    # 3. Authorization: Bearer dsk_* + return_spans=True returns ONLY post-mask placeholder coordinates,
    #    and raw PII never appears anywhere in the serialized response
    res_spans = client.post(
        "/api/v1/mask/text",
        headers={"Authorization": f"Bearer {plain_key}"},
        json={
            "text": raw_text,
            "policy_code": "gov_eval_corpus",
            "policy_version": None,
            "return_spans": True,
        },
    )
    assert res_spans.status_code == 200
    raw_http_body = res_spans.text
    for secret in ("张三", "32040219900307118X", "13812345678"):
        assert secret not in raw_http_body

    data_spans = res_spans.json()["data"]
    masked_out = data_spans["masked_text"]
    spans = data_spans["spans"]
    assert len(spans) == 3
    assert [s["placeholder"] for s in spans] == ["<PERSON_1>", "<IDCARD_1>", "<PHONE_1>"]
    assert [s["label"] for s in spans] == ["private_person", "cn_id_card", "cn_mobile"]
    for sp in spans:
        assert masked_out[sp["start"] : sp["end"]] == sp["placeholder"]
        assert set(sp.keys()).isdisjoint({"text", "raw_text", "plaintext", "orig_text"})

    # 4. Unknown policy_code or nonexistent policy_version -> 404 / 40401
    for missing_payload in (
        {"text": "我是张三", "policy_code": "nonexistent_policy"},
        {"text": "我是张三", "policy_code": "gov_eval_corpus", "policy_version": 99},
    ):
        nf = client.post(
            "/api/v1/mask/text",
            headers={"X-API-Key": plain_key},
            json=missing_payload,
        )
        assert nf.status_code == 404
        assert nf.json()["code"] == 40401
        assert "张三" not in nf.text


def test_sync_mask_batch_inline_bounds_golden_gov_qa_and_scope_reset(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
    fake_onnx_pipeline: HybridDetectorPipeline,
) -> None:
    tokens = _login_admin_roles(client, app, test_settings)
    plain_key = _issue_api_key(
        client,
        tokens["ADMIN"],
        default_policy_code="gov_eval_corpus",
    )["plain_key"]

    # 1. Item count outside 1..100 -> 400 / 40001 with zero plaintext echoed
    empty_resp = client.post(
        "/api/v1/mask/batch-inline",
        headers={"X-API-Key": plain_key},
        json={"policy_code": "gov_eval_corpus", "items": []},
    )
    assert empty_resp.status_code == 400
    assert empty_resp.json()["code"] == 40001

    too_many_resp = client.post(
        "/api/v1/mask/batch-inline",
        headers={"X-API-Key": plain_key},
        json={
            "policy_code": "gov_eval_corpus",
            "items": [
                {
                    "item_id": f"rec_{idx}",
                    "payload": {"input_text": "我是王五，手机 13900139000"},
                }
                for idx in range(101)
            ],
        },
    )
    assert too_many_resp.status_code == 400
    assert too_many_resp.json()["code"] == 40001
    assert "王五" not in too_many_resp.text
    assert "13900139000" not in too_many_resp.text

    # 2. Multi-item batch: API spec §1.2 case (李四 + references) + Golden Gov QA (张三),
    #    verifying per-item isolated EphemeralScopeDict reset to <PERSON_1> and <PHONE_1>
    batch_resp = client.post(
        "/api/v1/mask/batch-inline",
        headers={"X-API-Key": plain_key},
        json={
            "policy_code": "gov_eval_corpus",
            "policy_version": 1,
            "items": [
                {
                    "item_id": "src_rec_10086",
                    "payload": {
                        "case_code": "CASE_001",
                        "turn_mode": "MULTI_TURN",
                        "input_text": "我叫李四，想查一下我名下在钟楼区的公积金账户提取进度",
                        "turns": [
                            {"role": "user", "content": "你好，我是李四，手机 13900139000"},
                            {
                                "role": "assistant",
                                "content": (
                                    "李四您好，请拨打住房公积金热线 12329 "
                                    "或登录 https://gjj.changzhou.gov.cn 查询。"
                                ),
                            },
                        ],
                        "expected_output": "李四可通过 12329 热线或常州市住房公积金网厅查询提取进度。",
                        "references": [
                            {
                                "doc_name": "公积金办事指南.md",
                                "content": (
                                    "办理地点：常州市政务服务中心（锦绣路2号）1楼公积金窗口，"
                                    "咨询电话 0519-12329。"
                                ),
                            }
                        ],
                    },
                },
                {
                    "item_id": "src_rec_10087",
                    "payload": {
                        "case_code": "CASE_002",
                        "turn_mode": "MULTI_TURN",
                        "turns": [
                            {
                                "role": "user",
                                "content": "我是张三，身份证 32040219900307118X，手机 13812345678",
                            },
                            {
                                "role": "assistant",
                                "content": (
                                    "张三您好，可拨打 12345 或 0519-85681234，"
                                    "前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理"
                                ),
                            },
                        ],
                    },
                },
            ],
        },
    )
    assert batch_resp.status_code == 200
    batch_data = batch_resp.json()["data"]
    assert batch_data["policy_code"] == "gov_eval_corpus"
    assert batch_data["policy_version"] == 1
    assert batch_data["total_items"] == 2
    assert isinstance(batch_data["elapsed_ms"], int)
    assert len(batch_data["results"]) == 2

    rec1, rec2 = batch_data["results"]
    assert rec1["item_id"] == "src_rec_10086"
    assert rec1["masked_payload"] == {
        "case_code": "CASE_001",
        "turn_mode": "MULTI_TURN",
        "input_text": "我叫<PERSON_1>，想查一下我名下在钟楼区的公积金账户提取进度",
        "turns": [
            {"role": "user", "content": "你好，我是<PERSON_1>，手机 <PHONE_1>"},
            {
                "role": "assistant",
                "content": (
                    "<PERSON_1>您好，请拨打住房公积金热线 12329 "
                    "或登录 https://gjj.changzhou.gov.cn 查询。"
                ),
            },
        ],
        "expected_output": "<PERSON_1>可通过 12329 热线或常州市住房公积金网厅查询提取进度。",
        "references": [
            {
                "doc_name": "公积金办事指南.md",
                "content": (
                    "办理地点：常州市政务服务中心（锦绣路2号）1楼公积金窗口，"
                    "咨询电话 0519-12329。"
                ),
            }
        ],
    }
    assert rec1["hit_counts"] == {"private_person": 4, "cn_mobile": 1}

    assert rec2["item_id"] == "src_rec_10087"
    assert rec2["masked_payload"] == {
        "case_code": "CASE_002",
        "turn_mode": "MULTI_TURN",
        "turns": [
            {
                "role": "user",
                "content": "我是<PERSON_1>，身份证 <IDCARD_1>，手机 <PHONE_1>",
            },
            {
                "role": "assistant",
                "content": (
                    "<PERSON_1>您好，可拨打 12345 或 0519-85681234，"
                    "前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理"
                ),
            },
        ],
    }
    assert rec2["hit_counts"] == {
        "private_person": 2,
        "cn_id_card": 1,
        "cn_mobile": 1,
    }


def test_admin_sandbox_preview_text_and_structured_modes_draft_overrides_rbac_and_zero_persistence(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
    fake_onnx_pipeline: HybridDetectorPipeline,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging
    from sqlalchemy import inspect, text as sql_text

    tokens = _login_admin_roles(client, app, test_settings)
    plain_key = _issue_api_key(client, tokens["ADMIN"])["plain_key"]

    def _snapshot_all_tables() -> dict[str, list[tuple[Any, ...]]]:
        inspector = inspect(app.state.db_engine)
        snap: dict[str, list[tuple[Any, ...]]] = {}
        with app.state.db_engine.connect() as conn:
            for tbl in sorted(inspector.get_table_names()):
                rows = conn.execute(sql_text(f"SELECT * FROM {tbl} ORDER BY id ASC")).fetchall()
                snap[tbl] = [tuple(r) for r in rows]
        return snap

    # 1. Missing auth or API key rejected on admin sandbox -> 401 / 40101
    for bad_headers in (
        {},
        {"X-API-Key": plain_key},
        {"Authorization": f"Bearer {plain_key}"},
    ):
        unauth = client.post(
            "/api/admin/sandbox/preview",
            headers=bad_headers,
            json={"mode": "TEXT", "text": "我是张三"},
        )
        assert unauth.status_code == 401
        assert unauth.json()["code"] == 40101

    db_before_sandbox = _snapshot_all_tables()
    caplog.clear()

    sandbox_text = (
        "我是张三，身份证 32040219900307118X，手机 13812345678，"
        "可拨打 0519-85681234 前往常州市政务服务中心（锦绣路2号）办理。"
    )

    with caplog.at_level(logging.DEBUG):
        # 2. ADMIN, OPERATOR, AUDITOR can all execute TEXT mode sandbox preview
        for role in ("ADMIN", "OPERATOR", "AUDITOR"):
            text_resp = client.post(
                "/api/admin/sandbox/preview",
                headers={"Authorization": f"Bearer {tokens[role]}"},
                json={
                    "mode": "TEXT",
                    "policy_code": "gov_eval_corpus",
                    "text": sandbox_text,
                },
            )
            assert text_resp.status_code == 200
            tdata = text_resp.json()["data"]
            assert tdata["mode"] == "TEXT"
            assert tdata["policy_code"] == "gov_eval_corpus"
            assert tdata["policy_version"] == 1
            assert tdata["masked_text"] == (
                "我是<PERSON_1>，身份证 <IDCARD_1>，手机 <PHONE_1>，"
                "可拨打 0519-85681234 前往常州市政务服务中心（锦绣路2号）办理。"
            )
            assert tdata["hit_counts"] == {
                "private_person": 1,
                "cn_id_card": 1,
                "cn_mobile": 1,
            }
            assert isinstance(tdata["elapsed_ms"], int)

            # Verify 3-state spans: onnx, regex, allowlist
            spans = tdata["spans"]
            by_text = {sp["text"]: sp for sp in spans}
            assert by_text["张三"]["state"] == "onnx"
            assert by_text["张三"]["detector"] == "onnx"
            assert by_text["张三"]["replacement"] == "<PERSON_1>"
            assert by_text["张三"]["exempted"] is False

            assert by_text["32040219900307118X"]["state"] == "regex"
            assert by_text["32040219900307118X"]["detector"] == "regex"
            assert by_text["32040219900307118X"]["replacement"] == "<IDCARD_1>"

            assert by_text["13812345678"]["state"] == "regex"
            assert by_text["13812345678"]["replacement"] == "<PHONE_1>"

            assert by_text["0519-85681234"]["state"] == "allowlist"
            assert by_text["0519-85681234"]["exempted"] is True
            assert by_text["0519-85681234"]["allowlist_group"] == "gov_public_hotline"

            assert by_text["常州市政务服务中心（锦绣路2号）"]["state"] == "allowlist"
            assert by_text["常州市政务服务中心（锦绣路2号）"]["exempted"] is True
            assert by_text["常州市政务服务中心（锦绣路2号）"]["allowlist_group"] == "gov_public_hall"

            assert len(tdata["masked_spans"]) == 3
            for msp in tdata["masked_spans"]:
                assert (
                    tdata["masked_text"][msp["start"] : msp["end"]]
                    == msp["placeholder"]
                )

        # 3. STRUCTURED mode + inline draft policy overrides (e.g. PARTIAL mobile + url enabled with allowlist)
        struct_resp = client.post(
            "/api/admin/sandbox/preview",
            headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
            json={
                "mode": "STRUCTURED",
                "policy_code": "gov_eval_corpus",
                "entity_rules": {
                    "cn_mobile": {
                        "enabled": True,
                        "min_score": 1.0,
                        "action": "PARTIAL",
                        "keep_head": 3,
                        "keep_tail": 4,
                    },
                    "url": {
                        "enabled": True,
                        "min_score": 0.80,
                        "action": "PLACEHOLDER",
                        "prefix": "URL",
                    },
                },
                "payload": {
                    "turns": [
                        {
                            "role": "user",
                            "content": "我是张三，手机 13812345678，网址 https://www.changzhou.gov.cn",
                        },
                        {
                            "role": "assistant",
                            "content": "张三您好，请拨打 12345 咨询。",
                        },
                    ]
                },
            },
        )
        assert struct_resp.status_code == 200
        sdata = struct_resp.json()["data"]
        assert sdata["mode"] == "STRUCTURED"
        assert sdata["masked_payload"]["turns"][0]["content"] == (
            "我是<PERSON_1>，手机 138****5678，网址 https://www.changzhou.gov.cn"
        )
        assert sdata["masked_payload"]["turns"][1]["content"] == "<PERSON_1>您好，请拨打 12345 咨询。"
        assert "$.turns[0].content" in sdata["field_traces"]
        user_trace_by_text = {
            sp["text"]: sp for sp in sdata["field_traces"]["$.turns[0].content"]
        }
        assert user_trace_by_text["https://www.changzhou.gov.cn"]["state"] == "allowlist"
        assert (
            user_trace_by_text["https://www.changzhou.gov.cn"]["allowlist_group"]
            == "gov_public_domain"
        )

        # 4. Invalid draft override or missing text/payload -> 400 / 40001 with zero plaintext leak
        for invalid_req in (
            {"mode": "TEXT"},
            {"mode": "STRUCTURED", "text": "我是张三"},
            {
                "mode": "STRUCTURED",
                "policy_code": "gov_eval_corpus",
                "field_role_rules": {
                    "default_role": "FULL_MASK_WRITE_SCOPE",
                    "rules": [{"jsonpath": "$[unclosed", "role": "PASSTHROUGH"}],
                },
                "payload": {"input_text": "我是张三，身份证 32040219900307118X"},
            },
        ):
            bad_sandbox = client.post(
                "/api/admin/sandbox/preview",
                headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
                json=invalid_req,
            )
            assert bad_sandbox.status_code == 400
            assert bad_sandbox.json()["code"] == 40001
            assert "32040219900307118X" not in bad_sandbox.text

    # 5. STRICT ZERO DB WRITES across ALL 7 tables (including ds_api_usage_hourly & ds_policy_profile)
    #    and STRICT ZERO LOGS of sensitive input/output
    db_after_sandbox = _snapshot_all_tables()
    assert db_after_sandbox == db_before_sandbox
    assert db_after_sandbox["ds_api_usage_hourly"] == []

    for secret in ("张三", "32040219900307118X", "13812345678", "<PERSON_1>", "<IDCARD_1>"):
        assert secret not in caplog.text


def test_hourly_metrics_aggregation_14_entity_ranking_sandbox_isolation_and_rbac(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
    fake_onnx_pipeline: HybridDetectorPipeline,
) -> None:
    from datetime import timedelta
    from app.db.base import utcnow
    from app.telemetry import record_sync_api_usage, truncate_to_hour

    tokens = _login_admin_roles(client, app, test_settings)
    key_info = _issue_api_key(
        client,
        tokens["ADMIN"],
        default_policy_code="gov_eval_corpus",
    )
    plain_key = key_info["plain_key"]

    # 1. Auth & parameter validation on GET /api/admin/metrics/hourly
    for bad_headers in (
        {},
        {"X-API-Key": plain_key},
        {"Authorization": f"Bearer {plain_key}"},
    ):
        unauth = client.get("/api/admin/metrics/hourly?hours=24", headers=bad_headers)
        assert unauth.status_code == 401
        assert unauth.json()["code"] == 40101

    bad_hours = client.get(
        "/api/admin/metrics/hourly?hours=0",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
    )
    assert bad_hours.status_code == 400
    assert bad_hours.json()["code"] == 40001

    # 2. Empty baseline before any sync calls
    empty_metrics = client.get(
        "/api/admin/metrics/hourly?hours=24",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
    ).json()["data"]
    assert empty_metrics["total_requests"] == 0
    assert empty_metrics["total_chars"] == 0
    assert empty_metrics["avg_elapsed_ms"] == 0.0
    assert empty_metrics["error_count"] == 0
    assert empty_metrics["buckets"] == []
    assert len(empty_metrics["entity_distribution"]) == 14
    assert all(item["count"] == 0 for item in empty_metrics["entity_distribution"])
    assert empty_metrics["updated_at"].endswith("Z")

    # 3. Execute sync mask calls (2 single-text + 1 batch-inline with 2 items) + 1 sandbox call
    text_1 = "我是张三，身份证 32040219900307118X，手机 13812345678"
    text_2 = "联系人李四，临时口令 sk-prod-9988776655443322"
    r1 = client.post(
        "/api/v1/mask/text",
        headers={"X-API-Key": plain_key},
        json={"text": text_1},
    )
    r2 = client.post(
        "/api/v1/mask/text",
        headers={"X-API-Key": plain_key},
        json={"text": text_2},
    )
    r3 = client.post(
        "/api/v1/mask/batch-inline",
        headers={"X-API-Key": plain_key},
        json={
            "items": [
                {
                    "item_id": "b1",
                    "payload": {"input_text": "我是张三，手机 13900139000"},
                },
                {
                    "item_id": "b2",
                    "payload": {"input_text": "我是王五"},
                },
            ]
        },
    )
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 200

    # Sandbox traffic must not pollute hourly usage metrics
    sb = client.post(
        "/api/admin/sandbox/preview",
        headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
        json={"mode": "TEXT", "policy_code": "gov_eval_corpus", "text": text_1},
    )
    assert sb.status_code == 200

    # Also seed an earlier-hour bucket + a synthetic api_key_id=0 row to verify multi-bucket trend
    # AND default exclusion of api_key_id == 0 unless include_sandbox=true
    now = utcnow()
    two_hours_ago = truncate_to_hour(now) - timedelta(hours=2)
    thirty_hours_ago = truncate_to_hour(now) - timedelta(hours=30)
    with app.state.session_factory() as session:
        record_sync_api_usage(
            session,
            api_key_id=key_info["id"],
            policy_id=1,
            request_count=2,
            item_count=2,
            total_chars=100,
            elapsed_ms=40,
            error_count=0,
            hit_counts={"private_person": 3},
            occurred_at=two_hours_ago,
        )
        # Outside 24h window -> excluded from hours=24
        record_sync_api_usage(
            session,
            api_key_id=key_info["id"],
            policy_id=1,
            request_count=5,
            item_count=5,
            total_chars=500,
            elapsed_ms=100,
            error_count=1,
            hit_counts={"email": 9},
            occurred_at=thirty_hours_ago,
        )
        # Sandbox sentinel bucket (api_key_id == 0)
        record_sync_api_usage(
            session,
            api_key_id=0,
            policy_id=1,
            request_count=10,
            item_count=10,
            total_chars=999,
            elapsed_ms=200,
            error_count=0,
            hit_counts={"ip_address": 7},
            occurred_at=now,
        )

    expected_live_chars = (
        len(text_1) + len(text_2) + len("我是张三，手机 13900139000") + len("我是王五")
    )

    # 4. ADMIN, OPERATOR, AUDITOR all read identical default metrics (api_key_id == 0 excluded)
    for role in ("ADMIN", "OPERATOR", "AUDITOR"):
        m_resp = client.get(
            "/api/admin/metrics/hourly?hours=24",
            headers={"Authorization": f"Bearer {tokens[role]}"},
        )
        assert m_resp.status_code == 200
        mdata = m_resp.json()["data"]
        assert mdata["total_requests"] == 5  # 3 live + 2 from 2h ago
        assert mdata["total_chars"] == expected_live_chars + 100
        assert mdata["error_count"] == 0
        assert isinstance(mdata["avg_elapsed_ms"], float)
        assert len(mdata["buckets"]) == 2
        assert mdata["buckets"][0]["hour_bucket"] < mdata["buckets"][1]["hour_bucket"]
        assert mdata["buckets"][0]["request_count"] == 2
        assert mdata["buckets"][1]["request_count"] == 3
        assert mdata["buckets"][1]["item_count"] == 4

        dist = mdata["entity_distribution"]
        assert len(dist) == 14
        counts = [d["count"] for d in dist]
        assert counts == sorted(counts, reverse=True)
        dist_map = {d["label"]: d for d in dist}
        # private_person: 1 (r1) + 1 (r2) + 2 (r3) + 3 (2h ago) = 7
        assert dist_map["private_person"]["count"] == 7
        assert dist_map["cn_mobile"]["count"] == 2
        assert dist_map["cn_id_card"]["count"] == 1
        assert dist_map["common_secret"]["count"] == 1
        assert dist_map["ip_address"]["count"] == 0  # api_key_id=0 excluded!
        assert dist_map["email"]["count"] == 0  # >24h ago excluded!
        assert dist[0]["label"] == "private_person"
        assert dist[0]["label_zh"] == "个人姓名"

    # 5. include_sandbox=true includes api_key_id == 0 rows
    with_sb = client.get(
        "/api/admin/metrics/hourly?hours=24&include_sandbox=true",
        headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
    ).json()["data"]
    assert with_sb["total_requests"] == 15
    assert with_sb["total_chars"] == expected_live_chars + 100 + 999
    sb_dist_map = {d["label"]: d["count"] for d in with_sb["entity_distribution"]}
    assert sb_dist_map["ip_address"] == 7


def test_missing_onnx_weights_returns_50301_records_error_telemetry_and_allows_regex_only(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    set_default_pipeline(None)
    tokens = _login_admin_roles(client, app, test_settings)
    plain_key = _issue_api_key(
        client,
        tokens["ADMIN"],
        default_policy_code="gov_eval_corpus",
    )["plain_key"]

    probe_pii = "我是张三，身份证 32040219900307118X，手机 13812345678"

    with caplog.at_level(logging.DEBUG):
        # 1. Sync text mask fails with 503 / 50301 when ONNX weights missing & ONNX label enabled
        r_text = client.post(
            "/api/v1/mask/text",
            headers={"X-API-Key": plain_key},
            json={"text": probe_pii},
        )
        assert r_text.status_code == 503
        assert r_text.json()["code"] == 50301
        assert "32040219900307118X" not in r_text.text

        # 2. Sync batch-inline fails with 503 / 50301 when ONNX weights missing
        r_batch = client.post(
            "/api/v1/mask/batch-inline",
            headers={"X-API-Key": plain_key},
            json={
                "items": [
                    {"item_id": "err_1", "payload": {"input_text": probe_pii}},
                ]
            },
        )
        assert r_batch.status_code == 503
        assert r_batch.json()["code"] == 50301
        assert "32040219900307118X" not in r_batch.text

        # 3. Admin sandbox preview also returns 503 / 50301 without writing any DB telemetry
        r_sb_text = client.post(
            "/api/admin/sandbox/preview",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
            json={
                "mode": "TEXT",
                "policy_code": "gov_eval_corpus",
                "text": probe_pii,
            },
        )
        assert r_sb_text.status_code == 503
        assert r_sb_text.json()["code"] == 50301
        assert "32040219900307118X" not in r_sb_text.text

        r_sb_struct = client.post(
            "/api/admin/sandbox/preview",
            headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
            json={
                "mode": "STRUCTURED",
                "policy_code": "gov_eval_corpus",
                "payload": {"input_text": probe_pii},
            },
        )
        assert r_sb_struct.status_code == 503
        assert r_sb_struct.json()["code"] == 50301

    assert "32040219900307118X" not in caplog.text
    assert "13812345678" not in caplog.text

    # 4. Verify error_count=2 recorded for sync calls ONLY (sandbox 503 did NOT write to DB)
    metrics_after_503 = client.get(
        "/api/admin/metrics/hourly?hours=24&include_sandbox=true",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
    ).json()["data"]
    assert metrics_after_503["total_requests"] == 2
    assert metrics_after_503["error_count"] == 2
    assert metrics_after_503["total_chars"] == 0

    # 5. Regex-only policy succeeds with 200 even when ONNX weights are absent
    pol_create = client.post(
        "/api/admin/policies",
        headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        json={
            "policy_code": "regex_only_fast",
            "policy_name": "纯正则离线兜底策略",
            "scope_mode": "RECORD",
            "entity_rules": {
                "cn_id_card": {"enabled": True, "min_score": 1.0, "action": "PLACEHOLDER"},
                "cn_mobile": {"enabled": True, "min_score": 1.0, "action": "PLACEHOLDER"},
            },
        },
    )
    assert pol_create.status_code == 200

    regex_ok = client.post(
        "/api/v1/mask/text",
        headers={"X-API-Key": plain_key},
        json={"text": probe_pii, "policy_code": "regex_only_fast"},
    )
    assert regex_ok.status_code == 200
    assert regex_ok.json()["data"]["masked_text"] == "我是张三，身份证 <IDCARD_1>，手机 <PHONE_1>"

    # 6. Attaching detector_pipeline on app.state (consistent with /api/admin/auth/me) makes ONNX ready
    local_pipe = _build_fake_onnx_pipeline()
    app.state.detector_pipeline = local_pipe
    try:
        me_ready = client.get(
            "/api/admin/auth/me",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        ).json()["data"]
        assert me_ready["onnx_ready"] is True

        ready_ok = client.post(
            "/api/v1/mask/text",
            headers={"X-API-Key": plain_key},
            json={"text": probe_pii, "policy_code": "gov_eval_corpus"},
        )
        assert ready_ok.status_code == 200
        assert ready_ok.json()["data"]["masked_text"] == (
            "我是<PERSON_1>，身份证 <IDCARD_1>，手机 <PHONE_1>"
        )
    finally:
        app.state.detector_pipeline = None
        local_pipe.shutdown()


def test_full_seven_table_zero_plaintext_audit_after_sync_mask_and_sandbox(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
    fake_onnx_pipeline: HybridDetectorPipeline,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging
    from sqlalchemy import inspect, text as sql_text

    tokens = _login_admin_roles(client, app, test_settings)
    plain_key = _issue_api_key(
        client,
        tokens["ADMIN"],
        default_policy_code="gov_eval_corpus",
    )["plain_key"]

    sensitive_markers = (
        "张三",
        "李四",
        "王五",
        "32040219900307118X",
        "11010519491231002X",
        "13812345678",
        "13900139000",
        "钟楼区星港花园12栋301室",
        "sk-prod-9988776655443322",
    )

    with caplog.at_level(logging.DEBUG):
        assert (
            client.post(
                "/api/v1/mask/text",
                headers={"X-API-Key": plain_key},
                json={
                    "text": (
                        "住户张三，住址钟楼区星港花园12栋301室，身份证 32040219900307118X，"
                        "手机 13812345678，密钥 sk-prod-9988776655443322"
                    ),
                    "return_spans": True,
                },
            ).status_code
            == 200
        )

        assert (
            client.post(
                "/api/v1/mask/batch-inline",
                headers={"X-API-Key": plain_key},
                json={
                    "items": [
                        {
                            "item_id": "audit_1",
                            "payload": {
                                "turns": [
                                    {
                                        "role": "user",
                                        "content": (
                                            "我是李四，身份证 11010519491231002X，手机 13900139000"
                                        ),
                                    },
                                    {
                                        "role": "assistant",
                                        "content": "李四您好，请致电 12345。",
                                    },
                                ]
                            },
                        }
                    ]
                },
            ).status_code
            == 200
        )

        assert (
            client.post(
                "/api/admin/sandbox/preview",
                headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
                json={
                    "mode": "TEXT",
                    "policy_code": "strict_general",
                    "text": "测试王五 11010519491231002X 13900139000 钟楼区星港花园12栋301室",
                },
            ).status_code
            == 200
        )

        assert (
            client.get(
                "/api/admin/metrics/hourly?hours=24",
                headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
            ).status_code
            == 200
        )

    inspector = inspect(app.state.db_engine)
    table_names = set(inspector.get_table_names())
    assert table_names == {
        "ds_admin_user",
        "ds_api_key",
        "ds_allowlist_dict",
        "ds_policy_profile",
        "ds_datasource_conn",
        "ds_batch_job",
        "ds_api_usage_hourly",
    }

    with app.state.db_engine.connect() as conn:
        for table_name in sorted(table_names):
            rows = conn.execute(sql_text(f"SELECT * FROM {table_name}")).fetchall()
            for row in rows:
                for col_val in row:
                    if col_val is not None:
                        s_val = str(col_val)
                        for marker in sensitive_markers:
                            assert marker not in s_val, (
                                f"Plaintext marker leaked in table {table_name}"
                            )

    for marker in sensitive_markers:
        assert marker not in caplog.text




