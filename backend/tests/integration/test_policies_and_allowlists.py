from __future__ import annotations

from copy import deepcopy
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.auth.security import hash_password
from app.common.errors import NotFoundError
from app.db.base import new_uuid
from app.db.models import AdminUser, PolicyProfile
from app.db.seed import GOV_EVAL_CORPUS_ENTITY_RULES, GOV_EVAL_CORPUS_FIELD_ROLE_RULES
from app.engine import PolicyEngineService, get_policy_engine


def _seed_role_tokens(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
) -> dict[str, str]:
    with app.state.session_factory() as session:
        session.add_all(
            [
                AdminUser(
                    uuid=new_uuid(),
                    username="policy_operator",
                    display_name="策略操作员",
                    password_hash=hash_password("OpPass@123", rounds=test_settings.bcrypt_rounds),
                    role="OPERATOR",
                    is_enabled=1,
                    is_deleted=0,
                ),
                AdminUser(
                    uuid=new_uuid(),
                    username="policy_auditor",
                    display_name="只读审计员",
                    password_hash=hash_password("AuditPass@123", rounds=test_settings.bcrypt_rounds),
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
        "OPERATOR": _login("policy_operator", "OpPass@123"),
        "AUDITOR": _login("policy_auditor", "AuditPass@123"),
    }


def test_policies_lifecycle_immutable_version_bump_set_default_validation_and_rbac(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
) -> None:
    tokens = _seed_role_tokens(client, app, test_settings)

    # 1. Unauthenticated / API Key rejected on admin policies -> 401 / 40101
    for bad_headers in (
        {},
        {"Authorization": "Bearer dsk_live_00112233445566778899aabbccddeeff"},
    ):
        unauth = client.get("/api/admin/policies", headers=bad_headers)
        assert unauth.status_code == 401
        assert unauth.json()["code"] == 40101

    # 2. ADMIN, OPERATOR, AUDITOR can all query seeded policies & versions
    for role in ("ADMIN", "OPERATOR", "AUDITOR"):
        list_resp = client.get(
            "/api/admin/policies",
            headers={"Authorization": f"Bearer {tokens[role]}"},
        )
        assert list_resp.status_code == 200
        data = list_resp.json()["data"]
        codes = {(it["policy_code"], it["version"]) for it in data["items"]}
        assert ("strict_general", 1) in codes
        assert ("gov_eval_corpus", 1) in codes

    filtered_resp = client.get(
        "/api/admin/policies?policy_code=gov_eval_corpus",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
    )
    assert filtered_resp.status_code == 200
    gov_v1_before = filtered_resp.json()["data"]["items"][0]
    assert gov_v1_before["policy_code"] == "gov_eval_corpus"
    assert gov_v1_before["version"] == 1
    assert gov_v1_before["is_default"] is True

    # 3. AUDITOR is read-only -> 403 / 40301 on create and set-default
    auditor_post = client.post(
        "/api/admin/policies",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
        json={
            "policy_code": "auditor_forbidden",
            "policy_name": "禁止创建",
            "scope_mode": "RECORD",
            "entity_rules": {"cn_mobile": {"enabled": True, "min_score": 1.0, "action": "PLACEHOLDER"}},
        },
    )
    assert auditor_post.status_code == 403
    assert auditor_post.json()["code"] == 40301

    auditor_set_def = client.post(
        "/api/admin/policies/gov_eval_corpus/versions/1/set-default",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
    )
    assert auditor_set_def.status_code == 403
    assert auditor_set_def.json()["code"] == 40301

    # 4. Invalid JSONPath or invalid entity rule rejected with 400 / 40001
    for invalid_body in (
        {
            "policy_code": "gov_eval_corpus",
            "policy_name": "非法JSONPath测试",
            "scope_mode": "CONVERSATION",
            "entity_rules": deepcopy(GOV_EVAL_CORPUS_ENTITY_RULES),
            "field_role_rules": {
                "default_role": "FULL_MASK_WRITE_SCOPE",
                "rules": [{"jsonpath": "$[unclosed_filter", "role": "PASSTHROUGH"}],
            },
        },
        {
            "policy_code": "gov_eval_corpus",
            "policy_name": "非法动作测试",
            "scope_mode": "CONVERSATION",
            "entity_rules": {
                "cn_mobile": {"enabled": True, "min_score": 1.0, "action": "DECRYPTABLE"},
            },
        },
    ):
        bad_res = client.post(
            "/api/admin/policies",
            headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
            json=invalid_body,
        )
        assert bad_res.status_code == 400
        assert bad_res.json()["code"] == 40001

    # 5. OPERATOR creates brand-new policy_code -> version=1 & is_default=True
    new_code_resp = client.post(
        "/api/admin/policies",
        headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
        json={
            "policy_code": "fin_report_mask",
            "policy_name": "金融报表脱敏策略 v1",
            "scope_mode": "RECORD",
            "onnx_variant": "int8",
            "entity_rules": {
                "cn_id_card": {"enabled": True, "min_score": 1.0, "action": "HASH"},
                "cn_mobile": {
                    "enabled": True,
                    "min_score": 1.0,
                    "action": "PARTIAL",
                    "keep_head": 3,
                    "keep_tail": 4,
                },
            },
            "description": "金融导出场景",
        },
    )
    assert new_code_resp.status_code == 200
    fin_v1 = new_code_resp.json()["data"]
    assert fin_v1["policy_code"] == "fin_report_mask"
    assert fin_v1["version"] == 1
    assert fin_v1["is_default"] is True
    assert fin_v1["created_by"] == "policy_operator"
    assert len(fin_v1["entity_rules"]) == 14
    assert fin_v1["entity_rules"]["cn_id_card"]["action"] == "HASH"
    assert fin_v1["entity_rules"]["private_person"]["enabled"] is False

    # 6. Submitting update to existing gov_eval_corpus creates immutable version 2;
    #    version 1 remains untouched and stays default until set-default is called!
    v2_rules = deepcopy(GOV_EVAL_CORPUS_ENTITY_RULES)
    v2_rules["cn_mobile"] = {
        "enabled": True,
        "min_score": 1.0,
        "action": "PARTIAL",
        "keep_head": 3,
        "keep_tail": 4,
    }
    bump_resp = client.post(
        "/api/admin/policies",
        headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        json={
            "policy_code": "gov_eval_corpus",
            "policy_name": "政务问答与评测语料差异化脱敏策略 v2（手机号部分掩码）",
            "scope_mode": "CONVERSATION",
            "onnx_variant": "int8",
            "entity_rules": v2_rules,
            "field_role_rules": deepcopy(GOV_EVAL_CORPUS_FIELD_ROLE_RULES),
            "allowlist_groups": ["gov_public_hotline", "gov_public_domain", "gov_public_hall"],
        },
    )
    assert bump_resp.status_code == 200
    gov_v2 = bump_resp.json()["data"]
    assert gov_v2["policy_code"] == "gov_eval_corpus"
    assert gov_v2["version"] == 2
    assert gov_v2["is_default"] is False

    # Verify v1 rule definition is 100% unchanged and policy_version=None still hits v1
    versions_resp = client.get(
        "/api/admin/policies?policy_code=gov_eval_corpus",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
    )
    by_ver = {it["version"]: it for it in versions_resp.json()["data"]["items"]}
    assert set(by_ver.keys()) == {1, 2}
    assert by_ver[1]["policy_name"] == gov_v1_before["policy_name"]
    assert by_ver[1]["entity_rules"] == gov_v1_before["entity_rules"]
    assert by_ver[1]["field_role_rules"] == gov_v1_before["field_role_rules"]
    assert by_ver[1]["is_default"] is True
    assert by_ver[2]["entity_rules"]["cn_mobile"]["action"] == "PARTIAL"

    engine = PolicyEngineService()
    with app.state.session_factory() as session:
        snap_default_before = engine.resolve_policy(session, "gov_eval_corpus", None)
        snap_explicit_v2 = engine.resolve_policy(session, "gov_eval_corpus", 2)
        assert snap_default_before.version == 1
        assert snap_default_before.entity_rules["cn_mobile"]["action"] == "PLACEHOLDER"
        assert snap_explicit_v2.version == 2
        assert snap_explicit_v2.entity_rules["cn_mobile"]["action"] == "PARTIAL"

    # 7. Switch default version to v2 -> policy_version=None now resolves v2; v1 content remains intact!
    set_def_resp = client.post(
        "/api/admin/policies/gov_eval_corpus/versions/2/set-default",
        headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
    )
    assert set_def_resp.status_code == 200
    assert set_def_resp.json()["data"]["version"] == 2
    assert set_def_resp.json()["data"]["is_default"] is True

    after_resp = client.get(
        "/api/admin/policies?policy_code=gov_eval_corpus",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
    )
    by_ver_after = {it["version"]: it for it in after_resp.json()["data"]["items"]}
    assert by_ver_after[1]["is_default"] is False
    assert by_ver_after[1]["entity_rules"] == gov_v1_before["entity_rules"]
    assert by_ver_after[2]["is_default"] is True

    with app.state.session_factory() as session:
        snap_default_after = engine.resolve_policy(session, "gov_eval_corpus", None)
        assert snap_default_after.version == 2
        assert snap_default_after.entity_rules["cn_mobile"]["action"] == "PARTIAL"
        assert len(snap_default_after.allowlist_entries) == 4

        # Inline sandbox snapshot helper resolves draft overrides without persisting new DB rows
        count_before = session.query(PolicyProfile).count()
        draft_snap = engine.resolve_sandbox_snapshot(
            session,
            policy_code="gov_eval_corpus",
            scope_mode="NONE",
            entity_rules={"cn_mobile": {"enabled": True, "min_score": 1.0, "action": "HASH"}},
        )
        adhoc_snap = engine.resolve_sandbox_snapshot(
            session,
            policy_code=None,
            allowlist_groups=["gov_public_hotline"],
        )
        assert draft_snap.scope_mode == "NONE"
        assert draft_snap.entity_rules["cn_mobile"]["action"] == "HASH"
        assert adhoc_snap.policy_code == "sandbox_draft"
        assert len(adhoc_snap.allowlist_entries) == 2
        assert session.query(PolicyProfile).count() == count_before

        with pytest.raises(NotFoundError) as nf_exc:
            engine.resolve_policy(session, "does_not_exist", None)
        assert nf_exc.value.code == 40401

    # 8. set-default on missing policy_code or missing version returns 404 / 40401
    for missing_url in (
        "/api/admin/policies/unknown_code/versions/1/set-default",
        "/api/admin/policies/gov_eval_corpus/versions/999/set-default",
    ):
        nf = client.post(
            missing_url,
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        )
        assert nf.status_code == 404
        assert nf.json()["code"] == 40401


def test_allowlists_crud_inline_tester_rbac_invalid_regex_and_zero_plaintext_persistence(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging
    from sqlalchemy import inspect, text

    tokens = _seed_role_tokens(client, app, test_settings)

    # 1. GET /api/admin/allowlists accessible to ADMIN, OPERATOR, AUDITOR with group summaries
    for role in ("ADMIN", "OPERATOR", "AUDITOR"):
        list_resp = client.get(
            "/api/admin/allowlists",
            headers={"Authorization": f"Bearer {tokens[role]}"},
        )
        assert list_resp.status_code == 200
        body_data = list_resp.json()["data"]
        assert body_data["total"] == 4
        group_map = {g["group_code"]: g["total_count"] for g in body_data["groups"]}
        assert group_map == {
            "gov_public_domain": 1,
            "gov_public_hall": 1,
            "gov_public_hotline": 2,
        }

    hotline_only = client.get(
        "/api/admin/allowlists?group_code=gov_public_hotline",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
    ).json()["data"]
    assert len(hotline_only["items"]) == 2

    # 2. AUDITOR cannot POST / PUT / DELETE allowlists -> 403 / 40301
    existing_item_id = hotline_only["items"][0]["id"]
    assert (
        client.post(
            "/api/admin/allowlists",
            headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
            json={
                "group_code": "gov_public_hotline",
                "item_name": "审计员禁止新增",
                "match_mode": "EXACT",
                "pattern_text": "12345",
                "apply_labels": ["phone"],
            },
        ).json()["code"]
        == 40301
    )
    assert (
        client.put(
            f"/api/admin/allowlists/{existing_item_id}",
            headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
            json={"remark": "禁止修改"},
        ).json()["code"]
        == 40301
    )
    assert (
        client.delete(
            f"/api/admin/allowlists/{existing_item_id}",
            headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
        ).json()["code"]
        == 40301
    )

    # 3. OPERATOR creates allowlist item; invalid regex / bad label rejected with 400 / 40001
    for invalid_allowlist in (
        {
            "group_code": "gov_public_hotline",
            "item_name": "损坏正则",
            "match_mode": "REGEX",
            "pattern_text": "[unterminated(",
            "apply_labels": ["phone"],
        },
        {
            "group_code": "gov_public_hotline",
            "item_name": "未知标签",
            "match_mode": "EXACT",
            "pattern_text": "12345",
            "apply_labels": ["unknown_entity"],
        },
    ):
        bad_al = client.post(
            "/api/admin/allowlists",
            headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
            json=invalid_allowlist,
        )
        assert bad_al.status_code == 400
        assert bad_al.json()["code"] == 40001

    created_resp = client.post(
        "/api/admin/allowlists",
        headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
        json={
            "group_code": "gov_portal_sub",
            "item_name": "政务门户后缀规则",
            "match_mode": "SUFFIX",
            "pattern_text": ".changzhou.gov.cn",
            "apply_labels": ["url"],
            "remark": "操作员创建",
        },
    )
    assert created_resp.status_code == 200
    created_item = created_resp.json()["data"]
    item_id = created_item["id"]
    assert created_item["is_enabled"] is True
    assert created_item["created_by"] == "policy_operator"

    # 4. Inline allowlist tester (saved groups + ad-hoc regex) accessible to AUDITOR/OPERATOR/ADMIN,
    #    with strict zero-plaintext DB & log persistence
    sensitive_probe = "赵六-11010519491231002X-13700137000"
    with caplog.at_level(logging.DEBUG):
        # Saved group match
        saved_hit = client.post(
            "/api/admin/allowlists/test",
            headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
            json={
                "text": "0519-85681234",
                "label": "phone",
                "group_codes": ["gov_public_hotline"],
            },
        )
        assert saved_hit.status_code == 200
        assert saved_hit.json()["data"]["matched"] is True
        assert len(saved_hit.json()["data"]["matched_rules"]) == 1

        # Saved group miss on personal mobile PII
        saved_miss = client.post(
            "/api/admin/allowlists/test",
            headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
            json={
                "text": sensitive_probe,
                "label": "cn_mobile",
                "group_codes": ["gov_public_hotline"],
            },
        )
        assert saved_miss.status_code == 200
        assert saved_miss.json()["data"]["matched"] is False
        assert saved_miss.json()["data"]["matched_rules"] == []

        # Ad-hoc unsaved regex test
        adhoc_hit = client.post(
            "/api/admin/allowlists/test",
            headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
            json={
                "text": "https://zwfw.changzhou.gov.cn/portal",
                "label": "url",
                "match_mode": "SUFFIX",
                "pattern_text": ".changzhou.gov.cn",
                "apply_labels": ["url"],
            },
        )
        assert adhoc_hit.status_code == 200
        assert adhoc_hit.json()["data"]["matched"] is True

        # Ad-hoc invalid regex rejected with 400 / 40001 and zero plaintext echo
        adhoc_bad = client.post(
            "/api/admin/allowlists/test",
            headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
            json={
                "text": sensitive_probe,
                "label": "phone",
                "match_mode": "REGEX",
                "pattern_text": "[broken(",
                "apply_labels": ["phone"],
            },
        )
        assert adhoc_bad.status_code == 400
        assert adhoc_bad.json()["code"] == 40001
        assert sensitive_probe not in adhoc_bad.text

    assert sensitive_probe not in caplog.text
    assert "11010519491231002X" not in caplog.text

    # 5. PUT update (disable rule -> test misses; invalid regex on PUT -> 40001) & DELETE soft-delete -> 40401
    bad_put = client.put(
        f"/api/admin/allowlists/{item_id}",
        headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        json={"match_mode": "REGEX", "pattern_text": "[bad_regex("},
    )
    assert bad_put.status_code == 400
    assert bad_put.json()["code"] == 40001

    disable_put = client.put(
        f"/api/admin/allowlists/{item_id}",
        headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
        json={"is_enabled": False, "remark": "临时停用"},
    )
    assert disable_put.status_code == 200
    assert disable_put.json()["data"]["is_enabled"] is False
    assert disable_put.json()["data"]["remark"] == "临时停用"

    after_disable_test = client.post(
        "/api/admin/allowlists/test",
        headers={"Authorization": f"Bearer {tokens['AUDITOR']}"},
        json={
            "text": "https://zwfw.changzhou.gov.cn/portal",
            "label": "url",
            "group_codes": ["gov_portal_sub"],
        },
    )
    assert after_disable_test.json()["data"]["matched"] is False

    del_resp = client.delete(
        f"/api/admin/allowlists/{item_id}",
        headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
    )
    assert del_resp.status_code == 200

    assert (
        client.put(
            f"/api/admin/allowlists/{item_id}",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
            json={"remark": "已删除"},
        ).json()["code"]
        == 40401
    )
    assert (
        client.delete(
            f"/api/admin/allowlists/{item_id}",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        ).json()["code"]
        == 40401
    )

    # 6. Full 7-table zero-plaintext scan: sensitive_probe appears 0 times across all columns
    inspector = inspect(app.state.db_engine)
    with app.state.db_engine.connect() as conn:
        for table_name in inspector.get_table_names():
            rows = conn.execute(text(f"SELECT * FROM {table_name}")).fetchall()
            for row in rows:
                for col_val in row:
                    if col_val is not None:
                        s_val = str(col_val)
                        assert sensitive_probe not in s_val
                        assert "11010519491231002X" not in s_val
                        assert "13700137000" not in s_val


def test_end_to_end_db_seeded_gov_policy_and_live_allowlist_update_with_engine(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
) -> None:
    import numpy as np
    from app.detectors import (
        DEFAULT_ID2LABEL,
        HybridDetectorPipeline,
        OnnxNerDetector,
        set_default_pipeline,
    )

    label2id = {lbl: idx for idx, lbl in DEFAULT_ID2LABEL.items()}
    mentions = [
        ("张三", "private_person", 0.96),
        ("12345", "phone", 0.91),
        ("0519-85681234", "phone", 0.94),
        ("96123", "phone", 0.92),
        ("常州市政务服务中心（锦绣路2号）", "private_address", 0.93),
        ("https://www.changzhou.gov.cn", "url", 0.95),
        ("[已脱敏密钥]", "common_secret", 0.95),
    ]
    state = {"text": ""}

    class _Tok:
        def encode(self, text: str):
            state["text"] = text

            class _Enc:
                ids = [0, *[100 + i for i in range(len(text))], 2]
                offsets = [(0, 0), *[(i, i + 1) for i in range(len(text))], (0, 0)]

            return _Enc()

    class _Sess:
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
                    logits[0, pos, label2id[bio]] = float(np.log(prob * 20.0 / (1.0 - prob)))
                else:
                    logits[0, pos, label2id["O"]] = 12.0
            return [logits]

    fake_pipeline = HybridDetectorPipeline(
        onnx_detector=OnnxNerDetector(session=_Sess(), tokenizer=_Tok())
    )
    set_default_pipeline(fake_pipeline)
    try:
        tokens = _seed_role_tokens(client, app, test_settings)
        engine = get_policy_engine()

        with app.state.session_factory() as session:
            gov_snap = engine.resolve_policy(session, "gov_eval_corpus", None)

        # 1. Seeded gov_eval_corpus passes Golden Gov QA case end-to-end
        qa_res = engine.mask_structured_record(
            {
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
                ]
            },
            gov_snap,
        )
        assert (
            qa_res.masked_payload["turns"][0]["content"]
            == "我是<PERSON_1>，身份证 <IDCARD_1>，手机 <PHONE_1>"
        )
        assert qa_res.masked_payload["turns"][1]["content"] == (
            "<PERSON_1>您好，可拨打 12345 或 0519-85681234，"
            "前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理"
        )

        # 2. Before adding 96123 to gov_public_hotline, user-side "96123" is masked as <PHONE_1>;
        #    after adding via POST /api/admin/allowlists, "96123" is exempted!
        before_96123 = engine.mask_text("便民专线 96123", gov_snap)
        assert before_96123.masked_text == "便民专线 <PHONE_1>"

        add_96123 = client.post(
            "/api/admin/allowlists",
            headers={"Authorization": f"Bearer {tokens['OPERATOR']}"},
            json={
                "group_code": "gov_public_hotline",
                "item_name": "地方交通便民短号96123",
                "match_mode": "EXACT",
                "pattern_text": "96123",
                "apply_labels": ["phone"],
            },
        )
        assert add_96123.status_code == 200

        with app.state.session_factory() as session:
            refreshed_snap = engine.resolve_policy(session, "gov_eval_corpus", None)
            custom_fixed_snap = engine.resolve_sandbox_snapshot(
                session,
                policy_code="gov_eval_corpus",
                entity_rules={
                    "common_secret": {
                        "enabled": True,
                        "min_score": 0.80,
                        "action": "FIXED",
                        "replacement": "[已脱敏密钥]",
                    }
                },
            )

        after_96123 = engine.mask_text("便民专线 96123", refreshed_snap)
        assert after_96123.masked_text == "便民专线 96123"

        # 3. Pre-existing custom FIXED replacement token is protected from double-counting/re-masking
        fixed_res = engine.mask_text("历史凭据 [已脱敏密钥] 无需重复统计", custom_fixed_snap)
        assert fixed_res.masked_text == "历史凭据 [已脱敏密钥] 无需重复统计"
        assert fixed_res.hit_counts == {}
    finally:
        set_default_pipeline(None)
        fake_pipeline.shutdown()


