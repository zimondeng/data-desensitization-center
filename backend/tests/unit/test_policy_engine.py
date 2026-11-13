from __future__ import annotations

import hashlib
import numpy as np
import pytest

from app.detectors import (
    AllowlistEntry,
    DEFAULT_ID2LABEL,
    HybridDetectorPipeline,
    OnnxNerDetector,
)
from app.engine import (
    EphemeralScopeDict,
    MaskedSpanOut,
    PolicyEngineService,
    ResolvedPolicySnapshot,
)

_LABEL2ID = {label: idx for idx, label in DEFAULT_ID2LABEL.items()}


class _ScriptedFakeOnnx(OnnxNerDetector):
    """Deterministic fake ONNX detector built on real OnnxNerDetector's BIO decoder."""

    def __init__(self, scripted_mentions: list[tuple[str, str, float]]) -> None:
        self._scripted_mentions = scripted_mentions
        self._current_text = ""

        class _Tok:
            def encode(self_tok, text: str):
                self._current_text = text

                class _Enc:
                    ids = [0, *[100 + i for i in range(len(text))], 2]
                    offsets = [(0, 0), *[(i, i + 1) for i in range(len(text))], (0, 0)]

                return _Enc()

        class _Sess:
            def run(self_sess, output_names, input_feed):
                ids = input_feed["input_ids"]
                logits = np.zeros((1, ids.shape[1], 21), dtype=np.float32)
                tag_at: dict[int, tuple[str, float]] = {}
                # Sort longest mention first in fake tagger so scripted "张三丰" tags cleanly over "张三"
                for substr, lbl, prob in sorted(
                    self._scripted_mentions, key=lambda item: -len(item[0])
                ):
                    start = 0
                    while True:
                        idx = self._current_text.find(substr, start)
                        if idx < 0:
                            break
                        if any((idx + k) in tag_at for k in range(len(substr))):
                            start = idx + 1
                            continue
                        for k in range(len(substr)):
                            bio = f"B-{lbl}" if k == 0 else f"I-{lbl}"
                            tag_at[idx + k] = (bio, prob)
                        start = idx + len(substr)
                for pos in range(ids.shape[1]):
                    char_idx = int(ids[0, pos]) - 100
                    if char_idx in tag_at:
                        bio, prob = tag_at[char_idx]
                        logits[0, pos, _LABEL2ID[bio]] = float(
                            np.log(prob * 20.0 / (1.0 - prob))
                        )
                    else:
                        logits[0, pos, _LABEL2ID["O"]] = 12.0
                return [logits]

        super().__init__(session=_Sess(), tokenizer=_Tok())


def test_mask_text_supports_four_mask_actions_shared_phone_counter_and_post_mask_spans() -> None:
    salt = "unit-test-salt-v1"
    onnx = _ScriptedFakeOnnx(
        [
            ("张三", "private_person", 0.96),
            ("025-88889999", "phone", 0.93),
            ("62220299", "payment_card", 0.92),
            ("sk-prod-998877", "common_secret", 0.95),
            ("zhangsan@example.com", "email", 0.94),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    try:
        engine = PolicyEngineService(pipeline=pipeline, hash_salt=salt)
        snapshot = ResolvedPolicySnapshot(
            policy_id=1,
            policy_code="custom_actions",
            version=1,
            scope_mode="CONVERSATION",
            onnx_variant="int8",
            entity_rules={
                "private_person": {
                    "enabled": True,
                    "min_score": 0.80,
                    "action": "PLACEHOLDER",
                    "prefix": "PERSON",
                },
                "cn_mobile": {
                    "enabled": True,
                    "min_score": 1.00,
                    "action": "PLACEHOLDER",
                    "prefix": "PHONE",
                },
                "phone": {
                    "enabled": True,
                    "min_score": 0.80,
                    "action": "PLACEHOLDER",
                    "prefix": "PHONE",
                },
                "bank_card_luhn": {
                    "enabled": True,
                    "min_score": 1.00,
                    "action": "PARTIAL",
                    "keep_head": 4,
                    "keep_tail": 4,
                },
                "payment_card": {
                    "enabled": True,
                    "min_score": 0.80,
                    "action": "PARTIAL",
                    "keep_head": 4,
                    "keep_tail": 4,
                },
                "common_secret": {
                    "enabled": True,
                    "min_score": 0.80,
                    "action": "FIXED",
                    "replacement": "[REDACTED_SECRET]",
                },
                "email": {
                    "enabled": True,
                    "min_score": 0.80,
                    "action": "HASH",
                },
            },
            field_role_rules={"default_role": "FULL_MASK_WRITE_SCOPE", "rules": []},
            allowlist_groups=[],
            allowlist_entries=(),
        )

        # Valid 16-digit Luhn card: 6222021234567896 (check: Luhn valid? Wait: let's verify exact Luhn 6222020200123452 -> check below)
        # 6222020200001235 -> let's use known valid Luhn 6222021234567898? Let's compute exact Luhn: 6217000010041234567 -> use 6222026006705359550 or 4532015112830366 (Visa test Luhn card!)
        text = (
            "客户张三手机 13812345678，固话 025-88889999，再次确认张三手机 13812345678，"
            "银行卡 4532015112830366，短卡号 62220299，密钥 sk-prod-998877，邮箱 zhangsan@example.com"
        )
        expected_email_hash = (
            "[HASH_"
            + hashlib.sha256((salt + "zhangsan@example.com").encode("utf-8")).hexdigest()[:12]
            + "]"
        )

        res = engine.mask_text(text, snapshot, return_spans=True)

        assert res.masked_text == (
            "客户<PERSON_1>手机 <PHONE_1>，固话 <PHONE_2>，再次确认<PERSON_1>手机 <PHONE_1>，"
            f"银行卡 4532********0366，短卡号 62****99，密钥 [REDACTED_SECRET]，邮箱 {expected_email_hash}"
        )
        assert res.hit_counts == {
            "private_person": 2,
            "cn_mobile": 2,
            "phone": 1,
            "bank_card_luhn": 1,
            "payment_card": 1,
            "common_secret": 1,
            "email": 1,
        }
        assert res.elapsed_ms >= 0
        assert res.sandbox_spans == []
        assert len(res.masked_spans) == 9
        for ms in res.masked_spans:
            assert isinstance(ms, MaskedSpanOut)
            assert res.masked_text[ms.masked_start : ms.masked_end] == ms.placeholder
            assert "张三" not in ms.placeholder
            assert "13812345678" not in ms.placeholder
            assert "sk-prod-998877" not in ms.placeholder
    finally:
        pipeline.shutdown()


def test_scope_modes_conversation_record_and_none_reset_and_leave_zero_residue() -> None:
    onnx = _ScriptedFakeOnnx(
        [
            ("张三", "private_person", 0.96),
            ("李四", "private_person", 0.95),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    try:
        engine = PolicyEngineService(pipeline=pipeline)

        def _make_snap(mode: str) -> ResolvedPolicySnapshot:
            return ResolvedPolicySnapshot(
                policy_id=1,
                policy_code=f"mode_{mode.lower()}",
                version=1,
                scope_mode=mode,  # type: ignore[arg-type]
                onnx_variant="int8",
                entity_rules={
                    "private_person": {
                        "enabled": True,
                        "min_score": 0.80,
                        "action": "PLACEHOLDER",
                        "prefix": "PERSON",
                    }
                },
                field_role_rules={"default_role": "FULL_MASK_WRITE_SCOPE", "rules": []},
                allowlist_groups=[],
                allowlist_entries=(),
            )

        # 1. NONE mode never reuses placeholders even within the same text
        none_snap = _make_snap("NONE")
        none_res = engine.mask_text("张三和李四聊天，张三随后离开", none_snap)
        assert none_res.masked_text == "<PERSON_1>和<PERSON_2>聊天，<PERSON_3>随后离开"

        # 2. RECORD mode deduplicates within a single call, and resets numbering on the next call
        rec_snap = _make_snap("RECORD")
        rec1 = engine.mask_text("张三和李四聊天，张三随后离开", rec_snap)
        rec2 = engine.mask_text("李四独自登记", rec_snap)
        assert rec1.masked_text == "<PERSON_1>和<PERSON_2>聊天，<PERSON_1>随后离开"
        assert rec2.masked_text == "<PERSON_1>独自登记"

        # 3. CONVERSATION mode with explicit EphemeralScopeDict shares across turns, then wipes on exit
        conv_snap = _make_snap("CONVERSATION")
        with EphemeralScopeDict(mode="CONVERSATION") as conv_scope:
            t1 = engine.mask_text("你好我是张三", conv_snap, scope=conv_scope)
            t2 = engine.mask_text("张三委托李四代办", conv_snap, scope=conv_scope)
            assert not conv_scope.is_empty
        assert t1.masked_text == "你好我是<PERSON_1>"
        assert t2.masked_text == "<PERSON_1>委托<PERSON_2>代办"
        assert conv_scope.is_empty
        assert conv_scope.replay_entries() == ()
    finally:
        pipeline.shutdown()


def _build_gov_eval_snapshot() -> ResolvedPolicySnapshot:
    from copy import deepcopy
    from app.db.seed import (
        DEFAULT_ALLOWLIST_SEED_ITEMS,
        GOV_EVAL_CORPUS_ENTITY_RULES,
        GOV_EVAL_CORPUS_FIELD_ROLE_RULES,
    )

    entries = tuple(
        AllowlistEntry(
            group_code=item["group_code"],
            item_name=item["item_name"],
            match_mode=item["match_mode"],
            pattern_text=item["pattern_text"],
            apply_labels=tuple(item["apply_labels_json"]),
            is_enabled=True,
        )
        for item in DEFAULT_ALLOWLIST_SEED_ITEMS
    )
    return ResolvedPolicySnapshot(
        policy_id=2,
        policy_code="gov_eval_corpus",
        version=1,
        scope_mode="CONVERSATION",
        onnx_variant="int8",
        entity_rules=deepcopy(GOV_EVAL_CORPUS_ENTITY_RULES),
        field_role_rules=deepcopy(GOV_EVAL_CORPUS_FIELD_ROLE_RULES),
        allowlist_groups=[
            "gov_public_hotline",
            "gov_public_domain",
            "gov_public_hall",
        ],
        allowlist_entries=entries,
    )


def test_golden_government_qa_and_rag_two_pass_field_role_routing() -> None:
    onnx = _ScriptedFakeOnnx(
        [
            ("张三", "private_person", 0.96),
            ("李四", "private_person", 0.95),
            ("19900307", "private_date", 0.92),
            ("13812345678", "phone", 0.95),
            ("13900139000", "phone", 0.95),
            ("12345", "phone", 0.90),
            ("12329", "phone", 0.90),
            ("0519-85681234", "phone", 0.94),
            ("0519-12329", "phone", 0.91),
            ("常州市政务服务中心（锦绣路2号）", "private_address", 0.93),
            ("钟楼区", "private_address", 0.75),  # below 0.82 min_score
            ("https://www.changzhou.gov.cn", "url", 0.95),
            ("https://gjj.changzhou.gov.cn", "url", 0.95),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    try:
        engine = PolicyEngineService(pipeline=pipeline)
        gov_snap = _build_gov_eval_snapshot()

        # 1. Golden Government QA Acceptance Case (even when expected_output appears BEFORE turns in dict order!)
        golden_payload = {
            "case_code": "CASE_13812345678_PASSTHROUGH",
            "turn_mode": "MULTI_TURN",
            "expected_output": (
                "张三您好，可拨打 12345 或 0519-85681234，"
                "前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理"
            ),
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
        }
        golden_res = engine.mask_structured_record(golden_payload, gov_snap)

        # Input dict must not be mutated in place
        assert golden_payload["turns"][0]["content"].startswith("我是张三")

        # PASSTHROUGH preserves mobile-looking string inside case_code untouched
        assert golden_res.masked_payload["case_code"] == "CASE_13812345678_PASSTHROUGH"
        assert golden_res.masked_payload["turn_mode"] == "MULTI_TURN"

        assert (
            golden_res.masked_payload["turns"][0]["content"]
            == "我是<PERSON_1>，身份证 <IDCARD_1>，手机 <PHONE_1>"
        )
        expected_assistant = (
            "<PERSON_1>您好，可拨打 12345 或 0519-85681234，"
            "前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理"
        )
        assert golden_res.masked_payload["turns"][1]["content"] == expected_assistant
        assert golden_res.masked_payload["expected_output"] == expected_assistant
        assert golden_res.hit_counts == {
            "private_person": 3,
            "cn_id_card": 1,
            "cn_mobile": 1,
        }
        assert golden_res.char_count > 0

        # 2. Checksum verification: 320402199003071235 is valid mod-11, whereas 32040219900307123X has wrong check digit
        valid_id_res = engine.mask_text("身份证 320402199003071235", gov_snap)
        assert valid_id_res.masked_text == "身份证 <IDCARD_1>"
        invalid_id_res = engine.mask_text("身份证 32040219900307123X", gov_snap)
        assert "cn_id_card" not in invalid_id_res.hit_counts

        # 3. API Spec §1.2 RAG multi-turn payload (numbering resets to <PERSON_1>, <PHONE_1> on second record!)
        rag_payload = {
            "case_code": "CASE_001",
            "turn_mode": "MULTI_TURN",
            "input_text": "我叫李四，想查一下我名下在钟楼区的公积金账户提取进度",
            "turns": [
                {"role": "user", "content": "你好，我是李四，手机 13900139000"},
                {
                    "role": "assistant",
                    "content": "李四您好，请拨打住房公积金热线 12329 或登录 https://gjj.changzhou.gov.cn 查询。",
                },
            ],
            "expected_output": "李四可通过 12329 热线或常州市住房公积金网厅查询提取进度。",
            "references": [
                {
                    "doc_name": "公积金办事指南.md",
                    "content": "办理地点：常州市政务服务中心（锦绣路2号）1楼公积金窗口，咨询电话 0519-12329。",
                }
            ],
        }
        rag_res = engine.mask_structured_record(rag_payload, gov_snap)
        assert rag_res.masked_payload == {
            "case_code": "CASE_001",
            "turn_mode": "MULTI_TURN",
            "input_text": "我叫<PERSON_1>，想查一下我名下在钟楼区的公积金账户提取进度",
            "turns": [
                {"role": "user", "content": "你好，我是<PERSON_1>，手机 <PHONE_1>"},
                {
                    "role": "assistant",
                    "content": "<PERSON_1>您好，请拨打住房公积金热线 12329 或登录 https://gjj.changzhou.gov.cn 查询。",
                },
            ],
            "expected_output": "<PERSON_1>可通过 12329 热线或常州市住房公积金网厅查询提取进度。",
            "references": [
                {
                    "doc_name": "公积金办事指南.md",
                    "content": "办理地点：常州市政务服务中心（锦绣路2号）1楼公积金窗口，咨询电话 0519-12329。",
                }
            ],
        }
        assert rag_res.hit_counts == {
            "private_person": 4,
            "cn_mobile": 1,
        }
    finally:
        pipeline.shutdown()


def test_longest_first_replay_placeholder_protection_column_override_and_sandbox_traces() -> None:
    onnx = _ScriptedFakeOnnx(
        [
            ("张三丰", "private_person", 0.97),
            ("张三", "private_person", 0.96),
            ("李四", "private_person", 0.95),
            ("sk-leak-1122", "common_secret", 0.94),
            ("0519-85681234", "phone", 0.93),
            ("025-66667777", "phone", 0.92),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    try:
        engine = PolicyEngineService(pipeline=pipeline)
        gov_snap = _build_gov_eval_snapshot()

        # 1. Shorter entity ("张三") registered BEFORE longer entity ("张三丰") must NOT corrupt "张三丰" in Pass 2;
        #    existing placeholder "<PERSON_1>" must stay protected; leaked high-risk mobile & secret in Pass 2 must be masked,
        #    while non-high-risk landline "025-66667777" in Pass 2 is skipped.
        payload = {
            "turns": [
                {"role": "user", "content": "我是张三，父亲是张三丰"},
                {
                    "role": "assistant",
                    "content": (
                        "请张三丰与张三核对，已有标记 <PERSON_1> 保持不变，"
                        "紧急回执手机 13987654321，临时口令 sk-leak-1122，普通固话 025-66667777"
                    ),
                },
            ]
        }
        res = engine.mask_structured_record(payload, gov_snap)
        assert res.masked_payload["turns"][0]["content"] == "我是<PERSON_1>，父亲是<PERSON_2>"
        assert res.masked_payload["turns"][1]["content"] == (
            "请<PERSON_2>与<PERSON_1>核对，已有标记 <PERSON_1> 保持不变，"
            "紧急回执手机 <PHONE_1>，临时口令 [REDACTED_SECRET]，普通固话 025-66667777"
        )

        # 2. CONVERSATION vs RECORD vs NONE in mask_structured_record
        with EphemeralScopeDict(mode="CONVERSATION") as shared_scope:
            c1 = engine.mask_structured_record(
                {"input_text": "我是张三", "expected_output": "张三你好"},
                gov_snap,
                scope=shared_scope,
            )
            c2 = engine.mask_structured_record(
                {"input_text": "我是李四", "expected_output": "张三和李四同行"},
                gov_snap,
                scope=shared_scope,
            )
        assert c1.masked_payload == {"input_text": "我是<PERSON_1>", "expected_output": "<PERSON_1>你好"}
        assert c2.masked_payload == {
            "input_text": "我是<PERSON_2>",
            "expected_output": "<PERSON_1>和<PERSON_2>同行",
        }

        rec_snap = engine.build_inline_snapshot(
            base_snapshot=gov_snap,
            scope_mode="RECORD",
        )
        with EphemeralScopeDict(mode="CONVERSATION") as ignored_cross_record_scope:
            r1 = engine.mask_structured_record(
                {"input_text": "我是张三", "expected_output": "张三你好"},
                rec_snap,
                scope=ignored_cross_record_scope,
            )
            r2 = engine.mask_structured_record(
                {"input_text": "我是李四", "expected_output": "李四你好"},
                rec_snap,
                scope=ignored_cross_record_scope,
            )
        assert r1.masked_payload == {"input_text": "我是<PERSON_1>", "expected_output": "<PERSON_1>你好"}
        # Numbering resets to <PERSON_1> on second record under RECORD scope_mode!
        assert r2.masked_payload == {"input_text": "我是<PERSON_1>", "expected_output": "<PERSON_1>你好"}

        none_snap = engine.build_inline_snapshot(
            base_snapshot=gov_snap,
            scope_mode="NONE",
        )
        n_res = engine.mask_structured_record(
            {
                "input_text": "我是张三，又是张三",
                "expected_output": "张三回执手机 13987654321",
            },
            none_snap,
        )
        assert n_res.masked_payload == {
            "input_text": "我是<PERSON_1>，又是<PERSON_2>",
            # NONE mode disables user-scope literal replay, only scanning high-risk labels in Pass 2
            "expected_output": "张三回执手机 <PHONE_1>",
        }

        # 3. column_role_override (for #6 batch-jobs) + Chinese keys + non-string types + sandbox_trace=True
        row_payload = {
            "工单号": "WO_13812345678",
            "客户诉求": "我是张三，热线 0519-85681234，手机 13812345678",
            "坐席答复": "张三您好，请拨打 0519-85681234",
            "重试次数": 2,
            "已归档": False,
            "扩展备注": None,
        }
        row_res = engine.mask_structured_record(
            row_payload,
            gov_snap,
            column_role_override={
                "工单号": "PASSTHROUGH",
                "客户诉求": "FULL_MASK_WRITE_SCOPE",
                "坐席答复": "REPLAY_SCOPE_AND_HIGH_RISK",
            },
            sandbox_trace=True,
        )
        assert row_res.masked_payload == {
            "工单号": "WO_13812345678",
            "客户诉求": "我是<PERSON_1>，热线 0519-85681234，手机 <PHONE_1>",
            "坐席答复": "<PERSON_1>您好，请拨打 0519-85681234",
            "重试次数": 2,
            "已归档": False,
            "扩展备注": None,
        }
        query_traces = row_res.sandbox_field_traces["$['客户诉求']"]
        assert [(t.kind, t.label, t.replacement, t.allowlist_group) for t in query_traces] == [
            ("masked", "private_person", "<PERSON_1>", None),
            ("exempted", "phone", None, "gov_public_hotline"),
            ("masked", "cn_mobile", "<PHONE_1>", None),
        ]
        answer_traces = row_res.sandbox_field_traces["$['坐席答复']"]
        assert [(t.kind, t.label, t.replacement) for t in answer_traces] == [
            ("masked", "private_person", "<PERSON_1>"),
        ]
    finally:
        pipeline.shutdown()


def test_engine_validation_rejects_invalid_jsonpath_regex_and_policy_parameters_with_40001() -> None:
    from app.common.errors import BadRequestError

    engine = PolicyEngineService()

    for bad_jsonpath in (
        "",
        "not_a_jsonpath",
        "$$foo",
        "$[unclosed",
        "$.turns[?(@.role=='unterminated)]",
        "$.a..",
    ):
        with pytest.raises(BadRequestError) as exc_info:
            engine.build_inline_snapshot(
                field_role_rules={
                    "default_role": "FULL_MASK_WRITE_SCOPE",
                    "rules": [{"jsonpath": bad_jsonpath, "role": "PASSTHROUGH"}],
                }
            )
        assert exc_info.value.code == 40001

    with pytest.raises(BadRequestError) as exc_role:
        engine.build_inline_snapshot(
            field_role_rules={
                "default_role": "UNKNOWN_ROLE",
                "rules": [],
            }
        )
    assert exc_role.value.code == 40001

    with pytest.raises(BadRequestError) as exc_scope:
        engine.build_inline_snapshot(scope_mode="GLOBAL_FOREVER")
    assert exc_scope.value.code == 40001

    with pytest.raises(BadRequestError) as exc_variant:
        engine.build_inline_snapshot(onnx_variant="int4")
    assert exc_variant.value.code == 40001

    with pytest.raises(BadRequestError) as exc_label:
        engine.build_inline_snapshot(
            entity_rules={"unknown_label": {"enabled": True, "min_score": 0.8, "action": "PLACEHOLDER"}}
        )
    assert exc_label.value.code == 40001

    with pytest.raises(BadRequestError) as exc_action:
        engine.build_inline_snapshot(
            entity_rules={"private_person": {"enabled": True, "min_score": 0.8, "action": "REVERSIBLE_AES"}}
        )
    assert exc_action.value.code == 40001

    with pytest.raises(BadRequestError) as exc_score:
        engine.build_inline_snapshot(
            entity_rules={"private_person": {"enabled": True, "min_score": 1.5, "action": "PLACEHOLDER"}}
        )
    assert exc_score.value.code == 40001

    with pytest.raises(BadRequestError) as exc_regex:
        engine.build_inline_snapshot(
            allowlist_entries=(
                AllowlistEntry(
                    group_code="g1",
                    item_name="bad",
                    match_mode="REGEX",
                    pattern_text="[unclosed(",
                    apply_labels=("phone",),
                ),
            )
        )
    assert exc_regex.value.code == 40001


def test_array_jsonpath_rules_and_single_index_leaf_resolution() -> None:
    from types import SimpleNamespace

    from app.engine.field_router import _extract_datum_leaf_keys

    # 1. Compatibility regression: path objects exposing `.index` (int) rather than `.indices`
    arr = ["13800138000", "13900139000", "13700137000"]
    datum_pos = SimpleNamespace(
        value=arr[0],
        path=SimpleNamespace(index=0),
        context=SimpleNamespace(value=arr),
    )
    datum_neg = SimpleNamespace(
        value=arr[-1],
        path=SimpleNamespace(index=-1),
        context=SimpleNamespace(value=arr),
    )
    assert _extract_datum_leaf_keys(datum_pos) == [(id(arr), 0)]
    assert _extract_datum_leaf_keys(datum_neg) == [(id(arr), 2)]

    # 2. End-to-end array JSONPath rules (`[*]`, `[0]`, `[-1]`, `[0:2]`) override default_role
    pipeline = HybridDetectorPipeline(onnx_detector=_ScriptedFakeOnnx([]))
    try:
        engine = PolicyEngineService(pipeline=pipeline, hash_salt="unit-salt")
        snapshot = engine.build_inline_snapshot(
            scope_mode="CONVERSATION",
            entity_rules={
                "phone": {"enabled": True, "min_score": 0.5, "action": "PLACEHOLDER"},
                "cn_mobile": {"enabled": True, "min_score": 0.5, "action": "PLACEHOLDER"},
            },
            field_role_rules={
                "default_role": "FULL_MASK_WRITE_SCOPE",
                "rules": [
                    {"jsonpath": "$.items[*]", "role": "PASSTHROUGH"},
                    {"jsonpath": "$.first_only[0]", "role": "PASSTHROUGH"},
                    {"jsonpath": "$.last_only[-1]", "role": "PASSTHROUGH"},
                    {"jsonpath": "$.slice_only[0:2]", "role": "PASSTHROUGH"},
                ],
            },
        )
        payload = {
            "items": ["13811112222", "13911112222"],
            "first_only": ["13822223333", "13922223333"],
            "last_only": ["13833334444", "13933334444"],
            "slice_only": ["13844445555", "13944445555", "13744445555"],
        }
        res = engine.mask_structured_record(payload, snapshot)
        assert res.masked_payload["items"] == ["13811112222", "13911112222"]
        assert res.masked_payload["first_only"][0] == "13822223333"
        assert res.masked_payload["first_only"][1] == "<PHONE_1>"
        assert res.masked_payload["last_only"][0] == "<PHONE_2>"
        assert res.masked_payload["last_only"][1] == "13933334444"
        assert res.masked_payload["slice_only"][:2] == ["13844445555", "13944445555"]
        assert res.masked_payload["slice_only"][2] == "<PHONE_3>"
    finally:
        pipeline.shutdown()



