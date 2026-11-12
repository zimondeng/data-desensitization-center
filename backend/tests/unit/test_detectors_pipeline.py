from pathlib import Path
import numpy as np
import pytest

from app.detectors import (
    AllowlistEntry,
    AllowlistFilter,
    DEFAULT_ID2LABEL,
    DetectedSpan,
    DetectorNotReadyError,
    ExemptedSpan,
    HybridDetectorPipeline,
    InvalidAllowlistPatternError,
    OnnxNerDetector,
    find_matching_allowlist_entries,
    is_onnx_ready,
    validate_allowlist_pattern,
)


def test_allowlist_filter_supports_exact_prefix_suffix_url_hostname_and_regex_modes() -> None:
    text = (
        "市民可拨打 12345 或 0519-85681234，"
        "访问 https://www.changzhou.gov.cn/bszn?dept=gjj ，"
        "前往常州市政务服务中心（锦绣路2号），"
        "切勿泄露个人手机 13812345678 或钓鱼网 https://evilgov.cn/login"
    )
    entries = (
        AllowlistEntry(
            group_code="gov_public_hotline",
            item_name="全国政务便民短号12345",
            match_mode="EXACT",
            pattern_text="12345",
            apply_labels=("phone",),
        ),
        AllowlistEntry(
            group_code="gov_public_hotline",
            item_name="常州区号政务固话前缀",
            match_mode="PREFIX",
            pattern_text="0519-",
            apply_labels=("phone",),
        ),
        AllowlistEntry(
            group_code="gov_public_domain",
            item_name="政务域名后缀豁免",
            match_mode="SUFFIX",
            pattern_text="gov.cn",
            apply_labels=("url",),
        ),
        AllowlistEntry(
            group_code="gov_public_hall",
            item_name="政务大厅通用地址特征",
            match_mode="REGEX",
            pattern_text=r"(政务服务中心|行政审批局|市民中心)",
            apply_labels=("private_address",),
        ),
        AllowlistEntry(
            group_code="disabled_group",
            item_name="已禁用规则不生效",
            match_mode="PREFIX",
            pattern_text="138",
            apply_labels=("cn_mobile", "phone"),
            is_enabled=False,
        ),
    )

    def span_of(substr: str, label: str, detector: str = "onnx") -> DetectedSpan:
        idx = text.index(substr)
        return DetectedSpan(
            label=label,
            start=idx,
            end=idx + len(substr),
            score=1.0 if detector == "regex" else 0.92,
            detector=detector,  # type: ignore[arg-type]
        )

    candidates = [
        span_of("12345", "phone"),
        span_of("0519-85681234", "phone"),
        span_of("https://www.changzhou.gov.cn/bszn?dept=gjj", "url"),
        span_of("常州市政务服务中心（锦绣路2号）", "private_address"),
        span_of("13812345678", "cn_mobile", detector="regex"),
        span_of("https://evilgov.cn/login", "url"),
    ]

    kept, exempted = AllowlistFilter().filter_spans(
        text,
        candidates,
        entries,
        active_groups={"gov_public_hotline", "gov_public_domain", "gov_public_hall", "disabled_group"},
        trace_exemptions=True,
    )

    assert [(s.label, text[s.start : s.end]) for s in kept] == [
        ("cn_mobile", "13812345678"),
        ("url", "https://evilgov.cn/login"),
    ]
    assert [
        (e.label, text[e.start : e.end], e.group_code, e.rule_name)
        for e in exempted
    ] == [
        ("phone", "12345", "gov_public_hotline", "全国政务便民短号12345"),
        ("phone", "0519-85681234", "gov_public_hotline", "常州区号政务固话前缀"),
        (
            "url",
            "https://www.changzhou.gov.cn/bszn?dept=gjj",
            "gov_public_domain",
            "政务域名后缀豁免",
        ),
        (
            "private_address",
            "常州市政务服务中心（锦绣路2号）",
            "gov_public_hall",
            "政务大厅通用地址特征",
        ),
    ]
    assert all(isinstance(e, ExemptedSpan) for e in exempted)

    # Inline allowlist tester helper respects apply_labels and active_groups
    matched = find_matching_allowlist_entries(
        "0519-85681234",
        "phone",
        entries,
        active_groups={"gov_public_hotline"},
    )
    assert [m.item_name for m in matched] == ["常州区号政务固话前缀"]
    assert find_matching_allowlist_entries("0519-85681234", "cn_mobile", entries) == []


def test_allowlist_invalid_regex_raises_structured_error_without_input_plaintext() -> None:
    with pytest.raises(InvalidAllowlistPatternError):
        validate_allowlist_pattern("REGEX", "[unterminated(")

    bad_entry = AllowlistEntry(
        group_code="gov_public_hotline",
        item_name="损坏的正则",
        match_mode="REGEX",
        pattern_text="[unterminated(",
        apply_labels=("phone",),
    )
    secret_text = "敏感电话13812345678与姓名王五"
    span = DetectedSpan(label="phone", start=4, end=15, score=0.9, detector="onnx")

    with pytest.raises(InvalidAllowlistPatternError) as exc_info:
        AllowlistFilter().filter_spans(secret_text, [span], [bad_entry])

    assert "13812345678" not in str(exc_info.value)
    assert "王五" not in str(exc_info.value)


_LABEL2ID = {label: idx for idx, label in DEFAULT_ID2LABEL.items()}

SEED_ALLOWLIST_ENTRIES: tuple[AllowlistEntry, ...] = (
    AllowlistEntry(
        group_code="gov_public_hotline",
        item_name="全国政务与公共服务5位短号",
        match_mode="REGEX",
        pattern_text=r"^(12345|12333|12329|12366|12315|12348|12123|110|119|120|122)$",
        apply_labels=("phone",),
    ),
    AllowlistEntry(
        group_code="gov_public_hotline",
        item_name="400/800公共服务热线与带区号政务固话",
        match_mode="REGEX",
        pattern_text=r"^(0\d{2,3}-?\d{7,8}|[48]00-?\d{3}-?\d{4})$",
        apply_labels=("phone",),
    ),
    AllowlistEntry(
        group_code="gov_public_domain",
        item_name="中国政府网及各级政务域名",
        match_mode="REGEX",
        pattern_text=r"^https?://([a-zA-Z0-9-]+\.)*gov\.cn(/.*)?$",
        apply_labels=("url",),
    ),
    AllowlistEntry(
        group_code="gov_public_hall",
        item_name="政务服务中心与便民中心通用办公地址特征",
        match_mode="REGEX",
        pattern_text=r"(政务服务中心|行政审批局|市民中心|便民服务中心|公积金管理中心|社保中心|车管所|不动产登记交易中心)",
        apply_labels=("private_address",),
    ),
)

FULL_POLICY_RULES: dict[str, dict[str, object]] = {
    "private_person": {"enabled": True, "min_score": 0.80},
    "phone": {"enabled": True, "min_score": 0.80},
    "email": {"enabled": True, "min_score": 0.80},
    "private_address": {"enabled": True, "min_score": 0.80},
    "private_date": {"enabled": True, "min_score": 0.80},
    "account": {"enabled": True, "min_score": 0.80},
    "payment_card": {"enabled": True, "min_score": 0.80},
    "ip_address": {"enabled": True, "min_score": 0.80},
    "url": {"enabled": True, "min_score": 0.82},
    "common_secret": {"enabled": True, "min_score": 0.80},
    "cn_id_card": {"enabled": True, "min_score": 1.00},
    "cn_uscc": {"enabled": True, "min_score": 1.00},
    "cn_mobile": {"enabled": True, "min_score": 1.00},
    "bank_card_luhn": {"enabled": True, "min_score": 1.00},
}


class _SubstringFakeOnnx(OnnxNerDetector):
    """Deterministic fake ONNX detector built on top of real OnnxNerDetector's BIO decoder."""

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
                for substr, lbl, prob in self._scripted_mentions:
                    start = 0
                    while True:
                        idx = self._current_text.find(substr, start)
                        if idx < 0:
                            break
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


def test_pipeline_resolves_overlapping_spans_by_length_regex_priority_score_and_start() -> None:
    text = "我是张三，身份证 32040219900307118X，手机 13812345678，账号 user_01"
    # ONNX predicts:
    # - '张三' as private_person
    # - '19900307' (8 chars inside 18-char cn_id_card) as private_date -> must lose to longer cn_id_card
    # - '13812345678' (11 chars, equal length to cn_mobile) as phone -> must lose to regex priority
    # - 'user_01' as account
    onnx = _SubstringFakeOnnx(
        [
            ("张三", "private_person", 0.95),
            ("19900307", "private_date", 0.98),
            ("13812345678", "phone", 0.99),
            ("user_01", "account", 0.91),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    try:
        result = pipeline.detect(text, entity_rules=FULL_POLICY_RULES)
    finally:
        pipeline.shutdown()

    assert [
        (s.label, text[s.start : s.end], s.detector)
        for s in result.spans
    ] == [
        ("private_person", "张三", "onnx"),
        ("cn_id_card", "32040219900307118X", "regex"),
        ("cn_mobile", "13812345678", "regex"),
        ("account", "user_01", "onnx"),
    ]
    assert result.exempted_spans == []


def test_pipeline_skips_onnx_when_only_regex_labels_active_unless_require_onnx(
    tmp_path: Path,
) -> None:
    empty_models = tmp_path / "missing-astrlink"
    assert is_onnx_ready("int8", models_dir=empty_models) is False

    pipeline = HybridDetectorPipeline(models_dir=empty_models)
    try:
        assert pipeline.is_onnx_ready("int8") is False

        # High-risk regex-only pass works without ONNX model files
        res = pipeline.detect(
            "身份证 32040219900307118X 手机 13812345678",
            entity_rules=FULL_POLICY_RULES,
            only_labels={"cn_id_card", "cn_mobile", "bank_card_luhn"},
        )
        assert [s.label for s in res.spans] == ["cn_id_card", "cn_mobile"]

        # Explicit require_onnx=True forces readiness check even on regex-only labels
        with pytest.raises(DetectorNotReadyError):
            pipeline.detect(
                "身份证 32040219900307118X",
                entity_rules=FULL_POLICY_RULES,
                only_labels={"cn_id_card"},
                require_onnx=True,
            )

        # Active ONNX label with missing model raises DetectorNotReadyError
        with pytest.raises(DetectorNotReadyError):
            pipeline.detect(
                "我是张三",
                entity_rules=FULL_POLICY_RULES,
            )
    finally:
        pipeline.shutdown()


def test_pipeline_golden_government_qa_acceptance_with_seed_allowlist_and_sandbox_trace() -> None:
    user_text = "我是张三，身份证 32040219900307118X，手机 13812345678"
    assistant_text = (
        "张三您好，可拨打 12345 或 0519-85681234，"
        "前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理"
    )

    onnx = _SubstringFakeOnnx(
        [
            ("张三", "private_person", 0.96),
            ("19900307", "private_date", 0.93),
            ("13812345678", "phone", 0.95),
            ("12345", "phone", 0.90),
            ("0519-85681234", "phone", 0.94),
            ("常州市政务服务中心（锦绣路2号）", "private_address", 0.91),
            ("https://www.changzhou.gov.cn", "url", 0.95),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    try:
        user_res = pipeline.detect(
            user_text,
            entity_rules=FULL_POLICY_RULES,
            allowlist_entries=SEED_ALLOWLIST_ENTRIES,
            trace_exemptions=True,
        )
        assert [(s.label, user_text[s.start : s.end]) for s in user_res.spans] == [
            ("private_person", "张三"),
            ("cn_id_card", "32040219900307118X"),
            ("cn_mobile", "13812345678"),
        ]
        assert user_res.exempted_spans == []

        assistant_res = pipeline.detect(
            assistant_text,
            entity_rules=FULL_POLICY_RULES,
            allowlist_entries=SEED_ALLOWLIST_ENTRIES,
            trace_exemptions=True,
        )
        # Only '张三' is detected for masking; all 4 gov public items are preserved!
        assert [(s.label, assistant_text[s.start : s.end]) for s in assistant_res.spans] == [
            ("private_person", "张三"),
        ]
        assert [
            (e.label, assistant_text[e.start : e.end], e.group_code, e.rule_name)
            for e in assistant_res.exempted_spans
        ] == [
            ("phone", "12345", "gov_public_hotline", "全国政务与公共服务5位短号"),
            ("phone", "0519-85681234", "gov_public_hotline", "400/800公共服务热线与带区号政务固话"),
            (
                "private_address",
                "常州市政务服务中心（锦绣路2号）",
                "gov_public_hall",
                "政务服务中心与便民中心通用办公地址特征",
            ),
            (
                "url",
                "https://www.changzhou.gov.cn",
                "gov_public_domain",
                "中国政府网及各级政务域名",
            ),
        ]

        # Without trace_exemptions, exempted_spans stays empty while preserving identical final spans
        assistant_untraced = pipeline.detect(
            assistant_text,
            entity_rules=FULL_POLICY_RULES,
            allowlist_entries=SEED_ALLOWLIST_ENTRIES,
            trace_exemptions=False,
        )
        assert assistant_untraced.spans == assistant_res.spans
        assert assistant_untraced.exempted_spans == []
    finally:
        pipeline.shutdown()

