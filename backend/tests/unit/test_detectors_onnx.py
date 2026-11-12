from dataclasses import dataclass
from pathlib import Path
import numpy as np
import pytest

from app.detectors import DetectedSpan, DetectorNotReadyError
from app.detectors.onnx_detector import DEFAULT_ID2LABEL, OnnxNerDetector

LABEL2ID = {label: idx for idx, label in DEFAULT_ID2LABEL.items()}


@dataclass
class FakeEncoding:
    ids: list[int]
    offsets: list[tuple[int, int]]


class CharLevelFakeTokenizer:
    """Deterministic character-level tokenizer matching HuggingFace tokenizers.Encoding contract.
    Encodes BOS (id=0, offset=(0,0)), each char i as id=(100 + i), and EOS (id=2, offset=(0,0)).
    """

    def encode(self, text: str) -> FakeEncoding:
        ids = [0]
        offsets: list[tuple[int, int]] = [(0, 0)]
        for idx, _ in enumerate(text):
            ids.append(100 + idx)
            offsets.append((idx, idx + 1))
        ids.append(2)
        offsets.append((0, 0))
        return FakeEncoding(ids=ids, offsets=offsets)


class SpanScriptedFakeSession:
    """Deterministic fake ONNX session mapping character token IDs (100 + char_idx) to BIO logits."""

    def __init__(self, tag_by_char_idx: dict[int, tuple[str, float]]) -> None:
        self._tag_by_char_idx = tag_by_char_idx
        self.calls: list[dict[str, np.ndarray]] = []

    @staticmethod
    def _logit_for_prob(target_prob: float, num_classes: int = 21) -> float:
        # With 1 target logit = x and (num_classes - 1) other logits = 0:
        # exp(x) / (exp(x) + (num_classes - 1)) = target_prob  =>  x = ln(p * (K - 1) / (1 - p))
        return float(np.log(target_prob * (num_classes - 1) / (1.0 - target_prob)))

    def run(self, output_names: list[str], input_feed: dict[str, np.ndarray]) -> list[np.ndarray]:
        self.calls.append({k: v.copy() for k, v in input_feed.items()})
        input_ids = input_feed["input_ids"]
        seq_len = input_ids.shape[1]
        logits = np.zeros((1, seq_len, 21), dtype=np.float32)

        for pos in range(seq_len):
            tok_id = int(input_ids[0, pos])
            char_idx = tok_id - 100
            if char_idx in self._tag_by_char_idx:
                bio_tag, prob = self._tag_by_char_idx[char_idx]
                logits[0, pos, LABEL2ID[bio_tag]] = self._logit_for_prob(prob)
            else:
                logits[0, pos, LABEL2ID["O"]] = 12.0
        return [logits]


def test_onnx_bio_decoding_unicode_offsets_min_score_and_thresholds() -> None:
    text = "🙂联系人张三，秘钥sk-9，忽略王五"
    # Emoji '🙂' is at index 0; '张三' at 4..6; 'sk-9' at 9..13 (orphan I- start); '王五' at 16..18 (low score)
    zhang_start = text.index("张三")
    secret_start = text.index("sk-9")
    wang_start = text.index("王五")

    tag_plan: dict[int, tuple[str, float]] = {
        zhang_start: ("B-private_person", 0.96),
        zhang_start + 1: ("I-private_person", 0.87),
        # Orphan I- tag without preceding B- starts a new span per bio-offset-consistency-v1
        secret_start: ("I-common_secret", 0.93),
        secret_start + 1: ("I-common_secret", 0.91),
        secret_start + 2: ("I-common_secret", 0.95),
        secret_start + 3: ("I-common_secret", 0.92),
        # Below 0.80 threshold -> must be dropped
        wang_start: ("B-private_person", 0.72),
        wang_start + 1: ("I-private_person", 0.65),
    }

    detector = OnnxNerDetector(
        session=SpanScriptedFakeSession(tag_plan),
        tokenizer=CharLevelFakeTokenizer(),
    )
    try:
        spans = detector.detect(
            text,
            label_thresholds={"private_person": 0.80, "common_secret": 0.80},
        )
    finally:
        detector.shutdown()

    assert len(spans) == 2
    assert all(isinstance(s, DetectedSpan) for s in spans)
    assert spans[0].label == "private_person"
    assert text[spans[0].start : spans[0].end] == "张三"
    assert spans[0].detector == "onnx"
    assert spans[0].score == pytest.approx(0.87, abs=1e-4)

    assert spans[1].label == "common_secret"
    assert text[spans[1].start : spans[1].end] == "sk-9"
    assert spans[1].score == pytest.approx(0.91, abs=1e-4)


def test_onnx_refines_ip_address_and_dynamic_url_boundaries() -> None:
    text = "源地址[192.168.10.25:8080]，请访问(https://www.changzhou.gov.cn/bszn?id=1)，谢谢。"
    noisy_ip = "[192.168.10.25:8080]"
    ip_start = text.index(noisy_ip)
    partial_noisy_url = "(https://www.changzhou.gov"
    url_start = text.index(partial_noisy_url)

    tag_plan: dict[int, tuple[str, float]] = {}
    for offset in range(len(noisy_ip)):
        tag_plan[ip_start + offset] = ("B-ip_address" if offset == 0 else "I-ip_address", 0.95)
    for offset in range(len(partial_noisy_url)):
        tag_plan[url_start + offset] = ("B-url" if offset == 0 else "I-url", 0.94)

    detector = OnnxNerDetector(
        session=SpanScriptedFakeSession(tag_plan),
        tokenizer=CharLevelFakeTokenizer(),
    )
    try:
        spans = detector.detect(
            text,
            label_thresholds={"ip_address": 0.80, "url": 0.82},
        )
    finally:
        detector.shutdown()

    assert [(s.label, text[s.start : s.end]) for s in spans] == [
        ("ip_address", "192.168.10.25"),
        ("url", "https://www.changzhou.gov.cn/bszn?id=1"),
    ]


def test_onnx_missing_weights_and_shutdown_pool_raise_structured_error_without_plaintext_leak(
    tmp_path: Path,
) -> None:
    secret_input = "绝密申请人王小明身份证32040219900307118X手机号13812345678"
    missing_detector = OnnxNerDetector(models_dir=tmp_path / "nonexistent-models")
    try:
        assert missing_detector.is_ready("int8") is False
        with pytest.raises(DetectorNotReadyError) as exc_info:
            missing_detector.detect(secret_input, variant="int8")
        err_msg = f"{exc_info.value!s} {exc_info.value!r}"
        assert "王小明" not in err_msg
        assert "32040219900307118X" not in err_msg
        assert "13812345678" not in err_msg
    finally:
        missing_detector.shutdown()

    ready_detector = OnnxNerDetector(
        session=SpanScriptedFakeSession({}),
        tokenizer=CharLevelFakeTokenizer(),
    )
    assert ready_detector.is_ready("int8") is True
    ready_detector.shutdown()
    assert ready_detector.is_ready("int8") is False

    with pytest.raises(DetectorNotReadyError) as pool_exc:
        ready_detector.detect(secret_input, variant="int8")
    assert "王小明" not in str(pool_exc.value)
    assert "32040219900307118X" not in str(pool_exc.value)


def test_onnx_sliding_window_512_128_merges_entity_crossing_window_boundary() -> None:
    boundary_addr = "常州市钟楼区金色新城8幢1502"  # 16 chars crossing content index 510 (502..518)
    tail_person = "李四"
    prefix = "文" * 502
    middle = "字" * (610 - 502 - len(boundary_addr))
    suffix = "末" * (650 - 610 - len(tail_person))
    text = prefix + boundary_addr + middle + tail_person + suffix
    assert len(text) == 650
    assert text[502:518] == boundary_addr
    assert text[610:612] == tail_person

    class WindowAwareFakeSession:
        def __init__(self) -> None:
            self.window_shapes: list[tuple[int, int]] = []
            self.window_first_last_char: list[tuple[int, int]] = []

        def run(self, output_names: list[str], input_feed: dict[str, np.ndarray]) -> list[np.ndarray]:
            ids = input_feed["input_ids"]
            if ids.shape[1] > 512:
                raise ValueError(f"Window length {ids.shape[1]} exceeds 512 limit")
            win_idx = len(self.window_shapes)
            self.window_shapes.append(ids.shape)
            content_chars = [int(t) - 100 for t in ids[0] if int(t) >= 100]
            self.window_first_last_char.append((content_chars[0], content_chars[-1]))

            logits = np.zeros((1, ids.shape[1], 21), dtype=np.float32)
            for pos in range(ids.shape[1]):
                char_idx = int(ids[0, pos]) - 100
                if win_idx == 0 and 502 <= char_idx < 510:
                    tag = "B-private_address" if char_idx == 502 else "I-private_address"
                    logits[0, pos, LABEL2ID[tag]] = SpanScriptedFakeSession._logit_for_prob(0.88)
                elif win_idx == 1 and 505 <= char_idx < 518:
                    # Starts slightly later in window 1 (505..518) to verify union merge [502, 518)
                    tag = "B-private_address" if char_idx == 505 else "I-private_address"
                    logits[0, pos, LABEL2ID[tag]] = SpanScriptedFakeSession._logit_for_prob(0.94)
                elif 610 <= char_idx < 612:
                    tag = "B-private_person" if char_idx == 610 else "I-private_person"
                    logits[0, pos, LABEL2ID[tag]] = SpanScriptedFakeSession._logit_for_prob(0.92)
                else:
                    logits[0, pos, LABEL2ID["O"]] = 12.0
            return [logits]

    fake_sess = WindowAwareFakeSession()
    detector = OnnxNerDetector(session=fake_sess, tokenizer=CharLevelFakeTokenizer())
    try:
        spans = detector.detect(
            text,
            variant="int8",
            label_thresholds={"private_address": 0.80, "private_person": 0.80},
        )
    finally:
        detector.shutdown()

    # Window 0 covers content 0..509 (len 510 + BOS/EOS = 512); Window 1 starts at stride 382 (overlap 128)
    assert fake_sess.window_shapes == [(1, 512), (1, 270)]
    assert fake_sess.window_first_last_char == [(0, 509), (382, 649)]
    assert [(s.label, s.start, s.end, text[s.start : s.end]) for s in spans] == [
        ("private_address", 502, 518, boundary_addr),
        ("private_person", 610, 612, tail_person),
    ]
    assert spans[0].score == pytest.approx(0.94, abs=1e-4)


def test_onnx_fp16_variant_pads_static_512_and_crops_padded_logits() -> None:
    text = "访客赵六登记"
    zhao_start = text.index("赵六")
    expected_valid_len = len(text) + 2  # BOS + chars + EOS

    class StaticFp16FakeSession:
        def __init__(self) -> None:
            self.last_feed: dict[str, np.ndarray] | None = None

        def run(self, output_names: list[str], input_feed: dict[str, np.ndarray]) -> list[np.ndarray]:
            self.last_feed = {k: v.copy() for k, v in input_feed.items()}
            ids = input_feed["input_ids"]
            if ids.shape != (1, 512):
                raise ValueError(f"fp16 static512 requires (1, 512), got {ids.shape}")
            logits = np.zeros((1, 512, 21), dtype=np.float16)
            for pos in range(512):
                if pos >= expected_valid_len:
                    # Emit high person logits on padded positions to prove [:n] cropping drops them
                    logits[0, pos, LABEL2ID["B-private_person"]] = np.float16(10.0)
                    continue
                char_idx = int(ids[0, pos]) - 100
                if char_idx == zhao_start:
                    logits[0, pos, LABEL2ID["B-private_person"]] = np.float16(8.0)
                elif char_idx == zhao_start + 1:
                    logits[0, pos, LABEL2ID["I-private_person"]] = np.float16(8.0)
                else:
                    logits[0, pos, LABEL2ID["O"]] = np.float16(8.0)
            return [logits]

    fp16_sess = StaticFp16FakeSession()
    detector = OnnxNerDetector(
        sessions={"fp16": fp16_sess},
        tokenizer=CharLevelFakeTokenizer(),
    )
    try:
        spans = detector.detect(
            text,
            variant="fp16",
            label_thresholds={"private_person": 0.80},
        )
    finally:
        detector.shutdown()

    assert fp16_sess.last_feed is not None
    assert fp16_sess.last_feed["input_ids"].shape == (1, 512)
    assert np.all(fp16_sess.last_feed["input_ids"][0, expected_valid_len:] == 1)
    assert np.all(fp16_sess.last_feed["attention_mask"][0, :expected_valid_len] == 1)
    assert np.all(fp16_sess.last_feed["attention_mask"][0, expected_valid_len:] == 0)
    assert np.all(fp16_sess.last_feed["token_type_ids"] == 0)
    assert [(s.label, text[s.start : s.end]) for s in spans] == [("private_person", "赵六")]


def test_onnx_url_refinement_does_not_swallow_comma_or_quote_delimited_ascii_fields(
    tmp_path: Path,
) -> None:
    text = "url='https://www.changzhou.gov.cn/bszn',phone=13812345678;mail=a@b.com"
    raw_tagged = "https://www.changzhou.gov.cn/bszn',"
    url_start = text.index(raw_tagged)

    tag_plan = {
        url_start + k: ("B-url" if k == 0 else "I-url", 0.95)
        for k in range(len(raw_tagged))
    }

    # Also exercise fp32 variant + real HuggingFace Tokenizer.from_file + labels.json loading
    from tokenizers import Tokenizer
    from tokenizers.models import WordLevel
    from tokenizers.pre_tokenizers import Split

    fp32_dir = tmp_path / "fp32"
    fp32_dir.mkdir(parents=True)
    vocab = {"<unk>": 3, "<s>": 0, "<pad>": 1, "</s>": 2}
    for idx, ch in enumerate(sorted(set(text))):
        vocab[ch] = 10 + idx
    tok = Tokenizer(WordLevel(vocab=vocab, unk_token="<unk>"))
    tok.pre_tokenizer = Split("", behavior="isolated")
    tok.save(str(fp32_dir / "tokenizer.json"))
    import json

    (fp32_dir / "labels.json").write_text(
        json.dumps({str(k): v for k, v in DEFAULT_ID2LABEL.items()}),
        encoding="utf-8",
    )

    class DiskTokFp32Session:
        def run(self, output_names: list[str], input_feed: dict[str, np.ndarray]) -> list[np.ndarray]:
            seq_len = input_feed["input_ids"].shape[1]
            logits = np.zeros((1, seq_len, 21), dtype=np.float32)
            for pos in range(seq_len):
                if pos in tag_plan:
                    bio, prob = tag_plan[pos]
                    logits[0, pos, LABEL2ID[bio]] = SpanScriptedFakeSession._logit_for_prob(prob)
                else:
                    logits[0, pos, LABEL2ID["O"]] = 12.0
            return [logits]

    detector = OnnxNerDetector(
        models_dir=tmp_path,
        session_factory=lambda variant: DiskTokFp32Session(),
    )
    try:
        spans = detector.detect(text, variant="fp32", label_thresholds={"url": 0.80})
    finally:
        detector.shutdown()

    assert [(s.label, text[s.start : s.end]) for s in spans] == [
        ("url", "https://www.changzhou.gov.cn/bszn"),
    ]


