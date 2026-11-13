from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Protocol

import numpy as np

from app.detectors.types import DetectedSpan, DetectorNotReadyError, ONNX_ENTITY_LABELS

DEFAULT_ID2LABEL: dict[int, str] = {
    0: "O",
    1: "B-email",
    2: "I-email",
    3: "B-phone",
    4: "I-phone",
    5: "B-account",
    6: "I-account",
    7: "B-payment_card",
    8: "I-payment_card",
    9: "B-ip_address",
    10: "I-ip_address",
    11: "B-url",
    12: "I-url",
    13: "B-common_secret",
    14: "I-common_secret",
    15: "B-private_address",
    16: "I-private_address",
    17: "B-private_date",
    18: "I-private_date",
    19: "B-private_person",
    20: "I-private_person",
}

_VARIANT_MODEL_FILES: dict[str, tuple[str, str]] = {
    "int8": ("int8", "model_int8.onnx"),
    "fp32": ("fp32", "model.onnx"),
    "fp16": ("fp16", "model_fp16_static512.onnx"),
}
_MAX_WINDOW_TOKENS = 512
_CONTENT_WINDOW_TOKENS = 510  # 512 minus BOS <s> and EOS </s>
_CONTENT_STRIDE_TOKENS = 382  # 510 - 382 = 128 overlapping content tokens
_XLM_R_PAD_ID = 1

_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_URL_START_RE = re.compile(r"https?://|www\.", re.IGNORECASE)
_URL_ASCII_CONT_RE = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&()*+=%]+")
_URL_TRAILING_PUNCT = ".,;:!?'\""
_URL_LEADING_PUNCT = "([<{（【《“‘'\""


class EncodingProtocol(Protocol):
    @property
    def ids(self) -> Sequence[int]: ...

    @property
    def offsets(self) -> Sequence[tuple[int, int]]: ...


class TokenizerProtocol(Protocol):
    def encode(self, text: str) -> EncodingProtocol: ...


class SessionProtocol(Protocol):
    def run(
        self,
        output_names: list[str] | None,
        input_feed: dict[str, np.ndarray],
    ) -> Sequence[Any]: ...


@dataclass(slots=True)
class _MutableSpan:
    label: str
    start: int
    end: int
    score: float


def default_models_dir() -> Path:
    env_dir = (
        os.environ.get("DS_MODELS_DIR")
        or os.environ.get("ASTRLINK_MODEL_DIR")
        or os.environ.get("MODELS_DIR")
    )
    if env_dir:
        return Path(env_dir)
    return Path(__file__).resolve().parents[3] / "models" / "astrlink-guard"


def _is_valid_ipv4(text: str) -> bool:
    parts = text.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _refine_span_bounds(text: str, label: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    if start >= end:
        return start, end

    if label == "ip_address":
        sub = text[start:end]
        for match in _IPV4_RE.finditer(sub):
            if _is_valid_ipv4(match.group(0)):
                return start + match.start(), start + match.end()
        while start < end and text[start] in "([<{（【'\"":
            start += 1
        while end > start and text[end - 1] in ")]>}）】.,;:!?'\"，。；！":
            end -= 1
        return start, end

    if label == "url":
        sub = text[start:end]
        scheme_match = _URL_START_RE.search(sub)
        if scheme_match is not None:
            start = start + scheme_match.start()
        else:
            while start < end and text[start] in _URL_LEADING_PUNCT:
                start += 1
        # Dynamic URL extension across contiguous RFC-safe ASCII characters
        cont_match = _URL_ASCII_CONT_RE.match(text, start)
        if cont_match is not None:
            end = max(start, cont_match.end())
        else:
            while end > start and ord(text[end - 1]) > 0x7E:
                end -= 1

        while end > start:
            tail = text[end - 1]
            if tail in _URL_TRAILING_PUNCT:
                end -= 1
                continue
            if tail == ")" and text[start:end].count(")") > text[start:end].count("("):
                end -= 1
                continue
            if tail == "]" and text[start:end].count("]") > text[start:end].count("["):
                end -= 1
                continue
            break

    return start, end


class OnnxNerDetector:
    def __init__(
        self,
        *,
        models_dir: str | Path | None = None,
        max_workers: int = 2,
        session: SessionProtocol | None = None,
        sessions: Mapping[str, SessionProtocol] | None = None,
        session_factory: Callable[[str], SessionProtocol] | None = None,
        tokenizer: TokenizerProtocol | None = None,
        id2label: Mapping[int, str] | None = None,
    ) -> None:
        self._models_dir = Path(models_dir) if models_dir is not None else default_models_dir()
        self._session_factory = session_factory
        self._sessions: dict[str, SessionProtocol] = dict(sessions) if sessions else {}
        if session is not None:
            for variant_key in _VARIANT_MODEL_FILES:
                self._sessions.setdefault(variant_key, session)
        self._tokenizer: TokenizerProtocol | None = tokenizer
        self._id2label: dict[int, str] | None = dict(id2label) if id2label is not None else None
        self._lock = threading.Lock()
        self._closed = False
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, max_workers),
            thread_name_prefix="astrlink-onnx",
        )

    def shutdown(self, wait: bool = True) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=wait)

    def _resolve_model_paths(self, variant: str) -> tuple[Path, Path, Path | None]:
        spec = _VARIANT_MODEL_FILES.get(variant)
        if spec is None:
            raise DetectorNotReadyError(f"Unsupported AstrLink Guard ONNX variant: '{variant}'")
        subdir, onnx_filename = spec
        variant_dir = self._models_dir / subdir
        onnx_path = variant_dir / onnx_filename
        if not onnx_path.is_file() and (self._models_dir / onnx_filename).is_file():
            onnx_path = self._models_dir / onnx_filename

        tok_path = variant_dir / "tokenizer.json"
        if not tok_path.is_file():
            tok_path = self._models_dir / "tokenizer.json"

        labels_path: Path | None = None
        for candidate in (
            variant_dir / "labels.json",
            self._models_dir / "labels.json",
            variant_dir / "config.json",
            self._models_dir / "config.json",
        ):
            if candidate.is_file():
                labels_path = candidate
                break
        return onnx_path, tok_path, labels_path

    def is_ready(self, variant: str = "int8") -> bool:
        with self._lock:
            if self._closed:
                return False
            if variant not in _VARIANT_MODEL_FILES:
                return False
            has_session = variant in self._sessions or self._session_factory is not None
            has_tokenizer = self._tokenizer is not None
        if has_session and has_tokenizer:
            return True
        try:
            onnx_path, tok_path, _ = self._resolve_model_paths(variant)
        except DetectorNotReadyError:
            return False
        if not has_session and not onnx_path.is_file():
            return False
        if not has_tokenizer and not tok_path.is_file():
            return False
        return True

    def is_onnx_ready(self, variant: str = "int8") -> bool:
        return self.is_ready(variant)

    def _ensure_loaded(
        self, variant: str
    ) -> tuple[SessionProtocol, TokenizerProtocol, dict[int, str]]:
        if variant not in _VARIANT_MODEL_FILES:
            raise DetectorNotReadyError(f"Unsupported AstrLink Guard ONNX variant: '{variant}'")
        with self._lock:
            if self._closed:
                raise DetectorNotReadyError("AstrLink Guard ONNX inference pool is shut down")
            sess = self._sessions.get(variant)
            tok = self._tokenizer
            id2label = self._id2label

            if sess is not None and tok is not None:
                resolved_labels = id2label if id2label is not None else DEFAULT_ID2LABEL
                return sess, tok, resolved_labels

            onnx_path, tok_path, labels_path = self._resolve_model_paths(variant)

            if sess is None:
                if self._session_factory is not None:
                    try:
                        sess = self._session_factory(variant)
                    except Exception:
                        raise DetectorNotReadyError(
                            f"Failed to initialize ONNX session for variant '{variant}'"
                        ) from None
                else:
                    if not onnx_path.is_file():
                        raise DetectorNotReadyError(
                            f"Missing AstrLink Guard ONNX model file for variant '{variant}'"
                        )
                    try:
                        import onnxruntime as ort

                        so = ort.SessionOptions()
                        so.intra_op_num_threads = 2
                        so.inter_op_num_threads = 1
                        sess = ort.InferenceSession(
                            str(onnx_path),
                            sess_options=so,
                            providers=["CPUExecutionProvider"],
                        )
                    except Exception:
                        raise DetectorNotReadyError(
                            f"Failed to load AstrLink Guard ONNX weights for variant '{variant}'"
                        ) from None
                self._sessions[variant] = sess

            if tok is None:
                if not tok_path.is_file():
                    raise DetectorNotReadyError(
                        f"Missing AstrLink Guard tokenizer.json for variant '{variant}'"
                    )
                try:
                    from tokenizers import Tokenizer

                    loaded_tok = Tokenizer.from_file(str(tok_path))
                    loaded_tok.no_truncation()
                    loaded_tok.no_padding()
                    tok = loaded_tok
                except Exception:
                    raise DetectorNotReadyError(
                        f"Failed to load AstrLink Guard tokenizer for variant '{variant}'"
                    ) from None
                self._tokenizer = tok

            if id2label is None:
                id2label = dict(DEFAULT_ID2LABEL)
                if labels_path is not None:
                    try:
                        raw = json.loads(labels_path.read_text(encoding="utf-8"))
                        mapping = raw.get("id2label", raw) if isinstance(raw, dict) else {}
                        if isinstance(mapping, dict) and mapping:
                            id2label = {int(k): str(v) for k, v in mapping.items()}
                    except Exception:
                        id2label = dict(DEFAULT_ID2LABEL)
                self._id2label = id2label

            return sess, tok, id2label

    def _decode_window(
        self,
        text: str,
        logits: np.ndarray,
        offsets: Sequence[tuple[int, int]],
        id2label: Mapping[int, str],
        thresholds: Mapping[str, float],
    ) -> list[DetectedSpan]:
        logits_f32 = np.asarray(logits, dtype=np.float32)
        shifted = logits_f32 - np.max(logits_f32, axis=-1, keepdims=True)
        exp_vals = np.exp(shifted)
        probs = exp_vals / np.sum(exp_vals, axis=-1, keepdims=True)
        pred_ids = np.argmax(probs, axis=-1)
        pred_scores = probs[np.arange(len(pred_ids)), pred_ids]

        raw_spans: list[_MutableSpan] = []
        cur: _MutableSpan | None = None

        for tag_id, p, (start, end) in zip(pred_ids, pred_scores, offsets):
            if start >= end:
                continue
            tag = id2label.get(int(tag_id), "O")
            if tag == "O" or "-" not in tag:
                if cur is not None:
                    raw_spans.append(cur)
                    cur = None
                continue
            prefix, kind = tag.split("-", 1)
            if prefix == "B" or cur is None or cur.label != kind or start < cur.end:
                if cur is not None:
                    raw_spans.append(cur)
                cur = _MutableSpan(label=kind, start=start, end=end, score=float(p))
            else:
                cur.end = end
                cur.score = min(cur.score, float(p))

        if cur is not None:
            raw_spans.append(cur)

        decoded: list[DetectedSpan] = []
        for item in raw_spans:
            min_score = thresholds.get(item.label)
            if min_score is None or item.score < min_score:
                continue
            ref_start, ref_end = _refine_span_bounds(text, item.label, item.start, item.end)
            if ref_start >= ref_end:
                continue
            decoded.append(
                DetectedSpan(
                    label=item.label,
                    start=ref_start,
                    end=ref_end,
                    score=item.score,
                    detector="onnx",
                )
            )
        return decoded

    @staticmethod
    def _slice_windows(
        all_ids: Sequence[int],
        all_offsets: Sequence[tuple[int, int]],
    ) -> list[tuple[list[int], list[tuple[int, int]]]]:
        if (
            len(all_ids) >= 2
            and all_offsets[0][0] == all_offsets[0][1]
            and all_offsets[-1][0] == all_offsets[-1][1]
        ):
            bos_id = int(all_ids[0])
            eos_id = int(all_ids[-1])
            content_ids = [int(t) for t in all_ids[1:-1]]
            content_offsets = list(all_offsets[1:-1])
        else:
            bos_id = 0
            eos_id = 2
            content_ids = [int(t) for t in all_ids]
            content_offsets = list(all_offsets)

        if len(content_ids) <= _CONTENT_WINDOW_TOKENS:
            return [
                (
                    [bos_id, *content_ids, eos_id],
                    [(0, 0), *content_offsets, (0, 0)],
                )
            ]

        windows: list[tuple[list[int], list[tuple[int, int]]]] = []
        total_content = len(content_ids)
        win_start = 0
        while win_start < total_content:
            win_end = min(win_start + _CONTENT_WINDOW_TOKENS, total_content)
            windows.append(
                (
                    [bos_id, *content_ids[win_start:win_end], eos_id],
                    [(0, 0), *content_offsets[win_start:win_end], (0, 0)],
                )
            )
            if win_end >= total_content:
                break
            win_start += _CONTENT_STRIDE_TOKENS
        return windows

    @staticmethod
    def _run_window(
        sess: SessionProtocol,
        win_ids: list[int],
        variant: str,
    ) -> np.ndarray:
        ids_np = np.asarray([win_ids], dtype=np.int64)
        seq_len = ids_np.shape[1]
        if variant == "fp16":
            if seq_len < _MAX_WINDOW_TOKENS:
                pad = np.full(
                    (1, _MAX_WINDOW_TOKENS - seq_len),
                    _XLM_R_PAD_ID,
                    dtype=np.int64,
                )
                feed = {
                    "input_ids": np.concatenate([ids_np, pad], axis=1),
                    "attention_mask": np.concatenate(
                        [np.ones_like(ids_np), np.zeros_like(pad)],
                        axis=1,
                    ),
                    "token_type_ids": np.zeros((1, _MAX_WINDOW_TOKENS), dtype=np.int64),
                }
            else:
                feed = {
                    "input_ids": ids_np,
                    "attention_mask": np.ones_like(ids_np),
                    "token_type_ids": np.zeros_like(ids_np),
                }
            return sess.run(["logits"], feed)[0][0][:seq_len]

        feed = {
            "input_ids": ids_np,
            "attention_mask": np.ones_like(ids_np),
            "token_type_ids": np.zeros_like(ids_np),
        }
        return sess.run(["logits"], feed)[0][0]

    @staticmethod
    def _merge_cross_window_spans(spans: list[DetectedSpan]) -> list[DetectedSpan]:
        if len(spans) <= 1:
            return spans
        ordered = sorted(spans, key=lambda s: (s.label, s.start, s.end))
        merged: list[DetectedSpan] = []
        for span in ordered:
            if (
                merged
                and merged[-1].label == span.label
                and span.start < merged[-1].end
            ):
                prev = merged[-1]
                merged[-1] = DetectedSpan(
                    label=prev.label,
                    start=min(prev.start, span.start),
                    end=max(prev.end, span.end),
                    score=max(prev.score, span.score),
                    detector="onnx",
                )
            else:
                merged.append(span)
        merged.sort(key=lambda s: (s.start, s.end, s.label))
        return merged

    def _infer_sync(
        self,
        text: str,
        variant: str,
        thresholds: Mapping[str, float],
    ) -> list[DetectedSpan]:
        sess, tok, id2label = self._ensure_loaded(variant)
        if not text or not thresholds:
            return []

        try:
            enc = tok.encode(text)
            windows = self._slice_windows(enc.ids, enc.offsets)
            collected: list[DetectedSpan] = []
            for win_ids, win_offsets in windows:
                logits = self._run_window(sess, win_ids, variant)
                collected.extend(
                    self._decode_window(text, logits, win_offsets, id2label, thresholds)
                )
        except DetectorNotReadyError:
            raise
        except Exception:
            raise DetectorNotReadyError(
                f"AstrLink Guard ONNX inference failed for variant '{variant}'"
            ) from None

        return self._merge_cross_window_spans(collected)

    def detect(
        self,
        text: str,
        *,
        variant: str = "int8",
        label_thresholds: Mapping[str, float] | None = None,
        default_threshold: float = 0.80,
    ) -> list[DetectedSpan]:
        thresholds = (
            {lbl: float(score) for lbl, score in label_thresholds.items() if lbl in ONNX_ENTITY_LABELS}
            if label_thresholds is not None
            else {lbl: float(default_threshold) for lbl in ONNX_ENTITY_LABELS}
        )
        with self._lock:
            if self._closed:
                raise DetectorNotReadyError("AstrLink Guard ONNX inference pool is shut down")
            try:
                future = self._executor.submit(self._infer_sync, text, variant, thresholds)
            except RuntimeError:
                raise DetectorNotReadyError(
                    "AstrLink Guard ONNX inference pool is unavailable"
                ) from None
        return future.result()
