from collections.abc import Mapping, Sequence, Set as AbstractSet
from pathlib import Path
import threading
from typing import Any

from app.detectors.allowlist import AllowlistFilter
from app.detectors.onnx_detector import OnnxNerDetector, default_models_dir
from app.detectors.regex_detectors import detect_regex_spans
from app.detectors.types import (
    ALL_ENTITY_LABELS,
    AllowlistEntry,
    DetectedSpan,
    DetectionResult,
    ExemptedSpan,
    ONNX_ENTITY_LABELS,
    REGEX_ENTITY_LABELS,
)

_VARIANT_MODEL_FILES: dict[str, tuple[str, str]] = {
    "int8": ("int8", "model_int8.onnx"),
    "fp32": ("fp32", "model.onnx"),
    "fp16": ("fp16", "model_fp16_static512.onnx"),
}


def resolve_overlapping_spans(candidates: Sequence[DetectedSpan]) -> list[DetectedSpan]:
    if not candidates:
        return []
    prioritized = sorted(
        candidates,
        key=lambda s: (
            -(s.end - s.start),
            -(1 if s.detector == "regex" else 0),
            -s.score,
            s.start,
            s.label,
        ),
    )
    accepted: list[DetectedSpan] = []
    for cand in prioritized:
        if cand.start >= cand.end:
            continue
        if any(cand.start < prev.end and prev.start < cand.end for prev in accepted):
            continue
        accepted.append(cand)
    accepted.sort(key=lambda s: (s.start, s.end))
    return accepted


class HybridDetectorPipeline:
    def __init__(
        self,
        *,
        onnx_detector: OnnxNerDetector | None = None,
        allowlist_filter: AllowlistFilter | None = None,
        models_dir: str | Path | None = None,
        max_workers: int = 2,
    ) -> None:
        self._owns_onnx = onnx_detector is None
        self._onnx = (
            onnx_detector
            if onnx_detector is not None
            else OnnxNerDetector(models_dir=models_dir, max_workers=max_workers)
        )
        self._allowlist = allowlist_filter if allowlist_filter is not None else AllowlistFilter()

    @property
    def onnx_detector(self) -> OnnxNerDetector:
        return self._onnx

    def is_onnx_ready(self, variant: str = "int8") -> bool:
        return self._onnx.is_ready(variant)

    def shutdown(self, wait: bool = True) -> None:
        self._onnx.shutdown(wait=wait)

    def detect(
        self,
        text: str,
        *,
        entity_rules: Mapping[str, Mapping[str, Any]],
        allowlist_entries: Sequence[AllowlistEntry] = (),
        onnx_variant: str = "int8",
        only_labels: AbstractSet[str] | None = None,
        require_onnx: bool | None = None,
        trace_exemptions: bool = False,
        active_allowlist_groups: AbstractSet[str] | None = None,
    ) -> DetectionResult:
        active_thresholds: dict[str, float] = {}
        for label, cfg in entity_rules.items():
            if label not in ALL_ENTITY_LABELS:
                continue
            if only_labels is not None and label not in only_labels:
                continue
            if not bool(cfg.get("enabled", False)):
                continue
            default_min = 1.0 if label in REGEX_ENTITY_LABELS else 0.80
            active_thresholds[label] = float(cfg.get("min_score", default_min))

        active_onnx_thresholds = {
            lbl: score
            for lbl, score in active_thresholds.items()
            if lbl in ONNX_ENTITY_LABELS
        }
        active_regex_labels = {
            lbl for lbl in active_thresholds if lbl in REGEX_ENTITY_LABELS
        }

        should_run_onnx = (
            bool(active_onnx_thresholds) if require_onnx is None else bool(require_onnx)
        )

        candidates: list[DetectedSpan] = []

        if should_run_onnx:
            onnx_spans = self._onnx.detect(
                text,
                variant=onnx_variant,
                label_thresholds=active_onnx_thresholds,
            )
            candidates.extend(onnx_spans)

        if active_regex_labels and text:
            for span in detect_regex_spans(text, enabled_labels=active_regex_labels):
                if span.score >= active_thresholds[span.label]:
                    candidates.append(span)

        kept_candidates, raw_exempted = self._allowlist.filter_spans(
            text,
            candidates,
            allowlist_entries,
            active_groups=active_allowlist_groups,
            trace_exemptions=trace_exemptions,
        )

        surviving = resolve_overlapping_spans(kept_candidates)

        if not trace_exemptions or not raw_exempted:
            return DetectionResult(spans=surviving, exempted_spans=[])

        visible_exempted: list[ExemptedSpan] = []
        seen_exempt_keys: set[tuple[int, int, str]] = set()
        for ex in sorted(raw_exempted, key=lambda e: (e.start, e.end, -e.score, e.label)):
            if any(ex.start < s.end and s.start < ex.end for s in surviving):
                continue
            key = (ex.start, ex.end, ex.label)
            if key in seen_exempt_keys:
                continue
            seen_exempt_keys.add(key)
            visible_exempted.append(ex)

        return DetectionResult(spans=surviving, exempted_spans=visible_exempted)


_default_pipeline_lock = threading.Lock()
_default_pipeline: HybridDetectorPipeline | None = None


def get_default_pipeline() -> HybridDetectorPipeline:
    global _default_pipeline
    with _default_pipeline_lock:
        if _default_pipeline is None:
            _default_pipeline = HybridDetectorPipeline()
        return _default_pipeline


def set_default_pipeline(pipeline: HybridDetectorPipeline | None) -> None:
    global _default_pipeline
    with _default_pipeline_lock:
        _default_pipeline = pipeline


def is_onnx_ready(variant: str = "int8", models_dir: str | Path | None = None) -> bool:
    if models_dir is None:
        with _default_pipeline_lock:
            current = _default_pipeline
        if current is not None:
            return current.is_onnx_ready(variant)
    spec = _VARIANT_MODEL_FILES.get(variant)
    if spec is None:
        return False
    base_dir = Path(models_dir) if models_dir is not None else default_models_dir()
    subdir, onnx_filename = spec
    variant_dir = base_dir / subdir
    onnx_ok = (variant_dir / onnx_filename).is_file() or (base_dir / onnx_filename).is_file()
    tok_ok = (variant_dir / "tokenizer.json").is_file() or (base_dir / "tokenizer.json").is_file()
    return onnx_ok and tok_ok
