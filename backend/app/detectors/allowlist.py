from collections.abc import Sequence, Set as AbstractSet
from functools import lru_cache
import re
from urllib.parse import urlsplit

from app.detectors.types import (
    ALLOWLIST_MATCH_MODES,
    AllowlistEntry,
    DetectedSpan,
    ExemptedSpan,
    InvalidAllowlistPatternError,
)


@lru_cache(maxsize=512)
def _compile_regex_cached(pattern_text: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern_text)
    except re.error as exc:
        raise InvalidAllowlistPatternError(
            f"Invalid allowlist regex syntax: {exc.msg}"
        ) from None


def validate_allowlist_pattern(match_mode: str, pattern_text: str) -> None:
    if match_mode not in ALLOWLIST_MATCH_MODES:
        raise InvalidAllowlistPatternError(
            f"Unsupported allowlist match_mode: '{match_mode}'"
        )
    if not pattern_text:
        raise InvalidAllowlistPatternError("Allowlist pattern_text must not be empty")
    if match_mode == "REGEX":
        _compile_regex_cached(pattern_text)


def _matches_url_suffix(span_text: str, pattern_text: str) -> bool:
    if pattern_text.startswith((".", "/")) and span_text.endswith(pattern_text):
        return True
    candidate_url = span_text if "://" in span_text else f"http://{span_text}"
    try:
        hostname = urlsplit(candidate_url).hostname
    except ValueError:
        hostname = None
    if not hostname:
        return span_text.endswith(pattern_text)
    host_lower = hostname.lower()
    pat_lower = pattern_text.lower()
    if pat_lower.startswith("."):
        return host_lower.endswith(pat_lower) or host_lower == pat_lower[1:]
    if "/" in pat_lower:
        return span_text.lower().endswith(pat_lower)
    return host_lower == pat_lower or host_lower.endswith("." + pat_lower)


def match_allowlist_entry(span_text: str, label: str, entry: AllowlistEntry) -> bool:
    if not entry.is_enabled:
        return False
    if label not in entry.apply_labels:
        return False
    validate_allowlist_pattern(entry.match_mode, entry.pattern_text)

    if entry.match_mode == "EXACT":
        return span_text == entry.pattern_text
    if entry.match_mode == "PREFIX":
        return span_text.startswith(entry.pattern_text)
    if entry.match_mode == "SUFFIX":
        if label == "url":
            return _matches_url_suffix(span_text, entry.pattern_text)
        return span_text.endswith(entry.pattern_text)
    if entry.match_mode == "REGEX":
        return _compile_regex_cached(entry.pattern_text).search(span_text) is not None
    raise InvalidAllowlistPatternError(
        f"Unsupported allowlist match_mode: '{entry.match_mode}'"
    )


def find_matching_allowlist_entries(
    span_text: str,
    label: str,
    entries: Sequence[AllowlistEntry],
    *,
    active_groups: AbstractSet[str] | None = None,
) -> list[AllowlistEntry]:
    matched: list[AllowlistEntry] = []
    for entry in entries:
        if not entry.is_enabled:
            continue
        if active_groups is not None and entry.group_code not in active_groups:
            continue
        validate_allowlist_pattern(entry.match_mode, entry.pattern_text)
        if match_allowlist_entry(span_text, label, entry):
            matched.append(entry)
    return matched


class AllowlistFilter:
    def filter_spans(
        self,
        text: str,
        candidates: Sequence[DetectedSpan],
        entries: Sequence[AllowlistEntry],
        *,
        active_groups: AbstractSet[str] | None = None,
        trace_exemptions: bool = False,
    ) -> tuple[list[DetectedSpan], list[ExemptedSpan]]:
        active_entries: list[AllowlistEntry] = []
        for entry in entries:
            if not entry.is_enabled:
                continue
            if active_groups is not None and entry.group_code not in active_groups:
                continue
            validate_allowlist_pattern(entry.match_mode, entry.pattern_text)
            active_entries.append(entry)

        if not active_entries:
            return list(candidates), []

        kept: list[DetectedSpan] = []
        exempted: list[ExemptedSpan] = []

        for span in candidates:
            span_text = text[span.start : span.end]
            matched_rule: AllowlistEntry | None = None
            for entry in active_entries:
                if match_allowlist_entry(span_text, span.label, entry):
                    matched_rule = entry
                    break
            if matched_rule is None:
                kept.append(span)
            elif trace_exemptions:
                exempted.append(
                    ExemptedSpan(
                        label=span.label,
                        start=span.start,
                        end=span.end,
                        score=span.score,
                        detector=span.detector,
                        group_code=matched_rule.group_code,
                        rule_name=matched_rule.item_name,
                    )
                )

        return kept, exempted
