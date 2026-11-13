from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
from typing import Any, Literal

from app.detectors.types import DetectedSpan, DetectorSource
from app.engine.scope import EphemeralScopeDict, normalize_scope_entity

MaskAction = Literal["PLACEHOLDER", "PARTIAL", "FIXED", "HASH"]
MASK_ACTIONS: frozenset[str] = frozenset({"PLACEHOLDER", "PARTIAL", "FIXED", "HASH"})

DEFAULT_LABEL_PREFIXES: dict[str, str] = {
    "private_person": "PERSON",
    "phone": "PHONE",
    "email": "EMAIL",
    "private_address": "ADDR",
    "private_date": "DATE",
    "account": "ACCOUNT",
    "payment_card": "CARD",
    "ip_address": "IP",
    "url": "URL",
    "common_secret": "SECRET",
    "cn_id_card": "IDCARD",
    "cn_uscc": "USCC",
    "cn_mobile": "PHONE",
    "bank_card_luhn": "BANKCARD",
}


@dataclass(frozen=True, slots=True)
class PlannedReplacement:
    label: str
    orig_start: int
    orig_end: int
    replacement: str
    detector: DetectorSource
    score: float


def apply_partial_mask(
    raw_val: str,
    *,
    keep_head: int = 4,
    keep_tail: int = 4,
    mask_char: str = "*",
) -> str:
    n = len(raw_val)
    if n == 0:
        return ""
    ch = mask_char[0] if mask_char else "*"
    head = max(0, int(keep_head))
    tail = max(0, int(keep_tail))

    if n > head + tail:
        head_part = raw_val[:head] if head > 0 else ""
        tail_part = raw_val[n - tail :] if tail > 0 else ""
        mid_len = n - head - tail
        return f"{head_part}{ch * mid_len}{tail_part}"

    # Short-string fallback: guarantee at least ceil(n / 2) characters are masked
    if n == 1:
        return ch
    mask_count = max(1, (n + 1) // 2)
    rem = n - mask_count
    if head == 0 and tail == 0:
        return ch * n
    h = min(head, (rem + 1) // 2 if tail > 0 else rem)
    t = rem - h
    head_part = raw_val[:h] if h > 0 else ""
    tail_part = raw_val[n - t :] if t > 0 else ""
    return f"{head_part}{ch * mask_count}{tail_part}"


def apply_hash_mask(raw_val: str, *, salt: str, digest_chars: int = 12) -> str:
    norm = normalize_scope_entity(raw_val)
    digest = hashlib.sha256((salt + norm).encode("utf-8")).hexdigest()[:digest_chars]
    return f"[HASH_{digest}]"


def compute_mask_for_span(
    raw_val: str,
    *,
    label: str,
    detector: DetectorSource,
    score: float,
    rule_cfg: Mapping[str, Any],
    scope: EphemeralScopeDict,
    hash_salt: str,
    write_replay: bool = True,
) -> str:
    action = str(rule_cfg.get("action", "PLACEHOLDER")).upper()
    if action == "PLACEHOLDER":
        default_prefix = DEFAULT_LABEL_PREFIXES.get(label, label.upper())
        prefix = str(rule_cfg.get("prefix") or default_prefix).strip() or default_prefix
        group_key = f"PLACEHOLDER:{prefix}"
        existing = scope.lookup(group_key, raw_val)
        if existing is not None:
            return existing
        seq = scope.next_sequence(prefix)
        replacement = f"<{prefix}_{seq}>"
        return scope.register(
            group_key=group_key,
            raw_text=raw_val,
            replacement=replacement,
            label=label,
            detector=detector,
            score=score,
            write_replay=write_replay,
        )

    if action == "PARTIAL":
        keep_head = int(rule_cfg.get("keep_head", 3))
        keep_tail = int(rule_cfg.get("keep_tail", 4))
        mask_char = str(rule_cfg.get("mask_char", "*")) or "*"
        group_key = f"PARTIAL:{label}:{keep_head}:{keep_tail}:{mask_char}"
        existing = scope.lookup(group_key, raw_val)
        if existing is not None:
            return existing
        replacement = apply_partial_mask(
            raw_val,
            keep_head=keep_head,
            keep_tail=keep_tail,
            mask_char=mask_char,
        )
        return scope.register(
            group_key=group_key,
            raw_text=raw_val,
            replacement=replacement,
            label=label,
            detector=detector,
            score=score,
            write_replay=write_replay,
        )

    if action == "FIXED":
        replacement = str(rule_cfg.get("replacement") or "[REDACTED]")
        group_key = f"FIXED:{label}:{replacement}"
        existing = scope.lookup(group_key, raw_val)
        if existing is not None:
            return existing
        return scope.register(
            group_key=group_key,
            raw_text=raw_val,
            replacement=replacement,
            label=label,
            detector=detector,
            score=score,
            write_replay=write_replay,
        )

    if action == "HASH":
        digest_chars = int(rule_cfg.get("hash_len", 12))
        group_key = f"HASH:{label}:{digest_chars}"
        existing = scope.lookup(group_key, raw_val)
        if existing is not None:
            return existing
        replacement = apply_hash_mask(raw_val, salt=hash_salt, digest_chars=digest_chars)
        return scope.register(
            group_key=group_key,
            raw_text=raw_val,
            replacement=replacement,
            label=label,
            detector=detector,
            score=score,
            write_replay=write_replay,
        )

    raise ValueError(f"Unsupported mask action: '{action}'")


def replace_spans_reverse(
    text: str,
    planned: Sequence[PlannedReplacement],
) -> tuple[str, list[tuple[int, int, PlannedReplacement]]]:
    """Replace non-overlapping forward-ordered spans using reverse slice indexing.

    Returns (masked_text, [(masked_start, masked_end, item), ...]).
    """
    if not planned:
        return text, []

    ordered = sorted(planned, key=lambda item: (item.orig_start, item.orig_end))
    buf = text
    # Perform string slice replacement from right to left so earlier offsets never shift
    for item in reversed(ordered):
        buf = buf[: item.orig_start] + item.replacement + buf[item.orig_end :]

    # Compute post-mask coordinates in forward order
    delta = 0
    post_coords: list[tuple[int, int, PlannedReplacement]] = []
    for item in ordered:
        m_start = item.orig_start + delta
        m_end = m_start + len(item.replacement)
        post_coords.append((m_start, m_end, item))
        delta += len(item.replacement) - (item.orig_end - item.orig_start)

    return buf, post_coords


def plan_detected_replacements(
    text: str,
    spans: Sequence[DetectedSpan],
    *,
    entity_rules: Mapping[str, Mapping[str, Any]],
    scope: EphemeralScopeDict,
    hash_salt: str,
    write_replay: bool = True,
) -> list[PlannedReplacement]:
    planned: list[PlannedReplacement] = []
    for span in sorted(spans, key=lambda s: (s.start, s.end)):
        raw_val = text[span.start : span.end]
        rule_cfg = entity_rules.get(span.label, {})
        repl = compute_mask_for_span(
            raw_val,
            label=span.label,
            detector=span.detector,
            score=span.score,
            rule_cfg=rule_cfg,
            scope=scope,
            hash_salt=hash_salt,
            write_replay=write_replay,
        )
        planned.append(
            PlannedReplacement(
                label=span.label,
                orig_start=span.start,
                orig_end=span.end,
                replacement=repl,
                detector=span.detector,
                score=span.score,
            )
        )
    return planned
