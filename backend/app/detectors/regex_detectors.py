from collections.abc import Set as AbstractSet
from datetime import date
import re

from app.detectors.types import DetectedSpan, REGEX_ENTITY_LABELS

_CN_ID_CARD_RE = re.compile(
    r"(?<![0-9A-Za-z])([1-9]\d{5})((?:19|20)\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![0-9A-Za-z])"
)
_CN_ID_WEIGHTS: tuple[int, ...] = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_ID_CHECK_CHARS = "10X98765432"

# GB 32100-2015: 31-character base alphabet excluding I, O, Z, S, V
_USCC_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_CHAR_TO_VAL: dict[str, int] = {ch: idx for idx, ch in enumerate(_USCC_CHARSET)}
_USCC_WEIGHTS: tuple[int, ...] = (
    1,
    3,
    9,
    27,
    19,
    26,
    16,
    17,
    20,
    29,
    25,
    13,
    8,
    24,
    10,
    30,
    28,
)
_CN_USCC_RE = re.compile(
    r"(?<![0-9A-Za-z])[1-9ANY][1-9]\d{6}[0-9A-HJ-NPQRTUWXY]{10}(?![0-9A-Za-z])"
)

_CN_MOBILE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_BANK_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)[1-9]\d{15,18}(?!\d)")


def is_valid_cn_id_card(candidate: str) -> bool:
    if len(candidate) != 18:
        return False
    body = candidate[:17]
    if not body.isdigit():
        return False
    try:
        date(int(candidate[6:10]), int(candidate[10:12]), int(candidate[12:14]))
    except ValueError:
        return False
    weighted_sum = sum((ord(ch) - 48) * w for ch, w in zip(body, _CN_ID_WEIGHTS))
    expected_check = _CN_ID_CHECK_CHARS[weighted_sum % 11]
    return candidate[17].upper() == expected_check


def is_valid_cn_uscc(candidate: str) -> bool:
    if len(candidate) != 18:
        return False
    if not (
        candidate[0] in "123456789ANY"
        and candidate[1] in "123456789"
        and candidate[2:8].isdigit()
    ):
        return False
    total = 0
    for ch, weight in zip(candidate[:17], _USCC_WEIGHTS):
        val = _USCC_CHAR_TO_VAL.get(ch)
        if val is None:
            return False
        total += val * weight
    if candidate[17] not in _USCC_CHAR_TO_VAL:
        return False
    expected_idx = (31 - (total % 31)) % 31
    return candidate[17] == _USCC_CHARSET[expected_idx]


def is_valid_luhn(candidate: str) -> bool:
    if not (16 <= len(candidate) <= 19) or not candidate.isdigit() or candidate[0] == "0":
        return False
    total = 0
    for idx, ch in enumerate(reversed(candidate)):
        digit = ord(ch) - 48
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _overlaps_any(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start < r_end and r_start < end for r_start, r_end in ranges)


def detect_regex_spans(
    text: str,
    *,
    enabled_labels: AbstractSet[str] | None = None,
) -> list[DetectedSpan]:
    if not text:
        return []
    target_labels = (
        REGEX_ENTITY_LABELS if enabled_labels is None else (enabled_labels & REGEX_ENTITY_LABELS)
    )
    if not target_labels:
        return []

    need_id_exclusion = bool(target_labels & {"cn_id_card", "bank_card_luhn", "cn_uscc"})
    valid_id_ranges: list[tuple[int, int]] = []
    spans: list[DetectedSpan] = []

    if need_id_exclusion:
        for match in _CN_ID_CARD_RE.finditer(text):
            raw = match.group(0)
            if is_valid_cn_id_card(raw):
                valid_id_ranges.append((match.start(), match.end()))
                if "cn_id_card" in target_labels:
                    spans.append(
                        DetectedSpan(
                            label="cn_id_card",
                            start=match.start(),
                            end=match.end(),
                            score=1.0,
                            detector="regex",
                        )
                    )

    if "cn_uscc" in target_labels:
        for match in _CN_USCC_RE.finditer(text):
            s, e = match.start(), match.end()
            if _overlaps_any(s, e, valid_id_ranges):
                continue
            if is_valid_cn_uscc(match.group(0)):
                spans.append(
                    DetectedSpan(
                        label="cn_uscc",
                        start=s,
                        end=e,
                        score=1.0,
                        detector="regex",
                    )
                )

    if "cn_mobile" in target_labels:
        for match in _CN_MOBILE_RE.finditer(text):
            spans.append(
                DetectedSpan(
                    label="cn_mobile",
                    start=match.start(),
                    end=match.end(),
                    score=1.0,
                    detector="regex",
                )
            )

    if "bank_card_luhn" in target_labels:
        for match in _BANK_CARD_CANDIDATE_RE.finditer(text):
            s, e = match.start(), match.end()
            if _overlaps_any(s, e, valid_id_ranges):
                continue
            if is_valid_luhn(match.group(0)):
                spans.append(
                    DetectedSpan(
                        label="bank_card_luhn",
                        start=s,
                        end=e,
                        score=1.0,
                        detector="regex",
                    )
                )

    spans.sort(key=lambda sp: (sp.start, sp.end, sp.label))
    return spans
