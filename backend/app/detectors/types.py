from dataclasses import dataclass
from typing import Literal

DetectorSource = Literal["onnx", "regex"]
AllowlistMatchMode = Literal["EXACT", "SUFFIX", "PREFIX", "REGEX"]

ONNX_ENTITY_LABELS: frozenset[str] = frozenset(
    {
        "private_person",
        "phone",
        "email",
        "private_address",
        "private_date",
        "account",
        "payment_card",
        "ip_address",
        "url",
        "common_secret",
    }
)

REGEX_ENTITY_LABELS: frozenset[str] = frozenset(
    {
        "cn_id_card",
        "cn_uscc",
        "cn_mobile",
        "bank_card_luhn",
    }
)

ALL_ENTITY_LABELS: frozenset[str] = ONNX_ENTITY_LABELS | REGEX_ENTITY_LABELS
ALLOWLIST_MATCH_MODES: frozenset[str] = frozenset({"EXACT", "SUFFIX", "PREFIX", "REGEX"})


class DetectorNotReadyError(RuntimeError):
    """Raised when AstrLink Guard ONNX files are missing/corrupt or inference pool is unavailable.
    NEVER include input text in the error message. Mapped to HTTP 503 / code 50301 by upper layers."""


class InvalidAllowlistPatternError(ValueError):
    """Raised when an allowlist regex pattern fails compilation. Mapped to HTTP 400 / code 40001."""


@dataclass(frozen=True, slots=True)
class DetectedSpan:
    label: str
    start: int  # Python Unicode char start (inclusive)
    end: int  # Python Unicode char end (exclusive)
    score: float
    detector: DetectorSource


@dataclass(frozen=True, slots=True)
class ExemptedSpan:
    label: str
    start: int
    end: int
    score: float
    detector: DetectorSource
    group_code: str
    rule_name: str


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    group_code: str
    item_name: str
    match_mode: AllowlistMatchMode
    pattern_text: str
    apply_labels: tuple[str, ...]
    is_enabled: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.apply_labels, tuple):
            object.__setattr__(self, "apply_labels", tuple(self.apply_labels))


@dataclass(frozen=True, slots=True)
class DetectionResult:
    spans: list[DetectedSpan]  # Non-overlapping, sorted by start ASC
    exempted_spans: list[ExemptedSpan]  # Populated when trace_exemptions=True (for /sandbox)
