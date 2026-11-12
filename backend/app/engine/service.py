from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
import math
import re
import time
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common.errors import BadRequestError, NotFoundError
from app.config import get_settings
from app.db.models import AllowlistDict, PolicyProfile
from app.db.seed import STRICT_GENERAL_ENTITY_RULES
from app.detectors import (
    ALL_ENTITY_LABELS,
    AllowlistEntry,
    HybridDetectorPipeline,
    InvalidAllowlistPatternError,
    REGEX_ENTITY_LABELS,
    get_default_pipeline,
    validate_allowlist_pattern,
)
from app.engine.field_router import (
    DEFAULT_HIGH_RISK_LABELS,
    assign_leaf_roles,
    compile_field_role_router,
)
from app.engine.masker import (
    DEFAULT_LABEL_PREFIXES,
    MASK_ACTIONS,
    PlannedReplacement,
    plan_detected_replacements,
    replace_spans_reverse,
)
from app.engine.scope import SCOPE_MODES, EphemeralScopeDict, ScopeMode

ONNX_VARIANTS: frozenset[str] = frozenset({"int8", "fp32", "fp16"})
_PREFIX_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
_EXISTING_MASK_TOKEN_RE = re.compile(
    r"<[A-Z][A-Z0-9_]*_\d+>|\[HASH_[0-9a-f]{6,64}\]|\[REDACTED[^\]]*\]"
)


@dataclass(slots=True)
class ResolvedPolicySnapshot:
    policy_id: int
    policy_code: str
    version: int
    scope_mode: ScopeMode
    onnx_variant: str
    entity_rules: dict[str, dict[str, Any]]
    field_role_rules: dict[str, Any]
    allowlist_groups: list[str]
    allowlist_entries: tuple[AllowlistEntry, ...]


@dataclass(slots=True)
class MaskedSpanOut:
    """Safe post-mask span in masked_text coordinates (NO raw plaintext!)."""

    label: str
    masked_start: int
    masked_end: int
    placeholder: str
    detector: Literal["onnx", "regex"]
    score: float


@dataclass(slots=True)
class SandboxSpanDetail:
    """In-memory-only span detail for /api/admin/sandbox/preview (NEVER logged or persisted)."""

    kind: Literal["masked", "exempted"]
    label: str
    orig_start: int
    orig_end: int
    detector: Literal["onnx", "regex"]
    score: float
    replacement: str | None = None
    allowlist_group: str | None = None
    allowlist_rule: str | None = None


@dataclass(slots=True)
class TextMaskResult:
    masked_text: str
    hit_counts: dict[str, int]
    elapsed_ms: int
    masked_spans: list[MaskedSpanOut]
    sandbox_spans: list[SandboxSpanDetail]


@dataclass(slots=True)
class RecordMaskResult:
    masked_payload: dict[str, Any]
    hit_counts: dict[str, int]
    char_count: int
    sandbox_field_traces: dict[str, list[SandboxSpanDetail]]


def validate_scope_mode(scope_mode: Any) -> ScopeMode:
    if not isinstance(scope_mode, str) or scope_mode not in SCOPE_MODES:
        raise BadRequestError("Invalid scope_mode: must be CONVERSATION, RECORD, or NONE")
    return scope_mode  # type: ignore[return-value]


def validate_onnx_variant(onnx_variant: Any) -> str:
    if not isinstance(onnx_variant, str) or onnx_variant not in ONNX_VARIANTS:
        raise BadRequestError("Invalid onnx_variant: must be int8, fp32, or fp16")
    return onnx_variant


def validate_entity_rules(
    entity_rules: Mapping[str, Any],
    *,
    fill_missing_disabled: bool = False,
) -> dict[str, dict[str, Any]]:
    if not isinstance(entity_rules, Mapping) or not entity_rules:
        raise BadRequestError("entity_rules must be a non-empty mapping")

    normalized: dict[str, dict[str, Any]] = {}
    for label, raw_cfg in entity_rules.items():
        if not isinstance(label, str) or label not in ALL_ENTITY_LABELS:
            raise BadRequestError("Unsupported entity label in entity_rules")
        if not isinstance(raw_cfg, Mapping):
            raise BadRequestError(f"Rule config for '{label}' must be an object")

        raw_enabled = raw_cfg.get("enabled", True)
        if not isinstance(raw_enabled, (bool, int)):
            raise BadRequestError(f"Invalid 'enabled' flag for '{label}'")
        enabled = bool(raw_enabled)

        default_score = 1.0 if label in REGEX_ENTITY_LABELS else 0.80
        raw_score = raw_cfg.get("min_score", default_score)
        if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
            raise BadRequestError(f"Invalid 'min_score' for '{label}'")
        min_score = float(raw_score)
        if math.isnan(min_score) or math.isinf(min_score) or min_score < 0.0 or min_score > 1.0:
            raise BadRequestError(f"'min_score' for '{label}' must be between 0.0 and 1.0")

        raw_action = raw_cfg.get("action", "PLACEHOLDER")
        if not isinstance(raw_action, str) or raw_action.upper() not in MASK_ACTIONS:
            raise BadRequestError(
                f"Invalid mask action for '{label}': must be PLACEHOLDER, PARTIAL, FIXED, or HASH"
            )
        action = raw_action.upper()

        clean_cfg: dict[str, Any] = {
            "enabled": enabled,
            "min_score": round(min_score, 4),
            "action": action,
        }

        if action == "PLACEHOLDER":
            default_prefix = DEFAULT_LABEL_PREFIXES.get(label, label.upper())
            if "prefix" in raw_cfg and raw_cfg["prefix"] is not None:
                if not isinstance(raw_cfg["prefix"], str) or not raw_cfg["prefix"].strip():
                    raise BadRequestError(f"Placeholder 'prefix' for '{label}' cannot be blank")
                prefix = raw_cfg["prefix"].strip().upper()
            else:
                prefix = default_prefix
            if not _PREFIX_TOKEN_RE.match(prefix):
                raise BadRequestError(f"Invalid placeholder 'prefix' format for '{label}'")
            clean_cfg["prefix"] = prefix
        elif action == "PARTIAL":
            default_head = 4 if label in ("payment_card", "bank_card_luhn") else 3
            raw_head = raw_cfg.get("keep_head", default_head)
            raw_tail = raw_cfg.get("keep_tail", 4)
            if (
                isinstance(raw_head, bool)
                or not isinstance(raw_head, int)
                or raw_head < 0
                or raw_head > 64
            ):
                raise BadRequestError(f"Invalid 'keep_head' for '{label}'")
            if (
                isinstance(raw_tail, bool)
                or not isinstance(raw_tail, int)
                or raw_tail < 0
                or raw_tail > 64
            ):
                raise BadRequestError(f"Invalid 'keep_tail' for '{label}'")
            clean_cfg["keep_head"] = raw_head
            clean_cfg["keep_tail"] = raw_tail
            if "mask_char" in raw_cfg and raw_cfg["mask_char"] is not None:
                mc = raw_cfg["mask_char"]
                if not isinstance(mc, str) or len(mc) != 1:
                    raise BadRequestError(f"'mask_char' for '{label}' must be a single character")
                clean_cfg["mask_char"] = mc
        elif action == "FIXED":
            if "replacement" in raw_cfg and raw_cfg["replacement"] is not None:
                repl = raw_cfg["replacement"]
                if not isinstance(repl, str) or not repl or len(repl) > 128:
                    raise BadRequestError(f"Invalid 'replacement' for '{label}'")
                clean_cfg["replacement"] = repl
            else:
                clean_cfg["replacement"] = "[REDACTED]"
        elif action == "HASH":
            if "hash_len" in raw_cfg and raw_cfg["hash_len"] is not None:
                hl = raw_cfg["hash_len"]
                if isinstance(hl, bool) or not isinstance(hl, int) or hl < 6 or hl > 64:
                    raise BadRequestError(f"Invalid 'hash_len' for '{label}'")
                clean_cfg["hash_len"] = hl

        normalized[label] = clean_cfg

    if fill_missing_disabled:
        for label, default_cfg in STRICT_GENERAL_ENTITY_RULES.items():
            if label not in normalized:
                fallback = deepcopy(default_cfg)
                fallback["enabled"] = False
                normalized[label] = fallback

    return normalized


def validate_field_role_rules_dict(
    field_role_rules: Mapping[str, Any] | None,
) -> dict[str, Any]:
    router = compile_field_role_router(field_role_rules)
    out: dict[str, Any] = {
        "default_role": router.default_role,
        "high_risk_only_labels": [
            lbl
            for lbl in DEFAULT_HIGH_RISK_LABELS
            if lbl in router.high_risk_only_labels
        ]
        + sorted(router.high_risk_only_labels - set(DEFAULT_HIGH_RISK_LABELS)),
        "rules": [
            {"jsonpath": r.jsonpath, "role": r.role}
            for r in router.rules
        ],
    }
    return out


def validate_allowlist_groups_list(raw_groups: Sequence[Any] | None) -> list[str]:
    if raw_groups is None:
        return []
    if isinstance(raw_groups, (str, bytes)) or not isinstance(raw_groups, Sequence):
        raise BadRequestError("allowlist_groups must be a list of group_code strings")
    result: list[str] = []
    seen: set[str] = set()
    for g in raw_groups:
        if not isinstance(g, str) or not g.strip() or len(g.strip()) > 64:
            raise BadRequestError("Invalid group_code in allowlist_groups")
        clean = g.strip()
        if clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def validate_allowlist_entries_seq(
    entries: Sequence[AllowlistEntry],
) -> tuple[AllowlistEntry, ...]:
    validated: list[AllowlistEntry] = []
    for entry in entries:
        try:
            validate_allowlist_pattern(entry.match_mode, entry.pattern_text)
        except InvalidAllowlistPatternError as exc:
            raise BadRequestError(str(exc)) from None
        if not entry.apply_labels:
            raise BadRequestError("Allowlist entry requires at least one apply_label")
        for lbl in entry.apply_labels:
            if lbl not in ALL_ENTITY_LABELS:
                raise BadRequestError("Unsupported entity label in allowlist apply_labels")
        validated.append(entry)
    return tuple(validated)


def load_allowlist_entries_for_groups(
    session: Session,
    allowlist_groups: Sequence[str],
) -> tuple[AllowlistEntry, ...]:
    if not allowlist_groups:
        return ()
    rows = session.scalars(
        select(AllowlistDict)
        .where(
            AllowlistDict.is_deleted == 0,
            AllowlistDict.is_enabled == 1,
            AllowlistDict.group_code.in_(list(allowlist_groups)),
        )
        .order_by(AllowlistDict.id.asc())
    ).all()
    entries = [
        AllowlistEntry(
            group_code=row.group_code,
            item_name=row.item_name,
            match_mode=row.match_mode,  # type: ignore[arg-type]
            pattern_text=row.pattern_text,
            apply_labels=tuple(row.apply_labels_json or ()),
            is_enabled=bool(row.is_enabled),
        )
        for row in rows
    ]
    return validate_allowlist_entries_seq(entries)


def _overlaps_any(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start < r_end and r_start < end for r_start, r_end in ranges)


def _find_protected_mask_ranges(
    text: str,
    entity_rules: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[tuple[int, int]]:
    if not text:
        return []
    ranges = [(m.start(), m.end()) for m in _EXISTING_MASK_TOKEN_RE.finditer(text)]
    if entity_rules:
        for cfg in entity_rules.values():
            if not isinstance(cfg, Mapping):
                continue
            if str(cfg.get("action", "")).upper() == "FIXED":
                repl = str(cfg.get("replacement") or "")
                if repl:
                    pos = 0
                    r_len = len(repl)
                    while True:
                        idx = text.find(repl, pos)
                        if idx < 0:
                            break
                        end_idx = idx + r_len
                        if not _overlaps_any(idx, end_idx, ranges):
                            ranges.append((idx, end_idx))
                        pos = end_idx
    return ranges


class PolicyEngineService:
    def __init__(
        self,
        *,
        pipeline: HybridDetectorPipeline | None = None,
        hash_salt: str | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._hash_salt = hash_salt

    def _get_pipeline(self) -> HybridDetectorPipeline:
        return self._pipeline if self._pipeline is not None else get_default_pipeline()

    def _get_hash_salt(self) -> str:
        if self._hash_salt is not None:
            return self._hash_salt
        return get_settings().hash_mask_salt

    def resolve_policy(
        self,
        session: Session,
        policy_code: str,
        policy_version: int | None = None,
    ) -> ResolvedPolicySnapshot:
        clean_code = (policy_code or "").strip()
        if not clean_code:
            raise BadRequestError("policy_code must not be empty")

        if policy_version is not None:
            row = session.scalar(
                select(PolicyProfile).where(
                    PolicyProfile.policy_code == clean_code,
                    PolicyProfile.version == policy_version,
                    PolicyProfile.is_deleted == 0,
                )
            )
            if row is None:
                raise NotFoundError(
                    f"Policy '{clean_code}' version {policy_version} not found"
                )
        else:
            row = session.scalar(
                select(PolicyProfile)
                .where(
                    PolicyProfile.policy_code == clean_code,
                    PolicyProfile.is_default == 1,
                    PolicyProfile.is_deleted == 0,
                )
                .order_by(PolicyProfile.version.desc())
            )
            if row is None:
                raise NotFoundError(
                    f"Active default version for policy '{clean_code}' not found"
                )

        scope_mode = validate_scope_mode(row.scope_mode)
        onnx_variant = validate_onnx_variant(row.onnx_variant)
        entity_rules = validate_entity_rules(row.entity_rules_json)
        field_role_rules = validate_field_role_rules_dict(row.field_role_rules_json)
        allowlist_groups = validate_allowlist_groups_list(row.allowlist_groups_json)
        allowlist_entries = load_allowlist_entries_for_groups(session, allowlist_groups)

        return ResolvedPolicySnapshot(
            policy_id=row.id,
            policy_code=row.policy_code,
            version=row.version,
            scope_mode=scope_mode,
            onnx_variant=onnx_variant,
            entity_rules=entity_rules,
            field_role_rules=field_role_rules,
            allowlist_groups=allowlist_groups,
            allowlist_entries=allowlist_entries,
        )

    def build_inline_snapshot(
        self,
        *,
        base_snapshot: ResolvedPolicySnapshot | None = None,
        policy_id: int | None = None,
        policy_code: str | None = None,
        version: int | None = None,
        scope_mode: str | None = None,
        onnx_variant: str | None = None,
        entity_rules: Mapping[str, Any] | None = None,
        field_role_rules: Mapping[str, Any] | None = None,
        allowlist_groups: Sequence[str] | None = None,
        allowlist_entries: Sequence[AllowlistEntry] | None = None,
    ) -> ResolvedPolicySnapshot:
        """Pure-memory policy snapshot builder / draft override helper (zero DB writes)."""
        resolved_scope = validate_scope_mode(
            scope_mode
            if scope_mode is not None
            else (base_snapshot.scope_mode if base_snapshot is not None else "CONVERSATION")
        )
        resolved_variant = validate_onnx_variant(
            onnx_variant
            if onnx_variant is not None
            else (base_snapshot.onnx_variant if base_snapshot is not None else "int8")
        )
        if entity_rules is not None:
            if base_snapshot is not None:
                merged_rules: dict[str, Any] = deepcopy(base_snapshot.entity_rules)
                merged_rules.update(deepcopy(dict(entity_rules)))
                resolved_entity_rules = validate_entity_rules(merged_rules)
            else:
                resolved_entity_rules = validate_entity_rules(
                    entity_rules, fill_missing_disabled=True
                )
        elif base_snapshot is not None:
            resolved_entity_rules = validate_entity_rules(base_snapshot.entity_rules)
        else:
            resolved_entity_rules = validate_entity_rules(STRICT_GENERAL_ENTITY_RULES)

        resolved_field_rules = validate_field_role_rules_dict(
            field_role_rules
            if field_role_rules is not None
            else (base_snapshot.field_role_rules if base_snapshot is not None else None)
        )
        resolved_groups = validate_allowlist_groups_list(
            allowlist_groups
            if allowlist_groups is not None
            else (base_snapshot.allowlist_groups if base_snapshot is not None else [])
        )
        resolved_entries = validate_allowlist_entries_seq(
            allowlist_entries
            if allowlist_entries is not None
            else (base_snapshot.allowlist_entries if base_snapshot is not None else ())
        )

        return ResolvedPolicySnapshot(
            policy_id=(
                policy_id
                if policy_id is not None
                else (base_snapshot.policy_id if base_snapshot is not None else 0)
            ),
            policy_code=(
                policy_code
                if policy_code is not None
                else (
                    base_snapshot.policy_code
                    if base_snapshot is not None
                    else "sandbox_draft"
                )
            ),
            version=(
                version
                if version is not None
                else (base_snapshot.version if base_snapshot is not None else 0)
            ),
            scope_mode=resolved_scope,
            onnx_variant=resolved_variant,
            entity_rules=resolved_entity_rules,
            field_role_rules=resolved_field_rules,
            allowlist_groups=resolved_groups,
            allowlist_entries=resolved_entries,
        )

    def resolve_sandbox_snapshot(
        self,
        session: Session,
        *,
        policy_code: str | None = None,
        policy_version: int | None = None,
        scope_mode: str | None = None,
        onnx_variant: str | None = None,
        entity_rules: Mapping[str, Any] | None = None,
        field_role_rules: Mapping[str, Any] | None = None,
        allowlist_groups: Sequence[str] | None = None,
    ) -> ResolvedPolicySnapshot:
        """Read-only resolver for #5 /api/admin/sandbox/preview supporting saved policy + draft overrides."""
        base = (
            self.resolve_policy(session, policy_code, policy_version)
            if policy_code and policy_code.strip()
            else None
        )
        effective_groups = (
            validate_allowlist_groups_list(allowlist_groups)
            if allowlist_groups is not None
            else (base.allowlist_groups if base is not None else [])
        )
        entries = (
            load_allowlist_entries_for_groups(session, effective_groups)
            if allowlist_groups is not None or base is None
            else base.allowlist_entries
        )
        return self.build_inline_snapshot(
            base_snapshot=base,
            scope_mode=scope_mode,
            onnx_variant=onnx_variant,
            entity_rules=entity_rules,
            field_role_rules=field_role_rules,
            allowlist_groups=effective_groups,
            allowlist_entries=entries,
        )

    def _mask_full_write_scope_field(
        self,
        text: str,
        snapshot: ResolvedPolicySnapshot,
        scope: EphemeralScopeDict,
        *,
        return_spans: bool = False,
        sandbox_trace: bool = False,
    ) -> tuple[str, list[PlannedReplacement], list[MaskedSpanOut], list[SandboxSpanDetail]]:
        protected_ranges = _find_protected_mask_ranges(text, snapshot.entity_rules)
        try:
            detection = self._get_pipeline().detect(
                text,
                entity_rules=snapshot.entity_rules,
                allowlist_entries=snapshot.allowlist_entries,
                onnx_variant=snapshot.onnx_variant,
                active_allowlist_groups=(
                    set(snapshot.allowlist_groups) if snapshot.allowlist_groups else set()
                ),
                trace_exemptions=sandbox_trace,
            )
        except InvalidAllowlistPatternError as exc:
            raise BadRequestError(str(exc)) from None

        filtered_spans = [
            s
            for s in detection.spans
            if not _overlaps_any(s.start, s.end, protected_ranges)
        ]
        planned = plan_detected_replacements(
            text,
            filtered_spans,
            entity_rules=snapshot.entity_rules,
            scope=scope,
            hash_salt=self._get_hash_salt(),
            write_replay=True,
        )
        masked_text, post_coords = replace_spans_reverse(text, planned)

        masked_spans: list[MaskedSpanOut] = []
        if return_spans:
            for m_start, m_end, item in post_coords:
                masked_spans.append(
                    MaskedSpanOut(
                        label=item.label,
                        masked_start=m_start,
                        masked_end=m_end,
                        placeholder=item.replacement,
                        detector=item.detector,
                        score=item.score,
                    )
                )

        sandbox_spans: list[SandboxSpanDetail] = []
        if sandbox_trace:
            for item in planned:
                sandbox_spans.append(
                    SandboxSpanDetail(
                        kind="masked",
                        label=item.label,
                        orig_start=item.orig_start,
                        orig_end=item.orig_end,
                        detector=item.detector,
                        score=item.score,
                        replacement=item.replacement,
                    )
                )
            for ex in detection.exempted_spans:
                if not _overlaps_any(ex.start, ex.end, protected_ranges):
                    sandbox_spans.append(
                        SandboxSpanDetail(
                            kind="exempted",
                            label=ex.label,
                            orig_start=ex.start,
                            orig_end=ex.end,
                            detector=ex.detector,
                            score=ex.score,
                            allowlist_group=ex.group_code,
                            allowlist_rule=ex.rule_name,
                        )
                    )
            sandbox_spans.sort(key=lambda s: (s.orig_start, s.orig_end))

        return masked_text, planned, masked_spans, sandbox_spans

    def _mask_replay_and_high_risk_field(
        self,
        text: str,
        snapshot: ResolvedPolicySnapshot,
        scope: EphemeralScopeDict,
        high_risk_labels: frozenset[str],
        *,
        sandbox_trace: bool = False,
    ) -> tuple[str, list[PlannedReplacement], list[SandboxSpanDetail]]:
        protected_ranges = _find_protected_mask_ranges(text, snapshot.entity_rules)
        replay_planned: list[PlannedReplacement] = []

        # Step A: Longest-first literal replay of user-side scope entities
        for entry in scope.replay_entries():
            needle = entry.raw_text
            if not needle:
                continue
            search_from = 0
            n_len = len(needle)
            while True:
                idx = text.find(needle, search_from)
                if idx < 0:
                    break
                end_idx = idx + n_len
                if _overlaps_any(idx, end_idx, protected_ranges):
                    search_from = idx + 1
                    continue
                protected_ranges.append((idx, end_idx))
                replay_planned.append(
                    PlannedReplacement(
                        label=entry.label,
                        orig_start=idx,
                        orig_end=end_idx,
                        replacement=entry.replacement,
                        detector=entry.detector,
                        score=entry.score,
                    )
                )
                search_from = end_idx

        # Step B: High-risk-only rescan (skips landline phone, private_address, url, etc.)
        high_risk_planned: list[PlannedReplacement] = []
        exempted_details: list[SandboxSpanDetail] = []
        if high_risk_labels and text:
            try:
                detection = self._get_pipeline().detect(
                    text,
                    entity_rules=snapshot.entity_rules,
                    allowlist_entries=snapshot.allowlist_entries,
                    onnx_variant=snapshot.onnx_variant,
                    only_labels=high_risk_labels,
                    active_allowlist_groups=(
                        set(snapshot.allowlist_groups)
                        if snapshot.allowlist_groups
                        else set()
                    ),
                    trace_exemptions=sandbox_trace,
                )
            except InvalidAllowlistPatternError as exc:
                raise BadRequestError(str(exc)) from None

            surviving_hr = [
                s
                for s in detection.spans
                if not _overlaps_any(s.start, s.end, protected_ranges)
            ]
            high_risk_planned = plan_detected_replacements(
                text,
                surviving_hr,
                entity_rules=snapshot.entity_rules,
                scope=scope,
                hash_salt=self._get_hash_salt(),
                write_replay=False,
            )
            if sandbox_trace:
                for ex in detection.exempted_spans:
                    if not _overlaps_any(ex.start, ex.end, protected_ranges):
                        exempted_details.append(
                            SandboxSpanDetail(
                                kind="exempted",
                                label=ex.label,
                                orig_start=ex.start,
                                orig_end=ex.end,
                                detector=ex.detector,
                                score=ex.score,
                                allowlist_group=ex.group_code,
                                allowlist_rule=ex.rule_name,
                            )
                        )

        combined = sorted(
            [*replay_planned, *high_risk_planned],
            key=lambda item: (item.orig_start, item.orig_end),
        )
        masked_text, _ = replace_spans_reverse(text, combined)

        sandbox_spans: list[SandboxSpanDetail] = []
        if sandbox_trace:
            for item in combined:
                sandbox_spans.append(
                    SandboxSpanDetail(
                        kind="masked",
                        label=item.label,
                        orig_start=item.orig_start,
                        orig_end=item.orig_end,
                        detector=item.detector,
                        score=item.score,
                        replacement=item.replacement,
                    )
                )
            sandbox_spans.extend(exempted_details)
            sandbox_spans.sort(key=lambda s: (s.orig_start, s.orig_end))

        return masked_text, combined, sandbox_spans

    def mask_text(
        self,
        text: str,
        snapshot: ResolvedPolicySnapshot,
        *,
        scope: EphemeralScopeDict | None = None,
        return_spans: bool = False,
        sandbox_trace: bool = False,
    ) -> TextMaskResult:
        t0 = time.perf_counter()
        owns_scope = scope is None or snapshot.scope_mode == "NONE"
        active_scope = (
            EphemeralScopeDict(mode=snapshot.scope_mode)
            if owns_scope
            else scope
        )
        assert active_scope is not None

        try:
            masked_text, planned, masked_spans, sandbox_spans = (
                self._mask_full_write_scope_field(
                    text,
                    snapshot,
                    active_scope,
                    return_spans=return_spans,
                    sandbox_trace=sandbox_trace,
                )
            )
            hit_counts: dict[str, int] = {}
            for item in planned:
                hit_counts[item.label] = hit_counts.get(item.label, 0) + 1

            elapsed_ms = max(0, int(round((time.perf_counter() - t0) * 1000)))
            return TextMaskResult(
                masked_text=masked_text,
                hit_counts=hit_counts,
                elapsed_ms=elapsed_ms,
                masked_spans=masked_spans,
                sandbox_spans=sandbox_spans,
            )
        finally:
            if owns_scope:
                active_scope.clear()

    def mask_structured_record(
        self,
        payload: dict[str, Any],
        snapshot: ResolvedPolicySnapshot,
        *,
        column_role_override: Mapping[str, str] | None = None,
        sandbox_trace: bool = False,
        scope: EphemeralScopeDict | None = None,
    ) -> RecordMaskResult:
        if not isinstance(payload, dict):
            raise BadRequestError("Structured payload must be a JSON object")

        router = compile_field_role_router(snapshot.field_role_rules)
        payload_copy: dict[str, Any] = deepcopy(payload)
        pass1_leaves, pass2_leaves, _passthrough_leaves = assign_leaf_roles(
            payload_copy,
            router,
            column_role_override=column_role_override,
        )

        # In CONVERSATION mode an external session scope may be shared across records;
        # in RECORD or NONE mode, every record uses its own isolated scope cleared on return.
        use_external_scope = (
            scope is not None and snapshot.scope_mode == "CONVERSATION"
        )
        active_scope = (
            scope
            if use_external_scope
            else EphemeralScopeDict(mode=snapshot.scope_mode)
        )
        assert active_scope is not None

        hit_counts: dict[str, int] = {}
        char_count = 0
        sandbox_field_traces: dict[str, list[SandboxSpanDetail]] = {}

        try:
            # Pass 1: FULL_MASK_WRITE_SCOPE (detect all enabled labels & write scope)
            for leaf in pass1_leaves:
                raw_text = leaf.value
                char_count += len(raw_text)
                masked_val, planned, _, field_trace = self._mask_full_write_scope_field(
                    raw_text,
                    snapshot,
                    active_scope,
                    return_spans=False,
                    sandbox_trace=sandbox_trace,
                )
                leaf.set_value(masked_val)
                for item in planned:
                    hit_counts[item.label] = hit_counts.get(item.label, 0) + 1
                if sandbox_trace:
                    sandbox_field_traces[leaf.canonical_path] = field_trace

            # Pass 2: REPLAY_SCOPE_AND_HIGH_RISK (longest-first literal replay + high-risk rescan)
            for leaf in pass2_leaves:
                raw_text = leaf.value
                char_count += len(raw_text)
                masked_val, planned, field_trace = self._mask_replay_and_high_risk_field(
                    raw_text,
                    snapshot,
                    active_scope,
                    router.high_risk_only_labels,
                    sandbox_trace=sandbox_trace,
                )
                leaf.set_value(masked_val)
                for item in planned:
                    hit_counts[item.label] = hit_counts.get(item.label, 0) + 1
                if sandbox_trace:
                    sandbox_field_traces[leaf.canonical_path] = field_trace

            return RecordMaskResult(
                masked_payload=payload_copy,
                hit_counts=hit_counts,
                char_count=char_count,
                sandbox_field_traces=sandbox_field_traces,
            )
        finally:
            if not use_external_scope:
                active_scope.clear()


_default_engine_service: PolicyEngineService | None = None


def get_policy_engine() -> PolicyEngineService:
    global _default_engine_service
    if _default_engine_service is None:
        _default_engine_service = PolicyEngineService()
    return _default_engine_service


def set_policy_engine(service: PolicyEngineService | None) -> None:
    global _default_engine_service
    _default_engine_service = service
