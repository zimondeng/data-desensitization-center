from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
import re
from typing import Any, Literal

from jsonpath_ng.exceptions import JSONPathError
from jsonpath_ng.ext import parse as parse_jsonpath

from app.common.errors import BadRequestError
from app.detectors.types import ALL_ENTITY_LABELS

FieldRole = Literal[
    "FULL_MASK_WRITE_SCOPE",
    "REPLAY_SCOPE_AND_HIGH_RISK",
    "PASSTHROUGH",
]

FIELD_ROLES: frozenset[str] = frozenset(
    {
        "FULL_MASK_WRITE_SCOPE",
        "REPLAY_SCOPE_AND_HIGH_RISK",
        "PASSTHROUGH",
    }
)

DEFAULT_HIGH_RISK_LABELS: tuple[str, ...] = (
    "cn_id_card",
    "cn_mobile",
    "bank_card_luhn",
    "payment_card",
    "common_secret",
)

_SIMPLE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(slots=True)
class StringLeafRef:
    loc_key: tuple[int, str | int]
    parent: dict[str, Any] | list[Any]
    slot: str | int
    canonical_path: str

    @property
    def value(self) -> str:
        val = self.parent[self.slot]  # type: ignore[index]
        assert isinstance(val, str)
        return val

    def set_value(self, new_val: str) -> None:
        self.parent[self.slot] = new_val  # type: ignore[index]


@dataclass(frozen=True, slots=True)
class CompiledFieldRoleRule:
    jsonpath: str
    role: FieldRole
    compiled: Any


@dataclass(frozen=True, slots=True)
class CompiledFieldRouter:
    default_role: FieldRole
    high_risk_only_labels: frozenset[str]
    rules: tuple[CompiledFieldRoleRule, ...]


def compile_jsonpath_expr(expr_str: str) -> Any:
    if not isinstance(expr_str, str) or not expr_str.strip():
        raise BadRequestError("JSONPath expression must not be empty")
    cleaned = expr_str.strip()
    if not (cleaned == "$" or cleaned.startswith(("$.", "$["))):
        raise BadRequestError("Invalid JSONPath expression: must start with '$', '$.', or '$['")
    try:
        compiled = parse_jsonpath(cleaned)
        compiled.find({})
        return compiled
    except BadRequestError:
        raise
    except (JSONPathError, Exception):
        raise BadRequestError("Invalid JSONPath expression syntax") from None


def validate_field_role(role: Any) -> FieldRole:
    if not isinstance(role, str) or role not in FIELD_ROLES:
        raise BadRequestError(
            "Invalid field role: must be FULL_MASK_WRITE_SCOPE, REPLAY_SCOPE_AND_HIGH_RISK, or PASSTHROUGH"
        )
    return role  # type: ignore[return-value]


def compile_field_role_router(
    field_role_rules: Mapping[str, Any] | None,
) -> CompiledFieldRouter:
    if not field_role_rules:
        return CompiledFieldRouter(
            default_role="FULL_MASK_WRITE_SCOPE",
            high_risk_only_labels=frozenset(DEFAULT_HIGH_RISK_LABELS),
            rules=(),
        )
    if not isinstance(field_role_rules, Mapping):
        raise BadRequestError("field_role_rules must be an object")

    default_role = validate_field_role(
        field_role_rules.get("default_role", "FULL_MASK_WRITE_SCOPE")
    )

    raw_hr = field_role_rules.get("high_risk_only_labels")
    if raw_hr is None:
        high_risk = frozenset(DEFAULT_HIGH_RISK_LABELS)
    else:
        if not isinstance(raw_hr, (list, tuple, set, frozenset)):
            raise BadRequestError("high_risk_only_labels must be a list of entity labels")
        hr_set: set[str] = set()
        for lbl in raw_hr:
            if not isinstance(lbl, str) or lbl not in ALL_ENTITY_LABELS:
                raise BadRequestError("Unsupported entity label in high_risk_only_labels")
            hr_set.add(lbl)
        high_risk = frozenset(hr_set)

    raw_rules = field_role_rules.get("rules", [])
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, (list, tuple)):
        raise BadRequestError("field_role_rules.rules must be a list")

    compiled_rules: list[CompiledFieldRoleRule] = []
    for item in raw_rules:
        if not isinstance(item, Mapping):
            raise BadRequestError("Each field role rule must be an object")
        jp = item.get("jsonpath")
        role = validate_field_role(item.get("role"))
        if not isinstance(jp, str):
            raise BadRequestError("Each field role rule requires a string 'jsonpath'")
        compiled_expr = compile_jsonpath_expr(jp)
        compiled_rules.append(
            CompiledFieldRoleRule(
                jsonpath=jp.strip(),
                role=role,
                compiled=compiled_expr,
            )
        )

    return CompiledFieldRouter(
        default_role=default_role,
        high_risk_only_labels=high_risk,
        rules=tuple(compiled_rules),
    )


def _format_segment(prefix: str, key: str | int) -> str:
    if isinstance(key, int):
        return f"{prefix}[{key}]"
    if _SIMPLE_IDENT_RE.match(key):
        return f"{prefix}.{key}"
    escaped = key.replace("\\", "\\\\").replace("'", "\\'")
    return f"{prefix}['{escaped}']"


def collect_string_leaves(root: Any) -> list[StringLeafRef]:
    leaves: list[StringLeafRef] = []

    def _walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                child_path = _format_segment(prefix, k)
                if isinstance(v, str):
                    leaves.append(
                        StringLeafRef(
                            loc_key=(id(node), k),
                            parent=node,
                            slot=k,
                            canonical_path=child_path,
                        )
                    )
                elif isinstance(v, (dict, list)):
                    _walk(v, child_path)
        elif isinstance(node, list):
            for idx, v in enumerate(node):
                child_path = _format_segment(prefix, idx)
                if isinstance(v, str):
                    leaves.append(
                        StringLeafRef(
                            loc_key=(id(node), idx),
                            parent=node,
                            slot=idx,
                            canonical_path=child_path,
                        )
                    )
                elif isinstance(v, (dict, list)):
                    _walk(v, child_path)

    _walk(root, "$")
    return leaves


def _iter_container_leaf_keys(container: Any) -> Iterator[tuple[int, str | int]]:
    if isinstance(container, dict):
        for k, v in container.items():
            if isinstance(v, str):
                yield (id(container), k)
            elif isinstance(v, (dict, list)):
                yield from _iter_container_leaf_keys(v)
    elif isinstance(container, list):
        for idx, v in enumerate(container):
            if isinstance(v, str):
                yield (id(container), idx)
            elif isinstance(v, (dict, list)):
                yield from _iter_container_leaf_keys(v)


def _extract_datum_leaf_keys(datum: Any) -> list[tuple[int, str | int]]:
    val = datum.value
    if isinstance(val, (dict, list)):
        return list(_iter_container_leaf_keys(val))
    if not isinstance(val, str):
        return []

    ctx = getattr(datum, "context", None)
    if ctx is None:
        return []
    parent = ctx.value
    path_obj = datum.path

    keys: list[tuple[int, str | int]] = []
    if isinstance(parent, dict) and hasattr(path_obj, "fields"):
        for field_name in path_obj.fields:
            if field_name in parent and isinstance(parent[field_name], str):
                keys.append((id(parent), field_name))
    elif isinstance(parent, list):
        if hasattr(path_obj, "indices"):
            raw_indices: tuple[Any, ...] | list[Any] = path_obj.indices
        elif hasattr(path_obj, "index"):
            raw_indices = (path_obj.index,)
        else:
            raw_indices = ()
        n = len(parent)
        for idx in raw_indices:
            if isinstance(idx, int) and not isinstance(idx, bool) and -n <= idx < n:
                real_idx = idx if idx >= 0 else n + idx
                if isinstance(parent[real_idx], str):
                    keys.append((id(parent), real_idx))
    return keys


def assign_leaf_roles(
    payload_copy: dict[str, Any],
    router: CompiledFieldRouter,
    *,
    column_role_override: Mapping[str, str] | None = None,
) -> tuple[list[StringLeafRef], list[StringLeafRef], list[StringLeafRef]]:
    """Assign each string leaf in payload_copy to Pass 1, Pass 2, or Passthrough."""
    all_leaves = collect_string_leaves(payload_copy)
    if not all_leaves:
        return [], [], []

    leaf_by_key: dict[tuple[int, str | int], StringLeafRef] = {
        leaf.loc_key: leaf for leaf in all_leaves
    }
    assigned_role: dict[tuple[int, str | int], FieldRole] = {}

    # 1. Explicit column_role_override (highest priority, used by #6 batch-jobs)
    if column_role_override:
        for col_or_path, raw_role in column_role_override.items():
            role = validate_field_role(raw_role)
            if col_or_path.startswith("$"):
                compiled = compile_jsonpath_expr(col_or_path)
                for datum in compiled.find(payload_copy):
                    for lk in _extract_datum_leaf_keys(datum):
                        if lk in leaf_by_key and lk not in assigned_role:
                            assigned_role[lk] = role
            elif col_or_path in payload_copy:
                val = payload_copy[col_or_path]
                if isinstance(val, str):
                    lk = (id(payload_copy), col_or_path)
                    if lk in leaf_by_key and lk not in assigned_role:
                        assigned_role[lk] = role
                elif isinstance(val, (dict, list)):
                    for lk in _iter_container_leaf_keys(val):
                        if lk in leaf_by_key and lk not in assigned_role:
                            assigned_role[lk] = role

    # 2. Policy field_role_rules.rules in declaration order
    for rule in router.rules:
        for datum in rule.compiled.find(payload_copy):
            for lk in _extract_datum_leaf_keys(datum):
                if lk in leaf_by_key and lk not in assigned_role:
                    assigned_role[lk] = rule.role

    # 3. Fallback default_role for remaining string leaves
    pass1_full: list[StringLeafRef] = []
    pass2_replay: list[StringLeafRef] = []
    passthrough: list[StringLeafRef] = []

    for leaf in all_leaves:
        role = assigned_role.get(leaf.loc_key, router.default_role)
        if role == "FULL_MASK_WRITE_SCOPE":
            pass1_full.append(leaf)
        elif role == "REPLAY_SCOPE_AND_HIGH_RISK":
            pass2_replay.append(leaf)
        else:
            passthrough.append(leaf)

    return pass1_full, pass2_replay, passthrough
