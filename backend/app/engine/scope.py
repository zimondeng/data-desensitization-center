from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.detectors.types import DetectorSource

ScopeMode = Literal["CONVERSATION", "RECORD", "NONE"]
SCOPE_MODES: frozenset[str] = frozenset({"CONVERSATION", "RECORD", "NONE"})


def normalize_scope_entity(raw_text: str) -> str:
    stripped = raw_text.strip()
    return stripped if stripped else raw_text


@dataclass(frozen=True, slots=True)
class ScopeReplayEntry:
    raw_text: str
    replacement: str
    label: str
    detector: DetectorSource
    score: float
    order_index: int


class EphemeralScopeDict:
    """Stack-frame / single-session ephemeral consistency mapping.

    Never persisted or logged; explicitly cleared before request/record return.
    """

    __slots__ = ("_mode", "_counters", "_mappings", "_replay_entries_by_text", "_next_order")

    def __init__(self, mode: ScopeMode = "CONVERSATION") -> None:
        if mode not in SCOPE_MODES:
            raise ValueError(f"Unsupported scope_mode: '{mode}'")
        self._mode: ScopeMode = mode
        self._counters: dict[str, int] = {}
        self._mappings: dict[tuple[str, str], str] = {}
        self._replay_entries_by_text: dict[str, ScopeReplayEntry] = {}
        self._next_order: int = 0

    @property
    def mode(self) -> ScopeMode:
        return self._mode

    @property
    def is_empty(self) -> bool:
        return (
            not self._counters
            and not self._mappings
            and not self._replay_entries_by_text
        )

    def lookup(self, group_key: str, raw_text: str) -> str | None:
        if self._mode == "NONE":
            return None
        norm = normalize_scope_entity(raw_text)
        return self._mappings.get((group_key, norm))

    def next_sequence(self, prefix: str) -> int:
        nxt = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = nxt
        return nxt

    def register(
        self,
        *,
        group_key: str,
        raw_text: str,
        replacement: str,
        label: str,
        detector: DetectorSource,
        score: float,
        write_replay: bool = True,
    ) -> str:
        if self._mode == "NONE":
            return replacement

        norm = normalize_scope_entity(raw_text)
        self._mappings[(group_key, norm)] = replacement

        if write_replay and norm and norm not in self._replay_entries_by_text:
            self._replay_entries_by_text[norm] = ScopeReplayEntry(
                raw_text=norm,
                replacement=replacement,
                label=label,
                detector=detector,
                score=score,
                order_index=self._next_order,
            )
            self._next_order += 1

        return replacement

    def replay_entries(self) -> tuple[ScopeReplayEntry, ...]:
        if self._mode == "NONE" or not self._replay_entries_by_text:
            return ()
        return tuple(
            sorted(
                self._replay_entries_by_text.values(),
                key=lambda item: (-len(item.raw_text), item.order_index),
            )
        )

    def clear(self) -> None:
        self._counters.clear()
        self._mappings.clear()
        self._replay_entries_by_text.clear()
        self._next_order = 0

    def __enter__(self) -> EphemeralScopeDict:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.clear()
