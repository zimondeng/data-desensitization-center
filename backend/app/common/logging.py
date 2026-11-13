from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

FORBIDDEN_LOG_KEYS: frozenset[str] = frozenset(
    {
        "text",
        "raw_text",
        "input_text",
        "plain_text",
        "plaintext",
        "payload",
        "plain_key",
        "api_key",
        "password",
        "password_cipher",
        "items",
        "content",
        "query_text",
        "answer_text",
    }
)

_API_KEY_SECRET_RE = re.compile(r"\b(dsk_[a-zA-Z0-9]{1,8}_[a-zA-Z0-9]{4})[a-zA-Z0-9_-]+")


def mask_text_safe_log(char_len: int, hit_counts: Mapping[str, int]) -> str:
    """Safe telemetry summary with character count and entity label hit counts only."""
    return f"masked_chars={int(char_len)} hits={dict(hit_counts)}"


def sanitize_log_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in fields.items():
        if key.lower() in FORBIDDEN_LOG_KEYS:
            continue
        if isinstance(value, str):
            safe[key] = _API_KEY_SECRET_RE.sub(r"\1***", value)
        else:
            safe[key] = value
    return safe


class ZeroPlaintextLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _API_KEY_SECRET_RE.sub(r"\1***", record.msg)
        if isinstance(record.args, Mapping):
            record.args = sanitize_log_fields(record.args)
        elif isinstance(record.args, tuple):
            record.args = tuple(
                _API_KEY_SECRET_RE.sub(r"\1***", arg) if isinstance(arg, str) else arg
                for arg in record.args
            )
        return True


def get_safe_logger(name: str = "ds_center") -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(isinstance(flt, ZeroPlaintextLogFilter) for flt in logger.filters):
        logger.addFilter(ZeroPlaintextLogFilter())
    return logger
