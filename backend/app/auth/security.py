from __future__ import annotations

import hashlib
import importlib
import importlib.util
import inspect
import ipaddress
import secrets
import time
from pathlib import Path
from typing import Any

import bcrypt
import jwt
from fastapi import Request

from app.common.errors import BadRequestError, UnauthorizedError
from app.config import Settings


def hash_password(password: str, rounds: int = 12) -> str:
    raw = password.encode("utf-8")
    if not raw or len(raw) > 72:
        raise BadRequestError("Password must be between 1 and 72 UTF-8 bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password or not password_hash:
        return False
    raw = password.encode("utf-8")
    if len(raw) > 72:
        return False
    try:
        return bcrypt.checkpw(raw, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(
    *,
    user_uuid: str,
    username: str,
    role: str,
    settings: Settings,
) -> tuple[str, int]:
    now_ts = int(time.time())
    expires_in = int(settings.jwt_expire_seconds)
    payload = {
        "sub": user_uuid,
        "username": username,
        "role": role,
        "typ": "admin_access",
        "iat": now_ts,
        "exp": now_ts + expires_in,
    }
    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token, expires_in


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    if not token or token.startswith("dsk_"):
        raise UnauthorizedError("Invalid or expired token")
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError as exc:
        raise UnauthorizedError("Invalid or expired token") from exc
    if not isinstance(payload, dict) or not payload.get("sub"):
        raise UnauthorizedError("Invalid token payload")
    return payload


def hash_api_key(plain_key: str) -> str:
    return hashlib.sha256(plain_key.encode("utf-8")).hexdigest()


def generate_api_key(env_tag: str = "live") -> tuple[str, str, str]:
    clean_tag = env_tag if env_tag in ("live", "test") else "live"
    secret_hex = secrets.token_hex(20)
    plain_key = f"dsk_{clean_tag}_{secret_hex}"
    key_prefix = plain_key[:13]
    key_sha256 = hash_api_key(plain_key)
    return plain_key, key_prefix, key_sha256


def validate_allowed_ips_config(allowed_ips: list[str] | None) -> list[str] | None:
    if allowed_ips is None:
        return None
    normalized: list[str] = []
    for raw_entry in allowed_ips:
        entry = str(raw_entry).strip()
        if not entry:
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise BadRequestError(f"Invalid IP or CIDR entry: {entry}") from exc
        normalized.append(entry)
    return normalized or None


def is_client_ip_allowed(
    client_ip: str | None,
    allowed_ips: list[str] | None,
) -> bool:
    if not allowed_ips:
        return True
    if not client_ip:
        return False
    try:
        addr = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return False

    candidates = [addr]
    mapped_v4 = getattr(addr, "ipv4_mapped", None)
    if mapped_v4 is not None:
        candidates.append(mapped_v4)

    for entry in allowed_ips:
        try:
            net = ipaddress.ip_network(str(entry).strip(), strict=False)
        except ValueError:
            continue
        for cand in candidates:
            if cand.version == net.version and cand in net:
                return True
    return False


def _has_module(mod_name: str) -> bool:
    try:
        return importlib.util.find_spec(mod_name) is not None
    except ModuleNotFoundError:
        return False


def _check_models_dir_ready(models_dir: Path, variant: str) -> bool:
    candidates = (
        models_dir / variant,
        models_dir / "astrlink-guard" / variant,
        models_dir,
    )
    for cand in candidates:
        if not cand.is_dir():
            continue
        has_onnx = any(p.is_file() for p in cand.glob("*.onnx"))
        has_tokenizer = (cand / "tokenizer.json").is_file() or (
            cand.parent / "tokenizer.json"
        ).is_file()
        if has_onnx and has_tokenizer:
            return True
    return False


def check_onnx_ready(
    request: Request | None,
    settings: Settings,
    variant: str | None = None,
) -> bool:
    target_variant = variant or settings.default_onnx_variant

    if request is not None:
        state_pipeline = getattr(request.app.state, "detector_pipeline", None)
        if state_pipeline is not None and hasattr(state_pipeline, "is_onnx_ready"):
            try:
                return bool(state_pipeline.is_onnx_ready(target_variant))
            except TypeError:
                return bool(state_pipeline.is_onnx_ready())

    for mod_name in ("app.detectors.pipeline", "app.detectors"):
        if not _has_module(mod_name):
            continue
        mod = importlib.import_module(mod_name)
        fn = getattr(mod, "is_onnx_ready", None)
        if callable(fn):
            try:
                sig = inspect.signature(fn)
                kwargs: dict[str, Any] = {}
                for param_name in ("models_dir", "model_dir", "model_root", "base_dir"):
                    if param_name in sig.parameters:
                        kwargs[param_name] = settings.models_dir
                        break
                if "variant" in sig.parameters:
                    kwargs["variant"] = target_variant
                return bool(fn(**kwargs))
            except Exception:
                pass

        pipeline_cls = getattr(mod, "HybridDetectorPipeline", None)
        if isinstance(pipeline_cls, type) and hasattr(pipeline_cls, "is_onnx_ready"):
            try:
                sig = inspect.signature(pipeline_cls.__init__)
                init_kwargs: dict[str, Any] = {}
                for param_name in ("models_dir", "model_dir", "model_root", "base_dir"):
                    if param_name in sig.parameters:
                        init_kwargs[param_name] = settings.models_dir
                        break
                instance = pipeline_cls(**init_kwargs)
                return bool(instance.is_onnx_ready(target_variant))
            except Exception:
                pass

    return _check_models_dir_ready(settings.models_dir, target_variant)
