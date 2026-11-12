from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.rate_limiter import SlidingWindowRateLimiter
from app.auth.security import (
    decode_access_token,
    hash_api_key,
    is_client_ip_allowed,
)
from app.common.errors import (
    ForbiddenError,
    RateLimitExceededError,
    UnauthorizedError,
)
from app.config import get_request_settings
from app.db.base import utcnow
from app.db.models import AdminUser, ApiKey
from app.db.session import get_session

_FALLBACK_RATE_LIMITER = SlidingWindowRateLimiter()


@dataclass(slots=True)
class CallerPrincipal:
    domain: Literal["ADMIN_JWT", "API_KEY"]
    triggered_by: str
    admin_user: AdminUser | None = None
    api_key: ApiKey | None = None
    role: str | None = None
    default_policy_code: str = "strict_general"

    def require_admin_roles(self, *roles: str) -> None:
        if self.domain == "ADMIN_JWT" and roles and self.role not in roles:
            raise ForbiddenError(
                f"Role '{self.role}' is not permitted for this operation"
            )


def _extract_bearer_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization", "").strip()
    if not auth_header:
        return None
    parts = auth_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _extract_raw_api_key(request: Request) -> str | None:
    x_api_key = request.headers.get("X-API-Key", "").strip()
    if x_api_key:
        return x_api_key
    bearer = _extract_bearer_token(request)
    if bearer and bearer.startswith("dsk_"):
        return bearer
    return None


def _extract_client_ip(request: Request, trust_proxy_headers: bool) -> str | None:
    raw_host = request.client.host if request.client is not None else None
    if trust_proxy_headers or raw_host == "testclient":
        xff = request.headers.get("X-Forwarded-For", "").strip()
        if xff:
            first_hop = xff.split(",")[0].strip()
            if first_hop:
                return first_hop
        x_real_ip = request.headers.get("X-Real-IP", "").strip()
        if x_real_ip:
            return x_real_ip
    return raw_host


def get_current_admin(
    request: Request,
    session: Session = Depends(get_session),
) -> AdminUser:
    token = _extract_bearer_token(request)
    if not token:
        raise UnauthorizedError("Missing or invalid Authorization Bearer token")
    if token.startswith("dsk_"):
        raise UnauthorizedError("API Key cannot be used on admin endpoints")

    settings = get_request_settings(request)
    payload = decode_access_token(token, settings)
    user_uuid = str(payload["sub"])

    admin = session.scalar(
        select(AdminUser).where(
            AdminUser.uuid == user_uuid,
            AdminUser.is_deleted == 0,
        )
    )
    if admin is None or admin.is_enabled != 1:
        raise UnauthorizedError("Admin account is disabled or does not exist")
    return admin


def require_roles(*roles: str) -> Callable[..., AdminUser]:
    allowed = frozenset(roles)

    def _role_guard(admin: AdminUser = Depends(get_current_admin)) -> AdminUser:
        if admin.role not in allowed:
            raise ForbiddenError(
                f"Role '{admin.role}' is not permitted for this operation"
            )
        return admin

    return _role_guard


def get_current_api_key(
    request: Request,
    session: Session = Depends(get_session),
) -> ApiKey:
    raw_key = _extract_raw_api_key(request)
    if not raw_key or not raw_key.startswith("dsk_"):
        raise UnauthorizedError("Missing or invalid API Key")

    digest = hash_api_key(raw_key)
    api_key = session.scalar(
        select(ApiKey).where(
            ApiKey.key_sha256 == digest,
            ApiKey.is_deleted == 0,
        )
    )
    if api_key is None:
        raise UnauthorizedError("Invalid API Key")

    if api_key.status != "ACTIVE":
        raise ForbiddenError("API Key has been revoked")

    now = utcnow()
    if api_key.expires_at is not None and api_key.expires_at <= now:
        raise ForbiddenError("API Key has expired")

    settings = get_request_settings(request)
    client_ip = _extract_client_ip(request, settings.trust_proxy_headers)
    if not is_client_ip_allowed(client_ip, api_key.allowed_ips_json):
        raise ForbiddenError("Client IP is not in the API Key allowlist")

    limiter: SlidingWindowRateLimiter = (
        getattr(request.app.state, "rate_limiter", None) or _FALLBACK_RATE_LIMITER
    )
    if not limiter.allow(api_key.id, api_key.rate_limit_rpm):
        raise RateLimitExceededError("API Key rate limit exceeded")

    api_key.last_used_at = now
    session.commit()
    return api_key


def get_job_caller(
    request: Request,
    session: Session = Depends(get_session),
) -> CallerPrincipal:
    if request.headers.get("X-API-Key", "").strip():
        key = get_current_api_key(request, session)
        return CallerPrincipal(
            domain="API_KEY",
            triggered_by=key.key_prefix,
            api_key=key,
            default_policy_code=key.default_policy_code,
        )

    bearer = _extract_bearer_token(request)
    if bearer and bearer.startswith("dsk_"):
        key = get_current_api_key(request, session)
        return CallerPrincipal(
            domain="API_KEY",
            triggered_by=key.key_prefix,
            api_key=key,
            default_policy_code=key.default_policy_code,
        )
    if bearer:
        admin = get_current_admin(request, session)
        return CallerPrincipal(
            domain="ADMIN_JWT",
            triggered_by=admin.username,
            admin_user=admin,
            role=admin.role,
        )

    raise UnauthorizedError("Missing authentication credentials")


def require_job_caller(*admin_roles: str) -> Callable[..., CallerPrincipal]:
    def _caller_guard(
        caller: CallerPrincipal = Depends(get_job_caller),
    ) -> CallerPrincipal:
        caller.require_admin_roles(*admin_roles)
        return caller

    return _caller_guard
