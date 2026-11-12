from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_admin
from app.auth.security import (
    check_onnx_ready,
    create_access_token,
    verify_password,
)
from app.common.envelope import ok_response
from app.common.errors import UnauthorizedError
from app.config import get_request_settings
from app.db.base import utcnow
from app.db.models import AdminUser
from app.db.session import get_session

router = APIRouter(prefix="/api/admin/auth", tags=["admin-auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.post("/login")
def admin_login(
    body: LoginRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    settings = get_request_settings(request)
    admin = session.scalar(
        select(AdminUser).where(
            AdminUser.username == body.username.strip(),
            AdminUser.is_deleted == 0,
        )
    )
    if (
        admin is None
        or admin.is_enabled != 1
        or not verify_password(body.password, admin.password_hash)
    ):
        raise UnauthorizedError("Invalid username or password")

    admin.last_login_at = utcnow()
    session.commit()

    access_token, expires_in = create_access_token(
        user_uuid=admin.uuid,
        username=admin.username,
        role=admin.role,
        settings=settings,
    )
    onnx_ready = check_onnx_ready(request, settings, settings.default_onnx_variant)

    return ok_response(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "user": {
                "uuid": admin.uuid,
                "username": admin.username,
                "display_name": admin.display_name,
                "role": admin.role,
            },
            "onnx_ready": onnx_ready,
        },
        request=request,
    )


@router.get("/me")
def admin_me(
    request: Request,
    admin: AdminUser = Depends(get_current_admin),
) -> dict:
    settings = get_request_settings(request)
    onnx_variant = settings.default_onnx_variant
    onnx_ready = check_onnx_ready(request, settings, onnx_variant)
    return ok_response(
        {
            "uuid": admin.uuid,
            "username": admin.username,
            "display_name": admin.display_name,
            "role": admin.role,
            "onnx_ready": onnx_ready,
            "onnx_variant": onnx_variant,
        },
        request=request,
    )
