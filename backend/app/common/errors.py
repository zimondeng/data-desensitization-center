from __future__ import annotations

import importlib
import importlib.util
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.common.envelope import get_request_id
from app.common.logging import get_safe_logger

logger = get_safe_logger("ds_center.errors")


class AppError(Exception):
    def __init__(
        self,
        http_status: int,
        code: int,
        message: str,
        data: Any = None,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message
        self.data = data


class BadRequestError(AppError):
    def __init__(self, message: str = "Invalid request parameters", data: Any = None) -> None:
        super().__init__(400, 40001, message, data=data)


class UnauthorizedError(AppError):
    def __init__(self, message: str = "Unauthorized", data: Any = None) -> None:
        super().__init__(401, 40101, message, data=data)


class ForbiddenError(AppError):
    def __init__(self, message: str = "Forbidden", data: Any = None) -> None:
        super().__init__(403, 40301, message, data=data)


class NotFoundError(AppError):
    def __init__(self, message: str = "Resource not found", data: Any = None) -> None:
        super().__init__(404, 40401, message, data=data)


class ConflictLeakBlockedError(AppError):
    def __init__(
        self,
        message: str = "Artifact flagged for potential leak; download blocked",
        data: Any = None,
    ) -> None:
        super().__init__(409, 40901, message, data=data)


class ArtifactExpiredError(AppError):
    def __init__(
        self,
        message: str = "Artifact has expired and been removed",
        data: Any = None,
    ) -> None:
        super().__init__(410, 41001, message, data=data)


class RateLimitExceededError(AppError):
    def __init__(
        self,
        message: str = "API Key rate limit exceeded",
        data: Any = None,
    ) -> None:
        super().__init__(429, 42901, message, data=data)


class ModelNotReadyError(AppError):
    def __init__(
        self,
        message: str = "Local AstrLink Guard ONNX model is not ready",
        data: Any = None,
    ) -> None:
        super().__init__(503, 50301, message, data=data)


_HTTP_STATUS_TO_CODE: dict[int, int] = {
    400: 40001,
    401: 40101,
    403: 40301,
    404: 40401,
    405: 40001,
    409: 40901,
    410: 41001,
    422: 40001,
    429: 42901,
    503: 50301,
}


def build_error_response(
    request: Request,
    *,
    http_status: int,
    code: int,
    message: str,
    data: Any = None,
) -> JSONResponse:
    req_id = get_request_id(request)
    response = JSONResponse(
        status_code=http_status,
        content={
            "code": code,
            "message": message,
            "request_id": req_id,
            "data": data,
        },
    )
    response.headers["X-Request-Id"] = req_id
    return response


def map_dynamic_domain_exception(request: Request, exc: BaseException) -> JSONResponse | None:
    mro_names = {cls.__name__ for cls in type(exc).__mro__}
    if "DetectorNotReadyError" in mro_names:
        return build_error_response(
            request,
            http_status=503,
            code=50301,
            message=str(exc) or "Local AstrLink Guard ONNX model is not ready",
        )
    if "InvalidAllowlistPatternError" in mro_names:
        return build_error_response(
            request,
            http_status=400,
            code=40001,
            message=str(exc) or "Invalid allowlist pattern",
        )
    return None


def _has_module(mod_name: str) -> bool:
    try:
        return importlib.util.find_spec(mod_name) is not None
    except ModuleNotFoundError:
        return False


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        return build_error_response(
            request,
            http_status=exc.http_status,
            code=exc.code,
            message=exc.message,
            data=exc.data,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        # Zero-plaintext rule: NEVER echo exc.body or err['input'] values.
        safe_locs = [
            ".".join(str(part) for part in err.get("loc", ()))
            for err in exc.errors()
        ]
        safe_locs = [loc for loc in safe_locs if loc]
        msg = (
            f"Invalid request parameters: {', '.join(safe_locs)}"
            if safe_locs
            else "Invalid request parameters"
        )
        return build_error_response(
            request,
            http_status=400,
            code=40001,
            message=msg,
            data=None,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        http_status = exc.status_code
        code = _HTTP_STATUS_TO_CODE.get(http_status, 50001)
        detail = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        return build_error_response(
            request,
            http_status=http_status,
            code=code,
            message=detail,
            data=None,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_exception(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        mapped = map_dynamic_domain_exception(request, exc)
        if mapped is not None:
            return mapped
        logger.error(
            "Unhandled server exception type=%s request_id=%s",
            exc.__class__.__name__,
            get_request_id(request),
        )
        return build_error_response(
            request,
            http_status=500,
            code=50001,
            message="Internal server error",
            data=None,
        )

    if _has_module("app.detectors.types"):
        det_types = importlib.import_module("app.detectors.types")
        det_not_ready = getattr(det_types, "DetectorNotReadyError", None)
        if isinstance(det_not_ready, type) and issubclass(det_not_ready, Exception):

            @app.exception_handler(det_not_ready)
            async def handle_detector_not_ready(request: Request, exc: Exception) -> JSONResponse:
                return build_error_response(
                    request,
                    http_status=503,
                    code=50301,
                    message=str(exc) or "Local AstrLink Guard ONNX model is not ready",
                )

        invalid_pattern = getattr(det_types, "InvalidAllowlistPatternError", None)
        if isinstance(invalid_pattern, type) and issubclass(invalid_pattern, Exception):

            @app.exception_handler(invalid_pattern)
            async def handle_invalid_allowlist_pattern(
                request: Request,
                exc: Exception,
            ) -> JSONResponse:
                return build_error_response(
                    request,
                    http_status=400,
                    code=40001,
                    message=str(exc) or "Invalid allowlist pattern",
                )
