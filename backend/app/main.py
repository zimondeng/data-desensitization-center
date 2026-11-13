from __future__ import annotations

import importlib
import importlib.util
import inspect
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.common.envelope import generate_request_id, ok_response
from app.common.errors import (
    NotFoundError,
    map_dynamic_domain_exception,
    register_exception_handlers,
)
from app.config import Settings, get_settings

API_ROUTER_MODULES: tuple[str, ...] = (
    "app.api.admin_auth",
    "app.api.admin_api_keys",
    "app.api.admin_policies",
    "app.api.admin_allowlists",
    "app.api.v1_mask",
    "app.api.admin_sandbox",
    "app.api.admin_metrics",
    "app.api.v1_jobs",
    "app.api.admin_jobs",
    "app.api.admin_datasources",
)


def _has_module(mod_name: str) -> bool:
    try:
        return importlib.util.find_spec(mod_name) is not None
    except ModuleNotFoundError:
        return False


def _register_available_routers(app: FastAPI) -> None:
    for mod_name in API_ROUTER_MODULES:
        if _has_module(mod_name):
            mod = importlib.import_module(mod_name)
            router = getattr(mod, "router", None)
            if router is not None:
                app.include_router(router)


async def _call_optional_hook(mod_name: str, func_name: str, app: FastAPI) -> None:
    if not _has_module(mod_name):
        return
    mod = importlib.import_module(mod_name)
    fn = getattr(mod, func_name, None)
    if callable(fn):
        result = fn(app)
        if inspect.isawaitable(result):
            await result


def mount_spa_if_built(app: FastAPI, dist_dir: Path) -> None:
    index_file = dist_dir / "index.html"
    if not index_file.is_file():
        return
    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="web-assets")

    resolved_dist = dist_dir.resolve()

    @app.api_route(
        "/api/{api_subpath:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
        include_in_schema=False,
    )
    async def unmatched_api_route(api_subpath: str) -> Response:
        raise NotFoundError("API endpoint not found")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str) -> FileResponse:
        if full_path == "api" or full_path.startswith("api/"):
            raise NotFoundError("API endpoint not found")
        candidate = (dist_dir / full_path).resolve()
        if full_path and candidate.is_relative_to(resolved_dist) and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(index_file)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI) -> AsyncIterator[None]:
        resolved_settings.tmp_uploads_dir.mkdir(parents=True, exist_ok=True)
        resolved_settings.artifacts_dir.mkdir(parents=True, exist_ok=True)

        if resolved_settings.auto_init_db and _has_module("app.db.seed"):
            from app.db.base import Base
            from app.db.seed import seed_defaults

            Base.metadata.create_all(bind=app_instance.state.db_engine)
            with app_instance.state.session_factory() as session:
                seed_defaults(session, resolved_settings)

        await _call_optional_hook("app.jobs.ttl_cleaner", "start_ttl_cleaner", app_instance)
        try:
            yield
        finally:
            await _call_optional_hook("app.jobs.ttl_cleaner", "stop_ttl_cleaner", app_instance)
            await _call_optional_hook("app.jobs.runner", "shutdown_job_runner", app_instance)

    app_instance = FastAPI(title=resolved_settings.app_name, lifespan=lifespan)
    app_instance.state.settings = resolved_settings

    if _has_module("app.db.session"):
        from app.db.session import build_engine, build_session_factory

        engine = build_engine(resolved_settings.database_url)
        app_instance.state.db_engine = engine
        app_instance.state.session_factory = build_session_factory(engine)

    if _has_module("app.auth.rate_limiter"):
        from app.auth.rate_limiter import SlidingWindowRateLimiter

        app_instance.state.rate_limiter = SlidingWindowRateLimiter()

    @app_instance.middleware("http")
    async def request_id_and_domain_error_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        req_id = generate_request_id()
        request.state.request_id = req_id
        try:
            response = await call_next(request)
        except Exception as exc:
            mapped = map_dynamic_domain_exception(request, exc)
            if mapped is not None:
                return mapped
            raise
        response.headers["X-Request-Id"] = req_id
        return response

    register_exception_handlers(app_instance)

    @app_instance.get("/api/health", tags=["system"])
    async def health_check(request: Request) -> dict:
        return ok_response({"status": "healthy"}, request=request)

    if _has_module("app.auth.dependencies"):
        from app.auth.dependencies import get_current_api_key
        from app.db.models import ApiKey

        @app_instance.get("/api/v1/auth/ping", tags=["v1-auth"])
        def api_key_ping(
            request: Request,
            api_key: ApiKey = Depends(get_current_api_key),
        ) -> dict:
            return ok_response(
                {
                    "key_prefix": api_key.key_prefix,
                    "default_policy_code": api_key.default_policy_code,
                    "rate_limit_rpm": api_key.rate_limit_rpm,
                },
                request=request,
            )

    _register_available_routers(app_instance)
    mount_spa_if_built(app_instance, resolved_settings.web_dist_dir)
    return app_instance


app = create_app()
