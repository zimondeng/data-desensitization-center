from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def isolated_dirs(tmp_path: Path) -> dict[str, Path]:
    models_dir = tmp_path / "models" / "astrlink-guard"
    tmp_uploads_dir = tmp_path / "data" / "tmp_uploads"
    artifacts_dir = tmp_path / "data" / "artifacts"
    web_dist_dir = tmp_path / "web" / "dist"
    for d in (models_dir / "int8", tmp_uploads_dir, artifacts_dir):
        d.mkdir(parents=True, exist_ok=True)
    return {
        "models_dir": models_dir,
        "tmp_uploads_dir": tmp_uploads_dir,
        "artifacts_dir": artifacts_dir,
        "web_dist_dir": web_dist_dir,
    }


@pytest.fixture
def test_settings(isolated_dirs: dict[str, Path]):
    from app.config import Settings

    return Settings(
        database_url="sqlite://",
        auto_init_db=True,
        jwt_secret_key="test-jwt-secret-key-with-at-least-32-bytes!!",
        jwt_expire_seconds=3600,
        master_aes_key="test_master_aes_256_key_32bytes!",
        bcrypt_rounds=4,
        models_dir=isolated_dirs["models_dir"],
        tmp_uploads_dir=isolated_dirs["tmp_uploads_dir"],
        artifacts_dir=isolated_dirs["artifacts_dir"],
        web_dist_dir=isolated_dirs["web_dist_dir"],
    )


@pytest.fixture
def app(test_settings) -> FastAPI:
    from app.main import create_app

    return create_app(settings=test_settings)


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
