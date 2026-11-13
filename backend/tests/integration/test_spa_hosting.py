from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


REPO_ROOT = Path(__file__).resolve().parents[3]
WEB_DIR = REPO_ROOT / "web"
REAL_WEB_DIST_DIR = WEB_DIR / "dist"


def _ensure_real_web_dist(target_dir: Path) -> Path:
    """Use the built Vite output in web/dist, building it if absent."""
    if not (REAL_WEB_DIST_DIR / "index.html").is_file():
        npm_exe = shutil.which("npm")
        assert npm_exe is not None, "npm is required to build web/dist for SPA hosting integration test"
        subprocess.run([npm_exe, "run", "build"], cwd=str(WEB_DIR), check=True)
    assert (REAL_WEB_DIST_DIR / "index.html").is_file(), "Vite build did not produce web/dist/index.html"
    if target_dir != REAL_WEB_DIST_DIR:
        if target_dir.exists():
            shutil.rmtree(target_dir)
        shutil.copytree(REAL_WEB_DIST_DIR, target_dir)
    return target_dir


def test_real_vite_dist_spa_hosting_and_api_unshadowed(isolated_dirs: dict[str, Path]) -> None:
    dist_dir = _ensure_real_web_dist(isolated_dirs["web_dist_dir"])
    settings = Settings(
        database_url="sqlite://",
        auto_init_db=True,
        jwt_secret_key="test-jwt-secret-key-with-at-least-32-bytes!!",
        jwt_expire_seconds=3600,
        master_aes_key="test_master_aes_256_key_32bytes!",
        bcrypt_rounds=4,
        models_dir=isolated_dirs["models_dir"],
        tmp_uploads_dir=isolated_dirs["tmp_uploads_dir"],
        artifacts_dir=isolated_dirs["artifacts_dir"],
        web_dist_dir=dist_dir,
    )
    app = create_app(settings=settings)

    with TestClient(app) as client:
        # Root & all 6 console history routes resolve to SPA index.html
        for route in ("/", "/login", "/sandbox", "/policies", "/allowlists", "/jobs", "/settings"):
            resp = client.get(route)
            assert resp.status_code == 200, f"Route {route} returned {resp.status_code}"
            assert "text/html" in resp.headers.get("content-type", "")
            assert '<div id="app"></div>' in resp.text

        index_html = (dist_dir / "index.html").read_text(encoding="utf-8")
        asset_paths = re.findall(r'(?:src|href)="(/assets/[^"]+)"', index_html)
        assert asset_paths, "Expected built /assets/* script or stylesheet links in web/dist/index.html"
        for asset_path in asset_paths:
            asset_resp = client.get(asset_path)
            assert asset_resp.status_code == 200, f"Built asset {asset_path} returned {asset_resp.status_code}"
            assert len(asset_resp.content) > 0

        fav_resp = client.get("/favicon.svg")
        assert fav_resp.status_code == 200
        assert "<svg" in fav_resp.text

        # API routes and unknown /api/* catch-all stay unshadowed and return JSON
        health_resp = client.get("/api/health")
        assert health_resp.status_code == 200
        assert health_resp.json()["data"]["status"] == "healthy"

        unknown_get = client.get("/api/v1/does-not-exist")
        assert unknown_get.status_code == 404
        assert unknown_get.json()["code"] == 40401

        unknown_post = client.post("/api/admin/unknown-action")
        assert unknown_post.status_code == 404
        assert unknown_post.json()["code"] == 40401

        # Traversal attempts must never expose files outside dist_dir
        traversal_resp = client.get("/..%2F..%2Fbackend/app/main.py")
        assert traversal_resp.status_code == 200
        assert "create_app" not in traversal_resp.text
        assert '<div id="app"></div>' in traversal_resp.text
