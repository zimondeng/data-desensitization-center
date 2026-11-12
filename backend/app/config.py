from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from pathlib import Path

from fastapi import Request
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Data Desensitization Center"
    app_env: str = "dev"
    host: str = "0.0.0.0"
    port: int = 18100

    database_url: str = (
        "mysql+pymysql://root:root@127.0.0.1:3306/kd_desensitize?charset=utf8mb4"
    )
    auto_init_db: bool = True

    jwt_secret_key: str = "ds-center-local-jwt-secret-key-at-least-32-bytes-long"
    jwt_algorithm: str = "HS256"
    jwt_expire_seconds: int = 28800
    bcrypt_rounds: int = 12

    default_admin_username: str = "admin"
    default_admin_password: str = "Admin@123456"
    default_admin_display_name: str = "系统管理员"

    master_aes_key: str = "ds_default_master_aes_256_key_32"
    hash_mask_salt: str = "ds-center-irreversible-hash-salt-v1"

    default_onnx_variant: str = "int8"
    onnx_pool_workers: int = 2

    models_dir: Path = REPO_ROOT / "models" / "astrlink-guard"
    tmp_uploads_dir: Path = REPO_ROOT / "data" / "tmp_uploads"
    artifacts_dir: Path = REPO_ROOT / "data" / "artifacts"
    web_dist_dir: Path = REPO_ROOT / "web" / "dist"

    max_upload_bytes: int = 200 * 1024 * 1024
    default_artifact_ttl_hours: int = 72
    ttl_cleanup_interval_seconds: int = 300
    trust_proxy_headers: bool = False

    @property
    def master_aes_key_bytes(self) -> bytes:
        raw = self.master_aes_key.encode("utf-8")
        if len(raw) == 32:
            return raw
        if len(self.master_aes_key) == 64:
            try:
                return bytes.fromhex(self.master_aes_key)
            except ValueError:
                pass
        try:
            decoded = base64.urlsafe_b64decode(raw)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        return hashlib.sha256(raw).digest()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def get_request_settings(request: Request) -> Settings:
    state_settings = getattr(request.app.state, "settings", None)
    if isinstance(state_settings, Settings):
        return state_settings
    return get_settings()
