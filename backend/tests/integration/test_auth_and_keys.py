from __future__ import annotations

import logging
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field


class _SensitiveValidationBody(BaseModel):
    count: int = Field(ge=1, le=100)
    text: str = Field(min_length=10)


def test_unified_envelope_error_codes_and_zero_plaintext_validation(
    test_settings: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Slice 1: Unified response envelope, request_id echo, all 8 standard error codes,
    dynamic DetectorNotReadyError -> 503/50301, and zero-plaintext validation handling."""
    from app.common.errors import (
        ArtifactExpiredError,
        BadRequestError,
        ConflictLeakBlockedError,
        ForbiddenError,
        ModelNotReadyError,
        NotFoundError,
        RateLimitExceededError,
        UnauthorizedError,
    )
    from app.main import create_app

    class DetectorNotReadyError(RuntimeError):
        pass

    app: FastAPI = create_app(settings=test_settings)

    error_factories = {
        "bad-request": lambda: BadRequestError("Bad parameter"),
        "unauthorized": lambda: UnauthorizedError("Missing token"),
        "forbidden": lambda: ForbiddenError("IP blocked"),
        "not-found": lambda: NotFoundError("Policy missing"),
        "conflict-leak": lambda: ConflictLeakBlockedError("Flagged leak"),
        "artifact-expired": lambda: ArtifactExpiredError("TTL expired"),
        "rate-limit": lambda: RateLimitExceededError("RPM exceeded"),
        "model-not-ready": lambda: ModelNotReadyError("ONNX missing"),
        "detector-runtime-error": lambda: DetectorNotReadyError("AstrLink Guard int8 weights missing"),
    }

    @app.get("/api/test-errors/{kind}")
    async def trigger_error(kind: str):
        raise error_factories[kind]()

    @app.post("/api/test-validation")
    async def trigger_validation(body: _SensitiveValidationBody):
        return {"ok": body.count}

    with TestClient(app) as client:
        # 1. Health envelope + X-Request-Id
        resp = client.get("/api/health")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["code"] == 200
        assert payload["message"] == "ok"
        assert payload["request_id"].startswith("req_")
        assert resp.headers.get("X-Request-Id") == payload["request_id"]
        assert isinstance(payload["data"], dict)

        # 2. Unmatched /api/* path returns 404 / 40401 envelope
        missing_resp = client.get("/api/does-not-exist")
        assert missing_resp.status_code == 404
        assert missing_resp.json()["code"] == 40401
        assert missing_resp.json()["request_id"].startswith("req_")

        # 3. All 8 standard error codes + dynamic DetectorNotReadyError -> 50301
        expected_cases = [
            ("bad-request", 400, 40001),
            ("unauthorized", 401, 40101),
            ("forbidden", 403, 40301),
            ("not-found", 404, 40401),
            ("conflict-leak", 409, 40901),
            ("artifact-expired", 410, 41001),
            ("rate-limit", 429, 42901),
            ("model-not-ready", 503, 50301),
            ("detector-runtime-error", 503, 50301),
        ]
        for kind, expected_http, expected_code in expected_cases:
            err_resp = client.get(f"/api/test-errors/{kind}")
            assert err_resp.status_code == expected_http, kind
            err_body = err_resp.json()
            assert err_body["code"] == expected_code, kind
            assert err_body["request_id"].startswith("req_")
            assert err_resp.headers.get("X-Request-Id") == err_body["request_id"]

        # 4. Zero-plaintext validation error: raw PII input MUST NOT appear in response or logs
        raw_secret_pii = "张三-32040219900307118X-13812345678"
        with caplog.at_level(logging.DEBUG):
            val_resp = client.post(
                "/api/test-validation",
                json={"count": "invalid-count-" + raw_secret_pii, "text": "short"},
            )
        assert val_resp.status_code == 400
        val_body = val_resp.json()
        assert val_body["code"] == 40001
        assert "body.count" in val_body["message"]
        assert raw_secret_pii not in val_resp.text
        assert "32040219900307118X" not in val_resp.text
        assert raw_secret_pii not in caplog.text


def test_seven_tables_schema_and_idempotent_seed_defaults(
    app: FastAPI,
    test_settings: Any,
) -> None:
    """Slice 2: 7 core kd_desensitize tables, indexes/unique constraints, and idempotent seed defaults."""
    import re
    from sqlalchemy import inspect, select

    from app.db.models import (
        AdminUser,
        AllowlistDict,
        ApiKey,
        ApiUsageHourly,
        BatchJob,
        DatasourceConn,
        PolicyProfile,
    )
    from app.db.seed import seed_defaults

    assert all(
        [
            AdminUser,
            ApiKey,
            AllowlistDict,
            PolicyProfile,
            DatasourceConn,
            BatchJob,
            ApiUsageHourly,
        ]
    )

    expected_tables = {
        "ds_admin_user",
        "ds_api_key",
        "ds_allowlist_dict",
        "ds_policy_profile",
        "ds_datasource_conn",
        "ds_batch_job",
        "ds_api_usage_hourly",
    }
    expected_14_labels = {
        "private_person",
        "phone",
        "email",
        "private_address",
        "private_date",
        "account",
        "payment_card",
        "ip_address",
        "url",
        "common_secret",
        "cn_id_card",
        "cn_uscc",
        "cn_mobile",
        "bank_card_luhn",
    }

    with TestClient(app):
        inspector = inspect(app.state.db_engine)
        assert expected_tables.issubset(set(inspector.get_table_names()))

        # Verify key indexes and unique constraints exist
        policy_uniques = {
            tuple(u["column_names"])
            for u in inspector.get_unique_constraints("ds_policy_profile")
        }
        assert ("policy_code", "version") in policy_uniques

        usage_uniques = {
            tuple(u["column_names"])
            for u in inspector.get_unique_constraints("ds_api_usage_hourly")
        }
        assert ("hour_bucket", "api_key_id", "policy_id") in usage_uniques

        with app.state.session_factory() as session:
            # Run seed_defaults a second time to verify strict idempotency
            seed_defaults(session, test_settings)

            admins = session.scalars(select(AdminUser)).all()
            assert len(admins) == 1
            admin = admins[0]
            assert admin.username == test_settings.default_admin_username
            assert admin.role == "ADMIN"
            assert admin.is_enabled == 1
            assert admin.password_hash != test_settings.default_admin_password
            assert admin.password_hash.startswith("$2")

            allowlists = session.scalars(select(AllowlistDict)).all()
            assert len(allowlists) == 4
            by_group: dict[str, list[AllowlistDict]] = {}
            for item in allowlists:
                by_group.setdefault(item.group_code, []).append(item)
                assert item.match_mode == "REGEX"
                assert item.is_enabled == 1

            assert len(by_group["gov_public_hotline"]) == 2
            assert any(
                re.search(r.pattern_text, "12345") is not None
                for r in by_group["gov_public_hotline"]
            )
            assert any(
                re.search(r.pattern_text, "0519-85681234") is not None
                for r in by_group["gov_public_hotline"]
            )
            assert all(
                re.search(r.pattern_text, "13812345678") is None
                for r in by_group["gov_public_hotline"]
            )
            assert (
                re.search(
                    by_group["gov_public_domain"][0].pattern_text,
                    "https://www.changzhou.gov.cn",
                )
                is not None
            )
            assert (
                re.search(
                    by_group["gov_public_hall"][0].pattern_text,
                    "常州市政务服务中心（锦绣路2号）",
                )
                is not None
            )

            policies = {
                p.policy_code: p
                for p in session.scalars(select(PolicyProfile)).all()
            }
            assert set(policies.keys()) == {"strict_general", "gov_eval_corpus"}

            strict = policies["strict_general"]
            assert strict.version == 1
            assert strict.scope_mode == "RECORD"
            assert strict.onnx_variant == "int8"
            assert strict.is_default == 1
            assert strict.status == "ACTIVE"
            assert set(strict.entity_rules_json.keys()) == expected_14_labels
            assert strict.allowlist_groups_json == []

            gov = policies["gov_eval_corpus"]
            assert gov.version == 1
            assert gov.scope_mode == "CONVERSATION"
            assert gov.onnx_variant == "int8"
            assert gov.is_default == 1
            assert gov.status == "ACTIVE"
            assert set(gov.entity_rules_json.keys()) == expected_14_labels
            assert gov.entity_rules_json["ip_address"]["enabled"] is False
            assert gov.entity_rules_json["url"]["enabled"] is False
            assert gov.allowlist_groups_json == [
                "gov_public_hotline",
                "gov_public_domain",
                "gov_public_hall",
            ]
            assert gov.field_role_rules_json["default_role"] == "FULL_MASK_WRITE_SCOPE"
            assert len(gov.field_role_rules_json["rules"]) == 8


def test_admin_jwt_login_me_onnx_status_and_invalid_credentials(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
    isolated_dirs: dict[str, Any],
) -> None:
    """Slice 3: Admin login issues Bearer JWT, updates last_login_at, serves /api/admin/auth/me
    with onnx_ready status, and rejects wrong/oversized password, disabled account, or bad tokens with 40101."""
    import jwt
    from sqlalchemy import select

    from app.auth.security import hash_password
    from app.db.base import new_uuid
    from app.db.models import AdminUser

    # 1. Wrong password, unknown user, >72-byte password -> 401 / 40101
    for bad_creds in (
        {"username": test_settings.default_admin_username, "password": "WrongPassword!"},
        {"username": "nonexistent_admin", "password": test_settings.default_admin_password},
        {"username": test_settings.default_admin_username, "password": "A" * 90},
    ):
        bad_resp = client.post("/api/admin/auth/login", json=bad_creds)
        assert bad_resp.status_code == 401
        assert bad_resp.json()["code"] == 40101
        assert bad_creds["password"] not in bad_resp.text

    # 2. Valid admin login -> 200 + Bearer JWT + last_login_at updated + onnx_ready False initially
    login_resp = client.post(
        "/api/admin/auth/login",
        json={
            "username": test_settings.default_admin_username,
            "password": test_settings.default_admin_password,
        },
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()["data"]
    token = login_data["access_token"]
    assert token
    assert login_data["token_type"] == "Bearer"
    assert login_data["expires_in"] == test_settings.jwt_expire_seconds
    assert login_data["user"]["username"] == test_settings.default_admin_username
    assert login_data["user"]["role"] == "ADMIN"
    assert login_data["onnx_ready"] is False

    with app.state.session_factory() as session:
        admin_row = session.scalar(
            select(AdminUser).where(AdminUser.username == test_settings.default_admin_username)
        )
        assert admin_row is not None
        assert admin_row.last_login_at is not None

    # 3. /api/admin/auth/me with valid token -> 200; reflects onnx_ready=True once model files exist
    me_resp = client.get("/api/admin/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    me_data = me_resp.json()["data"]
    assert me_data["username"] == test_settings.default_admin_username
    assert me_data["role"] == "ADMIN"
    assert me_data["onnx_variant"] == "int8"
    assert me_data["onnx_ready"] is False

    int8_dir = isolated_dirs["models_dir"] / "int8"
    (int8_dir / "model_int8.onnx").write_bytes(b"onnx-placeholder")
    (int8_dir / "model_int8.onnx_data").write_bytes(b"weights-placeholder")
    for cfg_dir in (isolated_dirs["models_dir"], int8_dir):
        (cfg_dir / "tokenizer.json").write_text("{}", encoding="utf-8")
        (cfg_dir / "labels.json").write_text('{"0": "O"}', encoding="utf-8")
        (cfg_dir / "config.json").write_text("{}", encoding="utf-8")

    me_ready_resp = client.get("/api/admin/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_ready_resp.status_code == 200
    assert me_ready_resp.json()["data"]["onnx_ready"] is True

    # 4. Missing, forged, expired, or dsk_* token on /api/admin/auth/me -> 401 / 40101
    forged_jwt = jwt.encode(
        {"sub": login_data["user"]["uuid"], "role": "ADMIN", "exp": 9999999999},
        "wrong-secret-key-with-at-least-32-bytes-long!!",
        algorithm="HS256",
    )
    expired_jwt = jwt.encode(
        {"sub": login_data["user"]["uuid"], "role": "ADMIN", "exp": 1000000000},
        test_settings.jwt_secret_key,
        algorithm="HS256",
    )
    for headers in (
        {},
        {"Authorization": "Basic abcdef"},
        {"Authorization": f"Bearer {forged_jwt}"},
        {"Authorization": f"Bearer {expired_jwt}"},
        {"Authorization": "Bearer dsk_live_0123456789abcdef0123456789abcdef"},
    ):
        unauth_resp = client.get("/api/admin/auth/me", headers=headers)
        assert unauth_resp.status_code == 401
        assert unauth_resp.json()["code"] == 40101

    # 5. Disabled admin account rejected on both login and existing JWT -> 401 / 40101
    with app.state.session_factory() as session:
        disabled_user = AdminUser(
            uuid=new_uuid(),
            username="disabled_op",
            display_name="已禁用操作员",
            password_hash=hash_password("Disabled@123", rounds=test_settings.bcrypt_rounds),
            role="OPERATOR",
            is_enabled=1,
            is_deleted=0,
        )
        session.add(disabled_user)
        session.commit()
        disabled_uuid = disabled_user.uuid

    op_login = client.post(
        "/api/admin/auth/login",
        json={"username": "disabled_op", "password": "Disabled@123"},
    )
    assert op_login.status_code == 200
    op_token = op_login.json()["data"]["access_token"]

    with app.state.session_factory() as session:
        row = session.scalar(select(AdminUser).where(AdminUser.uuid == disabled_uuid))
        assert row is not None
        row.is_enabled = 0
        session.commit()

    assert (
        client.post(
            "/api/admin/auth/login",
            json={"username": "disabled_op", "password": "Disabled@123"},
        ).json()["code"]
        == 40101
    )
    assert (
        client.get(
            "/api/admin/auth/me",
            headers={"Authorization": f"Bearer {op_token}"},
        ).json()["code"]
        == 40101
    )


def test_api_key_lifecycle_rbac_and_one_time_plaintext_sha256_storage(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
) -> None:
    """Slice 4: POST/GET/DELETE /api/admin/api-keys enforces RBAC (ADMIN write, OPERATOR/AUDITOR read-only),
    returns dsk_* plain_key only once on creation, stores only prefix + 64-char SHA-256 in DB, and revokes keys."""
    import hashlib
    from sqlalchemy import select

    from app.auth.security import hash_password
    from app.db.base import new_uuid
    from app.db.models import AdminUser, ApiKey

    with app.state.session_factory() as session:
        session.add_all(
            [
                AdminUser(
                    uuid=new_uuid(),
                    username="op_user",
                    display_name="脱敏操作员",
                    password_hash=hash_password("OpPass@123", rounds=test_settings.bcrypt_rounds),
                    role="OPERATOR",
                    is_enabled=1,
                    is_deleted=0,
                ),
                AdminUser(
                    uuid=new_uuid(),
                    username="auditor_user",
                    display_name="安全审计员",
                    password_hash=hash_password("AuditPass@123", rounds=test_settings.bcrypt_rounds),
                    role="AUDITOR",
                    is_enabled=1,
                    is_deleted=0,
                ),
            ]
        )
        session.commit()

    def _login_jwt(username: str, password: str) -> str:
        res = client.post(
            "/api/admin/auth/login",
            json={"username": username, "password": password},
        )
        assert res.status_code == 200
        return res.json()["data"]["access_token"]

    admin_jwt = _login_jwt(test_settings.default_admin_username, test_settings.default_admin_password)
    op_jwt = _login_jwt("op_user", "OpPass@123")
    auditor_jwt = _login_jwt("auditor_user", "AuditPass@123")

    # 1. Invalid CIDR in allowed_ips rejected with 400 / 40001
    bad_cidr_resp = client.post(
        "/api/admin/api-keys",
        headers={"Authorization": f"Bearer {admin_jwt}"},
        json={
            "key_name": "bad-cidr-key",
            "allowed_ips": ["999.999.999.999/99"],
        },
    )
    assert bad_cidr_resp.status_code == 400
    assert bad_cidr_resp.json()["code"] == 40001

    # 2. ADMIN creates API Key -> receives plain_key once
    create_resp = client.post(
        "/api/admin/api-keys",
        headers={"Authorization": f"Bearer {admin_jwt}"},
        json={
            "key_name": "ai-eval-center-prod",
            "default_policy_code": "gov_eval_corpus",
            "rate_limit_rpm": 120,
            "allowed_ips": ["10.0.0.0/8", "127.0.0.1"],
        },
    )
    assert create_resp.status_code == 200
    created = create_resp.json()["data"]
    plain_key = created["plain_key"]
    key_uuid = created["uuid"]
    assert plain_key.startswith("dsk_live_")
    assert len(plain_key) > 30
    assert created["key_prefix"] == plain_key[:13]
    assert created["status"] == "ACTIVE"
    assert created["default_policy_code"] == "gov_eval_corpus"
    assert created["rate_limit_rpm"] == 120
    assert created["allowed_ips"] == ["10.0.0.0/8", "127.0.0.1"]
    assert "key_sha256" not in created

    # Verify DB stores ONLY prefix + 64-hex SHA-256, never plain_key
    expected_sha256 = hashlib.sha256(plain_key.encode("utf-8")).hexdigest()
    with app.state.session_factory() as session:
        db_key = session.scalar(select(ApiKey).where(ApiKey.uuid == key_uuid))
        assert db_key is not None
        assert db_key.key_prefix == plain_key[:13]
        assert db_key.key_sha256 == expected_sha256
        assert len(db_key.key_sha256) == 64

    # 3. GET /api/admin/api-keys works for ADMIN, OPERATOR, AUDITOR and NEVER leaks plain_key or key_sha256
    for role_token in (admin_jwt, op_jwt, auditor_jwt):
        list_resp = client.get(
            "/api/admin/api-keys",
            headers={"Authorization": f"Bearer {role_token}"},
        )
        assert list_resp.status_code == 200
        assert plain_key not in list_resp.text
        assert expected_sha256 not in list_resp.text
        items = list_resp.json()["data"]["items"]
        assert len(items) == 1
        assert items[0]["uuid"] == key_uuid
        assert items[0]["key_prefix"] == plain_key[:13]
        assert "plain_key" not in items[0]
        assert "key_sha256" not in items[0]

    # 4. OPERATOR and AUDITOR cannot create or delete API keys -> 403 / 40301
    for non_admin_token in (op_jwt, auditor_jwt):
        forb_create = client.post(
            "/api/admin/api-keys",
            headers={"Authorization": f"Bearer {non_admin_token}"},
            json={"key_name": "unauthorized-key"},
        )
        assert forb_create.status_code == 403
        assert forb_create.json()["code"] == 40301

        forb_del = client.delete(
            f"/api/admin/api-keys/{key_uuid}",
            headers={"Authorization": f"Bearer {non_admin_token}"},
        )
        assert forb_del.status_code == 403
        assert forb_del.json()["code"] == 40301

    # 5. ADMIN revokes key -> status REVOKED; missing key -> 404 / 40401
    missing_del = client.delete(
        "/api/admin/api-keys/nonexistent_uuid_0000",
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert missing_del.status_code == 404
    assert missing_del.json()["code"] == 40401

    del_resp = client.delete(
        f"/api/admin/api-keys/{key_uuid}",
        headers={"Authorization": f"Bearer {admin_jwt}"},
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["data"]["status"] == "REVOKED"


def test_dataplane_api_key_auth_cidr_expiry_revocation_rpm_dual_caller_and_zero_plaintext_db_scan(
    test_settings: Any,
) -> None:
    """Slice 5: Data-plane X-API-Key & Bearer dsk_*, revoked/expired/non-allowlisted CIDR -> 40301,
    rate_limit_rpm -> 42901, dual-domain get_job_caller/require_job_caller, and 7-table zero-plaintext scan."""
    from datetime import datetime, timedelta, timezone
    from fastapi import Depends
    from sqlalchemy import inspect, select, text

    from app.auth.dependencies import (
        CallerPrincipal,
        get_job_caller,
        require_job_caller,
    )
    from app.auth.security import hash_password
    from app.common.envelope import ok_response
    from app.db.base import new_uuid
    from app.db.models import AdminUser, ApiKey
    from app.main import create_app

    app = create_app(settings=test_settings)

    @app.post("/api/v1/test-dual-create")
    def dual_create_probe(
        caller: CallerPrincipal = Depends(require_job_caller("ADMIN", "OPERATOR")),
    ):
        return ok_response(
            {"domain": caller.domain, "triggered_by": caller.triggered_by}
        )

    @app.get("/api/v1/test-dual-read")
    def dual_read_probe(caller: CallerPrincipal = Depends(get_job_caller)):
        return ok_response(
            {"domain": caller.domain, "triggered_by": caller.triggered_by}
        )

    with TestClient(app, client=("10.10.5.9", 50000)) as allowed_client:
        with app.state.session_factory() as session:
            session.add(
                AdminUser(
                    uuid=new_uuid(),
                    username="audit_reader",
                    display_name="只读审计员",
                    password_hash=hash_password(
                        "AuditRead@123", rounds=test_settings.bcrypt_rounds
                    ),
                    role="AUDITOR",
                    is_enabled=1,
                    is_deleted=0,
                )
            )
            session.commit()

        admin_jwt = allowed_client.post(
            "/api/admin/auth/login",
            json={
                "username": test_settings.default_admin_username,
                "password": test_settings.default_admin_password,
            },
        ).json()["data"]["access_token"]

        auditor_jwt = allowed_client.post(
            "/api/admin/auth/login",
            json={"username": "audit_reader", "password": "AuditRead@123"},
        ).json()["data"]["access_token"]

        def _issue_key(**kwargs: Any) -> dict[str, Any]:
            res = allowed_client.post(
                "/api/admin/api-keys",
                headers={"Authorization": f"Bearer {admin_jwt}"},
                json=kwargs,
            )
            assert res.status_code == 200
            return res.json()["data"]

        # 1. Missing / unknown / JWT token on data-plane API-key endpoint -> 401 / 40101
        for bad_headers in (
            {},
            {"X-API-Key": "dsk_live_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
            {"Authorization": f"Bearer {admin_jwt}"},
        ):
            r = allowed_client.get("/api/v1/auth/ping", headers=bad_headers)
            assert r.status_code == 401
            assert r.json()["code"] == 40101

        # 2. Active key with CIDR allowlist ["10.10.0.0/16", "127.0.0.1"] & rate_limit_rpm=3
        cidr_rpm_key = _issue_key(
            key_name="eval-cidr-rpm",
            default_policy_code="gov_eval_corpus",
            rate_limit_rpm=3,
            allowed_ips=["10.10.0.0/16", "127.0.0.1"],
        )
        raw_cidr_key = cidr_rpm_key["plain_key"]

        # Request #1 via X-API-Key from allowlisted IP 10.10.5.9 -> 200 + updates last_used_at
        r1 = allowed_client.get(
            "/api/v1/auth/ping",
            headers={"X-API-Key": raw_cidr_key},
        )
        assert r1.status_code == 200
        assert r1.json()["data"]["key_prefix"] == cidr_rpm_key["key_prefix"]
        assert r1.json()["data"]["default_policy_code"] == "gov_eval_corpus"

        with app.state.session_factory() as session:
            db_row = session.scalar(
                select(ApiKey).where(ApiKey.uuid == cidr_rpm_key["uuid"])
            )
            assert db_row is not None
            assert db_row.last_used_at is not None

        # Request #2 via Authorization: Bearer dsk_* -> 200
        r2 = allowed_client.get(
            "/api/v1/auth/ping",
            headers={"Authorization": f"Bearer {raw_cidr_key}"},
        )
        assert r2.status_code == 200

        # Non-allowlisted IP 192.168.1.99 (even with spoofed X-Forwarded-For!) -> 403 / 40301
        blocked_client = TestClient(app, client=("192.168.1.99", 50001))
        blocked_resp = blocked_client.get(
            "/api/v1/auth/ping",
            headers={
                "X-API-Key": raw_cidr_key,
                "X-Forwarded-For": "10.10.5.9",
            },
        )
        assert blocked_resp.status_code == 403
        assert blocked_resp.json()["code"] == 40301

        # Request #3 from allowlisted IP -> 200; Request #4 exceeds rate_limit_rpm=3 -> 429 / 42901
        r3 = allowed_client.get(
            "/api/v1/auth/ping",
            headers={"X-API-Key": raw_cidr_key},
        )
        assert r3.status_code == 200

        r4 = allowed_client.get(
            "/api/v1/auth/ping",
            headers={"X-API-Key": raw_cidr_key},
        )
        assert r4.status_code == 429
        assert r4.json()["code"] == 42901

        # 3. Independent second key is unaffected by key #1's rate limit; test revocation -> 403 / 40301
        revocable_key = _issue_key(key_name="to-be-revoked", rate_limit_rpm=60)
        raw_revocable = revocable_key["plain_key"]
        assert (
            allowed_client.get(
                "/api/v1/auth/ping",
                headers={"X-API-Key": raw_revocable},
            ).status_code
            == 200
        )
        allowed_client.delete(
            f"/api/admin/api-keys/{revocable_key['uuid']}",
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        revoked_resp = allowed_client.get(
            "/api/v1/auth/ping",
            headers={"Authorization": f"Bearer {raw_revocable}"},
        )
        assert revoked_resp.status_code == 403
        assert revoked_resp.json()["code"] == 40301

        # 4. Expired key -> 403 / 40301
        past_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        expired_key = _issue_key(key_name="already-expired", expires_at=past_iso)
        raw_expired = expired_key["plain_key"]
        exp_resp = allowed_client.get(
            "/api/v1/auth/ping",
            headers={"X-API-Key": raw_expired},
        )
        assert exp_resp.status_code == 403
        assert exp_resp.json()["code"] == 40301

        # 5. Dual-domain get_job_caller & require_job_caller("ADMIN", "OPERATOR")
        dual_active_key = _issue_key(key_name="batch-job-caller", rate_limit_rpm=60)
        raw_dual_key = dual_active_key["plain_key"]

        assert (
            allowed_client.post(
                "/api/v1/test-dual-create",
                headers={"X-API-Key": raw_dual_key},
            ).json()["data"]
            == {
                "domain": "API_KEY",
                "triggered_by": dual_active_key["key_prefix"],
            }
        )
        assert (
            allowed_client.post(
                "/api/v1/test-dual-create",
                headers={"Authorization": f"Bearer {admin_jwt}"},
            ).json()["data"]
            == {
                "domain": "ADMIN_JWT",
                "triggered_by": test_settings.default_admin_username,
            }
        )
        # AUDITOR can read job status via get_job_caller, but gets 40301 on create/cancel
        assert (
            allowed_client.get(
                "/api/v1/test-dual-read",
                headers={"Authorization": f"Bearer {auditor_jwt}"},
            ).status_code
            == 200
        )
        auditor_create = allowed_client.post(
            "/api/v1/test-dual-create",
            headers={"Authorization": f"Bearer {auditor_jwt}"},
        )
        assert auditor_create.status_code == 403
        assert auditor_create.json()["code"] == 40301

        # 6. Full 7-table zero-plaintext scan: raw API keys & plaintext passwords appear 0 times
        forbidden_secrets = (
            raw_cidr_key,
            raw_revocable,
            raw_expired,
            raw_dual_key,
            test_settings.default_admin_password,
            "AuditRead@123",
        )
        inspector = inspect(app.state.db_engine)
        with app.state.db_engine.connect() as conn:
            for table_name in inspector.get_table_names():
                rows = conn.execute(text(f"SELECT * FROM {table_name}")).fetchall()
                for row in rows:
                    for col_val in row:
                        if col_val is None:
                            continue
                        as_text = str(col_val)
                        for secret in forbidden_secrets:
                            assert secret not in as_text, (
                                f"Forbidden plaintext leaked in {table_name}"
                            )


def test_spa_hosting_api_unshadowed_and_safe_logger_redaction(
    test_settings: Any,
    isolated_dirs: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Slice 6: Built SPA index.html serves frontend routes without shadowing GET/POST /api/* 404s,
    and get_safe_logger scrubs full dsk_* secrets and forbidden plaintext fields."""
    from app.common.logging import (
        get_safe_logger,
        mask_text_safe_log,
        sanitize_log_fields,
    )
    from app.main import create_app

    dist_dir = isolated_dirs["web_dist_dir"]
    assets_dir = dist_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "index.html").write_text(
        "<!doctype html><html><body>DS Console</body></html>",
        encoding="utf-8",
    )
    (assets_dir / "app.js").write_text("console.log('ready');", encoding="utf-8")

    app = create_app(settings=test_settings)
    with TestClient(app) as spa_client:
        # Root and deep Vue router paths return SPA index.html
        for spa_path in ("/", "/policies", "/sandbox"):
            r = spa_client.get(spa_path)
            assert r.status_code == 200
            assert "DS Console" in r.text

        asset_resp = spa_client.get("/assets/app.js")
        assert asset_resp.status_code == 200
        assert "ready" in asset_resp.text

        # Both GET and POST to unknown /api/* still return 404 / 40401 JSON (never 200 HTML or 405!)
        for method in ("GET", "POST", "DELETE"):
            api_miss = spa_client.request(method, "/api/v1/unknown-endpoint")
            assert api_miss.status_code == 404, method
            assert api_miss.json()["code"] == 40401, method

    # Safe logging redacts full dsk_* tokens and strips forbidden PII keys
    secret_token = "dsk_live_99887766554433221100aabbccddeeff00112233"
    raw_pii = "李四-32040219900307118X"
    safe_logger = get_safe_logger("ds_center.test_audit")
    with caplog.at_level(logging.INFO):
        safe_logger.info("Auth failed for token %s", secret_token)
        cleaned = sanitize_log_fields(
            {
                "request_id": "req_1234",
                "text": raw_pii,
                "plain_key": secret_token,
                "note": f"caller={secret_token}",
            }
        )
    assert secret_token not in caplog.text
    assert "dsk_live_9988***" in caplog.text
    assert "text" not in cleaned
    assert "plain_key" not in cleaned
    assert secret_token not in str(cleaned)
    assert mask_text_safe_log(42, {"cn_mobile": 1}) == "masked_chars=42 hits={'cn_mobile': 1}"





