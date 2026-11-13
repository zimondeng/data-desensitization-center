from __future__ import annotations

import logging
import threading
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
import numpy as np
import pytest
from sqlalchemy import select

from app.auth.security import hash_password
from app.db.base import new_uuid
from app.db.models import AdminUser, DatasourceConn
from app.detectors import DEFAULT_ID2LABEL, HybridDetectorPipeline, OnnxNerDetector
from app.engine import PolicyEngineService

_LABEL2ID = {lbl: idx for idx, lbl in DEFAULT_ID2LABEL.items()}


class _ScriptedFakeOnnx(OnnxNerDetector):
    """Deterministic fake ONNX detector for batch-job integration tests (no 37MB weights needed)."""

    def __init__(self, mentions: list[tuple[str, str, float]]) -> None:
        self._mentions = mentions
        self._tls = threading.local()

        class _Tok:
            def encode(s_tok, text: str):
                self._tls.current_text = text

                class _Enc:
                    ids = [0, *[100 + i for i in range(len(text))], 2]
                    offsets = [(0, 0), *[(i, i + 1) for i in range(len(text))], (0, 0)]

                return _Enc()

        class _Sess:
            def run(s_sess, output_names, input_feed):
                cur_text = getattr(self._tls, "current_text", "")
                ids = input_feed["input_ids"]
                logits = np.zeros((1, ids.shape[1], 21), dtype=np.float32)
                tag_at: dict[int, tuple[str, float]] = {}
                for substr, lbl, prob in sorted(
                    self._mentions, key=lambda item: -len(item[0])
                ):
                    pos = 0
                    while True:
                        idx = cur_text.find(substr, pos)
                        if idx < 0:
                            break
                        if any((idx + k) in tag_at for k in range(len(substr))):
                            pos = idx + 1
                            continue
                        for k in range(len(substr)):
                            bio = f"B-{lbl}" if k == 0 else f"I-{lbl}"
                            tag_at[idx + k] = (bio, prob)
                        pos = idx + len(substr)
                for p in range(ids.shape[1]):
                    ch_idx = int(ids[0, p]) - 100
                    if ch_idx in tag_at:
                        bio, prob = tag_at[ch_idx]
                        logits[0, p, _LABEL2ID[bio]] = float(
                            np.log(prob * 20.0 / (1.0 - prob))
                        )
                    else:
                        logits[0, p, _LABEL2ID["O"]] = 12.0
                return [logits]

        super().__init__(session=_Sess(), tokenizer=_Tok())


def _seed_auth_principals(
    client: TestClient,
    app: FastAPI,
    test_settings: Any,
) -> dict[str, str]:
    with app.state.session_factory() as session:
        session.add_all(
            [
                AdminUser(
                    uuid=new_uuid(),
                    username="batch_operator",
                    display_name="批处理操作员",
                    password_hash=hash_password("OpPass@123", rounds=test_settings.bcrypt_rounds),
                    role="OPERATOR",
                    is_enabled=1,
                    is_deleted=0,
                ),
                AdminUser(
                    uuid=new_uuid(),
                    username="batch_auditor",
                    display_name="合规审核员",
                    password_hash=hash_password("AuditPass@123", rounds=test_settings.bcrypt_rounds),
                    role="AUDITOR",
                    is_enabled=1,
                    is_deleted=0,
                ),
            ]
        )
        session.commit()

    def _login(username: str, password: str) -> str:
        res = client.post(
            "/api/admin/auth/login",
            json={"username": username, "password": password},
        )
        assert res.status_code == 200
        return res.json()["data"]["access_token"]

    tokens = {
        "ADMIN": _login(
            test_settings.default_admin_username,
            test_settings.default_admin_password,
        ),
        "OPERATOR": _login("batch_operator", "OpPass@123"),
        "AUDITOR": _login("batch_auditor", "AuditPass@123"),
    }

    key_resp = client.post(
        "/api/admin/api-keys",
        headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        json={
            "key_name": "eval-center-batch-caller",
            "default_policy_code": "gov_eval_corpus",
            "rate_limit_rpm": 600,
        },
    )
    assert key_resp.status_code == 200
    tokens["API_KEY"] = key_resp.json()["data"]["plain_key"]
    return tokens


def test_datasources_crud_aes_gcm_storage_rbac_and_readonly_connectivity_probe(
    test_settings: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from app.jobs.crypto import decrypt_secret
    from app.main import create_app

    app = create_app(settings=test_settings)
    sql_log: list[str] = []
    should_fail = {"flag": False}
    raw_db_password = "MySQL_ReadOnly_Secret#9981!"

    class _ProbeCursor:
        def execute(self, stmt: str, args=None) -> None:
            sql_log.append(stmt)
            if should_fail["flag"]:
                raise RuntimeError(f"Access denied with password {raw_db_password}")

        def fetchone(self):
            return {"1": 1}

        def close(self) -> None:
            pass

    class _ProbeConn:
        def cursor(self):
            return _ProbeCursor()

        def close(self) -> None:
            pass

    def fake_mysql_connector(**kwargs):
        assert kwargs["password"] == raw_db_password
        return _ProbeConn()

    app.state.mysql_connector_factory = fake_mysql_connector

    with TestClient(app) as client:
        tokens = _seed_auth_principals(client, app, test_settings)

        # Unauthenticated or API Key rejected on admin datasources -> 40101
        for bad_hdr in ({}, {"X-API-Key": tokens["API_KEY"]}):
            r_unauth = client.get("/api/admin/datasources", headers=bad_hdr)
            assert r_unauth.status_code == 401
            assert r_unauth.json()["code"] == 40101

        # OPERATOR and AUDITOR cannot create datasource -> 40301
        for role in ("OPERATOR", "AUDITOR"):
            r_forbid = client.post(
                "/api/admin/datasources",
                headers={"Authorization": f"Bearer {tokens[role]}"},
                json={
                    "conn_code": "gov_ro_db",
                    "conn_name": "政务只读从库",
                    "db_host": "10.20.30.40",
                    "db_port": 3306,
                    "db_name": "gov_routing",
                    "db_user": "ro_reader",
                    "password": raw_db_password,
                    "allowed_tables": ["ai_routing_conversation_record"],
                },
            )
            assert r_forbid.status_code == 403
            assert r_forbid.json()["code"] == 40301

        # Invalid allowed_tables identifier rejected -> 40001
        r_bad_tbl = client.post(
            "/api/admin/datasources",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
            json={
                "conn_code": "gov_ro_db",
                "conn_name": "政务只读从库",
                "db_host": "10.20.30.40",
                "db_port": 3306,
                "db_name": "gov_routing",
                "db_user": "ro_reader",
                "password": raw_db_password,
                "allowed_tables": ["valid_tbl", "bad;drop"],
            },
        )
        assert r_bad_tbl.status_code == 400
        assert r_bad_tbl.json()["code"] == 40001

        # ADMIN creates datasource -> 200, zero password/cipher in response
        r_create = client.post(
            "/api/admin/datasources",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
            json={
                "conn_code": "gov_prod_readonly",
                "conn_name": "政务线上只读库",
                "db_host": "10.20.30.40",
                "db_port": 3306,
                "db_name": "gov_routing",
                "db_user": "ro_reader",
                "password": raw_db_password,
                "allowed_tables": ["ai_routing_conversation_record", "gov_qa_log"],
            },
        )
        assert r_create.status_code == 200
        created = r_create.json()["data"]
        assert created["conn_code"] == "gov_prod_readonly"
        assert created["has_password"] is True
        assert "password" not in created
        assert "password_cipher" not in created
        assert raw_db_password not in r_create.text

        # Verify AES-256-GCM ciphertext in DB
        with app.state.session_factory() as session:
            db_row = session.scalar(
                select(DatasourceConn).where(DatasourceConn.conn_code == "gov_prod_readonly")
            )
            assert db_row is not None
            assert raw_db_password not in db_row.password_cipher
            assert (
                decrypt_secret(db_row.password_cipher, test_settings.master_aes_key_bytes)
                == raw_db_password
            )

        # ADMIN, OPERATOR, AUDITOR can all GET datasources (without password/cipher)
        for role in ("ADMIN", "OPERATOR", "AUDITOR"):
            r_list = client.get(
                "/api/admin/datasources",
                headers={"Authorization": f"Bearer {tokens[role]}"},
            )
            assert r_list.status_code == 200
            item = r_list.json()["data"]["items"][0]
            assert item["conn_code"] == "gov_prod_readonly"
            assert "password" not in item
            assert "password_cipher" not in item
            assert raw_db_password not in r_list.text

        # OPERATOR and AUDITOR forbidden on PUT, test, DELETE -> 40301
        for role in ("OPERATOR", "AUDITOR"):
            assert (
                client.put(
                    "/api/admin/datasources/gov_prod_readonly",
                    headers={"Authorization": f"Bearer {tokens[role]}"},
                    json={"conn_name": "改名"},
                ).json()["code"]
                == 40301
            )
            assert (
                client.post(
                    "/api/admin/datasources/gov_prod_readonly/test",
                    headers={"Authorization": f"Bearer {tokens[role]}"},
                ).json()["code"]
                == 40301
            )
            assert (
                client.delete(
                    "/api/admin/datasources/gov_prod_readonly",
                    headers={"Authorization": f"Bearer {tokens[role]}"},
                ).json()["code"]
                == 40301
            )

        # ADMIN runs connectivity test -> verifies SET SESSION TRANSACTION READ ONLY + SELECT 1
        r_test_ok = client.post(
            "/api/admin/datasources/gov_prod_readonly/test",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        )
        assert r_test_ok.status_code == 200
        test_data = r_test_ok.json()["data"]
        assert test_data["ok"] is True
        assert test_data["read_only_verified"] is True
        assert test_data["last_test_ok"] is True
        assert sql_log == ["SET SESSION TRANSACTION READ ONLY", "SELECT 1"]

        # Failure path updates last_test_ok=False and NEVER leaks password in response or logs
        sql_log.clear()
        should_fail["flag"] = True
        with caplog.at_level(logging.DEBUG):
            r_test_fail = client.post(
                "/api/admin/datasources/gov_prod_readonly/test",
                headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
            )
        assert r_test_fail.status_code == 200
        fail_data = r_test_fail.json()["data"]
        assert fail_data["ok"] is False
        assert fail_data["last_test_ok"] is False
        assert raw_db_password not in r_test_fail.text
        assert raw_db_password not in caplog.text

        # ADMIN updates allowed_tables without resending password, then deletes datasource
        r_upd = client.put(
            "/api/admin/datasources/gov_prod_readonly",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
            json={
                "conn_name": "政务线上只读库-更新",
                "allowed_tables": ["ai_routing_conversation_record"],
            },
        )
        assert r_upd.status_code == 200
        assert r_upd.json()["data"]["conn_name"] == "政务线上只读库-更新"
        assert r_upd.json()["data"]["allowed_tables"] == ["ai_routing_conversation_record"]

        r_del = client.delete(
            "/api/admin/datasources/gov_prod_readonly",
            headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
        )
        assert r_del.status_code == 200
        assert r_del.json()["data"]["deleted"] is True
        assert (
            client.get(
                "/api/admin/datasources",
                headers={"Authorization": f"Bearer {tokens['ADMIN']}"},
            ).json()["data"]["total"]
            == 0
        )


def _wait_until_terminal(
    client: TestClient,
    job_no: str,
    headers: dict[str, str],
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    import time

    deadline = time.monotonic() + timeout_sec
    last_data: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = client.get(f"/api/v1/jobs/{job_no}", headers=headers)
        assert resp.status_code == 200
        last_data = resp.json()["data"]
        if last_data["status"] in ("COMPLETED", "FAILED", "CANCELLED", "ARTIFACT_EXPIRED"):
            return last_data
        time.sleep(0.02)
    raise AssertionError(f"Job {job_no} did not reach terminal state: {last_data}")


def test_file_upload_batch_jobs_dual_auth_five_formats_size_guard_and_zero_tmp_residue(
    isolated_dirs: dict[str, Any],
) -> None:
    import hashlib
    import io
    import json
    import openpyxl

    from app.config import Settings
    from app.main import create_app

    settings = Settings(
        database_url="sqlite://",
        auto_init_db=True,
        jwt_secret_key="test-jwt-secret-key-with-at-least-32-bytes!!",
        jwt_expire_seconds=3600,
        master_aes_key="test_master_aes_256_key_32bytes!",
        bcrypt_rounds=4,
        max_upload_bytes=32 * 1024,  # 32 KB cap to verify streaming upload size guard deterministically
        models_dir=isolated_dirs["models_dir"],
        tmp_uploads_dir=isolated_dirs["tmp_uploads_dir"],
        artifacts_dir=isolated_dirs["artifacts_dir"],
        web_dist_dir=isolated_dirs["web_dist_dir"],
    )
    onnx = _ScriptedFakeOnnx(
        [
            ("张三", "private_person", 0.96),
            ("李四", "private_person", 0.95),
            ("12345", "phone", 0.90),
            ("0519-85681234", "phone", 0.92),
            ("常州市政务服务中心（锦绣路2号）", "private_address", 0.91),
            ("天宁区和平中路88号3幢502室", "private_address", 0.93),
            ("https://www.changzhou.gov.cn", "url", 0.94),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    app = create_app(settings=settings)
    app.state.policy_engine = PolicyEngineService(pipeline=pipeline, hash_salt="batch-salt")

    try:
        with TestClient(app) as client:
            tokens = _seed_auth_principals(client, app, settings)
            admin_hdr = {"Authorization": f"Bearer {tokens['ADMIN']}"}
            op_hdr = {"Authorization": f"Bearer {tokens['OPERATOR']}"}
            aud_hdr = {"Authorization": f"Bearer {tokens['AUDITOR']}"}
            key_hdr = {"X-API-Key": tokens["API_KEY"]}

            # 1. AUDITOR forbidden from submitting jobs -> 40301; unauth -> 40101
            r_unauth = client.post(
                "/api/v1/jobs/file",
                files={"file": ("a.txt", b"hello", "text/plain")},
            )
            assert r_unauth.status_code == 401
            assert r_unauth.json()["code"] == 40101

            r_aud = client.post(
                "/api/v1/jobs/file",
                headers=aud_hdr,
                files={"file": ("a.txt", b"hello", "text/plain")},
            )
            assert r_aud.status_code == 403
            assert r_aud.json()["code"] == 40301

            # 2. Unsupported extension & oversize file rejected -> 40001 + zero tmp_uploads residue
            r_ext = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                files={"file": ("malware.exe", b"MZ...", "application/octet-stream")},
            )
            assert r_ext.status_code == 400
            assert r_ext.json()["code"] == 40001

            r_big = client.post(
                "/api/v1/jobs/file",
                headers=key_hdr,
                files={"file": ("huge.txt", b"A" * (40 * 1024), "text/plain")},
            )
            assert r_big.status_code == 400
            assert r_big.json()["code"] == 40001
            assert list(isolated_dirs["tmp_uploads_dir"].iterdir()) == []

            # 3. JSONL via X-API-Key (uses api_key.default_policy_code = gov_eval_corpus)
            jsonl_record = {
                "case_code": "CASE_GOV_01",
                "input_text": "我是张三，身份证 32040219900307118X，手机 13812345678",
                "turns": [
                    {
                        "role": "assistant",
                        "content": "张三您好，可拨打 12345 或 0519-85681234，前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理",
                    }
                ],
            }
            jsonl_bytes = (json.dumps(jsonl_record, ensure_ascii=False) + "\n").encode("utf-8")
            r_jsonl = client.post(
                "/api/v1/jobs/file",
                headers=key_hdr,
                data={"job_name": "JSONL政务语料脱敏"},
                files={"file": ("gov_corpus.jsonl", jsonl_bytes, "application/x-ndjson")},
            )
            assert r_jsonl.status_code == 200
            j_jsonl = _wait_until_terminal(client, r_jsonl.json()["data"]["job_no"], key_hdr)
            assert j_jsonl["status"] == "COMPLETED"
            assert j_jsonl["policy_code"] == "gov_eval_corpus"
            assert j_jsonl["policy_version"] == 1
            assert j_jsonl["total_records"] == 1
            assert j_jsonl["processed_records"] == 1
            dl_jsonl = client.get(f"/api/v1/jobs/{j_jsonl['job_no']}/download", headers=key_hdr)
            assert dl_jsonl.status_code == 200
            assert len(dl_jsonl.content) == j_jsonl["output_size_bytes"]
            assert hashlib.sha256(dl_jsonl.content).hexdigest() == j_jsonl["output_sha256"]
            masked_obj = json.loads(dl_jsonl.text.strip())
            assert masked_obj["input_text"] == "我是<PERSON_1>，身份证 <IDCARD_1>，手机 <PHONE_1>"
            assert (
                masked_obj["turns"][0]["content"]
                == "<PERSON_1>您好，可拨打 12345 或 0519-85681234，前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理"
            )

            # 4. CSV via OPERATOR JWT
            csv_bytes = (
                "case_code,input_text,expected_output\n"
                "C1,我是李四，手机 13900139000,李四请拨打 12345\n"
            ).encode("utf-8")
            r_csv = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": "CSV语料脱敏", "policy_code": "gov_eval_corpus"},
                files={"file": ("cases.csv", csv_bytes, "text/csv")},
            )
            assert r_csv.status_code == 200
            j_csv = _wait_until_terminal(client, r_csv.json()["data"]["job_no"], aud_hdr)
            assert j_csv["status"] == "COMPLETED"
            assert j_csv["total_records"] == 1
            dl_csv = client.get(f"/api/v1/jobs/{j_csv['job_no']}/download", headers=aud_hdr)
            assert dl_csv.status_code == 200
            assert "<PERSON_1>" in dl_csv.text
            assert "<PHONE_1>" in dl_csv.text
            assert "12345" in dl_csv.text
            assert "李四" not in dl_csv.text
            assert "13900139000" not in dl_csv.text

            # 5. XLSX via ADMIN JWT
            xlsx_buf = io.BytesIO()
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.append(["input_text", "expected_output"])
            ws.append(["我是张三，住天宁区和平中路88号3幢502室", "张三您好，请拨打 12345"])
            wb.save(xlsx_buf)
            wb.close()
            r_xlsx = client.post(
                "/api/v1/jobs/file",
                headers=admin_hdr,
                data={"job_name": "Excel工单脱敏", "policy_code": "gov_eval_corpus"},
                files={
                    "file": (
                        "tickets.xlsx",
                        xlsx_buf.getvalue(),
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
                },
            )
            assert r_xlsx.status_code == 200
            j_xlsx = _wait_until_terminal(client, r_xlsx.json()["data"]["job_no"], admin_hdr)
            assert j_xlsx["status"] == "COMPLETED"
            assert j_xlsx["total_records"] == 1
            dl_xlsx = client.get(f"/api/v1/jobs/{j_xlsx['job_no']}/download", headers=admin_hdr)
            assert dl_xlsx.status_code == 200
            assert hashlib.sha256(dl_xlsx.content).hexdigest() == j_xlsx["output_sha256"]
            assert "<ADDR_1>" in dl_xlsx.text
            assert "天宁区和平中路88号3幢502室" not in dl_xlsx.text

            # 6. MD and TXT via Bearer dsk_*
            md_bytes = "# 市民来信\n我是张三，身份证 32040219900307118X\n后续：张三已完成办理\n".encode("utf-8")
            r_md = client.post(
                "/api/v1/jobs/file",
                headers={"Authorization": f"Bearer {tokens['API_KEY']}"},
                data={"job_name": "Markdown脱敏", "policy_code": "gov_eval_corpus"},
                files={"file": ("letter.md", md_bytes, "text/markdown")},
            )
            assert r_md.status_code == 200
            j_md = _wait_until_terminal(client, r_md.json()["data"]["job_no"], key_hdr)
            assert j_md["status"] == "COMPLETED"
            assert j_md["total_records"] == 3
            dl_md = client.get(f"/api/v1/jobs/{j_md['job_no']}/download", headers=key_hdr)
            assert "我是<PERSON_1>，身份证 <IDCARD_1>" in dl_md.text
            assert "后续：<PERSON_1>已完成办理" in dl_md.text

            txt_bytes = "市民李四电话 13812345678\n政务热线 12345\n".encode("utf-8")
            r_txt = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": "TXT脱敏", "policy_code": "gov_eval_corpus"},
                files={"file": ("notes.txt", txt_bytes, "text/plain")},
            )
            assert r_txt.status_code == 200
            j_txt = _wait_until_terminal(client, r_txt.json()["data"]["job_no"], op_hdr)
            assert j_txt["status"] == "COMPLETED"
            assert j_txt["total_records"] == 2
            dl_txt = client.get(f"/api/v1/jobs/{j_txt['job_no']}/download", headers=op_hdr)
            assert "<PERSON_1>" in dl_txt.text
            assert "<PHONE_1>" in dl_txt.text
            assert "12345" in dl_txt.text

            # 7. Malformed JSONL & corrupt XLSX -> FAILED, zero partial artifact, zero tmp_uploads residue!
            r_bad_jsonl = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": "畸形JSONL"},
                files={
                    "file": (
                        "broken.jsonl",
                        b'{"input_text":"ok"}\nNOT_JSON_WITH_SECRET_13812345678\n',
                        "application/x-ndjson",
                    )
                },
            )
            assert r_bad_jsonl.status_code == 200
            j_bad_jsonl = _wait_until_terminal(
                client, r_bad_jsonl.json()["data"]["job_no"], op_hdr
            )
            assert j_bad_jsonl["status"] == "FAILED"
            assert "13812345678" not in (j_bad_jsonl.get("error_summary") or "")

            r_bad_xlsx = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": "畸形XLSX"},
                files={
                    "file": (
                        "broken.xlsx",
                        b"CORRUPT_XLSX_32040219900307118X",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
                },
            )
            assert r_bad_xlsx.status_code == 200
            j_bad_xlsx = _wait_until_terminal(
                client, r_bad_xlsx.json()["data"]["job_no"], op_hdr
            )
            assert j_bad_xlsx["status"] == "FAILED"
            assert "32040219900307118X" not in (j_bad_xlsx.get("error_summary") or "")

            # Zero residue in tmp_uploads/ across all 7 uploads!
            assert list(isolated_dirs["tmp_uploads_dir"].iterdir()) == []
    finally:
        pipeline.shutdown()


def test_mysql_readonly_sample_job_whitelist_sql_guard_column_roles_and_admin_job_list(
    test_settings: Any,
) -> None:
    import json
    from app.main import create_app

    onnx = _ScriptedFakeOnnx(
        [
            ("张三", "private_person", 0.96),
            ("12345", "phone", 0.91),
            ("0519-85681234", "phone", 0.92),
            ("常州市政务服务中心（锦绣路2号）", "private_address", 0.93),
            ("钟楼区延陵西路99号", "private_address", 0.94),
            ("https://www.changzhou.gov.cn", "url", 0.95),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    app = create_app(settings=test_settings)
    app.state.policy_engine = PolicyEngineService(pipeline=pipeline, hash_salt="mysql-salt")

    executed_sql: list[tuple[str, Any]] = []
    sample_rows = [
        {
            "request_id": "req_001",
            "session_id": "sess_100",
            "query_text": "我是张三，住钟楼区延陵西路99号，身份证 32040219900307118X，手机 13812345678",
            "answer_text": "张三您好，可拨打 12345 或 0519-85681234，前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理",
            "selected_region": "320400",
        },
        {
            "request_id": "req_002",
            "session_id": "sess_101",
            "query_text": "你好，请问公积金热线是多少",
            "answer_text": "您好，可拨打 12345 咨询",
            "selected_region": "320402",
        },
    ]

    class _StreamCursor:
        def __init__(self) -> None:
            self._idx = 0

        def execute(self, stmt: str, args=None) -> None:
            executed_sql.append((stmt, args))

        def fetchone(self):
            if executed_sql and executed_sql[-1][0] == "SELECT 1":
                return {"1": 1}
            if self._idx >= len(sample_rows):
                return None
            r = sample_rows[self._idx]
            self._idx += 1
            return r

        def close(self) -> None:
            pass

    class _StreamConn:
        def cursor(self):
            return _StreamCursor()

        def close(self) -> None:
            pass

    app.state.mysql_connector_factory = lambda **kw: _StreamConn()

    try:
        with TestClient(app) as client:
            tokens = _seed_auth_principals(client, app, test_settings)
            admin_hdr = {"Authorization": f"Bearer {tokens['ADMIN']}"}
            op_hdr = {"Authorization": f"Bearer {tokens['OPERATOR']}"}
            aud_hdr = {"Authorization": f"Bearer {tokens['AUDITOR']}"}
            key_hdr = {"X-API-Key": tokens["API_KEY"]}

            # Create read-only datasource
            r_ds = client.post(
                "/api/admin/datasources",
                headers=admin_hdr,
                json={
                    "conn_code": "gov_prod_readonly",
                    "conn_name": "政务路由只读库",
                    "db_host": "10.10.0.15",
                    "db_port": 3306,
                    "db_name": "gov_routing",
                    "db_user": "ro_user",
                    "password": "RoSecretPassword!2026",
                    "allowed_tables": ["ai_routing_conversation_record"],
                },
            )
            assert r_ds.status_code == 200

            # 1. X-API-Key rejected with 40101; AUDITOR rejected with 40301 on mysql-sample
            base_req = {
                "job_name": "线上对话抽样脱敏",
                "datasource_code": "gov_prod_readonly",
                "table_name": "ai_routing_conversation_record",
                "select_columns": [
                    "request_id",
                    "session_id",
                    "query_text",
                    "answer_text",
                    "selected_region",
                ],
                "where_clause": "status = 'SUCCESS' AND is_deleted = 0",
                "limit_rows": 200,
                "column_role_mapping": {
                    "query_text": "FULL_MASK_WRITE_SCOPE",
                    "answer_text": "REPLAY_SCOPE_AND_HIGH_RISK",
                    "request_id": "PASSTHROUGH",
                    "session_id": "PASSTHROUGH",
                    "selected_region": "PASSTHROUGH",
                },
                "policy_code": "gov_eval_corpus",
                "output_format": "JSONL",
                "ttl_hours": 72,
            }
            assert (
                client.post(
                    "/api/admin/jobs/mysql-sample", headers=key_hdr, json=base_req
                ).json()["code"]
                == 40101
            )
            assert (
                client.post(
                    "/api/admin/jobs/mysql-sample", headers=aud_hdr, json=base_req
                ).json()["code"]
                == 40301
            )

            # 2. Disallowed table & SQL injection where_clauses rejected immediately -> 400 / 40001
            bad_table_req = {**base_req, "table_name": "ds_admin_user"}
            r_bad_tbl = client.post(
                "/api/admin/jobs/mysql-sample", headers=op_hdr, json=bad_table_req
            )
            assert r_bad_tbl.status_code == 400
            assert r_bad_tbl.json()["code"] == 40001

            for evil_where in (
                "1=1; DROP TABLE ai_routing_conversation_record",
                "status = 'SUCCESS' UNION SELECT username, password_hash, 1, 2, 3 FROM ds_admin_user",
                "status = 'SUCCESS' -- comment",
                "SLEEP(10)",
                "DELETE FROM ai_routing_conversation_record",
            ):
                r_evil = client.post(
                    "/api/admin/jobs/mysql-sample",
                    headers=op_hdr,
                    json={**base_req, "where_clause": evil_where},
                )
                assert r_evil.status_code == 400, evil_where
                assert r_evil.json()["code"] == 40001, evil_where

            # 3. Valid MySQL sample job via OPERATOR JWT -> SET SESSION TRANSACTION READ ONLY + 2-pass role masking
            r_ok = client.post(
                "/api/admin/jobs/mysql-sample", headers=op_hdr, json=base_req
            )
            assert r_ok.status_code == 200
            job_no = r_ok.json()["data"]["job_no"]
            done = _wait_until_terminal(client, job_no, aud_hdr)
            assert done["status"] == "COMPLETED"
            assert done["source_type"] == "MYSQL_READONLY"
            assert done["total_records"] == 2
            assert done["processed_records"] == 2
            assert executed_sql[0] == ("SET SESSION TRANSACTION READ ONLY", None)
            assert executed_sql[1][0].startswith(
                "SELECT `request_id`, `session_id`, `query_text`, `answer_text`, `selected_region` "
                "FROM `ai_routing_conversation_record` WHERE status = 'SUCCESS' AND is_deleted = 0 LIMIT %s"
            )
            assert executed_sql[1][1] == (200,)

            dl = client.get(f"/api/v1/jobs/{job_no}/download", headers=aud_hdr)
            assert dl.status_code == 200
            out_lines = [json.loads(line) for line in dl.text.strip().splitlines()]
            assert len(out_lines) == 2
            row0 = out_lines[0]
            assert row0["request_id"] == "req_001"
            assert row0["selected_region"] == "320400"
            assert (
                row0["query_text"]
                == "我是<PERSON_1>，住<ADDR_1>，身份证 <IDCARD_1>，手机 <PHONE_1>"
            )
            assert (
                row0["answer_text"]
                == "<PERSON_1>您好，可拨打 12345 或 0519-85681234，前往常州市政务服务中心（锦绣路2号）或登录 https://www.changzhou.gov.cn 办理"
            )

            # 4. Paginated & filtered admin job list (`GET /api/admin/jobs`)
            r_list = client.get(
                "/api/admin/jobs?page=1&page_size=10&source_type=MYSQL_READONLY&status=COMPLETED",
                headers=aud_hdr,
            )
            assert r_list.status_code == 200
            list_data = r_list.json()["data"]
            assert list_data["total"] == 1
            assert list_data["items"][0]["job_no"] == job_no
    finally:
        pipeline.shutdown()


def test_spot_check_leak_gate_ttl_expiry_cancellation_and_seven_table_zero_plaintext_scan(
    test_settings: Any,
    isolated_dirs: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    from datetime import timedelta
    import json
    import threading
    from sqlalchemy import inspect as sa_inspect, text as sa_text

    from app.db.base import utcnow
    from app.jobs import cleanup_expired_artifacts
    from app.main import create_app

    onnx = _ScriptedFakeOnnx(
        [
            ("张三", "private_person", 0.97),
            ("王五", "private_person", 0.96),
            ("12345", "phone", 0.91),
            ("钟楼区延陵西路99号", "private_address", 0.94),
        ]
    )
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    app = create_app(settings=test_settings)
    app.state.policy_engine = PolicyEngineService(pipeline=pipeline, hash_salt="gov-audit-salt")

    try:
        with caplog.at_level(logging.DEBUG), TestClient(app) as client:
            tokens = _seed_auth_principals(client, app, test_settings)
            admin_hdr = {"Authorization": f"Bearer {tokens['ADMIN']}"}
            op_hdr = {"Authorization": f"Bearer {tokens['OPERATOR']}"}
            aud_hdr = {"Authorization": f"Bearer {tokens['AUDITOR']}"}
            key_hdr = {"X-API-Key": tokens["API_KEY"]}

            # Create a 3-line JSONL job with PII
            lines = [
                {"input_text": "我是张三，身份证 32040219900307118X，手机 13812345678"},
                {"input_text": "我是王五，住钟楼区延陵西路99号，手机 13900139000"},
                {"input_text": "咨询政务热线 12345"},
            ]
            payload_bytes = ("\n".join(json.dumps(x, ensure_ascii=False) for x in lines) + "\n").encode("utf-8")

            r_create = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={
                    "job_name": "张三_语料待抽检",
                    "policy_code": "gov_eval_corpus",
                    "ttl_hours": "24",
                },
                files={"file": ("张三_公民隐私原始表.jsonl", payload_bytes, "application/x-ndjson")},
            )
            assert r_create.status_code == 200
            job_no = r_create.json()["data"]["job_no"]
            done = _wait_until_terminal(client, job_no, aud_hdr)
            assert done["status"] == "COMPLETED"
            assert done["spot_check_status"] == "UNCHECKED"
            # Even filename was sanitized/masked!
            assert "张三" not in (done["source_filename_masked"] or "")

            # 1. Auditor streams preview-masked?limit=2 -> returns first 2 masked records, has_more=True
            r_prev = client.get(
                f"/api/admin/jobs/{job_no}/preview-masked?limit=2",
                headers=aud_hdr,
            )
            assert r_prev.status_code == 200
            prev_data = r_prev.json()["data"]
            assert prev_data["returned_count"] == 2
            assert prev_data["has_more"] is True
            assert "<PERSON_1>" in prev_data["lines"][0]
            assert "张三" not in r_prev.text
            assert "32040219900307118X" not in r_prev.text

            # 2. Spot-check RBAC: OPERATOR -> 40301, API_KEY -> 40101
            assert (
                client.post(
                    f"/api/admin/jobs/{job_no}/spot-check",
                    headers=op_hdr,
                    json={"spot_check_status": "PASSED"},
                ).json()["code"]
                == 40301
            )
            assert (
                client.post(
                    f"/api/admin/jobs/{job_no}/spot-check",
                    headers=key_hdr,
                    json={"spot_check_status": "PASSED"},
                ).json()["code"]
                == 40101
            )

            # 3. AUDITOR flags FLAGGED_LEAK -> download immediately blocked with 409 / 40901!
            r_leak = client.post(
                f"/api/admin/jobs/{job_no}/spot-check",
                headers=aud_hdr,
                json={
                    "spot_check_status": "FLAGGED_LEAK",
                    "spot_check_note": "第2行疑似存在地址漏标风险，阻断导出",
                },
            )
            assert r_leak.status_code == 200
            assert r_leak.json()["data"]["spot_check_status"] == "FLAGGED_LEAK"
            assert r_leak.json()["data"]["spot_checked_by"] == "batch_auditor"

            for caller_hdr in (key_hdr, admin_hdr, aud_hdr):
                r_dl_blocked = client.get(
                    f"/api/v1/jobs/{job_no}/download", headers=caller_hdr
                )
                assert r_dl_blocked.status_code == 409
                assert r_dl_blocked.json()["code"] == 40901

            # Console preview-masked still accessible for ADMIN to review the flagged artifact
            assert (
                client.get(
                    f"/api/admin/jobs/{job_no}/preview-masked?limit=3",
                    headers=admin_hdr,
                ).status_code
                == 200
            )

            # 4. ADMIN updates spot-check to FLAGGED_OVERMASK then PASSED -> download allowed (200)
            r_overmask = client.post(
                f"/api/admin/jobs/{job_no}/spot-check",
                headers=admin_hdr,
                json={"spot_check_status": "FLAGGED_OVERMASK", "spot_check_note": "复核为误伤预警"},
            )
            assert r_overmask.status_code == 200
            assert client.get(f"/api/v1/jobs/{job_no}/download", headers=key_hdr).status_code == 200

            r_pass = client.post(
                f"/api/admin/jobs/{job_no}/spot-check",
                headers=aud_hdr,
                json={"spot_check_status": "PASSED", "spot_check_note": "人工复核通过"},
            )
            assert r_pass.status_code == 200
            assert r_pass.json()["data"]["spot_check_status"] == "PASSED"

            # 5. TTL cleaner expires artifact -> physical file deleted, status=ARTIFACT_EXPIRED, 410/41001, stats kept!
            artifact_file = isolated_dirs["artifacts_dir"] / f"{job_no}.jsonl"
            assert artifact_file.is_file()

            with app.state.session_factory() as session:
                cleaned = cleanup_expired_artifacts(
                    session,
                    test_settings,
                    now=utcnow() + timedelta(hours=25),
                )
            assert cleaned == 1
            assert not artifact_file.exists()

            r_dl_expired = client.get(f"/api/v1/jobs/{job_no}/download", headers=key_hdr)
            assert r_dl_expired.status_code == 410
            assert r_dl_expired.json()["code"] == 41001

            r_prev_expired = client.get(
                f"/api/admin/jobs/{job_no}/preview-masked", headers=aud_hdr
            )
            assert r_prev_expired.status_code == 410
            assert r_prev_expired.json()["code"] == 41001

            # Audit statistics remain 100% intact after TTL cleanup!
            expired_detail = client.get(f"/api/v1/jobs/{job_no}", headers=aud_hdr).json()["data"]
            assert expired_detail["status"] == "ARTIFACT_EXPIRED"
            assert expired_detail["total_records"] == 3
            assert expired_detail["processed_records"] == 3
            assert expired_detail["total_chars"] > 0
            assert expired_detail["entity_hit_stats"]["private_person"] == 2
            assert expired_detail["output_sha256"] is not None
            assert expired_detail["spot_check_status"] == "PASSED"

            # 6. Cancel both a RUNNING job and a queued PENDING job -> CANCELLED + zero partial/tmp files!
            entered_running = threading.Event()
            release_running = threading.Event()
            target_running_job: dict[str, str] = {}

            def _pause_first_running_job(j_no: str, cancel_ev: threading.Event) -> None:
                if target_running_job.get("first") is None:
                    target_running_job["first"] = j_no
                    entered_running.set()
                    release_running.wait(timeout=3.0)

            app.state.job_execution_hook = _pause_first_running_job
            try:
                r_run = client.post(
                    "/api/v1/jobs/file",
                    headers=op_hdr,
                    data={"job_name": "运行中待取消任务"},
                    files={"file": ("running.jsonl", payload_bytes, "application/x-ndjson")},
                )
                run_job_no = r_run.json()["data"]["job_no"]
                assert entered_running.wait(timeout=3.0)

                r_queued = client.post(
                    "/api/v1/jobs/file",
                    headers=key_hdr,
                    data={"job_name": "排队中待取消任务"},
                    files={"file": ("queued.jsonl", payload_bytes, "application/x-ndjson")},
                )
                queued_job_no = r_queued.json()["data"]["job_no"]

                # AUDITOR cannot cancel -> 40301
                assert (
                    client.post(
                        f"/api/v1/jobs/{run_job_no}/cancel", headers=aud_hdr
                    ).json()["code"]
                    == 40301
                )

                # Cancel queued PENDING job via API_KEY
                r_cancel_q = client.post(
                    f"/api/v1/jobs/{queued_job_no}/cancel", headers=key_hdr
                )
                assert r_cancel_q.status_code == 200
                assert r_cancel_q.json()["data"]["status"] == "CANCELLED"

                # Cancel RUNNING job via OPERATOR JWT, then release hook
                r_cancel_r = client.post(
                    f"/api/v1/jobs/{run_job_no}/cancel", headers=op_hdr
                )
                assert r_cancel_r.status_code == 200
                assert r_cancel_r.json()["data"]["status"] == "CANCELLED"
                release_running.set()

                final_r = _wait_until_terminal(client, run_job_no, op_hdr)
                final_q = _wait_until_terminal(client, queued_job_no, key_hdr)
                assert final_r["status"] == "CANCELLED"
                assert final_q["status"] == "CANCELLED"
            finally:
                release_running.set()
                app.state.job_execution_hook = None

            # Zero partial/completed artifacts and zero tmp_uploads left on disk!
            assert list(isolated_dirs["artifacts_dir"].iterdir()) == []
            assert list(isolated_dirs["tmp_uploads_dir"].iterdir()) == []

            # 7. Full 7-table zero-plaintext scan + log scan!
            forbidden_plaintexts = (
                "张三",
                "王五",
                "32040219900307118X",
                "13812345678",
                "13900139000",
                "钟楼区延陵西路99号",
            )
            with app.state.db_engine.connect() as conn:
                table_names = set(sa_inspect(conn).get_table_names())
                assert {
                    "ds_admin_user",
                    "ds_api_key",
                    "ds_allowlist_dict",
                    "ds_policy_profile",
                    "ds_datasource_conn",
                    "ds_batch_job",
                    "ds_api_usage_hourly",
                }.issubset(table_names)

                for tbl in sorted(table_names):
                    rows = conn.execute(sa_text(f"SELECT * FROM {tbl}")).fetchall()
                    for row in rows:
                        serialized_row = " | ".join(
                            "" if col_val is None else str(col_val) for col_val in row
                        )
                        for pii in forbidden_plaintexts:
                            assert pii not in serialized_row, f"Leaked '{pii}' in table {tbl}"

            for pii in forbidden_plaintexts:
                assert pii not in caplog.text, f"Leaked '{pii}' in logs"
    finally:
        pipeline.shutdown()


def test_mid_write_cancellation_on_windows_and_immutable_policy_version_snapshot_locking(
    test_settings: Any,
    isolated_dirs: dict[str, Any],
) -> None:
    import json
    import threading
    from app.db.seed import GOV_EVAL_CORPUS_ENTITY_RULES
    from app.main import create_app

    row1_written = threading.Event()
    allow_row2 = threading.Event()
    seen_calls = {"count": 0}

    class _PausingOnSecondRowOnnx(_ScriptedFakeOnnx):
        def detect(self, text: str, **kwargs):
            seen_calls["count"] += 1
            if "ROW_TWO_TRIGGER" in text:
                row1_written.set()
                allow_row2.wait(timeout=3.0)
            return super().detect(text, **kwargs)

    onnx = _PausingOnSecondRowOnnx([("张三", "private_person", 0.96)])
    pipeline = HybridDetectorPipeline(onnx_detector=onnx)
    app = create_app(settings=test_settings)
    app.state.policy_engine = PolicyEngineService(pipeline=pipeline, hash_salt="snap-salt")

    try:
        with TestClient(app) as client:
            tokens = _seed_auth_principals(client, app, test_settings)
            admin_hdr = {"Authorization": f"Bearer {tokens['ADMIN']}"}
            op_hdr = {"Authorization": f"Bearer {tokens['OPERATOR']}"}

            # 1. Mid-write cancellation while .part file is actively open on Windows!
            two_rows = (
                json.dumps({"input_text": "第一行我是张三"}, ensure_ascii=False)
                + "\n"
                + json.dumps({"input_text": "ROW_TWO_TRIGGER 第二行我是张三"}, ensure_ascii=False)
                + "\n"
            ).encode("utf-8")

            r_sub = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": "写入中途取消测试", "policy_code": "gov_eval_corpus"},
                files={"file": ("midwrite.jsonl", two_rows, "application/x-ndjson")},
            )
            assert r_sub.status_code == 200
            mid_job_no = r_sub.json()["data"]["job_no"]
            assert row1_written.wait(timeout=3.0)

            # Confirm .part file is currently open on disk before cancel
            part_file = isolated_dirs["artifacts_dir"] / f"{mid_job_no}.jsonl.part"
            assert part_file.exists()

            # Cancel while worker holds .part open -> must NOT raise WinError 32 PermissionError!
            r_cancel = client.post(f"/api/v1/jobs/{mid_job_no}/cancel", headers=op_hdr)
            allow_row2.set()
            assert r_cancel.status_code == 200
            assert r_cancel.json()["data"]["status"] == "CANCELLED"

            # Wait briefly for worker finally cleanup and verify zero .part or final artifact residue
            fut = app.state.job_runner._futures.get(mid_job_no)
            if fut is not None:
                fut.result(timeout=3.0)
            import time

            deadline = time.monotonic() + 3.0
            while part_file.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert not part_file.exists()
            assert list(isolated_dirs["artifacts_dir"].iterdir()) == []
            assert list(isolated_dirs["tmp_uploads_dir"].iterdir()) == []

            # 2. Policy immutable version snapshot locking across policy bump (v1 -> v2)
            r_v1_job = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": "锁定v1版本", "policy_code": "gov_eval_corpus"},
                files={"file": ("v1.txt", "我是张三\n".encode("utf-8"), "text/plain")},
            )
            v1_job_no = r_v1_job.json()["data"]["job_no"]
            _wait_until_terminal(client, v1_job_no, op_hdr)

            # Bump gov_eval_corpus to v2 and set as default
            r_bump = client.post(
                "/api/admin/policies",
                headers=admin_hdr,
                json={
                    "policy_code": "gov_eval_corpus",
                    "policy_name": "政务评测策略 v2",
                    "scope_mode": "CONVERSATION",
                    "entity_rules": GOV_EVAL_CORPUS_ENTITY_RULES,
                    "set_as_default": True,
                },
            )
            assert r_bump.status_code == 200
            assert r_bump.json()["data"]["version"] == 2

            # Earlier job remains locked to version 1; new default job uses v2; explicit version=1 locks v1
            assert (
                client.get(f"/api/v1/jobs/{v1_job_no}", headers=op_hdr).json()["data"][
                    "policy_version_snapshot"
                ]
                == 1
            )
            r_v2_job = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": "默认v2版本", "policy_code": "gov_eval_corpus"},
                files={"file": ("v2.txt", "我是张三\n".encode("utf-8"), "text/plain")},
            )
            assert r_v2_job.json()["data"]["policy_version"] == 2
            _wait_until_terminal(client, r_v2_job.json()["data"]["job_no"], op_hdr)

            r_pin_v1 = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={
                    "job_name": "显式指定v1",
                    "policy_code": "gov_eval_corpus",
                    "policy_version": "1",
                },
                files={"file": ("pin_v1.txt", "我是张三\n".encode("utf-8"), "text/plain")},
            )
            assert r_pin_v1.json()["data"]["policy_version"] == 1
            _wait_until_terminal(client, r_pin_v1.json()["data"]["job_no"], op_hdr)
            assert list(isolated_dirs["tmp_uploads_dir"].iterdir()) == []
    finally:
        allow_row2.set()
        pipeline.shutdown()


def test_job_creation_never_leaks_unmasked_job_name_and_leaves_zero_orphan_pending_rows(
    test_settings: Any,
    isolated_dirs: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.db.models import BatchJob
    from app.jobs.runner import get_or_create_job_runner
    from app.main import create_app

    # Case 1: Missing ONNX weights on gov_eval_corpus -> must propagate 50301 instead of saving raw PII job_name
    app_no_onnx = create_app(settings=test_settings)
    broken_pipeline = HybridDetectorPipeline(onnx_detector=None)
    app_no_onnx.state.policy_engine = PolicyEngineService(
        pipeline=broken_pipeline,
        hash_salt="batch-fail-salt",
    )
    try:
        with TestClient(app_no_onnx) as client:
            tokens = _seed_auth_principals(client, app_no_onnx, test_settings)
            admin_hdr = {"Authorization": f"Bearer {tokens['ADMIN']}"}
            op_hdr = {"Authorization": f"Bearer {tokens['OPERATOR']}"}
            raw_pii_name = "张三手机号13812345678任务"

            r_ds_no_onnx = client.post(
                "/api/admin/datasources",
                headers=admin_hdr,
                json={
                    "conn_code": "ro_no_onnx_ds",
                    "conn_name": "只读库",
                    "db_host": "127.0.0.1",
                    "db_port": 3306,
                    "db_name": "gov_db",
                    "db_user": "ro",
                    "password": "ro_secret_password",
                    "allowed_tables": ["qa_records"],
                },
            )
            assert r_ds_no_onnx.status_code == 200

            r_fail = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": raw_pii_name, "policy_code": "gov_eval_corpus"},
                files={"file": ("raw_张三.txt", "hello\n".encode("utf-8"), "text/plain")},
            )
            assert r_fail.status_code == 503
            assert r_fail.json()["code"] == 50301

            r_mysql_fail = client.post(
                "/api/admin/jobs/mysql-sample",
                headers=admin_hdr,
                json={
                    "job_name": raw_pii_name,
                    "datasource_code": "ro_no_onnx_ds",
                    "table_name": "qa_records",
                    "select_columns": ["id", "content"],
                    "limit_rows": 10,
                    "policy_code": "gov_eval_corpus",
                },
            )
            assert r_mysql_fail.status_code == 503
            assert r_mysql_fail.json()["code"] == 50301

            with app_no_onnx.state.session_factory() as session:
                jobs = session.scalars(select(BatchJob)).all()
                assert jobs == []
            assert list(isolated_dirs["tmp_uploads_dir"].iterdir()) == []
    finally:
        broken_pipeline.shutdown()

    # Case 2: Runner submission failure after commit -> must clean up PENDING row & tmp upload
    app_submit_fail = create_app(settings=test_settings)
    pipeline = HybridDetectorPipeline(onnx_detector=_ScriptedFakeOnnx([("张三", "private_person", 0.99)]))
    app_submit_fail.state.policy_engine = PolicyEngineService(
        pipeline=pipeline,
        hash_salt="batch-submit-fail-salt",
    )
    try:
        with TestClient(app_submit_fail, raise_server_exceptions=False) as client:
            tokens = _seed_auth_principals(client, app_submit_fail, test_settings)
            admin_hdr = {"Authorization": f"Bearer {tokens['ADMIN']}"}
            op_hdr = {"Authorization": f"Bearer {tokens['OPERATOR']}"}

            # Create datasource for mysql-sample check
            r_ds = client.post(
                "/api/admin/datasources",
                headers=admin_hdr,
                json={
                    "conn_code": "ro_fail_ds",
                    "conn_name": "只读库",
                    "db_host": "127.0.0.1",
                    "db_port": 3306,
                    "db_name": "gov_db",
                    "db_user": "ro",
                    "password": "ro_secret_password",
                    "allowed_tables": ["qa_records"],
                },
            )
            assert r_ds.status_code == 200

            runner = get_or_create_job_runner(app_submit_fail)

            def _boom_file(spec: Any) -> None:
                raise RuntimeError("simulated file executor failure")

            def _boom_mysql(spec: Any) -> None:
                raise RuntimeError("simulated mysql executor failure")

            monkeypatch.setattr(runner, "submit_file_job", _boom_file)
            monkeypatch.setattr(runner, "submit_mysql_job", _boom_mysql)

            r_file_err = client.post(
                "/api/v1/jobs/file",
                headers=op_hdr,
                data={"job_name": "普通任务名", "policy_code": "gov_eval_corpus"},
                files={"file": ("sample.txt", "hello\n".encode("utf-8"), "text/plain")},
            )
            assert r_file_err.status_code == 500
            assert list(isolated_dirs["tmp_uploads_dir"].iterdir()) == []

            r_mysql_err = client.post(
                "/api/admin/jobs/mysql-sample",
                headers=admin_hdr,
                json={
                    "job_name": "MySQL失败任务",
                    "datasource_code": "ro_fail_ds",
                    "table_name": "qa_records",
                    "select_columns": ["id", "content"],
                    "limit_rows": 10,
                    "policy_code": "gov_eval_corpus",
                },
            )
            assert r_mysql_err.status_code == 500

            with app_submit_fail.state.session_factory() as session:
                orphan_jobs = session.scalars(select(BatchJob)).all()
                assert orphan_jobs == []
    finally:
        pipeline.shutdown()





