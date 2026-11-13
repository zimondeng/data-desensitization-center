from __future__ import annotations

import os
import pytest


def test_aes_256_gcm_encrypt_decrypt_roundtrip_random_nonce_and_tamper_rejection() -> None:
    from app.jobs.crypto import decrypt_secret, encrypt_secret

    key_a = b"0123456789abcdef0123456789abcdef"
    key_b = os.urandom(32)
    raw_pwd = "RoMySQL#2026!常州政务_Secret"

    cipher_1 = encrypt_secret(raw_pwd, key_a)
    cipher_2 = encrypt_secret(raw_pwd, key_a)

    # Random 12-byte nonce ensures semantic security (distinct ciphertexts) and zero plaintext substring
    assert cipher_1 != cipher_2
    assert raw_pwd not in cipher_1
    assert "RoMySQL" not in cipher_1

    assert decrypt_secret(cipher_1, key_a) == raw_pwd
    assert decrypt_secret(cipher_2, key_a) == raw_pwd

    # Wrong key must fail authentication tag verification without leaking secret
    with pytest.raises(ValueError) as exc_wrong_key:
        decrypt_secret(cipher_1, key_b)
    assert raw_pwd not in str(exc_wrong_key.value)

    # Tampered ciphertext must fail authentication tag verification
    tampered = cipher_1[:-4] + ("AAAA" if cipher_1[-4:] != "AAAA" else "BBBB")
    with pytest.raises(ValueError):
        decrypt_secret(tampered, key_a)

    # Invalid key length rejected
    with pytest.raises(ValueError):
        encrypt_secret(raw_pwd, b"short-key")


def test_mysql_sample_query_validator_enforces_table_whitelist_identifiers_and_blocks_sql_injection() -> None:
    from app.common.errors import BadRequestError
    from app.jobs.mysql_sampler import (
        build_readonly_sample_query,
        redact_where_clause_literals,
        stream_readonly_mysql_rows,
        verify_readonly_mysql_connection,
    )

    allowed = ["ai_routing_conversation_record", "gov_qa_feedback"]
    sql, params = build_readonly_sample_query(
        table_name="ai_routing_conversation_record",
        select_columns=["request_id", "query_text", "answer_text"],
        allowed_tables=allowed,
        where_clause="status = 'SUCCESS' AND is_deleted = 0 AND create_time >= '2026-11-05 00:00:00'",
        limit_rows=250,
    )
    assert sql == (
        "SELECT `request_id`, `query_text`, `answer_text` "
        "FROM `ai_routing_conversation_record` "
        "WHERE status = 'SUCCESS' AND is_deleted = 0 AND create_time >= '2026-11-05 00:00:00' "
        "LIMIT %s"
    )
    assert params == (250,)

    # Redacted summary never retains literal filter values
    redacted = redact_where_clause_literals(
        "mobile = '13812345678' AND status = 'SUCCESS'"
    )
    assert "13812345678" not in redacted
    assert "SUCCESS" not in redacted

    # Disallowed table (outside allowed_tables) -> 400 / 40001
    with pytest.raises(BadRequestError) as exc_tbl:
        build_readonly_sample_query(
            table_name="ds_admin_user",
            select_columns=["username"],
            allowed_tables=allowed,
        )
    assert exc_tbl.value.code == 40001

    # Invalid table or column identifier -> 400 / 40001
    for bad_col in ("query_text; DROP TABLE x", "1bad", "col`name", "*"):
        with pytest.raises(BadRequestError) as exc_col:
            build_readonly_sample_query(
                table_name="gov_qa_feedback",
                select_columns=[bad_col],
                allowed_tables=allowed,
            )
        assert exc_col.value.code == 40001

    # Dangerous / multi-statement / comment / subquery / DML / DDL / sleep payloads -> 400 / 40001
    malicious_clauses = [
        "1=1; DROP TABLE gov_qa_feedback",
        "status = 'SUCCESS' -- bypass",
        "status = 'SUCCESS' /* comment */",
        "status = 'SUCCESS' # hash comment",
        "1=1 UNION SELECT username, password_hash, role FROM ds_admin_user",
        "id IN (SELECT id FROM ds_admin_user)",
        "SLEEP(5) = 0",
        "BENCHMARK(1000000, MD5('x'))",
        "1=1 INTO OUTFILE '/tmp/dump.csv'",
        "DELETE FROM gov_qa_feedback WHERE 1=1",
        "UPDATE gov_qa_feedback SET status='X'",
        "INSERT INTO gov_qa_feedback VALUES (1)",
        "ALTER TABLE gov_qa_feedback ADD COLUMN x INT",
        "TRUNCATE TABLE gov_qa_feedback",
        "CREATE TABLE evil (id INT)",
        "GRANT ALL ON *.* TO 'u'@'%'",
        "EXEC sp_executesql",
        "CALL some_proc()",
        "status = 'unclosed_quote",
        "status = 'escaped\\'quote' OR 1=1; DROP TABLE x",
    ]
    for bad_where in malicious_clauses:
        with pytest.raises(BadRequestError) as exc_where:
            build_readonly_sample_query(
                table_name="gov_qa_feedback",
                select_columns=["request_id"],
                allowed_tables=allowed,
                where_clause=bad_where,
            )
        assert exc_where.value.code == 40001, bad_where

    # Verify read-only session enforcement on both connectivity probe & streaming cursor
    executed_statements: list[tuple[str, tuple | None]] = []
    closed_flags = {"cursor": 0, "conn": 0}

    class _FakeCursor:
        def __init__(self, rows: list[dict]) -> None:
            self._rows = list(rows)
            self._idx = 0

        def execute(self, stmt: str, args=None) -> None:
            executed_statements.append((stmt, args))

        def fetchone(self):
            if executed_statements and executed_statements[-1][0] == "SELECT 1":
                return {"1": 1}
            if self._idx >= len(self._rows):
                return None
            row = self._rows[self._idx]
            self._idx += 1
            return row

        def close(self) -> None:
            closed_flags["cursor"] += 1

    class _FakeConn:
        def __init__(self, rows: list[dict]) -> None:
            self._rows = rows

        def cursor(self):
            return _FakeCursor(self._rows)

        def close(self) -> None:
            closed_flags["conn"] += 1

    def fake_factory(**kwargs):
        assert kwargs["host"] == "10.0.0.12"
        assert kwargs["port"] == 3306
        assert kwargs["user"] == "ro_sampler"
        assert kwargs["password"] == "RoPass#123"
        assert kwargs["database"] == "gov_biz"
        return _FakeConn(
            [
                {"request_id": "r1", "query_text": "你好"},
                {"request_id": "r2", "query_text": "再见"},
            ]
        )

    probe_ms = verify_readonly_mysql_connection(
        host="10.0.0.12",
        port=3306,
        user="ro_sampler",
        password="RoPass#123",
        database="gov_biz",
        connector_factory=fake_factory,
    )
    assert probe_ms >= 0
    assert executed_statements == [
        ("SET SESSION TRANSACTION READ ONLY", None),
        ("SELECT 1", None),
    ]
    assert closed_flags == {"cursor": 1, "conn": 1}

    executed_statements.clear()
    rows = list(
        stream_readonly_mysql_rows(
            host="10.0.0.12",
            port=3306,
            user="ro_sampler",
            password="RoPass#123",
            database="gov_biz",
            sql=sql,
            params=params,
            select_columns=["request_id", "query_text"],
            connector_factory=fake_factory,
        )
    )
    assert rows == [
        {"request_id": "r1", "query_text": "你好"},
        {"request_id": "r2", "query_text": "再见"},
    ]
    assert executed_statements[0] == ("SET SESSION TRANSACTION READ ONLY", None)
    assert executed_statements[1] == (sql, (250,))
    assert closed_flags == {"cursor": 2, "conn": 2}


def test_streaming_file_readers_all_five_formats_windows_openpyxl_close_and_zero_tmp_residue(
    tmp_path,
) -> None:
    import hashlib
    import json
    import openpyxl

    from app.db.seed import GOV_EVAL_CORPUS_ENTITY_RULES, GOV_EVAL_CORPUS_FIELD_ROLE_RULES
    from app.detectors import (
        AllowlistEntry,
        DEFAULT_ID2LABEL,
        HybridDetectorPipeline,
        OnnxNerDetector,
    )
    from app.engine import PolicyEngineService
    from app.jobs.file_readers import (
        FileParseError,
        preview_masked_artifact,
        process_uploaded_file_and_unlink,
        resolve_file_formats,
    )
    import numpy as np

    label2id = {lbl: idx for idx, lbl in DEFAULT_ID2LABEL.items()}

    class _FakeOnnx(OnnxNerDetector):
        def __init__(self) -> None:
            self._txt = ""

            class _Tok:
                def encode(s_tok, text: str):
                    self._txt = text

                    class _Enc:
                        ids = [0, *[100 + i for i in range(len(text))], 2]
                        offsets = [(0, 0), *[(i, i + 1) for i in range(len(text))], (0, 0)]

                    return _Enc()

            class _Sess:
                def run(s_sess, out_names, feed):
                    ids = feed["input_ids"]
                    logits = np.zeros((1, ids.shape[1], 21), dtype=np.float32)
                    logits[:, :, label2id["O"]] = 10.0
                    idx = self._txt.find("张三")
                    if idx >= 0:
                        logits[0, idx + 1, :] = 0.0
                        logits[0, idx + 1, label2id["B-private_person"]] = 10.0
                        logits[0, idx + 2, :] = 0.0
                        logits[0, idx + 2, label2id["I-private_person"]] = 10.0
                    return [logits]

            super().__init__(session=_Sess(), tokenizer=_Tok())

    pipeline = HybridDetectorPipeline(onnx_detector=_FakeOnnx())
    try:
        engine = PolicyEngineService(pipeline=pipeline, hash_salt="unit-salt")
        snapshot = engine.build_inline_snapshot(
            policy_id=1,
            policy_code="gov_eval_corpus",
            version=1,
            scope_mode="CONVERSATION",
            entity_rules=GOV_EVAL_CORPUS_ENTITY_RULES,
            field_role_rules=GOV_EVAL_CORPUS_FIELD_ROLE_RULES,
            allowlist_groups=["gov_public_hotline"],
            allowlist_entries=(
                AllowlistEntry(
                    group_code="gov_public_hotline",
                    item_name="政务短号",
                    match_mode="EXACT",
                    pattern_text="12345",
                    apply_labels=("phone",),
                ),
            ),
        )

        uploads_dir = tmp_path / "tmp_uploads"
        artifacts_dir = tmp_path / "artifacts"
        uploads_dir.mkdir()
        artifacts_dir.mkdir()

        # 1. Valid XLSX with numeric cell for mobile + string ID card -> wb.close() before unlink on Windows!
        in_fmt, out_fmt, _ = resolve_file_formats("citizens.xlsx", None)
        assert (in_fmt, out_fmt) == ("XLSX", "JSONL")

        xlsx_tmp = uploads_dir / "upload_valid.xlsx"
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["input_text", "mobile_num", "expected_output"])
        ws.append(["我是张三，身份证 32040219900307118X", 13812345678, "张三可拨打 12345 咨询"])
        wb.save(str(xlsx_tmp))
        wb.close()

        xlsx_out = artifacts_dir / "DSJ_XLSX.jsonl"
        summary = process_uploaded_file_and_unlink(
            src_tmp_path=xlsx_tmp,
            dest_final_path=xlsx_out,
            input_format="XLSX",
            output_format="JSONL",
            snapshot=snapshot,
            engine=engine,
        )
        assert not xlsx_tmp.exists()
        assert list(uploads_dir.iterdir()) == []
        assert summary.total_records == 1
        assert summary.processed_records == 1
        assert summary.output_size_bytes == xlsx_out.stat().st_size
        assert summary.output_sha256 == hashlib.sha256(xlsx_out.read_bytes()).hexdigest()

        parsed_line = json.loads(xlsx_out.read_text(encoding="utf-8").strip())
        assert parsed_line["input_text"] == "我是<PERSON_1>，身份证 <IDCARD_1>"
        assert parsed_line["mobile_num"] == "<PHONE_1>"
        assert parsed_line["expected_output"] == "<PERSON_1>可拨打 12345 咨询"

        preview = preview_masked_artifact(xlsx_out, "JSONL", limit=5)
        assert preview["returned_count"] == 1
        assert preview["has_more"] is False
        assert "<PERSON_1>" in preview["lines"][0]

        # 2. Malformed mid-stream JSONL -> raises FileParseError, cleans partial artifact & unlinks tmp upload!
        bad_jsonl_tmp = uploads_dir / "upload_bad.jsonl"
        bad_jsonl_tmp.write_text(
            '{"input_text": "我是张三"}\n<<<BROKEN_JSON_13812345678>>>\n',
            encoding="utf-8",
        )
        bad_jsonl_out = artifacts_dir / "DSJ_BAD.jsonl"
        with pytest.raises(FileParseError) as exc_bad_jsonl:
            process_uploaded_file_and_unlink(
                src_tmp_path=bad_jsonl_tmp,
                dest_final_path=bad_jsonl_out,
                input_format="JSONL",
                output_format="JSONL",
                snapshot=snapshot,
                engine=engine,
            )
        assert "13812345678" not in str(exc_bad_jsonl.value)
        assert not bad_jsonl_tmp.exists()
        assert not bad_jsonl_out.exists()
        assert list(uploads_dir.iterdir()) == []

        # 3. Corrupted XLSX bytes -> raises FileParseError & unlinks tmp upload cleanly on Windows!
        corrupt_xlsx_tmp = uploads_dir / "upload_corrupt.xlsx"
        corrupt_xlsx_tmp.write_bytes(b"NOT_A_ZIP_SECRET_32040219900307118X")
        corrupt_xlsx_out = artifacts_dir / "DSJ_CORRUPT.jsonl"
        with pytest.raises(FileParseError) as exc_corrupt:
            process_uploaded_file_and_unlink(
                src_tmp_path=corrupt_xlsx_tmp,
                dest_final_path=corrupt_xlsx_out,
                input_format="XLSX",
                output_format="JSONL",
                snapshot=snapshot,
                engine=engine,
            )
        assert "32040219900307118X" not in str(exc_corrupt.value)
        assert not corrupt_xlsx_tmp.exists()
        assert not corrupt_xlsx_out.exists()
        assert list(uploads_dir.iterdir()) == []
    finally:
        pipeline.shutdown()


def test_jsonl_export_preserves_untouched_numeric_types_under_mask_roles(tmp_path) -> None:
    import json
    import numpy as np

    from app.detectors import DEFAULT_ID2LABEL, HybridDetectorPipeline, OnnxNerDetector
    from app.engine import PolicyEngineService
    from app.jobs.file_readers import process_record_stream_to_artifact

    label2id = {lbl: idx for idx, lbl in DEFAULT_ID2LABEL.items()}

    class _NoopOnnx(OnnxNerDetector):
        def __init__(self) -> None:
            class _Tok:
                def encode(s_tok, text: str):
                    class _Enc:
                        ids = [0, *[100 + i for i in range(len(text))], 2]
                        offsets = [(0, 0), *[(i, i + 1) for i in range(len(text))], (0, 0)]

                    return _Enc()

            class _Sess:
                def run(s_sess, out_names, feed):
                    ids = feed["input_ids"]
                    logits = np.zeros((1, ids.shape[1], 21), dtype=np.float32)
                    logits[:, :, label2id["O"]] = 10.0
                    return [logits]

            super().__init__(session=_Sess(), tokenizer=_Tok())

    pipeline = HybridDetectorPipeline(onnx_detector=_NoopOnnx())
    try:
        engine = PolicyEngineService(pipeline=pipeline, hash_salt="unit-salt")
        snapshot = engine.build_inline_snapshot(
            policy_id=1,
            policy_code="num_preserve_test",
            version=1,
            scope_mode="CONVERSATION",
            entity_rules={
                "phone": {"enabled": True, "min_score": 0.5, "action": "PLACEHOLDER"},
                "cn_mobile": {"enabled": True, "min_score": 0.5, "action": "PLACEHOLDER"},
            },
            field_role_rules={"default_role": "FULL_MASK_WRITE_SCOPE", "rules": []},
        )
        out_path = tmp_path / "out.jsonl"
        records = [
            (
                {
                    "id": 42,
                    "score": 98.5,
                    "zero": 0,
                    "flag": True,
                    "mobile_num": 13812345678,
                    "replay_count": 7,
                },
                ["id", "score", "zero", "flag", "mobile_num", "replay_count"],
            )
        ]
        process_record_stream_to_artifact(
            records=records,
            dest_final_path=out_path,
            output_format="JSONL",
            snapshot=snapshot,
            engine=engine,
            column_role_mapping={
                "id": "FULL_MASK_WRITE_SCOPE",
                "score": "FULL_MASK_WRITE_SCOPE",
                "zero": "FULL_MASK_WRITE_SCOPE",
                "flag": "FULL_MASK_WRITE_SCOPE",
                "mobile_num": "FULL_MASK_WRITE_SCOPE",
                "replay_count": "REPLAY_SCOPE_AND_HIGH_RISK",
            },
            preserve_sql_types=True,
        )
        row = json.loads(out_path.read_text(encoding="utf-8").strip())
        assert row["id"] == 42 and type(row["id"]) is int
        assert row["score"] == 98.5 and type(row["score"]) is float
        assert row["zero"] == 0 and type(row["zero"]) is int
        assert row["flag"] is True and type(row["flag"]) is bool
        assert row["replay_count"] == 7 and type(row["replay_count"]) is int
        assert row["mobile_num"] == "<PHONE_1>"
    finally:
        pipeline.shutdown()



