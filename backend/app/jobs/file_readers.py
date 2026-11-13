from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
import csv
from dataclasses import dataclass
from datetime import date, datetime, time as dt_time
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from typing import Any

import openpyxl

from app.common.errors import BadRequestError
from app.engine import EphemeralScopeDict, PolicyEngineService, ResolvedPolicySnapshot

SUPPORTED_UPLOAD_EXTENSIONS: dict[str, str] = {
    ".jsonl": "JSONL",
    ".csv": "CSV",
    ".xlsx": "XLSX",
    ".md": "MD",
    ".txt": "TXT",
}

SUPPORTED_OUTPUT_FORMATS: frozenset[str] = frozenset(
    {"JSONL", "CSV", "MD", "TXT", "XLSX"}
)

OUTPUT_FORMAT_EXTENSIONS: dict[str, str] = {
    "JSONL": "jsonl",
    "CSV": "csv",
    "MD": "md",
    "TXT": "txt",
    "XLSX": "xlsx",
}

OUTPUT_MEDIA_TYPES: dict[str, str] = {
    "JSONL": "application/x-ndjson; charset=utf-8",
    "CSV": "text/csv; charset=utf-8",
    "MD": "text/markdown; charset=utf-8",
    "TXT": "text/plain; charset=utf-8",
    "XLSX": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


class FileParseError(ValueError):
    """Raised on malformed input file content. Message MUST NEVER contain raw input text."""


class JobCancelledError(RuntimeError):
    """Cooperative cancellation signal raised during streaming job execution."""


@dataclass(slots=True)
class ArtifactProcessSummary:
    total_records: int
    processed_records: int
    failed_records: int
    total_chars: int
    hit_counts: dict[str, int]
    output_size_bytes: int
    output_sha256: str


def resolve_file_formats(
    filename: str | None,
    requested_output_format: str | None = None,
) -> tuple[str, str, str]:
    raw_name = (filename or "").strip()
    if not raw_name:
        raise BadRequestError("Uploaded filename must not be empty")
    ext = Path(raw_name).suffix.lower()
    input_fmt = SUPPORTED_UPLOAD_EXTENSIONS.get(ext)
    if input_fmt is None:
        raise BadRequestError(
            "Unsupported file extension; supported formats: .jsonl, .csv, .xlsx, .md, .txt"
        )

    if requested_output_format is not None and requested_output_format.strip():
        out_fmt = requested_output_format.strip().upper()
        if out_fmt in ("AUTO", "SAME"):
            out_fmt = "JSONL" if input_fmt == "XLSX" else input_fmt
        if out_fmt not in SUPPORTED_OUTPUT_FORMATS:
            raise BadRequestError(
                "Unsupported output_format; allowed: JSONL, CSV, MD, TXT, XLSX"
            )
    else:
        # Per API spec §2.1: isomorphic with input for JSONL/CSV/MD/TXT, or JSONL for XLSX
        out_fmt = "JSONL" if input_fmt == "XLSX" else input_fmt

    return input_fmt, out_fmt, ext


def validate_output_format(raw_format: str | None, default: str = "JSONL") -> str:
    if raw_format is None or not raw_format.strip():
        return default
    clean = raw_format.strip().upper()
    if clean not in SUPPORTED_OUTPUT_FORMATS:
        raise BadRequestError(
            "Unsupported output_format; allowed: JSONL, CSV, MD, TXT, XLSX"
        )
    return clean


def _compute_file_size_and_sha256(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _cell_to_maskable_value(val: Any) -> Any:
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, bool):
        return val
    if isinstance(val, (datetime, date, dt_time)):
        return val.isoformat()
    if isinstance(val, Decimal):
        return str(val)
    if isinstance(val, float) and val.is_integer():
        return str(int(val))
    return str(val)


def _prepare_row_for_masking(
    row: dict[str, Any],
    column_role_mapping: Mapping[str, str] | None,
) -> dict[str, Any]:
    prepared: dict[str, Any] = {}
    for k, v in row.items():
        if v is None or isinstance(v, (str, bool)):
            prepared[k] = v
            continue
        role = column_role_mapping.get(k) if column_role_mapping else None
        if role == "PASSTHROUGH" and isinstance(v, (int, float)):
            prepared[k] = v
        elif isinstance(v, (datetime, date, dt_time)):
            prepared[k] = v.isoformat()
        elif isinstance(v, Decimal):
            prepared[k] = str(v)
        elif role in ("FULL_MASK_WRITE_SCOPE", "REPLAY_SCOPE_AND_HIGH_RISK", None):
            # Convert numeric cells/columns to str when eligible for masking so numeric PII (e.g. mobile) is scanned
            prepared[k] = str(int(v)) if isinstance(v, float) and v.is_integer() else str(v)
        else:
            prepared[k] = v
    return prepared


class _StreamingArtifactWriter:
    """Streams masked records or text lines into a temporary .part file."""

    def __init__(self, part_path: Path, output_format: str) -> None:
        self._part_path = part_path
        self._output_format = output_format
        self._text_fh: Any = None
        self._csv_writer: Any = None
        self._csv_headers: list[str] | None = None
        self._xlsx_wb: Any = None
        self._xlsx_ws: Any = None
        self._xlsx_headers: list[str] | None = None

        if output_format == "XLSX":
            wb = openpyxl.Workbook(write_only=True)
            self._xlsx_wb = wb
            self._xlsx_ws = wb.create_sheet(title="masked_output")
        else:
            newline = "" if output_format == "CSV" else "\n"
            self._text_fh = part_path.open("w", encoding="utf-8", newline=newline)

    def write_record(self, record: dict[str, Any], field_order: list[str] | None = None) -> None:
        fmt = self._output_format
        if fmt == "JSONL":
            self._text_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        elif fmt == "CSV":
            if self._csv_headers is None:
                self._csv_headers = list(field_order) if field_order else list(record.keys())
                self._csv_writer = csv.writer(self._text_fh)
                self._csv_writer.writerow(self._csv_headers)
            self._csv_writer.writerow(
                ["" if record.get(h) is None else record.get(h, "") for h in self._csv_headers]
            )
        elif fmt == "XLSX":
            if self._xlsx_headers is None:
                self._xlsx_headers = list(field_order) if field_order else list(record.keys())
                self._xlsx_ws.append(self._xlsx_headers)
            self._xlsx_ws.append(
                ["" if record.get(h) is None else record.get(h, "") for h in self._xlsx_headers]
            )
        else:
            # MD or TXT output from structured input
            self._text_fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def write_text_line(self, line: str, line_no: int) -> None:
        fmt = self._output_format
        if fmt in ("MD", "TXT"):
            self._text_fh.write(line + "\n")
        elif fmt == "JSONL":
            self._text_fh.write(
                json.dumps({"line_no": line_no, "text": line}, ensure_ascii=False) + "\n"
            )
        elif fmt == "CSV":
            if self._csv_headers is None:
                self._csv_headers = ["line_no", "text"]
                self._csv_writer = csv.writer(self._text_fh)
                self._csv_writer.writerow(self._csv_headers)
            self._csv_writer.writerow([line_no, line])
        elif fmt == "XLSX":
            if self._xlsx_headers is None:
                self._xlsx_headers = ["line_no", "text"]
                self._xlsx_ws.append(self._xlsx_headers)
            self._xlsx_ws.append([line_no, line])

    def close(self, *, save_xlsx: bool = True) -> None:
        if self._text_fh is not None:
            try:
                self._text_fh.close()
            finally:
                self._text_fh = None
        if self._xlsx_wb is not None:
            wb = self._xlsx_wb
            self._xlsx_wb = None
            self._xlsx_ws = None
            try:
                if save_xlsx:
                    wb.save(str(self._part_path))
            finally:
                try:
                    wb.close()
                except Exception:
                    pass


def _iter_jsonl_records(src_path: Path) -> Iterator[tuple[dict[str, Any], list[str] | None]]:
    try:
        with src_path.open("r", encoding="utf-8-sig", errors="strict") as fh:
            for line_idx, raw_line in enumerate(fh, start=1):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    parsed = json.loads(stripped)
                except json.JSONDecodeError:
                    raise FileParseError(f"Malformed JSONL syntax at line {line_idx}") from None
                if not isinstance(parsed, dict):
                    raise FileParseError(
                        f"JSONL line {line_idx} must be a JSON object"
                    )
                yield parsed, None
    except UnicodeDecodeError:
        raise FileParseError("Input JSONL file is not valid UTF-8 text") from None


def _iter_csv_records(src_path: Path) -> Iterator[tuple[dict[str, Any], list[str]]]:
    try:
        with src_path.open("r", encoding="utf-8-sig", errors="strict", newline="") as fh:
            reader = csv.reader(fh)
            header_row = next(reader, None)
            if header_row is None:
                return
            headers = [
                h.strip() if h and h.strip() else f"col_{idx + 1}"
                for idx, h in enumerate(header_row)
            ]
            for row_idx, row in enumerate(reader, start=2):
                if not row or all(cell == "" for cell in row):
                    continue
                if len(row) > len(headers) and any(c.strip() for c in row[len(headers) :]):
                    raise FileParseError(
                        f"CSV row {row_idx} has more columns than header"
                    )
                rec = {
                    col: (row[i] if i < len(row) else "")
                    for i, col in enumerate(headers)
                }
                yield rec, headers
    except UnicodeDecodeError:
        raise FileParseError("Input CSV file is not valid UTF-8 text") from None
    except csv.Error:
        raise FileParseError("Malformed CSV structure in uploaded file") from None


def _iter_xlsx_records(src_path: Path) -> Iterator[tuple[dict[str, Any], list[str]]]:
    wb = None
    try:
        try:
            wb = openpyxl.load_workbook(
                filename=str(src_path),
                read_only=True,
                data_only=True,
            )
        except Exception:
            raise FileParseError("Failed to open or parse XLSX workbook") from None

        ws = wb.active
        if ws is None:
            return

        rows_iter = ws.iter_rows(values_only=True)
        header_row = next(rows_iter, None)
        if header_row is None:
            return

        headers = [
            str(cell).strip() if cell is not None and str(cell).strip() else f"col_{idx + 1}"
            for idx, cell in enumerate(header_row)
        ]

        for row in rows_iter:
            if row is None or all(c is None or str(c) == "" for c in row):
                continue
            rec = {
                col: _cell_to_maskable_value(row[i] if i < len(row) else None)
                for i, col in enumerate(headers)
            }
            yield rec, headers
    except FileParseError:
        raise
    except Exception:
        raise FileParseError("Failed while streaming XLSX rows") from None
    finally:
        if wb is not None:
            try:
                wb.close()
            except Exception:
                pass


def _iter_text_lines(src_path: Path) -> Iterator[str]:
    try:
        with src_path.open("r", encoding="utf-8-sig", errors="strict") as fh:
            for raw_line in fh:
                yield raw_line.rstrip("\r\n")
    except UnicodeDecodeError:
        raise FileParseError("Input text file is not valid UTF-8 text") from None


def _run_streaming_artifact(
    *,
    dest_final_path: Path,
    output_format: str,
    should_cancel: Callable[[], bool] | None,
    on_progress: Callable[[int, int, int], None] | None,
    progress_interval: int,
    populate: Callable[[_StreamingArtifactWriter, Callable[[int, Mapping[str, int]], None]], None],
) -> ArtifactProcessSummary:
    dest_final_path.parent.mkdir(parents=True, exist_ok=True)
    part_path = dest_final_path.with_name(dest_final_path.name + ".part")

    writer = _StreamingArtifactWriter(part_path, output_format)
    succeeded = False
    total_records = 0
    processed_records = 0
    total_chars = 0
    hit_counts: dict[str, int] = {}

    def _record_step(chars: int, hits: Mapping[str, int]) -> None:
        nonlocal total_records, processed_records, total_chars
        total_records += 1
        processed_records += 1
        total_chars += chars
        for lbl, cnt in hits.items():
            hit_counts[lbl] = hit_counts.get(lbl, 0) + cnt
        if on_progress is not None and processed_records % progress_interval == 0:
            on_progress(total_records, processed_records, total_chars)

    try:
        populate(writer, _record_step)

        if should_cancel is not None and should_cancel():
            raise JobCancelledError("Job cancelled")

        writer.close(save_xlsx=True)

        if should_cancel is not None and should_cancel():
            raise JobCancelledError("Job cancelled")

        size_bytes, sha256_hex = _compute_file_size_and_sha256(part_path)
        part_path.replace(dest_final_path)
        succeeded = True

        return ArtifactProcessSummary(
            total_records=total_records,
            processed_records=processed_records,
            failed_records=0,
            total_chars=total_chars,
            hit_counts=hit_counts,
            output_size_bytes=size_bytes,
            output_sha256=sha256_hex,
        )
    finally:
        writer.close(save_xlsx=False)
        if not succeeded:
            part_path.unlink(missing_ok=True)
            dest_final_path.unlink(missing_ok=True)


def process_record_stream_to_artifact(
    *,
    records: Iterable[tuple[dict[str, Any], list[str] | None]],
    dest_final_path: Path,
    output_format: str,
    snapshot: ResolvedPolicySnapshot,
    engine: PolicyEngineService,
    column_role_mapping: Mapping[str, str] | None = None,
    preserve_sql_types: bool = False,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int, int], None] | None = None,
) -> ArtifactProcessSummary:
    def _populate(
        writer: _StreamingArtifactWriter,
        record_step: Callable[[int, Mapping[str, int]], None],
    ) -> None:
        for raw_rec, field_order in records:
            if should_cancel is not None and should_cancel():
                raise JobCancelledError("Job cancelled")

            rec_to_mask = (
                _prepare_row_for_masking(raw_rec, column_role_mapping)
                if preserve_sql_types
                else raw_rec
            )
            res = engine.mask_structured_record(
                rec_to_mask,
                snapshot,
                column_role_override=column_role_mapping,
            )
            masked_rec = res.masked_payload
            if preserve_sql_types:
                # Preserve original int/float when masking did not alter the value
                for k, orig_v in raw_rec.items():
                    if (
                        isinstance(orig_v, (int, float))
                        and not isinstance(orig_v, bool)
                        and masked_rec.get(k) == rec_to_mask.get(k)
                    ):
                        masked_rec[k] = orig_v

            writer.write_record(masked_rec, field_order=field_order)
            record_step(res.char_count, res.hit_counts)

    return _run_streaming_artifact(
        dest_final_path=dest_final_path,
        output_format=output_format,
        should_cancel=should_cancel,
        on_progress=on_progress,
        progress_interval=25,
        populate=_populate,
    )


def _process_text_stream_to_artifact(
    *,
    lines: Iterable[str],
    dest_final_path: Path,
    output_format: str,
    snapshot: ResolvedPolicySnapshot,
    engine: PolicyEngineService,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int, int], None] | None = None,
) -> ArtifactProcessSummary:
    doc_scope = (
        EphemeralScopeDict(mode="CONVERSATION")
        if snapshot.scope_mode == "CONVERSATION"
        else None
    )

    def _populate(
        writer: _StreamingArtifactWriter,
        record_step: Callable[[int, Mapping[str, int]], None],
    ) -> None:
        try:
            for line_idx, raw_line in enumerate(lines, start=1):
                if should_cancel is not None and should_cancel():
                    raise JobCancelledError("Job cancelled")

                if raw_line:
                    res = engine.mask_text(raw_line, snapshot, scope=doc_scope)
                    masked_line = res.masked_text
                    hits: Mapping[str, int] = res.hit_counts
                else:
                    masked_line = ""
                    hits = {}

                writer.write_text_line(masked_line, line_idx)
                record_step(len(raw_line), hits)
        finally:
            if doc_scope is not None:
                doc_scope.clear()

    return _run_streaming_artifact(
        dest_final_path=dest_final_path,
        output_format=output_format,
        should_cancel=should_cancel,
        on_progress=on_progress,
        progress_interval=50,
        populate=_populate,
    )


def process_uploaded_file_and_unlink(
    *,
    src_tmp_path: Path,
    dest_final_path: Path,
    input_format: str,
    output_format: str,
    snapshot: ResolvedPolicySnapshot,
    engine: PolicyEngineService,
    column_role_mapping: Mapping[str, str] | None = None,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int, int], None] | None = None,
) -> ArtifactProcessSummary:
    """Stream uploaded file through policy engine and ALWAYS physically unlink src_tmp_path."""
    try:
        if input_format == "JSONL":
            return process_record_stream_to_artifact(
                records=_iter_jsonl_records(src_tmp_path),
                dest_final_path=dest_final_path,
                output_format=output_format,
                snapshot=snapshot,
                engine=engine,
                column_role_mapping=column_role_mapping,
                should_cancel=should_cancel,
                on_progress=on_progress,
            )
        if input_format == "CSV":
            return process_record_stream_to_artifact(
                records=_iter_csv_records(src_tmp_path),
                dest_final_path=dest_final_path,
                output_format=output_format,
                snapshot=snapshot,
                engine=engine,
                column_role_mapping=column_role_mapping,
                should_cancel=should_cancel,
                on_progress=on_progress,
            )
        if input_format == "XLSX":
            return process_record_stream_to_artifact(
                records=_iter_xlsx_records(src_tmp_path),
                dest_final_path=dest_final_path,
                output_format=output_format,
                snapshot=snapshot,
                engine=engine,
                column_role_mapping=column_role_mapping,
                should_cancel=should_cancel,
                on_progress=on_progress,
            )
        if input_format in ("MD", "TXT"):
            return _process_text_stream_to_artifact(
                lines=_iter_text_lines(src_tmp_path),
                dest_final_path=dest_final_path,
                output_format=output_format,
                snapshot=snapshot,
                engine=engine,
                should_cancel=should_cancel,
                on_progress=on_progress,
            )
        raise BadRequestError(f"Unsupported input_format '{input_format}'")
    finally:
        src_tmp_path.unlink(missing_ok=True)


def preview_masked_artifact(
    artifact_path: Path,
    output_format: str,
    limit: int = 20,
) -> dict[str, Any]:
    """Stream ONLY the first `limit` lines/rows from a masked output artifact."""
    max_items = max(1, min(int(limit), 200))
    fmt = output_format.upper()
    lines: list[str] = []
    records: list[dict[str, Any]] = []
    has_more = False

    if fmt == "XLSX":
        wb = None
        try:
            wb = openpyxl.load_workbook(
                filename=str(artifact_path), read_only=True, data_only=True
            )
            ws = wb.active
            if ws is not None:
                rows_iter = ws.iter_rows(values_only=True)
                header = next(rows_iter, None)
                if header is not None:
                    cols = [
                        str(c) if c is not None else f"col_{i + 1}"
                        for i, c in enumerate(header)
                    ]
                    for row in rows_iter:
                        if len(records) >= max_items:
                            has_more = True
                            break
                        rec = {
                            cols[i]: ("" if i >= len(row) or row[i] is None else str(row[i]))
                            for i in range(len(cols))
                        }
                        records.append(rec)
                        lines.append(json.dumps(rec, ensure_ascii=False))
        finally:
            if wb is not None:
                try:
                    wb.close()
                except Exception:
                    pass
    elif fmt == "CSV":
        with artifact_path.open("r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader, None)
            if header is not None:
                for row in reader:
                    if len(records) >= max_items:
                        has_more = True
                        break
                    rec = {
                        header[i]: (row[i] if i < len(row) else "")
                        for i in range(len(header))
                    }
                    records.append(rec)
                    lines.append(json.dumps(rec, ensure_ascii=False))
    elif fmt == "JSONL":
        with artifact_path.open("r", encoding="utf-8-sig") as fh:
            for raw_line in fh:
                stripped = raw_line.rstrip("\r\n")
                if not stripped:
                    continue
                if len(lines) >= max_items:
                    has_more = True
                    break
                lines.append(stripped)
                try:
                    parsed = json.loads(stripped)
                    records.append(
                        parsed if isinstance(parsed, dict) else {"value": parsed}
                    )
                except json.JSONDecodeError:
                    records.append({"line": stripped})
    else:
        with artifact_path.open("r", encoding="utf-8-sig") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                if len(lines) >= max_items:
                    has_more = True
                    break
                text_line = raw_line.rstrip("\r\n")
                lines.append(text_line)
                records.append({"line_no": line_no, "content": text_line})

    return {
        "output_format": fmt,
        "limit": max_items,
        "returned_count": len(lines),
        "has_more": has_more,
        "lines": lines,
        "records": records,
    }
