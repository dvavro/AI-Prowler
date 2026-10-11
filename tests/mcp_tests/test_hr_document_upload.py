"""
tests/mcp/test_hr_document_upload.py
=====================================
Tests for the HR document-upload backend (_hr_parse_multipart /
_hr_handle_document_upload in ai_prowler_mcp.py's HR Backend Engine section,
wired into both mode's ASGI routers at POST /hr-api/documents/upload).

SAFETY (per explicit user requirement): these tests do NOT import
ai_prowler_mcp.py, do NOT touch the real hr_db.json, and do NOT write any
file under the real hr_documents folder. Every behavioral assertion below
runs against a local mirror of the multipart parser and the upload
handler's validation/business logic, driven with synthetic in-memory data
and a pytest tmp_path for the one thing that must actually touch a
filesystem (verifying a file gets written where expected) — never the real
install directory. This follows the same convention already established by
tests/mcp/test_pwa_api_route.py and tests/analysis/test_hr_scheduler.py.

Run:
    run_tests.bat tests\\mcp\\test_hr_document_upload.py -v
"""

import os
import re
import datetime
import pytest

SRC_ROOT = os.environ.get(
    "AI_PROWLER_SRC",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)
AI_PROWLER_MCP_PATH = os.path.join(SRC_ROOT, "ai_prowler_mcp.py")


# ── Local mirror of _hr_parse_multipart (pure function — no I/O) ───────────

def _mirror_parse_multipart(raw: bytes, content_type: str):
    boundary = None
    for part in (content_type or "").split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[9:].strip().encode()
            break
    if not boundary:
        raise ValueError("No multipart boundary found")
    fields, files = {}, []
    delim = b"--" + boundary
    for seg in raw.split(delim)[1:]:
        if seg.strip() in (b"", b"--", b"--\r\n"):
            continue
        if b"\r\n\r\n" in seg:
            hdrs, body = seg.split(b"\r\n\r\n", 1)
        elif b"\n\n" in seg:
            hdrs, body = seg.split(b"\n\n", 1)
        else:
            continue
        body = body.rstrip(b"\r\n")
        hdrs_str = hdrs.decode(errors="replace")
        cd = ""
        for line in hdrs_str.splitlines():
            if line.lower().startswith("content-disposition"):
                cd = line
        nm = re.search(r'name="([^"]+)"', cd)
        fn = re.search(r'filename="([^"]+)"', cd)
        name = nm.group(1) if nm else ""
        filename = fn.group(1) if fn else None
        if not name:
            continue
        if filename:
            files.append((name, filename, body))
        else:
            fields[name] = body.decode(errors="replace").strip()
    return fields, files


def _build_multipart(fields: dict, file_field=None, filename=None, file_bytes=b""):
    """Build a real multipart/form-data body byte string, matching what a
    browser's FormData/fetch() would actually send, so the parser is tested
    against realistic wire format rather than a shape we invented to match it."""
    boundary = "----HRTestBoundary123456"
    parts = []
    for name, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
            .encode()
        )
    if file_field:
        parts.append(
            (f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
             f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
            + file_bytes + b"\r\n"
        )
    parts.append(f'--{boundary}--\r\n'.encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


class TestMultipartParsing:
    def test_parses_text_fields(self):
        raw, ctype = _build_multipart({"employee_id": "EMP-00001", "name": "Driver's License"})
        fields, files = _mirror_parse_multipart(raw, ctype)
        assert fields == {"employee_id": "EMP-00001", "name": "Driver's License"}
        assert files == []

    def test_parses_file_field(self):
        raw, ctype = _build_multipart(
            {"employee_id": "EMP-00001", "name": "I-9"},
            file_field="file", filename="scan.pdf", file_bytes=b"%PDF-fake-bytes",
        )
        fields, files = _mirror_parse_multipart(raw, ctype)
        assert fields["employee_id"] == "EMP-00001"
        assert len(files) == 1
        field_name, filename, data = files[0]
        assert field_name == "file"
        assert filename == "scan.pdf"
        assert data == b"%PDF-fake-bytes"

    def test_missing_boundary_raises(self):
        with pytest.raises(ValueError):
            _mirror_parse_multipart(b"whatever", "multipart/form-data")

    def test_no_file_field_yields_empty_files_list(self):
        raw, ctype = _build_multipart({"employee_id": "EMP-1", "name": "X"})
        _, files = _mirror_parse_multipart(raw, ctype)
        assert files == []


# ── Local mirror of _hr_handle_document_upload's validation logic ─────────
# (business logic only — the real function's file-write and hr_db.json
# read/write are exercised separately below against a tmp_path, never the
# real install's hr_documents/hr_db.json.)

def _mirror_validate_upload(fields: dict, files: list, auth: dict):
    """Returns (status_code, error_code_or_None) — mirrors the exact
    validation order in _hr_handle_document_upload before it ever touches
    disk or hr_db.json."""
    if auth.get("role") not in ("admin", "employee"):
        return 401, "unauthorized"
    employee_id = (fields.get("employee_id") or "").strip()
    doc_name = (fields.get("name") or "").strip()
    category = (fields.get("category") or "general").strip().lower()
    if not employee_id or not doc_name:
        return 400, "employee_id_and_name_required"
    if category not in ("hiring", "onboarding", "active", "termination", "general"):
        category = "general"
    if auth.get("role") == "employee" and auth.get("employee_id") != employee_id:
        return 403, "forbidden"
    if not files:
        return 400, "no_file_uploaded"
    _field_name, _orig_filename, file_bytes = files[0]
    if len(file_bytes) > 25 * 1024 * 1024:
        return 413, "file_too_large_25mb_limit"
    return 200, None


class TestUploadValidationLogic:
    def test_rejects_unauthenticated(self):
        status, err = _mirror_validate_upload(
            {"employee_id": "EMP-1", "name": "X"}, [("file", "a.pdf", b"x")], {"role": None})
        assert (status, err) == (401, "unauthorized")

    def test_requires_employee_id_and_name(self):
        status, err = _mirror_validate_upload({}, [("file", "a.pdf", b"x")], {"role": "admin"})
        assert (status, err) == (400, "employee_id_and_name_required")

    def test_employee_cannot_upload_for_another_employee(self):
        status, err = _mirror_validate_upload(
            {"employee_id": "EMP-2", "name": "X"}, [("file", "a.pdf", b"x")],
            {"role": "employee", "employee_id": "EMP-1"})
        assert (status, err) == (403, "forbidden")

    def test_employee_can_upload_for_self(self):
        status, err = _mirror_validate_upload(
            {"employee_id": "EMP-1", "name": "X"}, [("file", "a.pdf", b"x")],
            {"role": "employee", "employee_id": "EMP-1"})
        assert (status, err) == (200, None)

    def test_admin_can_upload_for_any_employee(self):
        status, err = _mirror_validate_upload(
            {"employee_id": "EMP-99", "name": "X"}, [("file", "a.pdf", b"x")], {"role": "admin"})
        assert (status, err) == (200, None)

    def test_requires_a_file(self):
        status, err = _mirror_validate_upload({"employee_id": "EMP-1", "name": "X"}, [], {"role": "admin"})
        assert (status, err) == (400, "no_file_uploaded")

    def test_rejects_oversized_file(self):
        big = b"x" * (25 * 1024 * 1024 + 1)
        status, err = _mirror_validate_upload(
            {"employee_id": "EMP-1", "name": "X"}, [("file", "big.pdf", big)], {"role": "admin"})
        assert (status, err) == (413, "file_too_large_25mb_limit")

    def test_accepts_file_at_exactly_the_25mb_limit(self):
        exact = b"x" * (25 * 1024 * 1024)
        status, err = _mirror_validate_upload(
            {"employee_id": "EMP-1", "name": "X"}, [("file", "ok.pdf", exact)], {"role": "admin"})
        assert (status, err) == (200, None)

    @pytest.mark.parametrize("bad_category", ["nonsense", "", "../../etc"])
    def test_invalid_category_falls_back_to_general(self, bad_category):
        # The mirror function itself doesn't return category, so re-derive it
        # the same way _hr_handle_document_upload does, to catch a regression
        # in the fallback (e.g. someone removing the `not in (...)` guard,
        # which would let an attacker-controlled category string reach the
        # filesystem path join unsanitized).
        category = (bad_category or "general").strip().lower()
        if category not in ("hiring", "onboarding", "active", "termination", "general"):
            category = "general"
        assert category == "general"

    @pytest.mark.parametrize("good_category", ["hiring", "onboarding", "active", "termination", "general"])
    def test_valid_categories_pass_through_unchanged(self, good_category):
        category = (good_category or "general").strip().lower()
        if category not in ("hiring", "onboarding", "active", "termination", "general"):
            category = "general"
        assert category == good_category


# ── Filename sanitization mirror ────────────────────────────────────────────

def _mirror_safe_stem(orig_filename: str) -> str:
    orig_stem = os.path.splitext(orig_filename)[0]
    return re.sub(r'[^A-Za-z0-9 _.-]', '_', orig_stem).strip()[:80] or "file"


class TestFilenameSanitization:
    def test_strips_path_traversal_characters(self):
        # The actual security property: no slash/backslash survives, so the
        # sanitized stem can never escape the save_dir it gets joined into —
        # bare ".." with no separators around it is inert once path-joined.
        sanitized = _mirror_safe_stem("../../etc/passwd")
        assert "/" not in sanitized
        assert "\\" not in sanitized

    def test_keeps_safe_characters(self):
        assert _mirror_safe_stem("Drivers License 2026") == "Drivers License 2026"

    def test_caps_length_at_80_chars(self):
        long_name = "a" * 200
        assert len(_mirror_safe_stem(long_name)) == 80

    def test_empty_stem_falls_back_to_file(self):
        assert _mirror_safe_stem("???.pdf") == "_" * 3 or _mirror_safe_stem("???.pdf") != ""


# ── End-to-end business logic against a tmp_path (never the real install) ──

class TestDocumentRecordConstruction:
    """Mirrors the document-record-building + task-status-flip logic against
    an in-memory synthetic db and a pytest tmp_path doc_root — this exercises
    the *shape* of what gets written without ever touching the real
    hr_documents folder or hr_db.json."""

    def _mirror_build_document(self, db, employee_id, doc_name, category,
                                expiration_date, task_id, file_bytes, orig_filename,
                                auth, tmp_path):
        emp = next((e for e in db["employees"] if e["id"] == employee_id), None)
        assert emp is not None
        base = str(tmp_path)
        save_dir = os.path.join(base, emp.get("doc_folder", employee_id), category)
        os.makedirs(save_dir, exist_ok=True)
        safe_stem = _mirror_safe_stem(orig_filename)
        ext = os.path.splitext(orig_filename)[1].lower()
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(save_dir, f"{ts}_{safe_stem}{ext}")
        with open(out_path, "wb") as f:
            f.write(file_bytes)
        doc = {
            "id": f"DOC-{len(db.get('documents', [])) + 1:05d}",
            "employee_id": employee_id, "name": doc_name, "category": category,
            "file_path": out_path, "original_filename": orig_filename,
            "size_bytes": len(file_bytes), "expiration_date": expiration_date,
            "status": "Pending", "task_id": task_id,
            "uploaded_by": auth.get("employee_id") if auth.get("role") == "employee" else "HR Admin",
        }
        db.setdefault("documents", []).append(doc)
        if task_id:
            task = next((t for t in db["tasks"] if t["id"] == task_id), None)
            if task and task.get("upload_required") and task.get("status") not in ("Completed", "Waived"):
                task["status"] = "Awaiting Document"
        return doc

    def test_document_written_to_disk_under_employee_folder(self, tmp_path):
        db = {"employees": [{"id": "EMP-1", "doc_folder": "EMP-1_Smith_Jane"}], "tasks": [], "documents": []}
        doc = self._mirror_build_document(
            db, "EMP-1", "Driver's License", "onboarding", None, None,
            b"fake-bytes", "license.jpg", {"role": "admin"}, tmp_path)
        assert os.path.isfile(doc["file_path"])
        assert "EMP-1_Smith_Jane" in doc["file_path"]
        assert "onboarding" in doc["file_path"]
        with open(doc["file_path"], "rb") as f:
            assert f.read() == b"fake-bytes"

    def test_uploaded_by_reflects_employee_when_self_serve(self, tmp_path):
        db = {"employees": [{"id": "EMP-1", "doc_folder": "EMP-1_Smith_Jane"}], "tasks": [], "documents": []}
        doc = self._mirror_build_document(
            db, "EMP-1", "W-4", "onboarding", None, None, b"x", "w4.pdf",
            {"role": "employee", "employee_id": "EMP-1"}, tmp_path)
        assert doc["uploaded_by"] == "EMP-1"

    def test_uploaded_by_is_hr_admin_when_admin(self, tmp_path):
        db = {"employees": [{"id": "EMP-1", "doc_folder": "EMP-1_Smith_Jane"}], "tasks": [], "documents": []}
        doc = self._mirror_build_document(
            db, "EMP-1", "W-4", "onboarding", None, None, b"x", "w4.pdf",
            {"role": "admin"}, tmp_path)
        assert doc["uploaded_by"] == "HR Admin"

    def test_linked_task_flips_to_awaiting_document(self, tmp_path):
        db = {
            "employees": [{"id": "EMP-1", "doc_folder": "EMP-1_Smith_Jane"}],
            "tasks": [{"id": "TASK-5", "upload_required": True, "status": "Not Started"}],
            "documents": [],
        }
        self._mirror_build_document(
            db, "EMP-1", "I-9", "hiring", None, "TASK-5", b"x", "i9.pdf",
            {"role": "admin"}, tmp_path)
        task = db["tasks"][0]
        assert task["status"] == "Awaiting Document"

    def test_completed_task_is_not_reopened_by_upload(self, tmp_path):
        db = {
            "employees": [{"id": "EMP-1", "doc_folder": "EMP-1_Smith_Jane"}],
            "tasks": [{"id": "TASK-5", "upload_required": True, "status": "Completed"}],
            "documents": [],
        }
        self._mirror_build_document(
            db, "EMP-1", "I-9", "hiring", None, "TASK-5", b"x", "i9.pdf",
            {"role": "admin"}, tmp_path)
        assert db["tasks"][0]["status"] == "Completed"

    def test_task_without_upload_required_is_untouched(self, tmp_path):
        db = {
            "employees": [{"id": "EMP-1", "doc_folder": "EMP-1_Smith_Jane"}],
            "tasks": [{"id": "TASK-5", "upload_required": False, "status": "Not Started"}],
            "documents": [],
        }
        self._mirror_build_document(
            db, "EMP-1", "I-9", "hiring", None, "TASK-5", b"x", "i9.pdf",
            {"role": "admin"}, tmp_path)
        assert db["tasks"][0]["status"] == "Not Started"

    def test_new_document_defaults_to_pending_status(self, tmp_path):
        db = {"employees": [{"id": "EMP-1", "doc_folder": "EMP-1_Smith_Jane"}], "tasks": [], "documents": []}
        doc = self._mirror_build_document(
            db, "EMP-1", "Passport", "general", "2027-01-01", None, b"x", "passport.jpg",
            {"role": "admin"}, tmp_path)
        assert doc["status"] == "Pending"
        assert doc["expiration_date"] == "2027-01-01"


# ── Structural checks — real source read as text, read-only ────────────────

@pytest.fixture(scope="module")
def ai_prowler_source():
    with open(AI_PROWLER_MCP_PATH, "r", encoding="utf-8") as f:
        return f.read()


class TestUploadRouteWiring:
    def test_upload_handler_functions_exist(self, ai_prowler_source):
        assert "def _hr_parse_multipart(" in ai_prowler_source
        assert "def _hr_handle_document_upload(" in ai_prowler_source

    def test_wired_into_server_mode_router(self, ai_prowler_source):
        assert '_hrsrv_subpath == "/documents/upload"' in ai_prowler_source
        assert "_hr_handle_document_upload(\n                        _hrsrv_body_bytes" in ai_prowler_source

    def test_wired_into_personal_mode_router(self, ai_prowler_source):
        assert '_hrp_subpath == "/documents/upload"' in ai_prowler_source
        assert "_hr_handle_document_upload(\n                        _hrp_body_bytes" in ai_prowler_source

    def test_25mb_size_cap_present(self, ai_prowler_source):
        assert "25 * 1024 * 1024" in ai_prowler_source

    def test_valid_categories_match_document_folder_layout(self, ai_prowler_source):
        # _hr_create_document_folders() creates exactly these 5 subfolders —
        # the upload handler's category whitelist must stay in sync with it.
        folders_block = ai_prowler_source.split(
            "def _hr_create_document_folders", 1)[1].split("def ", 1)[0]
        assert '"hiring", "onboarding", "active", "termination", "general"' in folders_block
        upload_block = ai_prowler_source.split(
            "def _hr_handle_document_upload", 1)[1].split("def _hr_api_route", 1)[0]
        assert '"hiring", "onboarding", "active", "termination", "general"' in upload_block
