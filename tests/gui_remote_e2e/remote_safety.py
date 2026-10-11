"""Write guard for the Remote PWA E2E suite (REMOTE_PWA_E2E_TEST_SPEC.md §3).

Every /remote-api call and /remote/upload from the browser, and every setup /
cleanup call, is classified here before it may reach the live personal install:

  read     -> allowed
  create   -> allowed only for ZTEST-named learnings / tasks; new id registered
  scoped   -> allowed only for ids this run registered, or the sandbox folder
  record   -> never sent; a canned reply is returned (queueing a task could make
              the Autonomous Task Queue really run it and spend AI credits)
  unknown  -> blocked (fails the test)
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

ZTEST = "ZTEST E2E"
ZTEST_FILE_PREFIX = "ZTEST_E2E_"
# The sandbox is its OWN tracked folder, OUTSIDE every writable folder (moved
# 2026-09-29 with David's OK): inside a writable parent it could never be
# read-only (RM-R-007), so the grant / revoke / "no Upload when read-only" tests
# couldn't run. Only ZTEST_E2E_* files are ever written here.
SANDBOX = Path(r"C:\Users\david\AI-Prowler-E2E-Remote-Sandbox")
# Access-Only Folders tests (2026-10-09): the ONLY folder grant_access /
# revoke_access may touch (and, for its write switch, grant/revoke_write_access).
# 2026-10-10 (with David's OK): its own top-level folder next to the Remote
# sandbox — OUTSIDE every tracked AND every writable folder, so an upload into
# it is a true access-only upload (saved, never indexed) and its write switch
# really is its own (inside the writable work copy it was always "writable via
# parent" — R-088). The run takes it off the access-only and writable lists
# and deletes it.
AO_SANDBOX = Path(r"C:\Users\david\AI-Prowler-E2E-Remote-AccessOnly")

READ = {
    "check_ai_prowler_status", "list_indexed_directories", "list_indexed_documents",
    "list_directory", "read_file_lines", "search_documents", "list_learnings",
    "search_learnings", "get_learning_stats", "get_database_stats",
    "list_tracked_directories", "list_writable_directories", "list_analysis_tasks",
    "get_pending_analysis_tasks", "get_all_queued_tasks",
    "get_learning",                    # 2026-10-11: the Learn tab's Edit form (read-only)
}
CREATE = {"record_learning": "title", "create_analysis_task": "label"}
SCOPED_ID = {"delete_learning": "learning_id", "update_learning": "learning_id",
             "delete_analysis_task": "task_id", "update_analysis_task": "task_id"}
SCOPED_DIR = {"grant_write_access", "revoke_write_access"}
SCOPED_AO_DIR = {"grant_access", "revoke_access"}        # access-only list: AO_SANDBOX only
RECORD = {"queue_single_task", "sync_due_tasks_to_queue", "complete_analysis_task"}

ID_PATTERNS = [re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
               re.compile(r"\b(?:custom|task|analyze)_[A-Za-z0-9_\-]+\b")]


def _norm_dir(p) -> str:
    return os.path.normcase(os.path.normpath(str(p or "").strip().strip('"'))).rstrip("\\/")


def is_sandbox(p) -> bool:
    return bool(p) and _norm_dir(p) == _norm_dir(SANDBOX)


def is_ao_sandbox(p) -> bool:
    return bool(p) and _norm_dir(p) == _norm_dir(AO_SANDBOX)


def _inside(p, root) -> bool:
    n, r = _norm_dir(p), _norm_dir(root)
    return bool(p) and (n == r or n.startswith(r + "\\"))


def is_ao_rules_path(p) -> bool:
    """grant_access / revoke_access targets the ADD-rule tests may use
    (2026-10-10): the access-only test folder or anything inside it, or a
    ZTEST_E2E_* path inside the Remote sandbox (an indexed folder — the server
    must REFUSE it as access-only)."""
    if _inside(p, AO_SANDBOX):
        return True
    return _inside(p, SANDBOX) and "ZTEST_E2E_" in str(p)


def parse_tracked_sections(text: str) -> dict:
    """list_tracked_directories → {"tracked": [paths], "access_only": [paths],
    "has_access_only_section": bool}. Lines look like "  1. [W] 📁 C:\\path"."""
    out = {"tracked": [], "access_only": [], "has_access_only_section": False}
    cur = out["tracked"]
    for raw in str(text or "").splitlines():
        line = "".join(c for c in raw if 32 <= ord(c) < 127).strip()
        if line.lower().startswith("access-only folders"):
            cur, out["has_access_only_section"] = out["access_only"], True
            continue
        if line.lower().startswith("indexed directories"):
            cur = out["tracked"]
            continue
        m = re.match(r"^\d+\.\s*(?:\[(?:W|R|W\*)\]\s*)?(.+)$", line)
        if m and re.search(r"[:\\/]", m.group(1)):
            cur.append(m.group(1).strip())
    return out


def canned_reply(tool: str, why: str) -> dict:
    return {"ok": True, "result": f"✅ [E2E guard — not sent] {tool}: {why}"}


class RemoteGuard:
    def __init__(self, log=print):
        self.log = log
        self.registered: set[str] = set()
        self.recorded: list[dict] = []
        self.violations: list[dict] = []
        self.allowed_count = 0
        self._lock = threading.Lock()

    def register(self, ident: str, why: str = ""):
        if ident:
            with self._lock:
                self.registered.add(str(ident))
            self.log(f"guard: registered {ident} {why}".rstrip())

    def note_result(self, tool: str, result: str):
        """After an allowed create, register every id the server handed back."""
        if tool in CREATE:
            for pat in ID_PATTERNS:
                for m in pat.findall(str(result or "")):
                    self.register(m, f"(from {tool})")

    def check(self, tool: str, args: dict | None) -> tuple[str, str]:
        a = args or {}
        if tool in READ:
            return "allow", "read"
        if tool in CREATE:
            name = str(a.get(CREATE[tool], ""))
            return (("allow", "ZTEST item") if name.startswith(ZTEST)
                    else ("block", f"{tool} of a non-ZTEST item ({name[:40]!r})"))
        if tool in SCOPED_ID:
            ident = str(a.get(SCOPED_ID[tool], ""))
            return (("allow", f"this run's {ident}") if ident in self.registered
                    else ("block", f"{tool} on {ident!r}, which this run didn't create"))
        if tool in SCOPED_DIR:
            d = a.get("directory", "")
            if is_ao_sandbox(d):
                return ("allow", "access-only test folder")
            return (("allow", "sandbox folder") if is_sandbox(d)
                    else ("block", f"{tool} outside the sandbox ({d!r})"))
        if tool in SCOPED_AO_DIR:
            d = a.get("directory", "")
            return (("allow", "access-only test folder") if is_ao_rules_path(d)
                    else ("block", f"{tool} on {d!r} — only {AO_SANDBOX} (and inside it) may be added/removed"))
        if tool in RECORD:
            return "record", "never sent in E2E runs (could start a real AI task run)"
        return "block", f"unclassified tool {tool!r}"

    def check_upload(self, body: dict) -> tuple[str, str]:
        d, name = body.get("dir", ""), str(body.get("filename", ""))
        # 2026-10-10: the access-only test folder too (AO-10), nothing else
        if not (is_sandbox(d) or is_ao_sandbox(d)):
            return "block", f"upload outside the sandbox ({d!r})"
        if not name.startswith(ZTEST_FILE_PREFIX):
            return "block", f"upload of a non-ZTEST file name ({name!r})"
        return "allow", ("ZTEST file into the access-only test folder" if is_ao_sandbox(d)
                         else "ZTEST file into the sandbox")

    def enforce(self, tool: str, args: dict | None, source: str, decision=None) -> tuple[str, str]:
        decision, why = decision or self.check(tool, args)
        entry = {"source": source, "tool": tool,
                 "args": {k: v for k, v in (args or {}).items() if k not in ("token", "file_data")},
                 "decision": decision, "reason": why}
        with self._lock:
            if decision == "record":
                self.recorded.append(entry)
            elif decision == "block":
                self.violations.append(entry)
            else:
                self.allowed_count += 1
        self.log(f"guard[{source}]: {decision.upper():6} {tool} — {why}")
        return decision, why

    def take_violations(self) -> list[dict]:
        with self._lock:
            v, self.violations = self.violations, []
        return v
