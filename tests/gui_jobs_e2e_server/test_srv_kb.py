"""Server mode — SRV-KB: knowledge-base scopes vs. the Jobs app.

SRV-KB-01  Job data is NOT filtered by knowledge-base scope. Each user's real
           scopes are read from /whoami (it accepts a Jobs app session); the
           jobs each user sees must follow the crew rule only (owner/manager:
           every crew's ZTEST job; field crew: their own), whatever the scopes.
SRV-KB-02  The Jobs app never offers document-search tools: every KB tool
           answers "Unknown tool" from /pwa-api for every role, and the app's
           own page never calls one.
SRV-KB-03  (G-13, closed by design 2026-09-28) Learnings are company-wide: field
           crew can read learnings recorded by anyone. Guards that decision.
           Logs counts only, never learning content.

Read-only apart from two ZTEST jobs (created and removed by the owner).
Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_kb
"""
import json
import logging
import re

import pytest

from api import http

log = logging.getLogger("e2e_srv")

ROLE = {"U1": "owner", "U2": "manager", "U3": "field_crew"}
CREW = "Samual Cronin"
OTHER = "Vicki Vavro"

# Every knowledge-base (document) tool the MCP server has. None may be reachable
# from the Jobs app (spec §6.11.1: the /pwa-api allow-list has no KB tools).
KB_TOOLS = [
    "search_documents", "multi_query_search", "read_document", "expand_search_result",
    "list_indexed_documents", "list_indexed_directories", "search_within_directory",
    "get_knowledge_base_overview", "grep_documents", "index_path", "reindex_file",
    "reindex_directory", "reindex_all", "list_tracked_directories",
]


def _post(srv, key, tool, args):
    st, raw = http("POST", srv["origin"] + "/pwa-api", {"tool": tool, "args": args},
                   token=srv["users"][key].access_token, timeout=60)
    try:
        d = json.loads(raw)
    except ValueError:
        return st, {"ok": False, "error": raw[:200]}
    return st, d


def _whoami(srv, key):
    st, raw = http("GET", srv["origin"] + "/whoami", token=srv["users"][key].access_token, timeout=30)
    assert st == 200, f"/whoami for {key} -> HTTP {st}: {raw[:200]}"
    return json.loads(raw)


# ── SRV-KB-01 ─────────────────────────────────────────────────────────────────
@pytest.fixture
def two_jobs(clean_slate, data):
    return {"mine": data.job("KB mine", **{"Crew / Technician": CREW}),
            "theirs": data.job("KB theirs", "brannon", **{"Crew / Technician": OTHER})}


def test_SRV_KB_01_job_data_ignores_kb_scope(srv, api_as, two_jobs):
    scopes = {}
    for key in ("U1", "U2", "U3"):
        who = _whoami(srv, key)
        assert who.get("role") == ROLE[key], f"/whoami role for {key}: {who.get('role')!r}"
        scopes[key] = set(who.get("allowed_scopes") or [])
    log.info("[SRV-KB-01] scopes: " + " | ".join(f"{ROLE[k]}={sorted(v)}" for k, v in scopes.items()))
    if len({frozenset(v) for v in scopes.values()}) == 1:
        log.warning("[SRV-KB-01] all three users have the SAME scopes — this run can't show that a "
                    "narrower scope leaves jobs alone; give one user a different scope to make it bite")

    want = {"U1": {two_jobs["mine"], two_jobs["theirs"]},
            "U2": {two_jobs["mine"], two_jobs["theirs"]},
            "U3": {two_jobs["mine"]}}
    for key in ("U1", "U2", "U3"):
        seen = {r.get("JobID (JOB-####)") for r in api_as(key).read("Jobs_Schedule")}
        got = seen & {two_jobs["mine"], two_jobs["theirs"]}
        log.info(f"[SRV-KB-01] {ROLE[key]} sees {sorted(got)} (expected {sorted(want[key])})")
        assert got == want[key], (f"{ROLE[key]} (scopes {sorted(scopes[key])}) sees {sorted(got)}, "
                                  f"expected {sorted(want[key])} — job visibility must follow crew, not scope")


# ── SRV-KB-02 ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("key", ["U1", "U2", "U3"])
def test_SRV_KB_02_no_document_tools_in_jobs_app(srv, key):
    reachable = []
    for tool in KB_TOOLS:
        st, d = _post(srv, key, tool, {"query": "ZTEST", "directory": "", "filepath": ""})
        if not (st == 400 and "Unknown tool" in str(d.get("error", ""))):
            reachable.append(f"{tool} (HTTP {st}: {str(d)[:80]})")
    log.info(f"[SRV-KB-02] {ROLE[key]}: {len(KB_TOOLS) - len(reachable)}/{len(KB_TOOLS)} KB tools refused")
    assert not reachable, f"{ROLE[key]} can reach KB tools through the Jobs app: {reachable}"


def test_SRV_KB_02_app_page_never_calls_document_tools(srv):
    st, page = http("GET", srv["url"], timeout=30)
    assert st == 200 and "mcpCall" in page, f"couldn't load the Jobs app page ({srv['url']}): HTTP {st}"
    used = [t for t in KB_TOOLS if re.search(rf"['\"]{t}['\"]", page)]
    assert not used, f"the Jobs app page references KB tools: {used}"


# ── SRV-KB-03 (G-13, David 2026-09-28: keep — learnings are company-wide) ─────
def test_SRV_KB_03_learnings_are_company_wide(srv):
    me = srv["users"]["U3"].name
    others = total = 0
    for q in ("customer", "job", "photos", "price", "schedule"):
        st, d = _post(srv, "U3", "search_learnings", {"query": q, "n_results": 20})
        assert st == 200 and d.get("ok"), f"search_learnings as crew -> HTTP {st}: {str(d)[:200]}"
        for block in str(d.get("result", "")).split("───"):
            if not re.search(r"ID\s*:\s*[0-9a-f-]{36}", block):
                continue
            total += 1
            m = re.search(r"Recorded by:\s*(.+)", block)
            if not m or m.group(1).strip().lower() != me.lower():
                others += 1
    log.info(f"[SRV-KB-03] field crew's searches returned {total} learning hits, "
             f"{others} recorded by someone else (content not logged)")
    assert total and others, ("field crew no longer sees other people's learnings — learnings were "
                              "company-wide by decision (G-13); update the spec if this change is intended")
