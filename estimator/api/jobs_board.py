"""The Jobs board for all lanes (Coder 2 Sprint 10; spec: "a Jobs board shows every job by lane and stage with the
Director's next step and who it's waiting on").

The Director's board (est_jobs_board) gives each job's lane, step and who it's waiting on. For the standard and full
takeoff lanes that isn't enough to see where a job stands, so each job on the web board also gets its progress from
what's already in estimator.db - a few grouped queries for the whole board, never one per job:
  plans       plan sets read / being read / failed, sheets, sheets that need a scale
  symbols     symbols found from the legend, and how many to check
  takeoff     measurements approved / waiting for approval / with a suggested change
  runner      the latest Estimate Runner run: trade tasks done / needing review / failed
  reviews     reviews in progress
Read-only; nothing here changes a job.
"""
from __future__ import annotations

def _stages(lane: str | None) -> list[tuple[str, str]]:
    """[(stage id, label)] in the lane's playbook order."""
    from estimator.director import playbooks
    if not lane:
        return []
    try:
        return [(s.id, s.label) for s in playbooks.playbook_for_lane(lane).stages]
    except Exception:  # noqa: BLE001 - no playbook, no step numbers
        return []


def _in(ids) -> str:
    return ",".join("?" for _ in ids)


def progress(conn, ctx, jobs: list[dict]) -> dict[int, dict]:
    """{job id: progress} for the jobs on the board (only jobs with an estimate get anything)."""
    eids = sorted({j["estimate_id"] for j in jobs if j.get("estimate_id")})
    if not eids:
        return _steps_only(jobs)
    company = ctx.company_id
    per: dict[int, dict] = {e: {} for e in eids}

    for r in conn.execute(
            f"SELECT p.estimate_id, p.status, COUNT(DISTINCT p.id) AS n, COUNT(s.id) AS sheets FROM plan_sets p"
            f" LEFT JOIN sheets s ON s.plan_set_id = p.id WHERE p.company_id = ? AND p.estimate_id IN ({_in(eids)})"
            f" GROUP BY p.estimate_id, p.status", (company, *eids)):
        pl = per[r["estimate_id"]].setdefault("plans", {"plan_sets": 0, "processed": 0, "processing": 0, "failed": 0,
                                                         "uploaded": 0, "sheets": 0, "need_scale": 0})
        pl["plan_sets"] += r["n"]
        pl[r["status"]] = pl.get(r["status"], 0) + r["n"]
        pl["sheets"] += r["sheets"]
    for r in conn.execute(
            f"SELECT p.estimate_id, COUNT(DISTINCT s.id) AS n FROM plan_sets p JOIN sheets s ON s.plan_set_id = p.id"
            f" JOIN viewports v ON v.sheet_id = s.id WHERE p.company_id = ? AND p.estimate_id IN ({_in(eids)})"
            f" AND s.units = 'paper_in' AND v.scale_ratio IS NULL AND v.is_nts = 0 GROUP BY p.estimate_id",
            (company, *eids)):
        if "plans" in per[r["estimate_id"]]:
            per[r["estimate_id"]]["plans"]["need_scale"] = r["n"]

    for r in conn.execute(
            f"SELECT p.estimate_id, COUNT(d.id) AS n, SUM(d.needs_review) AS check_n,"
            f" SUM(CASE WHEN d.status = 'approved' THEN 1 ELSE 0 END) AS approved FROM symbol_detections d"
            f" JOIN plan_sets p ON p.id = d.plan_set_id WHERE d.company_id = ? AND p.estimate_id IN ({_in(eids)})"
            f" GROUP BY p.estimate_id", (company, *eids)):
        per[r["estimate_id"]]["symbols"] = {"found": r["n"], "to_check": r["check_n"] or 0, "approved": r["approved"] or 0}

    for r in conn.execute(
            f"SELECT estimate_id, status, COUNT(*) AS n, SUM(CASE WHEN suggested_qty IS NOT NULL THEN 1 ELSE 0 END) AS sug"
            f" FROM measurements WHERE company_id = ? AND estimate_id IN ({_in(eids)}) GROUP BY estimate_id, status",
            (company, *eids)):
        t = per[r["estimate_id"]].setdefault("takeoff", {"approved": 0, "proposed": 0, "rejected": 0, "suggested": 0})
        t[r["status"]] = r["n"]
        t["suggested"] += r["sug"] or 0

    latest = {r["estimate_id"]: r for r in conn.execute(
        f"SELECT r.estimate_id, r.id, r.state FROM runs r WHERE r.company_id = ? AND r.estimate_id IN ({_in(eids)})"
        f" AND r.id = (SELECT MAX(id) FROM runs x WHERE x.estimate_id = r.estimate_id AND x.company_id = r.company_id)",
        (company, *eids))}
    if latest:
        run_ids = [r["id"] for r in latest.values()]
        tasks: dict[int, dict] = {}
        for r in conn.execute(f"SELECT run_id, state, COUNT(*) AS n FROM takeoff_tasks WHERE run_id IN ({_in(run_ids)})"
                              f" GROUP BY run_id, state", run_ids):
            tasks.setdefault(r["run_id"], {})[r["state"]] = r["n"]
        for eid, r in latest.items():
            t = tasks.get(r["id"], {})
            per[eid]["runner"] = {"run_id": r["id"], "state": r["state"], "trades": sum(t.values()),
                                  "completed": t.get("completed", 0), "needs_review": t.get("needs_review", 0),
                                  "failed": t.get("failed", 0), "blocked": t.get("blocked", 0)}

    for r in conn.execute(
            f"SELECT estimate_id, COUNT(*) AS n FROM reviews WHERE company_id = ? AND status = 'in_review'"
            f" AND estimate_id IN ({_in(eids)}) GROUP BY estimate_id", (company, *eids)):
        per[r["estimate_id"]]["reviews"] = {"in_review": r["n"]}

    return _steps_only(jobs, per)


def _steps_only(jobs, per=None) -> dict[int, dict]:
    out, cache = {}, {}
    for j in jobs:
        p = dict((per or {}).get(j.get("estimate_id"), {}))
        lane = j.get("lane")
        if lane not in cache:
            cache[lane] = _stages(lane)
        ids = [s for s, _ in cache[lane]]
        if j.get("stage") in ids:
            i = ids.index(j["stage"])
            p["step"] = {"number": i + 1, "of": len(ids), "label": cache[lane][i][1],
                         "next": cache[lane][i + 1][1] if i + 1 < len(ids) else None}
        if p:
            out[j["id"]] = p
    return out


def summary(jobs: list[dict], user_id: str | None) -> dict:
    """Counts across the board: by lane, and how many wait on a person or on the customer."""
    lanes: dict[str, int] = {}
    waiting = {"you": 0, "customer": 0, "others": 0}
    for j in jobs:
        lanes[j.get("lane") or "needs_triage"] = lanes.get(j.get("lane") or "needs_triage", 0) + 1
        w = j.get("waiting_on")
        if j.get("state") in ("done", "cancelled") or not w:
            continue
        if w == "customer":
            waiting["customer"] += 1
        elif w == "user" and (not j.get("assigned_to") or j.get("assigned_to") == user_id):
            waiting["you"] += 1
        else:
            waiting["others"] += 1
    return {"by_lane": lanes, "waiting": waiting}
