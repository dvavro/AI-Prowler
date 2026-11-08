"""Plan files uploaded from the browser wait here until the user confirms them (Coder 2, Sprint 2).

Jamie's store.upload() checks a file on this PC and asks first (confirm=true). A browser can't hand over a
path, so the web app streams the file to disk here, runs the same checks with confirm=false to show the user
what will be attached, and only on "Attach" calls store.upload(confirm=true) on the staged copy. The staged
copy is then deleted (store.upload makes its own copy in projects\\estimate_NNNN\\plans\\).

- Files go to <data folder>\\cache\\web_uploads\\<stage id>\\<safe name>. cache\\ is "safe to delete" in the
  spec and is never indexed.
- A stage belongs to the user, company and estimate that made it; nobody else can attach or cancel it.
- Stages are forgotten after STAGE_TTL_SECONDS, and leftover folders (e.g. after a restart) are swept.
"""
from __future__ import annotations

import re
import secrets
import shutil
import threading
import time
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.errors import NotFound

STAGE_TTL_SECONDS = 60 * 60
CHUNK = 1024 * 1024
_SAFE = re.compile(r"[^A-Za-z0-9 _.()-]+")

_lock = threading.Lock()
_stages: dict[str, dict] = {}
_clock = time.time            # tests replace this (never the global time.time)


def root() -> Path:
    return config.data_dir() / "cache" / "web_uploads"


def safe_name(name: str) -> str:
    """The user's file name, made safe for the disk: no folders, no odd characters, extension kept."""
    base = Path(str(name or "").replace("\\", "/")).name
    p = Path(base)
    stem = _SAFE.sub("_", p.stem).strip(" ._")[:80] or "plans"
    suffix = _SAFE.sub("", p.suffix.lower())[:10]
    return stem + suffix


def new(ctx: RequestContext, estimate_id: int, name: str) -> tuple[str, Path]:
    sweep()
    stage_id = secrets.token_urlsafe(16)
    folder = (root() / stage_id).resolve()          # plan_upload's checks need a full path
    folder.mkdir(parents=True, exist_ok=False)
    path = folder / safe_name(name)
    with _lock:
        _stages[stage_id] = {"path": path, "estimate_id": int(estimate_id), "company_id": ctx.company_id,
                             "user_id": ctx.user_id, "created": _clock()}
    return stage_id, path


def receive(stream, length: int, path: Path) -> int:
    """Copy exactly `length` bytes from stream to path. Returns the number of bytes written."""
    got = 0
    with open(path, "wb") as f:
        while got < length:
            block = stream.read(min(CHUNK, length - got))
            if not block:
                break
            f.write(block)
            got += len(block)
    return got


def get(stage_id: str, ctx: RequestContext, estimate_id: int) -> Path:
    with _lock:
        s = _stages.get(str(stage_id or ""))
    if (s is None or s["company_id"] != ctx.company_id or s["user_id"] != ctx.user_id
            or s["estimate_id"] != int(estimate_id) or _clock() - s["created"] > STAGE_TTL_SECONDS
            or not s["path"].is_file()):
        raise NotFound("that upload has expired or isn't yours; please choose the file again")
    return s["path"]


def drop(stage_id: str) -> None:
    with _lock:
        _stages.pop(str(stage_id or ""), None)
    if stage_id and re.fullmatch(r"[A-Za-z0-9_-]+", str(stage_id)):
        shutil.rmtree(root() / str(stage_id), ignore_errors=True)


def sweep(now: float | None = None) -> int:
    """Forget expired stages and remove folders nobody is waiting on. Returns how many were removed."""
    now = _clock() if now is None else now
    with _lock:
        expired = [k for k, s in _stages.items() if now - s["created"] > STAGE_TTL_SECONDS]
        for k in expired:
            _stages.pop(k, None)
        live = set(_stages)
    removed = 0
    base = root()
    if base.is_dir():
        for d in base.iterdir():
            if d.name in live:
                continue
            try:
                old = now - d.stat().st_mtime > STAGE_TTL_SECONDS
            except OSError:
                continue
            if old or d.name in expired:
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
    return removed


def count() -> int:
    with _lock:
        return len(_stages)


def reset() -> None:
    """Tests: forget every stage (files are in the test's throwaway folder)."""
    with _lock:
        _stages.clear()
