#!/usr/bin/env python3
"""
AI-Prowler Self-Learning Engine
================================
A RAG-based self-learning system that allows Claude (and operators) to
record, retrieve, and apply learned knowledge over time.

Learnings are stored in a structured JSON file AND indexed into ChromaDB
for semantic retrieval.  This gives Claude instant access to corrections,
business lessons, project insights, and updated facts — no 30-minute
LoRA training cycle required.

Storage:
    ~/.ai-prowler/learnings/self_learning_data.json   (structured records)
    ChromaDB collection: "ai_prowler_learnings"       (semantic search)

Author: AI-Prowler project
"""

import json
import os
import uuid
import logging
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_log = logging.getLogger("ai_prowler_mcp.self_learning")


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class ChromaIndexError(RuntimeError):
    """Raised when a ChromaDB index operation fails (read/write/delete).

    Distinguishes real ChromaDB failures from missing-ID cases. Callers
    should catch this to handle ChromaDB unavailability or corruption
    gracefully without losing JSON-side state.
    """
    pass

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

LEARNINGS_DIR  = Path.home() / ".ai-prowler" / "learnings"
LEARNINGS_FILE = LEARNINGS_DIR / "self_learning_data.json"
LEARNINGS_COLLECTION = "ai_prowler_learnings"

VALID_CATEGORIES = [
    "fact_correction",       # Correcting an outdated or wrong fact
    "business_lesson",       # What worked / didn't in business context
    "project_insight",       # Lessons from a specific project
    "process_improvement",   # Better way to do something
    "mistake_learned",       # Something that went wrong and why
    "best_practice",         # Proven approach to adopt going forward
    "client_preference",     # Client-specific preferences or requirements
    "technical_note",        # Technical fact, configuration, or gotcha
    "general",               # Catch-all
]

VALID_SOURCES = [
    "operator",              # Explicitly told by the user/operator
    "claude_detected",       # Claude identified superseding information
    "project_review",        # Post-project review / retrospective
    "post_mortem",           # After-incident analysis
    "research",              # From web search or document research
    "observation",           # Noticed pattern across conversations
]

VALID_STATUSES  = ["active", "deprecated", "archived"]
VALID_OUTCOMES  = ["positive", "negative", "neutral", "unknown"]

SCHEMA_VERSION = "1.0"


# ─────────────────────────────────────────────────────────────────────────────
# Data layer — JSON file operations
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_dir():
    """Create the learnings directory if it doesn't exist."""
    LEARNINGS_DIR.mkdir(parents=True, exist_ok=True)


def _load_db() -> dict:
    """Load the learnings JSON file.  Returns empty structure if missing."""
    _ensure_dir()
    if LEARNINGS_FILE.exists():
        try:
            data = json.loads(LEARNINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "learnings" in data:
                return data
        except Exception as e:
            _log.warning("Corrupt learnings file, starting fresh: %s", e)
    return {"version": SCHEMA_VERSION, "learnings": []}


def _save_db(data: dict):
    """Atomically write the learnings JSON file."""
    _ensure_dir()
    tmp = LEARNINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    os.replace(str(tmp), str(LEARNINGS_FILE))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────────────────────
# ChromaDB integration — index learnings for semantic search
# ─────────────────────────────────────────────────────────────────────────────

def _get_learnings_collection():
    """
    Get or create the dedicated learnings collection in ChromaDB.
    Uses the same client/embedding function as the main knowledge base.
    """
    from rag_preprocessor import get_chroma_client
    client, embedding_func = get_chroma_client()
    try:
        return client.get_or_create_collection(
            name=LEARNINGS_COLLECTION,
            embedding_function=embedding_func,
        )
    except Exception as e:
        _log.error("Could not access learnings collection: %s", e)
        raise


def _build_chunk_text(learning: dict) -> str:
    """
    Build the text that gets embedded into ChromaDB for a learning.
    Combines title + content + context + tags for rich semantic matching.
    """
    parts = []
    parts.append(f"[LEARNING: {learning.get('title', 'Untitled')}]")
    parts.append(learning.get("content", ""))
    ctx = learning.get("context", "")
    if ctx:
        parts.append(f"Context: {ctx}")
    tags = learning.get("tags", [])
    if tags:
        parts.append(f"Tags: {', '.join(tags)}")
    category = learning.get("category", "general")
    parts.append(f"Category: {category}")
    outcome = learning.get("outcome", "unknown")
    if outcome != "unknown":
        parts.append(f"Outcome: {outcome}")
    return "\n".join(parts)


def _index_learning(learning: dict):
    """Add or update a single learning in the ChromaDB learnings collection."""
    try:
        collection = _get_learnings_collection()
        doc_text = _build_chunk_text(learning)
        meta = {
            "learning_id":   learning["id"],
            "title":         learning.get("title", ""),
            "category":      learning.get("category", "general"),
            "source":        learning.get("source", "operator"),
            "status":        learning.get("status", "active"),
            "confidence":    learning.get("confidence", 0.8),
            "outcome":       learning.get("outcome", "unknown"),
            "created_at":    learning.get("created_at", ""),
            "updated_at":    learning.get("updated_at", ""),
            "tags":          ",".join(learning.get("tags", [])),
            "supersedes":    learning.get("supersedes", ""),
            "superseded_by": learning.get("superseded_by", ""),
            "recorded_by":   learning.get("recorded_by", ""),
        }
        collection.upsert(
            ids=[learning["id"]],
            documents=[doc_text],
            metadatas=[meta],
        )
    except Exception as e:
        _log.warning("Failed to index learning %s: %s", learning.get("id"), e)


def _remove_from_index(learning_id: str):
    """
    Remove a learning from the ChromaDB index.

    Raises ChromaIndexError if the ChromaDB call fails for any reason
    other than the ID simply not being in the collection. The caller
    decides how to surface the error (re-raise, warn, log).

    A missing-ID delete is silently treated as success (idempotent).
    """
    try:
        collection = _get_learnings_collection()
        # ChromaDB's delete is idempotent — passing a non-existent ID is
        # not an error, it just deletes nothing. So we don't need to
        # pre-check existence.
        collection.delete(ids=[learning_id])
    except Exception as e:
        # Capture the full traceback so callers can diagnose root cause.
        # The traceback is included in the ChromaIndexError message and
        # also logged at error level. This is essential for diagnosing
        # process-specific issues (e.g. encoding errors that only surface
        # in the GUI process but not the MCP server).
        tb = traceback.format_exc()
        _log.error(
            "Failed to remove learning %s from ChromaDB index.\n"
            "Exception type : %s\n"
            "Exception repr : %r\n"
            "Full traceback :\n%s",
            learning_id, type(e).__name__, e, tb
        )
        raise ChromaIndexError(
            f"ChromaDB cleanup failed for learning {learning_id}.\n"
            f"  Exception type: {type(e).__name__}\n"
            f"  Exception repr: {e!r}\n"
            f"  Traceback:\n{tb}"
        ) from e


def reindex_all_learnings():
    """Rebuild the entire learnings ChromaDB collection from the JSON file."""
    db = _load_db()
    active = [l for l in db["learnings"] if l.get("status") != "archived"]
    try:
        collection = _get_learnings_collection()
        # Wipe and rebuild
        from rag_preprocessor import get_chroma_client
        client, _ = get_chroma_client()
        try:
            client.delete_collection(name=LEARNINGS_COLLECTION)
        except Exception:
            pass
        collection = _get_learnings_collection()
        for learning in active:
            _index_learning(learning)
        return len(active)
    except Exception as e:
        _log.error("Reindex failed: %s", e)
        raise


# ─────────────────────────────────────────────────────────────────────────────
# CRUD operations
# ─────────────────────────────────────────────────────────────────────────────

def record_learning(
    title: str,
    content: str,
    category: str = "general",
    context: str = "",
    source: str = "operator",
    confidence: float = 0.8,
    tags: list[str] | None = None,
    supersedes_id: str = "",
    outcome: str = "unknown",
    recorded_by: str = "",
) -> dict:
    """
    Record a new learning.

    Returns the created learning dict.
    """
    if category not in VALID_CATEGORIES:
        category = "general"
    if source not in VALID_SOURCES:
        source = "operator"
    if outcome not in VALID_OUTCOMES:
        outcome = "unknown"
    confidence = max(0.0, min(1.0, confidence))

    now = _now_iso()
    learning = {
        "id":             str(uuid.uuid4()),
        "title":          title.strip(),
        "content":        content.strip(),
        "category":       category,
        "context":        context.strip(),
        "source":         source,
        "confidence":     confidence,
        "tags":           [t.strip().lower() for t in (tags or [])],
        "supersedes":     supersedes_id.strip(),
        "superseded_by":  "",
        "status":         "active",
        "created_at":     now,
        "updated_at":     now,
        "applied_count":  0,
        "last_applied":   None,
        "outcome":        outcome,
        # Server-mode attribution: name of the employee who recorded this.
        # Empty string in personal mode (single-user install).
        "recorded_by":    recorded_by.strip(),
        # IDs of other learnings the user has explicitly OK'd as
        # not-a-conflict (used by find_conflicts to suppress repeat
        # flags after user review). Stored bidirectionally.
        "dismissed_conflicts": [],
    }

    db = _load_db()

    # If this supersedes an old learning, mark the old one as deprecated
    if supersedes_id:
        for old in db["learnings"]:
            if old["id"] == supersedes_id:
                old["status"] = "deprecated"
                old["superseded_by"] = learning["id"]
                old["updated_at"] = now
                _index_learning(old)  # update its status in the index
                break

    db["learnings"].append(learning)
    _save_db(db)
    _index_learning(learning)

    return learning


def check_learned(
    query: str,
    n_results: int = 5,
    category: str = "",
    active_only: bool = True,
    track_application: bool = True,
) -> list[dict]:
    """
    Search learnings by semantic similarity.
    Returns matching learnings sorted by relevance.

    When track_application is True (default), increments the applied_count
    on each returned learning so we can see how often learnings are actually
    used in practice. Pass track_application=False from non-application
    contexts (e.g. browsing/searching from the GUI) so that simply scrolling
    through the knowledge base doesn't inflate the counter.
    """
    try:
        collection = _get_learnings_collection()
    except Exception:
        return []

    count = collection.count()
    if count == 0:
        return []

    n = min(max(1, n_results), 20)

    # Build where filter
    where_filter = None
    if active_only and category:
        where_filter = {
            "$and": [
                {"status": "active"},
                {"category": category},
            ]
        }
    elif active_only:
        where_filter = {"status": "active"}
    elif category:
        where_filter = {"category": category}

    try:
        if where_filter:
            results = collection.query(
                query_texts=[query],
                n_results=n,
                where=where_filter,
            )
        else:
            results = collection.query(
                query_texts=[query],
                n_results=n,
            )
    except Exception as e:
        _log.warning("check_learned query failed: %s", e)
        return []

    if not results["documents"] or not results["documents"][0]:
        return []

    matches = []
    now = _now_iso()
    matched_ids = set()

    for i in range(len(results["documents"][0])):
        meta = results["metadatas"][0][i]
        dist = results["distances"][0][i]
        # ChromaDB returns squared L2 distance for normalized embeddings.
        # Convert to a proper [0, 1] cosine-equivalent similarity.
        # For unit-normalized vectors: cos_sim = 1 - (squared_L2 / 2)
        # Clamp to [0, 1] to handle numerical edge cases.
        sim  = max(0.0, min(1.0, 1.0 - (float(dist) / 2.0)))

        matches.append({
            "learning_id":  meta.get("learning_id", ""),
            "title":        meta.get("title", ""),
            "category":     meta.get("category", ""),
            "source":       meta.get("source", ""),
            "status":       meta.get("status", ""),
            "confidence":   meta.get("confidence", 0.0),
            "outcome":      meta.get("outcome", "unknown"),
            "created_at":   meta.get("created_at", ""),
            "tags":         meta.get("tags", ""),
            "supersedes":   meta.get("supersedes", ""),
            "superseded_by": meta.get("superseded_by", ""),
            "recorded_by":  meta.get("recorded_by", ""),
            "content":      results["documents"][0][i],
            "similarity":   sim,
        })
        matched_ids.add(meta.get("learning_id", ""))

    # Update applied_count in the JSON file for matched learnings
    if matched_ids and track_application:
        try:
            db = _load_db()
            for learning in db["learnings"]:
                if learning["id"] in matched_ids:
                    learning["applied_count"] = learning.get("applied_count", 0) + 1
                    learning["last_applied"] = now
            _save_db(db)
        except Exception as e:
            _log.debug("Could not update applied_count: %s", e)

    return matches


def list_learnings(
    category: str = "",
    status: str = "active",
    tag: str = "",
    limit: int = 50,
) -> list[dict]:
    """List learnings with optional filters. Returns from the JSON file."""
    db = _load_db()
    results = []
    for l in db["learnings"]:
        if status and l.get("status", "active") != status:
            continue
        if category and l.get("category", "general") != category:
            continue
        if tag and tag.lower() not in [t.lower() for t in l.get("tags", [])]:
            continue
        results.append(l)
    # Sort by created_at descending (newest first)
    results.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return results[:limit]


def update_learning(
    learning_id: str,
    updates: dict,
) -> dict | None:
    """
    Update fields on an existing learning.
    Allowed fields: title, content, context, category, confidence,
                    tags, status, outcome
    Returns the updated learning or None if not found.
    """
    allowed = {"title", "content", "context", "category", "confidence",
               "tags", "status", "outcome"}
    db = _load_db()
    for learning in db["learnings"]:
        if learning["id"] == learning_id:
            for key, value in updates.items():
                if key in allowed:
                    learning[key] = value
            learning["updated_at"] = _now_iso()
            _save_db(db)
            _index_learning(learning)
            return learning
    return None


def delete_learning(learning_id: str) -> bool:
    """
    Permanently delete a learning from both JSON and ChromaDB.

    Always attempts ChromaDB cleanup, even when the JSON entry is
    already missing — this lets callers clean up orphaned ChromaDB
    entries (e.g. from a previous partial-failure delete).

    Returns True if either store had something to remove, False if
    both stores were already clean. Raises ChromaIndexError if
    ChromaDB cleanup fails — JSON state will already be saved at
    that point so the caller can decide whether to retry the
    ChromaDB step or warn the user.
    """
    db = _load_db()
    original_count = len(db["learnings"])
    db["learnings"] = [l for l in db["learnings"] if l["id"] != learning_id]
    json_changed = len(db["learnings"]) < original_count

    if json_changed:
        _save_db(db)

    # Always attempt ChromaDB cleanup. If the JSON entry was missing,
    # this still cleans up any orphaned embedding. If ChromaDB cleanup
    # fails, the JSON change is already persisted — caller will see
    # the exception and can warn the user about the orphan.
    _remove_from_index(learning_id)

    return json_changed


def get_learning_stats() -> dict:
    """Return summary statistics about the learnings database."""
    db = _load_db()
    all_l = db["learnings"]
    stats = {
        "total":            len(all_l),
        "active":           sum(1 for l in all_l if l.get("status") == "active"),
        "deprecated":       sum(1 for l in all_l if l.get("status") == "deprecated"),
        "archived":         sum(1 for l in all_l if l.get("status") == "archived"),
        "by_category":      {},
        "by_source":        {},
        "by_outcome":       {},
        "most_applied":     [],
        "file_path":        str(LEARNINGS_FILE),
    }
    for l in all_l:
        cat = l.get("category", "general")
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        src = l.get("source", "operator")
        stats["by_source"][src] = stats["by_source"].get(src, 0) + 1
        out = l.get("outcome", "unknown")
        stats["by_outcome"][out] = stats["by_outcome"].get(out, 0) + 1

    # Top 5 most-applied learnings
    active = [l for l in all_l if l.get("status") == "active"]
    active.sort(key=lambda x: x.get("applied_count", 0), reverse=True)
    stats["most_applied"] = [
        {"title": l["title"], "applied_count": l.get("applied_count", 0),
         "id": l["id"]}
        for l in active[:5]
        if l.get("applied_count", 0) > 0
    ]

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Conflict detection — find pairs of active learnings that may contradict
# each other based on semantic similarity above a configurable threshold.
# ─────────────────────────────────────────────────────────────────────────────

CONFLICT_SETTINGS_FILE = LEARNINGS_DIR / "conflict_settings.json"

# Recommended default. 0.75 has been chosen empirically to flag pairs
# that talk about the same subject (and therefore plausibly contradict)
# without drowning the user in noise from merely-related entries.
DEFAULT_CONFLICT_THRESHOLD = 0.75
MIN_CONFLICT_THRESHOLD     = 0.50
MAX_CONFLICT_THRESHOLD     = 0.95


def get_conflict_threshold() -> float:
    """
    Read the user's preferred conflict-detection similarity threshold.
    Returns DEFAULT_CONFLICT_THRESHOLD if no preference is saved or the
    settings file is malformed.
    """
    try:
        if CONFLICT_SETTINGS_FILE.exists():
            data = json.loads(CONFLICT_SETTINGS_FILE.read_text(encoding="utf-8"))
            t = float(data.get("conflict_threshold", DEFAULT_CONFLICT_THRESHOLD))
            return max(MIN_CONFLICT_THRESHOLD,
                       min(MAX_CONFLICT_THRESHOLD, t))
    except Exception as e:
        _log.debug("conflict_settings unreadable, using default: %s", e)
    return DEFAULT_CONFLICT_THRESHOLD


def set_conflict_threshold(value: float) -> float:
    """
    Save a new default conflict-detection similarity threshold.
    Returns the value actually saved (clamped to the supported range).
    """
    _ensure_dir()
    clamped = max(MIN_CONFLICT_THRESHOLD,
                  min(MAX_CONFLICT_THRESHOLD, float(value)))
    try:
        existing = {}
        if CONFLICT_SETTINGS_FILE.exists():
            try:
                existing = json.loads(
                    CONFLICT_SETTINGS_FILE.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        existing["conflict_threshold"] = clamped
        existing["updated_at"]         = _now_iso()
        tmp = CONFLICT_SETTINGS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(CONFLICT_SETTINGS_FILE))
    except Exception as e:
        _log.warning("Could not save conflict threshold: %s", e)
    return clamped


def _pair_key(id_a: str, id_b: str) -> tuple[str, str]:
    """Order-independent key for an unordered pair of learning IDs."""
    return (id_a, id_b) if id_a < id_b else (id_b, id_a)


def dismiss_conflict(id_a: str, id_b: str) -> bool:
    """
    Mark a flagged conflict pair as 'not actually a conflict' so future
    runs of find_conflicts won't surface it again. Recorded bidirectionally
    on both learnings. Returns True if both records were updated.
    """
    if not id_a or not id_b or id_a == id_b:
        return False
    db = _load_db()
    found_a = found_b = False
    for l in db["learnings"]:
        if l["id"] == id_a:
            dlist = l.setdefault("dismissed_conflicts", [])
            if id_b not in dlist:
                dlist.append(id_b)
            found_a = True
        elif l["id"] == id_b:
            dlist = l.setdefault("dismissed_conflicts", [])
            if id_a not in dlist:
                dlist.append(id_a)
            found_b = True
    if found_a and found_b:
        _save_db(db)
        return True
    return False


def clear_conflict_dismissal(id_a: str, id_b: str) -> bool:
    """
    Undo a previous dismiss_conflict — useful if the user changes their mind
    or wants to re-review a pair. Returns True if at least one side was
    updated.
    """
    if not id_a or not id_b:
        return False
    db = _load_db()
    changed = False
    for l in db["learnings"]:
        if l["id"] == id_a and id_b in l.get("dismissed_conflicts", []):
            l["dismissed_conflicts"].remove(id_b)
            changed = True
        elif l["id"] == id_b and id_a in l.get("dismissed_conflicts", []):
            l["dismissed_conflicts"].remove(id_a)
            changed = True
    if changed:
        _save_db(db)
    return changed


def find_conflicts(threshold: float | None = None) -> list[dict]:
    """
    Find pairs of active learnings whose semantic similarity is at or above
    `threshold`. Pairs already linked via supersedes/superseded_by, or
    explicitly dismissed by the user, are excluded.

    For each pair we use ChromaDB to query each learning's text against the
    full active collection and read off the similarity to every other
    active learning. We then deduplicate so each pair is reported once.

    Args:
        threshold: similarity floor (0.0..1.0). If None, uses
                   get_conflict_threshold().

    Returns:
        List of pair dicts sorted by similarity descending. Each dict has:
          'a':           full learning record A
          'b':           full learning record B
          'similarity':  float in [0, 1]
    """
    if threshold is None:
        threshold = get_conflict_threshold()
    threshold = max(MIN_CONFLICT_THRESHOLD,
                    min(MAX_CONFLICT_THRESHOLD, float(threshold)))

    db = _load_db()
    active = [l for l in db["learnings"]
              if l.get("status", "active") == "active"]
    if len(active) < 2:
        return []

    by_id = {l["id"]: l for l in active}

    try:
        collection = _get_learnings_collection()
    except Exception as e:
        _log.warning("find_conflicts: collection unavailable: %s", e)
        return []

    if collection.count() < 2:
        return []

    # We ask Chroma for every active learning's nearest neighbours, capped
    # at len(active) per query so we cover the whole active set in one
    # round-trip. (Chroma scales linearly; for the size of a personal
    # knowledge base this is essentially instant.)
    pairs: dict[tuple[str, str], dict] = {}
    n_neighbours = min(len(active), 50)

    for src in active:
        # Skip if this learning was already linked to another via supersession
        already_linked = set()
        if src.get("supersedes"):
            already_linked.add(src["supersedes"])
        if src.get("superseded_by"):
            already_linked.add(src["superseded_by"])
        already_linked.update(src.get("dismissed_conflicts", []))

        try:
            res = collection.query(
                query_texts=[_build_chunk_text(src)],
                n_results=n_neighbours,
                where={"status": "active"},
            )
        except Exception as e:
            _log.debug("find_conflicts query failed for %s: %s", src["id"], e)
            continue

        if not res.get("metadatas") or not res["metadatas"][0]:
            continue

        metas = res["metadatas"][0]
        dists = res["distances"][0]
        for meta, dist in zip(metas, dists):
            other_id = meta.get("learning_id", "")
            if not other_id or other_id == src["id"]:
                continue
            if other_id in already_linked:
                continue
            if other_id not in by_id:
                # Indexed but not in JSON — skip (will be cleaned up on
                # next reindex).
                continue
            sim = max(0.0, min(1.0, 1.0 - (float(dist) / 2.0)))
            if sim < threshold:
                continue
            key = _pair_key(src["id"], other_id)
            # Keep the highest similarity if we see the pair from both sides
            existing = pairs.get(key)
            if existing is None or sim > existing["similarity"]:
                pairs[key] = {
                    "a":          by_id[src["id"]],
                    "b":          by_id[other_id],
                    "similarity": sim,
                }

    return sorted(pairs.values(),
                  key=lambda p: p["similarity"],
                  reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Export / import — shareable learning packs (.aiplearn JSON files)
# ─────────────────────────────────────────────────────────────────────────────

EXPORT_SCHEMA_VERSION = "1.0"


def export_learnings(
    dest_path: str,
    include_inactive: bool = False,
    include_ids: list[str] | None = None,
) -> dict:
    """
    Write a learning pack to dest_path in JSON form.

    Args:
        dest_path:        Output file path. Conventional extension: .aiplearn
        include_inactive: If False (default), exports only status=='active'.
                          If True, exports everything (active, deprecated,
                          archived). Useful for full-history backups.
        include_ids:      Optional list of specific learning IDs to export.
                          If provided, overrides the active/inactive filter.

    Returns:
        Summary dict: {'exported': int, 'path': str}
    """
    db = _load_db()
    learnings = db.get("learnings", [])

    if include_ids is not None:
        wanted = set(include_ids)
        selected = [l for l in learnings if l["id"] in wanted]
    elif include_inactive:
        selected = list(learnings)
    else:
        selected = [l for l in learnings
                    if l.get("status", "active") == "active"]

    pack = {
        "schema":      EXPORT_SCHEMA_VERSION,
        "exported_at": _now_iso(),
        "source_app":  "AI-Prowler",
        "count":       len(selected),
        "learnings":   selected,
    }

    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(pack, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    os.replace(str(tmp), str(dest))

    return {"exported": len(selected), "path": str(dest)}


def _validate_pack(pack: dict) -> tuple[bool, str]:
    """Return (ok, error_message). Lenient — accepts any version string."""
    if not isinstance(pack, dict):
        return False, "Top-level structure is not a JSON object."
    if "learnings" not in pack or not isinstance(pack["learnings"], list):
        return False, "Pack is missing a 'learnings' array."
    return True, ""


def import_learnings(
    src_path: str,
    mode: str = "merge",
    on_conflict: str = "ask",
    conflict_resolver=None,
) -> dict:
    """
    Import a learning pack from src_path.

    Args:
        src_path: Path to a .aiplearn (JSON) file produced by export_learnings.
        mode: How to handle the imported data:
            'merge'   — IDs that don't exist locally are added; IDs that
                        DO exist trigger the on_conflict policy.
            'append'  — Every imported learning is given a fresh UUID and
                        added; existing local data is untouched. Safe but
                        loses ID-based merge in the future.
            'replace' — Wipe local learnings and replace with the pack's
                        contents. DANGEROUS — caller must confirm with
                        the user before passing this mode.
        on_conflict: For 'merge' mode only — what to do when an imported
                     ID already exists locally:
            'ask'        — defer to conflict_resolver(local, incoming);
                           must return one of 'keep_local',
                           'take_incoming', 'supersede'.
            'keep_local' — leave local untouched; skip incoming.
            'take_incoming' — overwrite local with incoming (preserves ID).
            'supersede'  — keep both; mark local as deprecated and link
                           via superseded_by to incoming.
        conflict_resolver: Callable invoked once per ID-collision when
                           on_conflict='ask'. Signature:
                               resolver(local_learning, incoming_learning) -> str
                           Returns 'keep_local' | 'take_incoming' | 'supersede'.

    Returns:
        Summary dict:
            {'added': int, 'updated': int, 'skipped': int,
             'superseded': int, 'replaced_total': int (replace mode only),
             'errors': list[str]}
    """
    src = Path(src_path)
    if not src.exists():
        return {"added": 0, "updated": 0, "skipped": 0, "superseded": 0,
                "errors": [f"File not found: {src_path}"]}

    try:
        pack = json.loads(src.read_text(encoding="utf-8"))
    except Exception as e:
        return {"added": 0, "updated": 0, "skipped": 0, "superseded": 0,
                "errors": [f"Could not parse pack: {e}"]}

    ok, err = _validate_pack(pack)
    if not ok:
        return {"added": 0, "updated": 0, "skipped": 0, "superseded": 0,
                "errors": [err]}

    incoming = pack["learnings"]
    db       = _load_db()
    existing_by_id = {l["id"]: l for l in db["learnings"]}

    summary = {
        "added": 0, "updated": 0, "skipped": 0,
        "superseded": 0, "errors": [],
    }
    now = _now_iso()

    if mode == "replace":
        # Wipe everything and take the pack as-is. Ensure required fields
        # exist on incoming records (older packs may lack newer fields).
        new_list = []
        for inc in incoming:
            inc.setdefault("status", "active")
            inc.setdefault("dismissed_conflicts", [])
            inc.setdefault("applied_count", 0)
            new_list.append(inc)
        db["learnings"] = new_list
        _save_db(db)
        try:
            count = reindex_all_learnings()
        except Exception as e:
            summary["errors"].append(f"Reindex failed: {e}")
            count = 0
        summary["replaced_total"] = len(new_list)
        summary["added"]          = len(new_list)
        summary["reindexed"]      = count
        return summary

    if mode == "append":
        # Always assign fresh UUIDs; never collide with existing data.
        for inc in incoming:
            try:
                fresh = dict(inc)
                fresh["id"]            = str(uuid.uuid4())
                fresh["created_at"]    = inc.get("created_at", now)
                fresh["updated_at"]    = now
                fresh["status"]        = inc.get("status", "active")
                fresh["dismissed_conflicts"] = []
                # Imported supersession links would point at IDs that no
                # longer correspond to anything in this database — clear
                # them rather than leave dangling references.
                fresh["supersedes"]    = ""
                fresh["superseded_by"] = ""
                db["learnings"].append(fresh)
                _index_learning(fresh)
                summary["added"] += 1
            except Exception as e:
                summary["errors"].append(f"{inc.get('id','?')}: {e}")
        _save_db(db)
        return summary

    # mode == 'merge' (default)
    for inc in incoming:
        inc_id = inc.get("id")
        if not inc_id:
            summary["skipped"] += 1
            summary["errors"].append("Incoming record had no ID; skipped.")
            continue

        if inc_id not in existing_by_id:
            # New record — just add it.
            try:
                inc.setdefault("status", "active")
                inc.setdefault("dismissed_conflicts", [])
                inc.setdefault("applied_count", 0)
                db["learnings"].append(inc)
                _index_learning(inc)
                summary["added"] += 1
            except Exception as e:
                summary["errors"].append(f"{inc_id}: {e}")
            continue

        # ID collision — apply on_conflict policy
        local = existing_by_id[inc_id]
        if on_conflict == "ask":
            if conflict_resolver is None:
                # No resolver provided, but caller asked for ask; default
                # to safest behaviour.
                decision = "keep_local"
            else:
                try:
                    decision = conflict_resolver(local, inc)
                except Exception as e:
                    summary["errors"].append(
                        f"resolver raised on {inc_id}: {e}")
                    decision = "keep_local"
        else:
            decision = on_conflict

        if decision == "keep_local":
            summary["skipped"] += 1
        elif decision == "take_incoming":
            try:
                # In-place update preserves list ordering
                for idx, l in enumerate(db["learnings"]):
                    if l["id"] == inc_id:
                        merged = dict(inc)
                        merged.setdefault("status", "active")
                        merged.setdefault("dismissed_conflicts",
                                          local.get("dismissed_conflicts", []))
                        merged.setdefault("applied_count",
                                          local.get("applied_count", 0))
                        merged["updated_at"] = now
                        db["learnings"][idx] = merged
                        _index_learning(merged)
                        break
                summary["updated"] += 1
            except Exception as e:
                summary["errors"].append(f"{inc_id}: {e}")
        elif decision == "supersede":
            # Keep local, mark deprecated, add incoming with fresh UUID
            try:
                for l in db["learnings"]:
                    if l["id"] == inc_id:
                        l["status"]        = "deprecated"
                        l["updated_at"]    = now
                        new_inc = dict(inc)
                        new_inc["id"]            = str(uuid.uuid4())
                        new_inc["supersedes"]    = inc_id
                        new_inc["superseded_by"] = ""
                        new_inc["status"]        = "active"
                        new_inc["dismissed_conflicts"] = []
                        new_inc["applied_count"] = 0
                        new_inc["created_at"]    = now
                        new_inc["updated_at"]    = now
                        l["superseded_by"]       = new_inc["id"]
                        db["learnings"].append(new_inc)
                        _index_learning(l)
                        _index_learning(new_inc)
                        break
                summary["superseded"] += 1
            except Exception as e:
                summary["errors"].append(f"{inc_id}: {e}")
        else:
            summary["skipped"] += 1
            summary["errors"].append(
                f"{inc_id}: unknown decision '{decision}', skipped.")

    _save_db(db)
    return summary
