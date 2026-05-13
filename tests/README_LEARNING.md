# AI-Prowler 6.0.0 — Self-Learning Test Suite

This document describes the automated test suite for AI-Prowler's self-learning feature. The suite captures the scenarios you validated manually before tagging 6.0.0 as **75 deterministic pytest tests** that run in ~60 seconds and protect against regressions on future changes.

The scope here is **only the self-learning layer** — record, retrieve, update, delete, supersession, conflict detection, export/import, the MCP tool wrappers, and the GUI's Learnings tab. The broader indexing/update/tracking suite is documented elsewhere.

## Status

✅ **75 of 75 tests passing.**

Total wall-clock runtime: ~60 seconds on a typical machine (the bulk is taken up by ChromaDB collection setup, which `@pytest.mark.slow`-marked tests trigger).

## What's covered

The self-learning system has three layers, each with its own test directory:

| Layer | Source file | Tests | Focus |
|---|---|---|---|
| **Engine** | `self_learning.py` | 53 | CRUD, semantic search, supersession, conflicts, persistence, export/import |
| **MCP tools** | `ai_prowler_mcp.py` | 18 | The `@mcp.tool()`-decorated wrappers Claude calls — argument validation, output formatting, end-to-end consistency |
| **GUI** | `rag_gui.py` (Learnings tab) | 4 | The presentation layer — stats StringVars, file-path agreement, Treeview presence |

The engine layer is the bulk of substantive coverage. The MCP layer adds confidence that the user-visible wrappers behave as documented. The GUI layer is intentionally light — see the "Why the GUI section is small" note further down.

## File layout

```
tests/
├── conftest.py                              ← existing top-level fixtures (isolated_env, rag, …)
├── learning_fixtures.py                     ← NEW: shared self-learning fixtures
├── learning/                                ← engine tests (53)
│   ├── __init__.py
│   ├── conftest.py                          ← thin shim — imports from learning_fixtures
│   ├── test_crud_and_persistence.py        ← L-CRUD-* + L-PERS-* + L-STATS-*
│   ├── test_search_and_counters.py         ← L-SEARCH-* + L-COUNT-*
│   ├── test_supersession_and_conflicts.py  ← L-SUPER-* + L-CONF-*
│   └── test_export_import.py               ← L-PACK-*
├── mcp/
│   ├── conftest.py                          ← existing MCP fixtures + learning-fixture imports
│   └── test_learning_mcp_tools.py          ← L-MCP-* (18)
└── gui/
    ├── conftest.py                          ← existing GUI fixtures + learning-fixture imports
    └── test_learnings_tab.py               ← L-GUI-* (4)
```

### Why `learning_fixtures.py` lives outside `learning/`

Pytest auto-discovers `conftest.py` files **upward through the directory tree**, not across siblings. Fixtures defined in `tests/learning/conftest.py` are invisible to `tests/mcp/` and `tests/gui/`.

The standard fix is to put shared fixtures in the parent's `conftest.py`, but that would force a manual merge with the existing top-level fixtures. Instead, the substantive fixture code lives in `tests/learning_fixtures.py` (a regular module), and the three sibling `conftest.py` files import from it:

```python
from tests.learning_fixtures import sl_module, sl_env, seeded_learnings
```

Pytest treats imported fixtures the same as locally-defined ones — no plugin, no magic, no changes to `pytest.ini`. This is the cleanest sharing pattern when sibling directories need the same fixtures.

## Test ID system

Every test function name starts with its plan ID, so you can grep the table for an ID and find the test, or vice versa:

```
test_L_CRUD_01_record_learning_basic                → L-CRUD-01
test_L_SEARCH_02_results_ordered_by_similarity      → L-SEARCH-02
test_L_MCP_15_delete_unknown_id_reports_not_found   → L-MCP-15
```

ID-prefix inventory:

| Prefix | Area | Count | File |
|---|---|--:|---|
| `L-CRUD-*` | Create / read / update / delete | 14 | `test_crud_and_persistence.py` |
| `L-PERS-*` | Persistence — JSON survive, reindex, atomic save | 4 | `test_crud_and_persistence.py` |
| `L-STATS-*` | `get_learning_stats` correctness | 2 | `test_crud_and_persistence.py` |
| `L-SEARCH-*` | `check_learned` semantic search | 8 | `test_search_and_counters.py` |
| `L-COUNT-*` | `applied_count` tracking | 4 | `test_search_and_counters.py` |
| `L-SUPER-*` | Supersession chains | 3 | `test_supersession_and_conflicts.py` |
| `L-CONF-*` | Conflict detection, dismissal, threshold | 8 | `test_supersession_and_conflicts.py` |
| `L-PACK-*` | Export / import learning packs | 10 | `test_export_import.py` |
| `L-MCP-*` | MCP tool wrappers | 18 | `test_learning_mcp_tools.py` |
| `L-GUI-*` | GUI Learnings tab | 4 | `test_learnings_tab.py` |
| **Total** | | **75** | |

## How to run

```cmd
:: Just the learning tests
py -m pytest tests\learning tests\mcp\test_learning_mcp_tools.py tests\gui\test_learnings_tab.py

:: One directory at a time
py -m pytest tests\learning                       :: engine only — fastest
py -m pytest tests\mcp\test_learning_mcp_tools.py :: MCP wrappers
py -m pytest tests\gui\test_learnings_tab.py      :: GUI layer

:: Filter by prefix
py -m pytest tests -k "L_CRUD"      :: just CRUD tests
py -m pytest tests -k "L_CONF"      :: just conflict-detection tests

:: Skip slow tests (no embedding-model load) — useful for quick iteration
py -m pytest tests\learning -m "not slow"
```

## Isolation strategy

Every test gets its own:

1. **Learnings JSON file** at `<tmp_path>/learnings/self_learning_data.json` (per-test temp directory)
2. **Conflict-settings file** in the same temp dir
3. **ChromaDB collection** named `ai_prowler_learnings` — but inside a per-test temp database directory, so even though the collection name matches production, it lives in an isolated Chroma instance

The user's real learnings at `~/.ai-prowler/learnings/` are **never touched** by the test suite. The `sl_env` fixture in `learning_fixtures.py` redirects `LEARNINGS_DIR`, `LEARNINGS_FILE`, and `CONFLICT_SETTINGS_FILE` on the `self_learning` module before any test code runs, and resets the ChromaDB cache so the next collection lookup opens a fresh instance.

For the GUI tests there's one wrinkle: the Learnings tab reads its file path via `Path.home() / ".ai-prowler" / "learnings"` inside a closure, so we can't redirect it the same way as the engine. The `learnings_gui` fixture in `test_learnings_tab.py` monkey-patches `Path.home()` itself for the test duration, and re-points the engine's `LEARNINGS_FILE` to match — so the GUI's hardcoded path and the engine's path resolve to the same temp file. Both sides see the same data, just at a relocated location.

## Sample-data fixture

The `seeded_learnings` fixture pre-populates the database with four deterministic records covering several categories and sources:

| Title | Category | Source | Outcome |
|---|---|---|---|
| Client Alpha prefers email over phone | client_preference | operator | — |
| Always submit permits 2 weeks ahead | best_practice | post_mortem | positive |
| Smith project went over budget by 30% | project_insight | project_review | negative |
| Use FastMCP version >= 1.2 for instructions support | technical_note | claude_detected | — |

These cover the realistic shape of a small production knowledge base: a mix of operator-recorded preferences, project retrospectives, technical gotchas, and best practices with outcomes. Tests that need a non-empty starting state depend on this fixture rather than building from scratch.

## Categories of test in detail

### CRUD lifecycle (`L-CRUD-*`)

Verifies basic create/read/update/delete operations on a single learning.

- **Schema completeness** — every field documented in `record_learning`'s return type is populated (`id`, `title`, `content`, `category`, `context`, `source`, `confidence`, `tags`, `supersedes`, `superseded_by`, `status`, `created_at`, `updated_at`, `applied_count`, `last_applied`, `outcome`, `dismissed_conflicts`)
- **Input normalisation** — invalid category falls back to `general`; confidence clamps to `[0, 1]`; tags get lowercased and stripped
- **List filtering** — `list_learnings(category=..., tag=..., status=...)` returns the right subset, no leakage
- **Defence in depth** — `update_learning` silently ignores attempts to change `id`, `created_at`, or `applied_count` (the allow-list is `title, content, context, category, confidence, tags, status, outcome`)
- **Error paths** — updating or deleting a non-existent UUID returns `None`/`False`, never raises

### Persistence (`L-PERS-*`)

- Records survive a simulated process restart (`_load_db` after a write returns the same data)
- Corrupt JSON file is handled gracefully — engine starts fresh and the next write recovers cleanly
- Atomic save: no `.tmp` files left lying around after a successful save (the engine uses tmp+rename for safety)
- **`reindex_all_learnings` rebuilds the ChromaDB collection from the JSON file** — this is the recovery path when a user corrupts the index without corrupting the JSON

### Stats (`L-STATS-*`)

- `get_learning_stats` counts match the actual DB contents across status, category, source, and outcome dimensions
- Empty database returns zeros, not `KeyError` or `None`

### Semantic search (`L-SEARCH-*`)

- **Paraphrase matching**: "how should we contact Alpha" finds the seeded "Client Alpha prefers email" learning even though no keywords overlap
- Results ordered by similarity, descending
- Similarity scores clamped to `[0, 1]` regardless of ChromaDB's internal squared-L2 scaling
- Category filter restricts results without leakage
- `active_only=True` (the default) excludes deprecated learnings; `active_only=False` returns them
- `n_results` clamped to the documented `[1, 20]` range
- Empty database and empty query both handled gracefully

### Applied-count tracking (`L-COUNT-*`)

This is the metric Claude uses to know which learnings get applied vs gather dust:

- `applied_count` increments by 1 per match in default (application) mode
- `track_application=False` suppresses the bump — used by the GUI's Learnings tab so just scrolling through doesn't inflate the counter
- Counter accumulates correctly across multiple searches
- `most_applied` in stats reflects the counters and is ordered by usage

### Supersession (`L-SUPER-*`)

When `record_learning(..., supersedes_id=X)` is called, the old learning X becomes a historical record:

- Old learning's `status` flips to `deprecated`
- Old learning's `superseded_by` points at the new one
- New learning's `supersedes` points at the old one
- Active-only searches never return the old version
- Multi-link chains (v1 → v2 → v3) work correctly
- `active_only=False` exposes the full history for auditing

### Conflict detection (`L-CONF-*`)

`find_conflicts()` flags pairs of active learnings whose semantic similarity exceeds a threshold:

- Real contradictions (Phillips vs flathead screwdriver for the same panel) get flagged
- Unrelated learnings (HVAC vs Slack timezone) don't get flagged at the default threshold
- Pairs already linked via supersession are excluded — the user has resolved that relationship already
- Explicit `dismiss_conflict(a, b)` suppresses future flags for that pair (stored bidirectionally on both records' `dismissed_conflicts` lists)
- `clear_conflict_dismissal(a, b)` restores the flag
- Threshold persists across sessions; clamped to `[MIN_CONFLICT_THRESHOLD, MAX_CONFLICT_THRESHOLD]` (0.5–0.95)
- Empty / single-record databases return no conflicts

### Learning packs (`L-PACK-*`)

The `.aiplearn` export format for sharing or backup, with five import policies covered:

- **Round-trip** — export then import recovers the same learnings (same IDs, same content)
- **Merge / `keep_local`** — ID collisions resolved by skipping incoming; local kept
- **Merge / `take_incoming`** — ID collisions resolved by overwriting local
- **Merge / `supersede`** — keeps both: local becomes deprecated and is linked to incoming via `superseded_by`
- **Append** — every imported record gets a fresh UUID (lossless additive import; no ID collisions possible)
- **Replace** — wipes local entirely and takes the pack as-is (destructive; caller must confirm with user)
- **Invalid pack** or missing file: error reported in the result dict, no exception
- **`include_inactive=True`** exports all statuses; default exports only `active`

### MCP layer (`L-MCP-*`)

Wraps every learning tool that's exposed to Claude:

- **`record_learning`** — validates non-empty title/content at the MCP layer (engine is more permissive); converts the comma-separated `tags` string into the engine's list format
- **`check_learned`** — validates non-empty query; returns formatted multi-line output; "no matches" produces a friendly message rather than a blank string
- **`list_learnings`** — category/status/tag filters work; empty result shows "No learnings found"
- **`update_learning`** — empty `learning_id` rejected; empty `updates` dict rejected; non-existent ID returns `❌` error
- **`delete_learning`** — three distinct outcomes are documented in tests:
  - ✅ Success: "permanently deleted" message
  - ℹ️ Unknown ID: "No JSON entry found for learning …" — informational, **not** an error. The wrapper still attempts ChromaDB cleanup in case of orphan embeddings, which is a deliberate design choice
  - ⚠️ Partial: JSON delete succeeded but ChromaDB cleanup failed; surfaces the orphan to the user
  - ❌ Generic exception: `❌ delete_learning failed: …`
- **`get_learning_stats`** — multi-section human-readable output; includes counts across all dimensions
- **Cross-tool consistency** — record via MCP, search via MCP, find the record (`L-MCP-18`)

### GUI layer (`L-GUI-*`)

Four tests covering the Learnings tab's externally observable state.

The tab uses heavy local closures inside `create_learnings_tab` (`_load_learnings`, `_refresh_all`, `_open_editor`, etc.) which aren't accessible from outside. We verify what we *can* observe through public APIs:

- The tab is constructed — `_sl_stat_total` and the other stats StringVars exist
- Engine writes are visible to the GUI on file reload (the file the engine writes is the file the GUI reads)
- The engine and GUI agree on the file location — if they ever diverge, this test catches it
- A Treeview widget exists somewhere in the GUI

Deeper interactions (the editor dialog, conflict-review UI, export/import dialogs) would require either pywinauto or refactoring the closures into instance methods. That's a 6.1 candidate. The substantive logic is already covered by the engine and MCP test layers.

## Mapping to manual validation

If you have notes from the original manual learning validation, here's the rough mapping:

| Manual scenario | Automated test ID(s) |
|---|---|
| Record a learning, then search for it and find it | L-CRUD-01 + L-SEARCH-01 + L-MCP-18 |
| Update a learning and confirm changes persist | L-CRUD-10, L-CRUD-11 |
| Delete a learning and confirm it's gone from both stores | L-CRUD-13 |
| Supersede an old fact with a new one | L-SUPER-01, L-SUPER-02 |
| Browse all learnings without inflating the counter | L-COUNT-02 |
| Confirm `check_learned` is application-tracking by default | L-COUNT-01, L-COUNT-03 |
| Detect conflicting learnings | L-CONF-01, L-CONF-02 |
| Dismiss a non-conflict so it stops being flagged | L-CONF-04, L-CONF-05 |
| Reindex after corruption rebuilds the search index | L-PERS-04 |
| Export to `.aiplearn` and import on another machine | L-PACK-01 |
| Merge an imported pack with the same UUIDs already present | L-PACK-04, L-PACK-05, L-PACK-06 |
| Append a pack as fresh records | L-PACK-02 |
| Replace local entirely from a pack | L-PACK-03 |
| Stats reflect live database state | L-STATS-01, L-STATS-02, L-MCP-16 |
| Empty-database edge cases never crash | L-SEARCH-07, L-CONF-07, L-MCP-06, L-MCP-09, L-MCP-17 |

If any scenario from your manual notes isn't in the table, that's a gap worth flagging — add the test.

## What this suite intentionally doesn't test

- **JSON-RPC wire format and tool-discovery** — that's the FastMCP SDK's responsibility, not yours
- **Real Ollama integration during learning-application workflows** — your manual smoke test covers that; the automated tests work directly against ChromaDB and the JSON file
- **The conflict-review GUI dialog** — uses heavy closures inside `create_learnings_tab` that aren't reachable from outside; would need refactoring before it can be driven from tests
- **The export/import dialog UX** (file pickers, format conversion options, error toasts) — same closure-reachability reason
- **Performance under load** — pytest isn't a load tester. The implementation shares ChromaDB infrastructure that's already proven to scale fine for personal-knowledge-base workloads in production

These are 6.1 candidates. The engine-level tests cover the substantive logic, and the GUI test ensures the visible state stays consistent with the engine's writes.

## Maintenance notes for future changes

- **Adding a new learning-related test:** drop it into the appropriate file (`test_crud_*`, `test_search_*`, etc.) and name it with the next sequential ID (`L-CRUD-15`, `L-MCP-19`, etc.). The fixtures (`sl_env`, `seeded_learnings`) come automatically once imported in the relevant `conftest.py`.

- **Adding a new fixture:** add it to `tests/learning_fixtures.py`, then import it from the conftests in `tests/learning/`, `tests/mcp/`, and `tests/gui/`. The thin-shim conftests are the documentation for what's shared.

- **If a test breaks after an engine change:** check whether it's exercising real behaviour (genuine regression) or exact output strings (false positive). MCP-layer tests in particular use substring matching on human-readable output — if you change the wording of a message in `ai_prowler_mcp.py`, the corresponding test may need its expected-string list extended. See `L-MCP-15` as an example — it accepts four different phrasings of "not found" because the wrapper uses ℹ️ rather than ❌ for that case, and we want to document that as a deliberate design choice rather than coerce the wrapper to match a test.

- **If `seeded_learnings` content changes:** every test that depends on it implicitly assumes those four titles, categories, sources, and outcomes. Search for `seeded_learnings` and update the assertions in step with the fixture.

- **If the schema version changes:** `SCHEMA_VERSION` in `self_learning.py` flows into `_load_db()` and into export-pack `schema` fields. Update `test_L_CRUD_01_record_learning_basic` (which checks the version) and the pack validation tests.
