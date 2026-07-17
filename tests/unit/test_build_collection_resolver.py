"""
tests/unit/test_build_collection_resolver.py
================================================
RETIRED 2026-07-17 (SCOPE_SIMPLIFICATION_SPEC.md section 3.7, Phase 7
cleanup).

This file tested rag_preprocessor.build_collection_resolver() -- the
collection_map-based WHERE router rag_gui.py's Update Selected/Update All
buttons and command_update()'s unattended path used before the
single-collection cutover. That function has been deleted outright (not
just changed) -- there is only one physical collection now, and scope is
carried entirely by build_scope_resolver() (still live, tested in
tests/unit/test_build_scope_resolver.py), which tags chunk metadata
directly instead of proposing a collection target to route into.

There is nothing left to test here. This platform has no file-delete
tool by design (soft-delete only, per copy_to_backup's own contract), so
the file is retired in place rather than removed -- pytest collects zero
tests from it and it causes no failures. Left as a pointer for anyone
who finds this path via history/search rather than silently vanishing.
"""
