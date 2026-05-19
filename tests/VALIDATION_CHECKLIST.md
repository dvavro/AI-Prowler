# Code Tools Write-Side — Pre-Release Validation Checklist

Run this whole checklist before tagging a release with the 8 new write tools.
Total time: about 15–30 minutes depending on whether anything fails.

## 0. Pre-flight

- [ ] Work folder is `C:\Users\david\AI-Prowler_V601_to_V602_work\AI-Prowler`
- [ ] `git status` is clean (or any uncommitted changes are intentional)
- [ ] Existing test suite passes BEFORE applying the patch:
      ```
      cd C:\Users\david\AI-Prowler_V601_to_V602_work\AI-Prowler
      py -m pytest tests
      ```
      Expected: 212 passed (per v6.0.2 baseline)

## 1. Apply the main patch

- [ ] Copy `code_tools_write_side_patch.py` and `apply_patch.py` into the
      work folder (alongside the existing `ai_prowler_mcp.py`).

- [ ] Dry-run the patch:
      ```
      py apply_patch.py --dry-run
      ```
      Expected output (last lines):
      ```
      Tool decorator count:
        Before: 31
        After:  40
        Delta:  +9
        ✅ All 9 expected new tool functions present.
      [DRY RUN] Would write ~6,300 bytes to ai_prowler_mcp.py
      ```

- [ ] Apply for real:
      ```
      py apply_patch.py
      ```
      Expected: success message including a backup at
      `ai_prowler_mcp.py.before_codetools_writeside`.

- [ ] Verify the resulting file parses and has the new tools:
      ```
      py -c "import ast; ast.parse(open('ai_prowler_mcp.py').read()); print('OK')"
      findstr /R /C:"^@mcp\.tool()" ai_prowler_mcp.py | find /c "@mcp.tool"
      ```
      Expected: `OK` then `40`.

## 2. Apply the supporting patches (rag_preprocessor.py and rag_gui.py)

See `supporting_patches.md` for the exact diffs. Both are small and applied
by hand.

- [ ] **rag_preprocessor.py:** Added `is_backup_filename()` helper + updated 6
      `if ext in SKIP_EXTENSIONS` sites.
- [ ] **rag_gui.py:** Added `_check_write_approval_queue` +
      `_schedule_write_approval_poll` methods + `root.after(5000, ...)` call
      at the end of `__init__`.

- [ ] Both files parse:
      ```
      py -c "import ast; ast.parse(open('rag_preprocessor.py').read()); print('preproc OK')"
      py -c "import ast; ast.parse(open('rag_gui.py').read()); print('gui OK')"
      ```

## 3. Drop the new tests into the test tree

- [ ] Copy `test_write_tools.py` to `tests/mcp/test_write_tools.py`
- [ ] The file is auto-discovered by pytest under the existing rules
      (no harness changes needed — verified by inspection of conftest.py).

## 4. Run the existing test suite (must still pass)

- [ ] Run all pre-existing tests to confirm no regressions:
      ```
      py -m pytest tests --ignore=tests/mcp/test_write_tools.py
      ```
      Expected: **212 passed** (same as v6.0.2 baseline). If anything fails,
      something in the patches affected existing behaviour — investigate
      before proceeding.

## 5. Run the new tests

- [ ] Run just the new tests, verbose:
      ```
      py -m pytest tests/mcp/test_write_tools.py -v
      ```
      Expected: **75 passed**. Test IDs run from
      `test_C_MCP_WRITE_01_blocklist_windows_dir` through
      `test_C_MCP_WRITE_75_backups_isolated_after_many_operations`.

- [ ] Run the full suite together to confirm no cross-test contamination:
      ```
      py -m pytest tests
      ```
      Expected: **287 passed** (212 existing + 75 new).

## 6. Smoke test in Claude Desktop / Claude.ai

This verifies the MCP integration works end-to-end, not just the tool
internals.

### 6.1 Restart AI-Prowler so it picks up the new tools

- [ ] Stop AI-Prowler MCP (close the GUI / kill the python process).
- [ ] Restart it (run `rag_gui.py` or use the installed shortcut).
- [ ] Confirm in the log that all 9 new tools registered without error:
      ```
      type "%LOCALAPPDATA%\AI-Prowler\mcp_server.log" | findstr "Monkeypatched"
      ```

### 6.2 In Claude (Desktop or .ai), exercise each tool at least once

Pick a small test folder ALREADY in your tracked-paths allowlist
(e.g. `C:\Users\david\AI-Prowler_V601_to_V602_work\AI-Prowler\tests`). Don't
use a folder with files you can't lose — the smoke test will create and
modify files.

- [ ] Ask Claude: *"List the contents of <test folder>"* — should call
      `list_directory` and return a sensible listing.
- [ ] Ask Claude: *"Create a new file called smoke_test.txt at <test folder>
      with the content 'hello from claude'"* — should trigger the approval
      dialog on first attempt; approve it; the second attempt should succeed.
- [ ] Verify the approval persisted by asking Claude to create another file
      in the same folder — should succeed without a dialog.
- [ ] Ask Claude: *"Change 'hello from claude' to 'goodbye from claude' in
      that file, but show me a dry-run first"* — should call
      `str_replace_in_file` with `dry_run=True`, return a diff.
- [ ] Ask Claude to apply the change — should succeed and create a `.bak1`
      next to the file.
- [ ] Ask Claude: *"What backups exist for that file?"* — should call
      `list_backups`.
- [ ] Ask Claude: *"Restore the file from .bak1"* — should call
      `restore_backup`, succeed, content should be back to "hello from claude".
- [ ] Delete the smoke-test file and its .bak<N> manually when done.

### 6.3 Negative cases (security)

- [ ] Ask Claude to write to `C:\Windows\System32\foo.txt` — should be
      refused with the hard-blocklist message. **No file should be created.**
- [ ] Ask Claude to write to `C:\Users\david\.ssh\foo` — should be refused.
- [ ] Ask Claude to write to a folder NOT in your read allowlist — should
      be refused with the "Access denied" message (the read allowlist
      denial, NOT the approval queue).
- [ ] Ask Claude to overwrite an existing file via `create_file` — should
      be refused with the "use write_file" hint.

## 7. Verify ChromaDB stays in sync

This is the auto-re-index check.

- [ ] Pick a small `.py` file in a tracked + writable folder. Ask Claude to
      `grep_documents` for a unique string in it. Verify it's found.
- [ ] Ask Claude to `str_replace_in_file` that unique string with a new
      unique string.
- [ ] Wait ~5 seconds for the indexer to settle.
- [ ] Ask Claude to `grep_documents` for the NEW string. Verify it's found.
- [ ] Ask Claude to `grep_documents` for the OLD string. **Verify it's
      NOT found** (delete-then-add re-index semantics).

## 8. Verify backups are not indexed

- [ ] After the previous step, multiple `.bak<N>` files now exist next to
      the edited file.
- [ ] Ask Claude to `grep_documents` for the OLD string again. Should still
      return 0 matches (backups must NOT surface).
- [ ] If old string appears: the `is_backup_filename` filter is not wired
      into all 6 sites of `rag_preprocessor.py`. Re-check Patch 1 Step 2.

## 9. Production-load check: write counter circuit breaker

- [ ] Start a session, ask Claude to do a series of small writes (you can
      do this with: "create 25 small placeholder files named test_NN.txt
      in <writable folder>").
- [ ] After the 20th successful write, the next should be refused with the
      circuit-breaker message.
- [ ] Restart AI-Prowler. Counter resets — verify the 21st write now
      succeeds. (Or use the `reset_write_counter` tool from Claude.)
- [ ] Clean up the test files when done.

## 10. Record the implementation milestone

Once steps 1–9 all pass:

- [ ] Update the implementation-progress learning
      (ID `56a6b144-990b-4822-b6d6-0c039b70d3a7`) to mark all 8 write tools
      as ✅ shipped, including the version they shipped in.
- [ ] If you want a clean historical record: mark that learning
      `status="deprecated"` and `outcome="positive"` — the design spec
      learning (ID `6412cfe3-26e6-4029-a408-a9ea3b43b88a`) then stands alone
      as documentation of the shipped subsystem.
- [ ] Bump the AI-Prowler version (v6.0.2 → v6.1.0, since this is a feature
      addition not a patch).
- [ ] Tag the release in git and push.

## What to do if something fails

- **Existing tests regress (step 4):** the patch touched something it
      shouldn't have. Look at the failing test's name, check whether the
      affected file mentions any of the helpers introduced by the patch
      (`_resolve_writable_path`, `_is_blocked_path`, etc.). If unrelated,
      restore `ai_prowler_mcp.py.before_codetools_writeside` and investigate
      whether the manual rag_preprocessor.py / rag_gui.py patches broke
      something.

- **New tests fail (step 5):** read the failure message carefully. Common
      causes:
        - `_WRITABLE_DIRS_FILE` not properly monkey-patched in a test
        - The `_reindex_file_after_write` not properly stubbed for tests
          (would cause embedding model load on a test that doesn't expect it)
        - Path-separator differences between Windows and the test env

- **Smoke test fails (step 6):** the tools work in isolation but the MCP
      integration is broken. Check `mcp_server.log` for import errors or
      decorator failures.

- **ChromaDB sync fails (step 7):** the `_reindex_file_after_write` helper
      is not finding the right indexer functions. Check the actual signature
      of `index_file_list` and `_get_or_create_collection` in
      `rag_preprocessor.py` — they may have drifted from the May 18, 2026
      snapshot.

When all 10 steps pass, you can ship the new tools.
