#!/usr/bin/env python3
"""
AI-Prowler - Post-Upgrade Reindex
=================================
Run AFTER installing the v7 build (chromadb 1.0.x) on a machine whose old
0.6.x database was removed by AI-Prowler_PreUpgrade_Cleanup.bat.

It rebuilds the fresh 1.0.x store from data that SURVIVED the cleanup:
  * Documents - re-indexes every folder / file still in the tracked-paths
    list (~/.rag_auto_update_dirs.json).
  * Learnings - rebuilds the ai_prowler_learnings collection from the
    surviving self_learning_data.json.

Nothing new is authored here - this only rebuilds the SEARCH INDEXES from
files already on disk. Safe to re-run.
"""
import os
import sys

INSTALL_DIR = r"C:\Program Files\AI-Prowler"
if INSTALL_DIR not in sys.path:
    sys.path.insert(0, INSTALL_DIR)


def main():
    try:
        import rag_preprocessor as rp
    except Exception as e:
        print(f"FATAL: could not import rag_preprocessor from {INSTALL_DIR}: {e}")
        return 1

    # 1) Warm the embedding model so the first index call isn't cold.
    print("[1/3] Loading embedding model ...")
    try:
        rp.prewarm_embeddings()
        print("      Model ready.")
    except Exception as e:
        print(f"      (continuing without prewarm: {e})")

    # 2) Re-index every surviving tracked path.
    entries = rp.load_auto_update_list() or []
    if not entries:
        print("[2/3] No tracked paths found - skipping document reindex.")
    else:
        dirs = [p for p in entries if os.path.isdir(p)]
        files = [p for p in entries if os.path.isfile(p)]
        print(f"[2/3] Re-indexing {len(dirs)} folder(s) and {len(files)} file(s) ...")
        for d in dirs:
            print(f"      -> {d}")
            try:
                rp.index_directory(d, recursive=True, quiet=False)
            except Exception as e:
                print(f"         ERROR indexing {d}: {e}")
        if files:
            try:
                rp.index_file_list(files, label="post-upgrade reindex")
            except Exception as e:
                print(f"      ERROR indexing tracked files: {e}")

    # 3) Rebuild the learnings index from its surviving JSON source.
    print("[3/3] Rebuilding learnings index ...")
    try:
        import self_learning as sl
        result = sl.reindex_all_learnings()
        if result:
            print(f"      {result}")
        else:
            print("      Learnings index rebuilt.")
    except Exception as e:
        print(f"      ERROR rebuilding learnings: {e}")

    print("\nDone. AI-Prowler's document and learning indexes have been rebuilt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
