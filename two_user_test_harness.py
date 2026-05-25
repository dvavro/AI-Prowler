#!/usr/bin/env python3
"""
two_user_test_harness.py  —  v7.0.0 Phase B Step 2 isolation-test setup.

PURPOSE
    Seed scoped ChromaDB collections (shared / role:sales / role:field /
    user:<token>) with small, clearly-labelled test documents, by running them
    through the REAL indexing pipeline (index_directory with a collection_resolver).
    This does double duty:
      1. Exercises the WRITE-side surgery end-to-end — proves collection_resolver
         actually routes files to the right collection (a bug here shows up now,
         isolated, instead of tangled with the read-side test).
      2. Produces the data the TWO-USER ISOLATION TEST reads against.

    It does NOT modify ai_prowler_mcp.py or rag_preprocessor.py — it only USES
    them, so it is safe to run/delete freely.

USAGE  (run with the interpreter that has the deps, from the work-tree dir)
    python two_user_test_harness.py            # create test docs + index them scoped
    python two_user_test_harness.py --verify   # just report what's in each collection
    python two_user_test_harness.py --read-test # simulate the two-user read isolation
    python two_user_test_harness.py --cleanup   # drop the TEST collections (not 'documents')

SAFETY
    - Test collections use the real scope names (role:sales etc.) because that's
      what the read path queries. The single personal-mode 'documents' collection
      is NEVER touched by this script.
    - --cleanup deletes ONLY the scoped test collections it created, by name.
    - Test docs are written under a temp dir and removed after indexing.
"""
import sys
import os
import json
import shutil
import tempfile
from pathlib import Path

# Import the real engine.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rag_preprocessor as rp
import ai_prowler_mcp as ap


# ── Test fixtures ─────────────────────────────────────────────────────────────
# Two non-owner users in DIFFERENT scopes (owner-global-read is a separate,
# not-yet-wired refinement, so the isolation test deliberately uses non-owners).
USER_A = {"id": "userA00000000001", "name": "Alice Sales", "role": "manager",
          "scopes": ["role:sales"], "private_collection_enabled": True,
          "status": "active"}
USER_B = {"id": "userB00000000002", "name": "Bob Field", "role": "manager",
          "scopes": ["role:field"], "private_collection_enabled": True,
          "status": "active"}

# Sentinel content: each doc says which scope it belongs to, so the read test
# can assert "A must NOT see FIELD_SECRET / BOB_PRIVATE".
TEST_DOCS = {
    "shared_handbook.txt":
        "COMPANY_SHARED company handbook. Office hours are 8 to 5. "
        "Everyone in the company may read this shared document.",
    "sales_pricing.txt":
        "SALES_SECRET confidential sales pricing. Window cleaning is priced at "
        "competitive rates for the sales team only. role:sales content.",
    "field_routes.txt":
        "FIELD_SECRET confidential field crew routes and gate codes. "
        "Only the field crew scope should ever see this. role:field content.",
    "alice_notes.txt":
        "ALICE_PRIVATE Alice's personal notes. Only Alice (userA) may read this. "
        "user private collection content.",
    "bob_notes.txt":
        "BOB_PRIVATE Bob's personal notes. Only Bob (userB) may read this. "
        "user private collection content.",
}

# Which file maps to which collection (this is the Model-B mapping, expressed as
# a resolver the harness builds below).
FILE_TO_COLLECTION = {
    "shared_handbook.txt": "shared",
    "sales_pricing.txt":   "role:sales",
    "field_routes.txt":    "role:field",
    "alice_notes.txt":     f"user:{USER_A['id']}",
    "bob_notes.txt":       f"user:{USER_B['id']}",
}

TEST_COLLECTIONS = sorted(set(FILE_TO_COLLECTION.values()))


def _make_resolver():
    """Return a collection_resolver(filepath)->collection_name based on filename."""
    def _resolve(filepath):
        fname = os.path.basename(filepath)
        return FILE_TO_COLLECTION.get(fname)   # None falls back to 'documents'
    return _resolve


def cmd_seed():
    """Write test docs to a temp dir and index them through the real pipeline."""
    tmp = Path(tempfile.mkdtemp(prefix="aiprowler_2user_"))
    print(f"📝 Writing {len(TEST_DOCS)} test docs to {tmp}")
    for name, content in TEST_DOCS.items():
        (tmp / name).write_text(content, encoding="utf-8")

    resolver = _make_resolver()
    print("🔧 Indexing through index_directory(collection_resolver=...) ...")
    rp.index_directory(str(tmp), recursive=False, quiet=True,
                       collection_resolver=resolver)

    shutil.rmtree(tmp, ignore_errors=True)
    print("🧹 Removed temp docs.\n")
    cmd_verify()


def cmd_verify():
    """Report how many chunks landed in each expected collection."""
    client, ef = rp.get_chroma_client()
    print("📊 Collection contents:")
    try:
        # Chroma >=0.6.0: list_collections() returns NAMES (strings). Older
        # versions returned objects with .name. Handle both.
        raw = client.list_collections()
        existing = set()
        for c in raw:
            existing.add(c if isinstance(c, str) else getattr(c, "name", str(c)))
    except Exception as e:
        existing = set()
        print(f"   (could not list collections: {e})")
    for cname in TEST_COLLECTIONS:
        phys = rp.chroma_collection_name(cname)
        if phys in existing:
            try:
                col = client.get_collection(name=phys, embedding_function=ef)
                print(f"   ✅ {cname:28} -> {phys:24} {col.count()} chunk(s)")
            except Exception as e:
                print(f"   ⚠️  {cname:28} error: {e}")
        else:
            print(f"   ❌ {cname:28} -> {phys:24} MISSING (resolver did not route here?)")
    # Also confirm the personal 'documents' collection was NOT polluted.
    if "documents" in existing:
        try:
            doc = client.get_collection(name="documents", embedding_function=ef)
            print(f"   ℹ️  documents (personal)      {doc.count()} chunk(s) "
                  f"— should NOT contain the test docs")
        except Exception:
            pass


def _search_as(user, query, n_results=10):
    """Run the scoped search exactly as the MCP tool does for a given user."""
    scoped = ap._allowed_collections(user)
    return rp.search_documents(query, n_results=n_results,
                               collection_names=scoped), scoped


def cmd_read_test():
    """The TWO-USER ISOLATION TEST. Asserts each user sees only their scope."""
    print("🔒 TWO-USER ISOLATION TEST\n" + "─" * 50)
    passed = failed = 0

    def check(label, condition):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"   ✅ {label}")
        else:
            failed += 1
            print(f"   ❌ {label}")

    # Query broadly so every collection *would* match if not scoped out.
    QUERY = "confidential content notes pricing routes handbook"

    a_chunks, a_scope = _search_as(USER_A, QUERY)
    b_chunks, b_scope = _search_as(USER_B, QUERY)
    a_text = " ".join(c.get("content", "") for c in a_chunks)
    b_text = " ".join(c.get("content", "") for c in b_chunks)

    print(f"\n   User A ({USER_A['name']}) scope: {a_scope}")
    print(f"   User B ({USER_B['name']}) scope: {b_scope}\n")

    # A (sales) MUST see: shared + sales + own private. MUST NOT see: field, Bob.
    check("A sees SHARED",              "COMPANY_SHARED" in a_text)
    check("A sees SALES_SECRET",        "SALES_SECRET"   in a_text)
    check("A sees own ALICE_PRIVATE",   "ALICE_PRIVATE"  in a_text)
    check("A does NOT see FIELD_SECRET","FIELD_SECRET"   not in a_text)
    check("A does NOT see BOB_PRIVATE", "BOB_PRIVATE"    not in a_text)

    # B (field) MUST see: shared + field + own private. MUST NOT see: sales, Alice.
    check("B sees SHARED",              "COMPANY_SHARED" in b_text)
    check("B sees FIELD_SECRET",        "FIELD_SECRET"   in b_text)
    check("B sees own BOB_PRIVATE",     "BOB_PRIVATE"    in b_text)
    check("B does NOT see SALES_SECRET","SALES_SECRET"   not in b_text)
    check("B does NOT see ALICE_PRIVATE","ALICE_PRIVATE" not in b_text)

    print("\n" + "─" * 50)
    print(f"   RESULT: {passed} passed, {failed} failed")
    if failed:
        print("   ⛔ ISOLATION FAILED — do NOT expose multi-user mode.")
        return False
    print("   ✅ ISOLATION HOLDS for these two users.")
    return True


def cmd_cleanup():
    """Delete ONLY the scoped test collections (never 'documents')."""
    client, _ = rp.get_chroma_client()
    for cname in TEST_COLLECTIONS:
        if cname == "documents":
            continue  # paranoia: never delete the personal collection
        phys = rp.chroma_collection_name(cname)
        try:
            client.delete_collection(name=phys)
            print(f"   🗑️  deleted {cname} -> {phys}")
        except Exception as e:
            print(f"   (skip {cname} -> {phys}: {e})")
    print("Done. Personal 'documents' collection left intact.")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "--seed"
    if arg in ("--seed", "seed"):
        cmd_seed()
        print("\nNext: python two_user_test_harness.py --read-test")
    elif arg in ("--verify", "verify"):
        cmd_verify()
    elif arg in ("--read-test", "read-test", "--read", "test"):
        ok = cmd_read_test()
        sys.exit(0 if ok else 1)
    elif arg in ("--cleanup", "cleanup"):
        cmd_cleanup()
    else:
        print(__doc__)
