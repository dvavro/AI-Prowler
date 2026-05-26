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

# An owner who is ALSO the data custodian (can_manage_users=True). Sees
# EVERYTHING: shared + all role:* (read_all_role_scopes) + own private + every
# employee's user:* private (can_manage_users custody). In production the owner
# would typically have this flag; custody can also be delegated to a non-owner
# by setting can_manage_users=True on their users.json entry without the owner role.
USER_OWNER = {"id": "owner00000000003", "name": "Olive Owner", "role": "owner",
              "scopes": [], "private_collection_enabled": True,
              "can_manage_users": True, "status": "active"}

# A delegated ADMIN: can_manage_users=True but NOT the owner. Reads all
# employees' privates (Alice, Bob) for custody, but is BARRED from the owner's
# private collection (neither read nor delete). Tests the owner-protection.
USER_ADMIN = {"id": "admin00000000004", "name": "Adam Admin", "role": "manager",
              "scopes": [], "private_collection_enabled": True,
              "can_manage_users": True, "status": "active"}

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
    "owner_notes.txt":
        "OWNER_PRIVATE Olive the owner's confidential personal notes. An admin "
        "must NEVER read this — owner private data is protected. user content.",
}

# Which file maps to which collection (this is the Model-B mapping, expressed as
# a resolver the harness builds below).
FILE_TO_COLLECTION = {
    "shared_handbook.txt": "shared",
    "sales_pricing.txt":   "role:sales",
    "field_routes.txt":    "role:field",
    "alice_notes.txt":     f"user:{USER_A['id']}",
    "bob_notes.txt":       f"user:{USER_B['id']}",
    "owner_notes.txt":     f"user:{USER_OWNER['id']}",
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


def cmd_direct_test():
    """Isolation test for the DIRECT-collection tools (those using
    _scoped_collections_for_ctx via .get()/.query() rather than the
    search_documents delegation). Builds a stub ctx per user, asks
    ai_prowler_mcp._scoped_collections_for_ctx for the collections it would
    expose, aggregates their docs (as the migrated .get() tools do), and
    asserts each user sees only their scoped content."""
    print("🔒 DIRECT-COLLECTION ISOLATION TEST (_scoped_collections_for_ctx)\n"
          + "─" * 50)
    passed = failed = 0

    def check(label, condition):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"   ✅ {label}")
        else:
            failed += 1
            print(f"   ❌ {label}")

    # Stub ctx chain mirroring FastMCP: ctx.request_context.request.state.user
    class _Stub:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    def _ctx_for(user):
        return _Stub(request_context=_Stub(request=_Stub(state=_Stub(user=user))))

    def _aggregate_text(user):
        """Mimic the migrated .get() tools: pull all docs from the user's
        scoped collections and concatenate (this is exactly what
        list_indexed_documents / get_document_chunks iterate over)."""
        cols = ap._scoped_collections_for_ctx(_ctx_for(user))
        texts = []
        for col in cols:
            try:
                total = col.count()
                sample = col.get(limit=min(5000, total),
                                 include=["documents"])
                texts.extend(sample.get("documents", []) or [])
            except Exception as e:
                print(f"      (collection read error: {e})")
        return " ".join(texts)

    a_text = _aggregate_text(USER_A)
    b_text = _aggregate_text(USER_B)

    # Same sentinel assertions as the search test, but via the .get() path.
    check("A sees SHARED",               "COMPANY_SHARED" in a_text)
    check("A sees SALES_SECRET",         "SALES_SECRET"   in a_text)
    check("A sees own ALICE_PRIVATE",    "ALICE_PRIVATE"  in a_text)
    check("A does NOT see FIELD_SECRET", "FIELD_SECRET"   not in a_text)
    check("A does NOT see BOB_PRIVATE",  "BOB_PRIVATE"    not in a_text)
    check("B sees SHARED",               "COMPANY_SHARED" in b_text)
    check("B sees FIELD_SECRET",         "FIELD_SECRET"   in b_text)
    check("B sees own BOB_PRIVATE",      "BOB_PRIVATE"    in b_text)
    check("B does NOT see SALES_SECRET", "SALES_SECRET"   not in b_text)
    check("B does NOT see ALICE_PRIVATE","ALICE_PRIVATE"  not in b_text)

    print("\n" + "─" * 50)
    print(f"   RESULT: {passed} passed, {failed} failed")
    if failed:
        print("   ⛔ DIRECT-TOOL ISOLATION FAILED.")
        return False
    print("   ✅ DIRECT-TOOL ISOLATION HOLDS.")
    return True


def cmd_owner_test():
    """Owner enumeration test: an owner should see SHARED + ALL role:*
    collections (via _enumerate_role_collections) + their OWN private, but NOT
    other users' private collections (read_others_private intentionally not
    implemented). Run after --seed (which creates role:sales, role:field,
    user:A, user:B, shared)."""
    print("👑 OWNER ENUMERATION TEST\n" + "─" * 50)
    passed = failed = 0

    def check(label, condition):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"   ✅ {label}")
        else:
            failed += 1
            print(f"   ❌ {label}")

    class _Stub:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    ctx = _Stub(request_context=_Stub(request=_Stub(state=_Stub(user=USER_OWNER))))
    cols = ap._scoped_collections_for_ctx(ctx)
    texts = []
    for col in cols:
        try:
            total = col.count()
            sample = col.get(limit=min(5000, total), include=["documents"])
            texts.extend(sample.get("documents", []) or [])
        except Exception as e:
            print(f"      (collection read error: {e})")
    owner_text = " ".join(texts)

    # Owner SEES EVERYTHING on the company server: shared + both role scopes
    # (enumeration) + own private + every employee's private (data-custody model).
    check("Owner sees SHARED",        "COMPANY_SHARED" in owner_text)
    check("Owner sees SALES_SECRET (role enum)",  "SALES_SECRET" in owner_text)
    check("Owner sees FIELD_SECRET (role enum)",  "FIELD_SECRET" in owner_text)
    check("Owner sees ALICE_PRIVATE (custody)", "ALICE_PRIVATE" in owner_text)
    check("Owner sees BOB_PRIVATE (custody)",   "BOB_PRIVATE"   in owner_text)

    print("\n" + "─" * 50)
    print(f"   RESULT: {passed} passed, {failed} failed")
    if failed:
        print("   ⛔ OWNER ENUMERATION TEST FAILED.")
        return False
    print("   ✅ OWNER ENUMERATION CORRECT.")
    return True


def cmd_admin_test():
    """Owner-protection test for a delegated ADMIN (can_manage_users, not owner).
    Asserts the admin READS all employees' privates (custody) but NOT the
    owner's, AND that the delete-permission logic blocks the admin from the
    owner's data while allowing employees'. Run after --seed (which now also
    seeds the owner's private OWNER_PRIVATE doc)."""
    print("🛡️  ADMIN OWNER-PROTECTION TEST\n" + "─" * 50)
    passed = failed = 0

    def check(label, condition):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"   ✅ {label}")
        else:
            failed += 1
            print(f"   ❌ {label}")

    class _Stub:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    ctx = _Stub(request_context=_Stub(request=_Stub(state=_Stub(user=USER_ADMIN))))
    # _scoped_collections_for_ctx calls ap._owner_user_id(), which reads the REAL
    # users.json — but our test users are in-memory, not in that file. Patch it to
    # return our seeded owner's id so the owner-exclusion targets the right
    # collection. (Restored in finally.)
    _orig_owner_fn = ap._owner_user_id
    ap._owner_user_id = lambda *a, **k: USER_OWNER["id"]
    try:
        cols = ap._scoped_collections_for_ctx(ctx)
        texts = []
        for col in cols:
            try:
                total = col.count()
                sample = col.get(limit=min(5000, total), include=["documents"])
                texts.extend(sample.get("documents", []) or [])
            except Exception as e:
                print(f"      (collection read error: {e})")
        admin_text = " ".join(texts)
    finally:
        ap._owner_user_id = _orig_owner_fn

    # READ side: admin sees employees' privates + shared, but NOT owner's private.
    check("Admin sees SHARED",              "COMPANY_SHARED" in admin_text)
    check("Admin sees ALICE_PRIVATE (custody)", "ALICE_PRIVATE" in admin_text)
    check("Admin sees BOB_PRIVATE (custody)",   "BOB_PRIVATE"   in admin_text)
    check("Admin does NOT see OWNER_PRIVATE",   "OWNER_PRIVATE" not in admin_text)

    # DELETE side: _can_manage_user_data — admin may manage employees, not owner.
    owner_id = USER_OWNER["id"]
    ok_emp, _ = ap._can_manage_user_data(USER_ADMIN, USER_A["id"], owner_id)
    ok_own, _ = ap._can_manage_user_data(USER_ADMIN, owner_id, owner_id)
    ok_failclosed, _ = ap._can_manage_user_data(USER_ADMIN, USER_A["id"], None)
    check("Admin MAY manage employee data",     ok_emp is True)
    check("Admin may NOT manage owner data",    ok_own is False)
    check("Admin BLOCKED when owner id unknown (fail closed)", ok_failclosed is False)

    print("\n" + "─" * 50)
    print(f"   RESULT: {passed} passed, {failed} failed")
    if failed:
        print("   ⛔ ADMIN OWNER-PROTECTION FAILED.")
        return False
    print("   ✅ ADMIN OWNER-PROTECTION HOLDS.")
    return True


def cmd_ownership_test():
    """END-TO-END chunk-ownership test through the REAL index pipeline.
    Proves the 'delete only your own' protection actually TAKES EFFECT:
      1. Alice indexes a file → its chunks carry indexed_by == Alice.
      2. Bob tries to re-index the SAME path → the purge is REFUSED, so Alice's
         chunks survive (Bob cannot wipe Alice's data).
      3. Alice re-indexes her own file → succeeds.

    EXPECTED TO FAIL until the wiring (step 3) is done — nothing stamps
    indexed_by or gates the purge yet. This is the red→green target.
    Indexes into a dedicated 'scope-ownership-test' collection; cleaned at end."""
    print("📁 CHUNK-OWNERSHIP END-TO-END TEST (delete only your own)\n" + "─" * 50)
    passed = failed = 0

    def check(label, condition):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"   ✅ {label}")
        else:
            failed += 1
            print(f"   ❌ {label}")

    OWN_COLL = "ownership-test"   # logical; physical scope-ownership-test
    FNAME = "contested.txt"
    tmp = Path(tempfile.mkdtemp(prefix="aiprowler_own_"))
    fpath = tmp / FNAME
    fpath.write_text("CONTESTED document content owned by Alice. Shared work area.",
                     encoding="utf-8")

    def _resolver(_fp):
        return OWN_COLL

    def _index_as(user):
        """Index the file through the real pipeline AS `user`, with the SAME
        ownership gate the MCP layer will use (step-3 wiring). Returns (ok, note)."""
        # Build the purge gate exactly as the MCP index tool will: it asks
        # _can_purge_chunks(this user, existing chunk metas, owner_id). Owner id
        # is patched to our seeded owner (test users aren't in the real users.json).
        _orig = ap._owner_user_id
        ap._owner_user_id = lambda *a, **k: USER_OWNER["id"]
        try:
            owner_id = ap._owner_user_id()
            def _gate(existing_metas):
                return ap._can_purge_chunks(user, existing_metas, owner_id)
            rp.index_directory(str(tmp), recursive=False, quiet=True,
                               collection_resolver=_resolver,
                               indexer_user=user,
                               purge_gate=_gate)
            return (True, "")
        except TypeError as e:
            return (False, f"pipeline has no indexer_user/purge_gate param yet: {e}")
        finally:
            ap._owner_user_id = _orig

    def _chunks():
        client, ef = rp.get_chroma_client()
        phys = rp.chroma_collection_name(OWN_COLL)
        try:
            col = client.get_collection(name=phys, embedding_function=ef)
            got = col.get(include=["metadatas", "documents"])
            return got.get("metadatas", []) or [], got.get("documents", []) or []
        except Exception:
            return [], []

    try:
        # 1. Alice indexes.
        ok_a, note_a = _index_as(USER_A)
        if not ok_a:
            print(f"   ⚠️  {note_a}")
        metas, _ = _chunks()
        alice_owns = bool(metas) and all(
            m.get("indexed_by") == USER_A["id"] for m in metas)
        check("Alice's chunks stamped indexed_by == Alice", alice_owns)

        # 2. Bob attempts to re-index the SAME path → must be refused; Alice's
        #    content must survive.
        ok_b, note_b = _index_as(USER_B)
        if not ok_b:
            print(f"   ⚠️  {note_b}")
        metas2, docs2 = _chunks()
        alice_survived = any("CONTESTED" in d for d in docs2) and any(
            m.get("indexed_by") == USER_A["id"] for m in metas2)
        bob_did_not_take_over = not any(
            m.get("indexed_by") == USER_B["id"] for m in metas2)
        check("Alice's chunks SURVIVE Bob's re-index attempt", alice_survived)
        check("Bob did NOT take ownership of the path", bob_did_not_take_over)

        # 3. Alice re-indexes her own file → still hers.
        _index_as(USER_A)
        metas3, _ = _chunks()
        still_alice = bool(metas3) and all(
            m.get("indexed_by") == USER_A["id"] for m in metas3)
        check("Alice may re-index her own file", still_alice)

        # 4. Admin (custody) re-indexes Alice's file → ALLOWED, but Alice STAYS
        #    the owner (admin refresh must not steal ownership).
        ok_adm, note_adm = _index_as(USER_ADMIN)
        if not ok_adm:
            print(f"   ⚠️  {note_adm}")
        metas4, docs4 = _chunks()
        admin_refreshed = any("CONTESTED" in d for d in docs4)
        owner_preserved = bool(metas4) and all(
            m.get("indexed_by") == USER_A["id"] for m in metas4)
        check("Admin MAY re-index an employee's file (custody)", admin_refreshed)
        check("Original owner PRESERVED after admin re-index", owner_preserved)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        # Drop the test collection.
        try:
            client, _ = rp.get_chroma_client()
            client.delete_collection(name=rp.chroma_collection_name(OWN_COLL))
        except Exception:
            pass

    print("\n" + "─" * 50)
    print(f"   RESULT: {passed} passed, {failed} failed")
    if failed:
        print("   ⛔ OWNERSHIP PROTECTION NOT YET IN EFFECT "
              "(expected until step-3 wiring).")
        return False
    print("   ✅ OWNERSHIP PROTECTION HOLDS end-to-end.")
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
    elif arg in ("--direct-test", "direct-test", "--direct"):
        ok = cmd_direct_test()
        sys.exit(0 if ok else 1)
    elif arg in ("--owner-test", "owner-test", "--owner"):
        ok = cmd_owner_test()
        sys.exit(0 if ok else 1)
    elif arg in ("--admin-test", "admin-test", "--admin"):
        ok = cmd_admin_test()
        sys.exit(0 if ok else 1)
    elif arg in ("--ownership-test", "ownership-test", "--ownership"):
        ok = cmd_ownership_test()
        sys.exit(0 if ok else 1)
    elif arg in ("--cleanup", "cleanup"):
        cmd_cleanup()
    else:
        print(__doc__)
