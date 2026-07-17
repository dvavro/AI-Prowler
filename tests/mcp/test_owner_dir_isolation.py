"""
test_owner_dir_isolation.py -- AI-Prowler v7.0.1 Security Regression Tests
===========================================================================
Full coverage matrix for _scoped_collections_for_ctx (READ access) and
_can_manage_user_data (ADMIN/DELETE access).

DESIGN RULES (confirmed with David, v7.0.1)
--------------------------------------------
READ access (browsing tools: list_indexed_directories, search_documents, etc.)
  - Every user sees ONLY their own private dir (if private_collection_enabled=True)
  - Owner ALSO sees every other user's private dir (data custodian)
  - can_manage_users flag grants ADMIN rights, NOT read-browse rights
  - field_crew with private_collection_enabled=False gets no private dir
  - field_crew with private_collection_enabled=True gets their own private dir

ADMIN/DELETE access (_can_manage_user_data)
  - Owner: may manage/delete anyone's data
  - Manager with can_manage_users=True: may manage any EMPLOYEE's data,
    but NEVER the owner's (fail-closed if owner_id unknown)
  - Manager without can_manage_users: no management rights
  - Staff / field_crew: no management rights

TABLE 1 — READ access matrix (physical collections)
-----------------------------------------------------
User   Role        priv_enabled  own  owner  other_emp  scope  shared  Tests
David  owner       True          YES  YES    YES        YES    YES     R01-R08
Vicki  manager     True          YES  NO     NO         YES    YES     R10-R17
Plain  manager     True          YES  NO     NO         YES    YES     R20-R26
Alice  staff       True          YES  NO     NO         YES    YES     R30-R36
Bob    field_crew  False         NO   NO     NO         NO     YES     R40-R44
Bob*   field_crew  True          YES  NO     NO         NO     YES     R50-R54
Fail-closed (owner_id=None)                                            R60-R61

TABLE 2 — ADMIN/DELETE access matrix (_can_manage_user_data)
-------------------------------------------------------------
Actor              Target         Expected  Test
Owner              own            ALLOW     D01
Owner              manager+flag   ALLOW     D02
Owner              staff          ALLOW     D03
Owner              field_crew     ALLOW     D04
Owner              manager plain  ALLOW     D05
Manager+flag       staff          ALLOW     D10
Manager+flag       field_crew     ALLOW     D11
Manager+flag       own            ALLOW     D12
Manager+flag       plain manager  ALLOW     D15
Manager+flag       owner          DENY      D13 (+ reason check)
Manager+flag       owner_id=None  DENY      D14 (fail-closed)
Manager (no flag)  staff          DENY      D20
Manager (no flag)  own            DENY      D21
Manager (no flag)  field_crew     DENY      D22
Staff              owner          DENY      D30
Staff              manager        DENY      D31
Staff              field_crew     DENY      D32
Staff              own            DENY      D33
field_crew         owner          DENY      D40
field_crew         staff          DENY      D41
field_crew         own            DENY      D42
None actor         staff          DENY      D50

Run:
    py -m pytest tests/mcp/test_owner_dir_isolation.py -v
"""

import sys
import pytest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


# ── Session fixture: import mcp module once ──────────────────────────────────

@pytest.fixture(scope="session")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


# ── User tokens ───────────────────────────────────────────────────────────────

_OWNER_TOK        = "tok-owner-david"
_MANAGER_ADM_TOK  = "tok-manager-vicki"    # can_manage_users=True
_MANAGER_PLAIN_TOK= "tok-manager-plain"    # can_manage_users=False
_STAFF_TOK        = "tok-staff-alice"
_CREW_NOPRI_TOK   = "tok-crew-bob-nopri"   # private_collection_enabled=False
_CREW_PRI_TOK     = "tok-crew-bob-pri"     # private_collection_enabled=True (admin-enabled)

_USERS_DATA = {
    "users": {
        _OWNER_TOK: {
            "name": "David Owner", "role": "owner", "status": "active",
            "scopes": ["sales", "office"],
            "private_collection_enabled": True,
            "can_manage_users": True,
        },
        _MANAGER_ADM_TOK: {
            "name": "Vicki Manager", "role": "manager", "status": "active",
            "scopes": ["sales"],
            "private_collection_enabled": True,
            "can_manage_users": True,
        },
        _MANAGER_PLAIN_TOK: {
            "name": "Plain Manager", "role": "manager", "status": "active",
            "scopes": ["sales"],
            "private_collection_enabled": True,
            "can_manage_users": False,
        },
        _STAFF_TOK: {
            "name": "Alice Staff", "role": "staff", "status": "active",
            "scopes": ["sales"],
            "private_collection_enabled": True,
            "can_manage_users": False,
        },
        _CREW_NOPRI_TOK: {
            "name": "Bob Crew NoPri", "role": "field_crew", "status": "active",
            "scopes": [],
            "private_collection_enabled": False,
            "can_manage_users": False,
        },
        _CREW_PRI_TOK: {
            "name": "Bob Crew Pri", "role": "field_crew", "status": "active",
            "scopes": [],
            "private_collection_enabled": True,
            "can_manage_users": False,
        },
    }
}


# ── ctx stub ──────────────────────────────────────────────────────────────────

class _FakeCtx:
    def __init__(self, user):
        self.request_context = _RC(user)
class _RC:
    def __init__(self, u): self.request = _Req(u)
class _Req:
    def __init__(self, u): self.state = _St(u)
class _St:
    def __init__(self, u): self.user = u

def _ctx(mcp_mod, token):
    user = mcp_mod._resolve_user(_USERS_DATA, token)
    assert user is not None, f"Token {token!r} not in _USERS_DATA"
    return _FakeCtx(user)


# ── ChromaDB helpers ──────────────────────────────────────────────────────────

def _make_chroma(tmp_path):
    import chromadb
    return chromadb.Client(chromadb.config.Settings(
        is_persistent=True,
        persist_directory=str(tmp_path),
        anonymized_telemetry=False,
    ))

def _seed_one(collection, scope_value, key):
    collection.add(
        documents=["dummy"],
        metadatas=[{"filepath": f"/fake/{key}/f.txt", "filename": "f.txt",
                    "extension": "txt", "parent_directory": key,
                    "directory_chain": key, "total_chunks": 1,
                    "scope": scope_value}],
        ids=[f"{key}-0"],
    )

def _seed_all(client, mcp_mod):
    """SCOPE_SIMPLIFICATION_SPEC.md section 3.7 (Phase 7 cutover, query-side,
    2026-07-17): seeds ONE physical collection now, with every chunk tagged
    via "scope" metadata instead of being split across many physical
    collections. Returns {key: scope_value} so tests can assert on scope
    strings directly."""
    import chromadb
    from rag_preprocessor import COLLECTION_NAME
    ef = chromadb.utils.embedding_functions.DefaultEmbeddingFunction()
    coll = client.get_or_create_collection(name=COLLECTION_NAME, embedding_function=ef)

    scopes = {
        "owner":        f"private:{mcp_mod._resolve_user(_USERS_DATA, _OWNER_TOK)['id']}",
        "mgr_adm":      f"private:{mcp_mod._resolve_user(_USERS_DATA, _MANAGER_ADM_TOK)['id']}",
        "mgr_plain":    f"private:{mcp_mod._resolve_user(_USERS_DATA, _MANAGER_PLAIN_TOK)['id']}",
        "staff":        f"private:{mcp_mod._resolve_user(_USERS_DATA, _STAFF_TOK)['id']}",
        "crew_nopri":   f"private:{mcp_mod._resolve_user(_USERS_DATA, _CREW_NOPRI_TOK)['id']}",
        "crew_pri":     f"private:{mcp_mod._resolve_user(_USERS_DATA, _CREW_PRI_TOK)['id']}",
        "scope_sales":  "sales",
        "scope_office": "office",
        "shared":       "shared",
    }
    for key, scope_value in scopes.items():
        _seed_one(coll, scope_value, key)
    return scopes


# ═════════════════════════════════════════════════════════════════════════════
# TABLE 1 — READ access via _scoped_collections_for_ctx
#
# SUPERSEDED 2026-07-16/17 (SCOPE_SIMPLIFICATION_SPEC.md section 3.7, Phase 7
# cutover): the original TABLE 1 documented an owner/can_manage_users
# elevation carve-out ("Owner ALSO sees every other user's private dir (data
# custodian)") that browsed every team member's role/private PHYSICAL
# collection. That whole mechanism is gone -- there is one physical
# collection now, access is enforced by a "scope" metadata where-filter, and
# _allowed_scopes()'s own direct product decision (2026-07-16, tested
# separately in test_allowed_scopes.py) is NO role-based elevation, ever:
# every role -- including owner -- gets the IDENTICAL formula: shared +
# their own assigned scopes + their own private scope (if enabled). This
# replacement tests that formula end-to-end: querying the single collection
# with the where-filter _scoped_collections_for_ctx returns must actually
# retrieve only the scope-tagged chunks the caller should see.
# ═════════════════════════════════════════════════════════════════════════════

class TestReadAccessMatrix:
    """End-to-end coverage: _scoped_collections_for_ctx's where-filter,
    applied to a real .get() call against the single seeded collection,
    returns exactly the scope-tagged chunks each user should see -- no
    more, no less. Every assertion is a real ChromaDB query, not just a
    check of the filter's shape."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch, mcp_mod):
        import gc
        import chromadb as _chromadb
        self.client = _make_chroma(tmp_path)
        self.scopes = _seed_all(self.client, mcp_mod)
        ef = _chromadb.utils.embedding_functions.DefaultEmbeddingFunction()

        import rag_preprocessor as rp
        monkeypatch.setattr(rp, "get_chroma_client", lambda: (self.client, ef))
        monkeypatch.setattr(mcp_mod, "get_chroma_client",
                            lambda: (self.client, ef), raising=False)
        monkeypatch.setattr(mcp_mod, "_load_users", lambda: _USERS_DATA)

        self.m = mcp_mod

        yield

        # Explicitly release the ChromaDB client so the Rust segment manager
        # closes its SQLite/HNSW file handles promptly. Without this, many
        # tests × leaked kernel handles exhausts the process limit before
        # the suite finishes.
        client = self.client
        self.client = None
        try:
            if hasattr(client, "clear_system_cache"):
                client.clear_system_cache()
        except Exception:
            pass
        del client
        gc.collect()

    def _visible_keys(self, token):
        """Return the set of seed KEYS (owner/mgr_adm/.../shared) visible to
        this token, by actually querying the single collection with the
        where-filter _scoped_collections_for_ctx returns."""
        coll, where_filter = self.m._scoped_collections_for_ctx(_ctx(self.m, token))
        kwargs = {"include": ["metadatas"]}
        if where_filter:
            kwargs["where"] = where_filter
        result = coll.get(**kwargs)
        visible_scopes = {m.get("scope") for m in result.get("metadatas", [])}
        return {key for key, scope in self.scopes.items() if scope in visible_scopes}

    # ── OWNER (David) -- no more elevation; identical formula as everyone ────

    def test_R01_owner_sees_own_private(self):
        assert "owner" in self._visible_keys(_OWNER_TOK)

    def test_R02_owner_no_longer_sees_manager_adm_private(self):
        """The core behavior change this cutover documents: owner no
        longer has custody-browse access to another user's private
        content via search tools."""
        assert "mgr_adm" not in self._visible_keys(_OWNER_TOK)

    def test_R03_owner_no_longer_sees_manager_plain_private(self):
        assert "mgr_plain" not in self._visible_keys(_OWNER_TOK)

    def test_R04_owner_no_longer_sees_staff_private(self):
        assert "staff" not in self._visible_keys(_OWNER_TOK)

    def test_R05_owner_no_longer_sees_crew_pri_private(self):
        assert "crew_pri" not in self._visible_keys(_OWNER_TOK)

    def test_R06_owner_sees_own_assigned_scope_sales(self):
        assert "scope_sales" in self._visible_keys(_OWNER_TOK)

    def test_R06b_owner_sees_own_assigned_scope_office(self):
        assert "scope_office" in self._visible_keys(_OWNER_TOK)

    def test_R07_owner_sees_shared(self):
        assert "shared" in self._visible_keys(_OWNER_TOK)

    def test_R08_owner_no_longer_sees_crew_nopri_private(self):
        assert "crew_nopri" not in self._visible_keys(_OWNER_TOK)

    # ── MANAGER with can_manage_users=True (Vicki) — same formula, unaffected
    #    by the can_manage_users flag (that flag only ever gated ADMIN/DELETE
    #    rights via _can_manage_user_data, TABLE 2 below -- never read/browse
    #    rights, even before this cutover) ─────────────────────────────────

    def test_R10_manager_adm_sees_own_private(self):
        assert "mgr_adm" in self._visible_keys(_MANAGER_ADM_TOK)

    def test_R11_manager_adm_sees_assigned_scope(self):
        assert "scope_sales" in self._visible_keys(_MANAGER_ADM_TOK)

    def test_R12_manager_adm_sees_shared(self):
        assert "shared" in self._visible_keys(_MANAGER_ADM_TOK)

    def test_R13_manager_adm_BLOCKED_from_owner_private(self):
        assert "owner" not in self._visible_keys(_MANAGER_ADM_TOK), (
            "SECURITY: manager (can_manage_users) must not browse owner private dir"
        )

    def test_R14_manager_adm_BLOCKED_from_staff_private(self):
        assert "staff" not in self._visible_keys(_MANAGER_ADM_TOK), (
            "SECURITY: manager must not browse other employees' private dirs"
        )

    def test_R15_manager_adm_BLOCKED_from_plain_manager_private(self):
        assert "mgr_plain" not in self._visible_keys(_MANAGER_ADM_TOK), (
            "SECURITY: manager must not browse another manager's private dir"
        )

    def test_R16_manager_adm_BLOCKED_from_unassigned_scope(self):
        assert "scope_office" not in self._visible_keys(_MANAGER_ADM_TOK)

    def test_R17_manager_adm_BLOCKED_from_crew_nopri_private(self):
        assert "crew_nopri" not in self._visible_keys(_MANAGER_ADM_TOK)

    # ── MANAGER without can_manage_users (plain manager) ──────────────────────

    def test_R20_manager_plain_sees_own_private(self):
        assert "mgr_plain" in self._visible_keys(_MANAGER_PLAIN_TOK)

    def test_R21_manager_plain_sees_assigned_scope(self):
        assert "scope_sales" in self._visible_keys(_MANAGER_PLAIN_TOK)

    def test_R22_manager_plain_sees_shared(self):
        assert "shared" in self._visible_keys(_MANAGER_PLAIN_TOK)

    def test_R23_manager_plain_BLOCKED_from_owner_private(self):
        assert "owner" not in self._visible_keys(_MANAGER_PLAIN_TOK)

    def test_R24_manager_plain_BLOCKED_from_staff_private(self):
        assert "staff" not in self._visible_keys(_MANAGER_PLAIN_TOK)

    def test_R25_manager_plain_BLOCKED_from_unassigned_scope(self):
        assert "scope_office" not in self._visible_keys(_MANAGER_PLAIN_TOK)

    def test_R26_manager_plain_BLOCKED_from_crew_nopri_private(self):
        assert "crew_nopri" not in self._visible_keys(_MANAGER_PLAIN_TOK)

    # ── STAFF (Alice) ─────────────────────────────────────────────────────────

    def test_R30_staff_sees_own_private(self):
        assert "staff" in self._visible_keys(_STAFF_TOK)

    def test_R31_staff_sees_assigned_scope(self):
        assert "scope_sales" in self._visible_keys(_STAFF_TOK)

    def test_R32_staff_sees_shared(self):
        assert "shared" in self._visible_keys(_STAFF_TOK)

    def test_R33_staff_BLOCKED_from_owner_private(self):
        assert "owner" not in self._visible_keys(_STAFF_TOK)

    def test_R34_staff_BLOCKED_from_manager_private(self):
        assert "mgr_adm" not in self._visible_keys(_STAFF_TOK)

    def test_R35_staff_BLOCKED_from_unassigned_scope(self):
        assert "scope_office" not in self._visible_keys(_STAFF_TOK)

    def test_R36_staff_BLOCKED_from_crew_nopri_private(self):
        assert "crew_nopri" not in self._visible_keys(_STAFF_TOK)

    # ── FIELD CREW — private_collection_enabled=False (Bob NoPri) ────────────

    def test_R40_crew_nopri_sees_shared(self):
        assert "shared" in self._visible_keys(_CREW_NOPRI_TOK)

    def test_R41_crew_nopri_has_NO_private_dir(self):
        assert "crew_nopri" not in self._visible_keys(_CREW_NOPRI_TOK)

    def test_R42_crew_nopri_BLOCKED_from_owner_private(self):
        assert "owner" not in self._visible_keys(_CREW_NOPRI_TOK)

    def test_R43_crew_nopri_BLOCKED_from_staff_private(self):
        assert "staff" not in self._visible_keys(_CREW_NOPRI_TOK)

    def test_R44_crew_nopri_BLOCKED_from_any_scope(self):
        assert "scope_sales" not in self._visible_keys(_CREW_NOPRI_TOK)

    # ── FIELD CREW — private_collection_enabled=True (admin-enabled) ─────────

    def test_R50_crew_pri_sees_own_private(self):
        assert "crew_pri" in self._visible_keys(_CREW_PRI_TOK)

    def test_R51_crew_pri_sees_shared(self):
        assert "shared" in self._visible_keys(_CREW_PRI_TOK)

    def test_R52_crew_pri_BLOCKED_from_owner_private(self):
        assert "owner" not in self._visible_keys(_CREW_PRI_TOK)

    def test_R53_crew_pri_BLOCKED_from_staff_private(self):
        assert "staff" not in self._visible_keys(_CREW_PRI_TOK)

    def test_R54_crew_pri_BLOCKED_from_any_scope(self):
        assert "scope_sales" not in self._visible_keys(_CREW_PRI_TOK)

    # ── owner_id no longer relevant here at all ───────────────────────────────
    # The old fail-closed owner_id tests (R60/R61) tested a mechanism inside
    # the removed elevation carve-out -- _scoped_collections_for_ctx no
    # longer calls _owner_user_id() at all. This replacement locks in that
    # removal explicitly rather than silently dropping the coverage.

    def test_R60_owner_user_id_no_longer_consulted(self, monkeypatch):
        """Regardless of what _owner_user_id() would return -- including
        None -- results must be identical, since _scoped_collections_for_ctx
        no longer calls it."""
        monkeypatch.setattr(
            self.m, "_owner_user_id",
            lambda ud=None: (_ for _ in ()).throw(
                AssertionError("_owner_user_id should not be called")))
        # Must not raise for any of the six users.
        for tok in (_OWNER_TOK, _MANAGER_ADM_TOK, _MANAGER_PLAIN_TOK,
                    _STAFF_TOK, _CREW_NOPRI_TOK, _CREW_PRI_TOK):
            self._visible_keys(tok)



# ═════════════════════════════════════════════════════════════════════════════
# TABLE 2 — ADMIN/DELETE access via _can_manage_user_data
# ═════════════════════════════════════════════════════════════════════════════

class TestAdminDeleteMatrix:
    """
    Full matrix coverage for _can_manage_user_data.
    Tests both ALLOW and DENY cells so regressions in either direction are caught.
    """

    OWNER_ID      = _OWNER_TOK
    MANAGER_ID    = _MANAGER_ADM_TOK
    MGR_PLAIN_ID  = _MANAGER_PLAIN_TOK
    STAFF_ID      = _STAFF_TOK
    CREW_ID       = _CREW_NOPRI_TOK

    @pytest.fixture(autouse=True)
    def _users(self, mcp_mod):
        self.m = mcp_mod
        self.owner      = mcp_mod._resolve_user(_USERS_DATA, _OWNER_TOK)
        self.mgr_adm    = mcp_mod._resolve_user(_USERS_DATA, _MANAGER_ADM_TOK)
        self.mgr_plain  = mcp_mod._resolve_user(_USERS_DATA, _MANAGER_PLAIN_TOK)
        self.staff      = mcp_mod._resolve_user(_USERS_DATA, _STAFF_TOK)
        self.crew       = mcp_mod._resolve_user(_USERS_DATA, _CREW_NOPRI_TOK)

    def _can(self, actor, target_id):
        allowed, _ = self.m._can_manage_user_data(actor, target_id, self.OWNER_ID)
        return allowed

    # ── Owner: may manage anyone ──────────────────────────────────────────────

    def test_D01_owner_can_manage_own_data(self):
        assert self._can(self.owner, self.OWNER_ID)

    def test_D02_owner_can_manage_manager_adm_data(self):
        assert self._can(self.owner, self.MANAGER_ID)

    def test_D03_owner_can_manage_staff_data(self):
        assert self._can(self.owner, self.STAFF_ID)

    def test_D04_owner_can_manage_crew_data(self):
        assert self._can(self.owner, self.CREW_ID)

    def test_D05_owner_can_manage_manager_plain_data(self):
        assert self._can(self.owner, self.MGR_PLAIN_ID)

    # ── Manager with can_manage_users=True ────────────────────────────────────

    def test_D10_manager_adm_can_manage_staff_data(self):
        """Offboarding: manager cleans up a departed staff member's private dir."""
        assert self._can(self.mgr_adm, self.STAFF_ID)

    def test_D11_manager_adm_can_manage_crew_data(self):
        assert self._can(self.mgr_adm, self.CREW_ID)

    def test_D12_manager_adm_can_manage_own_data(self):
        assert self._can(self.mgr_adm, self.MANAGER_ID)

    def test_D15_manager_adm_can_manage_plain_manager_data(self):
        """Manager+flag may clean up any other employee including other managers."""
        assert self._can(self.mgr_adm, self.MGR_PLAIN_ID)

    def test_D13_manager_adm_CANNOT_manage_owner_data(self):
        """Critical: manager must never delete the owner's private data."""
        allowed, reason = self.m._can_manage_user_data(
            self.mgr_adm, self.OWNER_ID, self.OWNER_ID)
        assert not allowed, "SECURITY: manager must not be able to delete owner's data"
        assert any(w in reason.lower() for w in ("owner", "protected")), (
            f"Reason should mention 'owner' or 'protected', got: {reason!r}"
        )

    def test_D14_manager_adm_denied_when_owner_id_unknown(self):
        """Fail-closed: owner_id unknown -> manager denied to avoid risk."""
        allowed, reason = self.m._can_manage_user_data(
            self.mgr_adm, self.STAFF_ID, owner_id=None)
        assert not allowed
        assert "unknown" in reason.lower() or "fail" in reason.lower()

    # ── Manager WITHOUT can_manage_users ──────────────────────────────────────

    def test_D20_manager_plain_CANNOT_manage_staff_data(self):
        assert not self._can(self.mgr_plain, self.STAFF_ID)

    def test_D21_manager_plain_CANNOT_manage_own_data(self):
        """Even a manager cannot manage their own data without the flag."""
        assert not self._can(self.mgr_plain, self.MGR_PLAIN_ID)

    def test_D22_manager_plain_CANNOT_manage_crew_data(self):
        assert not self._can(self.mgr_plain, self.CREW_ID)

    # ── Staff: no management rights ───────────────────────────────────────────

    def test_D30_staff_CANNOT_manage_owner_data(self):
        assert not self._can(self.staff, self.OWNER_ID)

    def test_D31_staff_CANNOT_manage_manager_data(self):
        assert not self._can(self.staff, self.MANAGER_ID)

    def test_D32_staff_CANNOT_manage_crew_data(self):
        assert not self._can(self.staff, self.CREW_ID)

    def test_D33_staff_CANNOT_manage_own_data(self):
        assert not self._can(self.staff, self.STAFF_ID)

    # ── field_crew: no management rights ─────────────────────────────────────

    def test_D40_crew_CANNOT_manage_owner_data(self):
        assert not self._can(self.crew, self.OWNER_ID)

    def test_D41_crew_CANNOT_manage_staff_data(self):
        assert not self._can(self.crew, self.STAFF_ID)

    def test_D42_crew_CANNOT_manage_own_data(self):
        assert not self._can(self.crew, self.CREW_ID)

    # ── None actor ────────────────────────────────────────────────────────────

    def test_D50_none_actor_cannot_manage_anything(self):
        assert not self._can(None, self.STAFF_ID)
