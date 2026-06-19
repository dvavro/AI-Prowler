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

def _seed(client, phys_name):
    import chromadb
    ef = chromadb.utils.embedding_functions.DefaultEmbeddingFunction()
    col = client.get_or_create_collection(name=phys_name, embedding_function=ef)
    col.add(
        documents=["dummy"],
        metadatas=[{"filepath": f"/fake/{phys_name}/f.txt", "filename": "f.txt",
                    "extension": "txt", "parent_directory": phys_name,
                    "directory_chain": phys_name, "total_chunks": 1}],
        ids=[f"{phys_name}-0"],
    )

def _seed_all(client, mcp_mod):
    """Seed every physical collection that exists on a real server.
    Physical names are derived from slug ids (via _make_user_id + chroma_collection_name),
    NOT from bearer token keys."""
    import chromadb
    from rag_preprocessor import chroma_collection_name
    # Resolve each user to get their slug id, then build the physical collection name
    phys = {
        "owner":        chroma_collection_name(f"user:{mcp_mod._resolve_user(_USERS_DATA, _OWNER_TOK)['id']}"),
        "mgr_adm":      chroma_collection_name(f"user:{mcp_mod._resolve_user(_USERS_DATA, _MANAGER_ADM_TOK)['id']}"),
        "mgr_plain":    chroma_collection_name(f"user:{mcp_mod._resolve_user(_USERS_DATA, _MANAGER_PLAIN_TOK)['id']}"),
        "staff":        chroma_collection_name(f"user:{mcp_mod._resolve_user(_USERS_DATA, _STAFF_TOK)['id']}"),
        "crew_nopri":   chroma_collection_name(f"user:{mcp_mod._resolve_user(_USERS_DATA, _CREW_NOPRI_TOK)['id']}"),
        "crew_pri":     chroma_collection_name(f"user:{mcp_mod._resolve_user(_USERS_DATA, _CREW_PRI_TOK)['id']}"),
        "scope_sales":  "scope-role-sales",
        "scope_office": "scope-role-office",
        "shared":       "shared",
    }
    for name in phys.values():
        _seed(client, name)
    return phys


# ═════════════════════════════════════════════════════════════════════════════
# TABLE 1 — READ access via _scoped_collections_for_ctx
# ═════════════════════════════════════════════════════════════════════════════

class TestReadAccessMatrix:
    """
    Full matrix coverage for _scoped_collections_for_ctx.
    Every row in TABLE 1 gets positive AND negative assertions so a regression
    in either direction (gaining access or losing access) is caught.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch, mcp_mod):
        import gc
        import chromadb as _chromadb
        self.client = _make_chroma(tmp_path)
        self.phys   = _seed_all(self.client, mcp_mod)
        ef = _chromadb.utils.embedding_functions.DefaultEmbeddingFunction()

        import rag_preprocessor as rp
        monkeypatch.setattr(rp, "get_chroma_client", lambda: (self.client, ef))
        monkeypatch.setattr(mcp_mod, "get_chroma_client",
                            lambda: (self.client, ef), raising=False)
        monkeypatch.setattr(mcp_mod, "_load_users", lambda: _USERS_DATA)

        self.m = mcp_mod

        yield

        # Explicitly release the ChromaDB client so the Rust segment manager
        # closes its SQLite/HNSW file handles promptly. Without this, 65 tests
        # × ~65 leaked kernel handles = 4,000+ accumulated handles, which
        # exhausts the process limit long before the suite finishes.
        client = self.client
        self.client = None
        try:
            if hasattr(client, "clear_system_cache"):
                client.clear_system_cache()
        except Exception:
            pass
        del client
        gc.collect()

    def _cols(self, token):
        return {c.name for c in self.m._scoped_collections_for_ctx(_ctx(self.m, token))}

    # ── OWNER (David) ─────────────────────────────────────────────────────────

    def test_R01_owner_sees_own_private(self):
        assert self.phys["owner"] in self._cols(_OWNER_TOK)

    def test_R02_owner_sees_manager_adm_private(self):
        assert self.phys["mgr_adm"] in self._cols(_OWNER_TOK)

    def test_R03_owner_sees_manager_plain_private(self):
        assert self.phys["mgr_plain"] in self._cols(_OWNER_TOK)

    def test_R04_owner_sees_staff_private(self):
        assert self.phys["staff"] in self._cols(_OWNER_TOK)

    def test_R05_owner_sees_crew_pri_private(self):
        assert self.phys["crew_pri"] in self._cols(_OWNER_TOK)

    def test_R06_owner_sees_assigned_scope_sales(self):
        assert self.phys["scope_sales"] in self._cols(_OWNER_TOK)

    def test_R06b_owner_sees_assigned_scope_office(self):
        """Owner has two scopes; both must be visible."""
        assert self.phys["scope_office"] in self._cols(_OWNER_TOK)

    def test_R07_owner_sees_shared(self):
        assert self.phys["shared"] in self._cols(_OWNER_TOK)

    def test_R08_owner_sees_crew_nopri_private(self):
        """Owner sees all physical user: collections even when
        private_collection_enabled=False for that user — the collection
        exists on disk and the owner is the data custodian."""
        assert self.phys["crew_nopri"] in self._cols(_OWNER_TOK)

    # ── MANAGER with can_manage_users=True (Vicki) ────────────────────────────

    def test_R10_manager_adm_sees_own_private(self):
        assert self.phys["mgr_adm"] in self._cols(_MANAGER_ADM_TOK)

    def test_R11_manager_adm_sees_assigned_scope(self):
        assert self.phys["scope_sales"] in self._cols(_MANAGER_ADM_TOK)

    def test_R12_manager_adm_sees_shared(self):
        assert self.phys["shared"] in self._cols(_MANAGER_ADM_TOK)

    def test_R13_manager_adm_BLOCKED_from_owner_private(self):
        assert self.phys["owner"] not in self._cols(_MANAGER_ADM_TOK), (
            "SECURITY: manager (can_manage_users) must not browse owner private dir"
        )

    def test_R14_manager_adm_BLOCKED_from_staff_private(self):
        assert self.phys["staff"] not in self._cols(_MANAGER_ADM_TOK), (
            "SECURITY: manager must not browse other employees' private dirs"
        )

    def test_R15_manager_adm_BLOCKED_from_plain_manager_private(self):
        assert self.phys["mgr_plain"] not in self._cols(_MANAGER_ADM_TOK), (
            "SECURITY: manager must not browse another manager's private dir"
        )

    def test_R16_manager_adm_BLOCKED_from_unassigned_scope(self):
        assert self.phys["scope_office"] not in self._cols(_MANAGER_ADM_TOK)

    def test_R17_manager_adm_BLOCKED_from_crew_nopri_private(self):
        """Manager must not see crew member's private dir even if it exists."""
        assert self.phys["crew_nopri"] not in self._cols(_MANAGER_ADM_TOK)

    # ── MANAGER without can_manage_users (plain manager) ──────────────────────

    def test_R20_manager_plain_sees_own_private(self):
        assert self.phys["mgr_plain"] in self._cols(_MANAGER_PLAIN_TOK)

    def test_R21_manager_plain_sees_assigned_scope(self):
        assert self.phys["scope_sales"] in self._cols(_MANAGER_PLAIN_TOK)

    def test_R22_manager_plain_sees_shared(self):
        assert self.phys["shared"] in self._cols(_MANAGER_PLAIN_TOK)

    def test_R23_manager_plain_BLOCKED_from_owner_private(self):
        assert self.phys["owner"] not in self._cols(_MANAGER_PLAIN_TOK)

    def test_R24_manager_plain_BLOCKED_from_staff_private(self):
        assert self.phys["staff"] not in self._cols(_MANAGER_PLAIN_TOK)

    def test_R25_manager_plain_BLOCKED_from_unassigned_scope(self):
        assert self.phys["scope_office"] not in self._cols(_MANAGER_PLAIN_TOK)

    def test_R26_manager_plain_BLOCKED_from_crew_nopri_private(self):
        assert self.phys["crew_nopri"] not in self._cols(_MANAGER_PLAIN_TOK)

    # ── STAFF (Alice) ─────────────────────────────────────────────────────────

    def test_R30_staff_sees_own_private(self):
        assert self.phys["staff"] in self._cols(_STAFF_TOK)

    def test_R31_staff_sees_assigned_scope(self):
        assert self.phys["scope_sales"] in self._cols(_STAFF_TOK)

    def test_R32_staff_sees_shared(self):
        assert self.phys["shared"] in self._cols(_STAFF_TOK)

    def test_R33_staff_BLOCKED_from_owner_private(self):
        assert self.phys["owner"] not in self._cols(_STAFF_TOK)

    def test_R34_staff_BLOCKED_from_manager_private(self):
        assert self.phys["mgr_adm"] not in self._cols(_STAFF_TOK)

    def test_R35_staff_BLOCKED_from_unassigned_scope(self):
        assert self.phys["scope_office"] not in self._cols(_STAFF_TOK)

    def test_R36_staff_BLOCKED_from_crew_nopri_private(self):
        assert self.phys["crew_nopri"] not in self._cols(_STAFF_TOK)

    # ── FIELD CREW — private_collection_enabled=False (Bob NoPri) ────────────

    def test_R40_crew_nopri_sees_shared(self):
        assert self.phys["shared"] in self._cols(_CREW_NOPRI_TOK)

    def test_R41_crew_nopri_has_NO_private_dir(self):
        assert self.phys["crew_nopri"] not in self._cols(_CREW_NOPRI_TOK)

    def test_R42_crew_nopri_BLOCKED_from_owner_private(self):
        assert self.phys["owner"] not in self._cols(_CREW_NOPRI_TOK)

    def test_R43_crew_nopri_BLOCKED_from_staff_private(self):
        assert self.phys["staff"] not in self._cols(_CREW_NOPRI_TOK)

    def test_R44_crew_nopri_BLOCKED_from_any_scope(self):
        assert self.phys["scope_sales"] not in self._cols(_CREW_NOPRI_TOK)

    # ── FIELD CREW — private_collection_enabled=True (admin-enabled) ─────────

    def test_R50_crew_pri_sees_own_private(self):
        assert self.phys["crew_pri"] in self._cols(_CREW_PRI_TOK)

    def test_R51_crew_pri_sees_shared(self):
        assert self.phys["shared"] in self._cols(_CREW_PRI_TOK)

    def test_R52_crew_pri_BLOCKED_from_owner_private(self):
        assert self.phys["owner"] not in self._cols(_CREW_PRI_TOK)

    def test_R53_crew_pri_BLOCKED_from_staff_private(self):
        assert self.phys["staff"] not in self._cols(_CREW_PRI_TOK)

    def test_R54_crew_pri_BLOCKED_from_any_scope(self):
        assert self.phys["scope_sales"] not in self._cols(_CREW_PRI_TOK)

    # ── FAIL-CLOSED — owner_id unknown ────────────────────────────────────────

    def test_R60_fail_closed_owner_id_none_owner_still_sees_all(self, monkeypatch):
        """owner_id unknown has no effect on the owner themselves."""
        monkeypatch.setattr(self.m, "_owner_user_id", lambda ud=None: None)
        names = self._cols(_OWNER_TOK)
        assert self.phys["owner"] in names
        assert self.phys["staff"] in names

    def test_R61_fail_closed_owner_id_none_manager_still_blocked(self, monkeypatch):
        """When owner_id unknown, manager must NOT gain access to owner private."""
        monkeypatch.setattr(self.m, "_owner_user_id", lambda ud=None: None)
        assert self.phys["owner"] not in self._cols(_MANAGER_ADM_TOK)


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
