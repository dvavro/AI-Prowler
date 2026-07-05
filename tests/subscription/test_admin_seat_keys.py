"""
tests/subscription/test_admin_seat_keys.py
==========================================
Tests for Admin tab seat key validation and assignment flow.

Key formats (from provision.js):
  AP-BIZ-{8hex}-{8hex}           business parent  e.g. AP-BIZ-680E09EA-CA38123E
  AP-PERS-{8hex}-{8hex}          personal key     e.g. AP-PERS-16C50BFD-4FB265F4
  AP-CHLD-{8hex}-{8hex}          child seat key   e.g. AP-CHLD-3F2A1B4C-9D8E7F6A
  {biz_key}-S{NNN}               placeholder ID   e.g. AP-BIZ-680E09EA-CA38123E-S001
                                  (written locally by activate_from_payload() before
                                   Sync Seats fetches real AP-CHLD- keys from Worker)

Admin tab seat assignment rules (v8.2.0):
  - Placeholder IDs (-S###) → allowed with warning (not validated against Worker)
  - AP-CHLD- keys           → validated against Worker /license/validate
  - AP-PERS- keys           → validated against Worker /license/validate
  - Empty string            → always allowed (no seat assigned)
  - Bad format              → hard rejection
"""
import json
import re
import pytest
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers — replicate the key format logic from provision.js in Python
# ---------------------------------------------------------------------------

def make_biz_key(hex1="680E09EA", hex2="CA38123E"):
    return f"AP-BIZ-{hex1}-{hex2}"

def make_chld_key(hex1="3F2A1B4C", hex2="9D8E7F6A"):
    return f"AP-CHLD-{hex1}-{hex2}"

def make_pers_key(hex1="16C50BFD", hex2="4FB265F4"):
    return f"AP-PERS-{hex1}-{hex2}"

def make_seat_id(biz_key, seat_num=1):
    """Mirrors provision.js: `${licenseKey}-S${String(i+1).padStart(3,'0')}`"""
    return f"{biz_key}-S{str(seat_num).zfill(3)}"


# The regex used in rag_gui.py _admin_validate_child_key
PLACEHOLDER_RE = re.compile(
    r'^AP-BIZ-[0-9A-F]+-[0-9A-F]+-S\d+$', re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Unit tests — key format validation regex
# ---------------------------------------------------------------------------

class TestKeyFormats:
    """Verify key format regexes match provision.js output."""

    def test_biz_key_format(self):
        assert re.match(r'^AP-BIZ-[0-9A-F]{8}-[0-9A-F]{8}$', make_biz_key())

    def test_chld_key_format(self):
        assert re.match(r'^AP-CHLD-[0-9A-F]{8}-[0-9A-F]{8}$', make_chld_key())

    def test_pers_key_format(self):
        assert re.match(r'^AP-PERS-[0-9A-F]{8}-[0-9A-F]{8}$', make_pers_key())

    def test_placeholder_format_seat_001(self):
        ph = make_seat_id(make_biz_key(), 1)
        assert ph == "AP-BIZ-680E09EA-CA38123E-S001"
        assert PLACEHOLDER_RE.match(ph)

    def test_placeholder_format_seat_006(self):
        ph = make_seat_id(make_biz_key(), 6)
        assert ph == "AP-BIZ-680E09EA-CA38123E-S006"
        assert PLACEHOLDER_RE.match(ph)

    def test_chld_key_not_placeholder(self):
        """AP-CHLD- keys must NOT match the placeholder regex."""
        assert not PLACEHOLDER_RE.match(make_chld_key())

    def test_pers_key_not_placeholder(self):
        assert not PLACEHOLDER_RE.match(make_pers_key())

    def test_biz_key_alone_not_placeholder(self):
        assert not PLACEHOLDER_RE.match(make_biz_key())

    def test_empty_not_placeholder(self):
        assert not PLACEHOLDER_RE.match("")

    def test_all_six_seat_ids_match_placeholder(self):
        """All 6 seat IDs from a fresh 6-seat business install match
        placeholder regex — they're pre-sync local placeholders."""
        biz = make_biz_key()
        for n in range(1, 7):
            sid = make_seat_id(biz, n)
            assert PLACEHOLDER_RE.match(sid), \
                f"seat_id {sid} should match placeholder regex"


# ---------------------------------------------------------------------------
# Unit tests — _admin_validate_child_key logic (pure, no GUI)
# ---------------------------------------------------------------------------

def _validate_child_key(child_key, worker_response=None, http_error_code=None):
    """Pure Python replica of rag_gui.py _admin_validate_child_key logic."""
    if not child_key:
        return (True, "No seat assigned.")

    if PLACEHOLDER_RE.match(child_key):
        return (None,
                "This is a placeholder seat ID (not yet synced from the server).\n"
                "Click 'Sync Seats' to fetch real child keys from the license server.\n"
                "You can assign this placeholder seat now — the key will be "
                "updated automatically after syncing.")

    if http_error_code:
        return (False, f"Validation HTTP error {http_error_code} (key not accepted).")
    if worker_response is None:
        return (None, "Could not reach the license server (network error). "
                      "You can assign the seat now and it will be re-validated later.")
    if worker_response.get("valid") is True:
        exp = worker_response.get("expires_at", "")
        return (True, f"Valid child seat{(' — expires ' + exp) if exp else ''}.")
    reason = worker_response.get("reason", "invalid")
    msg = worker_response.get("message", "")
    return (False, f"License key rejected: {reason}. {msg}".strip())


class TestAdminValidateChildKey:

    def test_empty_key_always_allowed(self):
        ok, msg = _validate_child_key("")
        assert ok is True

    def test_placeholder_returns_none(self):
        """Placeholder IDs return (None,...) not (False,...) so caller
        gets a 'proceed anyway?' dialog, not a hard block."""
        biz = make_biz_key()
        for n in range(1, 7):
            ok, msg = _validate_child_key(make_seat_id(biz, n))
            assert ok is None, f"Placeholder seat {n} should return None not False"
            assert "placeholder" in msg.lower()
            assert "Sync Seats" in msg

    def test_valid_chld_key_passes(self):
        resp = {"valid": True, "expires_at": "2027-07-01T00:00:00Z"}
        ok, msg = _validate_child_key(make_chld_key(), worker_response=resp)
        assert ok is True
        assert "Valid" in msg

    def test_bad_format_chld_key_rejected(self):
        resp = {"valid": False, "reason": "bad_format"}
        ok, msg = _validate_child_key(make_chld_key(), worker_response=resp)
        assert ok is False
        assert "bad_format" in msg

    def test_suspended_chld_key_rejected(self):
        resp = {"valid": False, "reason": "suspended"}
        ok, msg = _validate_child_key(make_chld_key(), worker_response=resp)
        assert ok is False
        assert "suspended" in msg

    def test_not_found_rejected(self):
        resp = {"valid": False, "reason": "not_found"}
        ok, msg = _validate_child_key(make_chld_key(), worker_response=resp)
        assert ok is False

    def test_network_error_returns_none(self):
        ok, msg = _validate_child_key(make_chld_key(), worker_response=None)
        assert ok is None
        assert "license server" in msg.lower()

    def test_http_error_returns_false(self):
        ok, msg = _validate_child_key(make_chld_key(), http_error_code=404)
        assert ok is False

    def test_pers_key_validated_not_skipped(self):
        """AP-PERS- keys are real keys — must NOT match placeholder regex,
        so they go through Worker validation."""
        pers = make_pers_key()
        assert not PLACEHOLDER_RE.match(pers)
        resp = {"valid": True}
        ok, msg = _validate_child_key(pers, worker_response=resp)
        assert ok is True


# ---------------------------------------------------------------------------
# Integration — license_seats.json written by activate_from_payload
# ---------------------------------------------------------------------------

class TestLicenseSeatJsonFormat:

    def test_seat_ids_match_provision_js_format(self):
        """Placeholder IDs written by activate_from_payload() must match
        provision.js seatId format: `${licenseKey}-S${padded}`"""
        biz_key = make_biz_key()
        seat_records = [
            {"seat_id": f"{biz_key}-S{str(i+1).zfill(3)}", "status": "unassigned"}
            for i in range(6)
        ]
        for i, rec in enumerate(seat_records):
            expected = f"{biz_key}-S{str(i+1).zfill(3)}"
            assert rec["seat_id"] == expected
            assert PLACEHOLDER_RE.match(rec["seat_id"])

    def test_seats_json_round_trip(self, tmp_path):
        biz_key = make_biz_key()
        seats_data = {
            "license_key":      biz_key,
            "seats_total":      6,
            "seats_assigned":   0,
            "seats_unassigned": 6,
            "seats": [
                {"seat_id": f"{biz_key}-S{str(i+1).zfill(3)}",
                 "status": "unassigned", "assigned_to": None}
                for i in range(6)
            ],
        }
        f = tmp_path / "license_seats.json"
        f.write_text(json.dumps(seats_data), encoding="utf-8")
        loaded = json.loads(f.read_text(encoding="utf-8"))
        assert loaded["seats_total"] == 6
        assert len(loaded["seats"]) == 6
        assert loaded["seats"][0]["seat_id"] == f"{biz_key}-S001"
        assert loaded["seats"][5]["seat_id"] == f"{biz_key}-S006"

    def test_real_chld_keys_not_placeholder(self):
        """After Sync Seats, child_license_key values (AP-CHLD-...)
        must NOT match the placeholder regex."""
        chld_keys = [f"AP-CHLD-{i:08X}-{i+1:08X}" for i in range(6)]
        for k in chld_keys:
            assert not PLACEHOLDER_RE.match(k)
            assert re.match(r'^AP-CHLD-[0-9A-F]{8}-[0-9A-F]{8}$', k, re.IGNORECASE)


# ---------------------------------------------------------------------------
# End-to-end flow tests — full seat assignment lifecycle
# ---------------------------------------------------------------------------

class TestSeatAssignmentFlow:

    def test_TC_SEAT_001_placeholder_seat_not_hard_blocked(self):
        """Placeholder seat returns (None,...) — caller shows 'proceed anyway?'."""
        ok, msg = _validate_child_key(make_seat_id(make_biz_key(), 1))
        assert ok is None

    def test_TC_SEAT_002_real_chld_key_goes_to_worker(self):
        """AP-CHLD- key is NOT skipped — it goes through Worker validation."""
        chld = make_chld_key()
        assert not PLACEHOLDER_RE.match(chld)

    def test_TC_SEAT_003_valid_chld_key_assigned(self):
        ok, msg = _validate_child_key(make_chld_key(),
                                      worker_response={"valid": True})
        assert ok is True

    def test_TC_SEAT_004_suspended_chld_key_blocked(self):
        ok, msg = _validate_child_key(make_chld_key(),
                                      worker_response={"valid": False,
                                                       "reason": "suspended"})
        assert ok is False

    def test_TC_SEAT_005_all_six_placeholders_assignable(self):
        biz = make_biz_key()
        for n in range(1, 7):
            ok, msg = _validate_child_key(make_seat_id(biz, n))
            assert ok is None, f"Seat {n} placeholder must not hard-block"

    def test_TC_SEAT_006_after_sync_chld_keys_validate(self):
        """Post-sync: real AP-CHLD- keys validate successfully."""
        chld_keys = [f"AP-CHLD-AABBCC{n:02X}-DDEEFF{n:02X}" for n in range(6)]
        for k in chld_keys:
            assert not PLACEHOLDER_RE.match(k)
            ok, msg = _validate_child_key(k, worker_response={"valid": True})
            assert ok is True

    def test_TC_SEAT_007_empty_seat_always_allowed(self):
        ok, msg = _validate_child_key("")
        assert ok is True

    def test_TC_SEAT_008_worker_seat_id_format_matches_placeholder(self):
        """Worker seatId format ({licenseKey}-S{NNN}) matches placeholder regex
        so the GUI correctly identifies pre-sync seats in the dropdown."""
        biz = "AP-BIZ-12345678-ABCDEF01"
        for n in range(1, 7):
            sid = f"{biz}-S{str(n).zfill(3)}"
            assert PLACEHOLDER_RE.match(sid)



# ===========================================================================
# Admin seat LIFECYCLE tests — Cases 1-4
# All use tmp_path: never touch ~/.ai-prowler/, KV, Stripe, or Cloudflare.
# ===========================================================================

import json as _json_lc
import datetime as _dt
from pathlib import Path as _Path_lc


def _w_seats(ai_dir, lic_key, seats_list, extra=None):
    data = {"license_key": lic_key, "seats_total": len(seats_list),
            "seats": seats_list}
    if extra:
        data.update(extra)
    (ai_dir / "license_seats.json").write_text(
        _json_lc.dumps(data, indent=2), encoding="utf-8")
    return data


def _w_config(ai_dir, lic_key, plan="business"):
    (ai_dir / "config.json").write_text(
        _json_lc.dumps({"license_key": lic_key, "plan": plan}),
        encoding="utf-8")


def _w_users(ai_dir, users_dict):
    (ai_dir / "users.json").write_text(
        _json_lc.dumps({"users": users_dict}, indent=2), encoding="utf-8")


def _stale_check_logic(ai_dir):
    """Returns (fired, current_key, stored_key)."""
    sp = ai_dir / "license_seats.json"
    cp = ai_dir / "config.json"
    if not sp.exists() or not cp.exists():
        return False, "", ""
    data    = _json_lc.loads(sp.read_text())
    cfg     = _json_lc.loads(cp.read_text())
    current = cfg.get("license_key", "")
    stored  = data.get("license_key") or data.get("parent_license_key", "")
    fired   = (current and stored and current != stored
               and current.startswith("AP-BIZ-"))
    return bool(fired), current, stored


def _clear_seats_from_users(ai_dir):
    up = ai_dir / "users.json"
    if not up.exists():
        return False
    udata   = _json_lc.loads(up.read_text())
    changed = False
    for u in udata.get("users", {}).values():
        if isinstance(u, dict) and u.get("child_license_key"):
            u["child_license_key"] = ""
            u["seat_id"]           = ""
            changed = True
    if changed:
        up.write_text(_json_lc.dumps(udata, indent=2), encoding="utf-8")
    return changed


def _requires_lock_logic(ai_dir):
    up = ai_dir / "users.json"
    if not up.exists():
        return False
    try:
        data = _json_lc.loads(up.read_text())
        for u in data.get("users", {}).values():
            if not isinstance(u, dict):
                continue
            role = (u.get("role") or "").lower()
            if role == "owner" or u.get("can_manage_users"):
                return True
    except Exception:
        pass
    return False


def _mark_removed(ai_dir, child_key="", seat_id=""):
    lsf = ai_dir / "license_seats.json"
    if not lsf.exists():
        return False
    data    = _json_lc.loads(lsf.read_text())
    changed = False
    for s in data.get("seats", []):
        if ((child_key and s.get("child_license_key") == child_key)
                or (seat_id and s.get("seat_id") == seat_id)):
            s["status"]      = "removed"
            s["assigned_to"] = None
            changed = True
    if changed:
        lsf.write_text(_json_lc.dumps(data, indent=2), encoding="utf-8")
    return changed


# ── Case 1 ───────────────────────────────────────────────────────────────────

class TestLifecycleCase1FreshInstall:

    def test_no_users_json_means_no_lock(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        assert _requires_lock_logic(ai_dir) is False

    def test_no_seats_file_returns_no_stale_check(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        fired, _, _ = _stale_check_logic(ai_dir)
        assert fired is False

    def test_activation_writes_real_chld_keys_not_placeholders(self, tmp_path):
        """After activation with seat_records payload, seats have AP-CHLD- keys."""
        import sys
        sys.path.insert(0, str(_Path_lc(__file__).parent.parent.parent))
        import mobile_activator as ma
        from unittest.mock import patch

        biz_key = "AP-BIZ-FRESH001-FRESH002"
        seat_records = [
            {"seat_id": f"{biz_key}-S{str(i+1).zfill(3)}",
             "child_license_key": f"AP-CHLD-{i:08X}-AABB{i:04X}",
             "personal_license_key": f"AP-PERS-{i:08X}-CCDD{i:04X}",
             "status": "unassigned", "assigned_to": None}
            for i in range(3)
        ]
        payload = {
            "activation_code": "APRO-FRESH1-AAAAAA-BBBBBB",
            "license_key": biz_key, "plan": "business", "seats": 3,
            "domain": "ap-fresh.ai-prowler.com",
            "tunnel_id": "t-fresh", "tunnel_token": "tok-fresh",
            "expires_at": "2027-01-01T00:00:00Z",
            "seat_records": seat_records,
        }
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir(parents=True)
        (tmp_path / ".cloudflared").mkdir(parents=True)
        (ai_dir / "config.json").write_text("{}", encoding="utf-8")

        with patch("mobile_activator.AI_PROWLER_DIR", ai_dir), \
             patch("mobile_activator.CLOUDFLARED_DIR", tmp_path / ".cloudflared"), \
             patch("mobile_activator.CONFIG_PATH", ai_dir / "config.json"), \
             patch("mobile_activator.REMOTE_PATH", ai_dir / "remote_access.json"), \
             patch("mobile_activator.SEATS_PATH", ai_dir / "license_seats.json"):
            ma.activate_from_payload(payload)

        seats = _json_lc.loads((ai_dir / "license_seats.json").read_text())
        assert seats["license_key"] == biz_key
        for s in seats["seats"]:
            ck = s["child_license_key"]
            assert ck.startswith("AP-CHLD-"), f"Expected AP-CHLD-, got {ck}"


# ── Case 2 ───────────────────────────────────────────────────────────────────

class TestLifecycleCase2Reinstall:

    def test_stale_fires_on_different_biz_key(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _w_seats(ai_dir, "AP-BIZ-OLD00001-OLD00001", [])
        _w_config(ai_dir, "AP-BIZ-NEW00002-NEW00002")
        fired, cur, stored = _stale_check_logic(ai_dir)
        assert fired  is True
        assert cur    == "AP-BIZ-NEW00002-NEW00002"
        assert stored == "AP-BIZ-OLD00001-OLD00001"

    def test_stale_does_not_fire_same_key(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        key = "AP-BIZ-SAME0001-SAME0001"
        _w_seats(ai_dir, key, [])
        _w_config(ai_dir, key)
        fired, _, _ = _stale_check_logic(ai_dir)
        assert fired is False

    def test_stale_does_not_fire_personal_plan(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _w_seats(ai_dir, "AP-BIZ-OLD00001-OLD00001", [])
        _w_config(ai_dir, "AP-PERS-MYPERS01-MYPERS02", plan="personal")
        fired, _, _ = _stale_check_logic(ai_dir)
        assert fired is False

    def test_stale_clears_seat_keys_keeps_users(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _w_users(ai_dir, {
            "tok-alice": {
                "name": "Alice", "email": "a@x.com", "role": "field_crew",
                "child_license_key": "AP-CHLD-OLD00001-AABB0001",
                "seat_id": "AP-BIZ-OLD00001-OLD00001-S001",
            },
            "tok-owner": {
                "name": "David", "email": "d@x.com", "role": "owner",
                "child_license_key": "", "can_manage_users": True,
            },
        })
        changed = _clear_seats_from_users(ai_dir)
        assert changed is True
        result = _json_lc.loads((ai_dir / "users.json").read_text())["users"]
        # Users preserved
        assert result["tok-alice"]["name"]  == "Alice"
        assert result["tok-alice"]["email"] == "a@x.com"
        # Seat keys cleared
        assert result["tok-alice"]["child_license_key"] == ""
        assert result["tok-alice"]["seat_id"]           == ""
        # Owner untouched
        assert result["tok-owner"]["role"] == "owner"

    def test_lock_still_active_after_stale_clear_if_owner_exists(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _w_users(ai_dir, {"tok-owner": {"role": "owner",
                                         "can_manage_users": True,
                                         "child_license_key": ""}})
        assert _requires_lock_logic(ai_dir) is True


# ── Case 3 ───────────────────────────────────────────────────────────────────

class TestLifecycleCase3AddSeat:

    def test_unassigned_seats_detected_as_new(self):
        seats = [
            {"child_license_key": "AP-CHLD-A1", "status": "assigned",
             "assigned_to": "a@x.com"},
            {"child_license_key": "AP-CHLD-B2", "status": "unassigned",
             "assigned_to": None},
            {"child_license_key": "AP-CHLD-C3", "status": "unassigned",
             "assigned_to": None},
        ]
        new = [s for s in seats
               if s.get("status") == "unassigned" and not s.get("assigned_to")]
        assert len(new) == 2

    def test_no_notification_all_assigned(self):
        seats = [
            {"child_license_key": "AP-CHLD-A1", "status": "assigned",
             "assigned_to": "a@x.com"},
        ]
        new = [s for s in seats
               if s.get("status") == "unassigned" and not s.get("assigned_to")]
        assert len(new) == 0

    def test_removed_seats_excluded_from_pool(self):
        seats = [
            {"child_license_key": "AP-CHLD-A1", "status": "unassigned",
             "assigned_to": None},
            {"child_license_key": "AP-CHLD-B2", "status": "removed",
             "assigned_to": None},
        ]
        pool = [s["child_license_key"] for s in seats
                if s.get("status") == "unassigned"]
        assert "AP-CHLD-A1" in pool
        assert "AP-CHLD-B2" not in pool


# ── Case 4a ──────────────────────────────────────────────────────────────────

class TestLifecycleCase4aRemoveSeat:

    def test_remove_marks_seat_removed_by_child_key(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        bk   = "AP-BIZ-LIVE0001-LIVE0002"
        chld = "AP-CHLD-ALICE001-AABB0001"
        _w_seats(ai_dir, bk, [
            {"seat_id": f"{bk}-S001", "child_license_key": chld,
             "status": "assigned", "assigned_to": "alice@x.com"},
            {"seat_id": f"{bk}-S002", "child_license_key": "AP-CHLD-BOB2-CCDD",
             "status": "assigned", "assigned_to": "bob@x.com"},
        ])
        changed = _mark_removed(ai_dir, child_key=chld)
        assert changed is True
        seats = {s["child_license_key"]: s
                 for s in _json_lc.loads(
                     (ai_dir / "license_seats.json").read_text())["seats"]}
        assert seats[chld]["status"]                       == "removed"
        assert seats[chld]["assigned_to"]                  is None
        assert seats["AP-CHLD-BOB2-CCDD"]["status"]        == "assigned"
        assert seats["AP-CHLD-BOB2-CCDD"]["assigned_to"]   == "bob@x.com"

    def test_remove_marks_seat_removed_by_seat_id(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        bk  = "AP-BIZ-LIVE0001-LIVE0002"
        sid = f"{bk}-S001"
        _w_seats(ai_dir, bk, [
            {"seat_id": sid, "child_license_key": "",
             "status": "assigned", "assigned_to": "alice@x.com"},
        ])
        changed = _mark_removed(ai_dir, seat_id=sid)
        assert changed is True
        s = _json_lc.loads((ai_dir / "license_seats.json").read_text())["seats"][0]
        assert s["status"]      == "removed"
        assert s["assigned_to"] is None


# ── Case 4b ──────────────────────────────────────────────────────────────────

class TestLifecycleCase4bOverQuota:

    def test_over_quota_detected(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        since = (_dt.datetime.now(_dt.timezone.utc)
                 - _dt.timedelta(days=15)).isoformat()
        _w_seats(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [], extra={
            "over_quota_since": since,
            "over_quota_count": 2,
            "over_quota_target": 4,
        })
        lsd  = _json_lc.loads((ai_dir / "license_seats.json").read_text())
        oqs  = lsd.get("over_quota_since", "")
        oqc  = int(lsd.get("over_quota_count", 0))
        assert oqs and oqc == 2
        deadline  = _dt.datetime.fromisoformat(oqs) + _dt.timedelta(days=30)
        days_left = max(0, (deadline - _dt.datetime.now(_dt.timezone.utc)).days)
        assert 14 <= days_left <= 15

    def test_no_over_quota_when_field_absent(self, tmp_path):
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _w_seats(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [])
        lsd = _json_lc.loads((ai_dir / "license_seats.json").read_text())
        assert not (lsd.get("over_quota_since")
                    and int(lsd.get("over_quota_count", 0)) > 0)

    def test_newest_seats_targeted_for_auto_suspend(self):
        seats = [
            {"seat_id": f"AP-BIZ-X-S{str(i+1).zfill(3)}",
             "child_license_key": f"AP-CHLD-{i:08X}-AABB{i:04X}",
             "status": "assigned"}
            for i in range(6)
        ]
        quota      = 4
        active     = [s for s in seats
                      if s["status"] not in ("removed", "suspended")]
        to_suspend = active[-(len(active) - quota):]
        assert len(to_suspend) == 2
        assert to_suspend[0]["seat_id"] == "AP-BIZ-X-S005"
        assert to_suspend[1]["seat_id"] == "AP-BIZ-X-S006"

