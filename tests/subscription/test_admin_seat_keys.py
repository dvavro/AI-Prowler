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


# ===========================================================================
# TC-PORTAL: Manage Subscription button — server/business mode
# Tests _open_stripe_portal_srv() logic in complete isolation.
# No real config.json, no Worker, no KV, no Stripe, no Cloudflare touched.
# Uses tmp_path for config and a mock url_opener to intercept Worker calls.
# ===========================================================================

import urllib.error as _urllib_error


def _portal_srv_logic(config_path, url_opener):
    """Replicate _open_stripe_portal_srv() from rag_gui.py without Tkinter.

    config_path : Path to config.json (tmp_path — never real ~/.ai-prowler/)
    url_opener  : callable(url) -> dict  (mock in tests, real urllib in prod)

    Returns (action, detail):
      'no_license'  — config missing or no license_key
      'opened'      — Stripe URL received; detail = the URL
      'no_url'      — Worker returned 200 but no url field
      'http_error'  — Worker returned non-2xx; detail = str(code)
      'network_err' — urllib raised generic exception
    """
    import json as _j

    try:
        cfg_d = _j.loads(config_path.read_text(encoding='utf-8')) \
                if config_path.exists() else {}
        lic = cfg_d.get('license_key', '').strip()
    except Exception:
        lic = ''

    if not lic:
        return 'no_license', ''

    try:
        data = url_opener(
            f"https://api.ai-prowler.com/portal-session?license={lic}")
        portal_url = data.get('url', '')
        if portal_url:
            return 'opened', portal_url
        return 'no_url', data.get('error', 'unknown')
    except _urllib_error.HTTPError as e:
        return 'http_error', str(e.code)
    except Exception as e:
        return 'network_err', str(e)


class TestPortalSessionServerMode:

    def _cfg(self, tmp_path, license_key, extra=None):
        """Write tmp_path config — never touches ~/.ai-prowler/."""
        import json
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir(parents=True, exist_ok=True)
        d = {"license_key": license_key,
             "plan": "business", "edition": "business", "mode": "server"}
        if extra:
            d.update(extra)
        p = ai_dir / "config.json"
        p.write_text(json.dumps(d), encoding="utf-8")
        return p

    def test_TC_PORTAL_SRV_001_no_config_returns_no_license(self, tmp_path):
        """Missing config.json → no_license (not a crash)."""
        p = tmp_path / ".ai-prowler" / "config.json"
        assert not p.exists()
        action, _ = _portal_srv_logic(p, lambda url: {})
        assert action == 'no_license'

    def test_TC_PORTAL_SRV_002_config_with_no_license_key(self, tmp_path):
        """config.json exists but has no license_key → no_license."""
        import json
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        p = ai_dir / "config.json"
        p.write_text(json.dumps({"edition": "business", "mode": "server"}))
        action, _ = _portal_srv_logic(p, lambda url: {})
        assert action == 'no_license'

    def test_TC_PORTAL_SRV_003_worker_returns_stripe_url(self, tmp_path):
        """Worker returns Stripe URL → action='opened' with the URL."""
        p = self._cfg(tmp_path, "AP-BIZ-AC94AE8B-BA91CA47")

        def mock_opener(url):
            assert "AP-BIZ-AC94AE8B-BA91CA47" in url
            return {"url": "https://billing.stripe.com/session/test_abc123"}

        action, detail = _portal_srv_logic(p, mock_opener)
        assert action == 'opened'
        assert detail == "https://billing.stripe.com/session/test_abc123"

    def test_TC_PORTAL_SRV_004_worker_returns_no_url_field(self, tmp_path):
        """Worker returns 200 but no url field → no_url."""
        p = self._cfg(tmp_path, "AP-BIZ-AC94AE8B-BA91CA47")
        action, detail = _portal_srv_logic(
            p, lambda url: {"error": "No customer_id on record"})
        assert action == 'no_url'
        assert 'customer_id' in detail

    def test_TC_PORTAL_SRV_005_worker_returns_404(self, tmp_path):
        """Worker returns 404 (license not in KV) → http_error."""
        p = self._cfg(tmp_path, "AP-BIZ-AC94AE8B-BA91CA47")

        def mock_opener(url):
            raise _urllib_error.HTTPError(url, 404, "Not Found", {}, None)

        action, detail = _portal_srv_logic(p, mock_opener)
        assert action == 'http_error'
        assert detail == '404'

    def test_TC_PORTAL_SRV_006_worker_returns_403_suspended(self, tmp_path):
        """Worker returns 403 (suspended subscription) → http_error."""
        p = self._cfg(tmp_path, "AP-BIZ-AC94AE8B-BA91CA47")

        def mock_opener(url):
            raise _urllib_error.HTTPError(url, 403, "Forbidden", {}, None)

        action, detail = _portal_srv_logic(p, mock_opener)
        assert action == 'http_error'
        assert detail == '403'

    def test_TC_PORTAL_SRV_007_network_error(self, tmp_path):
        """Network timeout → network_err (not a crash)."""
        p = self._cfg(tmp_path, "AP-BIZ-AC94AE8B-BA91CA47")

        def mock_opener(url):
            raise Exception("Connection timed out")

        action, detail = _portal_srv_logic(p, mock_opener)
        assert action == 'network_err'
        assert 'timed out' in detail

    def test_TC_PORTAL_SRV_008_license_key_in_request_url(self, tmp_path):
        """license_key from config.json is sent in the Worker URL."""
        biz_key = "AP-BIZ-AC94AE8B-BA91CA47"
        p = self._cfg(tmp_path, biz_key)
        seen = []

        def mock_opener(url):
            seen.append(url)
            return {"url": "https://billing.stripe.com/session/xyz"}

        _portal_srv_logic(p, mock_opener)
        assert len(seen) == 1
        assert f"license={biz_key}" in seen[0]
        assert "portal-session" in seen[0]

    def test_TC_PORTAL_SRV_009_personal_and_server_same_logic(self, tmp_path):
        """Personal (AP-PERS-) and server (AP-BIZ-) use identical call logic."""
        for lic_key in [
            "AP-PERS-16C50BFD-4FB265F4",
            "AP-BIZ-AC94AE8B-BA91CA47",
        ]:
            p = self._cfg(tmp_path, lic_key)
            seen = []

            def mock_opener(url, _k=lic_key):
                seen.append(url)
                return {"url": "https://billing.stripe.com/session/test"}

            action, detail = _portal_srv_logic(p, mock_opener)
            assert action == 'opened', f"Failed for {lic_key}"
            assert f"license={lic_key}" in seen[0]

    def test_TC_PORTAL_SRV_010_reinstall_same_subscription_works(self, tmp_path):
        """After uninstall+reinstall with same AP-BIZ- key portal still works.
        config.json rewritten by activate_from_payload with same key —
        Worker KV still has the license record with customer_id."""
        biz_key = "AP-BIZ-AC94AE8B-BA91CA47"
        p = self._cfg(tmp_path, biz_key)

        def mock_opener(url):
            # Worker finds license in KV, creates portal session
            assert biz_key in url
            return {"url": "https://billing.stripe.com/session/reinstall_ok"}

        action, detail = _portal_srv_logic(p, mock_opener)
        assert action == 'opened'
        assert detail.startswith("https://billing.stripe.com")


# ===========================================================================
# TC-VALIDATE: _admin_validate_child_key — v8 endpoint contract
#
# Verifies the Admin tab calls the correct v8 Worker endpoint:
#   GET /license/{key}/validate?install_id=...
# NOT the old v7 endpoint:
#   POST /license/validate  (no longer exists — returns 404)
#
# All tests use a mock url_opener — no KV, no Stripe, no Cloudflare,
# no real ~/.ai-prowler/ files touched.
# ===========================================================================

import urllib.error as _ue
import re as _re


def _validate_child_key_logic(child_key, url_opener, install_id=""):
    """Replicate _admin_validate_child_key() from rag_gui.py without Tkinter.

    child_key  : the AP-CHLD-... (or placeholder) key to validate
    url_opener : callable(url, method) -> dict   (mock in tests)
    install_id : optional machine ID

    Returns (ok, message):
      (True,  msg) — valid seat
      (False, msg) — hard rejection from Worker
      (None,  msg) — network error or placeholder — non-fatal
    """
    # Placeholder check (same regex as rag_gui.py line 14074)
    if _re.match(r'^AP-BIZ-[0-9A-F]+-[0-9A-F]+-S\d+$',
                 child_key, _re.IGNORECASE):
        return (None,
                "This is a placeholder seat ID (not yet synced from the server).\n"
                "Click 'Sync Seats' to fetch real child keys from the license server.")

    endpoint = "https://api.ai-prowler.com"
    try:
        # v8 endpoint: GET /license/{key}/validate?install_id=...
        url = (f"{endpoint}/license/{child_key}/validate"
               + (f"?install_id={install_id}" if install_id else ""))
        resp = url_opener(url, method="GET")
        if resp.get("valid") is True:
            exp = resp.get("expires_at", "")
            return (True, f"Valid child seat{(' — expires ' + exp) if exp else ''}.")
        reason = resp.get("reason", "invalid")
        return (False,
                f"License key rejected: {reason}. {resp.get('message','')}"
                .strip())
    except _ue.HTTPError as e:
        return (False, f"Validation HTTP error {e.code} (key not accepted).")
    except Exception as e:
        return (None, f"Could not reach the license server ({e}).")


class TestValidateChildKey:

    def test_TC_VALIDATE_001_valid_key_returns_true(self):
        """Worker returns valid:true → (True, message with 'Valid')."""
        def mock(url, method="GET"):
            assert method == "GET"                        # must be GET not POST
            assert "/license/AP-CHLD-" in url            # key in URL path
            assert "/validate" in url                    # validate endpoint
            assert "/license/validate" not in url        # NOT the old v7 path
            return {"valid": True, "expires_at": "2027-07-01T00:00:00Z"}

        ok, msg = _validate_child_key_logic("AP-CHLD-ABCD1234-EFGH5678", mock)
        assert ok is True
        assert "Valid" in msg

    def test_TC_VALIDATE_002_url_uses_v8_get_path_not_v7_post(self):
        """Critical: URL must be GET /license/{key}/validate not POST /license/validate."""
        seen = {}

        def mock(url, method="GET"):
            seen['url']    = url
            seen['method'] = method
            return {"valid": True}

        _validate_child_key_logic("AP-CHLD-ABCD1234-EFGH5678", mock)

        # v8 format: key is IN the URL path
        assert "AP-CHLD-ABCD1234-EFGH5678" in seen['url']
        # v8 format: GET not POST
        assert seen['method'] == "GET"
        # NOT the old v7 format (key in body, flat /license/validate path)
        assert seen['url'].rstrip("?") != "https://api.ai-prowler.com/license/validate"

    def test_TC_VALIDATE_003_install_id_added_as_query_param(self):
        """install_id is passed as ?install_id= query param (v8 GET style)."""
        seen = {}

        def mock(url, method="GET"):
            seen['url'] = url
            return {"valid": True}

        _validate_child_key_logic(
            "AP-CHLD-ABCD1234-EFGH5678", mock, install_id="machine-abc123")

        assert "install_id=machine-abc123" in seen['url']

    def test_TC_VALIDATE_004_no_install_id_omits_query_param(self):
        """When no install_id available, URL has no query string."""
        seen = {}

        def mock(url, method="GET"):
            seen['url'] = url
            return {"valid": True}

        _validate_child_key_logic("AP-CHLD-ABCD1234-EFGH5678", mock,
                                  install_id="")
        assert "install_id" not in seen['url']

    def test_TC_VALIDATE_005_worker_returns_invalid_gives_false(self):
        """Worker returns valid:false → (False, message with reason)."""
        def mock(url, method="GET"):
            return {"valid": False, "reason": "suspended",
                    "message": "License is suspended."}

        ok, msg = _validate_child_key_logic("AP-CHLD-ABCD1234-EFGH5678", mock)
        assert ok is False
        assert "suspended" in msg

    def test_TC_VALIDATE_006_http_404_returns_false(self):
        """Worker returns 404 → (False, message with 404).
        This was the bug: v7 POST /license/validate always returned 404
        on the v8 Worker because the endpoint doesn't exist there."""
        def mock(url, method="GET"):
            raise _ue.HTTPError(url, 404, "Not Found", {}, None)

        ok, msg = _validate_child_key_logic("AP-CHLD-ABCD1234-EFGH5678", mock)
        assert ok is False
        assert "404" in msg

    def test_TC_VALIDATE_007_http_403_suspended_returns_false(self):
        """Worker returns 403 (suspended license) → (False, message)."""
        def mock(url, method="GET"):
            raise _ue.HTTPError(url, 403, "Forbidden", {}, None)

        ok, msg = _validate_child_key_logic("AP-CHLD-ABCD1234-EFGH5678", mock)
        assert ok is False
        assert "403" in msg

    def test_TC_VALIDATE_008_network_error_returns_none(self):
        """Network timeout → (None, message) — non-fatal, caller can proceed."""
        def mock(url, method="GET"):
            raise Exception("Connection timed out")

        ok, msg = _validate_child_key_logic("AP-CHLD-ABCD1234-EFGH5678", mock)
        assert ok is None
        assert "timed out" in msg

    def test_TC_VALIDATE_009_placeholder_key_returns_none(self):
        """Placeholder seat ID (AP-BIZ-...-S001) → (None, message) without
        making any network call — skipped immediately."""
        called = []

        def mock(url, method="GET"):
            called.append(url)  # should never be called
            return {"valid": True}

        ok, msg = _validate_child_key_logic(
            "AP-BIZ-ABCD1234-EF056789-S001", mock)
        assert ok is None
        assert "placeholder" in msg.lower()
        assert called == []  # no network call made

    def test_TC_VALIDATE_010_placeholder_case_insensitive(self):
        """Placeholder check is case-insensitive."""
        called = []

        def mock(url, method="GET"):
            called.append(url)
            return {"valid": True}

        ok, _ = _validate_child_key_logic(
            "ap-biz-abcd1234-ef056789-s003", mock)
        assert ok is None
        assert called == []

    def test_TC_VALIDATE_011_real_chld_key_not_treated_as_placeholder(self):
        """AP-CHLD- keys are NOT caught by the placeholder regex."""
        called = []

        def mock(url, method="GET"):
            called.append(url)
            return {"valid": True}

        ok, _ = _validate_child_key_logic(
            "AP-CHLD-ABCD1234-EF056789", mock)
        assert ok is True
        assert len(called) == 1  # network call WAS made

    def test_TC_VALIDATE_012_key_is_url_encoded_in_path(self):
        """Key is correctly embedded in the URL path (no injection)."""
        seen = {}

        def mock(url, method="GET"):
            seen['url'] = url
            return {"valid": True}

        key = "AP-CHLD-ABCD1234-EF056789"
        _validate_child_key_logic(key, mock)
        # Key appears between /license/ and /validate
        assert f"/license/{key}/validate" in seen['url']


# ===========================================================================
# TC-ADMIN-FIX: Tests for the 4 Admin tab fixes
#
# Fix 1: _admin_mark_seat_in_local_file — updates seat status in
#         license_seats.json when user is added/removed (no round-trip needed)
# Fix 2: Remove User marks seat 'unassigned' not 'removed' so seat can be
#         reassigned without Refresh Seats
# Fix 3: /seats/{key}/sync is public — no admin token needed on server
# Fix 4: Change Token dialog validates: min 8 chars, unique, not empty
#
# All tests use tmp_path — zero pollution of ~/.ai-prowler/ or any DB.
# ===========================================================================


def _make_seats_file(ai_dir, biz_key, seats):
    """Write license_seats.json to ai_dir."""
    import json
    p = ai_dir / "license_seats.json"
    p.write_text(json.dumps({
        "license_key":  biz_key,
        "seats_total":  len(seats),
        "seats":        seats,
    }, indent=2), encoding="utf-8")
    return p


def _read_seats(ai_dir):
    import json
    return json.loads((ai_dir / "license_seats.json").read_text())["seats"]


def _mark_seat_logic(lsf_path, child_key, status, assigned_to=None):
    """Replicate _admin_mark_seat_in_local_file() without Tkinter."""
    import json
    if not lsf_path.exists() or not child_key:
        return False
    data    = json.loads(lsf_path.read_text(encoding="utf-8"))
    changed = False
    for s in data.get("seats", []):
        if (s.get("child_license_key") == child_key
                or s.get("seat_id") == child_key):
            s["status"]      = status
            s["assigned_to"] = assigned_to if status == "assigned" else None
            changed = True
    if changed:
        lsf_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return changed


def _remove_user_seat_logic(lsf_path, child_key, seat_id=""):
    """Replicate the Remove User seat-update logic — marks seat 'unassigned'."""
    import json
    if not lsf_path.exists():
        return False
    data    = json.loads(lsf_path.read_text(encoding="utf-8"))
    changed = False
    for s in data.get("seats", []):
        if ((child_key and s.get("child_license_key") == child_key)
                or (seat_id and s.get("seat_id") == seat_id)):
            s["status"]      = "unassigned"   # FIX 2: was "removed"
            s["assigned_to"] = None
            changed = True
    if changed:
        lsf_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return changed


def _token_validation_logic(new_tok, existing_users, current_token):
    """Replicate Change Token dialog validation — returns (ok, error_msg)."""
    if not new_tok:
        return False, "Token required"
    if len(new_tok) < 8:
        return False, "Too short — minimum 8 characters"
    if new_tok in existing_users and new_tok != current_token:
        return False, "Already in use by another user"
    return True, ""


# ── Fix 1: _admin_mark_seat_in_local_file ───────────────────────────────────

class TestFix1MarkSeatInLocalFile:

    def test_add_user_marks_seat_assigned(self, tmp_path):
        """After Add User, _admin_mark_seat_in_local_file marks the seat
        'assigned' in license_seats.json so the count strip is correct."""
        ai_dir  = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        chld    = "AP-CHLD-ABCD1234-EF056789"
        lsf = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"child_license_key": chld, "status": "unassigned", "assigned_to": None},
        ])

        changed = _mark_seat_logic(lsf, chld, "assigned", "alice@example.com")
        assert changed is True

        seats = _read_seats(ai_dir)
        assert seats[0]["status"]      == "assigned"
        assert seats[0]["assigned_to"] == "alice@example.com"

    def test_mark_assigned_clears_other_seats(self, tmp_path):
        """Only the matching seat is updated; others are untouched."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        chld1 = "AP-CHLD-AAAA1111-BBBB2222"
        chld2 = "AP-CHLD-CCCC3333-DDDD4444"
        lsf = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"child_license_key": chld1, "status": "unassigned", "assigned_to": None},
            {"child_license_key": chld2, "status": "unassigned", "assigned_to": None},
        ])

        _mark_seat_logic(lsf, chld1, "assigned", "alice@example.com")

        seats = {s["child_license_key"]: s for s in _read_seats(ai_dir)}
        assert seats[chld1]["status"]      == "assigned"
        assert seats[chld1]["assigned_to"] == "alice@example.com"
        assert seats[chld2]["status"]      == "unassigned"  # untouched

    def test_mark_unassigned_clears_assigned_to(self, tmp_path):
        """Marking a seat unassigned clears assigned_to field."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        chld = "AP-CHLD-ABCD1234-EF056789"
        lsf = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"child_license_key": chld, "status": "assigned",
             "assigned_to": "alice@example.com"},
        ])

        _mark_seat_logic(lsf, chld, "unassigned")

        seats = _read_seats(ai_dir)
        assert seats[0]["status"]      == "unassigned"
        assert seats[0]["assigned_to"] is None

    def test_mark_seat_no_op_when_file_missing(self, tmp_path):
        """No error when license_seats.json doesn't exist."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        lsf = ai_dir / "license_seats.json"
        # No exception, no crash
        result = _mark_seat_logic(lsf, "AP-CHLD-ABCD1234-EF056789", "assigned")
        assert result is False

    def test_mark_seat_no_op_when_key_empty(self, tmp_path):
        """No-op when child_key is empty string."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        lsf = _make_seats_file(ai_dir, "AP-BIZ-X", [
            {"child_license_key": "AP-CHLD-ABCD1234-EF056789",
             "status": "unassigned"}
        ])
        result = _mark_seat_logic(lsf, "", "assigned")
        assert result is False

    def test_mark_seat_matches_by_seat_id_fallback(self, tmp_path):
        """Falls back to matching by seat_id when child_license_key absent."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        sid = "AP-BIZ-LIVE0001-LIVE0002-S001"
        lsf = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"seat_id": sid, "child_license_key": "",
             "status": "unassigned", "assigned_to": None},
        ])

        changed = _mark_seat_logic(lsf, sid, "assigned", "bob@example.com")
        assert changed is True
        seats = _read_seats(ai_dir)
        assert seats[0]["status"] == "assigned"


# ── Fix 2: Remove User marks seat 'unassigned' not 'removed' ────────────────

class TestFix2RemoveUserUnassignsSeat:

    def test_remove_user_returns_seat_to_pool(self, tmp_path):
        """Remove User marks seat 'unassigned' so it can be reassigned.
        Before fix: marked 'removed' — seat disappeared from dropdown."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        chld = "AP-CHLD-ABCD1234-EF056789"
        lsf  = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"child_license_key": chld, "status": "assigned",
             "assigned_to": "alice@example.com"},
        ])

        _remove_user_seat_logic(lsf, chld)

        seats = _read_seats(ai_dir)
        assert seats[0]["status"]      == "unassigned"   # FIX: was 'removed'
        assert seats[0]["assigned_to"] is None

    def test_remove_user_seat_not_marked_removed(self, tmp_path):
        """Critical: status must never be 'removed' after Remove User.
        'removed' is reserved for Stripe quantity reduction only."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        chld = "AP-CHLD-ABCD1234-EF056789"
        lsf  = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"child_license_key": chld, "status": "assigned",
             "assigned_to": "alice@example.com"},
        ])

        _remove_user_seat_logic(lsf, chld)

        seats = _read_seats(ai_dir)
        assert seats[0]["status"] != "removed"  # never 'removed' from UI action

    def test_unassigned_seat_appears_in_available_pool(self, tmp_path):
        """After Remove User, the seat appears in the unassigned pool
        and can be picked in the Add User seat dropdown."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        chld = "AP-CHLD-ABCD1234-EF056789"
        lsf  = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"child_license_key": chld, "status": "assigned",
             "assigned_to": "alice@example.com"},
        ])

        _remove_user_seat_logic(lsf, chld)

        seats = _read_seats(ai_dir)
        # Replicate _admin_unassigned_keys() pool logic
        pool = [s.get("child_license_key") for s in seats
                if s.get("status") == "unassigned"]
        assert chld in pool  # seat is back in the dropdown

    def test_other_seats_unaffected_on_remove(self, tmp_path):
        """Only the removed user's seat changes; other seats are untouched."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        chld1 = "AP-CHLD-AAAA1111-BBBB2222"
        chld2 = "AP-CHLD-CCCC3333-DDDD4444"
        lsf = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"child_license_key": chld1, "status": "assigned",
             "assigned_to": "alice@example.com"},
            {"child_license_key": chld2, "status": "assigned",
             "assigned_to": "bob@example.com"},
        ])

        _remove_user_seat_logic(lsf, chld1)

        seats = {s["child_license_key"]: s for s in _read_seats(ai_dir)}
        assert seats[chld1]["status"]      == "unassigned"
        assert seats[chld2]["status"]      == "assigned"   # bob unaffected
        assert seats[chld2]["assigned_to"] == "bob@example.com"

    def test_remove_then_reassign_full_cycle(self, tmp_path):
        """Full cycle: assign → remove → reassign to different user."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        chld = "AP-CHLD-ABCD1234-EF056789"
        lsf  = _make_seats_file(ai_dir, "AP-BIZ-LIVE0001-LIVE0002", [
            {"child_license_key": chld, "status": "assigned",
             "assigned_to": "alice@example.com"},
        ])

        # Remove alice
        _remove_user_seat_logic(lsf, chld)
        assert _read_seats(ai_dir)[0]["status"] == "unassigned"

        # Assign to jamie
        _mark_seat_logic(lsf, chld, "assigned", "jamie@example.com")
        seats = _read_seats(ai_dir)
        assert seats[0]["status"]      == "assigned"
        assert seats[0]["assigned_to"] == "jamie@example.com"


# ── Fix 3: /seats/{key}/sync public endpoint ─────────────────────────────────

class TestFix3SyncSeatPublic:

    def test_sync_allowed_without_admin_token(self):
        """/sync subpath bypasses isAdmin check — no 401 on server."""
        # Replicate the routing logic from worker.js
        def route_seats(subpath, is_admin):
            if subpath != '/sync' and not is_admin:
                return 401
            return 200  # handleSeats called

        # Server has no admin token → is_admin = False
        assert route_seats('/sync',     is_admin=False) == 200  # FIX: was 401
        assert route_seats('/assign',   is_admin=False) == 401  # still protected
        assert route_seats('/unassign', is_admin=False) == 401  # still protected
        assert route_seats('/revoke',   is_admin=False) == 401  # still protected
        assert route_seats('/add',      is_admin=False) == 401  # still protected
        assert route_seats('',          is_admin=False) == 401  # GET protected

    def test_sync_still_works_with_admin_token(self):
        """/sync also works when admin token IS present."""
        def route_seats(subpath, is_admin):
            if subpath != '/sync' and not is_admin:
                return 401
            return 200

        assert route_seats('/sync', is_admin=True)   == 200
        assert route_seats('/assign', is_admin=True) == 200

    def test_all_mutations_require_admin(self):
        """assign/unassign/revoke/add/GET all require admin — not relaxed."""
        protected = ['/assign', '/unassign', '/revoke', '/add', '']

        def route_seats(subpath, is_admin):
            if subpath != '/sync' and not is_admin:
                return 401
            return 200

        for subpath in protected:
            assert route_seats(subpath, is_admin=False) == 401, \
                f"{subpath!r} should require admin"


# ── Fix 4: Change Token dialog validation ────────────────────────────────────

class TestFix4ChangeTokenValidation:

    def _users(self):
        return {
            "token-alice": {"name": "Alice", "role": "field_crew"},
            "token-owner": {"name": "David", "role": "owner"},
        }

    def test_valid_manual_token_accepted(self):
        """Admin can type their own token — accepted when ≥8 chars and unique."""
        ok, msg = _token_validation_logic(
            "Synopsys1*", self._users(), "token-alice")
        assert ok is True
        assert msg == ""

    def test_empty_token_rejected(self):
        """Empty token is rejected with clear message."""
        ok, msg = _token_validation_logic("", self._users(), "token-alice")
        assert ok is False
        assert "required" in msg.lower() or "empty" in msg.lower() or msg != ""

    def test_too_short_rejected(self):
        """Token shorter than 8 chars is rejected."""
        ok, msg = _token_validation_logic("abc123", self._users(), "token-alice")
        assert ok is False
        assert "short" in msg.lower() or "8" in msg

    def test_exactly_8_chars_accepted(self):
        """Exactly 8 characters is the minimum — accepted."""
        ok, msg = _token_validation_logic("abcd1234", self._users(), "token-alice")
        assert ok is True

    def test_7_chars_rejected(self):
        """7 characters is one below minimum — rejected."""
        ok, msg = _token_validation_logic("abcd123", self._users(), "token-alice")
        assert ok is False

    def test_duplicate_token_rejected(self):
        """Token already in use by a DIFFERENT user is rejected."""
        ok, msg = _token_validation_logic(
            "token-owner", self._users(), "token-alice")
        assert ok is False
        assert "use" in msg.lower() or "exist" in msg.lower() or msg != ""

    def test_same_token_as_current_user_allowed(self):
        """Saving the same token for the SAME user is allowed (no-op change)."""
        ok, msg = _token_validation_logic(
            "token-alice", self._users(), "token-alice")
        assert ok is True

    def test_special_chars_allowed(self):
        """Tokens with special characters (like Synopsys1*) are valid."""
        ok, msg = _token_validation_logic(
            "Synopsys1*!", self._users(), "token-alice")
        assert ok is True

    def test_spaces_in_token_up_to_admin(self):
        """Spaces are technically allowed if ≥8 chars and unique — admin's choice."""
        ok, msg = _token_validation_logic(
            "my pass word", self._users(), "token-alice")
        assert ok is True  # no space restriction in the logic

    def test_long_token_accepted(self):
        """Long randomly-generated tokens (32+ chars) are always accepted."""
        import secrets
        long_tok = secrets.token_urlsafe(32)
        ok, msg  = _token_validation_logic(long_tok, self._users(), "token-alice")
        assert ok is True

    def test_generated_token_passes_validation(self):
        """Tokens from _admin_gen_token() (secrets.token_urlsafe(24)) always
        pass validation — they're ≥8 chars and URL-safe."""
        import secrets
        for _ in range(20):
            tok = secrets.token_urlsafe(24)
            ok, msg = _token_validation_logic(tok, {}, "old-token")
            assert ok is True, f"Generated token failed: {tok!r}: {msg}"


# ===========================================================================
# TC-DISPLAY: Full seat key display in Admin tab treeview
# TC-ASSIGN:  Worker assign called with seat_id not AP-BIZ- child_key
# TC-SYNC:    sync_seats works without admin token (public endpoint)
#
# All tests use tmp_path — zero ~/.ai-prowler/ pollution, no KV/Stripe.
# ===========================================================================


# ── helpers ──────────────────────────────────────────────────────────────────

def _build_seat_row_values(user_dict, token):
    """Replicate the treeview row-building logic from _admin_refresh_table.
    Returns the values tuple exactly as inserted into the tree."""
    u          = user_dict
    role       = u.get("role", "field_crew")
    scopes     = ", ".join(u.get("scopes") or [])
    is_owner   = (role == "owner")
    admin_flag = "✓ (owner)" if is_owner else ("✓" if u.get("can_manage_users") else "")
    private    = "✓" if u.get("private_collection_enabled") else ""
    # FIX: full key not masked
    seat       = u.get("child_license_key", "") or ""
    status     = u.get("status", "active")
    phone      = u.get("cell_phone", "")
    tok_display = "●" * 8   # token always masked
    return (u.get("name", "(unnamed)"), u.get("email", ""), phone,
            role, scopes, admin_flag, private, seat, status, tok_display)


def _find_seat_id_for_child_key(lsf_path, child_key):
    """Replicate the seat_id lookup logic added to _admin_add_user."""
    import json
    if not lsf_path.exists() or not child_key:
        return ""
    data = json.loads(lsf_path.read_text(encoding="utf-8"))
    for s in data.get("seats", []):
        if s.get("child_license_key") == child_key:
            return s.get("seat_id", "")
    return ""


def _sync_needs_no_token_logic(license_key, url_poster):
    """Replicate sync_seats() after the fix — token may be empty."""
    token = ""  # no admin token on server machine
    # Before fix: raised RuntimeError here if token empty
    # After fix: proceeds to network call — Worker accepts without token
    try:
        status, body = url_poster(f"/seats/{license_key}/sync", {}, bearer=token)
        if status == 200 and isinstance(body, dict):
            return True, body
        return False, body
    except Exception as e:
        return False, str(e)


# ── TC-DISPLAY: Full seat key in treeview ────────────────────────────────────

class TestFullSeatKeyDisplay:

    def test_seat_column_shows_full_chld_key(self):
        """Seat (key) column shows full AP-CHLD-... key, not masked/truncated."""
        user = {
            "name": "David Vavro",
            "email": "david@example.com",
            "role": "owner",
            "scopes": ["scope:office"],
            "can_manage_users": True,
            "private_collection_enabled": True,
            "child_license_key": "AP-CHLD-F8AEB4DF-21304384",
            "status": "active",
            "cell_phone": "4807470358",
        }
        values = _build_seat_row_values(user, "bearbear")
        seat_col = values[7]   # index 7 = seat column
        assert seat_col == "AP-CHLD-F8AEB4DF-21304384"

    def test_seat_column_not_masked_or_truncated(self):
        """Seat key must NOT be masked (●) or truncated (AP-C...4384)."""
        user = {
            "name": "Vicki Vavro",
            "email": "vicki@example.com",
            "role": "manager",
            "scopes": ["scope:office"],
            "can_manage_users": True,
            "private_collection_enabled": True,
            "child_license_key": "AP-CHLD-4B88898B-FD65DE92",
            "status": "active",
            "cell_phone": "4807470358",
        }
        values = _build_seat_row_values(user, "Synopsys1*")
        seat_col = values[7]
        assert "●" not in seat_col          # not masked
        assert "..." not in seat_col         # not truncated
        assert seat_col == "AP-CHLD-4B88898B-FD65DE92"

    def test_token_column_still_masked(self):
        """Token (password) column must remain masked — it's the employee's password."""
        user = {
            "name": "Jamie Vavro", "email": "jamie@example.com",
            "role": "staff", "scopes": [], "can_manage_users": False,
            "private_collection_enabled": True,
            "child_license_key": "AP-CHLD-5C6DB04C-C53AE9C4",
            "status": "active", "cell_phone": "",
        }
        values = _build_seat_row_values(user, "CrystalApp")
        tok_col = values[9]   # index 9 = token column
        assert tok_col == "●" * 8
        assert "CrystalApp" not in tok_col   # real token never shown

    def test_empty_seat_key_shows_blank(self):
        """User with no seat assigned shows empty string in seat column."""
        user = {
            "name": "Jamie Vavro", "email": "jamie@example.com",
            "role": "staff", "scopes": [], "can_manage_users": False,
            "private_collection_enabled": True,
            "child_license_key": "",
            "status": "suspended", "cell_phone": "",
        }
        values = _build_seat_row_values(user, "CrystalApp")
        seat_col = values[7]
        assert seat_col == ""


# ── TC-ASSIGN: Worker assign uses seat_id not AP-BIZ- child_key ──────────────

class TestWorkerAssignUsesCorrectId:

    def test_seat_id_found_for_child_key(self, tmp_path):
        """_find_seat_id_for_child_key returns correct seat_id from local file."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        biz_key = "AP-BIZ-AC94AE8B-BA91CA47"
        chld    = "AP-CHLD-F8AEB4DF-21304384"
        sid     = f"{biz_key}-S001"
        lsf = _make_seats_file(ai_dir, biz_key, [
            {"seat_id": sid, "child_license_key": chld,
             "status": "unassigned", "assigned_to": None},
        ])
        result = _find_seat_id_for_child_key(lsf, chld)
        assert result == sid

    def test_seat_id_lookup_returns_empty_when_not_found(self, tmp_path):
        """Returns empty string when child_key not in seats file."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        lsf = _make_seats_file(ai_dir, "AP-BIZ-X", [
            {"seat_id": "AP-BIZ-X-S001",
             "child_license_key": "AP-CHLD-AAAA1111-BBBB2222",
             "status": "unassigned"},
        ])
        result = _find_seat_id_for_child_key(lsf, "AP-CHLD-CCCC3333-DDDD4444")
        assert result == ""

    def test_assign_call_uses_seat_id_not_biz_prefix(self, tmp_path):
        """Worker assign call uses seat_id (AP-BIZ-...-S001) not child_key.
        Before fix: gated on AP-BIZ- prefix so AP-CHLD- keys never triggered."""
        ai_dir  = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        biz_key = "AP-BIZ-AC94AE8B-BA91CA47"
        chld    = "AP-CHLD-F8AEB4DF-21304384"
        sid     = f"{biz_key}-S001"
        lsf = _make_seats_file(ai_dir, biz_key, [
            {"seat_id": sid, "child_license_key": chld,
             "status": "unassigned", "assigned_to": None},
        ])
        # Replicate new assign logic: look up seat_id, use it or fall back to key
        found_sid = _find_seat_id_for_child_key(lsf, chld)
        assign_arg = found_sid or chld
        assert assign_arg == sid          # uses seat_id not child_key
        assert assign_arg.startswith("AP-BIZ-")  # correct format for /assign endpoint

    def test_old_prefix_check_would_have_failed(self):
        """Show why the old AP-BIZ- prefix check was wrong for AP-CHLD- keys."""
        chld = "AP-CHLD-F8AEB4DF-21304384"
        # Old condition: if child_key and child_key.startswith("AP-BIZ-")
        old_would_fire = chld.startswith("AP-BIZ-")
        assert old_would_fire is False   # always False for real seat keys

    def test_fallback_uses_child_key_when_lsf_missing(self, tmp_path):
        """When license_seats.json missing, falls back to child_key directly."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        lsf  = ai_dir / "license_seats.json"
        chld = "AP-CHLD-F8AEB4DF-21304384"
        # No file — fallback
        found_sid  = _find_seat_id_for_child_key(lsf, chld)
        assign_arg = found_sid or chld
        assert assign_arg == chld   # graceful fallback


# ── TC-SYNC: sync_seats works without admin token ─────────────────────────────

class TestSyncWithoutAdminToken:

    def test_sync_proceeds_without_token(self):
        """sync_seats no longer raises RuntimeError when token is empty.
        Before fix: raised 'No admin token available.' before network call."""
        called = []

        def mock_poster(path, body, bearer=""):
            called.append({"path": path, "bearer": bearer})
            return 200, {"seats": [], "seats_total": 6}

        ok, result = _sync_needs_no_token_logic("AP-BIZ-AC94AE8B-BA91CA47",
                                                 mock_poster)
        assert ok is True
        assert len(called) == 1    # network call WAS made
        assert called[0]["bearer"] == ""   # empty token sent (that's fine)

    def test_sync_url_contains_license_key(self):
        """sync_seats calls /seats/{key}/sync with correct license key."""
        seen = []

        def mock_poster(path, body, bearer=""):
            seen.append(path)
            return 200, {"seats": []}

        _sync_needs_no_token_logic("AP-BIZ-AC94AE8B-BA91CA47", mock_poster)
        assert len(seen) == 1
        assert "AP-BIZ-AC94AE8B-BA91CA47" in seen[0]
        assert "/sync" in seen[0]

    def test_sync_with_token_still_works(self):
        """sync_seats also works when admin token IS available (no regression)."""
        called = []

        def mock_poster(path, body, bearer=""):
            called.append({"bearer": bearer})
            return 200, {"seats": []}

        ok, _ = _sync_needs_no_token_logic("AP-BIZ-AC94AE8B-BA91CA47",
                                            mock_poster)
        assert ok is True
        assert len(called) == 1

    def test_sync_handles_worker_error_gracefully(self):
        """When Worker returns non-200, sync returns False without crashing."""
        def mock_poster(path, body, bearer=""):
            return 401, {"error": "Unauthorized"}

        ok, result = _sync_needs_no_token_logic("AP-BIZ-AC94AE8B-BA91CA47",
                                                 mock_poster)
        assert ok is False

    def test_sync_handles_network_exception_gracefully(self):
        """Network failure returns False without crashing."""
        def mock_poster(path, body, bearer=""):
            raise Exception("Connection refused")

        ok, result = _sync_needs_no_token_logic("AP-BIZ-AC94AE8B-BA91CA47",
                                                 mock_poster)
        assert ok is False
        assert "Connection refused" in result


# ===========================================================================
# TC-AUTOSYNC: _admin_refresh_table auto-sync of license_seats.json
#
# Cases:
#   1. Fresh install — no files, no crash
#   2. Reinstall — users.json has assignments, license_seats all unassigned
#   3a. Add user — seat already marked assigned, no double-write
#   3b. Remove user — seat already unassigned, no change
#   4. Change bearer password — child_license_key unchanged, seat stays assigned
#   5. Stripe reduces seats — over_quota_since present, removed seats protected
#
# All tests use tmp_path — zero ~/.ai-prowler/, KV, Stripe, CF pollution.
# ===========================================================================


def _auto_sync_logic(ai_dir):
    """Replicate the auto-sync block from _admin_refresh_table().
    Returns (changed: bool, updated_seats: list)."""
    import json

    users_p = ai_dir / "users.json"
    lsf_p   = ai_dir / "license_seats.json"

    if not users_p.exists() or not lsf_p.exists():
        return False, []

    users_data = json.loads(users_p.read_text(encoding="utf-8"))
    lsd        = json.loads(lsf_p.read_text(encoding="utf-8"))

    _assigned = {}
    for _u in users_data.get("users", {}).values():
        if isinstance(_u, dict) and _u.get("child_license_key"):
            _assigned[_u["child_license_key"]] = (
                _u.get("email") or _u.get("name", ""))

    _changed = False
    for _s in lsd.get("seats", []):
        _ck = _s.get("child_license_key", "")
        if _ck in _assigned:
            if _s.get("status") != "assigned":
                _s["status"]      = "assigned"
                _s["assigned_to"] = _assigned[_ck]
                _changed = True
        else:
            if _s.get("status") == "assigned":
                _s["status"]      = "unassigned"
                _s["assigned_to"] = None
                _changed = True
            elif _s.get("status") == "removed":
                _oqs = lsd.get("over_quota_since", "")
                if not _oqs:
                    _s["status"]      = "unassigned"
                    _s["assigned_to"] = None
                    _changed = True

    if _changed:
        lsf_p.write_text(json.dumps(lsd, indent=2), encoding="utf-8")

    return _changed, lsd.get("seats", [])


def _write_users_json(ai_dir, users_dict):
    import json
    (ai_dir / "users.json").write_text(
        json.dumps({"users": users_dict}, indent=2), encoding="utf-8")


def _write_license_seats(ai_dir, biz_key, seats, extra=None):
    import json
    data = {"license_key": biz_key, "seats_total": len(seats), "seats": seats}
    if extra:
        data.update(extra)
    (ai_dir / "license_seats.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8")


def _read_seats_by_key(ai_dir):
    import json
    data = json.loads((ai_dir / "license_seats.json").read_text())
    return {s["child_license_key"]: s for s in data["seats"]}


_BIZ = "AP-BIZ-AC94AE8B-BA91CA47"
_S1  = "AP-CHLD-F8AEB4DF-21304384"
_S2  = "AP-CHLD-4B88898B-FD65DE92"
_S3  = "AP-CHLD-5C6DB04C-C53AE9C4"
_S4  = "AP-CHLD-6530F921-5A259F36"


class TestAutoSyncCase1FreshInstall:

    def test_no_files_returns_no_change(self, tmp_path):
        """Case 1: No files at all — no crash, returns no change."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        changed, seats = _auto_sync_logic(ai_dir)
        assert changed is False
        assert seats == []

    def test_no_license_seats_returns_no_change(self, tmp_path):
        """Case 1: license_seats.json absent — no crash."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear": {"name": "David", "role": "owner",
                         "child_license_key": _S1}})
        changed, seats = _auto_sync_logic(ai_dir)
        assert changed is False

    def test_empty_users_no_seat_changes(self, tmp_path):
        """Case 1: No users yet — all seats stay unassigned."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {})
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "unassigned",
             "assigned_to": None},
        ])
        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is False


class TestAutoSyncCase2Reinstall:

    def test_reinstall_marks_assigned_seats(self, tmp_path):
        """Case 2: users.json has David+Vicki assigned, license_seats shows
        all unassigned — auto-sync corrects to 2/6 assigned."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear":   {"name": "David", "email": "d@x.com",
                           "role": "owner",   "child_license_key": _S1,
                           "status": "active"},
            "Synopsys1*": {"name": "Vicki", "email": "v@x.com",
                           "role": "manager", "child_license_key": _S2,
                           "status": "active"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S2, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S3, "status": "unassigned", "assigned_to": None},
        ])

        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is True

        seats = _read_seats_by_key(ai_dir)
        assert seats[_S1]["status"]      == "assigned"
        assert seats[_S1]["assigned_to"] == "d@x.com"
        assert seats[_S2]["status"]      == "assigned"
        assert seats[_S2]["assigned_to"] == "v@x.com"
        assert seats[_S3]["status"]      == "unassigned"

    def test_reinstall_seat_count_correct(self, tmp_path):
        """Case 2: After auto-sync, assigned+unassigned counts are correct."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear":   {"name": "David", "email": "d@x.com",
                           "child_license_key": _S1, "status": "active",
                           "role": "owner"},
            "Synopsys1*": {"name": "Vicki", "email": "v@x.com",
                           "child_license_key": _S2, "status": "active",
                           "role": "manager"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S2, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S3, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S4, "status": "unassigned", "assigned_to": None},
        ])

        _auto_sync_logic(ai_dir)

        import json
        seats = json.loads((ai_dir / "license_seats.json").read_text())["seats"]
        assert sum(1 for s in seats if s["status"] == "assigned")   == 2
        assert sum(1 for s in seats if s["status"] == "unassigned") == 2


class TestAutoSyncCase3AddRemoveUser:

    def test_add_user_already_assigned_no_double_write(self, tmp_path):
        """Case 3a: _admin_mark_seat_in_local_file already ran on Save —
        auto-sync sees correct state and does nothing."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear": {"name": "David", "email": "d@x.com",
                         "child_license_key": _S1, "status": "active",
                         "role": "owner"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "assigned",
             "assigned_to": "d@x.com"},
        ])
        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is False

    def test_remove_user_already_unassigned_no_change(self, tmp_path):
        """Case 3b: Remove User already marked seat unassigned — no-op."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear": {"name": "David", "email": "d@x.com",
                         "child_license_key": _S2, "status": "active",
                         "role": "owner"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S2, "status": "assigned",   "assigned_to": "d@x.com"},
        ])
        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is False

    def test_orphaned_assigned_seat_corrected(self, tmp_path):
        """Case 3b: Seat shows 'assigned' but no user has that key —
        auto-sync corrects it to 'unassigned'."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear": {"name": "David", "email": "d@x.com",
                         "child_license_key": _S2, "status": "active",
                         "role": "owner"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "assigned",
             "assigned_to": "old@x.com"},    # orphan — no user has S1
            {"child_license_key": _S2, "status": "assigned",
             "assigned_to": "d@x.com"},
        ])
        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is True

        seats = _read_seats_by_key(ai_dir)
        assert seats[_S1]["status"]      == "unassigned"
        assert seats[_S1]["assigned_to"] is None
        assert seats[_S2]["status"]      == "assigned"


class TestAutoSyncCase4ChangePassword:

    def test_new_token_preserves_seat_assignment(self, tmp_path):
        """Case 4: Token (dict key) changes but child_license_key is the same —
        auto-sync sees the child_license_key and leaves seat assigned."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        # User record moved from 'bearbear' key to 'NewPassword1!' key
        _write_users_json(ai_dir, {
            "NewPassword1!": {"name": "David", "email": "d@x.com",
                              "child_license_key": _S1, "status": "active",
                              "role": "owner"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "assigned",
             "assigned_to": "d@x.com"},
        ])
        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is False   # child_license_key unchanged → no-op ✅

        seats = _read_seats_by_key(ai_dir)
        assert seats[_S1]["status"] == "assigned"

    def test_token_change_does_not_unassign_seat(self, tmp_path):
        """Case 4: Token change must NOT cause seat to appear unassigned."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "BrandNewToken99": {"name": "Vicki", "email": "v@x.com",
                                "child_license_key": _S2, "status": "active",
                                "role": "manager"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S2, "status": "assigned",   "assigned_to": "v@x.com"},
        ])
        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is False
        seats = _read_seats_by_key(ai_dir)
        assert seats[_S2]["status"] == "assigned"


class TestAutoSyncCase5StripeReducesSeats:

    def test_removed_seat_protected_when_over_quota_set(self, tmp_path):
        """Case 5: over_quota_since present — 'removed' seat NOT un-removed
        (Stripe reduction grace period is active)."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear": {"name": "David", "email": "d@x.com",
                         "child_license_key": _S1, "status": "active",
                         "role": "owner"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "assigned",  "assigned_to": "d@x.com"},
            {"child_license_key": _S3, "status": "removed",   "assigned_to": None},
        ], extra={"over_quota_since": "2026-07-01T00:00:00Z",
                  "over_quota_count": 1})

        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is False   # S1 correct, S3 protected

        seats = _read_seats_by_key(ai_dir)
        assert seats[_S3]["status"] == "removed"   # protected ✅

    def test_removed_seat_unremoved_when_no_over_quota(self, tmp_path):
        """Case 5 inverse: 'removed' with no over_quota_since (old UI bug)
        gets restored to 'unassigned' so seat is back in the pool."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear": {"name": "David", "email": "d@x.com",
                         "child_license_key": _S1, "status": "active",
                         "role": "owner"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "assigned",  "assigned_to": "d@x.com"},
            {"child_license_key": _S3, "status": "removed",   "assigned_to": None},
        ])  # no over_quota_since

        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is True

        seats = _read_seats_by_key(ai_dir)
        assert seats[_S3]["status"] == "unassigned"   # back in pool ✅

    def test_real_server_scenario(self, tmp_path):
        """Exact scenario from uploaded server files:
        David+Vicki in users.json with keys, license_seats all unassigned,
        Jamie's S3 shows 'removed' from old bug, no over_quota_since."""
        ai_dir = tmp_path / ".ai-prowler"
        ai_dir.mkdir()
        _write_users_json(ai_dir, {
            "bearbear":    {"name": "David Vavro",  "email": "david@g.com",
                            "child_license_key": _S1, "status": "active",
                            "role": "owner"},
            "Synopsys1*":  {"name": "Vicki Vavro",  "email": "vicki@y.com",
                            "child_license_key": _S2, "status": "active",
                            "role": "manager"},
            "CyrestalApp": {"name": "Jamie Vavro",  "email": "jamie@g.com",
                            "child_license_key": "",   # no seat
                            "status": "suspended", "role": "staff"},
        })
        _write_license_seats(ai_dir, _BIZ, [
            {"child_license_key": _S1, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S2, "status": "unassigned", "assigned_to": None},
            {"child_license_key": _S3, "status": "removed",    "assigned_to": None},
            {"child_license_key": _S4, "status": "unassigned", "assigned_to": None},
        ])

        changed, _ = _auto_sync_logic(ai_dir)
        assert changed is True

        seats = _read_seats_by_key(ai_dir)
        assert seats[_S1]["status"]      == "assigned"
        assert seats[_S1]["assigned_to"] == "david@g.com"
        assert seats[_S2]["status"]      == "assigned"
        assert seats[_S2]["assigned_to"] == "vicki@y.com"
        assert seats[_S3]["status"]      == "unassigned"   # old bug fixed ✅
        assert seats[_S4]["status"]      == "unassigned"

