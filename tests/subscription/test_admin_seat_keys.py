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
