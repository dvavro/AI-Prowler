"""Settings toggles the E2E suite may flip — and always puts back (R-060,
David 2026-09-29: "can your tests change the settings ... turn on and off email
send with route or the customer reminders emails or SMS?" -> "Yes").

Only these three Enabled/Disabled rows, nothing else in Settings:
    Email Route On Build · Customer Reminder Email Enabled · Customer Reminder SMS Enabled

How it stays safe
  * snapshot() saves the original Value + Notes of each toggle to
    artifacts/settings_to_restore.json BEFORE anything can change. The guard
    (safety.py) allows a Settings write only for a toggle that is in that
    snapshot, only to Enabled/Disabled (or its own original value), and only
    with the Setting name / Notes unchanged.
  * restore() puts every toggle back and reads it back. It runs after each test
    that flips one (the `toggles` fixture), again at the end of the run, and at
    the START of the next run if a run was killed (the file is still there).
  * verify() compares with the snapshot; any difference is reported as a
    leftover, which fails the run like a leftover ZTEST row.
Flipping a toggle never widens what may really be SENT: tier safe sends
nothing, tier email/full one message to David, SMS never in the personal suite.
"""
from __future__ import annotations

import json
from pathlib import Path

# setting -> the only values a test may set it to. R-061 (David 2026-09-29
# 05:10) added the route start/end mode so routing is tested in both modes.
SWITCHES = {
    "Email Route On Build": ("Enabled", "Disabled"),
    "Customer Reminder Email Enabled": ("Enabled", "Disabled"),
    "Customer Reminder SMS Enabled": ("Enabled", "Disabled"),
    "Route Origin Mode": ("Jobs Only", "Company Location"),
    # Working Days (Vicki 2026-10-02): weekday-only vs. every day. The server
    # stores this in a tidy form, so these are exactly what it saves.
    "Working Days": ("Mon,Tue,Wed,Thu,Fri", "Mon,Tue,Wed,Thu,Fri,Sat,Sun"),
}
TOGGLES = tuple(SWITCHES)
# Saved with the switches but never changed: the app's Route Origin Mode form
# also re-saves these four Start/End Address rows (their current values) — the
# guard allows exactly that (same value as saved), nothing else.
KEEP_AS_IS = ("Start/End Street Address", "Start/End City", "Start/End State", "Start/End ZIP")
_WATCHED = TOGGLES + KEEP_AS_IS
STATE_FILE = Path(__file__).resolve().parent / "artifacts" / "settings_to_restore.json"


def _norm(v) -> str:
    return str(v or "").strip()


class SettingsSwitch:
    def __init__(self, api, guard, log=None, state_file: Path | None = None):
        self.api, self.guard = api, guard
        self.log = log or (lambda *a: None)
        self.state_file = Path(state_file or STATE_FILE)
        self.saved: dict[str, dict] = {}

    # ── reading ───────────────────────────────────────────────────────────────
    def current(self) -> dict[str, dict]:
        out = {}
        for r in self.api.read("Settings"):
            k = _norm(r.get("Setting"))
            if k in _WATCHED:
                out[k] = {"Value": _norm(r.get("Value")), "Notes": _norm(r.get("Notes"))}
        return out

    def value(self, key: str) -> str:
        return self.current().get(key, {}).get("Value", "")

    # ── the snapshot (first thing, before any write) ──────────────────────────
    def snapshot(self) -> dict:
        """Restores a killed run's leftovers first, then saves the originals."""
        recovered = []
        if self.state_file.exists():
            try:
                old = json.loads(self.state_file.read_text(encoding="utf-8"))
            except Exception:
                old = {}
            if old:
                self.log(f"settings: a previous run left {self.state_file.name} — putting its originals back first")
                self._arm(old)
                recovered = self._put_back(old)
        now = self.current()
        self.saved = {k: dict(v, Allowed=list(SWITCHES.get(k, ()))) for k, v in now.items() if k in _WATCHED}
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(self.saved, indent=2), encoding="utf-8")
        self._arm(self.saved)
        self.log("settings: saved originals " + ", ".join(f"{k}={v['Value']!r}" for k, v in self.saved.items()))
        return {"recovered": recovered, "saved": self.saved}

    def _arm(self, saved: dict):
        self.guard.settings_saved = {k: dict(v) for k, v in saved.items()}
        for k, v in saved.items():
            self.guard.observe_setting(k, v.get("Value", ""))

    # ── writing ───────────────────────────────────────────────────────────────
    def set(self, key: str, value: str) -> str:
        """Sets one toggle (through the guard) and reads it back."""
        if key not in self.saved:
            raise KeyError(f"{key!r} is not a saved toggle (snapshot() first)")
        if value not in SWITCHES.get(key, ()):
            raise ValueError(f"{key!r} may only be set to {SWITCHES.get(key, '(never changed)')}")
        self.guard.observe_setting(key, value, pending=True)
        out = self.api.call("update_job_spreadsheet", {
            "sheet_name": "Settings", "id_column": "Setting", "job_identifier": key,
            "updates": {"Value": value}}, expect_ok=False)
        got = self.value(key)
        self.guard.observe_setting(key, got)
        self.log(f"settings: {key} -> {got!r} (asked {value!r})")
        if got.lower() != value.lower():
            raise AssertionError(f"setting {key!r} did not change to {value!r}: now {got!r} ({str(out)[:160]!r})")
        return got

    def _put_back(self, saved: dict) -> list[str]:
        now = self.current()
        changed = []
        for k, v in saved.items():
            want = v.get("Value", "")
            if now.get(k, {}).get("Value", "") != want:
                self.guard.observe_setting(k, want, pending=True)
                self.api.call("update_job_spreadsheet", {
                    "sheet_name": "Settings", "id_column": "Setting", "job_identifier": k,
                    "updates": {"Value": want}}, expect_ok=False)
                changed.append(k)
        for k, v in self.current().items():
            self.guard.observe_setting(k, v["Value"])
        return changed

    def restore(self) -> list[str]:
        """Puts every toggle back; returns what was changed. Deletes the state
        file only when everything matches the snapshot again."""
        if not self.saved:
            return []
        changed = self._put_back(self.saved)
        if changed:
            self.log(f"settings: restored {changed}")
        if not self.verify():
            try:
                self.state_file.unlink()
            except FileNotFoundError:
                pass
        return changed

    def verify(self) -> list[str]:
        """Differences from the snapshot, as leftover lines ([] = all back)."""
        now = self.current()
        return [f"Setting '{k}' is {now.get(k, {}).get('Value', '(missing)')!r}, was {v['Value']!r}"
                for k, v in self.saved.items() if now.get(k, {}).get("Value", "") != v["Value"]]
