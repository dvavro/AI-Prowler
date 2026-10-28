"""Every AI-Prowler phone app shows the same AI-Prowler icon.

2026-10-28 (David): the Service Desk icon had a light-blue circle drawn in its
lower-right corner - desk/icon-*.png were a different picture from the one
the Jobs, Remote, HR Admin and HR Portal apps share. The look test only
checked that an icon loaded, so it slipped through. Same bytes, every app.
"""
import hashlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
APPS = ("jobs", "remote", "hr_admin", "hr_portal", "desk")


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.mark.parametrize("name", ["icon-192.png", "icon-512.png"])
def test_every_app_ships_the_same_icon(name):
    ref = _sha(ROOT / "jobs" / name)
    odd = [app for app in APPS if _sha(ROOT / app / name) != ref]
    assert not odd, f"{name} differs from the Jobs app's in: {odd}"
