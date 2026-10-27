"""
Tests for the v9.5.0 cloudflared security upgrade (Cloudflare eMudhra
advisory, Oct 2026): cloudflared_upgrade.py, upgrade_cloudflared.ps1 and
the places that must ship them (installer, release manifest, in-app
updater fallback list).

Default run: pure unit + static checks, no network, no UAC, no services.
The one live test (real download into a temp folder) is marked `manual`:
    python -m pytest tests\\unit\\test_cloudflared_upgrade.py -m manual -v
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import cloudflared_upgrade as cfu  # noqa: E402

PS1 = ROOT / "upgrade_cloudflared.ps1"
ISS = ROOT / "AI-Prowler-Setup.iss"
RELEASE = ROOT / "scripts" / "release.py"
GUI = ROOT / "rag_gui.py"


# ── Version parsing / comparison ─────────────────────────────────────────────

class TestParseVersion:
    def test_full_cli_output(self):
        assert cfu.parse_version(
            "cloudflared version 2026.3.0 (built 2026-03-05T16:47 UTC)") == (2026, 3, 0)

    def test_bare(self):
        assert cfu.parse_version("2026.10.2") == (2026, 10, 2)

    @pytest.mark.parametrize("junk", [None, "", "cloudflared", "version ?", 42])
    def test_unparseable(self, junk):
        assert cfu.parse_version(junk) == ()


class TestIsOutdated:
    def test_month_compared_numerically_not_as_text(self):
        # "2026.3.0" > "2026.10.2" as strings — must still count as outdated.
        assert cfu.is_outdated("2026.3.0", "2026.10.2") is True

    @pytest.mark.parametrize("cur", ["2026.6.0", "2026.7.3", "2026.10.1"])
    def test_versions_seen_in_dashboard_are_outdated(self, cur):
        assert cfu.is_outdated(cur, "2026.10.2") is True

    @pytest.mark.parametrize("cur", ["2026.10.2", "2026.10.4", "2027.1.0"])
    def test_current_versions_ok(self, cur):
        assert cfu.is_outdated(cur, "2026.10.2") is False

    def test_unknown_current_is_not_outdated(self):
        assert cfu.is_outdated(None, "2026.10.2") is False
        assert cfu.is_outdated("garbage", "2026.10.2") is False

    def test_bad_minimum_falls_back_to_floor(self):
        assert cfu.is_outdated("2026.3.0", "nonsense") is True


class TestResolveMinVersion:
    def test_default_without_notifications(self):
        assert cfu.resolve_min_version(None) == cfu.DEFAULT_MIN_VERSION
        assert cfu.resolve_min_version({}) == cfu.DEFAULT_MIN_VERSION

    def test_remote_can_raise_the_bar(self):
        assert cfu.resolve_min_version(
            {"min_cloudflared_version": "2027.2.1"}) == "2027.2.1"

    def test_remote_can_never_lower_the_floor(self):
        assert cfu.resolve_min_version(
            {"min_cloudflared_version": "2025.1.0"}) == cfu.DEFAULT_MIN_VERSION

    @pytest.mark.parametrize("bad", ["", "latest", None, 7])
    def test_invalid_remote_ignored(self, bad):
        assert cfu.resolve_min_version(
            {"min_cloudflared_version": bad}) == cfu.DEFAULT_MIN_VERSION

    def test_non_dict_notifications(self):
        assert cfu.resolve_min_version(["not", "a", "dict"]) == cfu.DEFAULT_MIN_VERSION


# ── check() ──────────────────────────────────────────────────────────────────

class TestCheck:
    def test_missing_exe_is_not_prompted(self, tmp_path):
        info = cfu.check(tmp_path / "cloudflared.exe")
        assert info["status"] == "missing"

    @pytest.mark.parametrize("ver,status", [
        ("2026.3.0", "outdated"),
        ("2026.10.2", "ok"),
        ("2026.10.4", "ok"),
        (None, "unknown"),
    ])
    def test_status(self, tmp_path, monkeypatch, ver, status):
        exe = tmp_path / "cloudflared.exe"
        exe.write_bytes(b"x")
        monkeypatch.setattr(cfu, "get_version", lambda e: ver)
        info = cfu.check(exe)
        assert info["status"] == status
        assert info["current"] == ver
        assert info["minimum"] == cfu.DEFAULT_MIN_VERSION

    def test_remote_minimum_applied(self, tmp_path, monkeypatch):
        exe = tmp_path / "cloudflared.exe"
        exe.write_bytes(b"x")
        monkeypatch.setattr(cfu, "get_version", lambda e: "2026.10.4")
        info = cfu.check(exe, {"min_cloudflared_version": "2027.1.0"})
        assert info["status"] == "outdated"
        assert info["minimum"] == "2027.1.0"

    def test_get_version_parses_cli_output(self, tmp_path, monkeypatch):
        exe = tmp_path / "cloudflared.exe"
        exe.write_bytes(b"x")

        class R:
            stdout = "cloudflared version 2026.7.3 (built 2026-07-01T00:00 UTC)\n"
            stderr = ""
        monkeypatch.setattr(cfu.subprocess, "run", lambda *a, **k: R())
        assert cfu.get_version(exe) == "2026.7.3"

    def test_get_version_survives_crash(self, tmp_path, monkeypatch):
        exe = tmp_path / "cloudflared.exe"
        exe.write_bytes(b"x")

        def boom(*a, **k):
            raise OSError("not a valid Win32 application")
        monkeypatch.setattr(cfu.subprocess, "run", boom)
        assert cfu.get_version(exe) is None


# ── run_elevated_upgrade() (UAC mocked) ──────────────────────────────────────

@pytest.mark.skipif(sys.platform != "win32", reason="ShellExecuteW is Windows-only")
class TestRunElevatedUpgrade:
    @pytest.fixture
    def home(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        return tmp_path

    def _patch_shellexecute(self, monkeypatch, fn):
        import ctypes
        monkeypatch.setattr(ctypes.windll.shell32, "ShellExecuteW", fn, raising=False)

    def test_uac_declined(self, home, monkeypatch):
        calls = []
        self._patch_shellexecute(monkeypatch, lambda *a: calls.append(a) or 5)
        res = cfu.run_elevated_upgrade(home / "cloudflared.exe", "2026.10.2", timeout=2)
        assert res["status"] == "cancelled"
        assert calls and calls[0][1] == "runas" and calls[0][2] == "powershell.exe"

    def test_result_file_returned(self, home, monkeypatch):
        result_file = home / ".ai-prowler" / "cloudflared_upgrade_result.json"

        def fake(hwnd, verb, exe, args, cwd, show):
            # The elevated script writes this when it finishes.
            assert f'-ResultFile "{result_file}"' in args
            result_file.write_text(json.dumps(
                {"status": "upgraded", "old_version": "2026.3.0",
                 "new_version": "2026.10.4", "message": "ok"}), encoding="ascii")
            return 42
        self._patch_shellexecute(monkeypatch, fake)
        res = cfu.run_elevated_upgrade(home / "cloudflared.exe", "2026.10.2", timeout=5)
        assert res["status"] == "upgraded"
        assert res["new_version"] == "2026.10.4"

    def test_stale_result_from_earlier_run_is_cleared(self, home, monkeypatch):
        state = home / ".ai-prowler"
        state.mkdir()
        (state / "cloudflared_upgrade_result.json").write_text(
            '{"status": "upgraded"}', encoding="ascii")
        self._patch_shellexecute(monkeypatch, lambda *a: 42)  # launches, never writes
        res = cfu.run_elevated_upgrade(home / "cloudflared.exe", "2026.10.2", timeout=2)
        assert res["status"] == "timeout"

    def test_missing_script(self, home, monkeypatch):
        monkeypatch.setattr(cfu, "SCRIPT_NAME", "does_not_exist.ps1")
        res = cfu.run_elevated_upgrade(home / "cloudflared.exe")
        assert res["status"] == "failed"


def test_build_ps_args_quotes_paths_with_spaces():
    args = cfu.build_ps_args(r"C:\Program Files\AI-Prowler\upgrade_cloudflared.ps1",
                             r"C:\Program Files\AI-Prowler\cloudflared.exe",
                             "2026.10.2", r"C:\Users\x y\r.json", r"C:\Users\x y\l.log")
    assert r'-File "C:\Program Files\AI-Prowler\upgrade_cloudflared.ps1"' in args
    assert r'-Dest "C:\Program Files\AI-Prowler\cloudflared.exe"' in args
    assert '-MinVersion "2026.10.2"' in args
    assert "-ExecutionPolicy Bypass" in args


# ── Static checks: the script and every place that must ship it ──────────────

class TestShipping:
    def test_ps1_is_pure_ascii(self):
        # Windows PowerShell 5.1 reads BOM-less scripts as ANSI.
        PS1.read_bytes().decode("ascii")

    def test_ps1_default_min_matches_python(self):
        m = re.search(r'\[string\]\$MinVersion\s*=\s*"([\d.]+)"', PS1.read_text())
        assert m and m.group(1) == cfu.DEFAULT_MIN_VERSION

    def test_ps1_safety_features_present(self):
        src = PS1.read_text()
        assert "Get-AuthenticodeSignature" in src
        assert 'CN="Cloudflare, Inc."' in src
        assert "<redacted>" in src, "service ImagePath (tunnel token) must be redacted in logs"
        assert "rolling back" in src

    def test_iss_min_matches_python(self):
        m = re.search(r"CLOUDFLARED_MIN_VERSION\s*=\s*'([\d.]+)'",
                      ISS.read_text(encoding="utf-8", errors="replace"))
        assert m and m.group(1) == cfu.DEFAULT_MIN_VERSION

    @pytest.mark.parametrize("name", ["cloudflared_upgrade.py", "upgrade_cloudflared.ps1"])
    def test_installer_ships(self, name):
        assert f'Source: "{name}"; DestDir: "{{app}}"' in ISS.read_text(
            encoding="utf-8", errors="replace")

    @pytest.mark.parametrize("name", ["cloudflared_upgrade.py", "upgrade_cloudflared.ps1"])
    def test_release_manifest_lists(self, name):
        assert f'"{name}"' in RELEASE.read_text(encoding="utf-8")

    @pytest.mark.parametrize("name", ["cloudflared_upgrade.py", "upgrade_cloudflared.ps1"])
    def test_in_app_updater_fallback_lists(self, name):
        assert f"'{name}'" in GUI.read_text(encoding="utf-8", errors="replace")

    def test_installer_runs_upgrade_after_download(self):
        src = ISS.read_text(encoding="utf-8", errors="replace")
        dl = src.find("cloudflared.exe already present - skipping download.")
        up = src.find("upgrade_cloudflared.ps1') + '\"'")
        assert dl != -1 and up != -1 and up > dl


# ── Live (manual): real download into a temp copy — never touches the service ─

@pytest.mark.manual
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_live_upgrade_of_temp_copy(tmp_path):
    src = Path(r"C:\Program Files\AI-Prowler\cloudflared.exe")
    if not src.exists():
        pytest.skip("no installed cloudflared.exe to copy")
    dest = tmp_path / "cloudflared.exe"
    shutil.copy2(src, dest)
    result = tmp_path / "result.json"
    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", str(PS1), "-Dest", str(dest),
                        "-ResultFile", str(result)],
                       capture_output=True, text=True, timeout=300)
    out = json.loads(result.read_text(encoding="utf-8-sig"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert out["status"] in ("upgraded", "ok")
    assert not cfu.is_outdated(cfu.get_version(dest), cfu.DEFAULT_MIN_VERSION)
    assert "--token" not in (r.stdout + r.stderr) or "<redacted>" in r.stdout
