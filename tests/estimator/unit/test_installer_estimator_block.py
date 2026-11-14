"""Sprint 26 (Coder 1): the Inno installer ships the whole Estimator (S26-I..).

AI-Prowler-Setup.iss lists every file it installs explicitly. These tests
keep its Estimator block in step with the payload install_estimator.py
copies for dev installs: every runtime file under estimator/ (no
__pycache__, no *.pyc, no *.bak* backups) has exactly one [Files] entry
with the DestDir matching its folder, and the block names no file that
is not payload. Adding an estimator file without updating the installer
fails here first, instead of shipping an install without it.
"""
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
ISS = REPO / "AI-Prowler-Setup.iss"
ESTIMATOR = REPO / "estimator"
BS = chr(92)  # backslash, kept out of literals so the parsing below stays obvious


def _payload():
    out = set()
    for p in ESTIMATOR.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(REPO)
        if "__pycache__" in rel.parts or p.suffix == ".pyc" or ".bak" in p.name:
            continue
        out.add(rel.as_posix().replace("/", BS))
    return out


def _entries():
    found = {}
    for ln in ISS.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if ln.startswith("Source: " + chr(34) + "estimator" + BS):
            parts = ln.split(chr(34))
            # parts: [Source: , src, ; DestDir: , dest, ; Flags: ignoreversion]
            found.setdefault(parts[1], []).append(parts[3])
    return found


def test_every_payload_file_is_in_the_installer():  # S26-I01
    payload, entries = _payload(), _entries()
    missing = sorted(payload - set(entries))
    assert not missing, (
        f"{len(missing)} estimator file(s) missing from AI-Prowler-Setup.iss, "
        f"e.g. {missing[:5]}"
    )


def test_no_stale_or_duplicate_entries():  # S26-I02
    payload, entries = _payload(), _entries()
    stale = sorted(set(entries) - payload)
    assert not stale, f"installer names estimator files that are not payload: {stale[:5]}"
    dups = sorted(k for k, v in entries.items() if len(v) > 1)
    assert not dups, f"duplicate estimator entries in the installer: {dups[:5]}"


def test_in_app_updates_ship_every_estimator_file():  # S26-I04 (2026-11-13)
    """scripts/release.py MANIFEST_FILES (what the in-app auto-update downloads) covers exactly the installer's
    Estimator payload: a new file type under estimator/ that no glob matches fails here."""
    import ast
    tree = ast.parse((REPO / "scripts" / "release.py").read_text(encoding="utf-8"))
    listed = next([e.value for e in node.value.elts] for node in ast.walk(tree)
                  if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "MANIFEST_FILES"
                                                          for t in node.targets))
    shipped = set()
    for rel in listed:
        if rel.startswith("estimator/"):
            hits = {p.relative_to(REPO).as_posix().replace("/", BS) for p in REPO.glob(rel) if p.is_file()}
            assert hits, f"release list glob matches nothing: {rel}"
            shipped |= hits
    payload = _payload()
    assert not sorted(payload - shipped), f"in-app updates would miss: {sorted(payload - shipped)[:5]}"
    assert not sorted(shipped - payload), f"in-app updates would ship non-payload files: {sorted(shipped - payload)[:5]}"


def test_destdir_matches_location():  # S26-I03
    for src, destdirs in _entries().items():
        want = "{app}" + BS + BS.join(src.split(BS)[:-1])
        assert destdirs == [want], f"{src}: DestDir {destdirs} != {want}"
