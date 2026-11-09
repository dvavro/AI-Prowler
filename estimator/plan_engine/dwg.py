"""DWG drawings through a converter the user installed (Coder 2 Sprint 16).

Spec, Target hardware and third-party components: the ODA File Converter is free but may not be redistributed, and
LibreDWG is GPL-3.0, so neither ships with AI-Prowler. When one is installed on this PC, a DWG is converted to DXF in
the plan set's work folder and read like any DXF (exact geometry, layers and block names). When none is, the upload
is still kept and the plans say how to get one, or to save the drawing as DXF or PDF instead.

Where a converter is looked for:
- ESTIMATOR_DWG_CONVERTER: a full path to ODAFileConverter.exe or dwg2dxf(.exe), or "off" (tests; never convert);
- the ODA File Converter on the PATH or in its install folders (Program Files\\ODA\\ODAFileConverter <version>);
- LibreDWG's dwg2dxf on the PATH.
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

TIMEOUT_S = 300
ODA_VERSION = "ACAD2018"            # the DXF version the ODA converter writes (ezdxf reads R12 to R2018)
GUIDANCE = ("DWG drawings need a DWG-to-DXF converter on this PC. Install the free ODA File Converter (opendesign.com, "
            "Guest Files, ODA File Converter) and process the plans again, or save the drawing as DXF from your CAD "
            "program (Save As > DXF) or print the sheets to PDF and upload that")


def _oda_installed() -> str:
    drive = os.environ.get("SystemDrive", "C:")
    for base in (("Program Files", "ODA"), ("Program Files (x86)", "ODA")):
        hits = sorted(glob.glob(os.path.join(drive + os.sep, *base, "ODAFileConverter*", "ODAFileConverter.exe")))
        if hits:
            return hits[-1]                       # the newest version folder
    return ""


def find_converter(which=None, search_installs: bool = True) -> dict | None:
    """{"kind": "oda" | "libredwg", "name", "path"} for the converter to use, or None.
    `which` (tests) replaces shutil.which; search_installs=False skips the install folders and the setting."""
    which = which or shutil.which
    if search_installs:
        env = os.environ.get("ESTIMATOR_DWG_CONVERTER", "").strip().strip('"')
        if env.lower() in ("off", "none", "0"):
            return None
        if env and Path(env).is_file():
            kind = "libredwg" if "dwg2dxf" in Path(env).name.lower() else "oda"
            return _entry(kind, env)
    oda = which("ODAFileConverter") or (_oda_installed() if search_installs else "")
    if oda:
        return _entry("oda", oda)
    lib = which("dwg2dxf")
    if lib:
        return _entry("libredwg", lib)
    return None


def _entry(kind: str, path: str) -> dict:
    return {"kind": kind, "path": str(path),
            "name": "ODA File Converter" if kind == "oda" else "LibreDWG (dwg2dxf)"}


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(cmd, capture_output=True, timeout=TIMEOUT_S, creationflags=flags, check=False)


def convert(dwg_path: Path, out_dir: Path, converter: dict | None = None) -> Path:
    """Convert one DWG to DXF in out_dir. Raises ValueError with a plain reason."""
    conv = converter or find_converter()
    if conv is None:
        raise ValueError(GUIDANCE)
    dwg_path = Path(dwg_path)
    if not dwg_path.is_file():
        raise ValueError(f"the DWG file isn't there ({dwg_path.name})")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / (dwg_path.stem + ".dxf")
    if target.exists():
        target.unlink()
    try:
        if conv["kind"] == "oda":
            # The ODA converter works on folders: copy the one file into a folder of its own.
            with tempfile.TemporaryDirectory(prefix="dwg_in_", dir=str(out_dir)) as tmp:
                src = Path(tmp) / dwg_path.name
                shutil.copy2(dwg_path, src)
                res = _run([conv["path"], tmp, str(out_dir), ODA_VERSION, "DXF", "0", "1", src.name])
        else:
            res = _run([conv["path"], "-y", "-o", str(target), str(dwg_path)])
    except subprocess.TimeoutExpired:
        raise ValueError(f"the {conv['name']} took over {TIMEOUT_S // 60} minutes on this drawing and was stopped; "
                         "save it as DXF from your CAD program instead") from None
    except OSError as exc:
        raise ValueError(f"the {conv['name']} couldn't be started ({exc}); reinstall it, or save the drawing as DXF"
                         ) from None
    if not target.is_file():
        found = sorted(out_dir.glob(dwg_path.stem + ".[dD][xX][fF]"))
        target = found[0] if found else target
    if not target.is_file() or target.stat().st_size == 0:
        err = (res.stderr or res.stdout or b"").decode("utf-8", "replace").strip().splitlines()
        why = f": {err[-1][:200]}" if err else ""
        raise ValueError(f"the {conv['name']} couldn't convert this drawing{why}. It may be damaged or from a newer CAD "
                         "version; save it as DXF from your CAD program instead")
    return target
