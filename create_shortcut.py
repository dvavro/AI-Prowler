#!/usr/bin/env python3
"""
AI Prowler Shortcut Creator
Creates a Windows desktop shortcut pointing to RAG_RUN.bat
Uses rag_icon.ico from the install directory (assumed to already exist).
"""

import os
import subprocess
from pathlib import Path


def create_desktop_shortcut():
    """Create desktop shortcut using PowerShell - no external dependencies."""

    install_dir = Path(__file__).parent
    target      = install_dir / "RAG_RUN.bat"
    icon_path   = install_dir / "rag_icon.ico"

    # Escape backslashes for embedding inside PowerShell string literals
    target_ps      = str(target).replace("\\", "\\\\")
    install_dir_ps = str(install_dir).replace("\\", "\\\\")
    icon_ps        = str(icon_path).replace("\\", "\\\\")

    # Resolve real Desktop path - handles OneDrive Desktop transparently
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "[Environment]::GetFolderPath('Desktop')"],
        capture_output=True, text=True
    )
    if result.returncode == 0 and result.stdout.strip():
        desktop = Path(result.stdout.strip())
    else:
        desktop = Path.home() / "Desktop"

    shortcut_file    = desktop / "AI Prowler.lnk"
    shortcut_file_ps = str(shortcut_file).replace("\\", "\\\\")

    # Always apply the icon - rag_icon.ico is assumed to be present
    icon_line = f'$Shortcut.IconLocation = "{icon_ps},0"'

    ps_script = f"""
$WshShell  = New-Object -ComObject WScript.Shell
$Shortcut  = $WshShell.CreateShortcut("{shortcut_file_ps}")
$Shortcut.TargetPath       = "{target_ps}"
$Shortcut.WorkingDirectory = "{install_dir_ps}"
$Shortcut.Description      = "AI Prowler - Personal AI Knowledge Base"
$Shortcut.WindowStyle      = 7
{icon_line}
$Shortcut.Save()
Write-Host "[OK] Shortcut saved"
"""

    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        capture_output=True, text=True
    )

    if shortcut_file.exists():
        print(f"[OK] Desktop shortcut created: {shortcut_file}")
        print(f"[OK] Icon applied: {icon_path}")

        # Tell the Windows shell to refresh all icons immediately.
        # SHChangeNotify(SHCNE_ASSOCCHANGED) is the correct API for this --
        # it signals Explorer to rebuild its icon cache for changed associations
        # without killing or restarting Explorer.
        try:
            import ctypes
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
            print("[OK] Icon cache refreshed - panther icon will appear now")
        except Exception:
            pass  # Non-fatal - icon will appear after next login if this fails

        return True
    else:
        print(f"[FAIL] Could not create shortcut.")
        if result.stderr:
            print(f"       Error: {result.stderr.strip()}")
        return False


def main():
    print()
    print("=" * 60)
    print("AI PROWLER SHORTCUT CREATOR")
    print("=" * 60)
    print()

    success = create_desktop_shortcut()

    print()
    print("=" * 60)
    if success:
        print("[OK] Desktop shortcut ready - launch AI Prowler from your desktop!")
    else:
        print("[WARN] Shortcut not created.")
        print("       You can still launch AI Prowler by running RAG_RUN.bat")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
