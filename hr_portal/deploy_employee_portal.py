import pathlib, shutil, sys

# ── Paths ────────────────────────────────────────────────────
DEV_ROOT = pathlib.Path(".")
EMPLOYEE_DEV = DEV_ROOT / "employee"
PROD_ROOT = pathlib.Path("C:/Program Files/AI-Prowler")
EMPLOYEE_PROD = PROD_ROOT / "employee"
MCP = DEV_ROOT / "ai_prowler_mcp.py"

# ── 1. Create dev employee folder ────────────────────────────
EMPLOYEE_DEV.mkdir(exist_ok=True)
print("Created dev employee/ folder")

# Copy files from Downloads or current dir
downloads = pathlib.Path.home() / "Downloads"
for fname, dest_name in [
    ("employee_index.html", "index.html"),
    ("employee_sw.js",      "sw.js"),
    ("employee_manifest.json", "manifest.json"),
]:
    src = downloads / fname
    if src.exists():
        shutil.copy2(str(src), str(EMPLOYEE_DEV / dest_name))
        print(f"Copied {fname} -> employee/{dest_name}")
    else:
        print(f"WARN: {fname} not found in Downloads - copy manually")

# Copy icons from hr/ folder (same icons)
for icon in ["icon-192.png", "icon-512.png"]:
    hr_icon = DEV_ROOT / "hr" / icon
    emp_icon = EMPLOYEE_DEV / icon
    if hr_icon.exists():
        shutil.copy2(str(hr_icon), str(emp_icon))
        print(f"Copied icon: {icon}")
    else:
        print(f"WARN: {icon} not found in hr/ - copy manually")

# ── 2. Add /employee route to ai_prowler_mcp.py ─────────────
import py_compile

src = MCP.read_text(encoding="utf-8")
shutil.copy2(str(MCP), str(MCP) + ".bak_employee")

ANCHOR = 'path.startswith("/hr")'
if ANCHOR not in src:
    print("ERROR: /hr route anchor not found in ai_prowler_mcp.py")
    sys.exit(1)

# Add /employee static route alongside /hr
NEW_ROUTE = (
    'path.startswith("/employee") or '
)
if 'path.startswith("/employee")' not in src:
    src = src.replace(ANCHOR, NEW_ROUTE + ANCHOR, 1)
    print("Added /employee route to dispatcher")
else:
    print("/employee route already present")

# Also add the static file serving for /employee/
STATIC_ANCHOR = '_HROS_ROOT_DIR / "hr"'
if STATIC_ANCHOR in src and '"employee"' not in src:
    NEW_STATIC = (
        '_HROS_ROOT_DIR / "employee" if path.startswith("/employee") else '
    )
    src = src.replace(STATIC_ANCHOR, NEW_STATIC + STATIC_ANCHOR, 1)
    print("Added /employee static file serving")

# Syntax check
tmp = pathlib.Path("_emp_tmp.py")
tmp.write_text(src, encoding="utf-8")
try:
    py_compile.compile(str(tmp), doraise=True)
    print("Syntax check: PASSED")
    tmp.unlink()
except py_compile.PyCompileError as e:
    print("Syntax check: FAILED -", e)
    tmp.unlink()
    # Restore backup
    shutil.copy2(str(MCP) + ".bak_employee", str(MCP))
    sys.exit(1)

MCP.write_text(src, encoding="utf-8")
print("ai_prowler_mcp.py updated")

# ── 3. Deploy to Program Files ───────────────────────────────
EMPLOYEE_PROD.mkdir(parents=True, exist_ok=True)
for f in EMPLOYEE_DEV.iterdir():
    shutil.copy2(str(f), str(EMPLOYEE_PROD / f.name))
    print(f"Deployed: employee/{f.name}")

shutil.copy2(str(MCP), str(PROD_ROOT / "ai_prowler_mcp.py"))
print("Deployed: ai_prowler_mcp.py")

print("")
print("SUCCESS! Employee portal deployed.")
print("URL: https://ap-jamievavroaiprowler-f68efeed.ai-prowler.com/employee/")
print("Restart AI-Prowler from the tray to activate.")
