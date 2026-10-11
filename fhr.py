import pathlib
src = pathlib.Path("ai_prowler_mcp.py").read_text(encoding="utf-8")
lines = src.split("\n")
for i,line in enumerate(lines,1):
    if "startswith" in line and "/hr" in line and "path" in line:
        print(str(i)+": "+line)
