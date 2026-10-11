"""One-off (2026-10-10): move the how_to_use_ai_prowler access-only section into a
module constant _ACCESS_ONLY_GUIDE (left out on a server) and remove the stray
lines of a botched edit. Checks every line it touches before writing."""
from pathlib import Path

f = Path(__file__).resolve().parents[2] / "ai_prowler_mcp.py"
lines = f.read_text(encoding="utf-8").split("\n")
i_dup = 1657 - 1            # 0-based
assert lines[i_dup].strip().startswith('"  • File transfer'), lines[i_dup]
assert lines[i_dup + 3].strip() == '"§§AO_MOVED§§"', lines[i_dup + 3]
assert lines[i_dup + 4].strip().startswith('"  • Access-only folders (personal mode only'), lines[i_dup + 4]
end = i_dup + 4
while not lines[end].strip().startswith('"      and the Remote Control app (Perms tab).'):
    end += 1
assert end - (i_dup + 4) < 25, "block too long — stop"
assert lines[end + 2].strip().startswith('"  • File transfer'), lines[end + 2]
block = lines[i_dup + 4: end + 1]
# drop: the 3 duplicated File-transfer lines, the marker, the block, and the blank line after it
del lines[i_dup: end + 2]
# the constant, right before how_to_use_ai_prowler's decorator
j = next(k for k, l in enumerate(lines) if l.startswith("def how_to_use_ai_prowler"))
while not lines[j - 1].startswith("@"):
    j -= 1
j -= 1
const = (["# Access-only folders section of how_to_use_ai_prowler — personal mode only.",
          "# 2026-10-10 (David): left out entirely on a server (a server offers nothing",
          "# access-only); the server footer just says it isn't available.",
          "_ACCESS_ONLY_GUIDE = ("]
         + ["    " + b.strip() for b in block] + [")", "", ""])
lines[j:j] = const
f.write_text("\n".join(lines), encoding="utf-8")
print(f"moved {len(block)} lines into _ACCESS_ONLY_GUIDE (inserted at line {j + 1})")
