"""One-off: undo doubled escapes (backslash-backslash, backslash-quote) in the
R-078..R-082 rows of JOBS_APP_E2E_TEST_SPEC.md. Byte-exact otherwise."""
import pathlib

p = pathlib.Path(__file__).resolve().parents[1] / "JOBS_APP_E2E_TEST_SPEC.md"
raw = p.read_bytes()
nl = b"\r\n" if b"\r\n" in raw else b"\n"
lines = raw.split(nl)
n = 0
for i, ln in enumerate(lines):
    if ln.startswith((b"| R-078 |", b"| R-079 |", b"| R-080 |", b"| R-081 |", b"| R-082 |")):
        new = ln.replace(b"\\\\", b"\\").replace(b'\\"', b'"')
        if new != ln:
            lines[i] = new
            n += 1
p.write_bytes(nl.join(lines))
print(f"fixed {n} row(s); newline={nl!r}")
