"""
Timing test for check_ai_prowler_status via Claude Code CLI.
Simulates what Claude Desktop does — uses the real claude CLI with the
work dir ai_prowler_mcp.py (which has the prewarm fixes applied).

PASS criteria:
  - Tool responds in < 20 seconds (was ~72s before fix)
  - No permission_denials
  - Result contains "AI-Prowler" (real response, not error)

Run this test before and after changes to ai_prowler_mcp.py to verify
the prewarm fix holds. The baseline (unfixed) was ~72s.
"""
import subprocess, time, json, os
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────
PASS_THRESHOLD_SECONDS = 20   # fail if slower than this
TOOL_NAME = "check_ai_prowler_status"
PYTHON_EXE = r'C:\Users\david\AppData\Local\Programs\Python\Python311\python.exe'
WORKDIR_MCP = Path(r'C:\Users\david\AI-Prowler_V812_to_V900_work\AI-Prowler\ai_prowler_mcp.py')
HOME = Path.home() / '.ai-prowler'
TOKEN_FILE = HOME / 'claude_oauth_token.txt'

# MCP config pointing to WORK DIR ai_prowler_mcp.py
# AI_PROWLER_HEADLESS=1 → prewarm skipped (headless runner path)
# Without it → prewarm + 15s watchdog (Claude Desktop path)
def make_mcp_config(headless: bool) -> Path:
    cfg_path = HOME / f'claude_mcp_config_test_{"headless" if headless else "interactive"}.json'
    cfg = {
        "mcpServers": {
            "ai-prowler": {
                "command": PYTHON_EXE,
                "args": [str(WORKDIR_MCP)],
                "env": {
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONIOENCODING": "utf-8",
                    "PYTHONUNBUFFERED": "1",
                    "PYTHONWARNINGS": "ignore",
                    **({"AI_PROWLER_HEADLESS": "1"} if headless else {}),
                }
            }
        }
    }
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding='utf-8')
    return cfg_path

def run_check(label: str, headless: bool, timeout: int = 60) -> dict:
    """Run check_ai_prowler_status via Claude CLI and return timing + result."""
    mcp_cfg = make_mcp_config(headless)
    token = TOKEN_FILE.read_text(encoding='utf-8').strip()

    env = os.environ.copy()
    env['CLAUDE_CODE_OAUTH_TOKEN'] = token

    prompt = (
        f"Call {TOOL_NAME} and report what it says. "
        "Do not call any other tools."
    )

    print(f"\n{'─'*60}")
    print(f"  {label}")
    print(f"  headless={headless}  timeout={timeout}s")
    print(f"  mcp_config: {mcp_cfg.name}")
    print(f"  Starting at {time.strftime('%H:%M:%S')}...")

    t0 = time.time()
    timed_out = False
    try:
        r = subprocess.run(
            ['claude', '-p', prompt,
             '--mcp-config', str(mcp_cfg),
             '--allowedTools', f'mcp__ai-prowler__{TOOL_NAME}',
             '--output-format', 'json',
             '--permission-mode', 'bypassPermissions'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            env=env,
            cwd=str(HOME),
            timeout=timeout
        )
        elapsed = time.time() - t0
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        timed_out = True

    result = {
        'label': label,
        'headless': headless,
        'elapsed': elapsed,
        'timed_out': timed_out,
        'passed': False,
        'result_text': '',
        'denials': 0,
        'error': None,
    }

    if timed_out:
        result['error'] = f'TimeoutExpired after {elapsed:.1f}s'
        print(f"  ❌ TIMED OUT after {elapsed:.1f}s")
        return result

    try:
        data = json.loads(r.stdout)
        result['denials'] = len(data.get('permission_denials', []))
        result['result_text'] = data.get('result', '')
        # PASS: fast enough, no denials, real response
        result['passed'] = (
            elapsed < PASS_THRESHOLD_SECONDS and
            result['denials'] == 0 and
            'AI-Prowler' in result['result_text']
        )
        status = '✅ PASS' if result['passed'] else '❌ FAIL'
        print(f"  {status} — {elapsed:.1f}s  denials={result['denials']}")
        print(f"  Result: {result['result_text'][:200]}")
    except Exception as e:
        result['error'] = str(e)
        print(f"  ❌ Parse error: {e}")
        print(f"  stdout: {r.stdout[:300]}")

    return result

# ── Run tests ──────────────────────────────────────────────────────────────
print("=" * 60)
print("  check_ai_prowler_status timing test")
print(f"  PASS threshold: < {PASS_THRESHOLD_SECONDS}s")
print(f"  Baseline (pre-fix): ~72s")
print("=" * 60)

results = []

# Test 1: Headless mode (AI_PROWLER_HEADLESS=1) — prewarm skipped
results.append(run_check(
    "Test 1: Headless mode (AI_PROWLER_HEADLESS=1)",
    headless=True,
    timeout=30
))

# Test 2: Interactive mode (no headless flag) — prewarm + 15s watchdog
results.append(run_check(
    "Test 2: Interactive mode (prewarm + 15s watchdog)",
    headless=False,
    timeout=30
))

# ── Summary ────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("  SUMMARY")
print(f"{'='*60}")
all_passed = True
for r in results:
    status = '✅ PASS' if r['passed'] else ('⏱ TIMEOUT' if r['timed_out'] else '❌ FAIL')
    print(f"  {status}  {r['elapsed']:.1f}s  {r['label']}")
    if not r['passed']:
        all_passed = False
        if r.get('error'):
            print(f"         error: {r['error']}")
        if r.get('denials', 0):
            print(f"         denials: {r['denials']}")

print()
if all_passed:
    print("  ✅ ALL TESTS PASSED — prewarm fix is working")
else:
    print("  ❌ SOME TESTS FAILED — check output above")
print(f"{'='*60}")
