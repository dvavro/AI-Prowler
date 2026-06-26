"""
AI-Prowler v8.0.0 — Two targeted fixes:

FIX 1  ai_prowler_mcp.py
  Problem : When the Worker returns HTTP 404 (license not in KV yet), the
            grace-ladder evaluator returns action="reverted_expired" which
            _run_http() treats as "blocked" and calls sys.exit(1).  This
            kills the HTTP MCP server immediately after it binds the port,
            so the GUI shows it flip green then red.
  Fix     : Only hard-block on "reverted_revoked" (Worker explicitly
            revoked/suspended the key).  Everything else (no cache + 404,
            network failure, new install) becomes "unmanaged" so the server
            starts in self-hosted/degraded mode instead of dying.

FIX 2  rag_gui.py
  Problem : The "Configure Mobile Access" _on_success handler updates only
            the domain preview label next to the activation code field.  It
            does NOT update:
              • The License Key field (still shows old key)
              • The Named Tunnel hostname field (still shows old domain)
              • The Named Tunnel token field (still shows old token)
            And it does NOT automatically reinstall the cloudflared service
            with the new tunnel token.
  Fix     : After activation succeeds, refresh all three fields from the
            result dict + freshly-read config.json, then call
            _activate_tunnel() to reinstall the tunnel service automatically.
"""

import sys
import re
from pathlib import Path

INSTALL_DIR = Path(r"C:\Program Files\AI-Prowler")
MCP_FILE    = INSTALL_DIR / "ai_prowler_mcp.py"
GUI_FILE    = INSTALL_DIR / "rag_gui.py"

errors = []

# ══════════════════════════════════════════════════════════════════════════════
# FIX 1 — ai_prowler_mcp.py  (fail-open on reverted_expired)
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("FIX 1 — ai_prowler_mcp.py: fail-open on reverted_expired")
print("=" * 70)

OLD_MCP = '''\
            elif _granted == "home":
                # Soft expiry of the grace ladder itself (reverted_expired /
                # no_license) — still "blocked" in the sense that remote
                # access is off, but phrased as expiry rather than revocation.
                _sub_result = {"status": "blocked", "name": None, "days_left": None,
                               "edition": "home",
                               "message": _startup_grace.get("banner") or
                                          "License could not be validated."}'''

NEW_MCP = '''\
            elif _granted == "home" and _action in ("reverted_revoked",):
                # Hard revocation — Worker explicitly said the key is revoked/
                # suspended. Only this path calls sys.exit(1). Ordinary expiry
                # or a network/404 failure falls through to "unmanaged" below
                # so a self-hosted install is never hard-blocked at startup.
                _sub_result = {"status": "blocked", "name": None, "days_left": None,
                               "edition": "home",
                               "message": _startup_grace.get("banner") or
                                          "License could not be validated."}
            elif _granted == "home":
                # reverted_expired / no_license: no cache AND Worker returned
                # 404 or was unreachable.  Fail-open — start in self-hosted /
                # unmanaged mode so the HTTP server stays up and Claude Desktop
                # (stdio path) is never blocked by a transient network issue.
                _sub_result = {"status": "unmanaged", "name": None, "days_left": None,
                               "edition": "home",
                               "message": _startup_grace.get("banner") or
                                          "License not validated — running in self-hosted mode."}'''

try:
    src = MCP_FILE.read_text(encoding='utf-8')
    if OLD_MCP not in src:
        print(f"  ⚠️  Target text NOT found in {MCP_FILE.name}")
        print("     The file may already be patched or has changed.")
        errors.append("mcp fix: old text not found")
    elif NEW_MCP in src:
        print(f"  ✅  Already patched — skipping.")
    else:
        patched = src.replace(OLD_MCP, NEW_MCP, 1)
        MCP_FILE.write_text(patched, encoding='utf-8')
        print(f"  ✅  {MCP_FILE.name} patched successfully.")
except PermissionError:
    print(f"  ❌  Permission denied writing {MCP_FILE}")
    print("     Re-run this script as Administrator (right-click → Run as admin).")
    errors.append("mcp fix: permission denied")
except Exception as e:
    print(f"  ❌  Error: {e}")
    errors.append(f"mcp fix: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# FIX 2 — rag_gui.py  (_on_success: refresh all fields + reinstall tunnel)
# ══════════════════════════════════════════════════════════════════════════════
print()
print("=" * 70)
print("FIX 2 — rag_gui.py: auto-refresh fields + reinstall tunnel on activate")
print("=" * 70)

OLD_GUI = '''\
                            _act_status_var.set("✅ Activated")
                            _configure_btn.configure(
                                text="⚡ Configure Mobile Access",
                                state=\'normal\')
                            self.status_var.set(
                                f"✅ Mobile access activated — {result[\'domain\']}")
                            self.root.after(
                                5000, lambda: self.status_var.set("Ready"))
                            messagebox.showinfo(
                                "Activation Successful",
                                f"Mobile access is now live!\\n\\n"
                                f"Domain:  {result[\'domain\']}\\n"
                                f"Plan:    {result[\'plan\'].title()}\\n"
                                f"License: {result[\'license_key\']}\\n\\n"
                                "Your Cloudflare Tunnel is running. "
                                "Connect Claude.ai to this domain to use "
                                "AI-Prowler from your phone or any browser.")'''

NEW_GUI = '''\
                            _act_status_var.set("✅ Activated")
                            _configure_btn.configure(
                                text="⚡ Configure Mobile Access",
                                state=\'normal\')
                            # ── v8.0.0: auto-refresh all config fields ─────────
                            # 1. License Key display field
                            _license_key_var.set(result.get(\'license_key\', \'\'))
                            # 2. Named Tunnel public hostname field
                            _tun_domain_var.set(result.get(\'domain\', \'\'))
                            # 3. Tunnel token — mobile_activator writes it to
                            #    config.json; re-read so the Named Tunnel section
                            #    shows the new value without requiring a restart.
                            try:
                                import json as _jcfg_refresh
                                _cfgr_path = Path.home() / \'.ai-prowler\' / \'config.json\'
                                if _cfgr_path.exists():
                                    _fresh_cfg = _jcfg_refresh.loads(
                                        _cfgr_path.read_text(encoding=\'utf-8\'))
                                    _new_tok = _fresh_cfg.get(\'tunnel_token\', \'\')
                                    if _new_tok:
                                        _tun_token_var.set(_new_tok)
                            except Exception:
                                pass
                            # 4. Re-run subscription status light check
                            self.root.after(500, _run_status_check)
                            self.status_var.set(
                                f"✅ Mobile access activated — {result[\'domain\']}")
                            self.root.after(
                                5000, lambda: self.status_var.set("Ready"))
                            messagebox.showinfo(
                                "Activation Successful",
                                f"Mobile access is now live!\\n\\n"
                                f"Domain:  {result[\'domain\']}\\n"
                                f"Plan:    {result[\'plan\'].title()}\\n"
                                f"License: {result[\'license_key\']}\\n\\n"
                                "Tunnel service is being reinstalled with the "
                                "new token — approve the UAC prompt to finish.")
                            # 5. Auto-reinstall cloudflared service with new token
                            _activate_tunnel()'''

try:
    src = GUI_FILE.read_text(encoding='utf-8')
    # Use literal string matching (no regex) to be safe with special chars
    old_literal = (
        '                            _act_status_var.set("✅ Activated")\n'
        '                            _configure_btn.configure(\n'
        '                                text="⚡ Configure Mobile Access",\n'
        "                                state='normal')\n"
        '                            self.status_var.set(\n'
        "                                f\"✅ Mobile access activated — {result['domain']}\")\n"
        '                            self.root.after(\n'
        "                                5000, lambda: self.status_var.set(\"Ready\"))\n"
        '                            messagebox.showinfo(\n'
        '                                "Activation Successful",\n'
        '                                f"Mobile access is now live!\\n\\n"\n'
        "                                f\"Domain:  {result['domain']}\\n\"\n"
        "                                f\"Plan:    {result['plan'].title()}\\n\"\n"
        "                                f\"License: {result['license_key']}\\n\\n\"\n"
        '                                "Your Cloudflare Tunnel is running. "\n'
        '                                "Connect Claude.ai to this domain to use "\n'
        '                                "AI-Prowler from your phone or any browser.")'
    )

    if old_literal not in src:
        print(f"  ⚠️  Target text NOT found in {GUI_FILE.name}")
        print("     The file may already be patched or has changed.")
        errors.append("gui fix: old text not found")
    else:
        new_literal = (
            '                            _act_status_var.set("✅ Activated")\n'
            '                            _configure_btn.configure(\n'
            '                                text="⚡ Configure Mobile Access",\n'
            "                                state='normal')\n"
            '                            # ── v8.0.0: auto-refresh all config fields ────────────\n'
            "                            # 1. License Key display field\n"
            "                            _license_key_var.set(result.get('license_key', ''))\n"
            "                            # 2. Named Tunnel public hostname field\n"
            "                            _tun_domain_var.set(result.get('domain', ''))\n"
            "                            # 3. Tunnel token — mobile_activator writes it to\n"
            "                            #    config.json; re-read so the Named Tunnel section\n"
            "                            #    shows the new value without requiring a restart.\n"
            "                            try:\n"
            "                                import json as _jcfg_refresh\n"
            "                                _cfgr_path = Path.home() / '.ai-prowler' / 'config.json'\n"
            "                                if _cfgr_path.exists():\n"
            "                                    _fresh_cfg = _jcfg_refresh.loads(\n"
            "                                        _cfgr_path.read_text(encoding='utf-8'))\n"
            "                                    _new_tok = _fresh_cfg.get('tunnel_token', '')\n"
            "                                    if _new_tok:\n"
            "                                        _tun_token_var.set(_new_tok)\n"
            "                            except Exception:\n"
            "                                pass\n"
            "                            # 4. Re-run subscription status light check\n"
            "                            self.root.after(500, _run_status_check)\n"
            '                            self.status_var.set(\n'
            "                                f\"✅ Mobile access activated — {result['domain']}\")\n"
            '                            self.root.after(\n'
            "                                5000, lambda: self.status_var.set(\"Ready\"))\n"
            '                            messagebox.showinfo(\n'
            '                                "Activation Successful",\n'
            '                                f"Mobile access is now live!\\n\\n"\n'
            "                                f\"Domain:  {result['domain']}\\n\"\n"
            "                                f\"Plan:    {result['plan'].title()}\\n\"\n"
            "                                f\"License: {result['license_key']}\\n\\n\"\n"
            '                                "Tunnel service is being reinstalled with the "\n'
            '                                "new token — approve the UAC prompt to finish.")\n'
            '                            # 5. Auto-reinstall cloudflared service with new token\n'
            '                            _activate_tunnel()'
        )
        patched = src.replace(old_literal, new_literal, 1)
        GUI_FILE.write_text(patched, encoding='utf-8')
        print(f"  ✅  {GUI_FILE.name} patched successfully.")
except PermissionError:
    print(f"  ❌  Permission denied writing {GUI_FILE}")
    print("     Re-run this script as Administrator (right-click → Run as admin).")
    errors.append("gui fix: permission denied")
except Exception as e:
    print(f"  ❌  Error: {e}")
    errors.append(f"gui fix: {e}")

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print("=" * 70)
if errors:
    print(f"Completed with {len(errors)} issue(s):")
    for e in errors:
        print(f"  • {e}")
    print()
    print("If you see 'Permission denied', right-click this script and choose")
    print("'Run as administrator', or run from an elevated Command Prompt.")
else:
    print("All fixes applied successfully.")
    print()
    print("Next steps:")
    print("  1. Close AI-Prowler completely")
    print("  2. Reopen AI-Prowler")
    print("  3. Click Start HTTP Server — should now stay green")
    print("     (new license AP-PERS-808F0151-EE581B55 is registered in KV)")
    print()
    print("  For future activations: Configure Mobile Access will now")
    print("  auto-fill all fields + reinstall the tunnel in one click.")
print("=" * 70)
