"""2026-10-12 (David's bug report): Subscription selected + token OK, but Test
Setup showed "Grok API key not set". Test Setup (and the scheduled run) used the
auth SAVED in task_automation_config.json — which only changed on Apply/toggle —
not the Auth radio the user had just picked.

  task_queue_automation.dry_run_check(auth=None): 'oauth' | 'anthropic' | 'grok'
    to test exactly that method (None = the saved setting, as before). Checks:
      oauth     -> Claude Code CLI + Claude Code token (no API key)
      anthropic -> Claude Code CLI + Claude API key   (no token)
      grok      -> xAI reachable   + Grok API key     (no CLI, no token)
  rag_gui.py: picking an Auth option saves it at once (and rewrites the
    scheduled run's script when the queue is on); Test Setup passes the
    current selection.
Writes only files that compile. ASCII output."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def edit(rel, pairs):
    p = ROOT / rel
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    s = raw.replace("\r\n", "\n")
    for old, new in pairs:
        assert s.count(old) == 1, f"{rel}: expected once: {old[:80]!r} ({s.count(old)})"
        s = s.replace(old, new)
    compile(s, rel, "exec")
    p.write_bytes(s.replace("\n", nl).encode("utf-8"))
    print(f"{rel}: {len(pairs)} change(s)")


edit("task_queue_automation.py", [
    ('def dry_run_check() -> dict:',
     'def dry_run_check(auth: str | None = None) -> dict:'),
    ('''    _ensure_hook_uses_absolute_python()
    checks = []

    # 2026-10-12: the runner-auth checks branch on the selected provider.''',
     '''    _ensure_hook_uses_absolute_python()
    checks = []

    # 2026-10-12 (David): test the auth method actually SELECTED in the panel
    # when the GUI passes it — 'oauth' (subscription token), 'anthropic'
    # (Claude API key) or 'grok' (Grok API key). Each needs only its own
    # credential. None = the saved setting (scheduled run / older callers).
    _sel = (auth or "").strip().lower()
    if _sel not in ("oauth", "anthropic", "grok"):
        _sel = effective_api_key_provider()

    # 2026-10-12: the runner-auth checks branch on the selected provider.'''),
    ('''    _prov = effective_api_key_provider()
    if _prov == "grok":''',
     '''    _prov = _sel
    if _prov == "grok":'''),
    ('''    if effective_api_key_provider(cfg) != "grok":''',
     '''    if _sel != "grok":'''),
    ('''    _auth_prov = effective_api_key_provider(cfg)
    if _auth_prov == "grok":''',
     '''    _auth_prov = _sel
    if _auth_prov == "grok":'''),
    ('''    elif cfg.get("use_api_key"):
        key_ok = has_api_key()''',
     '''    elif _auth_prov == "anthropic":
        key_ok = has_api_key("anthropic")'''),
])

edit("rag_gui.py", [
    ('''                report = _tqa.dry_run_check()''',
     '''                # 2026-10-12: check the auth method selected right now
                report = _tqa.dry_run_check(auth=_tqa_selected_provider())'''),
    ('''                _tqa_btn_get_api_key.config(
                    text="🔑 Get Grok API Key" if _prov == "grok" else "🔑 Get Claude API Key")
                _tqa_relayout_buttons()

            _tqa_auth_var.trace_add('write', _tqa_on_auth_change)''',
     '''                _tqa_btn_get_api_key.config(
                    text="🔑 Get Grok API Key" if _prov == "grok" else "🔑 Get Claude API Key")
                _tqa_relayout_buttons()
                _tqa_persist_auth(_prov)

            def _tqa_persist_auth(prov):
                """2026-10-12 (David): picking an Auth option takes effect at once —
                saved to the queue settings, and (when the queue is on) the
                scheduled run's script is rewritten so the next run uses it.
                Before, it only changed on Apply/toggle, so Test Setup and the
                scheduled run kept using the previously saved method."""
                want_key = prov in ("anthropic", "grok")
                want_prov = prov if want_key else _tqa_cfg.get("api_key_provider", "anthropic")
                if (bool(_tqa_cfg.get("use_api_key")) == want_key
                        and (not want_key or _tqa_cfg.get("api_key_provider") == prov)):
                    return                                   # nothing changed
                try:
                    cfg = dict(_tqa.load_config())
                    cfg["use_api_key"] = want_key
                    cfg["api_key_provider"] = want_prov
                    _tqa.save_config(cfg)
                    _tqa_cfg.update(cfg)
                    if cfg.get("enabled") and cfg.get("mcp_config_path"):
                        _tqa.install_wrapper_script(
                            _tqa.AI_PROWLER_HOME, cfg["mcp_config_path"], cfg["allowed_tools"],
                            cfg["notify_on_complete"], cfg["notify_method"], cfg["use_api_key"],
                            api_key_provider=cfg.get("api_key_provider", "anthropic"),
                            check_mode=cfg.get("check_mode", "daily"),
                            active_days=cfg.get("active_days"),
                            active_start_time=cfg.get("active_start_time", "00:00"),
                            active_end_time=cfg.get("active_end_time", "23:59"))
                    _tqa_refresh_status_display()
                except Exception as _e_auth:
                    self.status_var.set(f"Couldn't save the auth choice: {_e_auth}")

            _tqa_auth_var.trace_add('write', _tqa_on_auth_change)'''),
])
