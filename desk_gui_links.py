"""Service Desk links on the AI-Prowler Business tab (2026-10-28, David).

"In AI-Prowler business tab make sure you provide the URL for the PWA install on
cell phones like the copy and the QR code like the other PWA apps."

Two rows, same look as the Jobs app row (read-only URL · 📋 Copy · 📧 Email ·
📱 QR):
  * Service Desk app   https://<tunnel>/desk/          — the team's (or, on a
                       personal install, the owner's) phone app; installs from
                       the browser's "Add to Home Screen"
  * Customer requests  https://<tunnel>/support/new    — the page customers
                       use to file a request (no app, no sign-in)
Both modes. When Service Desk is switched off a line says so and where to turn
it on (the links then answer "turned off").

Kept out of rag_gui.py so it can be tested without building the whole GUI.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

DESK_PATH = "/desk/"
SUPPORT_PATH = "/support/new"


def _state_dir() -> Path:
    d = os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
    return Path(d) if d else Path.home() / ".ai-prowler"


def _config() -> dict:
    try:
        return json.loads((_state_dir() / "config.json").read_text(encoding="utf-8-sig")) or {}
    except Exception:
        return {}


def base_url(cfg: dict | None = None) -> str:
    """https://<tunnel_domain> — "" until Remote Access is activated."""
    cfg = _config() if cfg is None else cfg
    d = (str(cfg.get("tunnel_domain", "") or "").strip()
         .replace("https://", "").replace("http://", "").rstrip("/"))
    return f"https://{d}" if d else ""


def desk_urls(cfg: dict | None = None) -> dict:
    b = base_url(cfg)
    return {"app": f"{b}{DESK_PATH}" if b else "", "support": f"{b}{SUPPORT_PATH}" if b else ""}


def mode_of(cfg: dict | None = None) -> str:
    cfg = _config() if cfg is None else cfg
    return "server" if str(cfg.get("mode", "")).strip().lower() == "server" else "personal"


def desk_switched_on(cfg: dict | None = None) -> bool:
    try:
        import tool_config_store as tcs
        return bool(tcs.group_enabled(mode_of(cfg), "service_desk"))
    except Exception:
        return True                       # can't tell — don't show a false warning


def email_link(to_addr_hint: str, subject: str, body: str) -> str:
    """Send through the email account set up in Settings → Email. Returns the
    address it went to; raises with a plain message otherwise."""
    import base64
    import smtplib
    import ssl
    from email.mime.text import MIMEText
    p = Path.home() / ".ai-prowler" / "email_config.json"
    if not p.exists():
        raise RuntimeError("Configure your email in Settings → Email first.")
    e = json.loads(p.read_text(encoding="utf-8"))
    user = e.get("username", "")
    to = to_addr_hint or e.get("default_to", user)
    msg = MIMEText(body, "plain")
    msg["Subject"], msg["From"], msg["To"] = subject, f"{e.get('from_name', user)} <{user}>", to
    pw = base64.b64decode(e.get("_password_b64", "")).decode()
    host, port = e.get("smtp_host", ""), int(e.get("smtp_port", 587))
    if e.get("use_tls", True):
        with smtplib.SMTP(host, port) as s:
            s.ehlo()
            s.starttls(context=ssl.create_default_context())
            s.login(user, pw)
            s.sendmail(user, to, msg.as_string())
    else:
        with smtplib.SMTP_SSL(host, port) as s:
            s.login(user, pw)
            s.sendmail(user, to, msg.as_string())
    return to


ROWS = (
    # key, label, QR title, QR caption, email subject, email body, hint
    ("app", "Service Desk app",
     "Service Desk — scan with your phone",
     "Opens the AI-Prowler Service Desk app. Sign in, then use the browser's "
     "\"Add to Home Screen\" / \"Install app\" to put it on the phone.",
     "AI-Prowler Service Desk app",
     "Open this link on your phone to use the Service Desk (tickets):\n\n  {url}\n\n"
     "Sign in with your AI-Prowler name and token. Then tap the browser menu and choose "
     "'Add to Home Screen' (iPhone: Share → Add to Home Screen) to install it as an app icon.",
     "← install on phones"),
    ("support", "Customer requests",
     "Customer service requests — scan with your phone",
     "The page customers use to request service (no app or sign-in needed).",
     "Request service online",
     "You can request service online here:\n\n  {url}\n\n"
     "You'll get a short code by email or text to confirm it's you.",
     "← for your website / customers"),
)


def build_desk_url_rows(app, parent) -> dict:
    """Build the rows inside `parent` (a ttk.LabelFrame). `app` gives .root and
    .status_var like the rest of the Business tab. Returns {key: StringVar}."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    cfg = _config()
    urls = desk_urls(cfg)
    out = {}
    if not desk_switched_on(cfg):
        ttk.Label(parent, font=("Arial", 8), foreground="#b45309",
                  text=("Service Desk is turned off — turn on \"Service Desk (tickets)\" in "
                        "Settings → MCP Tool Configuration, then restart AI-Prowler.")
                  ).pack(anchor="w", pady=(0, 4))
    for key, label, qr_title, qr_caption, subject, body, hint in ROWS:
        var = tk.StringVar(value=urls[key])
        out[key] = var
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 2))
        ttk.Label(row, text=label, width=17, font=("Arial", 8)).pack(side="left")
        ttk.Entry(row, textvariable=var, width=40, state="readonly",
                  font=("Courier New", 9)).pack(side="left", padx=(0, 4))

        def _url(v=var):
            u = v.get().strip()
            if not u:
                messagebox.showwarning("No URL", "Activate Remote Access in Settings tab first.")
            return u

        def _copy(v=var):
            u = _url(v)
            if not u:
                return
            app.root.clipboard_clear()
            app.root.clipboard_append(u)
            app.root.update()
            app.status_var.set(f"📋  Copied: {u}")
            app.root.after(3000, lambda: app.status_var.set("Ready"))

        def _email(v=var, subject=subject, body=body):
            u = _url(v)
            if not u:
                return
            try:
                to = email_link("", subject, body.format(url=u))
            except Exception as e:
                messagebox.showerror("Send Failed", str(e))
                return
            messagebox.showinfo("Email Sent", f"Link sent to {to}")
            app.status_var.set(f"📧  {subject} link emailed to {to}")
            app.root.after(4000, lambda: app.status_var.set("Ready"))

        def _qr(v=var, title=qr_title, caption=qr_caption):
            try:
                import setup_wizard as sw
                sw.show_qr_window(app.root, title, v.get().strip(), caption)
            except Exception as e:
                messagebox.showerror("QR code", f"Couldn't show the QR code:\n{e}")

        ttk.Button(row, text="📋 Copy", command=_copy).pack(side="left", padx=(0, 4))
        ttk.Button(row, text="📧 Email", command=_email).pack(side="left", padx=(0, 4))
        ttk.Button(row, text="📱 QR", command=_qr).pack(side="left", padx=(0, 8))
        ttk.Label(row, text=hint, font=("Arial", 8), foreground="gray").pack(side="left")
    return out
