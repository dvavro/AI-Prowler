"""Show AI-Prowler's email settings with secrets hidden, and test the SMTP connection step by step."""
import json
import smtplib
import ssl
from pathlib import Path

SECRET_WORDS = ("pass", "secret", "token", "key")
cands = [p for p in (Path.home() / ".ai-prowler").glob("*.json") if "email" in p.name.lower() or "smtp" in p.name.lower()]
cfg = {}
for p in cands:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        print(p.name, "unreadable:", exc)
        continue
    shown = {k: ("***" if any(w in k.lower() for w in SECRET_WORDS) and v else v) for k, v in data.items()}
    print(p.name, json.dumps(shown, indent=1))
    cfg = cfg or data

host = cfg.get("smtp_host") or cfg.get("host") or cfg.get("server")
port = int(cfg.get("smtp_port") or cfg.get("port") or 0)
user = cfg.get("username") or cfg.get("smtp_user") or cfg.get("user")
pw = cfg.get("password") or cfg.get("smtp_password") or cfg.get("app_password")
print("\nhost:", host, "port:", port, "user:", user, "password set:", bool(pw), "length:", len(pw or ""))
if not host or not port:
    raise SystemExit("no host/port found")

def attempt(label, fn):
    try:
        fn()
        print(f"  {label}: OK")
    except Exception as exc:
        print(f"  {label}: FAILED — {type(exc).__name__}: {exc}")

def ssl_login():
    with smtplib.SMTP_SSL(host, 465, context=ssl.create_default_context(), timeout=20) as s:
        s.login(user, pw)

def starttls_login():
    with smtplib.SMTP(host, 587, timeout=20) as s:
        s.ehlo(); s.starttls(context=ssl.create_default_context()); s.ehlo(); s.login(user, pw)

def configured():
    if port == 465:
        ssl_login()
    else:
        starttls_login()

print("\nConnection tests:")
attempt(f"configured port {port}", configured)
attempt("port 465 (SSL)", ssl_login)
attempt("port 587 (STARTTLS)", starttls_login)
