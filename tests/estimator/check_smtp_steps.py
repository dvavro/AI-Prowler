"""Find the exact step where sending email fails (connect, greeting, TLS, login). Never prints the password."""
import base64
import json
import smtplib
import socket
import ssl
from pathlib import Path

cfg = json.loads((Path.home() / ".ai-prowler" / "email_config.json").read_text(encoding="utf-8"))
host, user = cfg["smtp_host"], cfg["username"]
pw = base64.b64decode(cfg.get("_password_b64", "")).decode("utf-8", "ignore") if cfg.get("_password_b64") else ""
print("password stored:", bool(pw), "| length:", len(pw), "| looks like a 16-letter Google app password:",
      len(pw.replace(" ", "")) == 16)

for port in (587, 465):
    print(f"\nport {port}:")
    try:
        s = socket.create_connection((host, port), timeout=15)
        s.settimeout(15)
        first = s.recv(200) if port == 587 else b"(SSL port: no plain greeting)"
        print("  1. network connect: OK; server says:", first[:80])
        s.close()
    except Exception as exc:
        print(f"  1. network connect: FAILED — {type(exc).__name__}: {exc}")
        continue
    try:
        if port == 587:
            srv = smtplib.SMTP(host, port, timeout=20)
            srv.ehlo()
            print("  2. greeting: OK")
            srv.starttls(context=ssl.create_default_context())
            srv.ehlo()
            print("  3. TLS: OK")
        else:
            srv = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20)
            print("  2-3. SSL connect: OK")
        srv.login(user, pw)
        print("  4. login: OK — email should work")
        srv.quit()
    except Exception as exc:
        print(f"  failed at this step — {type(exc).__name__}: {exc}")

print("\nSame password with the spaces removed (port 587):")
try:
    srv = smtplib.SMTP(host, 587, timeout=20)
    srv.ehlo(); srv.starttls(context=ssl.create_default_context()); srv.ehlo()
    srv.login(user, pw.replace(" ", ""))
    print("  login: OK — the spaces are the problem")
    srv.quit()
except smtplib.SMTPAuthenticationError as exc:
    print(f"  login refused by Google — the app password itself is wrong or revoked: {exc.smtp_code}")
except Exception as exc:
    print(f"  failed — {type(exc).__name__}: {exc}")
