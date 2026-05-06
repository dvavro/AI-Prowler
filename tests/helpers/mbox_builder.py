"""
Deterministic .mbox file builder for email-archive tests.

Why we build our own instead of fixturing a real mbox
-----------------------------------------------------
1. Stable Message-IDs — _make_message_uid() md5s the Message-ID header.
   We need to know exactly which UIDs will be produced so we can assert
   on incremental indexing behaviour (F-IDX-10, F-IDX-11).

2. Cross-platform line endings — mbox uses LF terminators by RFC 4155.
   A real exported mbox could have CRLF and break iter_mbox_emails.

3. No PII — checking real mailboxes into a public repo is a non-starter.

The output is a valid Unix-style mbox readable by mailbox.mbox(), which is
what iter_mbox_emails uses internally.
"""
from __future__ import annotations

from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timezone
from pathlib import Path


def _build_message(seq: int) -> EmailMessage:
    """Build one deterministic email message.

    Each message has a stable Message-ID derived from `seq` so md5-hashed
    UIDs in ~/.rag_email_index.json are predictable across runs.
    """
    msg = EmailMessage()
    msg["From"]       = f"sender{seq}@example.test"
    msg["To"]         = "recipient@example.test"
    msg["Subject"]    = f"Test message number {seq}"
    msg["Date"]       = format_datetime(
        datetime(2026, 1, 1, 12, seq % 60, 0, tzinfo=timezone.utc)
    )
    # Stable Message-ID — DO NOT randomise. Tests rely on these being identical
    # between runs so we can assert on UID set membership.
    msg["Message-ID"] = f"<msg-{seq:04d}@aiprowler.test>"
    msg.set_content(
        f"This is the body of test message number {seq}.\n"
        f"It contains some predictable text for indexing.\n"
        f"Lorem ipsum dolor sit amet, message {seq}.\n"
    )
    return msg


def make_mbox(path: Path, n_messages: int = 5) -> Path:
    """Write an mbox file with n deterministic messages.

    Format reference: https://datatracker.ietf.org/doc/html/rfc4155
    Each message starts with a 'From ' line (no colon — the unix mbox
    From-line, NOT the From: header) followed by the RFC 5322 message,
    followed by a blank line.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    chunks = []
    for seq in range(1, n_messages + 1):
        msg = _build_message(seq)
        # Mbox 'From ' separator — RFC 4155 specifies the format
        # "From <sender> <date>" with no colon after From. The date is
        # asctime-formatted, NOT RFC 5322.
        sep = f"From sender{seq}@example.test Thu Jan  1 12:00:00 2026\n"
        chunks.append(sep)
        chunks.append(msg.as_string())
        chunks.append("\n")

    path.write_bytes("".join(chunks).encode("utf-8"))
    return path


def append_message(path: Path, seq: int) -> None:
    """Append an additional message to an existing mbox file. Used to test
    the 'archive grew' case in incremental indexing (F-IDX-10)."""
    msg = _build_message(seq)
    sep = f"From sender{seq}@example.test Thu Jan  1 12:00:00 2026\n"
    with open(str(path), "ab") as f:
        f.write(sep.encode("utf-8"))
        f.write(msg.as_string().encode("utf-8"))
        f.write(b"\n")


def remove_first_n_messages(path: Path, n: int) -> int:
    """Rewrite an mbox with the first n messages removed. Used to test the
    'archive shrank' case (F-IDX-11). Returns the count of remaining messages.
    """
    import mailbox
    box = mailbox.mbox(str(path))
    keys = list(box.keys())
    keep_keys = keys[n:]
    keep_messages = [box[k] for k in keep_keys]
    box.close()

    # Recreate the file from scratch with only the kept messages.
    chunks = []
    for i, msg in enumerate(keep_messages, 1):
        # Use the message's own From header to keep the unix-mbox separator
        # consistent with the original.
        from_addr = msg.get("From", "unknown@example.test").split("<")[-1].rstrip(">")
        sep = f"From {from_addr} Thu Jan  1 12:00:00 2026\n"
        chunks.append(sep)
        chunks.append(msg.as_string())
        chunks.append("\n")
    Path(path).write_bytes("".join(chunks).encode("utf-8"))
    return len(keep_messages)
