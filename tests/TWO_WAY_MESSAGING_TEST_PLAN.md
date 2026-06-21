# V800 Two-Way Messaging — Test Plan

## Overview
This document covers the full test strategy for the V800 two-way messaging feature,
including the SMS backend abstraction layer, Twilio/SignalWire/Vonage/WhatsApp
provider support, inbound webhook, thread model, and new MCP tools.

Each test section maps to a Phase in the implementation plan.

---

## Test Structure

```
tests/
  unit/
    messaging/
      test_sms_backends.py        Phase 1 — backend abstraction
      test_sms_inbox.py           Phase 1 — inbox storage & thread model
      test_sms_webhook.py         Phase 1 — webhook signature validation
      test_sms_tools.py           Phase 2 — MCP tool integration
      test_whatsapp.py            Phase 2 — WhatsApp channel
  integration/
    messaging/
      test_webhook_server.py      Phase 1 — live HTTP endpoint
      test_provider_switching.py  Phase 3 — provider config switching
  e2e/
    messaging/
      test_sms_e2e.py             Full send → webhook → inbox → read cycle
```

---

## Phase 1 — Backend Abstraction + Webhook

### SMS-BK-01 through SMS-BK-10: Backend Abstraction Layer (sms_backends.py)

| ID | Test | Pass Condition |
|----|------|---------------|
| SMS-BK-01 | `TwilioBackend.send()` with mocked requests.post returns SID | Result contains SID or 'sent' |
| SMS-BK-02 | `TwilioBackend.send()` missing credentials returns clear error | Result contains 'not configured' |
| SMS-BK-03 | `TwilioBackend.send()` Twilio 400 error surfaces error message | Result contains '400' or 'invalid' |
| SMS-BK-04 | `TwilioBackend.send()` normalises 10-digit number to +1XXXXXXXXXX | POST called with To=+1XXXXXXXXXX |
| SMS-BK-05 | `SignalWireBackend.send()` uses Space URL + Project ID auth | POST URL contains signalwire.com |
| SMS-BK-06 | `VonageBackend.send()` uses api_key + api_secret | POST body contains api_key |
| SMS-BK-07 | `WhatsAppBackend.send()` prefixes To with 'whatsapp:' | POST called with To=whatsapp:+1... |
| SMS-BK-08 | `get_sms_backend(config)` returns TwilioBackend when provider='twilio' | isinstance TwilioBackend |
| SMS-BK-09 | `get_sms_backend(config)` returns SignalWireBackend when provider='signalwire' | isinstance SignalWireBackend |
| SMS-BK-10 | `get_sms_backend(config)` returns error for unknown provider | Result contains 'unknown provider' |

### SMS-IN-01 through SMS-IN-12: Inbox Storage & Thread Model

| ID | Test | Pass Condition |
|----|------|---------------|
| SMS-IN-01 | `sms_inbox_append()` writes message to sms_inbox.json | File exists, contains message |
| SMS-IN-02 | `sms_inbox_append()` is idempotent on duplicate message_id | Only one entry for same SID |
| SMS-IN-03 | `sms_inbox_read()` returns all messages | Returns list |
| SMS-IN-04 | `sms_inbox_read(since_hours=1)` filters by timestamp | Only recent messages returned |
| SMS-IN-05 | `sms_inbox_read(from_number='3865550101')` filters by sender | Only matching messages |
| SMS-IN-06 | `sms_inbox_read(unread_only=True)` returns only unread | Messages where read_by=[] |
| SMS-IN-07 | `sms_inbox_mark_read(msg_id, user_id)` adds user to read_by | read_by contains user_id |
| SMS-IN-08 | `sms_thread_log()` creates thread entry when send_sms called | sms_threads.json updated |
| SMS-IN-09 | `sms_thread_log()` updates existing thread on second send | Single thread entry updated |
| SMS-IN-10 | `sms_inbox_read_for_user()` returns only threads user participated in | Mike sees Karen's reply, not Jake's |
| SMS-IN-11 | Inbox file corrupted — read returns [] not crash | Returns [] with warning |
| SMS-IN-12 | Concurrent writes don't corrupt inbox (file lock test) | Final file has all entries |

### SMS-WH-01 through SMS-WH-10: Webhook Endpoint

| ID | Test | Pass Condition |
|----|------|---------------|
| SMS-WH-01 | POST /sms-webhook with valid Twilio signature returns 200 | HTTP 200, TwiML response |
| SMS-WH-02 | POST /sms-webhook with invalid signature returns 403 | HTTP 403 |
| SMS-WH-03 | POST /sms-webhook with missing signature returns 403 | HTTP 403 |
| SMS-WH-04 | POST /sms-webhook stores message to sms_inbox.json | Inbox contains message |
| SMS-WH-05 | POST /sms-webhook resolves contact name from contacts_cache.json | Inbox entry has contact_name |
| SMS-WH-06 | POST /whatsapp-webhook stores WhatsApp message with provider='whatsapp' | Inbox entry has provider='whatsapp' |
| SMS-WH-07 | POST /sms-webhook with SignalWire signature validates correctly | HTTP 200 |
| SMS-WH-08 | POST /sms-webhook with Vonage signature validates correctly | HTTP 200 |
| SMS-WH-09 | Webhook with empty body returns 400 | HTTP 400 |
| SMS-WH-10 | /sms-webhook accessible without Bearer token (Twilio has no auth header) | HTTP 200 not 401 |

---

## Phase 2 — New MCP Tools

### SMS-TL-01 through SMS-TL-20: MCP Tool Tests

| ID | Test | Pass Condition |
|----|------|---------------|
| SMS-TL-01 | `check_sms_inbox()` reads from local file (no API call) | Returns messages, no requests.get call |
| SMS-TL-02 | `check_sms_inbox(unread_only=True)` filters correctly | Only unread messages |
| SMS-TL-03 | `check_sms_inbox(from_number='386...')` filters by sender | Only matching messages |
| SMS-TL-04 | `check_sms_inbox()` empty inbox returns friendly message | 'No SMS messages' in result |
| SMS-TL-05 | `get_sms_thread('Karen')` returns full conversation | Both sent and received messages |
| SMS-TL-06 | `get_sms_thread()` unknown contact returns clear error | 'No thread found' in result |
| SMS-TL-07 | `send_whatsapp()` calls WhatsAppBackend.send() | backend.send called with whatsapp: prefix |
| SMS-TL-08 | `send_whatsapp()` no WhatsApp config returns setup instructions | 'not configured' in result |
| SMS-TL-09 | `check_whatsapp_replies()` reads from inbox filtered by provider='whatsapp' | Only WhatsApp messages |
| SMS-TL-10 | `list_sms_contacts_with_replies()` groups by contact | Returns grouped list |
| SMS-TL-11 | `send_sms()` using new backend abstraction still works (Twilio) | SID in result |
| SMS-TL-12 | `send_sms()` logs to sms_threads.json | Thread entry created |
| SMS-TL-13 | `check_sms_replies()` now reads from local inbox (not Twilio API) | No requests.get call |
| SMS-TL-14 | Field crew role can send SMS | Tool succeeds |
| SMS-TL-15 | Owner role can send SMS (new — was blocked before) | Tool succeeds |
| SMS-TL-16 | Manager role can send SMS | Tool succeeds |
| SMS-TL-17 | Personal mode send_sms works with Twilio config | SID in result |
| SMS-TL-18 | Personal mode send_sms works with SignalWire config | Success in result |
| SMS-TL-19 | Personal mode send_sms works with Vonage config | Success in result |
| SMS-TL-20 | WhatsApp tool available in both personal and server mode | Tool registered in MCP |

---

## Phase 3 — GUI Settings

### SMS-GUI-01 through SMS-GUI-10: Settings Tab

| ID | Test | Pass Condition |
|----|------|---------------|
| SMS-GUI-01 | Provider dropdown shows Twilio / SignalWire / Vonage / WhatsApp | All 4 options present |
| SMS-GUI-02 | Selecting Twilio shows Account SID, Auth Token, From Number | Correct fields visible |
| SMS-GUI-03 | Selecting SignalWire shows Project ID, Space URL, Token, From Number | Correct fields visible |
| SMS-GUI-04 | Selecting Vonage shows API Key, API Secret, From Number | Correct fields visible |
| SMS-GUI-05 | WhatsApp toggle appears only when Twilio selected | Toggle shown/hidden correctly |
| SMS-GUI-06 | Webhook URL field shows https://domain/sms-webhook | Correct URL displayed |
| SMS-GUI-07 | Save stores correct provider to config.json | config.json has sms_provider field |
| SMS-GUI-08 | Email config visible in personal mode | SMTP fields shown |
| SMS-GUI-09 | Email config visible in server mode (read-only for field crew) | SMTP fields shown |
| SMS-GUI-10 | Twilio config visible in both personal and server mode | Twilio section shown in both |

---

## End-to-End Tests

### SMS-E2E-01 through SMS-E2E-05

| ID | Test | Pass Condition |
|----|------|---------------|
| SMS-E2E-01 | Full Twilio cycle: send → mock inbound webhook → check_sms_inbox | Reply appears in inbox |
| SMS-E2E-02 | Full SignalWire cycle: send → mock webhook → check inbox | Reply appears in inbox |
| SMS-E2E-03 | Full WhatsApp cycle: send → mock webhook → check_whatsapp_replies | Reply appears in inbox |
| SMS-E2E-04 | Thread isolation: Mike sends to Karen, Jake sends to Bob — each sees only their replies | No cross-contamination |
| SMS-E2E-05 | Provider switch: change from Twilio to SignalWire in config, send succeeds with new provider | No restart needed |

---

## Test Data & Fixtures

### Mock Twilio Config
```python
TWILIO_CFG = {
    "sms_provider": "twilio",
    "twilio_sms_enabled": True,
    "twilio_account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "twilio_auth_token": "test_auth_token_1234567890abcdef",
    "twilio_from_number": "+13865550100",
}
```

### Mock SignalWire Config
```python
SIGNALWIRE_CFG = {
    "sms_provider": "signalwire",
    "signalwire_project_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "signalwire_auth_token": "PTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "signalwire_space_url": "example.signalwire.com",
    "signalwire_from_number": "+13865550100",
}
```

### Mock Vonage Config
```python
VONAGE_CFG = {
    "sms_provider": "vonage",
    "vonage_api_key": "12345678",
    "vonage_api_secret": "abcdefghijklmnop",
    "vonage_from_number": "AIProwler",
}
```

### Mock Inbound Webhook Payload (Twilio)
```python
TWILIO_INBOUND = {
    "MessageSid": "SM1234567890abcdef1234567890abcdef",
    "From": "+13865550101",
    "To": "+13865550100",
    "Body": "On my way, 10 min out",
    "NumMedia": "0",
}
```

### Mock Inbound Webhook Payload (WhatsApp via Twilio)
```python
WHATSAPP_INBOUND = {
    "MessageSid": "SM_wa_1234567890abcdef",
    "From": "whatsapp:+13865550101",
    "To": "whatsapp:+13865550100",
    "Body": "Job complete, sending photos",
    "NumMedia": "0",
}
```

---

## Running the Tests

```bash
# All messaging tests
run_tests.bat tests\unit\messaging\ -v
run_tests.bat tests\integration\messaging\ -v

# Specific phase
run_tests.bat tests\unit\messaging\test_sms_backends.py -v
run_tests.bat tests\unit\messaging\test_sms_webhook.py -v
run_tests.bat tests\unit\messaging\test_sms_tools.py -v

# E2E (requires local server running)
run_tests.bat tests\e2e\messaging\ -v

# Full suite including messaging
run_tests.bat tests\ -v
```

---

## Acceptance Criteria

Before merging V800 messaging to production:

- [ ] All SMS-BK-* pass (10/10)
- [ ] All SMS-IN-* pass (12/12)
- [ ] All SMS-WH-* pass (10/10)
- [ ] All SMS-TL-* pass (20/20)
- [ ] All SMS-GUI-* pass (manual verification, 10/10)
- [ ] All SMS-E2E-* pass (5/5)
- [ ] Full existing test suite still passes (no regressions)
- [ ] `rag_gui.py` syntax check clean
- [ ] `ai_prowler_mcp.py` syntax check clean
- [ ] `sms_backends.py` syntax check clean

**Total: 57 automated tests + 10 manual GUI checks**
