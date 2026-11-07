# Live API cost test — DavidsAI_LAPTOP (solo), 2026-11-03 10:47

| Test | Result | API calls | Tokens in (new / cache write / cache read) | Tokens out | Exact cost | AI-Prowler recorded | Per call |
|---|---|---|---|---|---|---|---|
| 1 Service Desk — tickets (DRY — no AI call) | passed | 3 | 0 / 0 / 0 | 0 | $0.0000 | $0.0000 | $0.0000 per item (one AI call) |
| 2 Service Desk — bookings (DRY — no AI call) | passed | 2 | 0 / 0 / 0 | 0 | $0.0000 | $0.0000 | $0.0000 per item (one AI call) |
| 3 Jobs app agent (DRY — no AI call) | passed | 5 | 0 / 0 / 0 | 0 | $0.0000 | $0.0000 | $0.0000 per item (one AI call) |

**Running total (API credits): $0.0000**

## 1 Service Desk — tickets (DRY — no AI call)

       ticket/intake: note — dry run
          • note (confidence 1): dry run
            "Dry run — no AI was called."
       ticket/first_reply: note — dry run
          • note (confidence 1): dry run
            "Dry run — no AI was called."
       ticket/resolution: note — dry run
          • note (confidence 1): dry run
            "Dry run — no AI was called."
- warning: ('ticket', 'first_reply'): expected one of ['ask_customer', 'reply'], the AI chose ['note']
- cleanup: removed ticket_messages 1, ticket_events 3, tickets 1, customer_contacts 1, folder 1
- shown: not shown (human mode off)

## 2 Service Desk — bookings (DRY — no AI call)

       booking/check: bk_note — dry run
          • bk_note (confidence 1): dry run
            "Dry run — no AI was called."
       booking/decide: bk_note — dry run
          • bk_note (confidence 1): dry run
            "Dry run — no AI was called."
- warning: ('booking', 'decide'): expected one of ['bk_approve', 'bk_decline', 'bk_recommend', 'bk_suggest_time'], the AI chose ['bk_note']
- cleanup: removed booking_holds 1, booking_requests 1, invoices 1, quotes 1, jobs 6, customers 2
- shown: not shown (human mode off)

## 3 Jobs app agent (DRY — no AI call)

       job/quotes: jb_note — dry run
          • jb_note (confidence 1): dry run
            "Dry run — no AI was called."
       job/schedule: jb_note — dry run
          • jb_note (confidence 1): dry run
            "Dry run — no AI was called."
       job/closeout: jb_note — dry run
          • jb_note (confidence 1): dry run
            "Dry run — no AI was called."
       job/collect: jb_note — dry run
          • jb_note (confidence 1): dry run
            "Dry run — no AI was called."
       route/route: no_action — dry run
          • no_action (confidence 1): dry run
            "Dry run — no AI was called."
- warning: ('job', 'quotes'): expected one of ['jb_quote_followup'], the AI chose ['jb_note']
- warning: ('job', 'schedule'): expected one of ['jb_schedule'], the AI chose ['jb_note']
- warning: ('job', 'closeout'): expected one of ['jb_draft_invoice'], the AI chose ['jb_note']
- warning: ('job', 'collect'): expected one of ['jb_payment_reminder'], the AI chose ['jb_note']
- warning: ('route', 'route'): expected one of ['rt_route_day'], the AI chose ['no_action']
- cleanup: removed invoices 1, quotes 1, jobs 5, customers 2
- shown: not shown (human mode off)
