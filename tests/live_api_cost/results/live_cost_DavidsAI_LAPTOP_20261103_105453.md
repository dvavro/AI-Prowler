# Live API cost test — DavidsAI_LAPTOP (solo), 2026-11-03 10:54

| Test | Result | API calls | Tokens in (new / cache write / cache read) | Tokens out | Exact cost | AI-Prowler recorded | Per call |
|---|---|---|---|---|---|---|---|
| 2 Service Desk — bookings | passed | 2 | 2,610 / 0 / 2,196 | 1,398 | $0.0114 | $0.0135 | $0.0057 per item (one AI call) |

**Running total (API credits): $0.0114**

## 2 Service Desk — bookings

       booking/check: bk_note — Pending test booking JOB-LCT-B1 summarized for team approval; no confirmation or customer message sent.
          • bk_note (confidence 0.9): Records the held slot, backup, and test status so the team can approve or decline without re-reading the booking.
            "Pending web booking JOB-LCT-B1 for Zz LiveCost Test (returning customer). Service: AI Prowler Server HW .5 TB SSD (Prod-001), 15 min, indoor. Address: 100 Flagler Ave, New Smyrna Beach 32169. Held slot Thu 05 Nov 7-9 (2026-11-05T07:00-09:00), backup Fri 06 Nov 7-9 (2026-11-06T07:00-09:00). Customer …"
       booking/decide: bk_recommend, bk_note — Recommended approving the Fri 06 Nov 7-9 backup, since the held Thu 05 Nov slot isn't open. Left a note for th
          • bk_recommend (confidence 0.7): The held slot (Thu 05 Nov, 7-9) is not in the open windows, but the customer's backup (Fri 06 Nov, 7-9) is open and 1.6 mi from another job  | {"choice": "approve", "window_key": "2026-11-06T07:00-09:00", "crew": ""}
          • bk_note (confidence 0.8): Give the team context and flag the access details that don't match.
            "Held window Thu 05 Nov 7-9 is not in the open windows list, so I recommend the customer's backup, Fri 06 Nov 7-9. The customer is returning and in the service area. The booking notes mention a gate code and a dog in the back yard, while the customer file says the gate is unlocked, so please confirm …"
- warning: AI-Prowler recorded $0.01354 but the API charged $0.01135 (cache pricing in desk_agent_providers.cost)
- cleanup: removed booking_holds 1, booking_requests 1, invoices 1, quotes 1, jobs 6, customers 2
- shown: shown in Service Desk → 🤖 Agent (2 highlighted)
