# Live API cost test — DavidsAI_LAPTOP (solo), 2026-11-03 10:50

| Test | Result | API calls | Tokens in (new / cache write / cache read) | Tokens out | Exact cost | AI-Prowler recorded | Per call |
|---|---|---|---|---|---|---|---|
| 1 Service Desk — tickets | passed | 3 | 1,882 / 2,196 / 1,098 | 1,406 | $0.0139 | $0.0154 | $0.0046 per item (one AI call) |

**Running total (API credits): $0.0139**

## 1 Service Desk — tickets

       ticket/intake: set_type, note — Classified T-0004 as a complaint and noted the streak rework request for the team; no routing or customer repl
          • set_type (confidence 0.75): Customer reports streaks after Friday's cleaning and asks for a return visit, which is a quality complaint. | {"type": "complaint"}
          • note (confidence 0.8): Records the complaint details and the customer's availability for the team to act on.
            "Customer says the back sliding doors and the two large windows facing the pool have streaks in the afternoon sun after Friday's cleaning. The front windows look fine. Customer is home most afternoons this week and asks for someone to come back and fix them. Not a duplicate of the other test tickets.…"
       ticket/first_reply: reply, note — Sent an acknowledgement reply and left a team note about the re-clean request for the back windows, including 
          • reply (confidence 0.85): First reply acknowledging the complaint, confirming details and availability, with no invented times or promises beyond the team follow-up.
            "Hi, thanks for letting us know, and sorry about the streaks on the back sliding doors and the two big windows facing the pool. I've passed this to the team so they can arrange a return visit to fix them. I can't confirm a day or time myself yet, but I've noted that you're home most afternoons this w…"
          • note (confidence 0.9): Gives the team the details to schedule the re-clean, since no job is linked and I can't book times from this stage.
            "Customer reports streaks on the back sliding doors and the two large pool-facing windows after Friday's clean (visible in afternoon sun). The front windows are fine. Customer is home most afternoons this week and would like a return visit to re-clean. No job or customer record is linked to this tick…"
       ticket/resolution: note, propose_job — Noted the streak complaint and the customer's afternoon availability, and proposed a return job for the back w
          • note (confidence 0.85): Records the details and the customer's availability for the team, since reply is not an allowed action at this stage.
            "Customer reports streaks on back sliding doors and two large windows facing the pool after Friday's clean; says the front looks good. They are home most afternoons this week. Streaks are visible in afternoon sun. Suggest a free/return visit per team policy, and check the afternoon availability for t…"
          • propose_job (confidence 0.8): A re-clean of the rear glass is needed, and a proposed job lets the team schedule it. | {"notes": "Return visit to re-clean streaked windows: back sliding doors and the two large windows facing the pool. Customer is home most afternoons this week. 
- warning: AI-Prowler recorded $0.01539 but the API charged $0.01388 (cache pricing in desk_agent_providers.cost)
- cleanup: removed ticket_messages 1, ticket_events 3, tickets 1, customer_contacts 1, folder 1
- shown: shown in Service Desk → 🤖 Agent (2 highlighted)
