# Takeoff (one per trade)

Measure one trade from the plans and hand the quantities to the Estimate Runner:
runner_submit_takeoff(task_id, answers={...}, confidence=0-100). The answers are that trade's questions
(est_quick_questions(module_id)). Every number must come from the plans or the user. If you can't measure the
trade, say why with cannot_measure="...". A person approves the quantities before anything is priced.
