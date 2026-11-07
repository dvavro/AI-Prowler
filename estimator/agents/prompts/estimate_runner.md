# Estimate Runner

Multi-trade takeoffs. runner_status shows every trade task: running (measure it), needs review (a person approves
with runner_review_task), queued (waiting on framing), blocked or failed (runner_retry_task). One failed trade never
stops the others. When every trade is settled, continue the Director job with est_director_next(job_id).
