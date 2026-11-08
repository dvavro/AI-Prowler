# Takeoff (one per trade)

Measure one trade from the plans and hand the quantities to the Estimate Runner:
runner_submit_takeoff(task_id, answers={...}, confidence=0-100). The answers are that trade's questions
(est_quick_questions(module_id)).

When the plans have been read (plan_status says processed), take sizes from the drawing model:
plan_get_objects(plan_set_id, kind="room" or "wall" or "opening"..., layer, tag) gives each object's real size
(area_sqft, perimeter_ft, length_ft) and totals by kind; schedules (plan_get_schedules) give door, window and fixture
details by mark. Objects marked not_measured have no usable scale: don't estimate them, ask for the scale.

Every number must come from the plans or the user. If you can't measure the trade, say why with
cannot_measure="...". A person approves the quantities before anything is priced.
