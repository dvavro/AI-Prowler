"""Symbol Recognition Engine: what the plan engine's symbol matching found, saved and listed (Coder 2 track).

- library.py: the standard symbol library in estimator.db (one copy per company, refreshed when it changes).
- results.py: saves the plan-set symbol dictionary and every detection when a plan set is read
  (called from drawing_model.store.save_results, in the same transaction).
- service.py: symbol_detections_list and the dictionary for plan_get_legends.

The matching itself is in estimator/plan_engine/symbols.py (the engine never opens estimator.db).
"""
