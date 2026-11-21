# Measure and approve on the plans
<!-- screen: takeoffs; words: takeoff, measure, measurement, approve, blueprint review, ai auto run, auto run, keep approved items on rerun, rerun, audit, clean up, area, length, count, room, wall, layers, review queue, lock, suggestion -->
Measure from plans (takeoff) is where you check what gets priced. Only approved measurements are priced, and an approved measurement is locked: the AI can only suggest a change to it, never overwrite it.

1. Open **Measure** and pick the project (or click **📏 Measure from plans (takeoff)** on the project page). Read the plans first if you haven't. The **🧭 Director** box at the top says what to do next.
2. Click **🤖 AI Auto Run**. It reads the sheets switched on for the trade and proposes the quantities (for Electrical it also runs the wiring — see "Run the wiring"). Hover over the button first: it says what that trade's run needs and what makes it read well. While it works, the waiting message shows what the AI is doing right now. With more than one trade, pick the trade beside the button.
3. Pick a sheet at the top. Scroll to zoom, drag to move around, or use **＋**, **－** and **Fit**. The drawing gets sharper as you zoom in.
4. The **Measurements** tab lists everything by trade and room with running totals. Click a measurement: its symbols light up on the drawing (a cable from the wiring run lights up its circuits) and a review card opens under it with **✓ Approve**, **✕ Reject**, **Detail** and **Close**. On a count, click a symbol on the drawing to take it off the count or add it. Tick **Review queue (lowest confidence first)** to check the doubtful ones first.
5. **Detail** shows how it was worked out, the sheet, the view and its scale, the drawing objects it came from, its confidence and who proposed and approved it. **Correct…** changes the number, label or room; **Reject…** needs a reason (it's kept in the history but never priced).
6. Click **🧹 Audit & clean up** to find what still needs a person — counts priced twice, items waiting, counts the drawing disagrees with — and fix them in one go.
7. To measure by hand, pick a tool: **📏 Length** (click along it, double-click to finish), **⬠ Area** (click the corners, click the first point to close), **▭ Rectangle** (two corners) or **✚ Count** (click each one, then **Finish**). Or select rooms or walls (Shift-click for more) and click **Make a measurement from these…**. A view with no scale can't be measured: use **📐 Calibrate** (click both ends of a known distance and type its real length).
8. Tick **Approve it now** when you save to approve in one step, or use **Approve all…** to approve every proposal at or above a confidence.

## Running it again
- **Keep approved items on rerun** (beside AI Auto Run, ticked by default): a rerun keeps what you already approved and only proposes the rest. When the rerun measures an approved item differently, the new value waits as a suggested change.
- Untick it to start the trade over from scratch: approved AI results on the sheet are replaced too (what you drew or typed is never touched).
- On an approved measurement, **Suggest a change…** records a different number beside the approved one. A person clicks **Accept the suggestion…** to use it. A rerun, re-reading the plans or changing a scale also shows up as a suggestion, or as "re-measure".

## Good to know
- While drawing, points snap to the corners of what's on the plan (a red ring shows the snap); hold **Alt** to place a point freely, hold **Shift** to keep a line straight across or down, and press **Backspace** to take back the last point. A drawn area can be saved as its **perimeter** instead (for example baseboard round a room).
- **＋ Type a number in…** adds a measurement without drawing (from a site visit or a schedule).
- The **Lines** tab lists the estimate's priced lines: click one to highlight every measurement behind it.
- The **Layers** tab shows and hides groups (Rooms, Walls, Doors & windows, Electrical, Plumbing…) and locks them so they can't be clicked.
- Every AI Auto Run is listed on **Agents → 🤖 AI Auto Runs**, with what it proposed, what it cost and why it failed if it did.
- Owners and estimators measure. Owners, estimators and reviewers approve, correct and reject. Office and field staff don't see Measure.
