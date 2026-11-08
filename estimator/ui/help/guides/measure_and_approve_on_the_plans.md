# Measure and approve on the plans
<!-- screen: takeoffs; words: takeoff, measure, measurement, approve, blueprint review, area, length, count, room, wall, layers, review queue, lock -->
Blueprint Review is where you check what gets priced. Only approved measurements are priced, and an approved measurement is locked: the AI can only suggest a change to it, never overwrite it.

1. Open **Takeoffs** and pick the project (or click **📏 Blueprint Review** on the project page). Read the plans first if you haven't.
2. Pick a sheet at the top. Scroll to zoom, drag to move around, or use **＋**, **－** and **Fit**. The drawing gets sharper as you zoom in.
3. Rooms the plan engine found are shaded and labelled with their area; walls are blue lines. Click one to select it (Shift-click for more), then **Make a measurement from these…**: pick the trade and the question it answers (for example Roofing → roof area), check the room, and click **Save…**, then **Yes**.
4. To measure by hand, pick a tool: **📏 Length** (click along it, double-click to finish), **⬠ Area** (click the corners, click the first point to close), **▭ Rectangle** (two corners) or **✚ Count** (click each one, then **Finish**). The size shows as you draw; the server measures it with the view's scale when you save.
5. A view with no scale can't be measured. Use **📐 Calibrate**: click both ends of a known distance and type its real length.
6. The **Measurements** tab lists everything by trade and room with running totals. Tick **Review queue (lowest confidence first)** to check the doubtful ones first.
7. Click a measurement to open **Detail**: how it was worked out, the sheet, the view and its scale, the drawing objects it came from, its confidence and who proposed and approved it. Click **✓ Approve…** to approve and lock it, **Correct…** to change the number, label or room, or **Reject…** with a reason (it's kept in the history but never priced).
8. Tick **Approve it now** when you save to approve in one step, or use **Approve all…** to approve every proposal at or above a confidence.

## Good to know
- While drawing, points snap to the corners of what's on the plan (a red ring shows the snap); hold **Alt** to place a point freely, hold **Shift** to keep a line straight across or down, and press **Backspace** to take back the last point. A drawn area can be saved as its **perimeter** instead (for example baseboard round a room).
- **＋ Type a number in…** adds a measurement without drawing (from a site visit or a schedule).
- The **Lines** tab lists the estimate's priced lines: click one to highlight every measurement behind it. A measurement's **Detail** shows the lines it feeds, with a link to the estimate.
- On an approved measurement, **Suggest a change…** records a different number beside the approved one. A person clicks **Accept the suggestion…** to use it. Re-reading the plans or changing a scale also shows up as a suggestion, or as "re-measure".
- The **Layers** tab shows and hides groups (Rooms, Walls, Doors & windows, Electrical, Plumbing…) and locks them so they can't be clicked. CAD layers are sorted into these groups by name. What's shown is remembered on this browser.
- Owners and estimators measure. Owners, estimators and reviewers approve, correct and reject. Office and field staff don't see Takeoffs.
