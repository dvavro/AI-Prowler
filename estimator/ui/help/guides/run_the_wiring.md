# Run the wiring (Electrical cable)
<!-- screen: takeoffs; words: wiring, run wiring, cable, wire, 12/2, 14/2, 10/3, circuits, panel, panel schedule, breakers, routing, route, basement, crawlspace, slab, studs, attic, wiring options, defaults, colour key, color code, wiring drawing, schematic, dxf -->
**⚡ Run wiring** routes the cable from the panel to every device and proposes the cable lengths by size, plus the breaker and range/dryer receptacle counts. It's plain geometry from the CAD plan: no AI tokens, and your device counts aren't touched. 🤖 AI Auto Run on Electrical runs it too.

1. Upload the electrical floor plan as a **DXF** file (devices drawn as symbols, the panel symbol where the panel is, each floor titled GROUND FLOOR, SECOND FLOOR…). The panel drawing with its schedule (CIRCUIT / DESCRIPTION / AMPS / POLES / WIRE) is optional: without it the circuits are laid out the usual residential way, and each one is flagged to check.
2. On Measure, click **⚡ Run wiring** (beside AI Auto Run, or in the ⚡ Wiring card on the **To measure** tab). The **Wiring options** box opens first.
3. Set how the cable runs. Each drop-down says, under it, what the choice you picked does:
   - **Foundation**: **Basement** (runs along the basement ceiling and up into the walls), **Crawlspace** (along the crawlspace joists), or **Slab on grade** (nothing ever goes in the concrete; the ground floor is fed from its ceiling).
   - **Outlets wired**: **Through the studs** (outlet to outlet at outlet height — the usual way), **From below** or **From the ceiling**. Lights always go through the ceiling, with the switches dropped from them.
   - **Longest outlet-to-outlet run through the studs**, **Upper floors fed from**, ceiling height, box heights, spare wire and waste.
4. Tick **Save as my defaults** to start every new project with these choices, then click **⚡ Run wiring**. A project's next run starts from its last run's choices.
5. The routes show on the floor plan with a colour key: one colour per circuit, with its breaker, cable and what it powers. Click a circuit in the key (or in the Wiring card) to show only it; hover a wire to see its size and circuit.
6. In the **Measurements** list, click a cable (for example "Cable 12/2 (wiring)"): the circuits using that cable light up and the others fade. Click it again to see every circuit.
7. Approve the cable and counts (**✓ Approve the cable and counts…** in the Wiring card, or one at a time). Approved cable prices the estimate and the Bill of Materials in place of the average-run wire guess.
8. Changed the options and ran it again? With **Keep approved items on rerun** ticked, approved lengths that changed wait as suggestions: click **Accept the new lengths…** in the Wiring card. Unticked, the cable starts over as new proposals.

## Good to know
- The Wiring card shows how the last run was routed ("Routed: basement — runs from the basement ceiling; outlets through the studs…").
- **⬇ Wiring drawing (DXF)** is the floor plan with every circuit's route on its own layer and a wire schedule; **⬇ Wiring schematic (DXF)** shows the panel, its breakers and each circuit's conductors.
- A range or dryer on /2 cable in the schedule is priced as /3 (it needs a neutral) and flagged for the designer.
- Move a device to another circuit from the Wiring card (pick a circuit, then change the device's circuit) and run it again.
- If the circuit lines are drawn on the plan, the run is checked against them, with a one-click "Move to C-2" for each difference.
