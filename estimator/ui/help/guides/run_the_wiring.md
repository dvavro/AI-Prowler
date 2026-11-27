# Run the wiring (Electrical cable)
<!-- screen: takeoffs; words: wiring, run wiring, cable, wire, 12/2, 14/2, 10/3, circuits, panel, panel schedule, breakers, routing, route, basement, crawlspace, slab, studs, attic, wiring options, defaults, colour key, color code, wiring drawing, schematic, dxf, conduit, emt, pvc, thhn, surface mount, metal shed, garage, expansion, expansion fitting, thermal -->
**⚡ Run wiring** routes the cable from the panel to every device and proposes the cable lengths by size, plus the breaker and range/dryer receptacle counts. It's plain geometry from the CAD plan: no AI tokens, and your device counts aren't touched. 🤖 AI Auto Measure/Count on Electrical runs it too.

1. Upload the electrical floor plan as a **DXF** file (devices drawn as symbols, the panel symbol where the panel is, each floor titled GROUND FLOOR, SECOND FLOOR…). The panel drawing with its schedule (CIRCUIT / DESCRIPTION / AMPS / POLES / WIRE) is optional: without it the circuits are laid out the usual residential way, and each one is flagged to check.
2. On Measure, click **⚡ Run wiring** (beside AI Auto Measure/Count, or in the ⚡ Wiring card on the **To measure** tab). The **Wiring options** box opens first.
3. Set how the cable runs. Each drop-down says, under it, what the choice you picked does:
   - **Foundation**: **Basement** (runs along the basement ceiling and up into the walls), **Crawlspace** (along the crawlspace joists), or **Slab on grade** (nothing ever goes in the concrete; the ground floor is fed from its ceiling).
   - **Outlets wired**: **Through the studs** (outlet to outlet at outlet height — the usual way), **From below** or **From the ceiling**. Lights always go through the ceiling, with the switches dropped from them.
   - **Longest outlet-to-outlet run through the studs**, **Upper floors fed from**, ceiling height, box heights, spare wire and waste.
4. Tick **Save as my defaults** to start every new project with these choices, then click **⚡ Run wiring**. A project's next run starts from its last run's choices.
5. The routes show on the floor plan with a colour key: one colour per circuit, with its breaker, cable and what it powers. Click a circuit in the key (or in the Wiring card) to show only it; hover a wire to see its size and circuit.
6. In the **Measurements** list, click a cable (for example "Cable 12/2 (wiring)"): the circuits using that cable light up and the others fade. Click it again to see every circuit.
7. Approve the cable and counts (**✓ Approve the cable and counts…** in the Wiring card, or one at a time). Approved cable prices the estimate and the Bill of Materials in place of the average-run wire guess.
8. Changed the options and ran it again? With **Keep approved items on rerun** ticked, approved lengths that changed wait as suggestions: click **Accept the new lengths…** in the Wiring card. Unticked, the cable starts over as new proposals.

## Conduit on the surface (metal sheds, garages, basements, add-ons)
When you can't (or don't want to) drill the studs — a steel building, or power added later to a finished garage or basement — set **Wiring method** in Wiring options to **EMT** (steel) or **PVC** conduit on the surface. To use a different method on one floor, pick it in that floor's row.
- Each circuit's wire becomes **THHN** conductors (hot, neutral, ground) pulled in the conduit, in place of NM cable.
- Conduit is sized by NEC Annex C fill: 1/2 in for most runs, 3/4 in or 1 in for home runs that share a conduit (**Circuits per home-run conduit**).
- The run counts elbows, couplings, connectors, straps (EMT every 10 ft, PVC every 3 ft, and within 3 ft of every box), a pull point for every 360° of bends, surface boxes and weatherproof boxes.
- An outdoor device gets a short stub through the wall with an LB conduit body; **Outside runs in** picks PVC or EMT for it.
- **Thermal expansion:** set what **The conduit is strapped to** (wood, steel or masonry), the **Temperature swing inside / outside**, and whether **Outside runs are in direct sun** (adds 30 °F). Each straight run's movement = coefficient × length × swing. PVC moves 3.38×10⁻⁵ in/in/°F and gets an expansion fitting where a run moves ¼ in or more (NEC 352.44). EMT moves 6.5×10⁻⁶ (NEC 300.7(B)) and is counted against how much the building itself moves — EMT on a steel building moves with it. The Wiring card's **Expansion** table shows each run, its movement and the fittings needed.
- **Review it on the plan:** click a conduit, fitting, box or THHN item in the Measurements list and the conduit runs it counts are drawn on the floor plan — EMT grey, PVC blue, thicker for bigger pipe — each labelled with its size and length. Expansion fittings show as ⇔, conduit bodies as LB, elbows as dots. Hover a run for its bends, fittings and circuits.
- **THHN vs cable:** in conduit each circuit is single THHN wires (hots, neutral and a green ground — a 12/2 circuit is three 12 AWG wires), so the THHN feet are about three times the run length. It replaces the NM cable, never adds to it.
- **Switched an approved NM job to conduit?** Run wiring again: each THHN item says which approved cable it replaces, and approving it takes that cable off the estimate.
- Approve it like the cable: the conduit, fittings, THHN and surface-run labour are priced in place of the NM cable and wall boxes (never both).

## Good to know
- The Wiring card shows how the last run was routed ("Routed: basement — runs from the basement ceiling; outlets through the studs…").
- Every run makes two drawings: the **wiring drawing** (the floor plan with every circuit's route and a wire schedule) and the **wiring schematic** (the panel, its breakers and each circuit's conductors — black, red, white and ground — out to its devices).
- See them right here: **📐 Wiring schematic** on the toolbar, beside **⚡ Run wiring**, or **👁 View wiring drawing** / **👁 View schematic** in the Wiring card. Scroll to zoom, drag to move around, **Fit** for the whole drawing, and switch between the two. **⬇ Download DXF** in the viewer (or the ⬇ buttons in the Wiring card) saves it for any CAD program.
- A range or dryer on /2 cable in the schedule is priced as /3 (it needs a neutral) and flagged for the designer.
- Move a device to another circuit from the Wiring card (pick a circuit, then change the device's circuit) and run it again.
- If the circuit lines are drawn on the plan, the run is checked against them, with a one-click "Move to C-2" for each difference.
