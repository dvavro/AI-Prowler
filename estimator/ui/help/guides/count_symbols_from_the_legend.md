# Count symbols from the plan's legend
<!-- screen: plans; words: symbols, legend, outlets, receptacles, switches, fixtures, devices, count, GFCI, detections, symbol dictionary -->
When the plans are read, AI-Prowler finds the legend (ELECTRICAL LEGEND, SYMBOLS, PLUMBING FIXTURE LEGEND...) and looks for each of its symbols on every sheet: turned any way, mirrored, or on a wall line. The codes next to a symbol (GFI, WP, $3) tell look-alikes apart.

1. Open **Plans**, click the plan set and click **📖 Read the plans…** (or **Read the plans again…**), then **Yes**.
2. When it's read, **Symbols found from the legend** lists each kind of symbol, how many were found, how many are **to check**, and how many are on each sheet.
3. A symbol the legend doesn't name says **needs a person**. Look at the legend under **Legends** below; the **Found** column says how many of each entry were counted.
4. Symbols drawn in CAD (DXF) are named from their block names, e.g. a DUPLEX_OUTLET_GFI block is a GFCI receptacle.
5. These counts are proposals. Approve them in **Blueprint Review** before they're priced. Ask your AI "how many GFCI outlets are on the plans?" and it uses symbol_detections_list.

## Good to know
- Scanned plans are matched from the picture and are always marked to check.
- The **Jobs board** shows each plan job's progress: sheets read, symbols found, measurements approved and trades done.
