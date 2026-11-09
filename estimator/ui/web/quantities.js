/* Plan quantities page (Coder 2 Sprint 12): the shared wall-and-room model of a project and each trade's answers
 * from it, so framing, drywall, painting, insulation and flooring all use the same rooms, walls and openings, and
 * electrical and plumbing use the symbols a person approved. Sprint 15: the site (zones, fences, gates) for fencing
 * and landscaping.
 *
 * Loaded after app.js (el, api, words, helpLink, tile, errorBox, go ...).
 * Route: #/quantities/<estimate id>   ?height=<ft> ceiling height for rooms the finish schedule doesn't give;
 *                                      ?proposed=1 also counts symbols still to check.
 * Read only: nothing is saved here. Pricing with these answers is done on the Estimate page or by the AI
 * (plan_trade_answers then est_quick_answer).
 */
"use strict";

const QTY_TRADES = { framing: "🪵 Framing", drywall: "🧱 Drywall", painting: "🎨 Painting", insulation: "🧶 Insulation",
                     flooring: "🟫 Flooring", windows_doors: "🪟 Windows and doors", siding: "🏠 Siding",
                     hvac: "❄️ HVAC", fencing: "🚧 Fencing", landscaping: "🌳 Landscaping",
                     electrical: "⚡ Electrical", plumbing: "🚰 Plumbing" };
const QTY_ZONES = { sod: "Sod / lawn", turf: "Artificial turf", rock: "Rock / gravel", mulch: "Mulch",
                    pavers: "Pavers", bed: "Planting beds" };

function qtyNum(v, unit) {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  const n = Number(v);
  if (isNaN(n)) return String(v);
  return n.toLocaleString(undefined, { maximumFractionDigits: 1 }) + (unit ? " " + unit : "");
}

function qtyTable(id, heads, rows) {
  return el("table", { class: "list", id },
    el("thead", {}, el("tr", {}, heads.map(h => el("th", {}, h)))),
    el("tbody", {}, rows.map(r => el("tr", {}, r.map((c, i) => el("td", i ? { class: "num" } : {}, c))))));
}

function qtyTradeCard(id, t) {
  const keys = Object.keys(t.answers || {});
  const from = t.from || {};
  const waiting = t.waiting || {};
  const body = keys.length
    ? el("table", { class: "list" }, el("tbody", {}, keys.map(k => el("tr", { "data-q": k },
        el("td", {}, words(k)), el("td", { class: "num" }, qtyNum(t.answers[k])),
        el("td", { class: "small muted" }, from[k] || "", waiting[k] ? " · " + waiting[k] + " still to check" : "")))))
    : el("p", { class: "muted" }, "Nothing from the plans yet.");
  const notes = (t.notes || []).map(n => el("p", { class: "small note" }, n));
  return el("div", { class: "card", id: "qty-trade-" + id, "data-trade": id },
    el("h3", {}, QTY_TRADES[id] || words(id)), body, ...notes);
}

async function renderQuantities(main, estimateId) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const height = q.get("height") || "";
  const proposed = q.get("proposed") === "1";
  const qs = new URLSearchParams();
  if (height) qs.set("height", height);
  if (proposed) qs.set("proposed", "1");
  const head = [el("p", {}, el("a", { href: "#/takeoffs/" + estimateId }, "← 📏 Blueprint Review"), " · ",
      el("a", { href: "#/projects/" + estimateId }, "Project page"), " · ", el("a", { href: "#/estimates/" + estimateId }, "🧮 Estimate")),
    el("div", { class: "page-head" }, el("h2", {}, "📐 Plan quantities"), helpLink("takeoffs"))];
  let r;
  try {
    r = await api("GET", "/estimates/" + estimateId + "/quantities" + (qs.toString() ? "?" + qs : ""));
  } catch (e) {
    main.replaceChildren(...head, errorBox(e));
    return;
  }
  const m = r.model, t = m.totals;
  const parts = [...head, el("p", { class: "muted" }, r.estimate_title || ""),
    el("p", { id: "qty-summary" }, m.summary)];

  // Settings: ceiling height for rooms the finish schedule doesn't give, and whether to count symbols still to check.
  const hIn = el("input", { id: "qty-height", type: "number", min: "4", max: "40", step: "0.5", value: height,
                            placeholder: "8", "aria-label": "Ceiling height (ft)" });
  const pIn = el("input", { id: "qty-proposed", type: "checkbox", checked: proposed });
  const apply = el("button", { id: "qty-apply", type: "button", onclick: () => {
    const nq = new URLSearchParams();
    if (hIn.value) nq.set("height", hIn.value);
    if (pIn.checked) nq.set("proposed", "1");
    go("#/quantities/" + estimateId + (nq.toString() ? "?" + nq : ""));
  } }, "Work it out again");
  parts.push(el("div", { class: "row filters" }, el("label", {}, "Ceiling height (ft) where the plans don't say", hIn),
    el("label", {}, pIn, " Count symbols still to check"), apply));

  for (const n of m.notes || []) parts.push(el("p", { class: "note" }, n));
  const st = m.site || {};
  const hasSite = (st.zones || []).length || (st.fences || []).length;
  if (!m.rooms.length && hasSite) {
    parts.push(el("p", { class: "muted", id: "qty-site-only" }, "No floor plan rooms: this project's plans are site and landscape plans."));
  } else if (!m.rooms.length) {
    parts.push(el("div", { class: "card empty", id: "qty-empty" },
      "No rooms found yet. Read the plans on the Plans screen (each floor plan needs a scale) and the rooms, walls and openings are worked out here."));
  } else {
    parts.push(el("div", { class: "tiles", id: "qty-totals" },
      tile(qtyNum(t.floor_sqft), "sq ft floor"), tile(qtyNum(t.wall_face_sqft), "sq ft wall faces"),
      tile(qtyNum(t.exterior_wall_lf), "lf exterior wall"), tile(qtyNum(t.interior_wall_lf), "lf interior wall"),
      tile(t.doors, "doors"), tile(t.windows, "windows"), tile(t.corners, "corners")));
    parts.push(el("h3", {}, "Rooms"), qtyTable("qty-rooms",
      ["Room", "Sheet", "Floor sq ft", "Perimeter ft", "Height", "Wall sq ft", "Openings sq ft", "Base lf"],
      m.rooms.map(rm => [rm.name, rm.sheet_no || "", qtyNum(rm.area_sqft), qtyNum(rm.perimeter_ft),
        el("span", { title: rm.height_from }, qtyNum(rm.height_ft, "ft"), rm.height_from === "finish schedule" ? " 📋" : ""),
        qtyNum(rm.wall_sqft), qtyNum(rm.openings_sqft), qtyNum(rm.base_lf)])));
    const ops = m.openings || [];
    if (ops.length) {
      parts.push(el("h3", {}, "Doors and windows"), qtyTable("qty-openings", ["Mark", "Kind", "Width ft", "Height ft", "Size from", "Rooms"],
        ops.map(o => [o.mark || "", words(o.kind), qtyNum(o.width_ft), qtyNum(o.height_ft), words(o.size_from || ""),
          String((o.rooms || []).length)])));
    }
  }
  // Sprint 14: door and window schedule linking - each mark, its size and type, and how many are tagged on the plans.
  const marks = m.schedule_marks || [];
  if (marks.length) {
    parts.push(el("h3", {}, "Door and window schedule"), qtyTable("qty-marks",
      ["Mark", "Kind", "Size (ft)", "Type", "On the plans", "In the schedule"],
      marks.map(k => [k.mark, words(k.kind), k.width_ft && k.height_ft ? qtyNum(k.width_ft) + " x " + qtyNum(k.height_ft) : "—",
        k.type || "", el("span", { class: k.on_plans ? "" : "chip warn" }, String(k.on_plans)),
        k.schedule_qty === null || k.schedule_qty === undefined ? "—" : String(k.schedule_qty)])));
  }
  // Sprint 14: exterior elevations - each side's wall (floor line to plate line) and its openings.
  const elevs = m.elevations || [];
  if (elevs.length) {
    parts.push(el("h3", {}, "Exterior elevations"), qtyTable("qty-elevations",
      ["Side", "Sheet", "Wall sq ft", "Openings", "Less openings", "Stories"],
      elevs.map(e => [e.view, e.sheet_no || "", qtyNum(e.wall_sqft), String(e.openings.length) + " (" + qtyNum(e.openings_sqft) + " sq ft)",
        qtyNum(e.net_sqft), String(e.stories)])));
  }
  // Sprint 15: the site - landscape zones by kind, fence lines and gates.
  if (hasSite) {
    parts.push(el("h3", {}, "Site and landscape"));
    const z = st.zone_sqft || {};
    const zk = Object.keys(QTY_ZONES).filter(k => z[k]);
    if (zk.length) {
      parts.push(qtyTable("qty-zones", ["Zone", "Sq ft", "Areas"],
        zk.map(k => [QTY_ZONES[k], qtyNum(z[k]), String((st.zones || []).filter(x => x.kind === k).length)])));
    }
    const fg = st.fence_groups || [];
    if (fg.length) {
      parts.push(qtyTable("qty-fences", ["Fence", "Height", "Length", "Runs"],
        fg.map(g => [words(g.material || "not given"), g.height_ft ? qtyNum(g.height_ft, "ft") : "—", qtyNum(g.length_ft, "lf"),
          String(g.runs)])));
    }
    const gates = st.gates || {};
    if (gates.walk || gates.drive) {
      parts.push(el("p", { id: "qty-gates" }, "Gates: " + (gates.walk || 0) + " walk, " + (gates.drive || 0) + " drive"));
    }
    for (const n of st.notes || []) parts.push(el("p", { class: "small note" }, n));
  }
  if ((m.skipped_sheets || []).length) {
    parts.push(el("details", { id: "qty-skipped" }, el("summary", {}, "Sheets not counted (" + m.skipped_sheets.length + ")"),
      el("ul", {}, m.skipped_sheets.map(s => el("li", {}, el("a", { href: "#/sheets/" + s.sheet_id }, s.sheet_no || "a sheet"), ": " + s.why)))));
  }

  parts.push(el("h3", {}, "Each trade's answers"),
    el("p", { class: "muted small" }, "All from the same rooms, walls and openings, so the trades agree. Electrical and plumbing count the symbols approved in Reviews. Price them on the Estimate page, or ask your AI to use these answers."));
  parts.push(el("div", { class: "grid", id: "qty-trades" }, Object.keys(QTY_TRADES).filter(k => r.trades[k]).map(k => qtyTradeCard(k, r.trades[k]))));
  main.replaceChildren(...parts);
}

PAGES.quantities = renderQuantities;
