/* Blueprint Review (Coder 2 Sprint 7) - the Takeoffs screen and one project's review page.
 *
 * Loaded after app.js (same globals: el, api, toast, go, words, helpLink, errorBox, APP_TOKEN, SCREENS, PAGES...).
 * Spec "Blueprint Review screen": the blueprint on the left (tiled viewer: zoom, pan, sheet navigation, colour overlays
 * per layer, rooms filled and labelled with their area), a tool palette, a layers panel, the measurements grouped by
 * trade and room with running totals, a measurement detail panel, approve / correct / reject, locked approvals with
 * suggested changes, and a review queue (lowest confidence first).
 *
 * Coordinates are sheet units from the top-left (paper inches, or the drawing's own units for DXF), the same frame
 * as the drawing model, the tiles and the server's measuring - the page never measures for real, it only previews.
 * Routes: #/takeoffs   #/takeoffs/<estimate id>?sheet=<sheet id>&m=<measurement id>
 */
"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const REVIEW_STORE = "est_review_layers";         // which layer groups are hidden or locked (this browser only)
const HIDDEN_BY_DEFAULT = ["text", "dimensions", "floor_plan"];
const REAL_FT = { in: 1 / 12, ft: 1, mm: 1 / 304.8, cm: 1 / 30.48, m: 3.28084 };
const TOOLS = [
  ["select", "↖", "Select", "Click a room, wall or symbol to select it (Shift-click for more). Drag to move around."],
  ["pan", "✋", "Pan", "Drag to move around the sheet."],
  ["zoomwin", "🔍", "Zoom window", "Drag a box to zoom into it. Click to zoom in one step."],
  ["length", "📏", "Length", "Click along the line; double-click (or Enter) to finish."],
  ["area", "⬠", "Area", "Click the corners; click the first point, double-click or press Enter to finish."],
  ["rect", "▭", "Rectangle", "Click two opposite corners."],
  // 2026-11-18 (David): no Count tool — it counted badly and took view room; 🤖 AI Auto Run counts now.
  ["calibrate", "📐", "Calibrate", "Click both ends of a distance you know, then type its real length."],
  ["symbol", "✳", "Add symbol", "Click a symbol the plan engine missed, then say what it is."],
];
const RV = { estimateId: null, data: null, sheetId: null, sheet: null, viewports: [], tiles: null, objects: [],
             inactiveTrades: [], groups: [], byId: new Map(), selected: new Set(), measurementId: null,
             tool: "select", draft: [], draftTool: null, view: {}, viewer: null, sheetGen: 0 };

function svg(tag, attrs) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) n.setAttribute(k, String(v));
  return n;
}

function layerPrefs() {
  try {
    const p = JSON.parse(localStorage.getItem(REVIEW_STORE) || "null");
    if (p && Array.isArray(p.hidden) && Array.isArray(p.locked)) return p;
  } catch (e) { /* storage can be off or empty */ }
  return { hidden: HIDDEN_BY_DEFAULT.slice(), locked: [] };
}
function saveLayerPrefs(p) { try { localStorage.setItem(REVIEW_STORE, JSON.stringify(p)); } catch (e) { /* fine */ } }

function num(v, digits) {
  const n = parseFloat(v);
  return isNaN(n) ? "—" : n.toLocaleString(undefined, { maximumFractionDigits: digits === undefined ? 2 : digits });
}
function pct(c) { return c === null || c === undefined || c === "" ? "—" : Math.round(parseFloat(c) * 100) + "%"; }

// ------------------------------------------------------------------ Takeoffs screen (the list)
async function renderTakeoffs(main, screen) {
  const r = await api("GET", "/takeoffs");
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("takeoffs")),
    el("p", { class: "muted" }, "Measurements by project. Open one to check the plans, measure, and approve what gets priced.")];
  if (!r.projects.length) {
    parts.push(el("div", { class: "card empty", id: "takeoffs-empty" }, "No plans or measurements yet. ", el("a", { href: "#/projects" }, "Open Projects"), " and upload plans, then read them first."));
  } else {
    parts.push(el("table", { class: "list clickable", id: "takeoff-projects" },
      el("thead", {}, el("tr", {}, el("th", {}, "Project"), el("th", {}, "Plans read"), el("th", {}, "To review"),
        el("th", {}, "Approved"), el("th", {}, "Status"))),
      el("tbody", {}, r.projects.map(p => el("tr", { "data-id": p.estimate_id, onclick: () => go("#/takeoffs/" + p.estimate_id) },
        el("td", {}, el("a", { href: "#/takeoffs/" + p.estimate_id }, p.title)),
        el("td", {}, p.read + " of " + p.plan_sets),
        el("td", {}, p.to_review ? el("span", { class: "status sample" }, p.to_review) : "0"),
        el("td", {}, p.measurements.approved),
        el("td", {}, el("span", { class: "status" }, words(p.status))))))));
  }
  main.replaceChildren(...parts);
}

// ------------------------------------------------------------------ the review page
async function renderReview(main, estimateId) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  if (RV.estimateId !== estimateId) { RV.view = {}; RV.selected = new Set(); RV.measurementId = null; }
  RV.designFor = null;                  // 2026-11-21: ✨ AI design reads its state again each time the screen opens
  RV.estimateId = estimateId;
  RV.data = await api("GET", "/estimates/" + estimateId + "/takeoff");
  const d = RV.data;
  RV.draft = []; RV.draftTool = null;
  // A reviewer only looks, approves and adds missed symbols.
  if (!d.can_measure && !["select", "pan"].concat(d.can_approve ? ["symbol"] : []).includes(RV.tool)) RV.tool = "select";
  if (q.get("m")) RV.measurementId = +q.get("m") || null;
  // Sprint 8: ?line=<id> (from the Estimates screen) highlights every measurement behind that priced line.
  RV.lineId = +(q.get("line") || 0) || null;
  // Sprint 11: ?symbol=<detection id> (from Reviews) opens that symbol highlighted on its sheet.
  RV.symbolId = +(q.get("symbol") || 0) || null;
  const lineSheet = RV.lineId ? (lineMeasurements(RV.lineId).find(m => m.sheet_id) || {}).sheet_id : null;
  const wanted = +(q.get("sheet") || 0) || lineSheet;
  // 2026-11-15 (David): open on a sheet switched ON for the project's trades (Plans screen), not on one that's off.
  const firstSheet = d.sheets.find(s => s.id === wanted) || d.sheets.find(s => s.id === RV.sheetId && sheetOn(s)) ||
    d.sheets.find(s => sheetOn(s) && s.objects) || d.sheets.find(sheetOn) || d.sheets.find(s => s.objects) || d.sheets[0];
  const head = [el("p", {}, el("a", { href: "#/projects/" + estimateId }, "← " + d.estimate.title), " · ",
      el("a", { id: "bp-quantities", href: "#/quantities/" + estimateId }, "📐 Plan quantities")),
    el("div", { class: "page-head" }, el("h2", {}, "📏 Measure from plans (takeoff)"), helpLink("takeoffs"))];
  // The Director comes along to Measure (2026-11-21, David: "my director list did not follow me").
  if (!d.estimate.practice && typeof directorGuide === "function") head.push(directorGuide(estimateId));
  const msg = el("div", { id: "review-message", role: "status" });
  if (!d.sheets.length) {
    main.replaceChildren(...head, el("div", { class: "card empty", id: "review-no-sheets" },
      d.plan_sets.length ? "The plans on this project haven't been read yet — open them on the Plans screen and read them."
        : "This project has no plans yet. Upload them on the project page, read them, then come back to measure."),
      d.plan_sets.length ? el("p", {}, el("a", { href: "#/plan-sets/" + d.plan_sets[0].id }, "Open the plans")) : null,
      el("h3", {}, "Measurements"), measurementPanel(msg), msg);
    return;
  }
  const sheetPick = el("select", { id: "review-sheet", "aria-label": "Sheet" },
    d.sheets.map(s => el("option", { value: s.id, selected: s.id === firstSheet.id },
      (sheetOn(s) ? "✅ " : "⛔ ") + (s.sheet_no || "Page " + s.page_no) + (s.title ? " — " + s.title : "") +
      (sheetOn(s) ? "" : " (switched off)") + (s.needs_scale ? " (needs a scale)" : ""))));
  sheetPick.addEventListener("change", () => openSheet(+sheetPick.value, msg));
  const prev = el("button", { class: "button", type: "button", id: "review-prev", title: "Previous sheet" }, "◀");
  const next = el("button", { class: "button", type: "button", id: "review-next", title: "Next sheet" }, "▶");
  const step = dir => {
    const i = d.sheets.findIndex(s => s.id === RV.sheetId) + dir;
    if (i >= 0 && i < d.sheets.length) { sheetPick.value = d.sheets[i].id; openSheet(d.sheets[i].id, msg); }
  };
  prev.addEventListener("click", () => step(-1));
  next.addEventListener("click", () => step(1));
  const viewerBox = el("div", { class: "bp-viewer", id: "bp-viewer", tabindex: "0", "aria-label": "Blueprint" });
  const stepsTab = tabButton("steps", "Measure steps");
  stepsTab.hidden = true;      // only shows when a run has a calc or quantities to show (drawStepsPanel)
  const side = el("div", { class: "bp-side" },
    el("div", { class: "bp-tabs", role: "tablist" },
      tabButton("list", "Measurements"), tabButton("guide", "To measure"), tabButton("symbols", "Symbols"),
      tabButton("lines", "Lines"), tabButton("layers", "Layers"),
      tabButton("detail", "Detail"), stepsTab),
    el("div", { class: "bp-pane", id: "bp-pane-list" }),
    el("div", { class: "bp-pane", id: "bp-pane-guide", hidden: true }),
    el("div", { class: "bp-pane", id: "bp-pane-symbols", hidden: true }),
    el("div", { class: "bp-pane", id: "bp-pane-lines", hidden: true }),
    el("div", { class: "bp-pane", id: "bp-pane-layers", hidden: true }), el("div", { class: "bp-pane", id: "bp-pane-detail", hidden: true }),
    el("div", { class: "bp-pane", id: "bp-pane-steps", hidden: true }));
  // 2026-11-18 (David): the tools sit with the drawing, not at the top of the page — the sheet
  // picker stays up top, and the help line + toolbar render immediately above the split.
  // Full screen is unaffected: it fullscreens #bp-viewer only, and the toolbar was outside it before.
  main.replaceChildren(...head,
    el("div", { class: "row bp-bar" }, prev, sheetPick, next, viewButtons()),
    el("div", { id: "bp-readout-slot" }), el("div", { id: "bp-notes" }),
    msg, el("div", { id: "bp-auto-slot" }),
    el("p", { class: "muted small", id: "bp-tool-help" }, TOOLS.find(t => t[0] === RV.tool)[3]),
    toolPalette(msg), el("div", { class: "bp-split" }, viewerBox, side));
  RV.viewer = new Viewer(viewerBox, msg);
  $("bp-pane-list").replaceChildren(measurementPanel(msg));
  $("bp-pane-detail").replaceChildren(detailEmpty());      // the Detail tab is never blank without explanation
  await openSheet(firstSheet.id, msg);
  if (RV.symbolId) {
    const o = RV.objects.find(x => x.symbol && x.symbol.detection_id === RV.symbolId);
    showTab("symbols");
    if (o) highlightSymbols([o], o.symbol.item_type || "unknown");
    else msg.replaceChildren(el("p", { class: "note warn", id: "bp-symbol-missing" }, "That symbol isn't on this sheet any more (the plans may have been read again)."));
  } else if (RV.lineId) { showTab("lines"); RV.viewer.zoomToSelection(true); }
  else if (RV.measurementId) showDetail(RV.measurementId, msg, true);
  // 2026-11-20 (David): ?audit=1 (from the Director's checklist) opens Audit & clean up straight away.
  if (q.get("audit") && d.can_approve) openAudit();
}

// ------------------------------------------------------------------ Sprint 11: symbols on this sheet
// Counts by type (taken-out ones aren't counted); click a type to highlight every one of them on the plan, step
// through them one at a time, or open them in Reviews to approve, take out or relabel.
function sheetSymbols() { return RV.objects.filter(o => o.symbol); }
// The legend's sample of the highlighted symbols (2026-11-20, David: "light up the legend symbol with a different
// color so the user can check the symbol quickly"). On a CAD sheet the legend draws one of each with the same block
// as the plan, and the plan reader leaves the legend's samples uncounted (no symbol record): so a plain block with the
// same block name as a highlighted symbol is its legend sample. Shown, never counted or clickable onto the count.
function legendRefs(objs) {
  const names = new Set((objs || []).filter(o => o.symbol && o.block_name).map(o => o.block_name));
  return names.size ? (RV.objects || []).filter(o => !o.symbol && o.block_name && names.has(o.block_name)) : [];
}
function symbolKey(o) { return o.symbol ? o.symbol.item_type || "unknown" : "label"; }   // a plan label (30A circuits)

function drawSymbolsPanel(msg) {
  const pane = $("bp-pane-symbols");
  if (!pane) return;
  const syms = sheetSymbols();
  if (!syms.length) {
    pane.replaceChildren(el("p", { class: "muted", id: "bp-symbols-empty" }, "No symbols were found on this sheet. Symbols are counted from the plan set's legend when the plans are read."),
      RV.data.can_approve ? el("p", { class: "small muted" }, "Missed one? Use ✳ Add symbol and click it on the plan.") : null);
    return;
  }
  const byType = new Map();
  for (const o of syms) { const k = symbolKey(o); if (!byType.has(k)) byType.set(k, []); byType.get(k).push(o); }
  const rows = [...byType.entries()].sort((a, b) => b[1].length - a[1].length);
  const psId = RV.sheet && RV.sheet.plan_set_id;
  const list = el("ul", { class: "bp-rows", id: "bp-symbol-types" }, rows.map(([k, os]) => {
    const counted = os.filter(o => o.symbol.status !== "rejected");
    const toCheck = os.filter(o => o.symbol.status === "proposed").length;
    const li = el("li", { class: "bp-row" + (RV.symbolType === k ? " active" : ""), "data-symbol-type": k, tabindex: "0" },
      el("span", { class: "bp-row-name" }, os[0].symbol.label || (k === "unknown" ? "Unidentified symbol" : words(k))),
      el("span", { class: "bp-row-qty" }, counted.length + " found"),
      el("span", { class: "muted small" }, (toCheck ? toCheck + " to check" : "all checked") +
        (os.length > counted.length ? " · " + (os.length - counted.length) + " taken out" : "")));
    const pick = () => highlightSymbols(counted.length ? counted : os, k);
    li.addEventListener("click", pick);
    li.addEventListener("keydown", ev => { if (ev.key === "Enter") pick(); });
    return li;
  }));
  const prev = el("button", { class: "button", type: "button", id: "bp-symbol-prev", title: "Previous symbol" }, "◀");
  const next = el("button", { class: "button", type: "button", id: "bp-symbol-next", title: "Next symbol" }, "▶");
  const where = el("span", { class: "muted small", id: "bp-symbol-where" });
  prev.addEventListener("click", () => stepSymbol(-1));
  next.addEventListener("click", () => stepSymbol(1));
  const parts = [el("p", { class: "muted small" }, "Click a type to see every one on the plan; ◀ ▶ go through them one at a time."),
    list, el("div", { class: "row" }, prev, next, where), el("div", { id: "bp-symbol-one" })];
  if (psId) parts.push(el("p", {}, el("a", { id: "bp-symbol-review", href: "#/reviews/" + psId + (RV.symbolType ? "?type=" + RV.symbolType : "") },
    "✅ Check these in Reviews")));
  if (RV.data.can_approve) parts.push(el("p", { class: "small muted" }, "Missed one? Use ✳ Add symbol and click it on the plan."));
  pane.replaceChildren(...parts);
  showSymbolPos();
}

function highlightSymbols(objs, key) {
  // A symbol-type click isn't a count-row click: the Measure steps row loses its "on" state
  // (the count-row click sets RV.countStep again after calling this).
  RV.countStep = null; markCountRows();
  RV.symbolType = key;
  RV.symbolList = objs;
  RV.symbolPos = objs.length === 1 ? 0 : -1;           // -1: all of them at once
  RV.measurementId = null; RV.lineId = null;
  const dp = $("bp-pane-detail"); if (dp) dp.replaceChildren(detailEmpty());   // no selection any more
  RV.selected = new Set(objs.map(o => o.id));
  // A symbol in a hidden layer is shown while it's highlighted (the layer setting itself isn't changed), and the
  // layer is hidden again when the highlight goes (2026-11-19: it used to stay shown).
  rehideRevealed();
  for (const o of objs) {
    const g = RV.viewer.overlay.querySelector('[data-group="' + o.group + '"]');
    if (g && g.classList.contains("hidden")) { g.classList.remove("hidden"); RV.revealed.add(o.group); }
  }
  drawMeasurements();
  RV.viewer.zoomToSelection(true);
  drawSymbolsPanel($("review-message"));
}

// Hide again the layers a highlight showed, if they're still switched off in the Layers tab.
function rehideRevealed() {
  if (!RV.revealed) RV.revealed = new Set();
  const hidden = layerPrefs().hidden;
  for (const id of RV.revealed) {
    const g = RV.viewer && RV.viewer.overlay.querySelector('[data-group="' + id + '"]');
    if (g && hidden.includes(id)) g.classList.add("hidden");
  }
  RV.revealed.clear();
}

function stepSymbol(dir) {
  const list = RV.symbolList && RV.symbolList.length ? RV.symbolList : sheetSymbols();
  if (!list.length) return;
  if (!RV.symbolList || !RV.symbolList.length) { RV.symbolList = list; RV.symbolType = null; }
  RV.symbolPos = RV.symbolPos < 0 ? (dir > 0 ? 0 : list.length - 1) : (RV.symbolPos + dir + list.length) % list.length;
  const o = list[RV.symbolPos];
  RV.selected = new Set([o.id]);
  drawMeasurements();
  RV.viewer.zoomToSelection(true);
  showSymbolPos();
}

function showSymbolPos() {
  const where = $("bp-symbol-where"), one = $("bp-symbol-one");
  if (!where || !one) return;
  const list = RV.symbolList || [];
  if (!list.length) { where.textContent = ""; one.replaceChildren(); return; }
  if (RV.symbolPos < 0) { where.textContent = list.length + " highlighted"; one.replaceChildren(); return; }
  const o = list[RV.symbolPos], s = o.symbol;
  where.textContent = (RV.symbolPos + 1) + " of " + list.length;
  if (!s) {   // a plan label (e.g. "RANGE 30A"), not a symbol: nothing to check in Reviews
    one.replaceChildren(el("div", { class: "card section", id: "bp-symbol-detail" }, el("strong", {}, o.label || "Plan label"),
      el("div", { class: "small muted" }, "a label on the plan")));
    return;
  }
  one.replaceChildren(el("div", { class: "card section", id: "bp-symbol-detail", "data-detection": s.detection_id },
    el("strong", {}, s.label || (s.item_type ? words(s.item_type) : "Unidentified symbol")),
    el("div", { class: "small" }, el("span", { class: "status" }, words(s.status === "proposed" ? "to check" : s.status === "rejected" ? "taken out" : s.status)),
      " · " + pct(s.confidence) + (s.origin && s.origin !== "engine" ? " · " + words(s.origin) : "")),
    RV.sheet && RV.sheet.plan_set_id ? el("a", { class: "small", href: "#/reviews/" + RV.sheet.plan_set_id + "?type=" + symbolKey(o) }, "check it in Reviews") : null));
}

function addSymbolForm(p, msg) {
  const known = [...new Set(sheetSymbols().map(o => o.symbol.item_type).filter(Boolean))];
  const list = el("datalist", { id: "bp-symbol-types-list" }, known.map(t => el("option", { value: t })));
  const it = el("input", { id: "bp-symbol-type", maxlength: 60, list: "bp-symbol-types-list", placeholder: "e.g. duplex_receptacle", "aria-label": "What it is" });
  const b = el("button", { class: "primary", type: "button", id: "bp-symbol-add" }, "Add…");
  const no = el("button", { class: "button", type: "button", id: "bp-symbol-cancel" }, "Cancel");
  const ask = el("div", {});
  msg.replaceChildren(el("div", { class: "card section", id: "bp-symbol-form" },
    el("strong", {}, "Add a symbol at " + num(p[0]) + "\", " + num(p[1]) + "\""),
    el("div", { class: "row" }, el("label", {}, "What it is", it, list), b, no),
    el("p", { class: "small muted" }, "It's counted as approved and your company's library learns its shape."), ask));
  it.focus();
  no.addEventListener("click", () => msg.replaceChildren());
  const go = () => {
    const t = it.value.trim().toLowerCase().replace(/[\s-]+/g, "_");
    if (!t) { it.focus(); return; }
    reviewAsk(ask, b, "/symbol-detections/review", { action: "add", sheet_id: RV.sheetId, point: p, item_type: t },
      () => words(t) + " added", "bp-sym", true);
  };
  b.addEventListener("click", go);
  it.addEventListener("keydown", ev => { if (ev.key === "Enter") { ev.preventDefault(); go(); } });
}

// ------------------------------------------------------------------ Sprint 8: priced lines <-> measurements
function linkData() { return (RV.data && RV.data.links) || { lines: [], measurements: [], trades: [] }; }
function lineMeasurements(lineId) {
  const ln = linkData().lines.find(l => l.line_id === lineId);
  if (!ln) return [];
  const ids = new Set(ln.measurement_ids.concat(ln.proposed_ids));
  return RV.data.takeoff.measurements.filter(m => ids.has(m.id));
}
function linesFor(measurementId) {
  const m = linkData().measurements.find(x => x.id === measurementId);
  return m ? linkData().lines.filter(l => m.line_ids.includes(l.line_id)) : [];
}

function drawLinesPanel() {
  const pane = $("bp-pane-lines");
  if (!pane) return;
  const lines = linkData().lines;
  if (!lines.length) {
    pane.replaceChildren(el("p", { class: "muted", id: "bp-lines-empty" }, "No lines are priced on this estimate yet. Approve measurements, then price the trade on the Estimates screen."));
    return;
  }
  const byTrade = new Map();
  for (const l of lines) { if (!byTrade.has(l.module_id)) byTrade.set(l.module_id, []); byTrade.get(l.module_id).push(l); }
  const parts = [el("p", { class: "muted small" }, "Click a line to see every measurement behind it on the plan.")];
  for (const [mod, ls] of byTrade) {
    parts.push(el("h4", {}, tradeName(mod)), el("ul", { class: "bp-rows", id: "bp-lines-" + mod }, ls.map(l => {
      const ms = lineMeasurements(l.line_id), here = ms.filter(m => m.sheet_id === RV.sheetId).length;
      const li = el("li", { class: "bp-row" + (RV.lineId === l.line_id ? " active" : ""), "data-line": l.line_id, tabindex: "0" },
        el("span", { class: "bp-row-name" }, l.description),
        el("span", { class: "bp-row-qty" }, num(l.quantity) + " " + l.unit),
        el("span", { class: "muted small" }, ms.length ? "📏 " + ms.length + " measurement(s)" + (ms.length > here ? " · " + here + " on this sheet" : "") :
          l.questions.length ? "not measured yet" : "entered by hand"),
        el("a", { href: "#/estimates/" + RV.estimateId + "?line=" + l.line_id, class: "small", onclick: ev => ev.stopPropagation() }, "on the estimate"));
      const pick = () => {
        RV.lineId = RV.lineId === l.line_id ? null : l.line_id;
        RV.measurementId = null;
        const dp = $("bp-pane-detail"); if (dp) dp.replaceChildren(detailEmpty());   // no selection any more
        drawMeasurements(); drawLinesPanel();
        if (RV.lineId) {
          const other = ms.find(m => m.sheet_id && m.sheet_id !== RV.sheetId);
          if (!here && other && $("review-sheet")) { $("review-sheet").value = other.sheet_id; openSheet(other.sheet_id, $("review-message")).then(() => RV.viewer.zoomToSelection(true)); }
          else RV.viewer.zoomToSelection(true);
        }
      };
      li.addEventListener("click", pick);
      li.addEventListener("keydown", ev => { if (ev.key === "Enter") pick(); });
      return li;
    })));
  }
  pane.replaceChildren(...parts);
}

function tabButton(id, label) {
  const b = el("button", { class: "bp-tab" + (id === "list" ? " active" : ""), type: "button", role: "tab", "data-tab": id, id: "bp-tab-" + id }, label);
  b.addEventListener("click", () => showTab(id));
  return b;
}
function showTab(id) {
  for (const t of document.querySelectorAll(".bp-tab")) t.classList.toggle("active", t.dataset.tab === id);
  for (const p of ["list", "guide", "symbols", "lines", "layers", "detail", "steps"]) { const n = $("bp-pane-" + p); if (n) n.hidden = p !== id; }
}

function toolPalette(msg) {
  const box = el("div", { class: "bp-tools", role: "toolbar", "aria-label": "Tools", id: "bp-tools" });
  for (const [id, icon, label, help] of TOOLS) {
    if (["length", "area", "rect"].includes(id) && !RV.data.can_measure) continue;
    if (id === "calibrate" && !RV.data.can_measure) continue;
    if (id === "symbol" && !RV.data.can_approve) continue;          // adding a symbol is a reviewer's decision
    const b = el("button", { class: "bp-tool" + (id === RV.tool ? " active" : ""), type: "button", "data-tool": id, title: label + " — " + help }, icon + " " + label);
    b.addEventListener("click", () => setTool(id, msg));
    box.append(b);
  }
  // Phase 1: the agent measures on its own (a measuring action, so it sits with the measure tools and is
  // hidden from reviewers). Without a runnable trade on the estimate it stays, disabled, with the reason —
  // the agent measures the quantities on the plans for the project's construction trades. drawAutoRunStatus
  // keeps the title naming the trade it will actually run.
  if (RV.data.can_measure) {
    const trade = selectedAutoRunTrade();
    const run = el("button", { class: "button", type: "button", id: "bp-auto-run",
      disabled: !trade,
      title: autoRunTitle(trade, true) },
      "🤖 AI Auto Run");
    run.addEventListener("click", () => startAutoRun());
    box.append(attachHoverCard(run, "bp-auto-run-help", autoRunHelp));    // what this trade's run needs (2026-11-21)
    // More than one runnable trade: a picker next to the button, so the run goes to the trade the user
    // wants — the default follows the open sheet's discipline until the user picks (drawAutoRunStatus
    // keeps the picker in step), and the choice is kept in AUTO.pickedTrade so a redraw never loses it.
    const runnable = autoRunTrades();
    if (runnable.length > 1) {
      const pick = el("select", { id: "bp-auto-trade", "aria-label": "Trade for AI Auto Run",
        title: "Which trade AI Auto Run measures" },
        runnable.map(t => el("option", { value: t.module_id, selected: t.module_id === trade }, t.name)));
      pick.addEventListener("change", () => { AUTO.pickedTrade = pick.value; drawAutoRunStatus(); });
      box.append(pick);
    }
    // 2026-11-23 (David: "move the Let AI Design to the main measure window by the AI Auto Run, let's not hide it in the
    // 'to measure' tab"): ✨ AI design on the toolbar, opening its own window (openDesignPanel).
    const design = el("button", { class: "button", type: "button", id: "bp-ai-design",
      title: "Describe what to add (e.g. lighting, receptacles and a subpanel for your shed) — the AI reads the building, " +
             "places every symbol to code and draws a new plan and panel schedule for you to review and approve. " +
             "Nothing is priced until you approve it. Uses the agent API key." }, designButtonText());
    design.addEventListener("click", () => openDesignPanel());
    box.append(design);
    if (RV.designFor !== RV.estimateId) drawDesign();     // the button says when a design is working or ready
    // 2026-11-20 (David: "I don't see the run wiring"): just the wiring, beside AI Auto Run - routes the cable from the
    // floor plan and the panel drawing (plain geometry, no AI tokens), the same run as the Wiring card's button.
    if (RV.data.trades.some(t => t.module_id === "electrical")) {
      const wire = el("button", { class: "button", type: "button", id: "bp-run-wiring",
        title: "Run just the wiring: route the cable from the panel to every device and propose the cable sizes and " +
               "lengths (plain geometry - no AI tokens, your counts aren't touched). Needs the electrical floor plan and " +
               "the panel drawing as DXF files. Settings and device moves: the ⚡ Wiring card in the To measure tab." },
        "⚡ Run wiring");
      wire.addEventListener("click", () => openWiringOptions(wire));   // 2026-11-21: how the cable runs, first
      box.append(attachHoverCard(wire, "bp-run-wiring-help", wiringHelp));
      // 2026-11-21 (David: "I thought we can generate a schematic diagram after the wiring is ran? I don't see it"): the
      // schematic was only in the Wiring card at the bottom of the To measure tab - now on the toolbar beside Run wiring.
      const sch = el("button", { class: "button", type: "button", id: "bp-tool-schematic",
        title: "Show the wiring schematic from the last wiring run: the panel, its breakers and every circuit's " +
               "conductors (black, red, white, ground) out to its devices. Zoom in, or download it as a DXF." },
        "📐 Wiring schematic");
      sch.addEventListener("click", async () => {
        // no run yet (or one from before schematics): say so instead of a failed download
        let w = null;
        try { w = await api("GET", "/wiring/" + RV.estimateId); } catch (e) { if (e.status === 401) return; }
        if (!(w && w.run && w.run.schematic)) {
          toast("No wiring schematic yet — click ⚡ Run wiring first; each run draws one.");
          return;
        }
        openWiringViewer("schematic");          // shown on the screen; ⬇ Download DXF is in the viewer
      });
      box.append(sch);
    }
    // 2026-11-19 (David): a rerun recalculates the trade; whether the items already approved stay (not proposed
    // again - saves the review time) or everything starts over from scratch is the user's choice. Kept between visits.
    const keep = el("input", { type: "checkbox", id: "bp-auto-keep", checked: keepApproved() ? "" : null });
    keep.addEventListener("change", () => setKeepApproved(keep.checked));
    box.append(el("label", { class: "small", for: "bp-auto-keep", id: "bp-auto-keep-label",
      title: "Ticked: a rerun (AI Auto Run or ⚡ Run wiring) keeps what you already approved and only proposes the rest; " +
             "when the rerun measures an approved item differently, the new value waits as a suggested change for you to accept. " +
             "Unticked: a rerun starts the trade over from scratch — approved AI results on the sheet are replaced too " +
             "(what you drew or typed is never touched)." },
      keep, " Keep approved items on rerun"));             // 2026-11-21 (David): say when it applies
  }
  // 2026-11-20 (David): one button finds what needs a person - counts priced twice, counts from before the plans were
  // read again, counts waiting, counts the drawing disagrees with, rejected items - and fixes them in one go.
  if (RV.data.can_approve) {
    const audit = el("button", { class: "button", type: "button", id: "bp-audit-open",
      title: "Find counts priced twice, counts from before the plans were read again, counts waiting for review and rejected items — and fix them all at once" },
      "🧹 Audit & clean up");
    audit.addEventListener("click", () => openAudit());
    box.append(audit);
  }
  return box;
}
// Keep approved items on an AI Auto Run / Wiring rerun (default yes), remembered in this browser.
const KEEP_APPROVED_STORE = "est_auto_keep_approved";
function keepApproved() {
  try { return localStorage.getItem(KEEP_APPROVED_STORE) !== "0"; } catch (e) { return true; }
}
function setKeepApproved(on) {
  try { localStorage.setItem(KEEP_APPROVED_STORE, on ? "1" : "0"); } catch (e) { /* storage off: this visit only */ }
  RV.keepApproved = !!on;
}
function keepApprovedNow() {
  const box = $("bp-auto-keep");
  return box ? box.checked : (RV.keepApproved !== undefined ? RV.keepApproved : keepApproved());
}
// A CAD drawing (DXF/DWG) is drawn at real size in real units, so it has no scale to set.
function isCadSheet() { return !!(RV.sheet && RV.sheet.units && RV.sheet.units !== "paper_in"); }
const CAD_NO_SCALE = "This drawing is a CAD file at real size, so it doesn't need calibrating — measure with 📏 Length, " +
  "⬠ Area or ▭ Rectangle and the lengths are already real.";

function setTool(id, msg) {
  if (id === "calibrate" && isCadSheet()) {      // say so now, not after both points are clicked (2026-11-19)
    if (msg) msg.replaceChildren(el("p", { class: "note", id: "bp-cad-no-scale" }, CAD_NO_SCALE));
    return;
  }
  RV.tool = id;
  RV.adjust = null;      // picking a tool by hand ends "draw an area to add / take away" (startAdjust sets it after this)
  RV.placing = null;     // ...and "click the footer section's corner" (startPlaceSection sets it after this)
  // Switching tools never throws the unfinished line away: it stays drawn
  // (and keeps the tool it was started with) until it is finished or Esc.
  if (RV.viewer) RV.viewer.drawDraft();
  if (RV.viewer) RV.viewer.clearZoomBox();
  for (const b of document.querySelectorAll(".bp-tool")) b.classList.toggle("active", b.dataset.tool === id);
  const t = TOOLS.find(x => x[0] === id);
  if ($("bp-tool-help")) $("bp-tool-help").textContent = (t ? t[3] : "") +
    (RV.draft.length ? " Your unfinished " + words(RV.draftTool || id) + " is kept — switch back to it to keep drawing, or press Finish." : "");
  if (RV.viewer) RV.viewer.box.classList.toggle("drawing", !["select", "pan"].includes(id));
  if (msg && ["length", "area", "rect", "calibrate"].includes(id)) msg.replaceChildren();
}
function viewButtons() {
  const mk = (id, text, title, fn) => { const b = el("button", { class: "button", type: "button", id, title }, text); b.addEventListener("click", fn); return b; };
  return el("div", { class: "row bp-view" },
    mk("bp-zoom-in", "＋", "Zoom in", () => RV.viewer.zoomBy(1.5)),
    mk("bp-zoom-out", "－", "Zoom out", () => RV.viewer.zoomBy(1 / 1.5)),
    mk("bp-fit", "Fit", "Fit the sheet", () => RV.viewer.fit()),
    mk("bp-rotate", "⟳ Rotate", "Rotate the sheet 90° clockwise", () => RV.viewer.rotate()),
    mk("bp-zoom-sel", "Zoom to selection", "Zoom to what's selected", () => RV.viewer.zoomToSelection()),
    mk("bp-full", "⛶", "Full screen", () => toggleBpFull()));
}

// Full screen for the Blueprint Review viewer (2026-11-13: iPhone Safari has no Fullscreen API for page elements, so the
// ⛶ button did nothing there). The real API where it exists (webkit names for iPad), else the viewer fills the window
// (.pseudo-full) with its own ✕ button, since the toolbar is outside it.
function toggleBpFull() {
  const v = $("bp-viewer");
  if (!v) return;
  const fsEl = document.fullscreenElement || document.webkitFullscreenElement;
  if (fsEl) { (document.exitFullscreen || document.webkitExitFullscreen).call(document); return; }
  if (v.classList.contains("pseudo-full")) { setBpPseudoFull(v, false); return; }
  const native = document.fullscreenEnabled || document.webkitFullscreenEnabled;
  if (native && v.requestFullscreen) v.requestFullscreen().catch(() => setBpPseudoFull(v, true));
  else if (native && v.webkitRequestFullscreen) v.webkitRequestFullscreen();
  else setBpPseudoFull(v, true);
}
function setBpPseudoFull(v, on) {
  v.classList.toggle("pseudo-full", on);
  document.documentElement.classList.toggle("pseudo-full-on", on);
  const old = $("bp-full-close");
  if (old) old.remove();
  if (on) {
    const close = el("button", { class: "button bp-full-close", type: "button", id: "bp-full-close",
      title: "Exit full screen", "aria-label": "Exit full screen" }, "✕ Exit full screen");
    close.addEventListener("pointerdown", e => e.stopPropagation());
    close.addEventListener("click", e => { e.stopPropagation(); setBpPseudoFull(v, false); });
    v.append(close);
  }
  requestAnimationFrame(() => { if (RV.viewer) RV.viewer.fit(); });
}
document.addEventListener("keydown", e => {
  const v = $("bp-viewer");
  if (e.key === "Escape" && v && v.classList.contains("pseudo-full")) setBpPseudoFull(v, false);
});
window.addEventListener("hashchange", () => {
  const v = $("bp-viewer");
  document.documentElement.classList.remove("pseudo-full-on");
  if (v && v.classList.contains("pseudo-full")) setBpPseudoFull(v, false);
});

async function openSheet(sheetId, msg) {
  // 2026-11-19: two opens can overlap (a fast picker change while a load is in flight) — the
  // last response to land used to win, so the tiles came from one sheet and the objects from
  // the other. Each open takes a generation; a stale response is abandoned whole, so RV.*
  // always agrees with the newest open.
  const gen = ++RV.sheetGen;
  RV.sheetId = sheetId;
  RV.selected = new Set();
  RV.draft = []; RV.draftTool = null;   // a half-drawn line belongs to its sheet
  RV.adjust = null; RV.placing = null;  // ...and so do an area being drawn to add / take away and a section being placed
  RV.symbolList = []; RV.symbolPos = -1; RV.symbolType = null; RV.countStep = null;   // the Symbols tab starts again on each sheet
  RV.review = null;                     // a review card's highlighted symbols belong to its sheet
  RV.revealed = new Set();             // the new sheet's layers are drawn from the Layers settings
  const [s, o] = await Promise.all([api("GET", "/sheets/" + sheetId), api("GET", "/sheets/" + sheetId + "/objects")]);
  if (gen !== RV.sheetGen) return;   // a newer open started while this one was in flight — abandon it
  RV.sheet = s.sheet; RV.viewports = s.viewports; RV.tiles = s.tiles;
  RV.inactiveTrades = s.inactive_trades || [];      // trades this sheet is switched off for (Plans screen)
  RV.objects = o.objects; RV.groups = o.layers;
  RV.byId = new Map(o.objects.map(x => [x.id, x]));
  if (isCadSheet() && RV.tool === "calibrate") setTool("select", null);   // no Calibrate on a CAD drawing
  const sel = $("bp-selection");
  if (sel) sel.remove();
  const warn = [];
  if (o.count > o.returned) warn.push("Showing the first " + o.returned + " of " + o.count + " things found on this sheet.");
  // A CAD drawing is at real size: it never needs a scale (2026-11-19, David: the note sent him to 📐 Calibrate, which
  // then refused). Only a paper sheet (PDF, scan, photo) can have a view with no scale.
  if (!isCadSheet() && s.viewports.some(v => !v.measurable && !v.is_nts)) warn.push("Part of this sheet has no scale yet — set it with 📐 Calibrate or on the Plans screen before measuring there.");
  $("bp-notes").replaceChildren(...(warn.length ? [el("p", { class: "note warn", id: "bp-sheet-note" }, warn.join(" "))] : []));
  RV.viewer.load();
  drawLayersPanel();
  drawSymbolsPanel(msg);
  drawLinesPanel();
  refreshList(msg);
  loadAutoCandidates();      // what the agent found on this sheet, in the background (never blocks the sheet)
  loadLatestRun();           // a run still going, or the last run's results on this sheet (2026-11-15)
}

// ------------------------------------------------------------------ the viewer: tiles + SVG overlay
class Viewer {
  constructor(box, msg) {
    this.box = box; this.msg = msg;
    this.stage = el("div", { class: "bp-stage" });
    this.tilesLayer = el("div", { class: "bp-tiles" });
    this.overlay = svg("svg", { class: "bp-overlay", "aria-hidden": "true" });
    this.stage.append(this.tilesLayer, this.overlay);
    box.replaceChildren(this.stage);
    this.z = 1; this.tx = 0; this.ty = 0; this.rot = 0; this.level = -1; this.tileEls = new Map(); this.pointers = new Map(); this.zoomBox = null;
    box.addEventListener("wheel", ev => { ev.preventDefault(); this.zoomAt(ev.deltaY < 0 ? 1.2 : 1 / 1.2, ev.clientX, ev.clientY); }, { passive: false });
    box.addEventListener("pointerdown", ev => this.down(ev));
    box.addEventListener("pointermove", ev => this.move(ev));
    box.addEventListener("pointerup", ev => this.up(ev));
    box.addEventListener("pointercancel", ev => this.cancel(ev));
    box.addEventListener("dragstart", ev => ev.preventDefault());
    box.addEventListener("dblclick", ev => { ev.preventDefault(); finishDraft(this.msg); });
    box.addEventListener("keydown", ev => this.key(ev));
  }
  get W() { return parseFloat(RV.sheet.width) || 1; }
  get H() { return parseFloat(RV.sheet.height) || 1; }

  load() {
    this.tileEls.forEach(t => t.remove()); this.tileEls.clear(); this.level = -1;
    this.backdrop = null;
    for (const n of this.box.querySelectorAll(".bp-empty")) n.remove();
    this.overlay.setAttribute("viewBox", "0 0 " + this.W + " " + this.H);
    this.clearZoomBox();
    drawOverlay(this.overlay);
    const saved = RV.view[RV.sheetId];
    if (saved) { this.z = saved.z; this.tx = saved.tx; this.ty = saved.ty; this.rot = saved.rot || 0; this.render(); } else { this.rot = 0; this.fit(); }
    if (!RV.tiles) this.box.append(el("p", { class: "bp-empty" }, "This sheet has no image yet."));
  }
  effDims() { return this.rot % 180 === 0 ? [this.W, this.H] : [this.H, this.W]; }
  fit() {
    const r = this.box.getBoundingClientRect();
    const [ew, eh] = this.effDims();
    this.z = Math.max(1e-4, Math.min((r.width - 20) / ew, (r.height - 20) / eh));
    const [x0, y0, x1, y1] = rotBox(0, 0, this.W * this.z, this.H * this.z, this.rot);
    this.tx = (r.width - (x1 - x0)) / 2 - x0;
    this.ty = (r.height - (y1 - y0)) / 2 - y0;
    this.render();
  }
  rotate() {
    // Keep whatever is in the middle of the screen in the middle.
    const r = this.box.getBoundingClientRect();
    const [ux, uy] = this.toSheet(r.left + r.width / 2, r.top + r.height / 2);
    this.rot = (this.rot + 90) % 360;
    this.centerOn(ux, uy);
  }
  centerOn(ux, uy) {
    const r = this.box.getBoundingClientRect();
    const [rx, ry] = rotXY(ux * this.z, uy * this.z, this.rot);
    this.tx = r.width / 2 - rx; this.ty = r.height / 2 - ry;
    this.render();
  }
  zoomBy(f) { const r = this.box.getBoundingClientRect(); this.zoomAt(f, r.left + r.width / 2, r.top + r.height / 2); }
  zoomAt(f, cx, cy) {
    const r = this.box.getBoundingClientRect();
    const [ux, uy] = this.toSheet(cx, cy);
    const [ew, eh] = this.effDims();
    const fitZ = Math.min(r.width / ew, r.height / eh);
    // Wheel zoom has no working cap: pro viewers let it run until the detail
    // fills the screen. The old fitZ * 40 cap stopped a plan that is a small
    // part of its sheet at ~40 px wide. The raster tiles blur past that, but
    // the vector overlay stays sharp; 4000x fit is a sanity bound only.
    this.z = Math.min(Math.max(this.z * f, fitZ / 4), fitZ * 4000);
    const [rx, ry] = rotXY(ux * this.z, uy * this.z, this.rot);
    this.tx = cx - r.left - rx; this.ty = cy - r.top - ry;
    this.render();
  }
  zoomToBox(b) {
    const r = this.box.getBoundingClientRect();
    // Floor is a small absolute size, not a fraction of the sheet: zoom to
    // selection must fit the selected thing, and W/200 is ~1,100 units on a
    // sheet whose plan is only 300 units wide.
    const [bx0, by0, bx1, by1] = rotBox(b[0], b[1], b[2], b[3], this.rot);
    const w = Math.max(bx1 - bx0, 10), h = Math.max(by1 - by0, 10);
    this.z = Math.min((r.width * 0.8) / w, (r.height * 0.8) / h);
    const [cx0, cy0, cx1, cy1] = rotBox(b[0] * this.z, b[1] * this.z, b[2] * this.z, b[3] * this.z, this.rot);
    this.tx = r.width / 2 - (cx0 + cx1) / 2; this.ty = r.height / 2 - (cy0 + cy1) / 2;
    this.render();
  }
  zoomToSelection(quiet) {
    const pts = [];
    for (const id of RV.selected) { const o = RV.byId.get(id); if (o && o.geometry) pts.push(...o.geometry.points); }
    const cur = currentMeasurement();
    const ms = (cur ? [cur] : []).concat(RV.lineId ? lineMeasurements(RV.lineId) : []).filter(m => m.sheet_id === RV.sheetId);
    for (const m of ms) {
      if (m.geometry) pts.push(...m.geometry.points);
      for (const id of m.source_object_ids) { const o = RV.byId.get(id); if (o && o.geometry) pts.push(...o.geometry.points); }
    }
    if (!pts.length) { if (!quiet) toast("Select something first."); return; }
    const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
    this.zoomToBox([Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)]);
  }
  drawZoomBox() {
    let r = this.overlay.querySelector("#bp-zoombox");
    if (!this.zoomBox) { if (r) r.remove(); return; }
    const [x0, y0, x1, y1] = this.zoomBox;
    if (!r) { r = svg("rect", { id: "bp-zoombox", class: "bp-zoombox" }); this.overlay.append(r); }
    r.setAttribute("x", x0); r.setAttribute("y", y0);
    r.setAttribute("width", Math.max(0, x1 - x0)); r.setAttribute("height", Math.max(0, y1 - y0));
  }
  clearZoomBox() { this.zoomBox = null; this.drawZoomBox(); }
  toSheet(cx, cy) {
    const r = this.box.getBoundingClientRect();
    const [x, y] = rotXY(cx - r.left - this.tx, cy - r.top - this.ty, -this.rot);
    return [x / this.z, y / this.z];
  }
  render() {
    if (!RV.sheet) return;
    RV.view[RV.sheetId] = { z: this.z, tx: this.tx, ty: this.ty, rot: this.rot };
    const w = this.W * this.z, h = this.H * this.z;
    this.stage.style.transform = "translate(" + this.tx + "px," + this.ty + "px) rotate(" + this.rot + "deg)";
    this.stage.style.width = w + "px"; this.stage.style.height = h + "px";
    this.overlay.setAttribute("width", w); this.overlay.setAttribute("height", h);
    // Room labels keep the same size on screen at any zoom (lines and dots use non-scaling strokes in the CSS).
    for (const t of this.overlay.querySelectorAll("text")) t.setAttribute("font-size", 12 / this.z);
    this.tilesFor();
  }
  tilesFor() {
    const t = RV.tiles;
    if (!t) return;
    const long = Math.max(this.W, this.H);
    if (!this.backdrop) {                          // level 0: the whole sheet in one tile, under everything
      this.backdrop = this.tile(0, 0, 0, true);
    }
    const dpr = window.devicePixelRatio || 1;
    const want = Math.max(0, Math.min(t.max_level, Math.ceil(Math.log2(Math.max(1, this.z * dpr * long / t.tile)))));
    if (want !== this.level) {
      this.tileEls.forEach((n, k) => { if (k !== "0/0/0") { n.remove(); this.tileEls.delete(k); } });
      this.level = want;
    }
    // Every tile already loaded moves with the zoom, even ones now out of view, so none is left in a stale spot.
    this.tileEls.forEach((n, k) => { const [l, x, y] = k.split("/").map(Number); this.layTile(n, l, x, y); });
    if (want === 0) return;
    const size = long / Math.pow(2, want);
    const r = this.box.getBoundingClientRect();
    const [x0, y0] = this.toSheet(r.left, r.top), [x1, y1] = this.toSheet(r.right, r.bottom);
    const cols = Math.ceil(this.W / size - 1e-9), rows = Math.ceil(this.H / size - 1e-9);
    const cx0 = Math.max(0, Math.floor(x0 / size)), cx1 = Math.min(cols - 1, Math.floor(x1 / size));
    const cy0 = Math.max(0, Math.floor(y0 / size)), cy1 = Math.min(rows - 1, Math.floor(y1 / size));
    for (let x = cx0; x <= cx1; x++) for (let y = cy0; y <= cy1; y++) {
      const k = want + "/" + x + "/" + y;
      const n = this.tileEls.get(k) || this.tile(want, x, y, false);
      this.layTile(n, want, x, y);
    }
  }
  tile(level, x, y, backdrop) {
    const k = level + "/" + x + "/" + y;
    const img = el("img", { class: "bp-tile" + (backdrop ? " backdrop" : ""), alt: "", draggable: "false", "data-tile": k });
    this.tileEls.set(k, img);
    this.tilesLayer.append(img);
    tileUrl(RV.sheetId, level, x, y).then(u => { img.src = u; }).catch(() => img.classList.add("missing"));
    return img;
  }
  layTile(n, level, x, y) {
    const size = Math.max(this.W, this.H) / Math.pow(2, level);
    const w = Math.min(size, this.W - x * size), h = Math.min(size, this.H - y * size);
    n.style.left = x * size * this.z + "px"; n.style.top = y * size * this.z + "px";
    n.style.width = w * this.z + "px"; n.style.height = h * this.z + "px";
  }

  down(ev) {
    this.box.focus({ preventScroll: true });
    this.pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    this.box.setPointerCapture(ev.pointerId);
    this.start = { x: ev.clientX, y: ev.clientY, tx: this.tx, ty: this.ty, moved: false, target: ev.target, shift: ev.shiftKey };
    if (this.pointers.size === 2) this.pinch = this.pinchState();
  }
  pinchState() {
    const [a, b] = [...this.pointers.values()];
    return { d: Math.hypot(a.x - b.x, a.y - b.y), cx: (a.x + b.x) / 2, cy: (a.y + b.y) / 2, z: this.z };
  }
  move(ev) {
    if (!this.pointers.has(ev.pointerId)) { this.hover(ev); return; }
    this.pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (this.pointers.size === 2 && this.pinch) {
      const p = this.pinchState();
      this.zoomAt((this.pinch.z * p.d / this.pinch.d) / this.z, p.cx, p.cy);
      return;
    }
    const s = this.start;
    if (!s) return;
    const dx = ev.clientX - s.x, dy = ev.clientY - s.y;
    if (!s.moved && Math.hypot(dx, dy) < 4) return;
    s.moved = true;
    if (["select", "pan"].includes(RV.tool) || ev.buttons === 4) {
      this.tx = s.tx + dx; this.ty = s.ty + dy; this.render();
    } else if (RV.tool === "zoomwin") {
      const [x0, y0] = this.toSheet(s.x, s.y);
      const [x1, y1] = this.toSheet(ev.clientX, ev.clientY);
      this.zoomBox = [Math.min(x0, x1), Math.min(y0, y1), Math.max(x0, x1), Math.max(y0, y1)];
      this.drawZoomBox();
    }
  }
  up(ev) {
    this.pointers.delete(ev.pointerId);
    if (this.pointers.size < 2) this.pinch = null;
    const s = this.start;
    this.start = null;
    if (RV.tool === "zoomwin") {
      if (this.pointers.size > 0) { this.clearZoomBox(); return; }
      if (s && s.moved && Math.hypot(ev.clientX - s.x, ev.clientY - s.y) >= 8) {
        const [x0, y0] = this.toSheet(s.x, s.y);
        const [x1, y1] = this.toSheet(ev.clientX, ev.clientY);
        this.clearZoomBox();
        this.zoomToBox([Math.min(x0, x1), Math.min(y0, y1), Math.max(x0, x1), Math.max(y0, y1)]);
      } else if (s) {
        this.clearZoomBox();
        this.zoomAt(1.5, ev.clientX, ev.clientY);
      }
      return;
    }
    if (!s || s.moved) return;
    if (RV.tool === "select") { pickAt(s.target, s.shift, this.msg); return; }
    if (RV.tool === "pan") return;
    const p = this.place(ev);
    if (RV.tool === "symbol") { addSymbolForm([round3(p[0]), round3(p[1])], this.msg); return; }
    addDraftPoint([round3(p[0]), round3(p[1])], this.msg);
  }
  cancel(ev) {
    this.pointers.delete(ev.pointerId);
    if (this.pointers.size < 2) this.pinch = null;
    if (!this.pointers.size) this.start = null;
    this.clearZoomBox();
  }
  // Sprint 8 polish: snap to the drawing's corners (within 10 px; hold Alt to place freely), and Shift keeps the new
  // segment straight across or straight down.
  place(ev) {
    let [ux, uy] = this.toSheet(ev.clientX, ev.clientY);
    this.snapped = null;
    const last = RV.draft[RV.draft.length - 1];
    if (ev.shiftKey && last) {
      if (Math.abs(ux - last[0]) >= Math.abs(uy - last[1])) uy = last[1]; else ux = last[0];
    }
    if (!ev.altKey) {
      const hit = snapPoint([ux, uy], 10 / this.z, ev.shiftKey && last ? last : null);
      if (hit) { [ux, uy] = hit; this.snapped = hit; }
    }
    return [ux, uy];
  }
  hover(ev) {
    if (["select", "pan", "zoomwin"].includes(RV.tool)) return;
    this.drawDraft(this.place(ev));
  }
  key(ev) {
    if (ev.key === "Escape") { RV.draft = []; RV.draftTool = null; RV.adjust = null; RV.placing = null; this.drawDraft(); this.clearZoomBox(); this.start = null; }
    else if ((ev.key === "Backspace" || ev.key === "Delete") && RV.draft.length) { RV.draft.pop(); this.drawDraft(); }
    else if (ev.key === "Enter") finishDraft(this.msg);
    else if (ev.key === "+" || ev.key === "=") this.zoomBy(1.5);
    else if (ev.key === "-") this.zoomBy(1 / 1.5);
    else if (ev.key === "0") this.fit();
    else return;
    ev.preventDefault();
  }
  drawDraft(cursor) {
    let g = this.overlay.querySelector("#bp-draft");
    if (g) g.remove();
    const ring = this.snapped && cursor ? svg("polyline", { points: this.snapped + " " + this.snapped, class: "bp-snap" }) : null;
    if (!RV.draft.length) {
      draftReadout("");
      if (ring) { g = svg("g", { id: "bp-draft" }); g.append(ring); this.overlay.append(g); }
      return;
    }
    g = svg("g", { id: "bp-draft" });
    if (ring) g.append(ring);
    const tool = RV.draftTool || RV.tool;
    const pts = cursor ? RV.draft.concat([cursor]) : RV.draft.slice();
    const shape = draftShape(pts);
    if (shape.type === "point") {
      for (const p of shape.points) g.append(svg("polyline", { points: p + " " + p, class: "bp-dot draft" }));
    } else {
      g.append(svg(shape.type === "polygon" ? "polygon" : "polyline", { points: shape.points.map(p => p.join(",")).join(" "), class: "bp-draft-shape" }));
      for (const p of RV.draft) g.append(svg("polyline", { points: p + " " + p, class: "bp-dot draft" }));
    }
    this.overlay.append(g);
    draftReadout(previewText(shape));
  }
}

function round3(v) { return Math.round(v * 1000) / 1000; }

// Rotate a point (x, y) by deg degrees around the origin; rotBox does the same
// for a box and returns its bounding box. The viewer rotates the whole sheet
// about its top-left corner, so every screen<->sheet conversion goes through these.
function rotXY(x, y, deg) {
  const a = deg * Math.PI / 180, c = Math.cos(a), s = Math.sin(a);
  return [x * c - y * s, x * s + y * c];
}
function rotBox(x0, y0, x1, y1, deg) {
  const ps = [rotXY(x0, y0, deg), rotXY(x1, y0, deg), rotXY(x0, y1, deg), rotXY(x1, y1, deg)];
  return [Math.min(...ps.map(p => p[0])), Math.min(...ps.map(p => p[1])),
          Math.max(...ps.map(p => p[0])), Math.max(...ps.map(p => p[1]))];
}

// The nearest corner of something drawn on the sheet (shown layers only) or of the shape being drawn, within tol.
// With `along` (Shift held), only corners in line with that point count, so the segment stays straight.
function snapPoint(p, tol, along) {
  const hidden = new Set(layerPrefs().hidden);
  let best = null, bestD = tol;
  const consider = q => {
    if (along && Math.abs(q[0] - along[0]) > 1e-9 && Math.abs(q[1] - along[1]) > 1e-9) return;
    const dd = Math.hypot(q[0] - p[0], q[1] - p[1]);
    if (dd < bestD) { bestD = dd; best = [q[0], q[1]]; }
  };
  for (const o of RV.objects) {
    if (!o.geometry || hidden.has(o.group)) continue;
    const pts = o.geometry.points;
    const b = o._box || (o._box = [Math.min(...pts.map(v => v[0])), Math.min(...pts.map(v => v[1])),
                                    Math.max(...pts.map(v => v[0])), Math.max(...pts.map(v => v[1]))]);
    if (p[0] < b[0] - tol || p[0] > b[2] + tol || p[1] < b[1] - tol || p[1] > b[3] + tol) continue;
    for (const q of pts) consider(q);
  }
  for (const q of RV.draft.slice(0, -1)) consider(q);
  if (RV.draft.length > 2 && (RV.draftTool || RV.tool) === "area") consider(RV.draft[0]);
  return best;
}

// The tile comes through the API with the same sign-in (cookie, or the Jobs app's token - then fetched as a blob).
async function tileUrl(sheetId, level, x, y) {
  const path = API + "/sheets/" + sheetId + "/tiles/" + level + "/" + x + "/" + y + ".png";
  if (!APP_TOKEN) return path;
  const r = await fetch(path, { credentials: "same-origin", headers: { Authorization: "Bearer " + APP_TOKEN } });
  if (!r.ok) throw new Error("tile " + r.status);
  return URL.createObjectURL(await r.blob());
}

// ------------------------------------------------------------------ overlays
function groupInfo(id) { return RV.groups.find(g => g.id === id) || { id, label: words(id), color: "#868e96" }; }

function drawOverlay(root) {
  root.replaceChildren();
  const prefs = layerPrefs();
  const byGroup = new Map();
  for (const g of RV.groups) {
    const node = svg("g", { "data-group": g.id, class: "bp-group" });
    node.style.setProperty("--c", g.color);
    node.classList.toggle("hidden", prefs.hidden.includes(g.id));
    node.classList.toggle("locked", prefs.locked.includes(g.id));
    byGroup.set(g.id, node);
  }
  const order = ["floor_plan", "rooms", "walls", "doors_windows", "furniture", "plumbing", "circuits", "electrical",
                 "mechanical", "symbols", "dimensions", "text"];
  for (const o of RV.objects) {
    const g = byGroup.get(o.group);
    if (!g || !o.geometry) continue;
    const n = objectShape(o);
    if (n) g.append(n);
  }
  for (const id of order) if (byGroup.has(id)) root.append(byGroup.get(id));
  const meas = byGroup.get("measurements") || svg("g", { "data-group": "measurements", class: "bp-group" });
  meas.id = "bp-measurements";
  root.append(meas);
  drawMeasurements();
}

function objectShape(o) {
  const g = o.geometry, pts = g.points.map(p => p.join(",")).join(" ");
  let n;
  // A dimension with no dimension line is measurement-shaped text (often in the spec
  // notes) with no scale information; the text itself is visible in the sheet image,
  // so don't draw it as a dot. Line dimensions still render below.
  if (o.kind === "dimension" && g.type === "point") return null;
  if (g.type === "point" || o.kind === "symbol" && g.points.length === 1) {
    n = svg("polyline", { points: g.points[0] + " " + g.points[0], class: "bp-dot" });
  } else if (g.type === "polygon") {
    n = svg("polygon", { points: pts, class: "bp-shape " + (o.kind === "room" ? "room" : "") });
  } else {
    n = svg("polyline", { points: pts, class: "bp-shape line " + (o.kind === "wall" ? "wall" : "") });
  }
  n.setAttribute("data-oid", o.id);
  const t = svg("title", {});
  t.textContent = objectLabel(o);
  n.append(t);
  if (o.kind === "room" && g.type === "polygon") {
    const wrap = svg("g", { "data-room": o.id });
    const [cx, cy] = centroid(g.points);
    const lbl = svg("text", { x: cx, y: cy, class: "bp-room-label", "text-anchor": "middle" });
    lbl.textContent = (o.label || "Room") + (o.real_units && o.real_units.area_sqft ? " · " + num(o.real_units.area_sqft, 0) + " sq ft" : "");
    wrap.append(n, lbl);
    return wrap;
  }
  return n;
}

function objectLabel(o) {
  const real = o.real_units || {};
  const size = real.area_sqft ? num(real.area_sqft) + " sq ft" : real.length_ft ? num(real.length_ft) + " ft" : o.not_measured ? "not measured: " + o.not_measured : "";
  return [words(o.kind), o.label, o.tag, o.block_name, size, o.layer ? "layer " + o.layer : ""].filter(Boolean).join(" · ");
}

function centroid(pts) {
  let a = 0, cx = 0, cy = 0;
  for (let i = 0; i < pts.length; i++) {
    const [x0, y0] = pts[i], [x1, y1] = pts[(i + 1) % pts.length];
    const f = x0 * y1 - x1 * y0;
    a += f; cx += (x0 + x1) * f; cy += (y0 + y1) * f;
  }
  if (Math.abs(a) < 1e-9) return [pts[0][0], pts[0][1]];
  return [cx / (3 * a), cy / (3 * a)];
}

function sheetMeasurements() {
  return RV.data.takeoff.measurements.filter(m => m.sheet_id === RV.sheetId && m.status !== "rejected");
}

function drawMeasurements() {
  const g = $("bp-measurements");
  if (!g) return;
  g.replaceChildren();
  for (const o of g.ownerSVGElement.querySelectorAll("[data-oid].in-m, [data-oid].sel, [data-oid].legend-ref")) o.classList.remove("in-m", "sel", "legend-ref");
  const cur = currentMeasurement();
  const lineIds = new Set(RV.lineId ? lineMeasurements(RV.lineId).map(m => m.id) : []);
  for (const m of sheetMeasurements()) {
    const on = (cur && cur.id === m.id) || lineIds.has(m.id);
    const cls = "bp-m " + m.status + (on ? " sel" : "");
    if (m.geometry) {
      const gm = m.geometry, pts = gm.points.map(p => p.join(",")).join(" ");
      let n;
      if (gm.type === "point") {
        n = svg("g", { class: cls, "data-mid": m.id });
        for (const p of gm.points) n.append(svg("polyline", { points: p + " " + p, class: "bp-dot" }));
      } else {
        n = svg(gm.type === "polygon" ? "polygon" : "polyline", { points: pts, class: cls, "data-mid": m.id });
      }
      const t = svg("title", {}); t.textContent = measurementName(m) + " · " + num(m.qty) + " " + m.unit + " · " + words(m.status);
      n.append(t);
      g.append(n);
    }
    for (const id of m.source_object_ids) {
      const n = g.ownerSVGElement.querySelector('[data-oid="' + id + '"]');
      if (n) { n.classList.add("in-m"); if (on) n.classList.add("sel"); }
    }
  }
  for (const id of RV.selected) {
    const n = g.ownerSVGElement.querySelector('[data-oid="' + id + '"]');
    if (n) n.classList.add("sel");
  }
  // A set of symbols highlighted (count row / Symbols-tab type): the rest of the plan fades back (2026-11-19).
  const symIds = new Set((RV.symbolList || []).map(o => o.id));
  // ... and the legend's sample of the same symbol lights up blue, to compare them at a glance (2026-11-20, David).
  for (const o of legendRefs(RV.symbolList)) {
    const n = g.ownerSVGElement.querySelector('[data-oid="' + o.id + '"]');
    if (n) n.classList.add("legend-ref");
  }
  g.ownerSVGElement.classList.toggle("bp-focus", RV.selected.size > 0 && [...RV.selected].every(id => symIds.has(id)));
  drawHighlight(false);
  drawWiringRoutes();
}

// ------------------------------------------------------------------ selecting on the plan
function pickAt(target, shift, msg) {
  if (reviewPick(target)) return;          // a review card is open: symbol clicks change its count (2026-11-19)
  // 2026-11-20: a click on a wiring route shows only that circuit (again: all of them) - not the room under it.
  const wire = target.closest ? target.closest("#bp-wiring-routes [data-circuit]") : null;
  if (wire) { pickCircuit(wire.getAttribute("data-circuit")); return; }
  const mNode = target.closest ? target.closest("[data-mid]") : null;
  if (mNode) { showDetail(+mNode.getAttribute("data-mid"), msg, false); return; }
  const node = target.closest ? target.closest("[data-oid]") : null;
  if (!node) { if (!shift) { RV.selected.clear(); drawMeasurements(); selectionBox(msg); } return; }
  const id = +node.getAttribute("data-oid");
  if (!shift) {
    // Clicking something a measurement already uses opens that measurement.
    const m = sheetMeasurements().find(x => x.source_object_ids.includes(id));
    if (m && !RV.selected.size) { showDetail(m.id, msg, false); return; }
    RV.selected.clear();
  }
  if (RV.selected.has(id)) RV.selected.delete(id); else RV.selected.add(id);
  drawMeasurements();
  selectionBox(msg);
}

function selectionBox(msg) {
  const box = $("bp-selection");
  if (box) box.remove();
  if (!RV.selected.size) return;
  const objs = [...RV.selected].map(id => RV.byId.get(id)).filter(Boolean);
  const area = objs.reduce((a, o) => a + parseFloat((o.real_units || {}).area_sqft || 0), 0);
  const len = objs.reduce((a, o) => a + parseFloat((o.real_units || {}).length_ft || 0), 0);
  const unmeasured = objs.filter(o => !o.real_units).length;
  const lines = [objs.length + " selected: " + objs.slice(0, 4).map(objectLabel).join("; ") + (objs.length > 4 ? "; …" : "")];
  if (area) lines.push("Area " + num(area) + " sq ft");
  if (len) lines.push("Length " + num(len) + " ft");
  if (unmeasured) lines.push(unmeasured + " not measured (no scale)");
  const card = el("div", { class: "card section", id: "bp-selection" }, el("p", {}, lines.join(" · ")));
  if (RV.data.can_measure && !unmeasured) {
    const b = el("button", { class: "primary", type: "button", id: "bp-measure-selected" }, "Make a measurement from these…");
    b.addEventListener("click", () => saveForm(msg, { objectIds: objs.map(o => o.id), kind: area ? "area" : len ? "length" : "count",
      label: objs.length === 1 ? objs[0].label : "", room: roomFor(objs[0]) }));
    card.append(el("div", { class: "row" }, b));
  }
  $("bp-pane-list").prepend(card);
  showTab("list");
}

function roomFor(o) {
  if (!o || !o.geometry) return "";
  if (o.kind === "room") return o.label || "";
  const p = o.geometry.points[0];
  const room = RV.objects.find(r => r.kind === "room" && r.geometry && r.geometry.type === "polygon" && inside(p, r.geometry.points));
  return room ? room.label || "" : "";
}
function inside(p, poly) {
  let ins = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    if ((yi > p[1]) !== (yj > p[1]) && p[0] < (xj - xi) * (p[1] - yi) / (yj - yi) + xi) ins = !ins;
  }
  return ins;
}

// ------------------------------------------------------------------ drawing a measurement or calibrating
function addDraftPoint(p, msg) {
  if (RV.placing) { placeSectionAt(p); return; }     // 📍 the footer section's bottom outside corner (2026-11-16)
  const tool = RV.tool;
  if (!RV.draft.length) RV.draftTool = tool;   // the line keeps the tool it was started with
  const last = RV.draft[RV.draft.length - 1];
  if (last && Math.hypot(p[0] - last[0], p[1] - last[1]) < 3 / RV.viewer.z) return;   // a double-click's 2nd click
  if (tool === "area" && RV.draft.length >= 3) {
    const f = RV.draft[0], tol = 8 / RV.viewer.z;
    if (Math.hypot(p[0] - f[0], p[1] - f[1]) < tol) { finishDraft(msg); return; }
  }
  RV.draft.push(p);
  RV.viewer.drawDraft();
  if ((tool === "rect" || tool === "calibrate") && RV.draft.length === 2) finishDraft(msg);
}

function draftShape(pts) {
  const tool = RV.draftTool || RV.tool;
  if (tool === "rect" && pts.length >= 2) {
    const [a, b] = pts;
    return { type: "polygon", points: [[a[0], a[1]], [b[0], a[1]], [b[0], b[1]], [a[0], b[1]]] };
  }
  if (tool === "area" && pts.length >= 3) return { type: "polygon", points: pts };
  return { type: pts.length === 2 ? "line" : "polyline", points: pts };
}

function viewportAt(p) {
  const vps = RV.viewports;
  const hit = vps.filter(v => v.bbox && p[0] >= v.bbox[0] && p[0] <= v.bbox[2] && p[1] >= v.bbox[1] && p[1] <= v.bbox[3]);
  hit.sort((a, b) => (a.bbox[2] - a.bbox[0]) * (a.bbox[3] - a.bbox[1]) - (b.bbox[2] - b.bbox[0]) * (b.bbox[3] - b.bbox[1]));
  return hit[0] || vps.find(v => !v.bbox) || (vps.length === 1 ? vps[0] : null);
}

function feetPerUnit(v) {
  if (!v) return null;
  if (REAL_FT[RV.sheet.units]) return REAL_FT[RV.sheet.units];
  if (v.is_nts || !v.measurable || !parseFloat(v.scale_ratio)) return null;
  return parseFloat(v.scale_ratio) / 12;
}

function previewText(shape) {
  if ((RV.draftTool || RV.tool) === "calibrate") {
    if (shape.points.length < 2) return "";
    const [a, b] = shape.points;
    return num(Math.hypot(b[0] - a[0], b[1] - a[1]), 3) + (RV.sheet.units === "paper_in" ? "″ on the paper" : " " + RV.sheet.units);
  }
  const f = feetPerUnit(viewportAt(shape.points[0]));
  if (!f) return "this part of the sheet has no scale yet";
  if (shape.type === "polygon") {
    let a2 = 0;
    const p = shape.points;
    for (let i = 0; i < p.length; i++) { const [x0, y0] = p[i], [x1, y1] = p[(i + 1) % p.length]; a2 += x0 * y1 - x1 * y0; }
    if (RV.adjust && RV.adjust.target === "footer") return "≈ " + num(Math.abs(a2) / 2 * f * f * 144) + " sq in";   // a footer section is in sq in
    return "≈ " + num(Math.abs(a2) / 2 * f * f) + " sq ft";
  }
  let len = 0;
  for (let i = 1; i < shape.points.length; i++) len += Math.hypot(shape.points[i][0] - shape.points[i - 1][0], shape.points[i][1] - shape.points[i - 1][1]);
  return "≈ " + num(len * f) + " ft";
}

function draftReadout(text) {
  let r = $("bp-readout");
  if (!text) { if (r) r.remove(); return; }
  if (!r) {
    r = el("div", { class: "bp-readout", id: "bp-readout" });
    const fin = el("button", { class: "button", type: "button", id: "bp-finish" }, "Finish");
    fin.addEventListener("click", () => finishDraft($("review-message")));
    const undo = el("button", { class: "button", type: "button", id: "bp-undo" }, "Undo point");
    undo.addEventListener("click", () => { RV.draft.pop(); RV.viewer.drawDraft(); });
    r.append(el("span", { id: "bp-readout-text" }), fin, undo);
    $("bp-readout-slot").replaceChildren(r);
  }
  $("bp-readout-text").textContent = text;
}

function finishDraft(msg) {
  const tool = RV.draftTool || RV.tool;
  const need = { length: 2, area: 3, rect: 2, calibrate: 2 }[tool];
  if (!need || RV.draft.length < need) return;
  const shape = draftShape(RV.draft);
  RV.draft = []; RV.draftTool = null;
  RV.viewer.drawDraft();
  if (tool === "calibrate") { calibrateForm(msg, shape.points); return; }
  const vp = viewportAt(shape.points[0]);
  if (!vp) { msg.replaceChildren(el("p", { class: "error" }, "That isn't inside a view on this sheet.")); return; }
  if (RV.adjust && tool === "area") { adjustForm(msg, shape, vp); return; }   // the server checks the view's scale
  if (!feetPerUnit(vp)) {
    msg.replaceChildren(el("p", { class: "error", id: "bp-no-scale" }, (vp.is_nts ? "That view is marked not to scale (NTS)" : "That view has no scale yet") +
      " — set it with 📐 Calibrate (or on the Plans screen) first, then measure again."));
    return;
  }
  saveForm(msg, { geometry: shape, viewportId: vp.id, kind: { length: "length", area: "area", rect: "area" }[tool],
    room: roomFor({ kind: "point", geometry: { points: [shape.points[0]] } }) });
}

function calibrateForm(msg, points) {
  const vp = viewportAt(points[0]);
  if (RV.sheet.units !== "paper_in") { msg.replaceChildren(el("p", { class: "error" }, "This drawing is a CAD file at real size; it doesn't need a scale.")); return; }
  if (!vp) { msg.replaceChildren(el("p", { class: "error" }, "Calibrate inside a view on the sheet.")); return; }
  const dist = el("input", { id: "bp-cal-distance", maxlength: 30, placeholder: "12'-6\"", "aria-label": "Real distance" });
  const ok = el("button", { class: "primary", type: "button", id: "bp-cal-set" }, "Set the scale…");
  const paperIn = Math.hypot(points[1][0] - points[0][0], points[1][1] - points[0][1]);
  const out = el("div", { id: "bp-cal-confirm" });
  msg.replaceChildren(el("div", { class: "card section", id: "bp-cal-box" },
    el("p", {}, "The two points are " + paperIn.toFixed(2) + "″ apart on the paper, in " + (vp.label || "the view") + ". How long is that in real life?"),
    el("div", { class: "row" }, el("label", {}, "Real distance", dist), ok), out));
  dist.focus();
  ok.addEventListener("click", () => {
    if (!dist.value.trim()) { dist.focus(); return; }
    reviewAsk(out, ok, "/viewports/" + vp.id + "/scale", { calibration: { p1: points[0], p2: points[1], distance: dist.value.trim() } },
      x => "Calibrated: 1″ = " + x.viewport.scale_ratio + "″; " + x.measured + " object(s) re-measured.", "bp-cal", true);
  });
}

// The form for a new measurement: which trade and question it feeds, label, room, and approve now.
function saveForm(msg, what) {
  const d = RV.data;
  const trades = d.trades.concat(d.other_trades);
  if (!trades.length) { msg.replaceChildren(el("p", { class: "error" }, "No trade can take a measurement yet.")); return; }
  const trade = el("select", { id: "bp-trade", "aria-label": "Trade" },
    d.trades.length ? el("optgroup", { label: "On this project" }, d.trades.map(t => el("option", { value: t.module_id }, t.name))) : null,
    d.other_trades.length ? el("optgroup", { label: "Other trades" }, d.other_trades.map(t => el("option", { value: t.module_id }, t.name))) : null);
  const feeds = el("select", { id: "bp-feeds", "aria-label": "Question it answers" });
  const fillFeeds = () => {
    const t = trades.find(x => x.module_id === trade.value);
    feeds.replaceChildren(el("option", { value: "" }, "— not linked to a question —"),
      ...(t ? t.questions : []).map(q => el("option", { value: q.id }, q.label + (q.unit ? " (" + q.unit + ")" : ""))));
    // Match the whole unit (2026-11-13): /ft/ also matched "sqft", so a drawn length was pointed at an area question
    // and the server turned the save down ("a measurement in lf can't feed 'area_sqft'").
    const UNITS = { area: ["sqft", "sf", "sy"], length: ["lf", "ft", "feet"], perimeter: ["lf", "ft", "feet"], count: ["ea", "each", "count"] };
    const fits = UNITS[what.kind] || [];
    const guess = (t ? t.questions : []).find(q => fits.includes(String(q.unit || "").toLowerCase().trim()));
    if (guess) feeds.value = guess.id;
  };
  trade.addEventListener("change", fillFeeds);
  fillFeeds();
  const label = el("input", { id: "bp-label", maxlength: 200, value: what.label || "", placeholder: "e.g. Kitchen floor" });
  const room = el("input", { id: "bp-room", maxlength: 200, value: what.room || "", placeholder: "Room" });
  // From the drawing: any kind. A drawn closed shape: its area or its perimeter (e.g. baseboard round a room).
  const kinds = what.objectIds ? ["area", "perimeter", "length", "count"]
    : what.geometry && what.geometry.type === "polygon" ? ["area", "perimeter"] : null;
  const qtyIn = what.typed ? el("input", { id: "bp-typed-qty", inputmode: "decimal", maxlength: 20, "aria-label": "Quantity" }) : null;
  const unitIn = what.typed ? el("select", { id: "bp-typed-unit", "aria-label": "Unit" },
    [["sqft", "sq ft"], ["lf", "linear ft"], ["ea", "each"], ["sy", "sq yd"], ["cy", "cu yd"]].map(([v, l]) => el("option", { value: v }, l))) : null;
  const kind = kinds ? el("select", { id: "bp-kind", "aria-label": "Measure" }, kinds.map(k => el("option", { value: k, selected: k === what.kind }, words(k)))) : null;
  const each = what.objectIds && what.objectIds.length > 1 ? el("input", { type: "checkbox", id: "bp-each" }) : null;
  const approve = d.can_approve ? el("input", { type: "checkbox", id: "bp-approve" }) : null;
  const save = el("button", { class: "primary", type: "button", id: "bp-save" }, "Save…");
  const cancel = el("button", { class: "button", type: "button", id: "bp-save-cancel" }, "Cancel");
  const out = el("div", { id: "bp-save-confirm" });
  const card = el("div", { class: "card section", id: "bp-save-box" },
    el("p", {}, el("strong", {}, what.objectIds ? "Measure " + what.objectIds.length + " selected item(s)"
        : what.typed ? "Type a number in" : "New " + words(what.kind) + " measurement"),
      " — " + (what.geometry ? previewText(what.geometry) : what.typed ? "from a site visit, a schedule or the plans' own numbers" : "the size comes from the drawing")),
    el("div", { class: "form-grid" }, qtyIn ? el("label", {}, "Quantity", qtyIn) : null, unitIn ? el("label", {}, "Unit", unitIn) : null,
      el("label", {}, "Trade", trade), el("label", {}, "Answers", feeds),
      kind ? el("label", {}, "Measure", kind) : null, el("label", {}, "Label", label), el("label", {}, "Room", room),
      each ? el("label", { class: "check" }, each, " One measurement per item") : null,
      approve ? el("label", { class: "check" }, approve, " Approve it now (locks it)") : null),
    el("div", { class: "row" }, save, cancel), out);
  msg.replaceChildren(card);
  cancel.addEventListener("click", () => msg.replaceChildren(el("p", { class: "muted" }, "Cancelled — nothing saved.")));
  save.addEventListener("click", () => {
    const body = { module_id: trade.value, feeds: feeds.value || null, label: label.value.trim() || null, room: room.value.trim() || null,
                   approve: !!(approve && approve.checked) };
    if (what.objectIds) {
      Object.assign(body, { object_ids: what.objectIds, kind: kind.value, one_per_object: !!(each && each.checked) });
      reviewAsk(out, save, "/estimates/" + RV.estimateId + "/measurements/propose", body,
        x => x.count + " measurement(s) saved" + (x.approved ? " and approved" : " — waiting for approval"), "bp-save");
    } else if (what.typed) {
      if (!qtyIn.value.trim()) { qtyIn.focus(); return; }
      Object.assign(body, { qty: qtyIn.value.trim().replace(/,/g, ""), unit: unitIn.value });
      reviewAsk(out, save, "/estimates/" + RV.estimateId + "/measurements", body,
        x => "Saved " + num(x.measurement.qty) + " " + x.measurement.unit + (x.measurement.status === "approved" ? " (approved)" : " — waiting for approval"), "bp-save");
    } else {
      Object.assign(body, { geometry: what.geometry, viewport_id: what.viewportId, kind: kind ? kind.value : what.kind });
      reviewAsk(out, save, "/estimates/" + RV.estimateId + "/measurements", body,
        x => "Saved " + num(x.measurement.qty) + " " + x.measurement.unit + (x.measurement.status === "approved" ? " (approved)" : " — waiting for approval"), "bp-save");
    }
  });
  if (unitIn) {                                  // the question picked decides the unit unless the user changes it
    const syncUnit = () => {
      const t = trades.find(x => x.module_id === trade.value), qn = t && t.questions.find(x => x.id === feeds.value);
      if (qn && qn.unit && [...unitIn.options].some(o => o.value === qn.unit)) unitIn.value = qn.unit;
    };
    feeds.addEventListener("change", syncUnit);
    trade.addEventListener("change", syncUnit);
    syncUnit();
    qtyIn.focus();
  } else label.focus();
}

// Ask the server's question, then repeat with confirm=true. Unlike askThen, it keeps the viewer where it is and
// only reloads the measurements (or the sheet, after a new scale).
async function reviewAsk(msg, btn, path, body, doneText, prefix, reloadSheet, skipDetail) {
  btn.disabled = true;
  msg.replaceChildren();
  const done = async r => {
    toast(doneText(r));
    $("review-message").replaceChildren();
    RV.selected.clear();
    await refreshData();
    if (reloadSheet) await openSheet(RV.sheetId, $("review-message"));
    if (skipDetail) return;      // the caller stays where it is (the count table refreshes in place)
    // A new or changed measurement opens in the detail panel; after an approve (which returns only ids) the one
    // being looked at is shown again with its new state.
    const mid = r.measurement ? r.measurement.id : RV.measurementId;
    if (mid && RV.data.takeoff.measurements.some(m => m.id === mid)) showDetail(mid, $("review-message"), false);
  };
  try {
    const r = await api("POST", path, body);
    if (!r.needs_confirmation) { await done(r); return; }
    const yes = el("button", { class: "primary", type: "button", id: prefix + "-yes" }, "Yes");
    const no = el("button", { class: "button", type: "button", id: prefix + "-no" }, "Cancel");
    msg.replaceChildren(el("div", { class: "confirm", id: prefix + "-question" }, el("p", {}, el("strong", {}, r.question)), el("div", { class: "row" }, yes, no)));
    yes.focus();
    no.addEventListener("click", () => msg.replaceChildren(el("p", { class: "muted" }, "Cancelled — nothing changed.")));
    yes.addEventListener("click", async () => {
      yes.disabled = no.disabled = true;
      try { await done(await api("POST", path, { ...body, confirm: true })); }
      catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
    });
  } catch (e) {
    if (e.status !== 401) msg.replaceChildren(errorBox(e));
  } finally { btn.disabled = false; }
}

async function refreshData() {
  RV.data = await api("GET", "/estimates/" + RV.estimateId + "/takeoff");
  drawMeasurements();
  refreshList($("review-message"));
  drawLinesPanel();
}

// ------------------------------------------------------------------ Phase 1: Concrete agent auto-run
// The agent measures the slab on its own — first from the drawing's own lines (no LLM, no cost), and when
// no outline is found, from the AI reading the foundation sheet (LLM takeoff, only when the owner turned it
// on in 🤖 AI agents). The button starts a run (POST /auto-run), the page polls GET /auto-run/<id> every 2 s until the
// run is done, failed, or 10 minutes pass, and the agent's measurements land as proposals to review like any
// other. Its outline can be shown on the plan and changed to another candidate rectangle (POST retarget,
// ask-first like every other change). The backend owns the runs; this page only starts, watches and corrects
// them. Every call here fails soft: with no backend yet (or no candidates) the page just shows nothing extra.
const AUTO_POLL_MS = 2000;                  // poll the run every 2 s
const AUTO_TIMEOUT_MS = 10 * 60 * 1000;     // give up after 10 minutes with no news from the run
const AUTO_MAX_MS = 60 * 60 * 1000;         // and after an hour in all
const AGENT = "concrete-agent";             // proposed_by of the agent's measurements
const LLM_AGENT = "llm-takeoff";            // proposed_by of the LLM fallback's measurements
const AUTO = { runId: null, estimateId: null, sheetId: null, viewportId: null, timer: null, startedAt: 0,
               status: null, step: "", error: null, measurementIds: [], moduleId: null, pickedTrade: null,
               candidates: new Map(), candidatesLoading: new Set(), llmTakeoff: new Map(),
               source: "geometry" };

function hasConcreteTrade() { return !!(RV.data && RV.data.trades.some(t => t.module_id === "concrete")); }

// Every trade AI Auto Run can measure (2026-11-18): the 15 construction trades with an auto-run reader.
// Services trades never deal with plans, so they never appear here.
const AUTO_RUN_TRADES = ["concrete", "electrical", "plumbing", "hvac", "flooring", "roofing", "framing",
  "windows_doors", "insulation", "demolition", "drywall", "siding", "fencing", "landscaping", "painting"];
function autoRunTrades() {
  return ((RV.data && RV.data.trades) || []).filter(t => AUTO_RUN_TRADES.includes(t.module_id));
}

// Which trade AI Auto Run measures on this project (2026-11-18): all 15 construction trades run now.
// The open sheet's discipline picks when it matches a runnable trade — an electrical sheet means the
// electrical count — otherwise concrete wins (it was first), and a project with only one runnable trade
// runs that one.
function autoRunTrade() {
  const runnable = autoRunTrades().map(t => t.module_id);
  if (!runnable.length) return null;
  const d = RV.sheet && RV.sheet.discipline;
  if (d && runnable.includes(d)) return d;
  if (runnable.includes("concrete")) return "concrete";
  return runnable[0];
}

// The trade the run button will run: the user's picker choice when it is still on the project, otherwise
// the default above. The choice lives here so a status redraw never loses it.
function selectedAutoRunTrade() {
  const runnable = autoRunTrades().map(t => t.module_id);
  if (AUTO.pickedTrade && runnable.includes(AUTO.pickedTrade)) return AUTO.pickedTrade;
  return autoRunTrade();
}

// The button's hover text names the trade it will actually run — never one trade's description while
// running another. Concrete and electrical keep their exact wording from 2026-11-15 / 2026-11-18.
const AUTO_RUN_BLURBS = {
  // 2026-11-20 (David: the hover said nothing about wiring): Electrical's run also routes the wiring.
  concrete: "measure the concrete",
  electrical: "count the outlets, switches, lights and circuits, then route the wiring from the panel (cable sizes and " +
    "lengths — needs the floor plan as a DXF file; the panel drawing's schedule is used when there is one; ⚡ Run wiring does just the wiring)",
  plumbing: "count the fixtures", hvac: "read the conditioned area and count the registers, returns and thermostats",
  flooring: "read the floor areas and count the stairs and transitions", roofing: "read the roof area, edges and ridge",
  framing: "count the openings, trusses and corners and read the floor area", windows_doors: "count the windows and doors",
  insulation: "read the attic and wall insulation areas", demolition: "read the areas to demolish and count the fixtures",
  drywall: "read the ceiling area and the openings", siding: "read the wall areas and count the corners and openings",
  fencing: "read the fence length and count the gates", landscaping: "read the landscaped areas and count the shrubs, trees and zones",
  painting: "read the ceiling and exterior areas and count the doors" };
// 2026-11-21 (David): a hover card on 🤖 AI Auto Run and ⚡ Run wiring saying what each trade's run needs from the plans,
// with recommendations - focused on the trade the button will run. needs: what has to be there; tips: what makes it
// read well. Every trade's run also needs the sheet switched ON for the trade (Plans screen) and the AI turned on.
const AUTO_RUN_NEEDS = {
  concrete: { needs: ["The foundation / slab plan, switched on for Concrete", "The slab's overall dimensions written on the plan (e.g. 40'-0\" × 30'-0\")",
    "The footing detail or section with the footer size (e.g. 12\" × 20\") and the slab thickness"],
    tips: ["A CAD (DXF) file lets the drawing agent trace the slab outline itself", "Rebar sizes written on the detail (#4 @ 12\" O.C.) are read too",
      "Switch off sheets that aren't the foundation so the run doesn't pick the wrong one"] },
  electrical: { needs: ["The electrical floor plan (outlets, switches, lights), switched on for Electrical",
    "A legend for the symbols — it's how lights, fans and outlet types are told apart"],
    tips: ["Switch the panel drawing / wiring diagram OFF for Electrical — it's read by ⚡ Run wiring, not counted",
      "Room names on the plan (KITCHEN, BATH, GARAGE) put devices on the right circuits",
      "Upload as CAD (DXF) so ⚡ Run wiring can route the cable (a PDF is counted, but not wired)",
      "Label 240 V appliances (RANGE 50A, DRYER 30A) — each gets its own circuit"] },
  plumbing: { needs: ["The plumbing plan (or the floor plan with the fixtures drawn), switched on for Plumbing", "A fixture legend or schedule"],
    tips: ["A plumbing fixture schedule (P-1 WC, P-2 LAV…) makes the counts exact", "The water heater and hose bibbs drawn on the plan are counted too"] },
  hvac: { needs: ["The mechanical (HVAC) plan with supply registers, returns and thermostats, switched on for HVAC",
    "The conditioned floor area — written on the plan, or the floor plan's dimensions"],
    tips: ["Equipment labels (tonnage, AHU, condenser) help size the system", "A register / diffuser schedule makes the counts exact"] },
  flooring: { needs: ["The floor plan with room names and dimensions (or a finish schedule), switched on for Flooring"],
    tips: ["A room finish schedule (carpet / tile / LVP by room) lets each area get its own material", "Stairs and thresholds drawn on the plan are counted"] },
  roofing: { needs: ["The roof plan with its outline, pitch (e.g. 6/12) and ridge / hip / valley lines, switched on for Roofing"],
    tips: ["Written overall dimensions or a scale make the area exact", "Elevations help confirm the pitch when the roof plan doesn't say"] },
  framing: { needs: ["The floor plan with dimensions, door and window openings, switched on for Framing"],
    tips: ["A truss / joist layout sheet makes the truss count exact", "Wall height noted on the sections (8', 9') gives the stud length"] },
  windows_doors: { needs: ["The floor plan with door and window tags, switched on for Windows & Doors"],
    tips: ["Door and window schedules (sizes, types) make each item exact", "Elevations help when a window isn't tagged on the plan"] },
  insulation: { needs: ["The floor plan with dimensions (attic and wall areas), switched on for Insulation"],
    tips: ["Wall sections with R-values (R-13 walls, R-38 attic) set the material", "Ceiling heights on the sections give the wall area"] },
  demolition: { needs: ["The demolition plan (walls and fixtures to remove, usually dashed), switched on for Demolition"],
    tips: ["A demo legend or notes (REMOVE EXISTING…) make the scope clear", "Dimensions or a scale make the areas exact"] },
  drywall: { needs: ["The floor plan with room dimensions, door and window openings, switched on for Drywall"],
    tips: ["Ceiling heights on the sections or a room schedule give the wall area", "Wet areas marked (bath, laundry) get moisture-resistant board"] },
  siding: { needs: ["The exterior elevations (all four sides), switched on for Siding"],
    tips: ["Written heights and widths make the wall areas exact", "Material callouts (lap, board & batten) on the elevations set the siding type"] },
  fencing: { needs: ["The site plan with the fence line and gates, switched on for Fencing"],
    tips: ["Written lengths along the fence line (or a scale) make the footage exact", "A fence detail gives the height and type"] },
  landscaping: { needs: ["The landscape plan (planting areas, trees, shrubs, irrigation zones), switched on for Landscaping"],
    tips: ["A plant schedule with quantities makes the counts exact", "Sod / mulch areas outlined and labelled are measured separately"] },
  painting: { needs: ["The floor plan with dimensions and the exterior elevations, switched on for Painting"],
    tips: ["A room finish schedule says which walls and ceilings get paint", "Ceiling heights on the sections give the wall area"] } };
const WIRING_NEEDS = {
  needs: ["The electrical floor plan as a CAD (DXF) file — devices drawn as symbols (blocks), with the panel symbol drawn where the panel is",
    "Each floor's title on the plan (GROUND FLOOR, SECOND FLOOR) so runs between floors go up the riser"],
  tips: ["Upload the panel drawing (DXF with a panel schedule: CIRCUIT / DESCRIPTION / AMPS / POLES / WIRE) to use the designer's circuits and wire sizes",
    "No panel schedule? It lays the circuits out the usual residential way (lighting by floor, two kitchen counter circuits, each bath, laundry and garage on its own 20 A) — check them",
    "Room names and 240 V appliance labels (RANGE 50A, DRYER 30A) on the plan put devices on the right circuits",
    "Clicking ⚡ Run wiring opens the wiring options first: foundation (a basement house runs from the basement ceiling; nothing goes in a slab), outlets through the studs, ceiling height — save them as your defaults",
    "Plain geometry — no AI tokens, and your device counts aren't touched"] };

// The hover card itself: shows on hover and on keyboard focus, next to its button. content() is called each time it
// opens, so it always describes the trade the button will run right now.
function attachHoverCard(btn, id, content) {
  const card = el("div", { class: "hovercard", id, role: "tooltip" });
  const wrap = el("span", { class: "hovercard-wrap" });
  btn.removeAttribute("title");
  btn.setAttribute("aria-describedby", id);
  const fill = () => card.replaceChildren(...content());
  wrap.addEventListener("mouseenter", fill);
  wrap.addEventListener("focusin", fill);
  fill();
  wrap.append(btn, card);
  return wrap;
}

function needsCard(title, intro, warn, needs, tips) {
  return [el("strong", {}, title), warn ? el("p", { class: "hovercard-warn" }, "⚠ " + warn) : null,
    intro ? el("p", {}, intro) : null,
    el("div", { class: "hovercard-h" }, "What it needs"), el("ul", {}, needs.map(n => el("li", {}, n))),
    tips && tips.length ? el("div", { class: "hovercard-h" }, "For the best result") : null,
    tips && tips.length ? el("ul", {}, tips.map(n => el("li", {}, n))) : null].filter(Boolean);
}

function autoRunHelp() {
  const trade = AUTO.status === "running" && AUTO.moduleId ? AUTO.moduleId : selectedAutoRunTrade();
  if (!trade) return needsCard("🤖 AI Auto Run", null, "Add a construction trade to this project first.",
    ["A construction trade on the project (Concrete, Electrical, Roofing…)", "The plans uploaded and read on the project page"], []);
  const anyOn = ((RV.data && RV.data.sheets) || []).some(s => !(s.inactive_trades || []).includes(trade));
  const n = AUTO_RUN_NEEDS[trade] || { needs: ["The plan sheet for " + tradeName(trade) + ", switched on for it"], tips: [] };
  return needsCard("🤖 AI Auto Run — " + tradeName(trade),
    "It will " + (AUTO_RUN_BLURBS[trade] || "read the quantities") + ", then you review and approve what it proposes.",
    anyOn ? null : "Every sheet is switched off for " + tradeName(trade) + " — switch the right sheet on from the Plans screen.",
    n.needs.concat(["AI measuring turned on with an API key (AI-Prowler's 🏗 Estimator tab → 🤖 AI agents)"]), n.tips);
}

function wiringHelp() {
  return needsCard("⚡ Run wiring — Electrical",
    "Routes the cable from the panel to every device, sizes it, and proposes the cable lengths and breaker counts.",
    null, WIRING_NEEDS.needs, WIRING_NEEDS.tips);
}

function autoRunTitle(trade, anyOn) {
  if (!trade) return "Add a construction trade to this project first — AI Auto Run measures the quantities on the plans for that trade.";
  const name = tradeName(trade);
  if (!anyOn) return "Every sheet is switched off for " + name + " — switch the sheets on from the Plans screen.";
  return "AI Auto Run: " + (AUTO_RUN_BLURBS[trade] || "read the quantities") +
    " on the sheets switched on for " + name + ", then review what it proposes.";
}

// A sheet is "on" when it isn't switched off (Plans screen) for every trade this project measures (2026-11-15).
// With no trade to measure yet, every sheet counts as on.
function sheetOn(s) {
  const off = (s && s.inactive_trades) || [];
  const mine = ((RV.data && RV.data.trades) || []).map(t => t.module_id);
  return !mine.length || mine.some(t => !off.includes(t));
}

// The view the agent measures: the first scaled view on the sheet (a sheet's plan is usually one view; a
// second view is a detail or an elevation). Unscaled views can't be measured, so they don't count — unless
// the sheet has nothing scaled, in which case the first view is returned and the server says why it can't run.
function autoRunViewport() {
  const vps = RV.viewports || [];
  return vps.find(v => v.measurable && !v.is_nts) || vps.find(v => !v.is_nts) || vps[0] || null;
}

function ftIn(ft) {
  const v = parseFloat(ft);
  if (isNaN(v)) return "—";
  let feet = Math.floor(v), inches = Math.round((v - feet) * 12);
  if (inches === 12) { feet += 1; inches = 0; }
  return feet + "'-" + inches + '"';
}

function candidateLabel(c) {
  if (!c) return "—";
  const size = (c.width_ft !== undefined && c.width_ft !== null && c.height_ft !== undefined && c.height_ft !== null)
    ? ftIn(c.width_ft) + " × " + ftIn(c.height_ft) : null;
  const area = (c.area_sqft !== undefined && c.area_sqft !== null) ? num(c.area_sqft, 0) + " sq ft" : null;
  if (size && area) return size + " — " + area;
  if (size) return size;
  if (c.label) return c.label;
  return "outline " + (c.id || "");
}

function agentMeasurementsOnSheet() {
  if (!RV.data) return [];
  return RV.data.takeoff.measurements.filter(m => m.sheet_id === RV.sheetId
    && (m.proposed_by === AGENT || m.proposed_by === LLM_AGENT));
}

// What an agent measurement came from. The list doesn't carry the calc (see _out in takeoff/measurements.py),
// so a row can only say whose outline it is and how many drawing objects it uses; the detail panel, which has
// the calc, names the outline itself. If the list ever carries calc_json, the row uses it too.
function agentSourceText(m) {
  if (m.proposed_by === LLM_AGENT) return "🤖 read from the plan by the AI — check the dimensions before approving";
  let from = "from the agent's outline";
  try {
    const calc = m.calc_json ? (typeof m.calc_json === "string" ? JSON.parse(m.calc_json) : m.calc_json) : null;
    const list = calc && calc.candidate_id && AUTO.candidates.get(m.viewport_id);
    const c = list && list.find(x => x.id === calc.candidate_id);
    if (c) from = "from outline: " + candidateLabel(c);
  } catch (e) { /* the fallback stands */ }
  const n = (m.source_object_ids || []).length;
  return "🤖 " + from + (n ? " — " + n + " drawing object(s)" : "");
}

// Display words for a measurement's proposed_by: the stored ids stay as they are, the Detail
// table shows what a person would call them ("llm-takeoff" is the AI measuring; a typed or drawn
// measurement already carries the person's name).
const PROPOSED_BY_WORDS = { "llm-takeoff": "AI measuring", "concrete-agent": "Concrete agent" };
function proposedByWords(v) { return PROPOSED_BY_WORDS[v] || v || "—"; }

// Show exactly which lines the agent used: select its drawing objects and zoom to them. With no objects (the
// agent drew the outline itself) the zoom falls to the measurement's own shape — zoomToSelection already
// includes the current measurement's geometry.
async function showAgentOutline(m) {
  if (m.sheet_id && m.sheet_id !== RV.sheetId && $("review-sheet") && RV.data.sheets.some(s => s.id === m.sheet_id)) {
    $("review-sheet").value = m.sheet_id;
    await openSheet(m.sheet_id, $("review-message"));
  }
  RV.measurementId = m.id;
  RV.selected = new Set(m.source_object_ids || []);
  drawMeasurements();
  refreshList($("review-message"));
  if (RV.viewer) RV.viewer.zoomToSelection();
}

// The candidate slab rectangles for a view, cached per view (the status line and the retarget form share it).
// Throws when the call fails — the status line swallows that (nothing to show yet), the retarget form shows it.
async function getCandidates(vpId) {
  if (AUTO.candidates.has(vpId)) return AUTO.candidates.get(vpId);
  const r = await api("GET", "/viewports/" + vpId + "/slab-candidates");
  const list = r.candidates || [];
  AUTO.candidates.set(vpId, list);
  AUTO.llmTakeoff.set(vpId, r.llm_takeoff || null);
  return list;
}

// What the agent found on this sheet, before anyone runs it — loaded once per sheet, in the background, so
// opening a sheet never waits on it. A missing backend (or a sheet with no candidates) just leaves the line out.
// Slab outlines are concrete-only: an electrical run counts devices, it has no geometric candidates.
async function loadAutoCandidates() {
  if (selectedAutoRunTrade() !== "concrete" || !RV.data.can_measure) return;
  const vp = autoRunViewport();
  if (!vp || AUTO.candidates.has(vp.id) || AUTO.candidatesLoading.has(vp.id)) return;
  AUTO.candidatesLoading.add(vp.id);
  try { await getCandidates(vp.id); } catch (e) { /* no backend yet, or no outline — stay silent */ }
  AUTO.candidatesLoading.delete(vp.id);
  drawAutoRunStatus();
}

function rerunButton() {
  const b = el("button", { class: "button", type: "button", id: "bp-auto-rerun" }, "↻ Re-run agent");
  b.addEventListener("click", () => rerunAutoRun(b));
  return el("div", { class: "row" }, b);
}

// The status area under the message line: the run's progress or result, what the agent found on this sheet,
// and the re-run button. A run's progress shows on its own sheet — a run on another sheet keeps polling, and
// its result shows when that sheet is opened again (the toast on finish reaches the user wherever they are).
// It lives in its own slot, not #review-message: that line is wiped by every save and confirm flow.
function drawAutoRunStatus() {
  const slot = $("bp-auto-slot");
  if (!slot || !RV.data) return;
  const runBtn = $("bp-auto-run");
  // 2026-11-15 (David): AI Auto Run measures the sheets switched ON for the trade being run, whichever sheet is
  // open — so an open sheet that's switched off doesn't disable it; the run goes to the sheet that is on.
  // While a run works, the button names the trade that is running — the open sheet may have changed since it started.
  const trade = AUTO.status === "running" && AUTO.moduleId ? AUTO.moduleId : selectedAutoRunTrade();
  const offForTrade = trade && (RV.inactiveTrades || []).includes(trade);
  const anyOn = trade && ((RV.data && RV.data.sheets) || []).some(s => !(s.inactive_trades || []).includes(trade));
  if (runBtn) {
    runBtn.disabled = !trade || AUTO.status === "running" || !anyOn;
    runBtn.dataset.runs = autoRunTitle(trade, anyOn);         // what a click runs (the hover card says it in full)
    if (!runBtn.closest(".hovercard-wrap")) runBtn.title = runBtn.dataset.runs;
  }
  const picker = $("bp-auto-trade");
  if (picker) {
    if (!AUTO.pickedTrade) picker.value = trade || "";   // no pick yet: follow the sheet's discipline
    picker.disabled = AUTO.status === "running";
  }
  const runHere = !!(AUTO.status && AUTO.sheetId === RV.sheetId);
  const parts = [];
  if (offForTrade && trade) {
    const psId = RV.sheet && RV.sheet.plan_set_id;
    parts.push(el("p", { class: "note warn", id: "bp-auto-off" }, "This sheet is switched off for " + tradeName(trade) + " — AI Auto Run skips it" +
      (anyOn ? " and measures the sheets that are on. " : ". "),
      psId ? el("a", { href: "#/plan-sets/" + psId }, "Change which sheets are on (Plans screen)") : "Change which sheets are on on the Plans screen", "."));
  }
  if (runBtn) {
    // While a run works the button says so and can't be clicked again (2026-11-15, David almost clicked it twice).
    const busy = AUTO.status === "running";
    runBtn.textContent = busy ? "⏳ AI Auto Run working…" : "🤖 AI Auto Run";
    runBtn.classList.toggle("bp-auto-run-busy", busy);
    runBtn.setAttribute("aria-busy", busy ? "true" : "false");
  }
  if (AUTO.status === "running") {
    parts.push(autoRunningBanner());
  } else if (runHere && AUTO.status === "done") {
    const n = (AUTO.measurementIds || []).length;
    const src = AUTO.source === "llm" ? " read from the plan by the AI" : "";
    parts.push(el("p", { class: "note", id: "bp-auto-status", role: "status" }, n
      ? "AI Auto Run finished: " + n + " proposed measurement(s)" + src + " — review and approve them below."
      : "AI Auto Run finished: no measurements proposed on this sheet."));
    // The AI (API key) reads the dimensions written on the plan and the app does the maths: no scale, no
    // calibration - say so instead of naming a scale it never used (2026-11-13, David).
    if (AUTO.source === "llm") parts.push(el("p", { class: "muted small", id: "bp-auto-scale" },
      AUTO.moduleId === "electrical" ? "📐 The AI counted the devices on the plan; counts don't need the sheet's scale."
        : AUTO.moduleId === "concrete" ? "📐 The AI read the slab's written dimensions off the plan; the app worked out the quantities from them, so they don't depend on the sheet's scale."
        : "📐 The AI read the quantities off the plan; the app worked out the numbers from them, so they don't depend on the sheet's scale."));
    else if (AUTO.scale) parts.push(el("p", { class: "muted small", id: "bp-auto-scale" }, autoScaleText(AUTO.scale)));
    // The run calibrated the view itself, or found it couldn't (2026-11-13): say which, and what to do.
    const cal = AUTO.calibration && autoCalText(AUTO.calibration);
    if (cal) parts.push(el("p", { class: cal[0], id: "bp-auto-calibration-result", role: cal[0] === "error" ? "alert" : null },
      (AUTO.calibration.view || "the view") + ": " + cal[1]));
  } else if (runHere && AUTO.status === "failed") {
    parts.push(el("p", { class: "error", id: "bp-auto-status", role: "alert" },
      "AI Auto Run failed — " + (AUTO.error || "unknown error")));
  } else if (runHere && AUTO.status === "timeout") {
    parts.push(el("p", { class: "error", id: "bp-auto-status", role: "alert" },
      "AI Auto Run stopped answering (no news for 10 minutes) — try re-running it."));
  }
  const vp = autoRunViewport();
  if (vp && trade === "concrete" && AUTO.candidates.has(vp.id)) {
    const list = AUTO.candidates.get(vp.id);
    let text = "Agent found no slab outline on this sheet — measure it manually or re-run after the plan is processed.";
    const llm = AUTO.llmTakeoff.get(vp.id);
    if (!list.length && llm && llm.enabled) {
      text = llm.ready
        ? "Agent found no slab outline on this sheet — the AI will read the plan instead when you run it (AI measuring is on)."
        : "Agent found no slab outline on this sheet — AI measuring is on, but the AI isn't ready (no API key saved?) — check AI-Prowler's 🏗 Estimator tab → 🤖 AI agents.";
    }
    if (list.length) {
      const big = list.reduce((a, b) => parseFloat(b.area_sqft || 0) > parseFloat(a.area_sqft || 0) ? b : a, list[0]);
      text = "Agent found " + list.length + " possible slab outline(s) — the largest is " + candidateLabel(big) + ".";
    }
    // LLM takeoff off: the AI won't run at all — say so and point at the switch, instead of only
    // suggesting manual measuring (off is the default, so this is the line most people see). The switch is on the
    // desktop: AI-Prowler's 🏗 Estimator tab → 🤖 AI agents, with the other agents' settings (2026-11-13).
    if (!list.length && llm && !llm.enabled) {
      parts.push(el("p", { class: "muted small", id: "bp-auto-candidates" },
        "Agent found no slab outline on this sheet — the AI didn't run because AI measuring is off. ",
        "Turn it on in AI-Prowler's 🏗 Estimator tab → 🤖 AI agents (AI measuring → Suggest) to let the AI read the plan, or measure it manually."));
    } else {
      parts.push(el("p", { class: "muted small", id: "bp-auto-candidates" }, text));
    }
  }
  const agentHere = agentMeasurementsOnSheet().length > 0;
  const runKnownHere = !!(AUTO.runId && AUTO.sheetId === RV.sheetId);
  // AI Log: what the AI was given and what it returned for this run (nothing there means the AI never ran).
  if (runKnownHere) parts.push(el("p", { class: "muted small", id: "bp-auto-ai-log" },
    el("a", { href: "#/agents/ai-log?auto_run_id=" + AUTO.runId, target: "_blank", rel: "noopener", id: "bp-auto-ai-log",
      title: "Opens in a new tab — this screen stays where it is" },
      "📋 AI Log — what the AI was given and what it returned for this run ↗")));
  if (AUTO.status !== "running" && (runKnownHere || agentHere) && RV.data.can_measure) parts.push(rerunButton());
  slot.replaceChildren(...parts);
  drawStepsPanel();      // the calc lives in the Measure steps tab, beside the drawing
}

// "Please wait" while AI Auto Run works (2026-11-15, David): a spinner, the steps it goes through with the current one
// marked, and how long it has been going — so nobody clicks it twice. The run's own step names come from the server
// (llm_takeoff.run_llm_takeoff's on_step); an unknown step just shows as the current line.
// The steps differ by trade (2026-11-18): concrete calibrates and measures a slab, electrical counts devices,
// and the other trades share the default list — find the sheet, read it, work out the quantities.
const AUTO_STEPS_BY_TRADE = { concrete: [["starting", "Starting the run"], ["finding the foundation sheet", "Finding the foundation sheet (sheets switched on)"],
  ["calibrating the sheet", "Calibrating the slab view"], ["reading the plan with the AI", "Sending the sheet to the AI to read the dimensions"],
  ["reading the footer detail", "Reading the footer section detail (close-up)"],
  ["checking the reading against the plan", "The AI checks its footer reading against the plan"],
  ["calibrating the footer detail", "Calibrating the footer detail (it has its own scale)"],
  ["measuring", "Working out the measurements and the concrete volume"]],
  electrical: [["starting", "Starting the run"], ["finding the electrical sheet", "Finding the electrical sheet (sheets switched on)"],
  ["reading the plan with the AI", "Sending the sheet to the AI to count the devices"],
  ["counting the devices", "Working out the device counts"]],
  default: [["starting", "Starting the run"], ["finding the", "Finding the right sheet (sheets switched on)"],
  ["reading the plan with the AI", "Sending the sheet to the AI to read the quantities"],
  ["working out the quantities", "Working out the quantities"]] };
let autoTick = null;
function autoRunningBanner() {
  const steps = AUTO_STEPS_BY_TRADE[AUTO.moduleId] || AUTO_STEPS_BY_TRADE.default;
  const step = String(AUTO.step || "").toLowerCase().replace(/[.…]+$/, "");
  let at = steps.findIndex(([k]) => step.startsWith(k.toLowerCase()));
  if (at < 0) at = step && step !== "starting" ? -1 : 0;
  const secs = Math.max(0, Math.round((Date.now() - (AUTO.startedAt || Date.now())) / 1000));
  const items = steps.map(([, label], i) => el("li", { class: at < 0 ? "todo" : i < at ? "done" : i === at ? "now" : "todo" },
    (at >= 0 && i < at ? "✓ " : at === i ? "▶ " : "") + label));
  if (at < 0 && AUTO.step) items.push(el("li", { class: "now" }, "▶ " + AUTO.step));
  if (!autoTick) {
    autoTick = setInterval(() => {
      const e = $("bp-auto-elapsed");
      if (!e || AUTO.status !== "running") { clearInterval(autoTick); autoTick = null; return; }
      e.textContent = Math.round((Date.now() - AUTO.startedAt) / 1000) + " s";
    }, 1000);
  }
  return el("div", { class: "bp-running", id: "bp-auto-status", role: "status", "aria-live": "polite" },
    el("div", { class: "bp-spinner", "aria-hidden": "true" }),
    el("div", {},
      el("strong", {}, "🤖 AI Auto Run is working — please wait"),
      el("div", { class: "muted small" }, "This usually takes 1–2 minutes (a busy plan can take 10 or more). You don't need to click again; the results show here when it's done. ",
        "Running for ", el("span", { id: "bp-auto-elapsed" }, secs + " s"), "."),
      el("ol", { id: "bp-auto-steps" }, items),
      autoLiveLine(AUTO.live)));
}

// What the AI is doing right now, while its answer streams in (2026-11-21, David: "show only its latest sentence,
// trimmed, plus the progress counts ... for all trades"). The runner updates it every couple of seconds.
function autoLiveLine(live) {
  if (!live) return null;
  const k = n => n >= 1000 ? (Math.round(n / 100) / 10) + "k" : String(n || 0);
  const counts = [];
  if (live.thinking_chars) counts.push(k(live.thinking_chars) + " characters of thinking");
  if (live.answer_chars) counts.push(k(live.answer_chars) + " characters of the answer");
  const writing = live.phase === "writing";
  return el("div", { class: "bp-auto-live", id: "bp-auto-live" },
    el("div", { id: "bp-auto-live-text" }, writing
      ? "✍️ The AI is writing its answer" + (live.item ? " — latest: " + live.item : "")
      : "💭 " + (live.thought ? live.thought : "The AI is thinking it through…")),
    counts.length ? el("div", { class: "muted small", id: "bp-auto-live-counts" }, counts.join(" · ")) : null);
}

// The concrete calc, in the "Measure steps" tab (2026-11-18, David): the volume and every step of it, the
// footer's check and correction, and the areas added or taken away — beside the drawing, so clicking a step
// shows it on the plan without scrolling up and down. The measurements themselves are approved in the
// Measurements tab (the old results table above the drawing was removed 2026-11-18: it duplicated this tab).
function concreteStepsBox(c) {
  const parts = [];
  parts.push(el("div", { id: "bp-auto-volume" },
    el("p", {}, el("strong", {}, "Concrete volume: " + num(c.total_cuyd) + " cu yd"),
      " (" + num(c.with_waste_cuyd) + " cu yd with 5% waste) — slab " + num(c.slab_cuyd) + " + footer " + num(c.footer_cuyd) + " cu yd"),
    el("p", { class: "muted small" }, "How it was worked out — check any line by hand:"),
    slabFitNote(c),
    el("table", { class: "list", id: "bp-auto-formulas" },
      el("thead", {}, el("tr", {}, el("th", {}, "Step"), el("th", {}, "Formula"), el("th", {}, "Result"))),
      el("tbody", {}, (c.steps || []).map(s => stepRow(s, c)))),
    el("p", { class: "muted small" }, "1 cu yd = 27 cu ft. Thickness: " + num(c.thickness_in, 0) + " in (" + c.thickness_from + ").")));
  const chk = footerCheckBox(c);
  if (chk) parts.push(chk);
  if (RV.data && RV.data.can_measure && c.footer_section) parts.push(footerEditForm(c));
  const drawn = drawnAreasBox(c);
  if (drawn) parts.push(drawn);
  return parts;
}

// Which classified symbols each count question counts (the plan engine's symbol library,
// estimator/plan_engine/symbol_library.py FEEDS, inverted). Clicking a count row highlights
// those symbols on the drawing, the way the Symbols tab highlights a type. A question with no
// entry here has no symbols behind it — circuits are wires, not symbols, and windows/doors
// can't be told apart by size from the symbol alone — so its row isn't clickable. A sheet
// whose symbols are unclassified (item_type null or "unknown", e.g. the US plan's 'CE' blocks)
// matches nothing either: the click does nothing, quietly.
const COUNT_SYMBOLS = {
  electrical: {
    outlets: ["duplex_receptacle"],             // 2026-11-19: each outlet type is its own count
    usb_outlets: ["duplex_receptacle_usb"],
    quad_outlets: ["quad_receptacle"],
    floor_boxes: ["floor_box"],
    wp_outlets: ["duplex_receptacle_wp"],
    gfci: ["duplex_receptacle_gfci"],
    switches: ["switch"],                      // 2026-11-19: each switch type is its own count
    switches_3way: ["switch_3way"],
    switches_4way: ["switch_4way"],
    dimmers: ["switch_dimmer"],
    occupancy_switches: ["switch_occupancy"],
    lights: ["light_fixture"],                   // 2026-11-20: each light type is its own count
    recessed_lights: ["light_recessed"],
    wall_lights: ["light_wall"],
    pendant_lights: ["light_pendant"],
    undercabinet_lights: ["light_undercabinet"],
    exterior_lights: ["light_exterior"],
    exit_emergency_lights: ["exit_sign", "emergency_light"],
    fans: ["ceiling_fan"],
    exhaust_fans: ["exhaust_fan"],
    smoke_detectors: ["smoke_detector", "smoke_co_detector"],   // 2026-11-20: counted too
    main_panels: ["panel"],
    appliance_circuits: ["receptacle_240v", "receptacle_dedicated", "ev_charger"],
    range_receptacles: ["range_receptacle"],     // 2026-11-20: drawn on the revised plan, so they light up too
    dryer_receptacles: ["dryer_receptacle"],
    disconnects: ["disconnect"],
    low_voltage: ["data_outlet", "phone_outlet", "tv_outlet", "speaker"],
  },
  plumbing: {
    toilets: ["water_closet", "urinal"],
    sinks: ["lavatory", "sink"],
    kitchen_sinks: ["kitchen_sink", "bar_sink", "laundry_sink", "mop_sink"],
    showers: ["shower", "tub", "tub_shower"],
    dishwashers: ["dishwasher"],
    washers: ["washer_box"],
    hose_bibs: ["hose_bibb"],
  },
  hvac: {
    registers: ["supply_diffuser", "linear_diffuser", "floor_register"],
    returns: ["return_grille"],
    thermostats: ["thermostat"],
    zones: ["mini_split_head"],
  },
  landscaping: {
    trees: ["tree", "palm"],
    shrubs: ["shrub"],
    drip_zones: ["drip_valve"],
    sprinkler_zones: ["irrigation_valve"],
  },
};

// The classified symbols on this sheet behind a count question (module + feeds): the ones still
// counted (rejected ones are taken out), or all of them when every one was rejected — the same
// rule the Symbols tab uses. [] when the question has no mapping or the sheet has no such symbols.
function countSymbols(moduleId, feeds) {
  const types = (COUNT_SYMBOLS[moduleId] || {})[feeds];
  if (!types) return [];
  const want = new Set(types);
  const all = sheetSymbols().filter(o => want.has(symbolKey(o)));
  const counted = all.filter(o => o.symbol.status !== "rejected");
  const syms = counted.length ? counted : all;
  // 2026-11-19 (David): a 30 Amp circuit is often only a label on the plan ("RANGE 30A", "DRYER 30A", "AC 30A"),
  // with no symbol; those labels are what the AI counts, so the row highlights them.
  const rx = (COUNT_LABELS[moduleId] || {})[feeds];
  const labels = rx ? RV.objects.filter(o => !o.symbol && o.kind === "text" && rx.test(o.label || "")) : [];
  return syms.concat(labels);
}

// Count questions whose items can be plain text labels on the plan rather than symbols.
const COUNT_LABELS = {
  electrical: { appliance_circuits: /\b(?:30|40|50|60)\s?A(?:MP)?\b/i },
};

// Click a count row: highlight the symbols it counted on the drawing (click again to clear),
// like clicking a formula row. The row shows "on" while its symbols are highlighted.
function toggleCountHighlight(moduleId, feeds) {
  RV.review = null;                        // a To measure highlight replaces an open review card
  if (RV.countStep === feeds) {
    RV.countStep = null;
    RV.symbolType = null; RV.symbolList = []; RV.symbolPos = -1;
    RV.selected = new Set();
    rehideRevealed();
    drawMeasurements();
    drawSymbolsPanel($("review-message"));
    markCountRows();
    return;
  }
  const objs = countSymbols(moduleId, feeds);
  if (!objs.length) return;   // no classified symbols for it on this sheet — nothing to show
  highlightSymbols(objs, symbolKey(objs[0]));
  RV.countStep = feeds;
  markCountRows();
}

function markCountRows() {
  for (const tr of document.querySelectorAll("#bp-auto-count-table tr[data-feeds], #bp-auto-quantities-table tr[data-feeds], #bp-pane-guide li[data-feeds]"))
    tr.classList.toggle("on", !!RV.countStep && tr.dataset.feeds === RV.countStep);
}

// The measurement behind a count row: the proposed one feeding that question, or the approved
// one when it's already approved (a rejected one doesn't count). Null for a zero-count row —
// the run proposes no measurement for a count of 0.
function countMeasurement(moduleId, feeds) {
  const ms = RV.data.takeoff.measurements.filter(m => m.module_id === moduleId && m.feeds === feeds && m.status !== "rejected");
  return ms.find(m => m.status === "proposed") || ms[0] || null;
}

// The Count cell: an editable number input (a whole number, 0–1000 — the manifest's max for a
// count) so a wrong AI count is corrected by hand here. It shows the measurement's qty when one
// exists — a hand correction, which is what gets priced — else the run's count. Without the
// right to change a measurement, it's just the number.
function countInput(moduleId, x) {
  const m = countMeasurement(moduleId, x.feeds);
  const shown = m ? parseFloat(m.qty) : parseFloat(x.qty) || 0;
  if (!(RV.data.can_correct || RV.data.can_measure)) return num(shown, 0);
  const inp = el("input", { type: "number", class: "bp-count-in", min: "0", max: "1000", step: "1",
    value: String(shown), "data-feeds": x.feeds, "data-mid": m ? m.id : "",
    "aria-label": "Count for " + (x.label || words(x.feeds)),
    title: "Correct the count by hand (whole number, 0–1000)" });
  const commit = () => {
    const v = inp.value.trim() === "" ? NaN : Number(inp.value);
    if (!Number.isInteger(v) || v < 0 || v > 1000) {
      inp.value = String(shown);
      toast("A count is a whole number from 0 to 1000.");
      return;
    }
    if (v === shown) return;
    saveCount(moduleId, x, m, v, inp);
  };
  inp.addEventListener("change", commit);
  inp.addEventListener("click", ev => ev.stopPropagation());   // clicking to edit mustn't highlight the row
  inp.addEventListener("keydown", ev => {
    if (ev.key === "Enter" || ev.key === " ") ev.stopPropagation();   // the row's keys, not the input's
    if (ev.key === "Enter") { ev.preventDefault(); inp.blur(); }      // Enter commits, like leaving the box
  });
  return inp;
}

// Correct a count by hand: edit the measurement behind the row, or create one when the row had
// none (a zero count). Editing to 0 keeps the measurement at 0 — the server only refuses
// negatives, and 0 prices as nothing. Asks first, like every other change; the table, the guide
// badges and the Measurements list all refresh from the save (reviewAsk reloads the data).
function saveCount(moduleId, x, m, v, inp) {
  const msg = $("bp-count-message") || $("review-message");
  if (m) {
    reviewAsk(msg, inp, "/measurements/" + m.id + "/edit", { qty: String(v) },
      () => "Count corrected to " + v, "bp-count", false, true);
  } else {
    // A typed measurement, not the propose endpoint: propose measures drawing objects
    // (object_ids are required), and a zero-count row has no objects to measure.
    reviewAsk(msg, inp, "/estimates/" + RV.estimateId + "/measurements",
      { module_id: moduleId, feeds: x.feeds, qty: String(v), unit: "ea", kind: "count",
        label: x.label || words(x.feeds) },
      () => "Count saved: " + v, "bp-count", false, true);
  }
}

// The electrical counts, in the "Measure steps" tab (2026-11-18): one row per device the AI counted, with the
// evidence it counted from. Click a row to highlight the symbols it counted on the drawing (where the sheet's
// symbols are classified — see COUNT_SYMBOLS); the Count column is editable, so a wrong AI count is corrected
// by hand here instead of with the old Count tool.
function electricalStepsBox(c) {
  const rows = (c.counts || []).map(x => {
    const objs = countSymbols("electrical", x.feeds);
    const on = RV.countStep === x.feeds;
    const tr = el("tr", { "data-feeds": x.feeds,
        class: (objs.length ? "bp-step-link" : "") + (on ? " on" : ""),
        tabindex: objs.length ? "0" : null,
        title: objs.length ? "Show these on the drawing" : null },
      el("td", {}, objs.length ? el("span", { class: "bp-step-eye", "aria-hidden": "true" }, "🔍 ") : null, x.label || words(x.feeds)),
      el("td", { class: "num" }, countInput("electrical", x)),
      el("td", { class: "muted small" }, x.evidence || ""));
    if (objs.length) {
      const go = () => toggleCountHighlight("electrical", x.feeds);
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
    }
    return tr;
  });
  const parts = [el("div", { id: "bp-auto-counts" },
    el("p", {}, el("strong", {}, "Device counts")),
    el("table", { class: "list", id: "bp-auto-count-table" },
      el("thead", {}, el("tr", {}, el("th", {}, "Device"), el("th", {}, "Count"), el("th", {}, "Evidence"))),
      el("tbody", {}, rows)),
    el("div", { id: "bp-count-message", role: "status" }))];
  const conf = c.confidence;
  const confText = conf === undefined || conf === null || conf === "" ? ""
    : "Confidence: " + (typeof conf === "number" ? pct(conf) : conf) + ". ";
  if (confText || c.notes) parts.push(el("p", { class: "muted small" }, confText + (c.notes || "")));
  return parts;
}

// The quantity trades' results, in the "Measure steps" tab (2026-11-18): one generic table for all 13 —
// one row per quantity the AI read, with the amount, the unit, and the evidence it read it from. Counts,
// areas and lengths all come through the same shape (the run's results.quantities). A count row whose
// question has classified symbols behind it (plumbing fixtures, HVAC registers, landscape trees — see
// COUNT_SYMBOLS) clicks to highlight them on the drawing; areas and lengths have no symbols to show.
function quantitiesStepsBox(q) {
  const rows = (q.items || []).map(x => {
    const objs = countSymbols(AUTO.moduleId, x.feeds);
    const on = RV.countStep === x.feeds;
    const tr = el("tr", { "data-feeds": x.feeds,
        class: (objs.length ? "bp-step-link" : "") + (on ? " on" : ""),
        tabindex: objs.length ? "0" : null,
        title: objs.length ? "Show these on the drawing" : null },
      el("td", {}, objs.length ? el("span", { class: "bp-step-eye", "aria-hidden": "true" }, "🔍 ") : null, x.label || words(x.feeds)),
      el("td", { class: "num" }, num(x.qty, x.unit === "ea" ? 0 : 2) + (x.unit ? " " + x.unit : "")),
      el("td", { class: "muted small" }, x.evidence || ""));
    if (objs.length) {
      const go = () => toggleCountHighlight(AUTO.moduleId, x.feeds);
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
    }
    return tr;
  });
  const parts = [el("div", { id: "bp-auto-quantities" },
    el("p", {}, el("strong", {}, (q.label ? q.label + " quantities" : "Quantities"))),
    el("table", { class: "list", id: "bp-auto-quantities-table" },
      el("thead", {}, el("tr", {}, el("th", {}, "Quantity"), el("th", {}, "Amount"), el("th", {}, "Evidence"))),
      el("tbody", {}, rows)))];
  const conf = q.confidence;
  const confText = conf === undefined || conf === null || conf === "" ? ""
    : "Confidence: " + (typeof conf === "number" ? pct(conf) : conf) + ". ";
  if (confText || q.notes) parts.push(el("p", { class: "muted small" }, confText + (q.notes || "")));
  return parts;
}

// The "Measure steps" tab shows only when this sheet has a finished run with a concrete calc, electrical
// counts, or a quantity trade's quantities. For an electrical run it reads "AI Count steps" — the tab
// holds counts, not calc steps — and the label follows the run whenever the status redraws (a new run,
// or the trade picker moving). If the calc goes away while the tab is showing (a re-run started), fall
// back to Measurements so the user isn't left on a tab with no button.
function drawStepsPanel() {
  const pane = $("bp-pane-steps"), tab = $("bp-tab-steps");
  if (!pane || !tab) return;
  tab.textContent = AUTO.results && AUTO.results.electrical ? "AI Count steps" : "Measure steps";
  const show = !!(AUTO.status === "done" && AUTO.sheetId === RV.sheetId && AUTO.results
    && (AUTO.results.concrete || AUTO.results.electrical || AUTO.results.quantities));
  tab.hidden = !show;
  if (!show) {
    pane.replaceChildren();
    if (!pane.hidden) showTab("list");
    return;
  }
  pane.replaceChildren(...(AUTO.results.electrical ? electricalStepsBox(AUTO.results.electrical)
    : AUTO.results.quantities ? quantitiesStepsBox(AUTO.results.quantities)
    : concreteStepsBox(AUTO.results.concrete)));
  markCountRows();
}

// The AI's own check of its footer reading against the plan (2026-11-15, David: "is it possible that some AI checking
// itself against the plans"): agrees, or each item it disagrees on with what the drawing shows - never settled silently.
function footerCheckBox(c) {
  const k = c.footer_check;
  if (c.footer_error) {
    return el("p", { class: "note warn", id: "bp-footer-check" }, "⚠ The AI couldn't read the footer detail (" + c.footer_error +
      ") — the footer below uses the plan's footer size note. Check it against the detail and correct it below.");
  }
  if (!k) return null;
  const bad = (k.checks || []).filter(x => !x.agrees);
  if (k.overall === "agrees" && !bad.length) {
    return el("p", { class: "ok", id: "bp-footer-check" }, "🔎 The AI checked its footer reading against the plan: every value agrees (" +
      (k.checks || []).length + " checked).");
  }
  if (k.overall === "not checked") {
    return el("p", { class: "note warn", id: "bp-footer-check" }, "⚠ The footer reading wasn't checked" + (k.notes ? " (" + k.notes + ")" : "") +
      " — check it against the detail before approving.");
  }
  return el("div", { class: "note warn", id: "bp-footer-check" },
    el("strong", {}, "⚠ The AI's check disagrees with its own footer reading — confirm these against the detail:"),
    el("ul", {}, bad.map(x => el("li", { "data-item": x.item }, words(x.item) + ": read " + (x.read || "—") + ", the drawing shows " +
      (x.drawing_shows || "—") + (x.why ? " (" + x.why + ")" : "")))));
}

// Correct the footer section by hand (inches); the footer length, cross-section and volume are worked out again, and
// the Concrete price uses them once approved. Asks first, like every other change.
const FOOTER_FIELDS = [["outside_in", "Outside face height", "top of slab to bottom of footer"], ["slab_in", "Slab thickness", ""],
  ["width_in", "Footer width", "bottom width"], ["ledge_w_in", "Ledge width", "notch at the top outside corner"],
  ["ledge_d_in", "Ledge depth", ""], ["haunch_w_in", "Haunch width", "sloped inside face, if dimensioned"], ["haunch_h_in", "Haunch height", ""]];
function footerEditForm(c) {
  const sec = c.footer_section || {}, from = c.footer_from || {};
  const inputs = {};
  const rows = FOOTER_FIELDS.map(([k, label, hint]) => {
    inputs[k] = el("input", { type: "number", step: "0.25", min: "0", id: "bp-footer-" + k, value: sec[k] === null || sec[k] === undefined ? "" : sec[k],
      "aria-label": label + " (in)", class: "bp-footer-in" });     // a class, not style= (the CSP blocks inline styles)
    return el("tr", {}, el("td", {}, label, hint ? el("div", { class: "muted small" }, hint) : null),
      el("td", {}, inputs[k], " in"), el("td", { class: "muted small" }, from[k] || (sec[k] ? "" : "none")));
  });
  const out = el("div", { id: "bp-footer-message", role: "status" });
  const save = el("button", { class: "button", type: "button", id: "bp-footer-save" }, "Recalculate the footer…");
  save.addEventListener("click", () => {
    const section = {};
    for (const [k] of FOOTER_FIELDS) {                     // only what was changed: the rest keeps where it came from
      const was = sec[k] === null || sec[k] === undefined ? "" : String(sec[k]);
      if (inputs[k].value !== was) section[k] = inputs[k].value === "" ? 0 : +inputs[k].value;
    }
    if (!Object.keys(section).length) { out.replaceChildren(el("p", { class: "muted" }, "Nothing changed.")); return; }
    reviewAsk(out, save, "/auto-run/" + AUTO.runId + "/footer", { section }, r => {
      if (r.results) { AUTO.results = r.results; setTimeout(drawAutoRunStatus, 0); }
      return "Footer recalculated: " + (r.results && r.results.concrete ? r.results.concrete.footer_cuyd + " cu yd" : "done");
    }, "bp-footer");
  });
  return el("details", { class: "card section", id: "bp-footer-edit" },
    el("summary", {}, "✏️ Footer section — check or correct it (below the slab: " + (c.footer_below_slab_in || "?") + " in, " +
      (c.footer_section_sqin || "?") + " sq in)"),
    el("p", { class: "muted small" }, "In inches, as on the footer detail. Where each number came from is on the right."),
    el("table", { class: "list" }, el("tbody", {}, rows)), el("div", { class: "row" }, save), out);
}

// ------------------------------------------------------------------ formulas <-> the drawing (2026-11-16, David)
// "When you click on the equations to compute the volume ... it would select it and highlight the area in the drawing
// so that the user could visually inspect the area." Each formula row lists the shapes it measured (the server places
// the slab on the plan's drawn edges at the calibrated scale; the footer is a band inside it; the cross-section is the
// footer detail). Click a row: the drawing goes there and outlines them in red. Click it again to clear.
function stepRow(s, c) {
  const keys = (s.shapes || []).filter(k => c.shapes && c.shapes[k]);
  const on = RV.highlight && RV.highlight.step === s.what;
  const tr = el("tr", { class: (/^(Total|Order)/.test(s.what) ? "total" : "") + (keys.length ? " bp-step-link" : "") + (on ? " on" : ""),
      "data-step": s.what, tabindex: keys.length ? "0" : null, title: keys.length ? "Show this on the drawing" : null },
    el("td", {}, keys.length ? el("span", { class: "bp-step-eye", "aria-hidden": "true" }, "🔍 ") : null, s.what,
      s.note ? el("div", { class: "muted small" }, s.note) : null),
    el("td", { class: "formula" }, s.formula),
    el("td", { class: "num" }, "= " + s.result));
  if (keys.length) {
    const go = () => toggleHighlight(s.what, keys, c.shapes);
    tr.addEventListener("click", go);
    tr.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
  }
  return tr;
}

function slabFitNote(c) {
  const f = c.slab_fit;
  if (f && f.ok) return el("p", { class: "muted small", id: "bp-slab-fit" },
    "🔍 Click a step to see it on the drawing. The slab is placed on the plan's own lines (" + f.cover_pct + "% of its outline lies on drawn edges).");
  if (f && f.reason) return el("p", { class: "note warn", id: "bp-slab-fit" },
    "⚠ The slab couldn't be outlined on the drawing: " + f.reason + ". The numbers don't depend on it — measure the outline with ▭ Area to check it.");
  return null;
}

async function toggleHighlight(what, keys, all) {
  if (RV.highlight && RV.highlight.step === what) { RV.highlight = null; drawHighlight(false); markStepRows(); return; }
  const shapes = keys.map(k => all[k]).filter(s => s && (s.points || []).length);
  if (!shapes.length) return;
  RV.highlight = { step: what, shapes };
  markStepRows();
  const sid = shapes[0].sheet_id;
  if (sid && sid !== RV.sheetId) {
    if ($("review-sheet")) $("review-sheet").value = String(sid);
    await openSheet(sid, $("review-message"));
  }
  drawHighlight(true);
}

function markStepRows() {
  for (const tr of document.querySelectorAll("#bp-auto-formulas tr[data-step]"))
    tr.classList.toggle("on", !!RV.highlight && tr.dataset.step === RV.highlight.step);
}

function drawHighlight(zoom) {
  if (!RV.viewer || !RV.viewer.overlay) return;
  const old = RV.viewer.overlay.querySelector("#bp-hl");
  if (old) old.remove();
  const h = RV.highlight;
  if (!h) return;
  const mine = h.shapes.filter(s => !s.sheet_id || s.sheet_id === RV.sheetId);
  if (!mine.length) return;
  const g = svg("g", { id: "bp-hl" });
  for (const s of mine) {
    const cls = "bp-hl" + (s.part === "slab" ? " inslab" : s.sign === -1 ? " minus" : s.sign === 1 ? " plus" : "");
    g.append(svg(s.type === "polygon" ? "polygon" : "polyline", { points: s.points.map(p => p.join(",")).join(" "), class: cls,
      "data-part": s.part || null }));
  }
  for (const s of mine.filter(x => x.label)) {          // the footer section's parts say what they are (2026-11-16)
    const xs = s.points.map(p => p[0]), ys = s.points.map(p => p[1]);
    const bw = Math.max(...xs) - Math.min(...xs), bh = Math.max(...ys) - Math.min(...ys);
    const t = svg("text", { x: (Math.max(...xs) + Math.min(...xs)) / 2, y: (Math.max(...ys) + Math.min(...ys)) / 2,
      "font-size": Math.max(0.03, Math.min(bw / Math.max(6, s.label.length * 0.6), bh * 0.45)), class: "bp-hl-label" + (s.part === "slab" ? " inslab" : s.sign === -1 ? " minus" : s.sign === 1 ? " plus" : "") });
    t.textContent = s.label;
    g.append(t);
  }
  RV.viewer.overlay.append(g);
  if (zoom) {
    const pts = mine.flatMap(s => s.points), xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
    RV.viewer.zoomToBox([Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)]);
  }
}

// ------------------------------------------------------------------ areas a person adds or takes away (2026-11-16)
// "I want the user to be able to add area to be included in the calculation, for example the sloped edge ... by adding
// three points and assuming to scale drawing" — and to take away an area the AI counted that shouldn't be. Click the
// corners on the drawing (3 or more), Finish; the server works out the real area from the view's scale (a footer
// detail has its own scale: AI Auto Run calibrates it; else 🤖 Auto-calibrate / 📏 Calibrate it), asks, and the
// formulas above change.
const ADJUST_WHAT = { footer: "the footer cross-section", slab: "the slab area" };
function drawnAreasBox(c) {
  const can = RV.data && RV.data.can_measure;
  const list = c.drawn_areas || [];
  if (!can && !list.length) return null;
  const out = el("div", { id: "bp-adjust-message", role: "status" });
  const rows = list.map(a => {
    const show = el("button", { class: "button", type: "button", "data-show": a.id, title: "Show it on the drawing" }, "🔍");
    show.addEventListener("click", () => toggleHighlight("area " + a.id, [a.key], c.shapes));
    const rm = can ? el("button", { class: "button", type: "button", "data-remove": a.id }, "✖ Remove…") : null;
    if (rm) rm.addEventListener("click", () => reviewAsk(out, rm, "/auto-run/" + AUTO.runId + "/adjust", { remove: a.id }, r => {
      if (r.results) { AUTO.results = r.results; setTimeout(drawAutoRunStatus, 0); }
      return "Removed " + a.amount + " (" + a.label + ")";
    }, "bp-adjust"));
    return el("tr", { "data-area": a.id },
      el("td", {}, (a.sign > 0 ? "➕ " : "➖ ") + a.label, el("div", { class: "muted small" }, (a.sign > 0 ? "added to " : "taken from ") + ADJUST_WHAT[a.target] +
        (a.view ? " · drawn on " + a.view : ""))),
      el("td", { class: "num" }, (a.sign > 0 ? "+ " : "− ") + a.amount), el("td", {}, show, " ", rm));
  });
  const btn = (id, text, target, sign, title) => {
    const b = el("button", { class: "button", type: "button", id, title }, text);
    b.addEventListener("click", () => startAdjust(target, sign, c));
    return b;
  };
  const noScale = sectionPlaceBox(c);
  return el("div", { class: "card section", id: "bp-adjust" },
    el("strong", {}, "✏️ Add or take away an area"),
    el("p", { class: "muted small" }, "Something the AI left out (a sloped edge with no dimension) or counted that it shouldn't? " +
      "Click its corners on the drawing — 3 or more points, then Finish (or click the first point again). The drawing's scale gives the real size."),
    can ? el("div", { class: "row" },
      btn("bp-adjust-footer-add", "➕ Add to the footer section", "footer", 1, "Draw it on the footer detail"),
      btn("bp-adjust-footer-sub", "➖ Take from the footer section", "footer", -1, "Draw it on the footer detail"),
      btn("bp-adjust-slab-add", "➕ Add slab area", "slab", 1, "Draw it on the foundation plan"),
      btn("bp-adjust-slab-sub", "➖ Take away slab area", "slab", -1, "Draw it on the foundation plan")) : null,
    noScale,
    list.length ? el("table", { class: "list", id: "bp-adjust-list" }, el("tbody", {}, rows)) : null,
    out);
}

// The footer section on its detail (2026-11-16, David: "put a red box around the cross section that the area
// calculations are made from ... the user needs to see the area parts"). The detail needs its own scale (it is drawn
// bigger than the plan); then one click on the footer's bottom outside corner places the parts — to scale — on it:
// the part below the slab (red, what the footer volume counts), the top that is already in the slab (grey), the ledge
// notch (orange), a dimensioned haunch (green). Parts that don't sit on the drawing show a number that is wrong.
function sectionPlaceBox(c) {
  const det = c.detail;
  if (!det || !(RV.data && RV.data.can_measure)) return null;
  if (!det.scaled) {
    const why = det.calibration && det.calibration.status === "manual_required" && det.calibration.reason
      ? " The automatic calibration couldn't do it: " + det.calibration.reason : "";
    const cal = el("button", { class: "button", type: "button", id: "bp-detail-calibrate" }, "📏 Calibrate the footer detail");
    cal.addEventListener("click", () => startDetailCalibrate(c));
    return el("div", { class: "note warn", id: "bp-detail-noscale" },
      el("p", {}, "The footer detail has no scale yet — it's drawn at its own (bigger) scale, so the plan's scale doesn't fit it." + why),
      el("p", {}, "Calibrate it by hand: click both ends of the 12\" dimension under the footer, then type 12\". After that the " +
        "section's parts can be shown on it, and areas drawn on it get their real size."),
      el("div", { class: "row" }, cal, " ", detailCalButton(det)));
  }
  const place = el("button", { class: "button", type: "button", id: "bp-section-place-btn" },
    det.placed ? "📍 Move the section" : "📍 Show the section's parts on the detail");
  place.addEventListener("click", () => startPlaceSection(c));
  const kids = [el("p", { class: "muted small" }, det.placed
      ? "The parts are drawn to the detail's scale (1″ = " + num(det.scale_ratio, 1) + "″) from the corner you clicked — " +
        "if they don't sit on the drawing, a number is off. Click 🔍 Footer cross-section above to see them."
      : "One click on the footer's bottom outside corner on the detail, and the parts the cross-section is worked out from " +
        "are drawn on it to scale."), highlightKey(), place];
  if (det.placed) {
    const flip = el("button", { class: "button", type: "button", id: "bp-section-flip" }, "⇄ The inside is the other way");
    flip.addEventListener("click", () => saveSectionPlace(c, det.anchor.viewport_id, det.anchor.point, -det.anchor.dir));
    kids.push(" ", flip);
  }
  return el("div", { id: "bp-section-place" }, ...kids);
}

// What the colours on the drawing mean (2026-11-16, David: a taken-away area looked red, not yellow).
function highlightKey() {
  return el("div", { class: "bp-hl-key", id: "bp-hl-key" },
    el("span", { class: "k-below" }, "counted (below the slab)"), el("span", { class: "k-slab" }, "already in the slab"),
    el("span", { class: "k-plus" }, "added"), el("span", { class: "k-minus" }, "taken away (ledge, drawn areas)"));
}

async function goToDetail(c) {
  const det = c.shapes && c.shapes.detail;
  if (!det) return;
  if (det.sheet_id && det.sheet_id !== RV.sheetId) {
    if ($("review-sheet")) $("review-sheet").value = String(det.sheet_id);
    await openSheet(det.sheet_id, $("review-message"));
  }
  RV.highlight = { step: "detail", shapes: [det] };
  markStepRows();
  drawHighlight(true);
}

async function startDetailCalibrate(c) {
  await goToDetail(c);
  RV.draft = []; RV.draftTool = null;
  setTool("calibrate", $("review-message"));
  if ($("bp-tool-help")) $("bp-tool-help").textContent = "Calibrate the footer detail: click both ends of the 12\" dimension " +
    "under the footer (zoom in for the exact ends), then type 12\". Esc cancels.";
  toast("📏 Click both ends of the 12\" dimension on the footer detail.");
}

async function startPlaceSection(c) {
  await goToDetail(c);
  RV.draft = []; RV.draftTool = null;
  // Any drawing tool works here: RV.placing intercepts the click before a draft starts
  // (addDraftPoint) — length is the plainest single-click tool. (Was the Count tool, removed 2026-11-18.)
  setTool("length", $("review-message"));
  RV.placing = { c };
  if ($("bp-tool-help")) $("bp-tool-help").textContent = "Click the footer's bottom outside corner on the detail — where the " +
    "outside face meets the bottom of the footer (it snaps to the drawing's corners; hold Alt to place it freely). Esc cancels.";
  toast("📍 Click the footer's bottom outside corner on the detail.");
}

function placeSectionAt(p) {
  const c = RV.placing.c;
  RV.placing = null;
  const vp = viewportAt(p);
  const det = c.detail;
  if (!vp || vp.id !== det.viewport_id) {
    $("review-message").replaceChildren(el("p", { class: "error", id: "bp-place-error" }, "That's not on the footer detail — click the corner inside the detail."));
    return;
  }
  // The inside of the footer is toward the middle of the detail (where the slab runs on); ⇄ flips it.
  const box = vp.bbox || [p[0] - 1, 0, p[0] + 1, 0];
  saveSectionPlace(c, vp.id, p, p[0] <= (box[0] + box[2]) / 2 ? 1 : -1);
}

async function saveSectionPlace(c, viewportId, point, dir) {
  try {
    const r = await api("POST", "/auto-run/" + AUTO.runId + "/section-place", { viewport_id: viewportId, point, dir });
    setTool("select", $("review-message"));
    if (r.results) { AUTO.results = r.results; drawAutoRunStatus(); }
    const step = r.results && r.results.concrete && r.results.concrete.steps.find(s => s.what === "Footer cross-section");
    if (step) { RV.highlight = null; toggleHighlight(step.what, step.shapes, r.results.concrete.shapes); }
    toast("📍 The footer section's parts are on the detail.");
  } catch (e) {
    if (e.status !== 401) $("review-message").replaceChildren(errorBox(e));
  }
}

function detailCalButton(det) {
  const vp = (RV.viewports || []).find(v => v.id === det.viewport_id);
  if (!vp || !(RV.data && RV.data.can_measure)) return el("span", {}, "Calibrate it with 📐 Calibrate on one of its written dimensions.");
  const b = el("button", { class: "button", type: "button", id: "bp-detail-autocal" }, "🤖 Auto-calibrate the footer detail");
  b.addEventListener("click", async () => {
    await runAutoCalibrate(vp, b, false);
    try {                                         // the run's results again: the detail now has a scale (or says why not)
      const r = await api("GET", "/auto-run/" + AUTO.runId);
      if (r.run && r.run.results) { AUTO.results = r.run.results; drawAutoRunStatus(); }
    } catch (e) { /* the results box keeps what it showed */ }
  });
  return b;
}

async function startAdjust(target, sign, c) {
  const where = target === "footer" ? c.shapes && c.shapes.detail : c.shapes && c.shapes.slab;
  if (where && where.sheet_id && where.sheet_id !== RV.sheetId) {
    if ($("review-sheet")) $("review-sheet").value = String(where.sheet_id);
    await openSheet(where.sheet_id, $("review-message"));
  }
  RV.highlight = where ? { step: "adjust", shapes: [where] } : null;
  drawHighlight(true);
  RV.draft = []; RV.draftTool = null;
  setTool("area", $("review-message"));
  RV.adjust = { target, sign };
  if ($("bp-tool-help")) $("bp-tool-help").textContent = "Click the corners of the area to " + (sign > 0 ? "add to " : "take from ") +
    ADJUST_WHAT[target] + (target === "footer" ? " on the footer detail" : " on the plan") + " — 3 or more points, then Finish. Esc cancels.";
  toast((sign > 0 ? "➕ " : "➖ ") + "Click the corners on the drawing, then Finish.");
}

function adjustForm(msg, shape, vp) {
  const a = RV.adjust;
  RV.adjust = null;
  const label = el("input", { id: "bp-adjust-label", maxlength: 60, placeholder: a.target === "footer" ? "sloped edge" : "porch", "aria-label": "What it is" });
  const save = el("button", { class: "primary", type: "button", id: "bp-adjust-save" }, (a.sign > 0 ? "Add" : "Take away") + " it…");
  const out = el("div", { id: "bp-adjust-confirm" });
  save.addEventListener("click", () => reviewAsk(out, save, "/auto-run/" + AUTO.runId + "/adjust",
    { target: a.target, sign: a.sign > 0 ? "add" : "subtract", viewport_id: vp.id, points: shape.points, label: label.value.trim() },
    r => {
      if (r.results) { AUTO.results = r.results; setTimeout(drawAutoRunStatus, 0); }
      RV.highlight = null; drawHighlight(false);
      return (a.sign > 0 ? "Added to " : "Taken from ") + ADJUST_WHAT[a.target];
    }, "bp-adjust"));
  msg.replaceChildren(el("div", { class: "card section", id: "bp-adjust-box" },
    el("p", {}, (a.sign > 0 ? "➕ Add" : "➖ Take away") + " this area " + (a.sign > 0 ? "to " : "from ") + ADJUST_WHAT[a.target] +
      " (" + shape.points.length + " points, in " + (vp.label || "the view") + "). What is it?"),
    el("div", { class: "row" }, el("label", {}, "What it is", label), save), out));
  label.focus();
}

// What ran on this sheet before: a run still going is watched again (with its "please wait"), a finished one shows its
// results — so a reload, or coming back to the sheet later, doesn't lose them (2026-11-15).
async function loadLatestRun() {
  if (!RV.data || !autoRunTrade() || (AUTO.status === "running")) return;
  if (AUTO.runId && AUTO.sheetId === RV.sheetId && AUTO.status) {
    // Same run: fetch its results again quietly — a new scale (the footer detail just calibrated) changes its shapes.
    if (AUTO.status === "done") {
      try {
        const x = await api("GET", "/auto-run/" + AUTO.runId);
        if (x.run && x.run.results && AUTO.status === "done") { AUTO.results = x.run.results; if (x.run.module_id) AUTO.moduleId = x.run.module_id; drawAutoRunStatus(); }
      } catch (e) { /* keep what is shown */ }
    }
    return;
  }
  let r;
  try { r = await api("GET", "/auto-run?estimate_id=" + RV.estimateId + "&sheet_id=" + RV.sheetId); }
  catch (e) { return; }
  const run = r && r.run;
  if (!run || AUTO.status === "running") return;
  if (run.status === "running") {
    AUTO.moduleId = run.module_id || null;
    trackAutoRun(run.id, null);
    AUTO.sheetId = run.sheet_id;
    const t = Date.parse(run.created_at);
    if (!isNaN(t)) AUTO.startedAt = Math.min(Date.now(), t);       // the elapsed time counts from the real start
    drawAutoRunStatus();
    return;
  }
  AUTO.runId = run.id; AUTO.sheetId = run.sheet_id; AUTO.estimateId = RV.estimateId;
  AUTO.status = run.status === "done" ? "done" : "failed";
  AUTO.moduleId = run.module_id || null;
  AUTO.error = run.error || null; AUTO.source = run.source || "geometry"; AUTO.scale = run.scale || null;
  AUTO.calibration = run.calibration || null; AUTO.measurementIds = run.measurement_ids || [];
  AUTO.results = run.results || null;
  drawAutoRunStatus();
}

// Which scale the agent measured with, and who set it (2026-11-13): "The agent calibrated this sheet…" or "Measured
// with the scale owner calibrated on 2026-11-11…", so a calibration is never silently someone else's.
function autoScaleText(s) {
  const ratio = "1″ = " + (Math.round(parseFloat(s.scale_ratio) * 10) / 10) + "″";
  const when = s.set_at ? " on " + String(s.set_at).slice(0, 10) : "";
  if (s.by_agent && s.during_run) return "📏 The agent calibrated this sheet itself (" + ratio + ") — check the scale in Views and scales.";
  if (s.method === "calibration") return "📏 Measured with the scale " + (s.set_by || "someone") + " calibrated" + when + " (" + ratio + ").";
  if (s.method === "note") return "📏 Measured with the plan's own scale note (" + ratio + ").";
  return "📏 Measured with the scale set by " + (s.set_by || "someone") + when + " (" + ratio + ").";
}

function stopAutoPoll() { if (AUTO.timer) { clearTimeout(AUTO.timer); AUTO.timer = null; } }

// Watch a run that was just started (or re-run): poll every 2 s until it is done, failed, or 10 minutes pass.
// The timer stops itself when the page goes away (the status slot is gone) or a newer run takes over.
function trackAutoRun(runId, vp) {
  stopAutoPoll();
  AUTO.runId = runId;
  AUTO.estimateId = RV.estimateId;
  AUTO.live = null; AUTO.lastNews = 0; AUTO.lastUpdated = null;    // a new run starts with no AI progress (2026-11-21)
  AUTO.sheetId = RV.sheetId;
  AUTO.viewportId = vp ? vp.id : null;
  AUTO.status = "running";
  AUTO.step = "";
  AUTO.error = null;
  AUTO.measurementIds = [];
  AUTO.source = "geometry";
  AUTO.startedAt = Date.now();
  drawAutoRunStatus();
  pollAutoRun();
}

function pollAutoRun() {
  stopAutoPoll();
  AUTO.timer = setTimeout(async () => {
    AUTO.timer = null;
    if (!$("bp-auto-slot") || !$("bp-auto-slot").isConnected) return;   // left the review page
    // 2026-11-21: the run streams the AI's progress, so it only "times out" when it has gone quiet for 10 minutes
    // (or after an hour in all) - a busy plan can take the AI longer than 10 minutes while it's still working.
    if (Date.now() - (AUTO.lastNews || AUTO.startedAt) > AUTO_TIMEOUT_MS || Date.now() - AUTO.startedAt > AUTO_MAX_MS) {
      AUTO.status = "timeout"; drawAutoRunStatus(); return;
    }
    const runId = AUTO.runId;
    let r;
    try { r = await api("GET", "/auto-run/" + runId); }
    catch (e) {
      if (e.status === 401) { AUTO.status = null; AUTO.step = ""; drawAutoRunStatus(); }   // signed out: the run is forgotten, start it again
      else { AUTO.status = "failed"; AUTO.error = e.message; drawAutoRunStatus(); }
      return;
    }
    if (AUTO.runId !== runId) return;                                    // a newer run took over meanwhile
    const run = r.run || {};
    if (run.updated_at && run.updated_at !== AUTO.lastUpdated) { AUTO.lastUpdated = run.updated_at; AUTO.lastNews = Date.now(); }
    AUTO.live = run.live || null;                       // the AI's latest sentence and progress (2026-11-21)
    AUTO.step = run.step || "";
    AUTO.source = run.source || "geometry";
    if (run.module_id) AUTO.moduleId = run.module_id;
    // The server picks the sheet switched on for the trade being run (2026-11-15): show that sheet while the run works on it.
    if (run.sheet_id && run.sheet_id !== AUTO.sheetId) {
      AUTO.sheetId = run.sheet_id;
      AUTO.viewportId = run.viewport_id || null;
      if (run.sheet_id !== RV.sheetId && $("review-sheet")) {
        $("review-sheet").value = run.sheet_id;
        await openSheet(run.sheet_id, $("review-message"));
      }
    }
    if (run.status === "done") {
      AUTO.status = "done";
      AUTO.scale = run.scale || null;
      AUTO.calibration = run.calibration || null;
      AUTO.measurementIds = run.measurement_ids || [];
      AUTO.results = run.results || null;
      const n = AUTO.measurementIds.length;
      const src = AUTO.source === "llm" ? " (read from the plan by the AI)" : "";
      const elec = AUTO.results && AUTO.results.electrical;
      const extra = AUTO.results && AUTO.results.concrete ? " — about " + num(AUTO.results.concrete.total_cuyd) + " cu yd of concrete"
        : elec ? " — " + (elec.counts || []).reduce((a, c) => a + (parseFloat(c.qty) || 0), 0) + " devices counted" : "";
      // Electrical's run also routes the wiring (2026-11-19): say what it did, or why it didn't.
      const wired = elec && elec.wiring;
      const wiring = wired ? (wired.ran ? " ⚡ Wiring: " + wired.summary + "." : " ⚡ " + wired.why + ".") : "";
      toast(n ? "AI Auto Run finished: " + n + " proposed measurement(s)" + src + extra + " to review." + wiring
              : "AI Auto Run finished: nothing proposed." + wiring);
      if (wired) { RV.wiringFor = null; RV.showWiringNext = !!wired.ran; }   // the Wiring card reloads with the new run, routes on
      drawAutoRunStatus();
      await refreshData();
    } else if (run.status === "failed") {
      AUTO.status = "failed";
      AUTO.error = run.error || "The agent run failed.";
      drawAutoRunStatus();
    } else {
      drawAutoRunStatus();
      pollAutoRun();
    }
  }, AUTO_POLL_MS);
}

async function startAutoRun() {
  if (AUTO.status === "running") return;
  const trade = selectedAutoRunTrade();
  if (!trade) return;   // the button is disabled without a runnable trade; a stray click does nothing
  // 2026-11-15 (David): one click measures the project. The open sheet is sent only when it is switched on for
  // the trade being run; otherwise the server picks the sheet that is on, and the plan's view on it.
  const here = !(RV.inactiveTrades || []).includes(trade);
  // Running from the click, not from the answer: a second click while the start is in flight is ignored.
  AUTO.status = "running";
  AUTO.moduleId = trade;
  AUTO.sheetId = RV.sheetId;
  AUTO.estimateId = RV.estimateId;
  AUTO.viewportId = null;
  AUTO.results = null;
  AUTO.step = "Starting…";
  AUTO.error = null;
  AUTO.startedAt = Date.now();
  drawAutoRunStatus();
  toast("AI Auto Run started — please wait, it usually takes 1–2 minutes.");
  const slot = $("bp-auto-slot");
  if (slot && slot.scrollIntoView) slot.scrollIntoView({ block: "nearest", behavior: "smooth" });
  try {
    const r = await api("POST", "/auto-run", { estimate_id: RV.estimateId, sheet_id: here ? RV.sheetId : null,
                                               module_id: trade, keep_approved: keepApprovedNow() });
    if (!r.run_id) throw new Error("AI Auto Run didn't start (no run id)");
    trackAutoRun(r.run_id, null);
  } catch (e) {
    if (e.status === 401) { AUTO.status = null; AUTO.step = ""; drawAutoRunStatus(); }
    else { AUTO.status = "failed"; AUTO.error = e.message; drawAutoRunStatus(); }
  }
}

// The latest run on this sheet: the one started here, or the one behind an agent measurement on the sheet
// (its calc names the run). Nothing found means the agent never ran here — the button then says so.
async function resolveRunIdForSheet() {
  if (AUTO.runId && AUTO.sheetId === RV.sheetId) return AUTO.runId;
  const ms = agentMeasurementsOnSheet();
  const first = ms.find(m => m.status === "proposed") || ms[0];
  if (!first) return null;
  try {
    const d = await api("GET", "/measurements/" + first.id);
    const calc = d.calc || {};
    if (calc.auto_run_id) {
      AUTO.runId = calc.auto_run_id;
      AUTO.sheetId = RV.sheetId;
      return calc.auto_run_id;
    }
  } catch (e) { /* fall through: no run to re-run */ }
  return null;
}

async function rerunAutoRun(btn) {
  if (btn) btn.disabled = true;
  AUTO.status = "running";
  AUTO.sheetId = RV.sheetId;
  AUTO.step = "Re-running…";
  drawAutoRunStatus();
  const id = await resolveRunIdForSheet();
  if (!id) {
    AUTO.status = "failed";
    AUTO.error = "No agent run to re-run on this sheet yet — use 🤖 AI Auto Run first.";
    drawAutoRunStatus();
    return;
  }
  try {
    const r = await api("POST", "/auto-run/" + id + "/rerun", { keep_approved: keepApprovedNow() });
    if (!r.run_id) throw new Error("the agent didn't re-run (no run id)");
    trackAutoRun(r.run_id, autoRunViewport());
  } catch (e) {
    if (e.status === 401) { AUTO.status = null; AUTO.step = ""; drawAutoRunStatus(); }
    else { AUTO.status = "failed"; AUTO.error = e.message; drawAutoRunStatus(); }
  }
}

// Change an agent measurement's outline to another candidate rectangle (ask-first, like every other change).
// Only for proposed agent measurements — approved ones are locked.
async function retargetForm(x, out, calc) {
  const vpId = x.viewport_id || (autoRunViewport() || {}).id;
  out.replaceChildren(el("p", { class: "muted" }, "Loading outlines…"));
  let list;
  try { list = vpId ? await getCandidates(vpId) : []; }
  catch (e) { out.replaceChildren(errorBox(e)); return; }
  if (!list.length) {
    out.replaceChildren(el("p", { class: "muted" }, "No slab outlines found on this view — measure it manually."));
    return;
  }
  const sel = el("select", { id: "bp-retarget-select", "aria-label": "Slab outline" },
    list.map(c => el("option", { value: c.id, selected: calc && calc.candidate_id === c.id }, candidateLabel(c))));
  const go2 = el("button", { class: "primary", type: "button", id: "bp-retarget-go" }, "Retarget…");
  const ask = el("div", {});
  out.replaceChildren(el("div", { class: "card section" },
    el("p", { class: "muted small" }, "Pick the outline the slab really is — the measurement is re-measured from it."),
    el("div", { class: "row" }, el("label", {}, "Outline", sel), go2), ask));
  go2.addEventListener("click", () => reviewAsk(ask, go2, "/measurements/" + x.id + "/retarget",
    { candidate_id: sel.value },
    r => "Outline changed — now " + num(r.measurement.qty) + " " + r.measurement.unit, "bp-retarget"));
}

// ------------------------------------------------------------------ the measurement list (by trade and room)
const LIST_FILTER = { status: "open", sheetOnly: false, queue: false };

function measurementPanel(msg) {
  const wrap = el("div", { id: "bp-list" });
  RV.listBox = wrap;
  refreshList(msg);
  return wrap;
}

function measurementName(m) { return m.label || words(m.feeds) || words(m.kind); }
function currentMeasurement() { return RV.data && RV.measurementId ? RV.data.takeoff.measurements.find(m => m.id === RV.measurementId) : null; }
function tradeName(id) { const t = RV.data.trades.concat(RV.data.other_trades).find(x => x.module_id === id); return t ? t.name : words(id); }

function refreshList(msg) {
  const box = RV.listBox;
  if (!box || !RV.data) return;
  const t = RV.data.takeoff;
  const status = el("select", { id: "bp-filter", "aria-label": "Show" },
    [["open", "To review and approved"], ["proposed", "To review"], ["approved", "Approved"], ["rejected", "Rejected"], ["all", "All"]]
      .map(([v, l]) => el("option", { value: v, selected: v === LIST_FILTER.status }, l)));
  status.addEventListener("change", () => { LIST_FILTER.status = status.value; refreshList(msg); });
  const only = el("input", { type: "checkbox", id: "bp-sheet-only", checked: LIST_FILTER.sheetOnly });
  only.addEventListener("change", () => { LIST_FILTER.sheetOnly = only.checked; refreshList(msg); });
  const queue = el("input", { type: "checkbox", id: "bp-queue", checked: LIST_FILTER.queue });
  queue.addEventListener("change", () => { LIST_FILTER.queue = queue.checked; refreshList(msg); });
  let rows = t.measurements.filter(m => LIST_FILTER.status === "all" || (LIST_FILTER.status === "open" ? m.status !== "rejected" : m.status === LIST_FILTER.status));
  if (LIST_FILTER.sheetOnly) rows = rows.filter(m => m.sheet_id === RV.sheetId);
  if (LIST_FILTER.queue) {
    const order = new Map(t.review_queue.map((id, i) => [id, i]));
    rows = rows.filter(m => order.has(m.id)).sort((a, b) => order.get(a.id) - order.get(b.id));
  }
  const parts = [el("p", { class: "muted small", id: "bp-counts" }, t.counts.proposed + " to review · " + t.counts.approved + " approved · " + t.counts.rejected + " rejected"),
    el("div", { class: "row filters" }, el("label", {}, "Show", status), el("label", { class: "check" }, only, " This sheet only"),
      el("label", { class: "check" }, queue, " Review queue (lowest confidence first)"))];
  if (t.suggestions_waiting.length) parts.push(el("p", { class: "note warn", id: "bp-suggestions" }, t.suggestions_waiting.length + " approved measurement(s) have a suggested change waiting for a person."));
  if (t.needs_remeasure.length) parts.push(el("p", { class: "note warn", id: "bp-remeasure" }, t.needs_remeasure.length + " measurement(s) need measuring again (the plans or a scale changed)."));
  if (RV.data.can_measure) {
    const typed = el("button", { class: "button", type: "button", id: "bp-type-number" }, "＋ Type a number in…");
    typed.addEventListener("click", () => saveForm($("review-message") || msg, { typed: true }));
    parts.push(el("div", { class: "row" }, typed));
  }
  if (RV.data.can_approve && t.counts.proposed) parts.push(bulkApprove(msg));
  if (!rows.length) {
    parts.push(el("div", { class: "card empty", id: "bp-list-empty" }, t.measurements.length ? "Nothing matches." :
      // 2026-11-21 (David): measuring by hand is too much work - AI Auto Run (and the wiring run) measure the plans.
      RV.data.can_measure ? "No measurements yet. Click 🤖 AI Auto Run — it reads the plans and measures and counts everything for you" +
        ((RV.data.trades || []).some(x => x.module_id === "electrical") ? ", then ⚡ Run wiring for the cable runs" : "") +
        ". Then approve what it found. (Missed something? The drawing tools — 📏 Length, ⬠ Area — are there for the odd extra.)" :
        "No measurements yet."));
  } else if (LIST_FILTER.queue) {
    parts.push(el("ul", { class: "bp-rows", id: "bp-rows" }, rows.map(m => measurementRow(m, msg))));
  } else {
    const byTrade = new Map();
    for (const m of rows) {
      if (!byTrade.has(m.module_id)) byTrade.set(m.module_id, new Map());
      const rooms = byTrade.get(m.module_id), r = m.room || "";
      if (!rooms.has(r)) rooms.set(r, []);
      rooms.get(r).push(m);
    }
    const list = el("div", { id: "bp-rows" });
    for (const [mod, rooms] of byTrade) {
      const all = [...rooms.values()].flat();
      const approved = (t.approved_answers || {})[mod] || {};
      const sec = el("details", { open: true, class: "bp-trade", "data-module": mod },
        el("summary", {}, tradeName(mod) + " — " + totalsText(all)));
      const priced = Object.entries(approved);
      if (priced.length) sec.append(el("p", { class: "muted small" }, "Priced from approved: " + priced.map(([q, v]) => words(q) + " " + num(v)).join(" · ")));
      for (const [room, ms] of rooms) {
        sec.append(el("h4", {}, (room || "No room") + " · " + totalsText(ms)), el("ul", { class: "bp-rows" }, ms.map(m => measurementRow(m, msg))));
      }
      list.append(sec);
    }
    parts.push(list);
  }
  box.replaceChildren(...parts);
  drawTakeoffGuide();
  drawAutoRunStatus();
  drawLayersPanel();      // the Measurements row counts this sheet's measurements — keep it fresh
}

// ------------------------------------------------------------------ guided takeoff: what to measure, with which tool
// A persistent tab beside the drawing (not a one-off tour): for every measurement-backed question
// of each trade on this project, the quantity, the tool that measures it, and why — plus whether
// it is measured yet. David's first live takeoff (NSB shed slab) had no such list: he used
// Rectangle on the footing, which gives an area, not the linear feet the footing is priced by.
// The list comes from the questions the takeoff call already returns (RV.data.trades — number and
// integer questions only, see _trade in estimator/api/takeoff_api.py), so no new endpoint.
const GUIDE_TOOLS = {
  area: { tool: "rect", label: "▭ Rectangle or ⬠ Area" },
  length: { tool: "length", label: "📏 Length" },
  count: { tool: null, label: "🤖 AI Auto Run" },   // 2026-11-18: no Count tool — AI Auto Run is the only way to count
  wiring: { tool: null, label: "⚡ Wiring" },        // cable sizes/lengths: the Wiring stage (AI Auto Run, Electrical)
};
// Why this quantity needs that tool. The concrete lines are the ones David tripped over;
// everything else falls back to the unit: sqft is priced by the square foot, lf by the foot.
const GUIDE_WHY = {
  "concrete.area_sqft": "the slab's area — it sets the concrete, gravel, mesh, and finish, all priced by the square foot",
  "concrete.perimeter_lf": "forms are the boards around the slab edge that hold wet concrete in place, priced per foot — if left at 0 the app guesses a square slab's perimeter, badly wrong for a long narrow slab",
  "concrete.footing_lf": "the thickened edge under the slab's rim — its length sets the digging, forms, and rebar, priced by the linear foot; click all four corners AND back to the start to close the loop",
};
function isWireQuestion(q) { return /^wire_\d+_\d+_ft$/.test(q.id); }
function guideToolFor(q) {
  if (isWireQuestion(q)) return "wiring";   // cable is routed by the Wiring stage, not clicked along (2026-11-19)
  const u = (q.unit || "").toLowerCase();
  if (/sq|sf/.test(u)) return "area";
  if (/lf|ft|feet/.test(u)) return "length";
  return "count";                    // no unit: a count of things (outlets, doors, windows…)
}
function guideWhyFor(mod, q) {
  const key = mod + "." + q.id;
  if (GUIDE_WHY[key]) return GUIDE_WHY[key];
  const kind = guideToolFor(q);
  if (kind === "wiring") return "routed from the panel to every device by 🤖 AI Auto Run (or ⚡ Run wiring below) — needs the floor plan and the panel drawing as DXF files";
  if (kind === "area") return "priced by the square foot — Rectangle for a straight-sided shape, Area for an odd one";
  if (kind === "length") return "priced by the linear foot — click along it";
  return "priced each — 🤖 AI Auto Run counts them from the plan";
}
// [state, text]: approved (from approved_answers, already in the question's unit), to review
// (a proposed measurement feeds it), or not yet measured.
function guideStatusFor(mod, q) {
  const t = RV.data.takeoff, approved = ((t.approved_answers || {})[mod] || {})[q.id];
  if (approved !== undefined && approved !== null) {
    return ["approved", "✓ approved — " + num(approved) + (q.unit ? " " + q.unit : "")];
  }
  const waiting = t.measurements.filter(m => m.module_id === mod && m.feeds === q.id && m.status === "proposed");
  if (waiting.length) {
    // A count question has no unit in the manifest, but its measurements are counted "ea" — treat those as
    // the question's unit, or the badge shows "1 measurement(s)" instead of the total (2026-11-18).
    const same = waiting.filter(m => m.unit === q.unit || (!q.unit && m.unit === "ea"));
    const total = same.reduce((a, m) => a + parseFloat(m.qty || 0), 0);
    const unit = q.unit || (same.length ? same[0].unit : null);
    const text = same.length ? num(total) + (unit ? " " + unit : "") : waiting.length + " measurement(s)";
    const remeasure = waiting.some(m => m.needs_remeasure) ? " · ⚠ re-measure" : "";
    return ["proposed", "to review — " + text + remeasure];
  }
  return ["missing", "not yet measured"];
}
// Calibration is the first step: until a view has a scale, nothing measured on
// it has real feet. Uses the viewport state the sheet already carries — no new
// endpoint. NTS views cannot be calibrated, so they do not count.
function guideCalibration() {
  if (isCadSheet()) return ["approved", "✓ CAD drawing at real size — no scale needed"];
  const views = (RV.viewports || []).filter(v => !v.is_nts);
  if (!views.length) return ["missing", "not to scale — nothing to calibrate"];
  if (views.some(v => !v.measurable)) return ["missing", "not calibrated — calibrate before measuring"];
  const scaled = views.find(v => parseFloat(v.scale_ratio));
  return ["approved", "✓ calibrated" + (scaled ? " — 1″ = " + scaled.scale_ratio + "″" : "")];
}

// The auto calibrator (2026-11-13, David): per view, what it did or why a person must calibrate it, and a button to
// run it. It reads the plan's written dimensions (the drawing's own lines first; the AI when AI takeoff is on).
function autoCalText(c) {
  if (!c) return null;
  if (c.status === "manual_required")
    return ["error", "⚠️ Manual calibration required — " + (c.reason || "") + " " + (c.how || "")];
  if (c.status === "calibrated" || c.status === "calibrated_unchecked") {
    const used = c.used ? c.used.label : "a written dimension";
    const check = (c.check || []).map(x => x.label + " " + x.off_pct + "% off").join(", ");
    const how = c.method === "drawing" ? "the drawing's own dimension lines" : "the dimensions the AI read";
    return [c.status === "calibrated" ? "muted small" : "note",
      "📏 Calibrated automatically from " + used + " (" + how + ")" +
      (check ? " — checked against " + check + "." : " — only one dimension, so it couldn't be cross-checked: measure something you know to check it.")];
  }
  return null;
}

function autoCalibrationBox() {
  if (isCadSheet()) return null;       // nothing to calibrate on a CAD drawing
  const views = RV.viewports || [];
  const rows = [];
  for (const v of views) {
    const said = autoCalText(v.auto_calibration);
    const name = v.label || "main view";
    const line = el("li", { class: "bp-auto-cal", "data-viewport": String(v.id) });
    if (said) line.append(el("p", { class: said[0], role: said[0] === "error" ? "alert" : null }, name + ": " + said[1]));
    if (!v.measurable && RV.data.can_measure) {
      const b = el("button", { class: "button", type: "button", "data-autocal": String(v.id),
        title: "Reads the dimensions written on the plan and sets the scale from them. Uses the drawing's own lines first; "
          + "the AI (your API key) only when AI measuring is on. If none are found, it says you need to calibrate by hand." },
        "🤖 Auto-calibrate " + name);
      b.addEventListener("click", () => runAutoCalibrate(v, b, false));
      line.append(b);
    }
    if (line.childNodes.length) rows.push(line);
  }
  return rows.length ? el("ul", { class: "bp-rows", id: "bp-auto-calibration" }, ...rows) : null;
}

async function runAutoCalibrate(v, button, confirm) {
  const msg = $("review-message");
  button.disabled = true;
  const was = button.textContent;
  button.textContent = "⏳ Reading the written dimensions…";
  try {
    const got = await api("POST", "/viewports/" + v.id + "/auto-calibrate", confirm ? { confirm: true } : {});
    if (got.needs_confirmation) {
      if (window.confirm(got.question)) return runAutoCalibrate(v, button, true);
      return;
    }
    const said = autoCalText(got);
    await refreshData();
    await openSheet(RV.sheetId, msg);
    if (msg && said) msg.replaceChildren(el("p", { class: said[0] === "error" ? "error" : "ok", id: "bp-autocal-result" },
      (v.label || "main view") + ": " + said[1]));
  } catch (e) {
    if (msg) msg.replaceChildren(el("p", { class: "error" }, "Auto-calibrate failed — " + (e.message || e)));
  } finally {
    button.disabled = false;
    button.textContent = was;
  }
}

function drawTakeoffGuide() {
  const slot = $("bp-pane-guide");
  if (!slot || !RV.data) return;
  const trades = RV.data.trades || [];
  const head = el("h3", {}, "📋 What to measure — and which tool");
  if (!trades.length) {
    slot.replaceChildren(el("div", { id: "bp-guide" }, head,
      el("p", { class: "muted small" }, "No trade on this project needs a measurement yet.")));
    return;
  }
  const parts = [head];
  const [calState, calText] = guideCalibration();
  const calRow = el("li", { class: "bp-row", "data-calibration": "1",
    tabindex: RV.data.can_measure ? "0" : null,
    title: RV.data.can_measure ? "Use the Calibrate tool" : null },
    el("span", { class: "bp-row-name" }, "Calibrate the scale", el("br", {}),
      el("span", { class: "muted small" }, "the plan is a picture — until the scale is set, nothing you measure has real feet")),
    el("span", { class: "bp-row-qty" }, "📐 Calibrate"),
    el("span", { class: "status" + (calState === "approved" ? "" : " sample") }, calText));
  if (RV.data.can_measure && !isCadSheet()) {
    const pickCal = () => setTool("calibrate", $("review-message"));
    calRow.addEventListener("click", pickCal);
    calRow.addEventListener("keydown", ev => { if (ev.key === "Enter") pickCal(); });
  }
  parts.push(el("ul", { class: "bp-rows", id: "bp-guide-calibration" }, calRow));
  const auto = autoCalibrationBox();
  if (auto) parts.push(auto);
  for (const tr of trades) {
    parts.push(el("h4", {}, tr.name));
    // A sheet switched off for this trade: the guide stays (measuring by hand still works), with the note.
    if ((RV.inactiveTrades || []).includes(tr.module_id)) {
      parts.push(el("p", { class: "note warn small", id: "bp-guide-off-" + tr.module_id },
        "This sheet is switched off for " + tr.name + " — the agent skips it, but you can still measure by hand."));
    }
    const rows = tr.questions.map(q => {
      const kind = guideToolFor(q), tool = GUIDE_TOOLS[kind];
      const [state, text] = guideStatusFor(tr.module_id, q);
      // A count row has no tool to pick (AI Auto Run counts) — instead it highlights the
      // symbols it counts on the drawing, the way the Measure steps rows do (same rule:
      // only when the sheet has classified symbols behind the question).
      const pickable = !!(RV.data.can_measure && tool.tool);
      const symbols = kind === "count" ? countSymbols(tr.module_id, q.id) : [];
      const wiringRow = kind === "wiring";
      const clickable = pickable || symbols.length > 0 || wiringRow;
      const li = el("li", { class: "bp-row" + (symbols.length || wiringRow ? " bp-step-link" : "") + (RV.countStep === q.id ? " on" : ""), "data-module": tr.module_id, "data-question": q.id, "data-feeds": kind === "count" || wiringRow ? q.id : null,
        tabindex: clickable ? "0" : null,
        title: pickable ? "Use the " + tool.label + " tool"
          : symbols.length ? "Show these on the drawing"
          : wiringRow ? "Go to the ⚡ Wiring card (routes, cable totals, Run wiring)"
          : !tool.tool ? "Run 🤖 AI Auto Run (above the drawing) to count these" : null },
        el("span", { class: "bp-row-name" },
          symbols.length ? el("span", { class: "bp-step-eye", "aria-hidden": "true" }, "🔍 ") : null, q.label, el("br", {}),
          el("span", { class: "muted small" }, guideWhyFor(tr.module_id, q))),
        el("span", { class: "bp-row-qty" }, tool.label),
        el("span", { class: "status" + (state === "approved" ? "" : " sample") }, text));
      if (pickable) {
        const pick = () => setTool(tool.tool, $("review-message"));
        li.addEventListener("click", pick);
        li.addEventListener("keydown", ev => { if (ev.key === "Enter") pick(); });
      }
      else if (wiringRow) {
        const go = () => { const w = $("bp-wiring"); if (w && w.scrollIntoView) w.scrollIntoView({ block: "start", behavior: "smooth" }); };
        li.addEventListener("click", go);
        li.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); go(); } });
      }
      else if (symbols.length) {
        const go = () => toggleCountHighlight(tr.module_id, q.id);
        li.addEventListener("click", go);
        li.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); go(); } });
      }
      return li;
    });
    parts.push(el("ul", { class: "bp-rows", id: "bp-guide-" + tr.module_id }, rows));
    // Electrical's second measuring stage: the Wiring run (cable sizes and lengths from the panel to every device).
    if (tr.module_id === "electrical") parts.push(el("div", { class: "card section", id: "bp-wiring" }));
  }
  slot.replaceChildren(el("div", { id: "bp-guide" }, ...parts));
  drawWiring();
}

// ------------------------------------------------------------------ ✨ AI design (2026-11-21, David)
// "In many cases the user has a shed drawing or house drawing and wants AI to do the addition of the electrical work ...
// design me the lighting and receptacles ... then review." The person says what to add; the AI reads the building, places
// every symbol to code, and the server draws a new plan + panel schedule. It stays proposed - changed in plain words,
// viewed, approved (it becomes plan sets that are measured and priced) or discarded. Electrical first.
const DESIGN_TYPES = {
  outlet: "outlets", outlet_gfci: "GFCI outlets", outlet_wp: "weatherproof outlets", outlet_usb: "USB outlets",
  outlet_quad: "quad outlets", outlet_240: "240 V outlets", range_outlet: "range outlets", dryer_outlet: "dryer outlets",
  ev_charger: "EV chargers", disconnect: "disconnects", switch: "switches", switch_3way: "3-way switches",
  switch_4way: "4-way switches", switch_dimmer: "dimmers", light: "ceiling lights", light_led: "LED shop lights",
  light_recessed: "recessed lights", light_pendant: "pendants", light_wall: "wall lights",
  light_undercabinet: "under-cabinet lights", light_exterior: "exterior lights", fan: "ceiling fans",
  exhaust_fan: "exhaust fans", smoke: "smoke alarms", smoke_co: "smoke/CO alarms", junction_box: "junction boxes",
  data: "data drops", tv: "TV drops" };

// 2026-11-23 (David: "move it to the main measure window by the AI Auto Run ... it will not let me type anything"):
// the card lives in its own window opened from the toolbar's ✨ AI design - the To measure tab redrew itself (and the
// card with it) whenever the screen refreshed, which threw away what was being typed. The window is only redrawn when
// the design itself changes, and what is typed is kept in RV.designDraft across any redraw.
function openDesignPanel() {
  closeDesignPanel();
  const x = el("button", { class: "button", type: "button", id: "bp-design-x", title: "Close (Esc)" }, "✕");
  x.addEventListener("click", closeDesignPanel);
  const panel = el("div", { class: "bp-wv bp-dp", id: "bp-design-panel", role: "dialog", "aria-label": "AI design" },
    el("div", { class: "bp-wv-head" }, el("strong", {}, "✨ AI design"), el("span", { class: "bp-wv-btns" }, x)),
    el("div", { class: "card section", id: "bp-design" }));
  const back = el("div", { class: "bp-wv-back", id: "bp-design-back" }, panel);
  back.addEventListener("click", e => { if (e.target.id === "bp-design-back") closeDesignPanel(); });
  document.body.append(back);
  document.addEventListener("keydown", designPanelKeys);
  drawDesign();
  setTimeout(() => { const t = $("bp-design-request") || $("bp-design-change"); if (t) t.focus(); }, 50);
}
function designPanelKeys(e) { if (e.key === "Escape" && !$("bp-wiring-viewer-back")) closeDesignPanel(); }
window.addEventListener("hashchange", () => { closeDesignPanel(); closeWiringViewer(); });   // leaving the screen closes them
function closeDesignPanel() {
  const b = $("bp-design-back");
  if (b) b.remove();
  document.removeEventListener("keydown", designPanelKeys);
}

function designButtonText() {
  const j = designJob();
  if (j && j.status === "working") return /^approving/.test(j.step || "") ? "⏳ Approving the AI design…" : "⏳ AI design working…";
  if (j && j.status === "proposed") return "✨ AI design (ready to review)";
  if (j && j.reapply) return "✨ AI design (not in place yet)";
  return "✨ AI design";
}
function designButtonState() {
  const b = $("bp-ai-design");
  if (b) b.textContent = designButtonText();
}

async function drawDesign() {
  if (!RV.estimateId) return;
  if (RV.designFor !== RV.estimateId) { RV.design = null; RV.designNew = false; RV.designDraft = {}; }
  RV.designFor = RV.estimateId;
  if (!RV.design) renderDesign();
  try { RV.design = await api("GET", "/design/" + RV.estimateId); }
  catch (e) { if (e.status === 401) return; RV.design = { error: e }; }
  renderDesign();
  designPoll();
}

function designJob() { return RV.design && RV.design.designs ? RV.design.designs.electrical : null; }

// While the AI works (a minute or two), check every few seconds - with the window closed too: the toolbar button says
// it's working, and a message says when it's ready.
function designPoll() {
  clearTimeout(RV.designTimer);
  designButtonState();
  const j = designJob();
  if (!j || j.status !== "working") return;
  const est = RV.estimateId;
  RV.designTimer = setTimeout(async () => {
    if (RV.estimateId !== est || !location.hash.startsWith("#/takeoffs/")) return;     // left the screen
    try {
      const r = await api("GET", "/design/" + est + "/electrical");
      RV.design.designs.electrical = r.design;
      renderDesign();
      if (r.design && r.design.status !== "working") {
        if (r.design.status === "proposed") toast(r.design.rev > 1 ? "The AI made the change — open ✨ AI design to have a look."
                                                                     : "The AI design is ready — open ✨ AI design to have a look.");
        else if (r.design.status === "failed") toast("The AI design didn't finish — open ✨ AI design to see why.");
        else if (r.design.status === "approved") designApproved(r.design);
      }
    } catch (e) { if (e.status === 401) return; }
    designPoll();
  }, 3000);
}

// What is being typed survives a redraw (a poll, a refresh).
function designKeep(t, key) {
  if (!RV.designDraft) RV.designDraft = {};
  if (RV.designDraft[key] !== undefined) t.value = RV.designDraft[key];
  t.addEventListener("input", () => { RV.designDraft[key] = t.value; });
  return t;
}

// 2026-11-23 (David: "add screenshots to the AI Design to give geometric guidance to the AI, for example move this
// here"): up to 3 screenshots with a request or a change - picked (📎) or pasted (Ctrl+V in the text box). Each is shrunk
// here so the request stays small; the server sends them to the AI with its numbered reference picture of the building.
const DESIGN_MAX_SHOTS = 3;
function designShots(key) {
  if (!RV.designShotList) RV.designShotList = {};
  if (!RV.designShotList[key]) RV.designShotList[key] = [];
  return RV.designShotList[key];
}

function shrinkPicture(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      let side = 1400, q = 0.85, out = "";
      for (let i = 0; i < 6; i++) {
        const k = Math.min(1, side / Math.max(img.naturalWidth, img.naturalHeight));
        const c = document.createElement("canvas");
        c.width = Math.max(1, Math.round(img.naturalWidth * k)); c.height = Math.max(1, Math.round(img.naturalHeight * k));
        const g = c.getContext("2d");
        g.fillStyle = "#fff"; g.fillRect(0, 0, c.width, c.height);
        g.drawImage(img, 0, 0, c.width, c.height);
        out = c.toDataURL("image/jpeg", q);
        if (out.length <= 300000) break;            // three of them stay well under the server's 1 MB request limit
        side = Math.round(side * 0.82); q = Math.max(0.5, q - 0.08);
      }
      resolve(out);
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error("that file isn't a picture")); };
    img.src = url;
  });
}

async function designAddShots(key, files) {
  const list = designShots(key);
  const msg = $("bp-design-msg");
  for (const f of files) {
    if (!f || !/^image\//.test(f.type || "")) continue;
    if (list.length >= DESIGN_MAX_SHOTS) { toast("Up to " + DESIGN_MAX_SHOTS + " screenshots at a time."); break; }
    try { list.push({ name: f.name || "screenshot", url: await shrinkPicture(f) }); }
    catch (e) { if (msg) msg.replaceChildren(el("p", { class: "error" }, "That screenshot couldn't be read — " + e.message)); }
  }
  const box = $("bp-design-shots-" + key);
  if (box) box.replaceWith(designShotBox(key));
}

// Paste a screenshot straight into the text box (Snipping Tool, Print Screen ...).
function designPaste(t, key) {
  t.addEventListener("paste", e => {
    const files = [...((e.clipboardData && e.clipboardData.items) || [])].filter(i => i.kind === "file").map(i => i.getAsFile());
    if (files.length) { e.preventDefault(); designAddShots(key, files); }
  });
  return t;
}

function designShotBox(key) {
  const list = designShots(key);
  const input = el("input", { type: "file", accept: "image/*", multiple: "", id: "bp-design-file-" + key, hidden: "" });
  input.addEventListener("change", () => { designAddShots(key, [...input.files]); input.value = ""; });
  const add = el("button", { class: "button", type: "button", id: "bp-design-attach-" + key,
    disabled: list.length >= DESIGN_MAX_SHOTS ? "" : null,
    title: "Add a screenshot or photo with your marks on it (an arrow, a circle, 'here') — up to " + DESIGN_MAX_SHOTS },
    "📎 Add screenshot");
  add.addEventListener("click", () => input.click());
  const thumbs = list.map((s, i) => {
    const x = el("button", { class: "link-btn", type: "button", title: "Remove", "aria-label": "Remove screenshot " + (i + 1) }, "✕");
    x.addEventListener("click", () => { list.splice(i, 1); $("bp-design-shots-" + key).replaceWith(designShotBox(key)); });
    return el("span", { class: "bp-shot" }, el("img", { src: s.url, alt: s.name }), x);
  });
  return el("div", { class: "bp-shots", id: "bp-design-shots-" + key }, input, add, ...thumbs,
    el("span", { class: "muted small" }, list.length ? list.length + " of " + DESIGN_MAX_SHOTS
      : "or paste one into the box (Ctrl+V) — mark it up to show what goes where"));
}

function renderDesign() {
  const box = $("bp-design");
  if (!box) return;
  const head = el("h4", {}, "Describe it — the AI draws it");
  const d = RV.design;
  if (!d) { box.replaceChildren(head, el("p", { class: "muted small" }, "Loading…")); return; }
  if (d.error) { box.replaceChildren(head, errorBox(d.error)); return; }
  const parts = [head, el("p", { class: "muted small" },
    "Tell the AI what to add to your drawings — it reads the building, places every symbol to the code rules and your specs, " +
    "and draws a new plan and panel schedule for you to review. Nothing is priced until you approve it. " +
    "Uses the agent API key" + (d.ai_label ? " (" + d.ai_label + ")" : "") + ".")];
  if (!d.ai_on) parts.push(el("p", { class: "note warn small", id: "bp-design-off" }, d.why_off));
  const j = designJob();
  parts.push(el("div", { id: "bp-design-msg" }));
  if (j && j.status === "working") parts.push(designWorking(j));
  else if (j && (j.status === "proposed" || j.status === "approved") && !RV.designNew) parts.push(...designResult(j, d));
  else {
    if (j && j.status === "failed") parts.push(el("p", { class: "error", id: "bp-design-failed" }, "The last design didn't finish: " + j.error));
    if (d.can_run) parts.push(designForm(d, j));
    else parts.push(el("p", { class: "muted small" }, "An owner or estimator can start an AI design."));
  }
  box.replaceChildren(...parts);
}

function designForm(d, j) {
  const trade = el("select", { id: "bp-design-trade", "aria-label": "Trade" },
    ...d.trades.map(t => el("option", { value: t.id, disabled: t.ready ? null : "" }, t.label + (t.ready ? "" : " (coming)"))));
  const sets = d.plan_sets || [];
  const ps = el("select", { id: "bp-design-plans", "aria-label": "The drawings to design on" },
    ...sets.map(p => el("option", { value: p.id }, "#" + p.id + " " + p.name + (p.file_type === "dxf" ? " (CAD)" : ""))));
  const ex = (d.trades.find(t => t.id === "electrical") || {}).example || "";
  const req = designPaste(designKeep(el("textarea", { id: "bp-design-request", rows: "5", maxlength: "3000",
    placeholder: "e.g. " + ex }, (j && j.request) || ""), "request"), "start");
  const specs = designKeep(el("textarea", { id: "bp-design-specs", rows: "3", maxlength: "3000",
    placeholder: "e.g. receptacles at 48 in, LED 4 ft shop lights, 3-way at both walk doors, metal building — EMT conduit" },
    (j && j.specs) || ""), "specs");
  const go = el("button", { class: "primary", type: "button", id: "bp-design-go",
    disabled: d.ai_on && sets.length ? null : "" }, "✨ Design it");
  go.addEventListener("click", () => designStart(go, req, specs, ps, trade));
  const cancel = RV.designNew ? el("button", { class: "button", type: "button", id: "bp-design-cancel" }, "Back to the design") : null;
  if (cancel) cancel.addEventListener("click", () => { RV.designNew = false; renderDesign(); });
  return el("div", { id: "bp-design-form" },
    !sets.length ? el("p", { class: "note warn small" }, "Upload the building's drawings first (PDF, photo or CAD) on the project page.") : null,
    el("div", { class: "row" }, el("label", { for: "bp-design-trade" }, "Trade "), trade,
      el("label", { for: "bp-design-plans" }, " on "), ps),
    el("label", { for: "bp-design-request", class: "small" }, "What do you want added?"), req, designShotBox("start"),
    el("details", { id: "bp-design-specs-box", open: (j && j.specs) ? "" : null },
      el("summary", { class: "small" }, "Specs and preferences (optional)"), specs),
    el("div", { class: "row" }, go, cancel));
}

async function designStart(btn, req, specs, ps, trade) {
  const msg = $("bp-design-msg");
  btn.disabled = true;
  msg.replaceChildren();
  try {
    const r = await api("POST", "/design/" + RV.estimateId + "/" + trade.value,
      { request: req.value, specs: specs.value, plan_set_id: parseInt(ps.value, 10),
        images: designShots("start").map(s => s.url) });
    RV.design.designs.electrical = r.design;
    RV.designNew = false;
    RV.designDraft = {};                                      // the job keeps the request and specs now
    RV.designShotList.start = [];
    renderDesign();
    designPoll();
  } catch (e) {
    if (e.status !== 401) msg.replaceChildren(errorBox(e));
    btn.disabled = false;
  }
}

function designWorking(j) {
  const approving = /^approving/.test(j.step || "");
  return el("div", { id: "bp-design-working", class: "note", role: "status" },
    el("strong", {}, approving ? "✅ Approving: " : "🤖 The AI is working: "),
    (approving ? j.step.replace(/^approving:\s*/, "") : (j.step || "starting")) + "…", el("br", {}),
    el("span", { class: "muted small" }, approving
      ? "Putting the design in place of the older drawings, measuring it and pricing it — no AI cost. The card updates by itself."
      : "This takes a minute or two — you can keep working; the card updates by itself."));
}

// The approval finished: say what was done, and show the new drawings and counts on the Measure screen.
function designApproved(j) {
  toast((j.approval && j.approval.say) || "Approved.");
  if (RV.estimateId) refreshData();
}

function designResult(j, d) {
  const out = [];
  const c = j.counts || {}, b = j.building || {}, ds = j.design || {};
  if (j.status === "approved") {
    const a = j.approval || {};
    if (j.reapply) out.push(el("p", { class: "note warn", id: "bp-design-reapply" },
      "This design was approved before the app took over the rest of the work, so the older electrical drawings are " +
      "still on the project and it wasn't measured. Click ✅ Put it in place of the older drawings below — the app " +
      "replaces them, counts every device, runs the wiring and updates the estimate (no AI cost)."));
    else out.push(el("p", { class: "note ok", id: "bp-design-approved" },
      "✅ " + (a.say || "Approved.") + " It's the project's electrical plan and panel schedule now (plan sets " +
      (j.approved_plan_set_ids || []).map(i => "#" + i).join(" and ") + ")" +
      (a.approved ? " — the counts and the cable are approved; see them in the measurement list." : ".")));
  }
  else out.push(el("p", { class: "note warn small", id: "bp-design-proposed" },
    "Proposed — revision " + j.rev + ". Have a look, change anything in plain words, then approve it."));
  if (j.error) out.push(el("p", { class: "error", id: "bp-design-error" }, j.error));
  out.push(el("p", { class: "small", id: "bp-design-building" },
    el("strong", {}, b.name || "Building"), " · " + (b.size || "") + " · " + (b.kind || "") +
    " · read from " + (b.source === "dxf" ? "the CAD drawing" : "the sheets by the AI")));
  if (ds.summary) out.push(el("p", { class: "small", id: "bp-design-summary" }, ds.summary));
  const chips = Object.entries(c.devices || {}).map(([k, n]) => el("span", { class: "chip" }, n + " " + (DESIGN_TYPES[k] || words(k))));
  out.push(el("div", { class: "chips", id: "bp-design-counts" },
    el("span", { class: "chip strong" }, (c.total || 0) + " devices · " + (c.circuits || 0) + " circuits · " + (c.panel || "")), ...chips));
  const p = ds.panel || {};
  if (p.kind === "subpanel") out.push(el("p", { class: "small", id: "bp-design-feeder" },
    "Fed from: " + (p.fed_from || "—") + (p.feeder ? " · " + p.feeder : "") +
    (p.feeder_breaker_amps ? " · feeder breaker " + p.feeder_breaker_amps + " A (confirm by load calc)" : "")));
  const view = (id, label, what) => {
    const btn = el("button", { class: "button", type: "button", id }, label);
    btn.addEventListener("click", () => openDrawingViewer({
      title: what === "panel" ? "AI design — panel schedule" : "AI design — electrical plan",
      url: "/design/" + RV.estimateId + "/electrical/" + what + "/svg",
      download: b2 => designDownload(b2, what),
      other: { label: what === "panel" ? "🗺 Plan" : "📋 Panel schedule", title: "Show the other drawing",
               go: () => $(what === "panel" ? "bp-design-view-plan" : "bp-design-view-panel").click() } }));
    return btn;
  };
  const ref = el("button", { class: "button", type: "button", id: "bp-design-view-ref",
    title: "Every device numbered on a 5 ft grid — say \"move 12 to x 30, y 44\", or mark it up and paste it as a screenshot" },
    "🔢 Numbered plan");
  ref.addEventListener("click", () => openDrawingViewer({
    title: "AI design — numbered plan (what the AI sees with your screenshots)",
    url: "/design/" + RV.estimateId + "/electrical/reference",
    download: b2 => designDownload(b2, "reference"),
    downloadLabel: "⬇ Save picture", downloadTitle: "Save it as a PNG to mark up" }));
  out.push(el("div", { class: "row", id: "bp-design-files" }, view("bp-design-view-plan", "👁 View the plan", "plan"),
    view("bp-design-view-panel", "👁 Panel schedule", "panel"), ref));
  out.push(designFindings(j));
  if ((ds.circuits || []).length) out.push(el("details", { id: "bp-design-circuits" },
    el("summary", { class: "small" }, "Circuits (" + ds.circuits.length + ")"),
    el("table", { class: "small" }, el("tbody", {}, ...ds.circuits.map(x => el("tr", {},
      el("td", {}, x.id), el("td", {}, x.description), el("td", {}, x.amps + " A" + (x.poles > 1 ? " 2P" : "")), el("td", {}, x.wire)))))));
  const notes = [...(ds.assumptions || []).map(a => "Assumed: " + a), ...(ds.code_notes || [])];
  if (notes.length) out.push(el("details", { id: "bp-design-notes" }, el("summary", { class: "small" }, "Assumptions and code notes (" + notes.length + ")"),
    el("ul", { class: "small" }, ...notes.map(n => el("li", {}, n)))));
  if ((ds.changes || []).length && j.rev > 1) out.push(el("div", { class: "small", id: "bp-design-changes" },
    el("strong", {}, "What changed: "), el("ul", {}, ...ds.changes.map(x => el("li", {}, x)))));
  if (d.can_run) out.push(designActions(j));
  const revs = j.revisions || [];
  if (revs.length > 1 || j.cost_usd) out.push(el("p", { class: "muted small", id: "bp-design-cost" },
    "AI cost of this design: $" + (j.cost_usd || 0).toFixed(2) + (j.model ? " (" + j.model + ")" : "") +
    " · " + revs.length + " revision" + (revs.length === 1 ? "" : "s")));
  return out;
}

function designFindings(j) {
  const f = j.findings || [];
  const icon = { error: "⛔", warning: "⚠️", info: "ℹ️" };
  const head = j.errors ? j.errors + " code error" + (j.errors === 1 ? "" : "s") + " to fix before approving"
    : j.warnings ? "No code errors · " + j.warnings + " thing" + (j.warnings === 1 ? "" : "s") + " to look at" : "Code check: nothing found";
  const main = f.filter(x => x.level !== "info"), info = f.filter(x => x.level === "info");
  return el("div", { id: "bp-design-findings" },
    el("p", { class: j.errors ? "error small" : "ok small" }, (j.errors ? "⛔ " : "✓ ") + head),
    main.length ? el("ul", { class: "small" }, ...main.map(x => el("li", { class: x.level === "error" ? "error" : "" }, icon[x.level] + " " + x.message))) : null,
    info.length ? el("details", {}, el("summary", { class: "small muted" }, info.length + " note" + (info.length === 1 ? "" : "s")),
      el("ul", { class: "small muted" }, ...info.map(x => el("li", {}, x.message)))) : null);
}

function designActions(j) {
  const text = designPaste(designKeep(el("textarea", { id: "bp-design-change", rows: "3", maxlength: "3000",
    placeholder: j.errors ? "e.g. fix the errors"
      : "e.g. add two outlets on the rear wall · move device 12 to x 30, y 44 (🔢 Numbered plan) · move this outlet here (add a marked-up screenshot)" }),
    "change"), "change");
  const change = el("button", { class: "button", type: "button", id: "bp-design-change-go" }, "✏️ Make the change");
  change.addEventListener("click", () => designChange(change, text));
  const approve = el("button", { class: "primary", type: "button", id: "bp-design-approve",
    disabled: j.can_approve ? null : "", title: j.errors ? "Fix the code errors first (ask for it above)" : null },
    j.reapply ? "✅ Put it in place of the older drawings" : j.status === "approved" ? "✅ Approved" : "✅ Approve design");
  if (j.status === "approved" && !j.reapply) approve.disabled = true;
  approve.addEventListener("click", () => designApprove(approve, false));
  const fresh = el("button", { class: "button", type: "button", id: "bp-design-new" }, "＋ New design");
  fresh.addEventListener("click", () => { RV.designNew = true; renderDesign(); });
  const drop = el("button", { class: "button", type: "button", id: "bp-design-discard" }, "🗑 Discard");
  drop.addEventListener("click", () => designDiscard(drop));
  return el("div", { id: "bp-design-actions" },
    el("label", { for: "bp-design-change", class: "small" }, "Change it in plain words"), text, designShotBox("change"),
    el("div", { class: "row" }, change, approve, fresh, j.status === "proposed" ? drop : null),
    el("div", { id: "bp-design-confirm-slot" }));
}

async function designChange(btn, text) {
  const msg = $("bp-design-msg");
  btn.disabled = true;
  msg.replaceChildren();
  try {
    const r = await api("POST", "/design/" + RV.estimateId + "/electrical/change",
      { text: text.value, images: designShots("change").map(s => s.url) });
    RV.design.designs.electrical = r.design;
    RV.designDraft.change = "";                               // sent: the box starts empty for the next change
    RV.designShotList.change = [];
    renderDesign();
    designPoll();
  } catch (e) {
    if (e.status !== 401) msg.replaceChildren(errorBox(e));
    btn.disabled = false;
  }
}

async function designApprove(btn, confirmed) {
  const slot = $("bp-design-confirm-slot"), msg = $("bp-design-msg");
  btn.disabled = true;
  msg.replaceChildren();
  try {
    const r = await api("POST", "/design/" + RV.estimateId + "/electrical/approve", confirmed ? { confirm: true } : {});
    if (r.needs_confirmation) {
      const yes = el("button", { class: "primary", type: "button", id: "bp-design-confirm" }, "Yes, approve it");
      const no = el("button", { class: "button", type: "button", id: "bp-design-confirm-cancel" }, "Cancel");
      yes.addEventListener("click", () => designApprove(yes, true));
      no.addEventListener("click", () => { slot.replaceChildren(); btn.disabled = false; });
      slot.replaceChildren(el("div", { class: "confirm", id: "bp-design-confirm-box" }, el("p", {}, el("strong", {}, r.question)),
        el("div", { class: "row" }, yes, no)));
      yes.focus();
      return;
    }
    // 2026-11-23: approving replaces the older electrical drawings, measures the design and prices it - in the
    // background; the window shows each step, then what was done
    RV.design.designs.electrical = r;
    renderDesign();
    if (r.status === "approved") designApproved(r);
    else designPoll();
  } catch (e) {
    if (e.status !== 401) msg.replaceChildren(errorBox(e));
    btn.disabled = false;
  }
}

async function designDiscard(btn) {
  btn.disabled = true;
  try {
    const r = await api("POST", "/design/" + RV.estimateId + "/electrical/discard", {});
    RV.design.designs.electrical = r.design;
    toast("Discarded — nothing on the estimate changed.");
    renderDesign();
  } catch (e) {
    if (e.status !== 401) $("bp-design-msg").replaceChildren(errorBox(e));
    btn.disabled = false;
  }
}

async function designDownload(btn, what) {
  btn.disabled = true;
  try {
    const opts = { credentials: "same-origin", headers: {} };
    if (APP_TOKEN) opts.headers["Authorization"] = "Bearer " + APP_TOKEN;
    const r = await fetch(API + "/design/" + RV.estimateId + "/electrical/" + what, opts);
    if (!r.ok) {
      let data = null;
      try { data = await r.json(); } catch (e) { data = null; }
      throw new ApiError(r.status, data);
    }
    const name = ((r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/) || [])[1] || (what === "reference" ? "ai_design_reference.png" : "ai_design.dxf");
    const url = URL.createObjectURL(await r.blob());
    const a = el("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (e) {
    if (e.status !== 401) toast("The download didn't work — " + (e.message || "unknown error"));
  } finally { btn.disabled = false; }
}

// ------------------------------------------------------------------ Wiring run (2026-11-19, David)
// The second Electrical measuring stage. The project's two CAD drawings — the electrical floor plan and the panel
// drawing (the one with the panel schedule) — give every device, room and circuit; the run routes each circuit from the
// panel through the ceiling (or the walls), sizes the cable from the schedule, and proposes one cable measurement per
// size for a person to approve (approved cable replaces the 'average run per device' wire guess on the estimate). The
// routes can be shown on the plan, a device moved to another circuit (then run again), and the wiring DXF downloaded.
const WIRE_COLORS = ["#1c7ed6", "#e8590c", "#2b8a3e", "#ae3ec9", "#f08c00", "#0c8599", "#c2255c", "#5c940d",
                     "#3b5bdb", "#d9480f", "#087f5b", "#862e9c"];
function wireColor(i) { return WIRE_COLORS[i % WIRE_COLORS.length]; }
function wireDevice(a) { return words(a.item_type || "device") + (a.room ? " · " + a.room : ""); }

function wiringReset(w) {
  RV.wiring = w;
  const run = w && w.run;
  RV.wiringMoves = { ...((run && run.overrides) || {}) };
  const s = (run && run.settings) || {};
  RV.wiringForm = { route: { ...(s.route || {}) }, ceiling_ft: s.ceiling_ft ?? "", floor_framing_ft: s.floor_framing_ft ?? "" };
}

async function drawWiring() {
  if (!$("bp-wiring") || !RV.estimateId) return;
  if (RV.wiringFor !== RV.estimateId) {
    RV.wiringFor = RV.estimateId;
    // 2026-11-21 (David: "after hitting run wiring ... nothing shows up in the cad window"): a reload right after a
    // wiring run (⚡ Run wiring, AI Auto Run) keeps the routes showing; opening the screen starts with them hidden.
    RV.wiring = null; RV.wiringPick = null; RV.showWiring = !!RV.showWiringNext; RV.showWiringNext = false;
    renderWiring();
    try { wiringReset(await api("GET", "/wiring/" + RV.estimateId)); }
    catch (e) { if (e.status === 401) return; RV.wiring = { error: e }; }
  }
  renderWiring();
  drawWiringRoutes();
}

function renderWiring() {
  const box = $("bp-wiring");
  if (!box) return;
  const w = RV.wiring;
  const head = el("h4", {}, "⚡ Wiring — cable from the panel to every device");
  if (!w) { box.replaceChildren(head, el("p", { class: "muted small" }, "Loading…")); return; }
  if (w.error) { box.replaceChildren(head, errorBox(w.error)); return; }
  const run = w.run, src = w.sources || {};
  const parts = [head, el("p", { class: "muted small" },
    "Second measuring stage: reads the floor plan and the panel drawing, routes every circuit from the panel the way you set in " +
    "the wiring options (foundation, outlets through the studs, lights through the ceiling — never in a slab), and sizes the cable " +
    "from the panel schedule. Plain geometry — no AI tokens.")];
  const srcLine = (label, s, missing) => [label + ": ", s ? el("strong", {}, s.name) : el("span", { class: "warn" }, missing)];
  parts.push(el("p", { class: "small", id: "bp-wiring-sources" },
    ...srcLine("Floor plan", src.plan, "none yet — upload the electrical floor plan as a DXF (CAD) file on the Plans screen"), el("br", {}),
    // 2026-11-21: with no panel drawing the run lays the circuits out itself (typical residential layout).
    ...srcLine("Panel drawing", src.panel, "none — the circuits will be laid out the usual residential way (upload the panel drawing with its schedule to use the designer's circuits)")));
  if (run && run.circuits_from === "laid_out") parts.push(el("p", { class: "note warn", id: "bp-wiring-laid-out" },
    "No panel schedule: AI-Prowler laid out these circuits the usual residential way (lighting by floor on 15 A, kitchen counter on two 20 A " +
    "small-appliance circuits, each bathroom, laundry and garage on its own 20 A, the range, dryer and other appliances on their own 240 V circuits). " +
    "Good for estimating — check them against the electrician's layout."));
  if (w.can_run) parts.push(wiringSettings(run, src));
  parts.push(el("div", { id: "bp-wiring-msg" }));
  if (run) parts.push(...wiringResults(run, w.can_run));
  box.replaceChildren(...parts);
}

// The Wiring card's run controls (2026-11-21, David: "can we have the user decide/set wire running options before the
// run wiring"): how the last run was routed, and ⚡ Run wiring - which opens the routing options first.
function wiringSettings(run, src) {
  const ready = !!src.plan;                    // the panel drawing is optional (2026-11-21)
  const btn = el("button", { class: "primary", type: "button", id: "bp-wiring-run", disabled: ready ? null : "" },
    run ? "⚡ Run wiring again…" : "⚡ Run wiring…");
  btn.addEventListener("click", () => openWiringOptions(btn));
  const how = run && run.routing ? el("p", { class: "small", id: "bp-wiring-routing" }, "Routed: " + run.routing + ".") : null;
  return el("div", {}, how, el("div", { class: "row" }, btn));
}

// ---- the routing options box (2026-11-21, David: "Don't run any electrical through cement slabs, all get routed from
// basement ceiling" / "I like the user setting defaults for routing wires"). Opens before every ⚡ Run wiring, filled
// in with this project's last run (or the user's saved defaults); each option says what electricians usually do.
const WIRE_OPTIONS = [
  // 2026-11-21 (David: "explain what these routing options are in the drop-down box and how it affects routing"):
  // each choice is [value, short label, what it does to the routing] - the "what it does" shows under the box for the
  // choice picked, so the user sees the effect before running.
  // 2026-11-23 (David: "a metal shed ... mount the conduit on top of the steel and not drill holes through studs ...
  // adding power after a house is built, outside the walls ... include a basic expansion coefficient"):
  { key: "method", label: "Wiring method", tip: "How the wire is installed — it decides what's measured and priced.",
    choices: [
      ["nm", "NM-B cable in the walls", "Romex-type cable through the studs, joists and ceiling, stapled inside the walls — new construction or open walls. Measures cable by size."],
      ["emt", "EMT conduit on the surface", "Steel tubing strapped to the walls, girts or ceiling with THHN wire pulled in it — metal buildings, garages, unfinished basements, adding power after a house is built. Measures the pipe, elbows, couplings, connectors, straps, surface boxes and THHN; outside runs use the outdoor material below."],
      ["pvc", "PVC conduit on the surface", "Schedule 40 PVC strapped on the surface — wet or corrosive places and outdoors. PVC grows and shrinks about 5 times as much as steel with temperature, so long straight runs need expansion couplings (NEC 352.44)."]] },
  { key: "outdoor_material", label: "Outside runs in", when: f => f.method === "emt",
    tip: "From an inside run out through the wall (an LB) to a weatherproof box, or along an outside wall.",
    choices: [
      ["pvc", "PVC", "Schedule 40 PVC outside — doesn't rust; expands with the sun, so expansion couplings are counted where a straight leg moves 1/4 in or more."],
      ["emt", "EMT with compression fittings", "Steel outside too, with raintight compression fittings."]] },
  { key: "structure", label: "The conduit is strapped to", when: f => f.method !== "nm",
    tip: "Metal conduit moves with what it's strapped to: EMT on a steel building expands nearly the same as the steel, so it rarely needs expansion fittings. PVC is counted by its own coefficient (the code table).",
    choices: [
      ["wood", "Wood framing", "Wood barely moves with temperature (about 2.5 millionths in/in/°F), so long EMT runs on wood can need an expansion fitting in a big temperature swing."],
      ["steel", "A steel building", "Girts, purlins and columns — steel moves 6.5 millionths in/in/°F, the same as EMT."],
      ["masonry", "Block or concrete", "About 5.5 millionths in/in/°F."]] },
  { key: "temp_swing_indoor_f", label: "Temperature swing inside (°F)", step: "5", when: f => f.method !== "nm",
    tip: "Coldest to hottest the conduit will see inside. Heated and cooled rooms 30–60; an unconditioned metal building, garage or attic 90–100." },
  { key: "temp_swing_outdoor_f", label: "Temperature swing outside (°F)", step: "5", when: f => f.method !== "nm",
    tip: "Coldest winter night to hottest summer day where the job is." },
  { key: "outdoor_in_sun", label: "Outside runs are in direct sun", check: true, when: f => f.method !== "nm",
    tip: "Sun heats the conduit well above the air — PVC makers add 30 °F." },
  { key: "sun_add_f", label: "Added for the sun (°F)", step: "5", when: f => f.method !== "nm" && f.outdoor_in_sun },
  { key: "expansion_threshold_in", label: "Expansion fitting where a straight leg moves (in)", step: "0.05", when: f => f.method !== "nm",
    tip: "NEC 352.44: an expansion fitting on PVC where the movement is 1/4 in or more. Movement = coefficient × leg length × temperature swing (PVC 3.38e-5, EMT 6.5e-6 in/in/°F)." },
  { key: "homerun_max_circuits", label: "Circuits per home-run conduit", step: "1", when: f => f.method !== "nm",
    tip: "Home runs leave the panel together in one pipe, up to this many circuits, then split. The pipe is sized for the wires in it." },
  { key: "foundation", label: "Foundation", tip: "What the ground floor sits on — it decides where the cable from the panel travels.",
    choices: [
      ["basement", "Basement", "Cable leaves the panel, runs along the basement ceiling (under the ground floor), then comes up through the floor into the walls. Ground-floor outlets too far apart to chain are fed from below."],
      ["crawlspace", "Crawlspace", "Like a basement: cable runs along the floor joists in the crawlspace and comes up into the walls. The panel stays where it's drawn."],
      ["slab", "Slab on grade", "No cable ever goes in the concrete. Ground-floor runs come down from the ceiling (or attic) into the walls — usually more cable than a basement."]] },
  { key: "panel_in_basement", label: "The panel is in the basement (under where it's drawn)", check: true, when: f => f.foundation === "basement",
    tip: "Usual in a basement house. Untick if the panel hangs on a ground-floor wall." },
  { key: "basement_ceiling_ft", label: "Basement ceiling height (ft)", step: "0.5", when: f => f.foundation === "basement" },
  { key: "outlets_via", label: "Outlets wired", tip: "How the cable gets from one outlet to the next. (Lights always go through the ceiling, with the switches dropped down from them.)",
    choices: [
      ["walls", "Through the studs", "Outlet to outlet through holes drilled in the studs at outlet height — the shortest way, and what most electricians do. When the next outlet is farther than the distance below (past a door, round a corner), the cable goes the floor's feed way instead: down through the floor framing, or up through the ceiling on a slab."],
      ["below", "From below", "Each outlet is fed from the floor framing underneath (basement ceiling or crawlspace): down out of the box, along the joists, up into the next box. Not on a slab floor — it uses the ceiling there instead."],
      ["above", "From the ceiling", "Each outlet is fed from the ceiling: up the wall from the box, across the ceiling, back down to the next. The most cable — for walls you can't drill along, like block walls or finished walls."]] },
  { key: "wall_max_ft", label: "Longest outlet-to-outlet run through the studs (ft)", step: "1", when: f => f.outlets_via === "walls",
    tip: "Outlets farther apart than this aren't chained through the studs — the cable goes the floor's feed way (down and under, or up and over) to reach the next one." },
  { key: "upper_feed", label: "Upper floors fed from", tip: "How cable reaches the second floor and above. It always goes up a chase (a hollow wall) from the panel first.",
    choices: [
      ["below", "Floor framing under them", "From the chase, cable runs across in the floor joists between the floors, then up into the upstairs walls. Usual for a two-storey house."],
      ["above", "The attic", "The chase goes all the way up to the attic; cable runs across the attic and drops down into the walls of the top floor. Usual when the floor between the storeys is closed off."]] },
  { key: "ceiling_ft", label: "Ceiling height (ft)", step: "0.5" },
  { key: "floor_framing_ft", label: "Floor framing between floors (ft)", step: "0.25" },
  { key: "receptacle_in", label: "Outlet box height (in)", step: "1", tip: "Typical 12–18\"." },
  { key: "switch_in", label: "Switch box height (in)", step: "1", tip: "Typical 48\"." },
  { key: "counter_in", label: "Counter outlet height (in)", step: "1", tip: "Kitchen and bath GFCI outlets over the counter, typical 42–44\"." },
  { key: "wall_detour", label: "Extra on runs through the studs (%)", pct1: true, step: "5", tip: "Round corners and openings — 10–25%." },
  { key: "makeup_ft_per_end", label: "Spare wire per cable end at a box (ft)", step: "0.5", tip: "Code wants at least 6\"; most leave 8–12\"." },
  { key: "panel_makeup_ft", label: "Spare wire inside the panel (ft)", step: "0.5" },
  { key: "waste", label: "Waste on the order (%)", pct: true, step: "1", tip: "10–15% is usual." },
];

function wireOptValue(o, v) {                  // stored value -> what the box shows
  if (o.pct) return v == null ? "" : String(Math.round(v * 100));
  if (o.pct1) return v == null ? "" : String(Math.round((v - 1) * 100));
  return v == null ? "" : String(v);
}
function wireOptStore(o, s) {                   // what the box shows -> stored value
  if (s === "" || s == null) return null;
  const n = parseFloat(s);
  if (o.pct) return n / 100;
  if (o.pct1) return 1 + n / 100;
  return n;
}

function closeWiringOptions() { const p = $("bp-wiring-options"); if (p) p.remove(); }

async function openWiringOptions(btn) {
  closeWiringOptions();
  let w;
  try { w = await api("GET", "/wiring/" + RV.estimateId); }
  catch (e) { if (e.status !== 401) toast("Couldn't open the wiring options — " + (e.message || "error")); return; }
  if (!w.can_run) {
    const src = w.sources || {};
    toast("The wiring can't run yet: " + (src.plan ? "only owners and estimators can run it."
      : "upload the electrical floor plan as a DXF (CAD) file on the Plans screen (the panel drawing is used when there is one)."));
    return;
  }
  const opts = w.options || { current: {}, saved: {}, builtin: {} };
  const f = { ...opts.current, route: { ...(opts.current.route || {}) },
              method_by_floor: { ...(opts.current.method_by_floor || {}) } };
  if (!f.method) f.method = "nm";
  const panel = el("div", { class: "card bp-audit bp-wire-options", id: "bp-wiring-options", role: "dialog", "aria-label": "Wiring options" });
  for (const ev of ["pointerdown", "mousedown", "wheel"]) panel.addEventListener(ev, e => e.stopPropagation());
  const close = el("button", { class: "button", type: "button", id: "bp-wiring-options-close", "aria-label": "Close" }, "✕");
  close.addEventListener("click", closeWiringOptions);
  const body = el("div", { id: "bp-wiring-options-body" });
  const draw = () => {
    const rows = [];
    for (const o of WIRE_OPTIONS) {
      if (o.when && !o.when(f)) continue;
      const id = "bp-wire-" + o.key;
      let input;
      if (o.check) {
        input = el("input", { type: "checkbox", id, checked: f[o.key] ? "" : null });
        input.addEventListener("change", () => { f[o.key] = input.checked; });
        rows.push(el("div", { class: "bp-wire-opt" }, el("label", { for: id }, input, " " + o.label),
          o.tip ? el("div", { class: "muted small" }, o.tip) : null));
        continue;
      }
      if (o.choices) {
        input = el("select", { id }, o.choices.map(([v, t]) => el("option", {
          value: v, disabled: o.key === "outlets_via" && v === "below" && f.foundation === "slab" ? "" : null },
          t + (o.key === "outlets_via" && v === "below" && f.foundation === "slab" ? " (not on a slab)" : ""))));
        input.value = f[o.key];
        input.addEventListener("change", () => {
          f[o.key] = input.value;
          if (f.foundation === "slab" && f.outlets_via === "below") f.outlets_via = "walls";   // never in the slab
          draw();
        });
        // What the picked choice does to the routing, under the box (the general tip comes after it).
        const picked = o.choices.find(c => c[0] === f[o.key]);
        rows.push(el("div", { class: "bp-wire-opt" }, el("label", { for: id }, o.label), input,
          picked && picked[2] ? el("div", { class: "small bp-wire-choice-help", id: id + "-help" },
            el("strong", {}, picked[1] + ": "), picked[2]) : null,
          o.tip ? el("div", { class: "muted small" }, o.tip) : null));
        continue;
      } else {
        input = el("input", { type: "number", id, step: o.step || "any", value: wireOptValue(o, f[o.key]) });
        input.addEventListener("input", () => { f[o.key] = wireOptStore(o, input.value); });
      }
      rows.push(el("div", { class: "bp-wire-opt" }, el("label", { for: id }, o.label), input,
        o.tip ? el("div", { class: "muted small" }, o.tip) : null));
    }
    // A floor forced one way for this project only (rare: an open ceiling, a finished basement with no access).
    const floors = (RV.wiring && RV.wiring.run && RV.wiring.run.floors) || [];
    if (floors.length) {
      const force = floors.map(fl => {
        const sel = el("select", { id: "bp-wire-route-" + fl.index, "data-floor": String(fl.index) },
          el("option", { value: "" }, "As above"), el("option", { value: "ceiling" }, "Everything through the ceiling"),
          el("option", { value: "walls" }, "Everything through the walls"));
        sel.value = f.route[String(fl.index)] || "";
        sel.addEventListener("change", () => { if (sel.value) f.route[String(fl.index)] = sel.value; else delete f.route[String(fl.index)]; });
        // 2026-11-23: a floor wired another way (a finished upstairs in NM-B, an unfinished basement in EMT)
        const how = el("select", { id: "bp-wire-method-" + fl.index, "data-floor": String(fl.index), "aria-label": fl.name + " wiring method" },
          el("option", { value: "" }, "Same wiring method"), el("option", { value: "nm" }, "NM-B cable in the walls"),
          el("option", { value: "emt" }, "EMT conduit on the surface"), el("option", { value: "pvc" }, "PVC conduit on the surface"));
        how.value = f.method_by_floor[String(fl.index)] || "";
        how.addEventListener("change", () => { if (how.value) f.method_by_floor[String(fl.index)] = how.value; else delete f.method_by_floor[String(fl.index)]; });
        return el("div", { class: "bp-wire-opt" }, el("label", { for: sel.id }, fl.name + " — this project only"), sel, how);
      });
      rows.push(el("details", { class: "small", id: "bp-wire-force" }, el("summary", {}, "Force a floor one way, or wire it another way (this project only)"), ...force));
    }
    body.replaceChildren(...rows);
  };
  draw();
  const save = el("input", { type: "checkbox", id: "bp-wiring-save-default" });
  const mine = el("button", { class: "button small", type: "button", id: "bp-wiring-options-mine" },
    Object.keys(opts.saved || {}).length ? "Back to my defaults" : "Back to the built-in defaults");
  mine.addEventListener("click", () => {
    Object.assign(f, opts.builtin, opts.saved || {});
    f.route = {};
    f.method_by_floor = {};
    draw();
  });
  const run = el("button", { class: "primary", type: "button", id: "bp-wiring-options-run" }, "⚡ Run wiring");
  const out = el("div", { id: "bp-wiring-options-out" });
  run.addEventListener("click", async () => {
    const settings = {};
    for (const o of WIRE_OPTIONS) if (f[o.key] !== null && f[o.key] !== undefined && f[o.key] !== "") settings[o.key] = f[o.key];
    settings.route = { ...f.route };
    settings.method_by_floor = { ...f.method_by_floor };
    try {
      if (save.checked) await api("POST", "/wiring/defaults", { settings });
    } catch (e) { if (e.status !== 401) out.replaceChildren(errorBox(e)); return; }
    closeWiringOptions();
    await doRunWiring(btn, settings, (RV.wiring && RV.wiring.run && RV.wiring.run.overrides) || RV.wiringMoves || {}, save.checked);
  });
  panel.append(
    el("div", { class: "bp-audit-head" }, el("strong", {}, "⚡ Wiring options — how the cable runs"), close),
    el("p", { class: "muted small" }, "Started from " + (opts.from || "the built-in defaults") +
      ". The run measures every cable this way; change anything, then Run."),
    body, out,
    el("div", { class: "row bp-audit-foot" }, run, el("label", { for: save.id, class: "small" }, save, " Save as my defaults"), mine));
  document.body.append(panel);
}

// Run it with these settings, keep its routes on the plan (on the floor plan's sheet) and show the result.
async function doRunWiring(btn, settings, overrides, saved) {
  const was = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "⚡ Routing…"; }
  try {
    const r = await api("POST", "/wiring/" + RV.estimateId, { settings, overrides: overrides || {}, keep_approved: keepApprovedNow() });
    wiringReset({ ...(RV.wiring || {}), run: r.run });
    RV.wiringFor = RV.estimateId;
    RV.showWiring = true;
    RV.wiringPick = null; RV.wiringSize = null; RV.wiringLit = null; RV.wiringMark = null;
    const n = (r.run.measurement_ids || []).length;
    const sug = (r.run.suggested_ids || []).length;       // approved items the new run measured differently
    toast("Wiring done" + (saved ? " (and saved as your defaults)" : "") + " — " +
      (n ? n + " item(s) waiting for approval; click a cable in the list to light up its circuits" : "") +
      (sug ? (n ? "; " : "") + sug + " approved item(s) changed — ✓ Accept the new lengths in the ⚡ Wiring card" : "") +
      (!n && !sug ? "nothing changed (the approved cable already matches)" : "") + ".");
    const planSheet = r.run.sources && r.run.sources.plan && r.run.sources.plan.sheet_id;
    if (planSheet && planSheet !== RV.sheetId) await auditGoToSheet(planSheet, $("review-message"));
    await refreshData();
    renderWiring();
    drawWiringRoutes();
    if ($("bp-audit")) await openAudit();
  } catch (e) {
    if (e.status === 401) return;
    const m = $("bp-wiring-msg");
    if (m) m.replaceChildren(errorBox(e)); else toast("The wiring run didn't work — " + (e.message || "unknown error"));
  } finally {
    if (btn && btn.isConnected) { btn.disabled = false; btn.textContent = was; }
  }
}

// A rerun from the Wiring card (device moves): the last run's routing, no options box.
async function runWiring(btn, overrides) {
  const settings = { ...((RV.wiring && RV.wiring.run && RV.wiring.run.settings) || {}) };
  const msg = $("bp-wiring-msg");
  if (msg) msg.replaceChildren();
  const was = btn.textContent;
  btn.disabled = true; btn.textContent = "Routing…";
  try {
    const r = await api("POST", "/wiring/" + RV.estimateId, { settings, overrides: overrides || RV.wiringMoves || {},
                                                              keep_approved: keepApprovedNow() });
    wiringReset({ ...RV.wiring, run: r.run });
    RV.showWiring = true;
    const n = r.run.bom.length;
    const sug = (r.run.suggested_ids || []).length;
    toast("Wiring done — " + n + " cable size" + (n === 1 ? "" : "s") + " routed; " +
      (sug ? sug + " approved item(s) changed — accept the new lengths below" : "approve the cable below to price it"));
    await refreshData();          // the proposals show in the list; the guide (and this panel) redraws
  } catch (e) {
    const m = $("bp-wiring-msg");
    if (e.status !== 401 && m) m.replaceChildren(errorBox(e));
  } finally { btn.disabled = false; btn.textContent = was; }
}

// 2026-11-23 (David: surface conduit "with a basic expansion coefficient ... so the structure will last"): what the run
// measured for the conduit, and every straight leg's thermal movement - the ones that get an expansion fitting first.
function conduitBlock(c) {
  const items = el("table", { id: "bp-wiring-conduit" }, el("tr", {}, el("th", {}, "Conduit and fittings"), el("th", { class: "n" }, "Qty")));
  for (const it of c.items || []) items.append(el("tr", { title: it.how },
    el("td", {}, it.label.replace(/ \(wiring\)$/, "")), el("td", { class: "n" }, num(it.qty) + " " + it.unit)));
  const exp = c.expansion || [];
  const rows = exp.map(e => el("tr", { class: e.fittings ? "bp-exp-yes" : null },
    el("td", {}, e.run), el("td", {}, e.material.toUpperCase() + " " + e.size + " in" + (e.outdoor ? " · outside" : "")),
    el("td", { class: "n" }, num(e.leg_ft) + " ft"), el("td", { class: "n" }, num(e.swing_f) + " °F"),
    el("td", { class: "n" }, e.movement_in.toFixed(2) + " in"), el("td", { class: "n" }, e.fittings ? String(e.fittings) : "—")));
  const expTable = exp.length ? el("table", { id: "bp-wiring-expansion", class: "small" },
    el("tr", {}, el("th", {}, "Straight leg"), el("th", {}, "Conduit"), el("th", { class: "n" }, "Length"),
      el("th", { class: "n" }, "Swing"), el("th", { class: "n" }, "Moves"), el("th", { class: "n" }, "Fittings")), ...rows) : null;
  return el("div", { id: "bp-wiring-conduit-box" },
    el("p", { class: "small" }, el("strong", {}, "🔩 Surface conduit: "),
      c.runs + " runs · " + [["emt", "EMT"], ["pvc", "PVC"]].filter(([k]) => (c.total_ft || {})[k]).map(([k, n]) => num(c.total_ft[k]) + " ft " + n).join(" · ") +
      " · " + (c.expansion_fittings ? c.expansion_fittings + " expansion fitting" + (c.expansion_fittings === 1 ? "" : "s") : "no expansion fittings needed")),
    items,
    el("details", { id: "bp-wiring-expansion-box", open: c.expansion_fittings ? "" : null },
      el("summary", { class: "small" }, "Thermal expansion — movement = coefficient × leg × temperature swing"),
      expTable || el("p", { class: "small muted" }, "No straight leg moves enough to matter."),
      el("ul", { class: "small muted" }, ...(c.notes || []).map(n => el("li", {}, n)))));
}

function wiringResults(run, canRun) {
  const out = [];
  const devices = run.circuits.reduce((a, c) => a + c.devices, 0);
  out.push(el("p", { class: "small", id: "bp-wiring-summary" }, "Last run " + new Date(run.ran_at).toLocaleString() + " · " +
    run.circuits.length + " circuits · " + devices + " devices" + (run.unassigned.length ? " · " + run.unassigned.length + " not on a circuit" : "")));

  // Cable for the Bill of Materials
  const bom = el("table", { id: "bp-wiring-bom" }, el("tr", {}, el("th", {}, "Cable / wire"), el("th", { class: "n" }, "Routed ft"),
    el("th", { class: "n" }, "Order ft (+waste)"), el("th", { class: "n" }, "Rolls / spools")));
  for (const b of run.bom) bom.append(el("tr", {}, el("td", {}, b.cable), el("td", { class: "n" }, num(b.measured_ft)),
    el("td", { class: "n" }, num(b.order_ft)), el("td", { class: "n" }, b.rolls + " × " + (b.roll_ft || 250) + " ft")));
  out.push(bom);
  if (run.conduit) out.push(conduitBlock(run.conduit));

  // Its measurements: approve to price them; after a rerun, approved ones carry the new length as a suggestion.
  // 2026-11-21: plus the approved ones the rerun measured differently (kept, with the new value suggested).
  const ours = new Set([...(run.measurement_ids || []), ...(run.suggested_ids || [])]);
  const mine = ((RV.data && RV.data.takeoff.measurements) || []).filter(m => ours.has(m.id));
  const waiting = mine.filter(m => m.status === "proposed");
  const suggested = mine.filter(m => m.status === "approved" && m.suggested_qty !== null && m.suggested_qty !== undefined);
  const approved = mine.filter(m => m.status === "approved");
  const act = el("div", { id: "bp-wiring-approve" });
  const counts = waiting.filter(m => m.kind === "count").length;
  const what = counts ? " (cable lengths plus the breaker and range/dryer receptacle counts)" : "";
  const note = waiting.length ? waiting.length + " wiring measurement" + (waiting.length === 1 ? "" : "s") + what + " waiting for approval — once approved they price the estimate and the BOM in place of the average-run wire guess."
    : suggested.length ? "The rerun changed " + suggested.length + " approved wiring measurement" + (suggested.length === 1 ? "" : "s") + " — accept the new values to use them."
    : approved.length ? "✓ Cable approved — the cable, breakers and receptacles from the wiring price the estimate and the BOM." : "";
  if (note) out.push(el("p", { class: "small" + (approved.length && !waiting.length && !suggested.length ? "" : " note"), id: "bp-wiring-state" }, note));
  if (canRun && waiting.length) {
    const b = el("button", { class: "primary", type: "button", id: "bp-wiring-approve-btn" }, counts ? "✓ Approve the cable and counts…" : "✓ Approve the cable…");
    b.addEventListener("click", () => reviewAsk(act, b, "/measurements/approve", { measurement_ids: waiting.map(m => m.id) },
      x => x.done.length + " wiring measurement(s) approved", "bp-wiring-approve", false, true));
    out.push(el("div", { class: "row" }, b), act);
  } else if (canRun && suggested.length) {
    const b = el("button", { class: "primary", type: "button", id: "bp-wiring-accept-btn" }, "Accept the new lengths…");
    b.addEventListener("click", () => reviewAsk(act, b, "/measurements/approve", { measurement_ids: suggested.map(m => m.id), accept_suggestion: true },
      x => x.done.length + " cable length(s) updated", "bp-wiring-accept", false, true));
    out.push(el("div", { class: "row" }, b), act);
  }

  // Show on the plan + download
  const show = el("input", { type: "checkbox", id: "bp-wiring-show", checked: RV.showWiring ? "" : null });
  show.addEventListener("change", () => { RV.showWiring = show.checked; drawWiringRoutes(); });
  const onSheet = run.sources && run.sources.plan && run.sources.plan.sheet_id === RV.sheetId;
  const dl = el("button", { class: "button", type: "button", id: "bp-wiring-dxf" }, "⬇ Wiring drawing (DXF)");
  dl.addEventListener("click", () => downloadWiringDxf(dl, "dxf"));
  // 2026-11-20 (David: "make a wiring schematic diagram that shows wires, and save it as a DXF")
  const sch = run.schematic ? el("button", { class: "button", type: "button", id: "bp-wiring-schematic",
    title: "The panel, its breakers and every circuit's conductors (black, red, white, ground) out to its devices - a DXF" },
    "⬇ Wiring schematic (DXF)") : null;
  if (sch) sch.addEventListener("click", () => downloadWiringDxf(sch, "schematic"));
  // 2026-11-21 (David: "why does the file have to be downloaded when it can be just displayed or downloaded or both?")
  const viewDxf = el("button", { class: "button", type: "button", id: "bp-wiring-view-dxf",
    title: "Show the wiring drawing here - zoom and move around; download it from the viewer too" }, "👁 View wiring drawing");
  viewDxf.addEventListener("click", () => openWiringViewer("dxf"));
  const viewSch = run.schematic ? el("button", { class: "button", type: "button", id: "bp-wiring-view-schematic",
    title: "Show the wiring schematic here - zoom and move around; download it from the viewer too" }, "👁 View schematic") : null;
  if (viewSch) viewSch.addEventListener("click", () => openWiringViewer("schematic"));
  out.push(el("div", { class: "row" }, el("label", { for: "bp-wiring-show" }, show, " Show the routes on the plan")));
  out.push(el("div", { class: "row", id: "bp-wiring-files" }, viewDxf, dl, viewSch, sch));
  if (!onSheet && run.sources && run.sources.plan) {
    out.push(el("p", { class: "muted small" }, "The routes are drawn on the floor plan's sheet (" + run.sources.plan.name + ") — open it to see them."));
  }

  // Circuits: click one to pick it on the plan and move its devices
  const flags = run.circuits.flatMap(c => c.flags.map(f => c.id + ": " + f));
  const ct = el("table", { id: "bp-wiring-circuits" }, el("tr", {}, el("th", {}, "Circuit"), el("th", {}, "Cable"),
    el("th", { class: "n" }, "Devices"), el("th", { class: "n" }, "Feet")));
  run.circuits.forEach((c, i) => {
    const swatch = el("span", { class: "bp-wire-swatch" });
    swatch.style.backgroundColor = wireColor(i);       // set from script: the page's CSP refuses inline style attributes
    const tr = el("tr", { class: "bp-wire-row" + (RV.wiringPick === c.id ? " on" : ""), "data-circuit": c.id, tabindex: "0",
      title: "Show this circuit on the plan and move its devices" },
      el("td", {}, swatch, c.id + " — " + c.description + (c.flags.length ? " ⚠" : "")),
      el("td", {}, c.wire + (c.travelers_ft ? " (+3-way)" : "")),
      el("td", { class: "n" }, String(c.devices)), el("td", { class: "n" }, num(c.total_ft)));
    const pick = () => { RV.wiringPick = RV.wiringPick === c.id ? null : c.id; RV.wiringSize = null; RV.showWiring = true; renderWiring(); drawWiringRoutes(); };
    tr.addEventListener("click", pick);
    tr.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(); } });
    ct.append(tr);
  });
  out.push(el("h4", {}, "Circuits"), ct);
  if (flags.length) out.push(el("ul", { class: "small warn", id: "bp-wiring-flags" }, flags.map(f => el("li", {}, "⚠ " + f))));
  out.push(...drawingCheck(run, canRun));

  // Moving devices between circuits (and putting the unassigned ones on one)
  const picked = run.circuits.find(c => c.id === RV.wiringPick);
  const moves = RV.wiringMoves || {};
  const circuitSelect = (a, current) => {
    const sel = el("select", { "data-device": a.device, "aria-label": "Circuit for " + wireDevice(a), disabled: canRun ? null : "" },
      current ? null : el("option", { value: "" }, "— pick a circuit —"),
      run.circuits.map(c2 => el("option", { value: c2.id }, c2.id + " — " + c2.description)));
    sel.value = moves[a.device] || current || "";
    sel.addEventListener("change", () => {
      if (sel.value) moves[a.device] = sel.value; else delete moves[a.device];
      RV.wiringMoves = moves;
      renderWiring();
    });
    return sel;
  };
  if (picked) {
    out.push(el("h4", {}, picked.id + " — devices"), el("ul", { class: "bp-rows", id: "bp-wiring-devices" },
      picked.assigned.map(a => el("li", { class: "bp-row" }, el("span", { class: "bp-row-name" }, wireDevice(a), el("br", {}),
        el("span", { class: "muted small" }, a.why || "")), circuitSelect(a, picked.id)))));
  }
  if (run.unassigned.length) {
    out.push(el("h4", {}, "Not on a circuit"), el("ul", { class: "bp-rows", id: "bp-wiring-unassigned" },
      run.unassigned.map(a => el("li", { class: "bp-row" }, el("span", { class: "bp-row-name" }, wireDevice(a)), circuitSelect(a, null)))));
  }
  const changed = JSON.stringify(moves) !== JSON.stringify(run.overrides || {});
  if (canRun && changed) {
    const n = Object.keys(moves).filter(k => moves[k] !== (run.overrides || {})[k]).length;
    const b = el("button", { class: "primary", type: "button", id: "bp-wiring-rerun" }, "⚡ Run again with " + n + " device move(s)");
    b.addEventListener("click", () => runWiring(b, moves));
    out.push(el("div", { class: "row" }, b));
  }
  if (canRun && Object.keys(run.overrides || {}).length) {
    const b = el("button", { class: "button", type: "button", id: "bp-wiring-clear-moves" }, "Undo all device moves and run again");
    b.addEventListener("click", () => { RV.wiringMoves = {}; runWiring(b, {}); });
    out.push(el("div", { class: "row" }, b));
  }
  return out;
}

// 2026-11-20 (David): the run checked against the circuit lines the designer drew on the plan (E-CIRCUIT). Each
// difference: a "Show" (the device on the drawing) and a one-click "Move to C-4" that runs the wiring again.
function drawingCheck(run, canRun) {
  const ck = run.drawing_check;
  if (!ck || !ck.lines) return [];
  const diffs = ck.differ || [];
  const head = "🔎 Checked against the circuit lines on the drawing: " + ck.matched + " of " + (ck.matched + diffs.length)
    + " circuit(s) agree" + (diffs.length ? " — " + diffs.length + " to check" : " ✓");
  const parts = [el("p", { class: "small" + (diffs.length ? " note" : ""), id: "bp-wiring-check" }, head)];
  const rows = diffs.map(d => {
    const li = el("li", { class: "bp-row", "data-device": d.device || "" });
    if (d.what === "device") {
      const all = run.circuits.flatMap(c => c.assigned);
      const a = all.find(x => x.device === d.device) || { item_type: d.item_type, room: d.room };
      li.append(el("span", { class: "bp-row-name" }, wireDevice(a), el("br", {}),
        el("span", { class: "muted small" }, "drawing: " + d.circuit + " · wiring run: " + (d.run_circuit || "none"))));
      if (canRun) {
        const mv = el("button", { class: "button small bp-wiring-check-move", type: "button" }, "Move to " + d.circuit);
        mv.addEventListener("click", () => {
          RV.wiringMoves = { ...(RV.wiringMoves || {}), [d.device]: d.circuit };
          runWiring(mv, RV.wiringMoves);
        });
        li.append(mv);
      }
      // Where the device is on the sheet: the overlay lists each circuit's devices (sheet coordinates) in the same
      // order as the circuit's assigned devices.
      const rc = run.circuits.find(c => c.id === d.run_circuit);
      const oc = rc && run.overlay && run.overlay.circuits.find(c => c.id === rc.id);
      const at = oc ? oc.devices[rc.assigned.findIndex(x => x.device === d.device)] : null;
      if (at) {
        const show = el("button", { class: "button small bp-wiring-check-show", type: "button" }, "Show");
        show.addEventListener("click", async () => {
          const sheet = run.sources && run.sources.plan && run.sources.plan.sheet_id;
          if (typeof auditGoToSheet === "function") await auditGoToSheet(sheet, $("review-message"));
          RV.wiringPick = d.run_circuit; RV.wiringSize = null; RV.showWiring = true;
          renderWiring(); drawWiringRoutes();
          if (RV.viewer) RV.viewer.zoomToBox([at[0] - 6, at[1] - 6, at[0] + 6, at[1] + 6]);
        });
        li.append(show);
      }
    } else {
      li.append(el("span", { class: "bp-row-name" }, d.circuit + ": the drawing runs it up the riser; the wiring run keeps it downstairs"));
    }
    return li;
  });
  if (rows.length) parts.push(el("ul", { class: "bp-rows", id: "bp-wiring-check-list" }, rows));
  if ((ck.not_drawn || []).length) parts.push(el("p", { class: "small muted" }, "No circuit line on the drawing for: " + ck.not_drawn.join(", ") + "."));
  if ((ck.not_in_schedule || []).length) parts.push(el("p", { class: "small warn" }, "⚠ On the drawing but not in the panel schedule: " + ck.not_in_schedule.join(", ") + "."));
  return parts;
}

function drawWiringRoutes() {
  const old = $("bp-wiring-routes");
  if (old) old.remove();
  const oldKey = $("bp-wiring-key");
  if (oldKey) oldKey.remove();
  const meas = $("bp-measurements");
  const run = RV.wiring && RV.wiring.run;
  if (!meas || !RV.showWiring || !run || !run.overlay || !run.sources || !run.sources.plan
      || run.sources.plan.sheet_id !== RV.sheetId) return;
  // A picked circuit stands out; or (2026-11-20, the audit's "Show on drawing" for a cable size) every circuit of
  // that cable size does.
  // ... or (2026-11-20, Show on drawing for the breakers / range / dryer receptacles) the circuits behind that mark.
  const lit = !RV.wiringPick && RV.wiringLit && RV.wiringLit.length ? new Set(RV.wiringLit) : null;
  const bySize = !RV.wiringPick && (lit ? true : RV.wiringSize && run.overlay.circuits.some(c => c.wire === RV.wiringSize));
  const g = svg("g", { id: "bp-wiring-routes", class: RV.wiringPick || bySize || RV.conduitFeeds ? "picked" : "" });
  const info = new Map((run.circuits || []).map(c => [c.id, c]));
  run.overlay.circuits.forEach((c, i) => {
    const col = wireColor(i);
    const on = RV.wiringPick ? RV.wiringPick === c.id : bySize && (lit ? lit.has(c.id) : c.wire === RV.wiringSize);
    const cg = svg("g", { class: "bp-wire-c" + (on ? " on" : ""), "data-circuit": c.id });
    // 2026-11-20 (David: "I can't hover over a line and see what wire size it is, what breaker it's on and what it
    // powers"): each circuit says so on hover; a wide invisible line under each wire makes it easy to point at.
    const t = svg("title", {});
    t.textContent = circuitText(c, info.get(c.id)) + "\nClick: show only this circuit";
    cg.append(t);
    for (const line of c.lines) {
      if (line.length < 2) continue;
      const pts = line.map(p => p.join(",")).join(" ");
      cg.append(svg("polyline", { points: pts, class: "bp-wire-hit" }), svg("polyline", { points: pts, class: "bp-wire", stroke: col }));
    }
    for (const p of c.devices) cg.append(svg("polyline", { points: p.join(",") + " " + p.join(","), class: "bp-wire-dev", stroke: col }));
    g.append(cg);
  });
  g.append(...wiringAddedMarks(run));
  if (RV.conduitFeeds) g.append(...conduitMarks(run));
  meas.parentNode.insertBefore(g, meas);      // over the plan, under the measurements
  drawWiringKey(run, info, bySize);
}

// 2026-11-20 (David: "3 of these items don't have symbols, can they be added to the drawing"): what the wiring run
// prices that the designer drew no symbol for - a receptacle mark at the range and the dryer, the branch breaker count
// at the panel. Drawn with the routes (and on the wiring DXF), never into the designer's plan. Sized to the drawing.
const ADDED_LETTER = { range_receptacle: "R", dryer_receptacle: "D", branch_breakers: "B" };
function wiringAddedMarks(run) {
  const added = (run.overlay && run.overlay.added) || [];
  if (!added.length) return [];
  const pts = run.overlay.circuits.flatMap(c => [...c.lines.flat(), ...c.devices]).concat(added.map(a => a.at));
  const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
  const r = Math.max(Math.max(...xs) - Math.min(...xs), Math.max(...ys) - Math.min(...ys)) / 90 || 1;
  return added.map(a => {
    const on = RV.wiringMark ? RV.wiringMark === a.feeds : true;
    const m = svg("g", { class: "bp-wire-added" + (RV.wiringMark === a.feeds ? " on" : on ? "" : " off"),
      "data-added": a.kind, "data-feeds": a.feeds });
    const t = svg("title", {});
    t.textContent = a.label + "\nAdded by the wiring run - the designer's drawing has no symbol for this.";
    m.append(t);
    const [x, y] = a.at;
    m.append(a.kind === "branch_breakers"
      ? svg("rect", { x: x - r, y: y - r, width: 2 * r, height: 2 * r, class: "bp-wire-added-mark" })
      : svg("circle", { cx: x, cy: y, r: r, class: "bp-wire-added-mark" }));
    const letter = svg("text", { x: x, y: y + r * 0.4, "font-size": r * 1.2, class: "bp-wire-added-letter" });
    letter.textContent = ADDED_LETTER[a.kind] || "+";
    const label = svg("text", { x: x + r * 1.4, y: y + r * 0.4, "font-size": r * 0.9, class: "bp-wire-added-label" });
    label.textContent = a.label;
    m.append(letter, label);
    return m;
  });
}

// 2026-11-23 (David: "Cant see a visual of the conduit, so how can I review it?"): click a conduit, fitting, box or
// THHN measurement and the conduit runs it counts are drawn on the plan - EMT grey, PVC blue, thicker for bigger pipe -
// with the size and length on each, the expansion fittings (⇔), the conduit bodies (LB) and the elbows marked; the
// other runs and the circuits not in them fade.
const CONDUIT_SIZE = { "050": "1/2", "075": "3/4", "100": "1" };
function conduitMatch(feeds) {
  let mm;
  if ((mm = /^thhn_(\d+)_ft$/.exec(feeds))) {
    const g = +mm[1];
    // 2026-11-24 (David: "approving the 6 AWG run but why is it highlighting 12 AWG and other circuits?"): a home run
    // carries several circuits; only the circuits of this gauge light up, the conduits they share are still drawn.
    return { pick: r => (r.awg || []).includes(g), head: g + " AWG THHN", gauge: g };
  }
  if ((mm = /^(emt|pvc)_(050|075|100)_ft$/.exec(feeds))) {
    const size = CONDUIT_SIZE[mm[2]], mat = mm[1];
    return { pick: r => r.material === mat && r.size === size, head: size + " in " + mat.toUpperCase() };
  }
  if ((mm = /^(emt|pvc)_expansion$/.exec(feeds))) {
    const mat = mm[1];
    return { pick: r => r.material === mat && r.expansion_fittings > 0, head: mat.toUpperCase() + " expansion fittings", mark: "exp" };
  }
  if ((mm = /^(emt|pvc)_(elbows|couplings|connectors|straps)$/.exec(feeds))) {
    const mat = mm[1];
    return { pick: r => r.material === mat, head: mat.toUpperCase() + " " + mm[2], mark: mm[2] === "elbows" ? "bend" : null };
  }
  if (feeds === "conduit_bodies") return { pick: r => r.pull_points > 0, head: "Conduit bodies (LB) and pull points", mark: "lb" };
  if (feeds === "wp_boxes") return { pick: r => !!r.outdoor, head: "Weatherproof boxes — the runs outside" };
  if (feeds === "surface_boxes") return { pick: r => !r.outdoor, head: "Surface boxes — the runs inside" };
  return null;
}
function isConduitFeed(feeds) { return !!conduitMatch(feeds || ""); }
// "6/3" -> 6 (the gauge of a circuit's wire), null when it isn't a gauge/conductors size
function wireGauge(wire) { const mm = /^(\d+)\/\d$/.exec(wire || ""); return mm ? +mm[1] : null; }

function conduitMarks(run) {
  const runs = (run.overlay && run.overlay.conduit) || [];
  const match = conduitMatch(RV.conduitFeeds || "");
  if (!runs.length || !match) return [];
  const pts = runs.flatMap(r => r.line);
  const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
  const u = Math.max(Math.max(...xs) - Math.min(...xs), Math.max(...ys) - Math.min(...ys)) / 120 || 1;   // a marker size
  const lit = runs.filter(match.pick);
  const out = [svg("g", { id: "bp-conduit", "data-feeds": RV.conduitFeeds })];
  const grp = out[0];
  const W = { "1/2": 3, "3/4": 5, "1": 7 };
  runs.forEach((r, i) => {
    const on = match.pick(r);
    const cg = svg("g", { class: "bp-conduit-run" + (on ? " on" : "") + " " + r.material, "data-run": String(i) });
    const t = svg("title", {});
    t.textContent = r.what + "\n" + r.size + " in " + r.material.toUpperCase() + (r.outdoor ? " (outside)" : "") + " · "
      + num(r.length_ft) + " ft · " + r.bends + " bend(s)" + (r.expansion_fittings ? " · " + r.expansion_fittings + " expansion fitting(s)" : "")
      + (r.pull_points ? " · " + r.pull_points + " conduit body / pull point" : "") + (r.circuits && r.circuits.length ? "\nCircuits: " + r.circuits.join(", ") : "");
    cg.append(t);
    const line = r.line.length === 2 && r.line[0][0] === r.line[1][0] && r.line[0][1] === r.line[1][1]
      ? [r.line[0], [r.line[0][0] + u * 2, r.line[0][1]]] : r.line;           // the short stub out through a wall
    const p = line.map(q => q.join(",")).join(" ");
    cg.append(svg("polyline", { points: p, class: "bp-conduit-line", "stroke-width": (W[r.size] || 3) + (on ? 2 : 0) + "px" }));
    if (on) {
      // the label at the middle of its longest piece
      let best = [line[0], line[line.length - 1]], len = -1;
      for (let k = 1; k < line.length; k++) {
        const d = Math.hypot(line[k][0] - line[k - 1][0], line[k][1] - line[k - 1][1]);
        if (d > len) { len = d; best = [line[k - 1], line[k]]; }
      }
      const mx = (best[0][0] + best[1][0]) / 2, my = (best[0][1] + best[1][1]) / 2;
      if (lit.length <= 60) {
        const label = svg("text", { x: mx + u * 0.6, y: my - u * 0.6, "font-size": u * 1.6, class: "bp-conduit-label" });
        label.textContent = r.size + "\" " + r.material.toUpperCase() + " " + num(r.length_ft) + "'";
        cg.append(label);
      }
      if (match.mark === "exp" && r.expansion_fittings) {
        cg.append(svg("rect", { x: mx - u * 1.6, y: my - u, width: u * 3.2, height: u * 2, class: "bp-conduit-fit" }));
        const tx = svg("text", { x: mx, y: my + u * 0.55, "font-size": u * 1.5, class: "bp-conduit-fit-text" });
        tx.textContent = "⇔" + (r.expansion_fittings > 1 ? "×" + r.expansion_fittings : "");
        cg.append(tx);
      }
      if (match.mark === "lb" && r.pull_points) {
        const [ex, ey] = r.line[r.line.length - 1];
        cg.append(svg("circle", { cx: ex, cy: ey, r: u * 1.3, class: "bp-conduit-fit" }));
        const tx = svg("text", { x: ex, y: ey + u * 0.5, "font-size": u * 1.2, class: "bp-conduit-fit-text" });
        tx.textContent = "LB";
        cg.append(tx);
      }
      if (match.mark === "bend") {
        for (let k = 1; k < line.length - 1; k++) {
          const a = line[k - 1], b = line[k], c = line[k + 1];
          if ((a[0] === b[0] && a[1] === b[1]) || (b[0] === c[0] && b[1] === c[1])) continue;
          cg.append(svg("circle", { cx: b[0], cy: b[1], r: u * 0.7, class: "bp-conduit-bend" }));
        }
      }
    }
    grp.append(cg);
  });
  return out;
}

// A circuit's wire as it's installed: "12/2" for NM cable; in conduit (2026-11-23) "12 AWG THHN ×3 in EMT" - its hots
// and neutral plus the green ground, pulled in the pipe.
function wireLabel(c, f) {
  const run = RV.wiring && RV.wiring.run;
  const how = run && run.conduit && run.conduit.methods && f && f.floor != null ? run.conduit.methods[String(f.floor)] : null;
  if (!how || how === "nm" || !/^\d+\/\d$/.test(c.wire || "")) return c.wire;
  const [gauge, n] = c.wire.split("/");
  return gauge + " AWG THHN ×" + (Number(n) + 1) + " in " + how.toUpperCase();
}

// "C-1 · Living / Dining receptacles · 20 A breaker (120 V) · 12/2 cable · 13 devices · 322.9 ft"
function circuitText(c, full) {
  const f = full || {};
  const amps = f.amps ? f.amps + " A" + (f.poles === 2 ? " 2-pole breaker (240 V)" : " breaker") : "";
  const w = wireLabel(c, f);
  return [c.id, f.description, amps, (w === c.wire ? c.wire + " cable" : w) + (f.travelers_ft ? " (+ 3-way travelers)" : ""),
          f.devices != null ? f.devices + " device" + (f.devices === 1 ? "" : "s") : "",
          f.total_ft != null ? num(f.total_ft) + " ft" : ""].filter(Boolean).join(" · ") +
         (f.flags && f.flags.length ? "\n⚠ " + f.flags.join("; ") : "");
}

// 2026-11-20 (David: "there is no color code saying red is one circuit, yellow is another"): a colour key on the
// drawing - one row per circuit, with its colour, breaker, cable and what it powers. Click a row to show only that
// circuit (click again for all of them). With a cable size picked (the audit's Show on drawing), its circuits lead.
function drawWiringKey(run, info, bySize) {
  const old = $("bp-wiring-key");
  if (old) old.remove();
  const box = RV.viewer && RV.viewer.box;
  if (!box) return;
  const key = el("div", { class: "bp-wiring-key", id: "bp-wiring-key", role: "list", "aria-label": "Wiring colour key" });
  for (const ev of ["pointerdown", "mousedown", "wheel", "click"]) key.addEventListener(ev, e => e.stopPropagation());
  const close = el("button", { class: "button small", type: "button", id: "bp-wiring-key-hide", title: "Hide the wiring routes" }, "✕");
  close.addEventListener("click", () => { RV.showWiring = false; wiringClearFocus(); renderWiring(); drawWiringRoutes(); });
  const lit = !RV.wiringPick && RV.wiringLit && RV.wiringLit.length ? new Set(RV.wiringLit) : null;
  const MARK_HEAD = { branch_circuits: "Branch breakers", range_receptacles: "Range receptacle", dryer_receptacles: "Dryer receptacle" };
  const cm = RV.conduitFeeds ? conduitMatch(RV.conduitFeeds) : null;
  const cruns = cm ? (run.overlay.conduit || []).filter(cm.pick) : [];
  const pipeFt = num(cruns.reduce((a, r) => a + (r.length_ft || 0), 0));
  const head = cm && cm.gauge && lit
      ? "🔩 " + cm.head + " — " + lit.size + " circuit" + (lit.size === 1 ? "" : "s") + " (" + [...lit].join(", ") + ") · in "
        + cruns.length + " conduit run" + (cruns.length === 1 ? "" : "s") + " (" + pipeFt + " ft of pipe; the conduits they share are drawn too)"
    : cm ? "🔩 " + cm.head + " — " + cruns.length + " run" + (cruns.length === 1 ? "" : "s") + " · " + pipeFt + " ft"
    : lit ? "⚡ " + (MARK_HEAD[RV.wiringMark] || (RV.wiringSize ? RV.wiringSize + " cable" : "Circuits")) + " — " + lit.size + " circuit" + (lit.size === 1 ? "" : "s")
    : bySize ? "⚡ " + RV.wiringSize + " circuits" : RV.wiringPick ? "⚡ Circuit " + RV.wiringPick : "⚡ Wiring — " + run.overlay.circuits.length + " circuits";
  key.append(el("div", { class: "bp-wiring-key-head" }, el("strong", {}, head), close));
  run.overlay.circuits.forEach((c, i) => {
    const f = info.get(c.id) || {};
    const on = RV.wiringPick ? RV.wiringPick === c.id : !bySize || (lit ? lit.has(c.id) : c.wire === RV.wiringSize);
    const row = el("div", { class: "bp-wiring-key-row" + (on ? "" : " off") + (RV.wiringPick === c.id ? " picked" : ""),
      role: "listitem", tabindex: "0", "data-circuit": c.id, title: circuitText(c, f) },
      el("span", { class: "bp-wire-swatch", "data-color": String(i) }),
      el("span", {}, el("strong", {}, c.id), " " + (f.amps ? f.amps + "A " : "") + wireLabel(c, f) + (f.description ? " · " + f.description : "")
        + (f.flags && f.flags.length ? " ⚠" : "")));
    row.querySelector(".bp-wire-swatch").style.background = wireColor(i);
    const pick = () => pickCircuit(c.id);
    row.addEventListener("click", pick);
    row.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    key.append(row);
  });
  if (RV.wiringPick || bySize) {
    const all = el("button", { class: "button small", type: "button", id: "bp-wiring-key-all" }, "Show all circuits");
    all.addEventListener("click", () => { wiringClearFocus(); renderWiring(); drawWiringRoutes(); });
    key.append(all);
  }
  box.append(key);
}

// Nothing picked: every circuit and mark at full strength.
function wiringClearFocus() { RV.wiringPick = null; RV.wiringSize = null; RV.wiringLit = null; RV.wiringMark = null; RV.conduitFeeds = null; }

function pickCircuit(id) {
  RV.wiringPick = RV.wiringPick === id ? null : id;
  RV.wiringSize = null; RV.wiringLit = null; RV.wiringMark = null; RV.conduitFeeds = null; RV.showWiring = true;
  renderWiring(); drawWiringRoutes();
}

// A download that also works inside the Jobs app, where the Estimator is signed in by a token (no cookie).
// what: "dxf" (the wiring drawing) or "schematic" (2026-11-20: panel, breakers and each circuit's conductors)
async function downloadWiringDxf(btn, what) {
  btn.disabled = true;
  try {
    const opts = { credentials: "same-origin", headers: {} };
    if (APP_TOKEN) opts.headers["Authorization"] = "Bearer " + APP_TOKEN;
    const r = await fetch(API + "/wiring/" + RV.estimateId + "/" + (what || "dxf"), opts);
    if (!r.ok) {
      let data = null;
      try { data = await r.json(); } catch (e) { data = null; }
      throw new ApiError(r.status, data);
    }
    const name = ((r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/) || [])[1] || "wiring.dxf";
    const url = URL.createObjectURL(await r.blob());
    const a = el("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (e) {
    const m = $("bp-wiring-msg");
    // 2026-11-21: the toolbar's 📐 Wiring schematic has no Wiring card in view - say it in a toast.
    if (m && btn.closest("#bp-wiring")) m.replaceChildren(errorBox(e));
    else if (e.status !== 401) toast(e.status === 404 ? "No wiring schematic yet — click ⚡ Run wiring first; each run draws one."
                                                      : "The download didn't work — " + (e.message || "unknown error"));
  } finally { btn.disabled = false; }
}

// 2026-11-21 (David: "why does the file have to be downloaded when it can be just displayed or downloaded or both?"):
// the wiring drawing and the wiring schematic shown on the screen - the server draws the DXF as an SVG picture - with
// zoom (wheel, + / -), pan (drag), Fit, and the DXF download still one click away. what: "dxf" or "schematic".
const WIRING_VIEW = { dxf: "Wiring drawing — every circuit's route on the floor plan",
                      schematic: "Wiring schematic — the panel, its breakers and every circuit's conductors" };
async function openWiringViewer(what) {
  const other = what === "schematic" ? "dxf" : "schematic";
  return openDrawingViewer({
    title: WIRING_VIEW[what], url: "/wiring/" + RV.estimateId + "/" + what + "/svg",
    download: b => downloadWiringDxf(b, what),
    other: { label: other === "schematic" ? "📐 Schematic" : "🗺 Wiring drawing", title: "Show the other wiring drawing",
             go: () => openWiringViewer(other) } });
}

// 2026-11-21: the same viewer for any drawing the server shows as SVG (the wiring drawings, an AI design's plan and
// panel schedule). o: {title, url (API path of the SVG), download(button), other: {label, title, go}}.
async function openDrawingViewer(o) {
  closeWiringViewer();
  const v = { scale: 1, x: 0, y: 0, url: null };
  const img = el("img", { id: "bp-wiring-viewer-img", alt: o.title, draggable: "false" });
  const stage = el("div", { class: "bp-wv-stage", id: "bp-wiring-viewer-stage" },
    el("p", { class: "muted", id: "bp-wiring-viewer-loading" }, "Drawing it…"));
  const place = () => { img.style.transform = "translate(" + v.x + "px," + v.y + "px) scale(" + v.scale + ")"; };
  const fit = () => {
    if (!img.naturalWidth) return;
    const r = stage.getBoundingClientRect();
    v.scale = Math.min(r.width / img.naturalWidth, r.height / img.naturalHeight) * 0.96;
    v.x = (r.width - img.naturalWidth * v.scale) / 2;
    v.y = (r.height - img.naturalHeight * v.scale) / 2;
    place();
  };
  const zoomAt = (k, cx, cy) => {               // zoom by k about a point in the stage
    const s = Math.min(40, Math.max(0.05, v.scale * k));
    v.x = cx - (cx - v.x) * (s / v.scale); v.y = cy - (cy - v.y) * (s / v.scale); v.scale = s; place();
  };
  const mid = k => { const r = stage.getBoundingClientRect(); zoomAt(k, r.width / 2, r.height / 2); };
  const btn = (id, label, title, fn) => {
    const b = el("button", { class: "button", type: "button", id, title }, label);
    b.addEventListener("click", fn);
    return b;
  };
  const dl = btn("bp-wiring-viewer-download", o.downloadLabel || "⬇ Download DXF",
    o.downloadTitle || "Save the drawing as a DXF for any CAD program", () => o.download(dl));
  const box = el("div", { class: "bp-wv", id: "bp-wiring-viewer", role: "dialog", "aria-label": o.title },
    el("div", { class: "bp-wv-head" },
      el("strong", { id: "bp-wiring-viewer-title" }, o.title),
      el("span", { class: "bp-wv-btns" },
        btn("bp-wiring-viewer-in", "+", "Zoom in", () => mid(1.25)),
        btn("bp-wiring-viewer-out", "−", "Zoom out", () => mid(0.8)),
        btn("bp-wiring-viewer-fit", "Fit", "The whole drawing", fit),
        o.other ? btn("bp-wiring-viewer-other", o.other.label, o.other.title, o.other.go) : null,
        dl,
        btn("bp-wiring-viewer-x", "✕", "Close (Esc)", closeWiringViewer))),
    el("p", { class: "muted small bp-wv-hint" }, "Scroll to zoom, drag to move around."),
    stage);
  document.body.append(el("div", { class: "bp-wv-back", id: "bp-wiring-viewer-back" }, box));
  $("bp-wiring-viewer-back").addEventListener("click", e => { if (e.target.id === "bp-wiring-viewer-back") closeWiringViewer(); });
  document.addEventListener("keydown", wiringViewerKeys);
  stage.addEventListener("wheel", e => {
    e.preventDefault();
    const r = stage.getBoundingClientRect();
    zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });
  let drag = null;
  stage.addEventListener("pointerdown", e => { drag = { x: e.clientX - v.x, y: e.clientY - v.y }; stage.setPointerCapture(e.pointerId); stage.classList.add("dragging"); });
  stage.addEventListener("pointermove", e => { if (drag) { v.x = e.clientX - drag.x; v.y = e.clientY - drag.y; place(); } });
  const end = () => { drag = null; stage.classList.remove("dragging"); };
  stage.addEventListener("pointerup", end);
  stage.addEventListener("pointercancel", end);
  try {
    const opts = { credentials: "same-origin", headers: {} };
    if (APP_TOKEN) opts.headers["Authorization"] = "Bearer " + APP_TOKEN;
    const r = await fetch(API + o.url, opts);
    if (!r.ok) {
      let data = null;
      try { data = await r.json(); } catch (e) { data = null; }
      throw new ApiError(r.status, data);
    }
    v.url = URL.createObjectURL(await r.blob());
    WV_URL = v.url;
    img.addEventListener("load", () => { stage.replaceChildren(img); fit(); box.dataset.ready = "1"; }, { once: true });
    img.src = v.url;
  } catch (e) {
    if (e.status !== 401 && $("bp-wiring-viewer-stage")) stage.replaceChildren(errorBox(e));
  }
}
let WV_URL = null;
function wiringViewerKeys(e) { if (e.key === "Escape") closeWiringViewer(); }
function closeWiringViewer() {
  const b = $("bp-wiring-viewer-back");
  if (b) b.remove();
  document.removeEventListener("keydown", wiringViewerKeys);
  if (WV_URL) { URL.revokeObjectURL(WV_URL); WV_URL = null; }
}

function totalsText(ms) {
  const by = {};
  for (const m of ms) if (m.status !== "rejected") by[m.unit] = (by[m.unit] || 0) + parseFloat(m.qty || 0);
  const s = Object.entries(by).map(([u, v]) => num(v) + " " + u).join(" + ");
  return s || "nothing yet";
}

// 2026-11-20 (David: "why AI counted 18 but the highlighted shows 12"): AI Auto Run's and the wiring run's
// measurements sit on a sheet; one with no sheet is from before the plans were read again (its sheet went). Such an
// approved count is replaced when the new count for the same question is approved (the server retires it then).
const WIRING_AGENT = "wiring-takeoff";
const SHEET_AGENTS = ["llm-takeoff", WIRING_AGENT];
function isFromOldPlans(m) { return !m.sheet_id && SHEET_AGENTS.includes(m.proposed_by); }
function oldApproved(m) {
  if (!m.sheet_id || !m.feeds) return [];
  return RV.data.takeoff.measurements.filter(x => x.id !== m.id && x.status === "approved" && isFromOldPlans(x)
    && x.module_id === m.module_id && x.feeds === m.feeds);
}

function measurementRow(m, msg) {
  const flags = [m.locked ? "🔒" : "", m.suggested_qty !== null && m.suggested_qty !== undefined ? "✎ suggestion" : "", m.needs_remeasure ? "⚠ re-measure" : "",
    m.status !== "rejected" && isFromOldPlans(m) ? "⚠ from before the plans were read again" : ""].filter(Boolean).join(" ");
  const agent = m.proposed_by === AGENT || m.proposed_by === LLM_AGENT;
  const llm = m.proposed_by === LLM_AGENT;
  const li = el("li", { class: "bp-row " + m.status + (RV.measurementId === m.id ? " active" : ""), "data-mid": m.id, tabindex: "0" },
    el("span", { class: "bp-row-name" }, agent ? el("span", { class: "bp-agent", title: llm ? "Read from the plan by the AI" : "Proposed by the Concrete agent" }, "🤖 ") : null, measurementName(m)),
    el("span", { class: "bp-row-qty" }, num(m.qty) + " " + m.unit),
    el("span", { class: "status " + (m.status === "approved" ? "" : "sample") }, m.status === "proposed" ? "to review" : words(m.status)),
    el("span", { class: "muted small" }, pct(m.confidence) + " · " + words(m.method) + (flags ? " · " + flags : "") + (agent ? " · " + agentSourceText(m) : "")));
  if (m.proposed_by === AGENT) {   // LLM measurements have no outline to show
    const show = el("button", { class: "button", type: "button", id: "bp-show-outline-" + m.id }, "Show outline");
    show.addEventListener("click", ev => { ev.stopPropagation(); showAgentOutline(m); });
    li.append(show);
  }
  // 2026-11-19 (David): one click reviews it right here - its symbols light up on the drawing and the review card
  // opens under the row (no jump to the Detail tab). Click the row again to close it.
  const open = () => openReview(m, msg);
  li.addEventListener("click", open);
  li.addEventListener("keydown", ev => { if (ev.key === "Enter" && ev.target === li) open(); });
  if (RV.review && RV.review.mid === m.id) {
    li.classList.add("reviewing");
    li.append(reviewCard(m, msg));
  }
  return li;
}

// ------------------------------------------------------------------ inline review (2026-11-19, David)
// "The approval should consist of the drawing with highlighted symbols the user can count and reference to the
// Measurements tab's item selected to the right-hand side." One click on a measurement:
//   - its symbols light up on the drawing (the same symbols the To measure tab highlights), the rest fades;
//   - a review card opens under the row: what the AI counted and why, the count to approve with − / +, and the
//     number highlighted on the drawing;
//   - clicking a symbol on the drawing while the card is open takes it off the count or adds it (the count follows);
//   - ✓ Approve saves the count (changed first if it was changed) and moves on to the next one to review;
//   - the AI Log opens in a new browser tab, so this screen stays where it is.
const REVIEW_KINDS_COUNTED = new Set(["count"]);
function isCountMeasurement(m) { return REVIEW_KINDS_COUNTED.has(m.kind) || m.unit === "ea"; }

// The sheet a measurement belongs on: its own, or (a count taken from symbols on the plans, which has no sheet of its
// own) the sheet its symbols are on. 2026-11-24 (David: "it should automatically open the correct file ... it stayed
// on the architecture sheet").
function homeSheet(m) { return (m && (m.sheet_id || m.plan_sheet_id)) || null; }
async function goToHomeSheet(m, msg) {
  const sid = homeSheet(m);
  if (sid && sid !== RV.sheetId && $("review-sheet") && RV.data.sheets.some(s => s.id === sid)) {
    $("review-sheet").value = sid;
    await openSheet(sid, msg);
  }
}

async function openReview(m, msg) {
  if (RV.review && RV.review.mid === m.id) { closeReview(); return; }
  await goToHomeSheet(m, msg);
  // 2026-11-21 (David: "selecting each wiring estimate, I expected the wiring color code to popup and highlight the
  // wire routing"): a wiring run's cable has no symbols - its circuits light up on the floor plan with the colour key,
  // the other circuits faded; a breaker / range / dryer count lights up the run's mark and the circuits behind it.
  const wireSize = m.proposed_by === WIRING_AGENT && /^wire_(\d+)_(\d+)_ft$/.exec(m.feeds || "");
  // 2026-11-23 (David: "Cant see a visual of the conduit, so how can I review it?"): conduit, fittings, boxes and THHN
  // light up the conduit runs they count.
  const wireMark = m.proposed_by === WIRING_AGENT && (WIRING_MARK_FEEDS.includes(m.feeds) || isConduitFeed(m.feeds));
  if (wireSize || wireMark) {
    RV.review = { mid: m.id, objs: new Map(), count: parseFloat(m.qty || 0) || 0, aiQty: parseFloat(m.qty || 0) || 0 };
    const lit = wireSize ? await auditShowWiring(wireSize[1] + "/" + wireSize[2], msg)
                         : await auditShowWiring(null, msg, m.feeds);
    // The measurement says which circuits its cable is (a range's 10/2 on the schedule is priced as 10/3): light those.
    const mine = (wireSize || /^thhn_\d+_ft$/.test(m.feeds || "")) && m.calc && Array.isArray(m.calc.circuits) ? m.calc.circuits : [];
    if (mine.length && RV.wiring && RV.wiring.run && RV.wiring.run.overlay) {
      RV.wiringLit = mine;
      renderWiring(); drawWiringRoutes();
    }
    if (wireSize || lit) {
      RV.symbolType = null; RV.symbolList = []; RV.selected = new Set(); rehideRevealed();
      RV.countStep = null; markCountRows();
      RV.measurementId = m.id;
      drawMeasurements();
      showTab("list");
      refreshList(msg);
      return;
    }
  }
  const objs = isCountMeasurement(m) && m.feeds ? countSymbols(m.module_id, m.feeds) : [];
  const qty = parseFloat(m.qty || 0) || 0;
  // 2026-11-20 (David): the count to approve starts at what's lit up on the drawing (the AI's own number is shown
  // above it); an approved count stays as it was approved until the user changes it.
  const start = objs.length && m.status !== "approved" ? objs.length : qty;
  RV.review = { mid: m.id, objs: new Map(objs.map(o => [o.id, o])), count: start, aiQty: qty };
  if (objs.length) highlightSymbols(objs, symbolKey(objs[0]));      // lights them up and zooms to them
  else {
    RV.symbolType = null; RV.symbolList = []; RV.selected = new Set(); rehideRevealed();
  }
  RV.countStep = null; markCountRows();
  RV.measurementId = m.id;
  drawMeasurements();
  if (!objs.length && m.geometry && m.sheet_id === RV.sheetId) RV.viewer.zoomToSelection();
  showTab("list");
  refreshList(msg);
  const row = document.querySelector('#bp-rows li[data-mid="' + m.id + '"]');
  if (row && row.scrollIntoView) row.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function closeReview(quiet) {
  RV.review = null;
  if (RV.wiringSize || RV.wiringLit) { wiringClearFocus(); renderWiring(); drawWiringRoutes(); }   // every circuit again
  RV.symbolType = null; RV.symbolList = []; RV.symbolPos = -1;
  RV.selected = new Set();
  RV.measurementId = null;
  rehideRevealed();
  drawMeasurements();
  if (!quiet) refreshList($("review-message"));
}

// A click on the drawing while a review card is open: a symbol (or a counted plan label) goes on or off the count.
// Every other click is ignored, so a stray click can't lose the highlight. True when the click was handled.
function reviewPick(target) {
  const R = RV.review;
  if (!R) return false;
  const node = target.closest ? target.closest("[data-oid]") : null;
  const o = node && RV.byId.get(+node.getAttribute("data-oid"));
  if (!o || !(o.symbol || o.kind === "text")) return true;
  if (R.objs.has(o.id)) { R.objs.delete(o.id); R.count = Math.max(0, (parseFloat(R.count) || 0) - 1); }
  else { R.objs.set(o.id, o); R.count = (parseFloat(R.count) || 0) + 1; }
  RV.symbolList = [...R.objs.values()];
  RV.selected = new Set(R.objs.keys());
  drawMeasurements();
  refreshList($("review-message"));
  return true;
}

function reviewCard(m, msg) {
  const R = RV.review, d = RV.data, calc = m.calc || {};
  const counted = isCountMeasurement(m);
  const unit = m.unit || "";
  const card = el("div", { class: "card section bp-review", id: "bp-review" });
  card.addEventListener("click", ev => ev.stopPropagation());         // clicks in the card never toggle the row
  card.addEventListener("keydown", ev => ev.stopPropagation());
  const lines = [];
  if (m.proposed_by === LLM_AGENT || m.proposed_by === AGENT) {
    lines.push(el("div", { class: "small" }, el("strong", {}, "AI: " + num(R.aiQty) + " " + unit),
      calc.how ? el("span", { class: "muted" }, " — " + calc.how) : null));
  }
  if (counted) {
    lines.push(el("div", { class: "small", id: "bp-review-onplan" }, R.objs.size
      ? [el("strong", {}, R.objs.size + " highlighted on the drawing"), " — click a symbol on the drawing to take it off the count or add one.",
         legendRefs([...R.objs.values()]).length
           ? el("span", { id: "bp-review-legend" }, " ", el("span", { class: "bp-legend-key" }, "Blue"), " is the legend's symbol, to compare (not counted).")
           : null]
      : "Nothing for this on this sheet to highlight — count it on the plan and set the number with − / +."));
  }
  const qty = el("input", { id: "bp-review-qty", class: "bp-review-qty", value: String(R.count), inputmode: "decimal",
    maxlength: 20, "aria-label": "Quantity to approve" });
  qty.addEventListener("input", () => { R.count = qty.value; refreshButtons(); });
  qty.addEventListener("keydown", ev => { if (ev.key === "Enter") approve.click(); });
  const step = delta => () => {
    R.count = Math.max(0, (parseFloat(R.count) || 0) + delta);
    qty.value = String(R.count);
    refreshButtons();
  };
  const minus = el("button", { class: "button", type: "button", id: "bp-review-minus", "aria-label": "One less" }, "−");
  const plus = el("button", { class: "button", type: "button", id: "bp-review-plus", "aria-label": "One more" }, "+");
  minus.addEventListener("click", step(-1));
  plus.addEventListener("click", step(1));
  const qtyRow = el("div", { class: "row bp-review-count" }, counted ? minus : null, qty, counted ? plus : null,
    el("span", {}, unit));
  // Shown whenever the count isn't what's lit up on the drawing (after − / + or typing too), to put it back.
  let use = null;
  if (counted && R.objs.size) {
    use = el("button", { class: "button", type: "button", id: "bp-review-use-highlighted" },
      "Use the " + R.objs.size + " highlighted");
    use.addEventListener("click", () => { R.count = R.objs.size; qty.value = String(R.count); refreshButtons(); });
    qtyRow.append(use);
  }
  const out = el("div", { id: "bp-review-out" });
  const approve = el("button", { class: "primary", type: "button", id: "bp-review-approve" });
  approve.addEventListener("click", () => reviewSave(m, approve, out, msg));
  const actions = el("div", { class: "row" });
  // 2026-11-20 (David): the user can always change their mind - approve a rejected one again, change or reject an
  // approved one. Only agents are kept off approved and rejected measurements (the server checks that).
  const olds = m.status === "approved" ? [] : oldApproved(m);
  // 2026-11-23 (David: "What is the 6, 10, 12 AWG THHN wiring when we already have a cable lengths?"): the wiring
  // method changed (NM cable to conduit, or back) - this wire replaces the approved cable named in its calc.
  const handed = m.status === "approved" || !m.calc || !Array.isArray(m.calc.replaces) ? []
    : RV.data.takeoff.measurements.filter(x => m.calc.replaces.includes(x.id) && x.status === "approved");
  if (handed.length) {
    lines.push(el("div", { class: "small warn", id: "bp-review-handover" }, el("strong", {}, "Replaces "),
      handed.map(o => (o.label || o.feeds).replace(/ \(wiring\)$/, "") + " (" + num(o.qty) + " " + o.unit + ")").join(", ") +
      " — the wiring method changed. Approving this takes that off the estimate, so the wire isn't priced twice."));
  }
  if (olds.length) {
    lines.push(el("div", { class: "small warn", id: "bp-review-replaces" }, el("strong", {}, "Replaces "),
      olds.map(o => num(o.qty) + " " + o.unit).join(", ") + " approved before the plans were read again — approving this one takes that one off the estimate, so it isn't priced twice."));
  } else if (m.status === "approved" && isFromOldPlans(m)) {
    lines.push(el("div", { class: "small warn", id: "bp-review-replaces" }, el("strong", {}, "From before the plans were read again"),
      " — its symbols can't be shown. Approve the new count for this item (it replaces this one), or reject this one if a newer one is already approved."));
  }
  if (m.status === "rejected") {
    lines.push(el("div", { class: "small", id: "bp-review-state" }, el("strong", {}, "Rejected"),
      m.reject_reason ? " (" + m.reject_reason + ")" : "", " — not priced. Approve it to use it again."));
  } else if (m.status === "approved") {
    lines.push(el("div", { class: "small", id: "bp-review-state" }, el("strong", {}, "Approved"),
      " — change the count and save it, or reject it."));
  }
  if (d.can_approve) actions.append(approve);
  if (d.can_correct && m.status !== "rejected") {
    const reject = el("button", { class: "button danger", type: "button", id: "bp-review-reject" }, "✕ Reject");
    reject.addEventListener("click", () => reviewReject(m, reject, out, msg));
    actions.append(reject);
  }
  const more = el("button", { class: "button", type: "button", id: "bp-review-detail" }, "Detail");
  more.addEventListener("click", () => showDetail(m.id, msg, false));
  const close = el("button", { class: "button", type: "button", id: "bp-review-close" }, "Close");
  close.addEventListener("click", () => closeReview());
  actions.append(more, close);
  const links = el("div", { class: "small" });
  if (calc.auto_run_id) {
    links.append(el("a", { href: "#/agents/ai-log?auto_run_id=" + calc.auto_run_id, target: "_blank", rel: "noopener",
      id: "bp-review-ai-log", title: "Opens in a new tab — this screen stays where it is" },
      "📋 What the AI was given and returned ↗"));
  }
  function refreshButtons() {
    const v = parseFloat(R.count);
    const changed = !isNaN(v) && v !== (parseFloat(m.qty) || 0);
    approve.textContent = m.status === "approved"
      ? (changed ? "✓ Save " + num(v) + " " + unit : "✓ Approved")
      : (m.status === "rejected" ? "✓ Approve again " : "✓ Approve ") + (isNaN(v) ? "" : num(v) + " " + unit);
    approve.disabled = m.status === "approved" && !changed;
    if (use) use.hidden = (parseFloat(R.count) || 0) === R.objs.size;
  }
  refreshButtons();
  card.append(...lines, qtyRow, actions, out, links);
  return card;
}

// The next measurement to review after this one: on this sheet first, in list order.
function nextToReview(afterId) {
  const ms = RV.data.takeoff.measurements.filter(x => x.status === "proposed" && x.id !== afterId);
  return ms.find(x => x.sheet_id === RV.sheetId) || ms[0] || null;
}

async function reviewSave(m, btn, out, msg) {
  const R = RV.review;
  const v = String(R.count).trim().replace(/,/g, "");
  if (v === "" || isNaN(Number(v)) || Number(v) < 0) { out.replaceChildren(el("p", { class: "error" }, "Give a number (0 or more).")); return; }
  btn.disabled = true;
  out.replaceChildren();
  try {
    // The click is the confirmation: change the count first if it was changed, then approve - one step for the user.
    if (Number(v) !== (parseFloat(m.qty) || 0)) await api("POST", "/measurements/" + m.id + "/edit", { qty: v, confirm: true });
    const approving = m.status === "proposed" || m.status === "rejected";
    const done = approving ? await api("POST", "/measurements/approve", { measurement_ids: [m.id], confirm: true }) : null;
    const replaced = done && done.replaced && done.replaced.length ? " (replaces the count from before the plans were read again)" : "";
    toast(measurementName(m) + ": " + num(v) + " " + (m.unit || "") + (approving ? " approved" : " saved") + replaced);
    const next = nextToReview(m.id);
    closeReview(true);
    await refreshData();
    const fresh = next && RV.data.takeoff.measurements.find(x => x.id === next.id && x.status === "proposed");
    if (fresh) openReview(fresh, msg);
  } catch (e) {
    btn.disabled = false;
    if (e.status !== 401) out.replaceChildren(errorBox(e));
  }
}

async function reviewReject(m, btn, out, msg) {
  btn.disabled = true;
  try {
    await api("POST", "/measurements/" + m.id + "/reject", { reason: "rejected in review", confirm: true });
    toast(measurementName(m) + " rejected — kept in the history, never priced");
    const next = nextToReview(m.id);
    closeReview(true);
    await refreshData();
    const fresh = next && RV.data.takeoff.measurements.find(x => x.id === next.id && x.status === "proposed");
    if (fresh) openReview(fresh, msg);
  } catch (e) {
    btn.disabled = false;
    if (e.status !== 401) out.replaceChildren(errorBox(e));
  }
}

function bulkApprove(msg) {
  const level = el("select", { id: "bp-bulk-level", "aria-label": "Confidence" },
    ["0.95", "0.9", "0.8", "0.7"].map(v => el("option", { value: v, selected: v === "0.9" }, Math.round(v * 100) + "% or higher")));
  const b = el("button", { class: "button", type: "button", id: "bp-bulk" }, "Approve all…");
  const out = el("div", { id: "bp-bulk-confirm" });
  b.addEventListener("click", () => reviewAsk(out, b, "/measurements/approve", { estimate_id: RV.estimateId, above_confidence: level.value },
    x => x.done.length + " measurement(s) approved and locked", "bp-bulk"));
  return el("div", { class: "card section" }, el("div", { class: "row" }, el("span", {}, "Bulk approve proposals at"), level, b), out);
}

// ------------------------------------------------------------------ the detail panel
// Nothing selected yet: say so, instead of a blank tab (2026-11-18, David: the Detail tab had no info).
function detailEmpty() {
  return el("p", { class: "muted", id: "bp-detail-empty" },
    "Select a measurement to see its detail — click one in the Measurements list or on the drawing.");
}
async function showDetail(id, msg, zoom) {
  RV.measurementId = id;
  const m = RV.data.takeoff.measurements.find(x => x.id === id);
  if (m) await goToHomeSheet(m, msg);
  drawMeasurements();
  refreshList(msg);
  if (zoom && m && m.sheet_id === RV.sheetId) RV.viewer.zoomToSelection();
  const pane = $("bp-pane-detail");
  if (!pane) return;
  pane.replaceChildren(el("p", { class: "muted" }, "Loading…"));
  showTab("detail");
  let d;
  try { d = await api("GET", "/measurements/" + id); } catch (e) { pane.replaceChildren(errorBox(e)); return; }
  const x = d.measurement, c = d.calc || {};
  // Agent measurements say which outline they came from: the run that made them still holds its candidates.
  let agentOutline = null;
  if (x.proposed_by === AGENT) {
    agentOutline = "from the agent's outline";
    if (c.auto_run_id) {
      try {
        const rr = await api("GET", "/auto-run/" + c.auto_run_id);
        const found = ((rr.run && rr.run.candidates) || []).find(y => y.id === c.candidate_id);
        if (found) agentOutline = "from outline: " + candidateLabel(found);
      } catch (e) { /* the run is gone or the backend isn't there — the fallback stands */ }
    }
  }
  // LLM measurements say what the AI read: the dimensions stay in the calc as provenance.
  let aiReading = null;
  if (c.source === "llm") {
    aiReading = "read " + (c.slab_width || "?") + " × " + (c.slab_length || "?") + " from the foundation plan"
      + (c.footer_size ? ", footer " + c.footer_size : "") + (c.footer_bar ? " " + c.footer_bar : "")
      + (c.model ? " (" + c.model + ")" : "");
  }
  const rows = [
    ["Quantity", num(x.qty) + " " + x.unit + (x.suggested_qty !== null && x.suggested_qty !== undefined ? " (suggested: " + num(x.suggested_qty) + " " + x.unit + " — " + (x.suggested_reason || "") + ")" : "")],
    ["Trade", tradeName(x.module_id) + (x.feeds ? " → " + words(x.feeds) : " (not linked to a question)")],
    ["Status", words(x.status) + (x.locked ? " 🔒 locked" : "") + (x.reject_reason ? " — " + x.reject_reason : "")],
    ["How", (c.how || "") + (c.edited ? " · changed by " + c.edited.by + " from " + c.edited.from + " to " + c.edited.to : "")],
    ["Sheet", d.sheet ? (d.sheet.sheet_no || "page " + d.sheet.page_no) + (d.sheet.title ? " — " + d.sheet.title : "") : "—"],
    ["View and scale", d.viewport ? (d.viewport.label || "view") + " · " + (d.viewport.is_nts ? "NTS" : d.viewport.scale_note || (d.viewport.scale_ratio ? "1:" + d.viewport.scale_ratio : "no scale")) + (d.viewport.scale_method ? " (" + words(d.viewport.scale_method) + ")" : "") : c.scale_ratio ? "1:" + c.scale_ratio : "—"],
    ["Method", words(x.method)], ["Confidence", pct(x.confidence)],
    ["Proposed by", proposedByWords(x.proposed_by)],
    agentOutline ? ["Agent outline", agentOutline] : null,
    aiReading ? ["AI reading", aiReading] : null,
    aiReading && c.auto_run_id ? ["AI Log", el("a", { href: "#/agents/ai-log?auto_run_id=" + c.auto_run_id, id: "bp-detail-ai-log", target: "_blank", rel: "noopener",
      title: "Opens in a new tab — this screen stays where it is" }, "What the AI was given and what it returned ↗")] : null,
    ["Approved", x.approved_by ? x.approved_by + " · " + when(x.approved_at) : "not yet"],
  ];
  const parts = [el("h3", {}, measurementName(x)), el("table", { class: "kv", id: "bp-detail" }, rows.filter(Boolean).map(([k, v]) => el("tr", {}, el("th", {}, k), el("td", {}, v))))];
  if (d.source_objects.length) {
    parts.push(el("h4", {}, "From the drawing (" + d.source_objects.length + ")"),
      el("ul", { class: "small", id: "bp-sources" }, d.source_objects.slice(0, 50).map(o => el("li", {}, objectLabel({ ...o, layer: null }) + " · " + words(o.source) + " " + pct(o.confidence)))));
  }
  if (d.missing_objects.length) parts.push(el("p", { class: "note warn" }, d.missing_objects.length + " drawing object(s) it came from are gone (the plans were read again)."));
  // Sprint 8: the priced lines this measurement drives (through the question it answers).
  const feeds = linesFor(x.id);
  parts.push(el("h4", {}, x.status === "approved" ? "Priced lines it feeds" : "Lines it will feed once approved"), feeds.length
    ? el("ul", { class: "small", id: "bp-feeds-lines" }, feeds.map(l => el("li", {},
        el("a", { href: "#/estimates/" + RV.estimateId + "?line=" + l.line_id }, l.description), " · " + num(l.quantity) + " " + l.unit)))
    : el("p", { class: "muted small", id: "bp-feeds-lines" }, x.feeds
        ? (x.status === "approved" ? "None yet — price " + tradeName(x.module_id) + " on the Estimates screen to use it." : "None until it's approved.")
        : "It isn't linked to a question, so it isn't priced."));
  parts.push(detailActions(x, msg, c));
  if (d.history.length) {
    parts.push(el("details", { id: "bp-history" }, el("summary", {}, "History (" + d.history.length + ")"),
      el("ul", { class: "small" }, d.history.map(h => el("li", {}, when(h.at) + " · " + h.by + " · " + words(h.action.replace(/^measurement_/, "")))))));
  }
  pane.replaceChildren(...parts);
}

function detailActions(x, msg, calc) {
  const d = RV.data, out = el("div", { id: "bp-act-confirm" }), row = el("div", { class: "row", id: "bp-actions" });
  const btn = (id, text, fn) => { const b = el("button", { class: id === "bp-approve-one" ? "primary" : "button", type: "button", id }, text); b.addEventListener("click", () => fn(b)); row.append(b); };
  if ((x.status === "proposed" || x.status === "rejected") && d.can_approve) {   // 2026-11-20: a rejected one too
    btn("bp-approve-one", x.status === "rejected" ? "✓ Approve again…" : "✓ Approve…", b => reviewAsk(out, b, "/measurements/approve", { measurement_ids: [x.id] }, () => "Approved and locked", "bp-approve"));
  }
  if (x.proposed_by === AGENT) {
    btn("bp-show-outline", "Show outline", () => showAgentOutline(x));
  }
  if (x.status === "proposed" && x.proposed_by === AGENT && d.can_correct) {
    btn("bp-retarget", "Change outline…", () => retargetForm(x, out, calc || {}));
  }
  if (x.status === "approved" && x.suggested_qty !== null && x.suggested_qty !== undefined && d.can_approve) {
    btn("bp-accept", "Accept the suggestion…", b => reviewAsk(out, b, "/measurements/approve", { measurement_ids: [x.id], accept_suggestion: true }, () => "Suggestion accepted", "bp-accept"));
  }
  if (d.can_correct) {
    btn("bp-edit", "Correct…", () => correctForm(x, out));
  }
  if (x.status !== "rejected" && d.can_correct) {
    btn("bp-reject", "Reject…", () => rejectForm(x, out));
    if (x.status === "approved") btn("bp-suggest", "Suggest a change…", () => suggestForm(x, out));
  }
  return el("div", {}, row, out);
}

function correctForm(x, out) {
  const qty = el("input", { id: "bp-edit-qty", value: x.qty, inputmode: "decimal", maxlength: 20, "aria-label": "Quantity" });
  const label = el("input", { id: "bp-edit-label", value: x.label || "", maxlength: 200, "aria-label": "Label" });
  const room = el("input", { id: "bp-edit-room", value: x.room || "", maxlength: 200, "aria-label": "Room" });
  const save = el("button", { class: "primary", type: "button", id: "bp-edit-save" }, "Save…");
  const ask = el("div", {});
  out.replaceChildren(el("div", { class: "card section" }, x.locked ? el("p", { class: "muted small" }, "It's approved: your correction is a person's change and is logged.") : null,
    el("div", { class: "form-grid" }, el("label", {}, "Quantity (" + x.unit + ")", qty), el("label", {}, "Label", label), el("label", {}, "Room", room)),
    el("div", { class: "row" }, save), ask));
  save.addEventListener("click", () => {
    const body = {};
    if (qty.value.trim() !== String(x.qty)) body.qty = qty.value.trim();
    if (label.value.trim() !== (x.label || "")) body.label = label.value.trim();
    if (room.value.trim() !== (x.room || "")) body.room = room.value.trim();
    if (!Object.keys(body).length) { ask.replaceChildren(el("p", { class: "muted" }, "Nothing changed.")); return; }
    reviewAsk(ask, save, "/measurements/" + x.id + "/edit", body, () => "Measurement corrected", "bp-edit");
  });
  qty.focus();
}

function rejectForm(x, out) {
  const reason = el("input", { id: "bp-reject-reason", maxlength: 200, placeholder: "Why? e.g. counted twice", "aria-label": "Reason" });
  const go2 = el("button", { class: "button danger", type: "button", id: "bp-reject-go" }, "Reject…");
  const ask = el("div", {});
  out.replaceChildren(el("div", { class: "card section" }, el("div", { class: "row" }, el("label", {}, "Reason", reason), go2), ask));
  go2.addEventListener("click", () => reviewAsk(ask, go2, "/measurements/" + x.id + "/reject", { reason: reason.value.trim() }, () => "Rejected — kept in the history, never priced", "bp-reject"));
  reason.focus();
}

function suggestForm(x, out) {
  const qty = el("input", { id: "bp-suggest-qty", inputmode: "decimal", maxlength: 20, "aria-label": "Suggested quantity" });
  const reason = el("input", { id: "bp-suggest-reason", maxlength: 200, "aria-label": "Reason" });
  const go2 = el("button", { class: "button", type: "button", id: "bp-suggest-go" }, "Suggest…");
  const ask = el("div", {});
  out.replaceChildren(el("div", { class: "card section" }, el("p", { class: "muted small" }, "The approved value stays; a person accepts the suggestion or not."),
    el("div", { class: "form-grid" }, el("label", {}, "New quantity (" + x.unit + ")", qty), el("label", {}, "Why", reason)), el("div", { class: "row" }, go2), ask));
  go2.addEventListener("click", () => reviewAsk(ask, go2, "/measurements/" + x.id + "/suggest", { qty: qty.value.trim(), reason: reason.value.trim() }, () => "Suggestion saved", "bp-suggest"));
  qty.focus();
}

// ------------------------------------------------------------------ layers panel
function drawLayersPanel() {
  const pane = $("bp-pane-layers");
  if (!pane) return;
  const prefs = layerPrefs();
  const rows = RV.groups.map(g => {
    const show = el("input", { type: "checkbox", checked: !prefs.hidden.includes(g.id), "data-layer": g.id, "aria-label": "Show " + g.label });
    const lock = el("input", { type: "checkbox", checked: prefs.locked.includes(g.id), "data-lock": g.id, "aria-label": "Lock " + g.label });
    const swatch = el("span", { class: "swatch" });
    swatch.style.background = g.color;
    const change = () => {
      const p = layerPrefs();
      p.hidden = p.hidden.filter(x => x !== g.id); if (!show.checked) p.hidden.push(g.id);
      p.locked = p.locked.filter(x => x !== g.id); if (lock.checked) p.locked.push(g.id);
      saveLayerPrefs(p);
      const node = RV.viewer.overlay.querySelector('[data-group="' + g.id + '"]');
      if (node) { node.classList.toggle("hidden", !show.checked); node.classList.toggle("locked", lock.checked); }
    };
    show.addEventListener("change", change);
    lock.addEventListener("change", change);
    // Measurements isn't a CAD group (the server sends 0 for it): count the measurements on this sheet instead.
    const n = g.id === "measurements" ? sheetMeasurements().length : g.count;
    return el("tr", { "data-group": g.id }, el("td", {}, swatch, " " + g.label), el("td", {}, n), el("td", {}, show), el("td", {}, lock));
  });
  pane.replaceChildren(el("table", { class: "list", id: "bp-layers" },
    el("thead", {}, el("tr", {}, el("th", {}, "Layer"), el("th", {}, "Items"), el("th", {}, "Show"), el("th", {}, "Lock"))), el("tbody", {}, rows)),
    el("p", { class: "muted small" }, "CAD layers are sorted into these groups by their names (A-WALL → Walls, E-LITE → Electrical…). A locked layer can't be selected. What's shown is remembered on this browser."));
}

// ------------------------------------------------------------------ Audit & clean up (2026-11-20, David)
// "Can we have an AI Cleanup run that fixes and removes double counted items and 'from before the plans were read
// again' issues ... a way to remove [rejected items] ... make sure the user can mass accept all of the changes; you may
// need a popup window when the user runs the AI Audit that the user can work with." A panel beside the drawing (the
// drawing stays usable): what the audit found, each with its fix ticked or not, "Show on drawing" for a count, and one
// button that applies every ticked fix. The server (estimator/takeoff/audit.py) audits again before applying.
async function openAudit() {
  let panel = $("bp-audit");
  if (!panel) {
    panel = el("div", { class: "card bp-audit", id: "bp-audit", role: "dialog", "aria-label": "Audit and clean up" });
    (document.querySelector("main") || document.body).append(panel);   // leaving the screen takes it away too
  }
  panel.replaceChildren(el("p", { class: "muted" }, "🧹 Auditing the measurements…"));
  try {
    renderAudit(panel, await api("GET", "/estimates/" + RV.estimateId + "/audit"));
  } catch (e) {
    if (e.status !== 401) panel.replaceChildren(auditHead(panel), errorBox(e));
  }
}

// "⚡ Run wiring" on the toolbar and the audit's "⚡ Run wiring now": the same run as the Wiring card's button, with
// the last run's settings and device moves and the "Keep approved items" choice. Old cable from before the plans were
// read again is proposed again; if the audit window is open it audits again, so the new cable shows as waiting.
async function quickRunWiring(btn) {
  const was = btn.textContent;
  btn.disabled = true; btn.textContent = "⚡ Routing…";
  try {
    const w = await api("GET", "/wiring/" + RV.estimateId);
    if (!w.can_run) {
      const src = w.sources || {};
      toast("The wiring can't run yet: " + (src.plan ? "only owners and estimators can run it."
        : "upload the electrical floor plan as a DXF (CAD) file on the Plans screen (the panel drawing is used when there is one)."));
      return;
    }
    const run = w.run;
    const r = await api("POST", "/wiring/" + RV.estimateId, { settings: (run && run.settings) || {},
      overrides: (run && run.overrides) || {}, keep_approved: keepApprovedNow() });
    // 2026-11-21 (David: "nothing shows up in the cad window"): the new run is the screen's run now, its routes on.
    wiringReset({ ...w, run: r.run });
    RV.wiringFor = RV.estimateId;
    RV.showWiring = true;
    RV.wiringPick = null; RV.wiringSize = null; RV.wiringLit = null; RV.wiringMark = null;
    const n = (r.run.measurement_ids || []).length;
    const sug = (r.run.suggested_ids || []).length;
    toast("Wiring done — " + (n ? n + " cable size(s) waiting for approval; click one in the list to light up its circuits" :
      sug ? sug + " approved item(s) changed — ✓ Accept the new lengths in the ⚡ Wiring card" :
      "nothing changed (the approved cable already matches)") +
      (n ? ($("bp-audit") ? "." : " (🧹 Audit & clean up approves them in one click).") : "."));
    // The routes are drawn on the floor plan the wiring was routed on: go there (from the panel drawing, say).
    const planSheet = r.run.sources && r.run.sources.plan && r.run.sources.plan.sheet_id;
    if (planSheet && planSheet !== RV.sheetId) await auditGoToSheet(planSheet, $("review-message"));
    await refreshData();
    renderWiring();
    drawWiringRoutes();
    if ($("bp-audit")) await openAudit();
  } catch (e) {
    if (e.status === 401) return;
    const out = $("bp-audit-out");
    if (out) out.replaceChildren(errorBox(e));
    else toast("The wiring run didn't work — " + (e.message || "unknown error"));
  } finally {
    if (btn.isConnected) { btn.disabled = false; btn.textContent = was; }
  }
}
const auditRunWiring = quickRunWiring;

function closeAudit() {
  const panel = $("bp-audit");
  if (panel) panel.remove();
}

function auditHead(panel) {
  const close = el("button", { class: "button", type: "button", id: "bp-audit-close", "aria-label": "Close" }, "✕");
  close.addEventListener("click", closeAudit);
  return el("div", { class: "bp-audit-head" }, el("strong", {}, "🧹 Audit & clean up"), close);
}

const AUDIT_GROUPS = [
  ["double_counted", "Priced twice"], ["replace_old", "New counts to replace old ones"],
  ["drawing_differs", "Approved counts the drawing disagrees with"], ["waiting", "Waiting for review"],
  ["rerun", "Needs a run done again"], ["rejected", "Rejected items"],
];

function renderAudit(panel, r) {
  const out = el("div", { id: "bp-audit-out", role: "status" });
  const boxes = [];
  const apply = el("button", { class: "primary", type: "button", id: "bp-audit-apply" });
  const refresh = () => {
    const n = boxes.filter(b => b.checked).length;
    apply.textContent = "✓ Apply " + n + " fix" + (n === 1 ? "" : "es");
    apply.disabled = !n || !r.can_apply;
  };
  const parts = [auditHead(panel), el("p", { class: "small", id: "bp-audit-summary" }, r.summary)];
  if (!r.findings.length) {
    panel.replaceChildren(...parts, el("p", { class: "small" }, "✅ All clean."));
    return;
  }
  const all = el("button", { class: "button small", type: "button", id: "bp-audit-all" }, "Tick all");
  const none = el("button", { class: "button small", type: "button", id: "bp-audit-none" }, "Untick all");
  all.addEventListener("click", () => { boxes.forEach(b => { b.checked = true; }); refresh(); });
  none.addEventListener("click", () => { boxes.forEach(b => { b.checked = false; }); refresh(); });
  parts.push(el("div", { class: "row" }, all, none));
  const list = el("div", { class: "bp-audit-list", id: "bp-audit-list" });
  for (const [kind, heading] of AUDIT_GROUPS) {
    const fs = r.findings.filter(f => f.kind === kind);
    if (!fs.length) continue;
    list.append(el("div", { class: "bp-audit-group" }, heading));
    for (const f of fs) {
      const item = el("div", { class: "bp-audit-item " + kind, "data-fid": f.id });
      let tick = null;
      if (f.can_fix) {
        tick = el("input", { type: "checkbox", "data-fid": f.id, checked: f.selected ? "" : null,
          "aria-label": f.title });
        tick.addEventListener("change", refresh);
        boxes.push(tick);
      }
      // Cable shows its wiring routes on the floor plan, sheet or not (old cable from before a re-read has none).
      const show = f.feeds && (f.sheet_id || /^wire_/.test(f.feeds))
        ? el("a", { href: "#", class: "small bp-audit-show" }, "Show on drawing") : null;
      if (show) show.addEventListener("click", ev => { ev.preventDefault(); auditShow(f); });
      // 2026-11-20 (David): old cable needs the wiring run again - offer it right here (no AI Auto Run needed).
      let runIt = null;
      if (f.rerun === "wiring" && r.can_apply) {
        runIt = el("button", { class: "button small bp-audit-run-wiring", type: "button" }, "⚡ Run wiring now");
        runIt.addEventListener("click", () => auditRunWiring(runIt));
      }
      item.append(el("label", { class: "bp-audit-title" }, tick, " ", el("strong", {}, f.title)),
        el("div", { class: "small muted" }, f.detail),
        el("div", { class: "small" }, f.can_fix ? "Fix: " + f.fix : "👉 " + (f.advice || "")),
        ...[runIt, show].filter(Boolean));          // append() writes a missing one as the word "null"
      list.append(item);
    }
  }
  parts.push(list);
  apply.addEventListener("click", () => applyAudit(panel, boxes.filter(b => b.checked).map(b => b.dataset.fid), apply, out));
  const again = el("button", { class: "button", type: "button", id: "bp-audit-again" }, "Audit again");
  again.addEventListener("click", () => openAudit());
  parts.push(el("div", { class: "row bp-audit-foot" }, apply, again), out);
  if (!r.can_apply) parts.push(el("p", { class: "small muted" }, "Your role can look, but only someone who approves measurements can apply the fixes."));
  panel.replaceChildren(...parts);
  refresh();
}

// Light up the count's symbols on the drawing (switching to its sheet first) while the panel stays open.
async function auditShow(f) {
  const msg = $("review-message");
  // 2026-11-20 (David: "show on drawing for the wiring shows nothing"): cable has no symbols - show the wiring routes
  // on the floor plan the wiring was routed on, the circuits of that cable size standing out.
  const size = /^wire_(\d+)_(\d+)_ft$/.exec(f.feeds || "");
  if (size) return auditShowWiring(size[1] + "/" + size[2], msg);
  // 2026-11-20 (David: "3 of these items don't have symbols"): the breakers and the range/dryer receptacles have no
  // symbol on the designer's drawing - show the wiring run's marks for them, and the circuits behind them.
  // When a revised drawing has the real symbol, the wiring run marks nothing: light up the symbol instead.
  if ((WIRING_MARK_FEEDS.includes(f.feeds) || isConduitFeed(f.feeds)) && await auditShowWiring(null, msg, f.feeds)) return;
  await auditGoToSheet(f.sheet_id, msg);
  const objs = countSymbols(f.module_id, f.feeds);
  if (objs.length) { highlightSymbols(objs, symbolKey(objs[0])); auditKeepDrawingVisible(); }
  else toast("Nothing for this on the drawing to light up.");
}

const WIRING_MARK_FEEDS = ["branch_circuits", "range_receptacles", "dryer_receptacles"];

async function auditShowWiring(size, msg, mark) {
  try {
    if (!RV.wiring || RV.wiringFor !== RV.estimateId || RV.wiring.error) {
      wiringReset(await api("GET", "/wiring/" + RV.estimateId));
      RV.wiringFor = RV.estimateId;
    }
  } catch (e) { if (e.status !== 401) toast("Couldn't load the wiring routes — " + (e.message || "error")); return; }
  const run = RV.wiring && RV.wiring.run;
  const sheet = run && run.sources && run.sources.plan && run.sources.plan.sheet_id;
  if (!run || !run.overlay || !sheet) {
    toast("No wiring routes to show yet — click ⚡ Run wiring first.");
    return;
  }
  await auditGoToSheet(sheet, msg);
  RV.showWiring = true; RV.wiringPick = null; RV.wiringSize = size; RV.wiringLit = null; RV.wiringMark = null; RV.conduitFeeds = null;
  const name = (RV.sheet && (RV.sheet.title || RV.sheet.name)) || "the floor plan";
  if (mark && isConduitFeed(mark)) {
    // 2026-11-23 (David: "Cant see a visual of the conduit"): the conduit runs this item counts
    if (!(run.overlay.conduit || []).length) {
      renderWiring(); drawWiringRoutes();
      toast("This wiring run was made before the conduit could be drawn — click ⚡ Run wiring again to see the conduit runs.");
      return true;
    }
    const cm = conduitMatch(mark);
    const lit = run.overlay.conduit.filter(cm.pick);
    RV.conduitFeeds = mark;
    RV.wiringLit = cm.gauge
      ? run.overlay.circuits.filter(c => wireGauge(c.wire) === cm.gauge).map(c => c.id)    // only this gauge's circuits
      : [...new Set(lit.flatMap(r => r.circuits || []))];
    renderWiring(); drawWiringRoutes();
    const pts = (lit.length ? lit : run.overlay.conduit).flatMap(r => r.line);
    if (pts.length && RV.viewer) {
      const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
      RV.viewer.zoomToBox([Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)]);
    }
    auditKeepDrawingVisible();
    toast("On " + name + ": " + cm.head + " — " + lit.length + " conduit run(s) lit up. Hover a run for its size, length, bends and circuits.");
    return true;
  }
  if (mark) {
    const marks = (run.overlay.added || []).filter(a => a.feeds === mark);
    if (!marks.length) return false;           // the drawing has its own symbol for it (or no run marked it)
    RV.wiringMark = mark; RV.wiringLit = marks.flatMap(a => a.circuits || []);
    renderWiring();
    drawWiringRoutes();
    const xs = marks.map(a => a.at[0]), ys = marks.map(a => a.at[1]);
    const all = run.overlay.circuits.flatMap(c => [...c.lines.flat(), ...c.devices]);
    const pad = Math.max(Math.max(...all.map(p => p[0])) - Math.min(...all.map(p => p[0])),
                         Math.max(...all.map(p => p[1])) - Math.min(...all.map(p => p[1]))) / 6 || 10;
    if (RV.viewer) RV.viewer.zoomToBox([Math.min(...xs) - pad, Math.min(...ys) - pad, Math.max(...xs) + pad, Math.max(...ys) + pad]);
    auditKeepDrawingVisible();
    toast("On " + name + ": " + marks.map(a => a.label).join("; ") + " — marked by the wiring run (the designer drew no symbol for it).");
    return true;
  }
  renderWiring();
  drawWiringRoutes();
  // Zoom to the circuits of this size (all the routes when it is only the 3-way travelers).
  const lit = run.overlay.circuits.filter(c => c.wire === size);
  const pts = (lit.length ? lit : run.overlay.circuits).flatMap(c => [...c.lines.flat(), ...c.devices]);
  if (pts.length && RV.viewer) {
    const xs = pts.map(p => p[0]), ys = pts.map(p => p[1]);
    RV.viewer.zoomToBox([Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)]);
  }
  auditKeepDrawingVisible();
  toast(lit.length ? "On " + name + ": the " + lit.length + " circuit(s) wired in " + size + " are lit up (the others are faded)."
                   : "On " + name + ": the wiring routes (" + size + " is the 3-way travelers, inside the 3-way circuits).");
}

// 2026-11-20 (David: "the click should switch to the sheet or plan that needs review and light it up"): always go to
// the sheet - whichever sheet is open - before lighting anything up.
async function auditGoToSheet(sheet, msg) {
  if (!sheet || sheet === RV.sheetId || !RV.data.sheets.some(s => s.id === sheet)) return;
  if ($("review-sheet")) $("review-sheet").value = sheet;
  await openSheet(sheet, msg);
}

// The drawing on screen, and what's lit not hidden under the audit window (it sits over the drawing's right side).
function auditKeepDrawingVisible() {
  const v = RV.viewer;
  if (!v || !v.box) return;
  v.box.scrollIntoView({ block: "nearest", behavior: "smooth" });
  const panel = $("bp-audit");
  if (!panel) return;
  const r = v.box.getBoundingClientRect(), p = panel.getBoundingClientRect();
  const covered = Math.max(0, r.right - Math.max(p.left, r.left));
  if (covered > 0 && covered < r.width) { v.tx -= covered / 2; v.render(); }
}

async function applyAudit(panel, ids, btn, out) {
  btn.disabled = true;
  out.replaceChildren(el("p", { class: "muted small" }, "Applying…"));
  try {
    const done = await api("POST", "/estimates/" + RV.estimateId + "/audit/apply", { finding_ids: ids, confirm: true });
    toast(done.summary);
    await refreshData();
    const r = await api("GET", "/estimates/" + RV.estimateId + "/audit");
    renderAudit(panel, r);
    const o = $("bp-audit-out");
    if (o) o.replaceChildren(el("p", { class: "small ok", id: "bp-audit-done" }, "✓ " + done.summary));
  } catch (e) {
    btn.disabled = false;
    if (e.status !== 401) out.replaceChildren(errorBox(e));
  }
}

window.addEventListener("resize", () => { if (RV.viewer && RV.viewer.box.isConnected) RV.viewer.render(); });

SCREENS.takeoffs = renderTakeoffs;
PAGES.takeoff = renderReview;
