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
  ["count", "✚", "Count", "Click each item; press Enter or Finish when done."],
  ["calibrate", "📐", "Calibrate", "Click both ends of a distance you know, then type its real length."],
  ["symbol", "✳", "Add symbol", "Click a symbol the plan engine missed, then say what it is."],
];
const RV = { estimateId: null, data: null, sheetId: null, sheet: null, viewports: [], tiles: null, objects: [],
             inactiveTrades: [], groups: [], byId: new Map(), selected: new Set(), measurementId: null,
             tool: "select", draft: [], view: {}, viewer: null };

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
  RV.estimateId = estimateId;
  RV.data = await api("GET", "/estimates/" + estimateId + "/takeoff");
  const d = RV.data;
  RV.draft = [];
  // A reviewer only looks, approves and adds missed symbols.
  if (!d.can_measure && !["select", "pan"].concat(d.can_approve ? ["symbol"] : []).includes(RV.tool)) RV.tool = "select";
  if (q.get("m")) RV.measurementId = +q.get("m") || null;
  // Sprint 8: ?line=<id> (from the Estimates screen) highlights every measurement behind that priced line.
  RV.lineId = +(q.get("line") || 0) || null;
  // Sprint 11: ?symbol=<detection id> (from Reviews) opens that symbol highlighted on its sheet.
  RV.symbolId = +(q.get("symbol") || 0) || null;
  const lineSheet = RV.lineId ? (lineMeasurements(RV.lineId).find(m => m.sheet_id) || {}).sheet_id : null;
  const wanted = +(q.get("sheet") || 0) || lineSheet;
  const firstSheet = d.sheets.find(s => s.id === wanted) || d.sheets.find(s => s.id === RV.sheetId) ||
    d.sheets.find(s => s.objects) || d.sheets[0];
  const head = [el("p", {}, el("a", { href: "#/projects/" + estimateId }, "← " + d.estimate.title), " · ",
      el("a", { id: "bp-quantities", href: "#/quantities/" + estimateId }, "📐 Plan quantities")),
    el("div", { class: "page-head" }, el("h2", {}, "📏 Blueprint Review"), helpLink("takeoffs"))];
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
      (s.sheet_no || "Page " + s.page_no) + (s.title ? " — " + s.title : "") + (s.needs_scale ? " (needs a scale)" : ""))));
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
  const side = el("div", { class: "bp-side" },
    el("div", { class: "bp-tabs", role: "tablist" },
      tabButton("list", "Measurements"), tabButton("symbols", "Symbols"), tabButton("lines", "Lines"), tabButton("layers", "Layers"),
      tabButton("detail", "Detail")),
    el("div", { class: "bp-pane", id: "bp-pane-list" }), el("div", { class: "bp-pane", id: "bp-pane-symbols", hidden: true }),
    el("div", { class: "bp-pane", id: "bp-pane-lines", hidden: true }),
    el("div", { class: "bp-pane", id: "bp-pane-layers", hidden: true }), el("div", { class: "bp-pane", id: "bp-pane-detail", hidden: true }));
  main.replaceChildren(...head,
    el("div", { class: "row bp-bar" }, prev, sheetPick, next, toolPalette(msg), viewButtons()),
    el("p", { class: "muted small", id: "bp-tool-help" }, TOOLS.find(t => t[0] === RV.tool)[3]),
    el("div", { id: "bp-guide-slot" }), el("div", { id: "bp-readout-slot" }), el("div", { id: "bp-notes" }),
    msg, el("div", { id: "bp-auto-slot" }), el("div", { class: "bp-split" }, viewerBox, side));
  RV.viewer = new Viewer(viewerBox, msg);
  $("bp-pane-list").replaceChildren(measurementPanel(msg));
  await openSheet(firstSheet.id, msg);
  if (RV.symbolId) {
    const o = RV.objects.find(x => x.symbol && x.symbol.detection_id === RV.symbolId);
    showTab("symbols");
    if (o) highlightSymbols([o], o.symbol.item_type || "unknown");
    else msg.replaceChildren(el("p", { class: "note warn", id: "bp-symbol-missing" }, "That symbol isn't on this sheet any more (the plans may have been read again)."));
  } else if (RV.lineId) { showTab("lines"); RV.viewer.zoomToSelection(true); }
  else if (RV.measurementId) showDetail(RV.measurementId, msg, true);
}

// ------------------------------------------------------------------ Sprint 11: symbols on this sheet
// Counts by type (taken-out ones aren't counted); click a type to highlight every one of them on the plan, step
// through them one at a time, or open them in Reviews to approve, take out or relabel.
function sheetSymbols() { return RV.objects.filter(o => o.symbol); }
function symbolKey(o) { return o.symbol.item_type || "unknown"; }

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
  RV.symbolType = key;
  RV.symbolList = objs;
  RV.symbolPos = objs.length === 1 ? 0 : -1;           // -1: all of them at once
  RV.measurementId = null; RV.lineId = null;
  RV.selected = new Set(objs.map(o => o.id));
  // A symbol in a hidden layer is shown while it's highlighted (the layer setting itself isn't changed).
  for (const o of objs) {
    const g = RV.viewer.overlay.querySelector('[data-group="' + o.group + '"]');
    if (g) g.classList.remove("hidden");
  }
  drawMeasurements();
  RV.viewer.zoomToSelection(true);
  drawSymbolsPanel($("review-message"));
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
  for (const p of ["list", "symbols", "lines", "layers", "detail"]) { const n = $("bp-pane-" + p); if (n) n.hidden = p !== id; }
}

function toolPalette(msg) {
  const box = el("div", { class: "bp-tools", role: "toolbar", "aria-label": "Tools", id: "bp-tools" });
  for (const [id, icon, label, help] of TOOLS) {
    if (["length", "area", "rect", "count"].includes(id) && !RV.data.can_measure) continue;
    if (id === "calibrate" && !RV.data.can_measure) continue;
    if (id === "symbol" && !RV.data.can_approve) continue;          // adding a symbol is a reviewer's decision
    const b = el("button", { class: "bp-tool" + (id === RV.tool ? " active" : ""), type: "button", "data-tool": id, title: label + " — " + help }, icon + " " + label);
    b.addEventListener("click", () => setTool(id, msg));
    box.append(b);
  }
  // Phase 1: the Concrete agent measures the slab on its own (a measuring action, so it sits with the measure
  // tools and is hidden from reviewers). Without the Concrete trade on the estimate it stays, disabled, with
  // the reason — the agent only measures concrete slabs.
  if (RV.data.can_measure) {
    const hasConcrete = hasConcreteTrade();
    const run = el("button", { class: "button", type: "button", id: "bp-auto-run",
      disabled: !hasConcrete,
      title: hasConcrete ? "Let the Concrete agent measure the slab on this sheet, then review what it proposes."
        : "Add the Concrete trade to this estimate first — the agent only measures concrete slabs." },
      "🤖 Agent auto-run");
    run.addEventListener("click", () => startAutoRun());
    box.append(run);
  }
  return box;
}
function setTool(id, msg) {
  RV.tool = id;
  RV.draft = [];
  if (RV.viewer) RV.viewer.drawDraft();
  if (RV.viewer) RV.viewer.clearZoomBox();
  for (const b of document.querySelectorAll(".bp-tool")) b.classList.toggle("active", b.dataset.tool === id);
  const t = TOOLS.find(x => x[0] === id);
  if ($("bp-tool-help")) $("bp-tool-help").textContent = t ? t[3] : "";
  if (RV.viewer) RV.viewer.box.classList.toggle("drawing", !["select", "pan"].includes(id));
  if (msg && ["length", "area", "rect", "count", "calibrate"].includes(id)) msg.replaceChildren();
}
function viewButtons() {
  const mk = (id, text, title, fn) => { const b = el("button", { class: "button", type: "button", id, title }, text); b.addEventListener("click", fn); return b; };
  return el("div", { class: "row bp-view" },
    mk("bp-zoom-in", "＋", "Zoom in", () => RV.viewer.zoomBy(1.5)),
    mk("bp-zoom-out", "－", "Zoom out", () => RV.viewer.zoomBy(1 / 1.5)),
    mk("bp-fit", "Fit", "Fit the sheet", () => RV.viewer.fit()),
    mk("bp-zoom-sel", "Zoom to selection", "Zoom to what's selected", () => RV.viewer.zoomToSelection()),
    mk("bp-full", "⛶", "Full screen", () => { const v = $("bp-viewer"); if (document.fullscreenElement) document.exitFullscreen(); else if (v.requestFullscreen) v.requestFullscreen(); }));
}

async function openSheet(sheetId, msg) {
  RV.sheetId = sheetId;
  RV.selected = new Set();
  RV.symbolList = []; RV.symbolPos = -1; RV.symbolType = null;      // the Symbols tab starts again on each sheet
  const [s, o] = await Promise.all([api("GET", "/sheets/" + sheetId), api("GET", "/sheets/" + sheetId + "/objects")]);
  RV.sheet = s.sheet; RV.viewports = s.viewports; RV.tiles = s.tiles;
  RV.inactiveTrades = s.inactive_trades || [];      // trades this sheet is switched off for (Plans screen)
  RV.objects = o.objects; RV.groups = o.layers;
  RV.byId = new Map(o.objects.map(x => [x.id, x]));
  const sel = $("bp-selection");
  if (sel) sel.remove();
  const warn = [];
  if (o.count > o.returned) warn.push("Showing the first " + o.returned + " of " + o.count + " things found on this sheet.");
  if (s.viewports.some(v => !v.measurable && !v.is_nts)) warn.push("Part of this sheet has no scale yet — set it with 📐 Calibrate or on the Plans screen before measuring there.");
  $("bp-notes").replaceChildren(...(warn.length ? [el("p", { class: "note warn", id: "bp-sheet-note" }, warn.join(" "))] : []));
  RV.viewer.load();
  drawLayersPanel();
  drawSymbolsPanel(msg);
  drawLinesPanel();
  refreshList(msg);
  loadAutoCandidates();      // what the agent found on this sheet, in the background (never blocks the sheet)
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
    this.z = 1; this.tx = 0; this.ty = 0; this.level = -1; this.tileEls = new Map(); this.pointers = new Map(); this.zoomBox = null;
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
    if (saved) { this.z = saved.z; this.tx = saved.tx; this.ty = saved.ty; this.render(); } else this.fit();
    if (!RV.tiles) this.box.append(el("p", { class: "bp-empty" }, "This sheet has no image yet."));
  }
  fit() {
    const r = this.box.getBoundingClientRect();
    this.z = Math.max(1e-4, Math.min((r.width - 20) / this.W, (r.height - 20) / this.H));
    this.tx = (r.width - this.W * this.z) / 2; this.ty = (r.height - this.H * this.z) / 2;
    this.render();
  }
  zoomBy(f) { const r = this.box.getBoundingClientRect(); this.zoomAt(f, r.left + r.width / 2, r.top + r.height / 2); }
  zoomAt(f, cx, cy) {
    const r = this.box.getBoundingClientRect();
    const [ux, uy] = this.toSheet(cx, cy);
    const fitZ = Math.min(r.width / this.W, r.height / this.H);
    // Wheel zoom has no working cap: pro viewers let it run until the detail
    // fills the screen. The old fitZ * 40 cap stopped a plan that is a small
    // part of its sheet at ~40 px wide. The raster tiles blur past that, but
    // the vector overlay stays sharp; 4000x fit is a sanity bound only.
    this.z = Math.min(Math.max(this.z * f, fitZ / 4), fitZ * 4000);
    this.tx = cx - r.left - ux * this.z; this.ty = cy - r.top - uy * this.z;
    this.render();
  }
  zoomToBox(b) {
    const r = this.box.getBoundingClientRect();
    // Floor is a small absolute size, not a fraction of the sheet: zoom to
    // selection must fit the selected thing, and W/200 is ~1,100 units on a
    // sheet whose plan is only 300 units wide.
    const w = Math.max(b[2] - b[0], 10), h = Math.max(b[3] - b[1], 10);
    this.z = Math.min((r.width * 0.8) / w, (r.height * 0.8) / h);
    this.tx = r.width / 2 - (b[0] + w / 2) * this.z; this.ty = r.height / 2 - (b[1] + h / 2) * this.z;
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
    return [(cx - r.left - this.tx) / this.z, (cy - r.top - this.ty) / this.z];
  }
  render() {
    if (!RV.sheet) return;
    RV.view[RV.sheetId] = { z: this.z, tx: this.tx, ty: this.ty };
    const w = this.W * this.z, h = this.H * this.z;
    this.stage.style.transform = "translate(" + this.tx + "px," + this.ty + "px)";
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
    if (ev.shiftKey && last && RV.tool !== "count") {
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
    if (ev.key === "Escape") { RV.draft = []; this.drawDraft(); this.clearZoomBox(); this.start = null; }
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
    const pts = cursor && RV.tool !== "count" ? RV.draft.concat([cursor]) : RV.draft.slice();
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
  if (RV.draft.length > 2 && RV.tool === "area") consider(RV.draft[0]);
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
  const order = ["floor_plan", "rooms", "walls", "doors_windows", "furniture", "plumbing", "electrical", "mechanical",
                 "symbols", "dimensions", "text"];
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
  for (const o of g.ownerSVGElement.querySelectorAll("[data-oid].in-m, [data-oid].sel")) o.classList.remove("in-m", "sel");
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
}

// ------------------------------------------------------------------ selecting on the plan
function pickAt(target, shift, msg) {
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
  const tool = RV.tool;
  const last = RV.draft[RV.draft.length - 1];
  if (last && tool !== "count" && Math.hypot(p[0] - last[0], p[1] - last[1]) < 3 / RV.viewer.z) return;   // a double-click's 2nd click
  if (tool === "area" && RV.draft.length >= 3) {
    const f = RV.draft[0], tol = 8 / RV.viewer.z;
    if (Math.hypot(p[0] - f[0], p[1] - f[1]) < tol) { finishDraft(msg); return; }
  }
  RV.draft.push(p);
  RV.viewer.drawDraft();
  if ((tool === "rect" || tool === "calibrate") && RV.draft.length === 2) finishDraft(msg);
}

function draftShape(pts) {
  if (RV.tool === "rect" && pts.length >= 2) {
    const [a, b] = pts;
    return { type: "polygon", points: [[a[0], a[1]], [b[0], a[1]], [b[0], b[1]], [a[0], b[1]]] };
  }
  if (RV.tool === "area" && pts.length >= 3) return { type: "polygon", points: pts };
  if (RV.tool === "count") return { type: "point", points: pts };
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
  if (RV.tool === "calibrate") {
    if (shape.points.length < 2) return "";
    const [a, b] = shape.points;
    return num(Math.hypot(b[0] - a[0], b[1] - a[1]), 3) + (RV.sheet.units === "paper_in" ? "″ on the paper" : " " + RV.sheet.units);
  }
  if (shape.type === "point") return shape.points.length + " counted";
  const f = feetPerUnit(viewportAt(shape.points[0]));
  if (!f) return "this part of the sheet has no scale yet";
  if (shape.type === "polygon") {
    let a2 = 0;
    const p = shape.points;
    for (let i = 0; i < p.length; i++) { const [x0, y0] = p[i], [x1, y1] = p[(i + 1) % p.length]; a2 += x0 * y1 - x1 * y0; }
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
  const tool = RV.tool;
  const need = { length: 2, area: 3, rect: 2, count: 1, calibrate: 2 }[tool];
  if (!need || RV.draft.length < need) return;
  const shape = draftShape(RV.draft);
  RV.draft = [];
  RV.viewer.drawDraft();
  if (tool === "calibrate") { calibrateForm(msg, shape.points); return; }
  const vp = viewportAt(shape.points[0]);
  if (!vp) { msg.replaceChildren(el("p", { class: "error" }, "That isn't inside a view on this sheet.")); return; }
  if (!feetPerUnit(vp)) {
    msg.replaceChildren(el("p", { class: "error", id: "bp-no-scale" }, (vp.is_nts ? "That view is marked not to scale (NTS)" : "That view has no scale yet") +
      " — set it with 📐 Calibrate (or on the Plans screen) first, then measure again."));
    return;
  }
  saveForm(msg, { geometry: shape, viewportId: vp.id, kind: { length: "length", area: "area", rect: "area", count: "count" }[tool],
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
    const guess = (t ? t.questions : []).find(q => (what.kind === "area" && /sq|sf/.test(q.unit || "")) ||
      (what.kind === "length" && /lf|ft|feet/.test(q.unit || "")) || (what.kind === "count" && /ea|count/.test(q.unit || "") ));
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
async function reviewAsk(msg, btn, path, body, doneText, prefix, reloadSheet) {
  btn.disabled = true;
  msg.replaceChildren();
  const done = async r => {
    toast(doneText(r));
    $("review-message").replaceChildren();
    RV.selected.clear();
    await refreshData();
    if (reloadSheet) await openSheet(RV.sheetId, $("review-message"));
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
const AUTO_TIMEOUT_MS = 10 * 60 * 1000;     // give up after 10 minutes
const AGENT = "concrete-agent";             // proposed_by of the agent's measurements
const LLM_AGENT = "llm-takeoff";            // proposed_by of the LLM fallback's measurements
const AUTO = { runId: null, estimateId: null, sheetId: null, viewportId: null, timer: null, startedAt: 0,
               status: null, step: "", error: null, measurementIds: [],
               candidates: new Map(), candidatesLoading: new Set(), llmTakeoff: new Map(),
               source: "geometry" };

function hasConcreteTrade() { return !!(RV.data && RV.data.trades.some(t => t.module_id === "concrete")); }

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
async function loadAutoCandidates() {
  if (!hasConcreteTrade() || !RV.data.can_measure) return;
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
  // A sheet switched off for Concrete can't run the agent — the button stays, disabled, with the reason.
  const offForConcrete = (RV.inactiveTrades || []).includes("concrete");
  if (runBtn) {
    runBtn.disabled = !hasConcreteTrade() || AUTO.status === "running" || offForConcrete;
    runBtn.title = offForConcrete
      ? "This sheet is switched off for Concrete — switch it back on from the Plans screen to run the agent."
      : (hasConcreteTrade() ? "Let the Concrete agent measure the slab on this sheet, then review what it proposes."
        : "Add the Concrete trade to this estimate first — the agent only measures concrete slabs.");
  }
  const runHere = !!(AUTO.status && AUTO.sheetId === RV.sheetId);
  const parts = [];
  if (offForConcrete && hasConcreteTrade()) {
    const psId = RV.sheet && RV.sheet.plan_set_id;
    parts.push(el("p", { class: "note warn", id: "bp-auto-off" }, "This sheet is switched off for Concrete — the agent skips it. ",
      psId ? el("a", { href: "#/plan-sets/" + psId }, "Switch it back on from the Plans screen") : "Switch it back on from the Plans screen", "."));
  }
  if (runHere && AUTO.status === "running") {
    parts.push(el("p", { class: "note", id: "bp-auto-status", role: "status" },
      "🤖 Agent running" + (AUTO.step ? " — " + AUTO.step : "…")));
  } else if (runHere && AUTO.status === "done") {
    const n = (AUTO.measurementIds || []).length;
    const src = AUTO.source === "llm" ? " read from the plan by the AI" : "";
    parts.push(el("p", { class: "note", id: "bp-auto-status", role: "status" }, n
      ? "Agent finished: " + n + " proposed measurement(s)" + src + " — review and approve them below."
      : "Agent finished: no measurements proposed on this sheet."));
  } else if (runHere && AUTO.status === "failed") {
    parts.push(el("p", { class: "error", id: "bp-auto-status", role: "alert" },
      "Agent run failed — " + (AUTO.error || "unknown error")));
  } else if (runHere && AUTO.status === "timeout") {
    parts.push(el("p", { class: "error", id: "bp-auto-status", role: "alert" },
      "Agent run timed out after 10 minutes — try re-running it."));
  }
  const vp = autoRunViewport();
  if (vp && hasConcreteTrade() && AUTO.candidates.has(vp.id)) {
    const list = AUTO.candidates.get(vp.id);
    let text = "Agent found no slab outline on this sheet — measure it manually or re-run after the plan is processed.";
    const llm = AUTO.llmTakeoff.get(vp.id);
    if (!list.length && llm && llm.enabled) {
      text = llm.ready
        ? "Agent found no slab outline on this sheet — the AI will read the plan instead when you run it (LLM takeoff is on)."
        : "Agent found no slab outline on this sheet — LLM takeoff is on, but the AI isn't ready (no API key saved?) — check 🤖 AI agents in Setup.";
    }
    if (list.length) {
      const big = list.reduce((a, b) => parseFloat(b.area_sqft || 0) > parseFloat(a.area_sqft || 0) ? b : a, list[0]);
      text = "Agent found " + list.length + " possible slab outline(s) — the largest is " + candidateLabel(big) + ".";
    }
    // LLM takeoff off: the AI won't run at all — say so and point at the switch, instead of only
    // suggesting manual measuring (off is the default, so this is the line most people see).
    if (!list.length && llm && !llm.enabled) {
      parts.push(el("p", { class: "muted small", id: "bp-auto-candidates" },
        "Agent found no slab outline on this sheet — the AI didn't run because LLM takeoff is off. ",
        el("a", { href: "#/agents" }, "Turn it on in 🤖 AI agents"), " to let the AI read the plan, or measure it manually."));
    } else {
      parts.push(el("p", { class: "muted small", id: "bp-auto-candidates" }, text));
    }
  }
  const agentHere = agentMeasurementsOnSheet().length > 0;
  const runKnownHere = !!(AUTO.runId && AUTO.sheetId === RV.sheetId);
  // AI Log: what the AI was given and what it returned for this run (nothing there means the AI never ran).
  if (runKnownHere) parts.push(el("p", { class: "muted small", id: "bp-auto-ai-log" },
    el("a", { href: "#/agents/ai-log?auto_run_id=" + AUTO.runId }, "📋 AI Log — what the AI was given and what it returned for this run")));
  if (AUTO.status !== "running" && (runKnownHere || agentHere) && RV.data.can_measure) parts.push(rerunButton());
  slot.replaceChildren(...parts);
}

function stopAutoPoll() { if (AUTO.timer) { clearTimeout(AUTO.timer); AUTO.timer = null; } }

// Watch a run that was just started (or re-run): poll every 2 s until it is done, failed, or 10 minutes pass.
// The timer stops itself when the page goes away (the status slot is gone) or a newer run takes over.
function trackAutoRun(runId, vp) {
  stopAutoPoll();
  AUTO.runId = runId;
  AUTO.estimateId = RV.estimateId;
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
    if (Date.now() - AUTO.startedAt > AUTO_TIMEOUT_MS) { AUTO.status = "timeout"; drawAutoRunStatus(); return; }
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
    AUTO.step = run.step || "";
    AUTO.source = run.source || "geometry";
    if (run.status === "done") {
      AUTO.status = "done";
      AUTO.measurementIds = run.measurement_ids || [];
      const n = AUTO.measurementIds.length;
      const src = AUTO.source === "llm" ? " (read from the plan by the AI)" : "";
      toast(n ? "Agent finished: " + n + " proposed measurement(s)" + src + " to review." : "Agent finished: nothing proposed.");
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
  const vp = autoRunViewport();
  if (!vp) {
    AUTO.status = "failed";
    AUTO.sheetId = RV.sheetId;
    AUTO.error = "This sheet has no view to measure — read the plans first.";
    drawAutoRunStatus();
    return;
  }
  // Running from the click, not from the answer: a second click while the start is in flight is ignored.
  AUTO.status = "running";
  AUTO.sheetId = RV.sheetId;
  AUTO.estimateId = RV.estimateId;
  AUTO.viewportId = vp.id;
  AUTO.step = "Starting…";
  AUTO.error = null;
  drawAutoRunStatus();
  try {
    const r = await api("POST", "/auto-run", { estimate_id: RV.estimateId, sheet_id: RV.sheetId,
                                               viewport_id: vp.id, module_id: "concrete" });
    if (!r.run_id) throw new Error("the agent didn't start (no run id)");
    trackAutoRun(r.run_id, vp);
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
    AUTO.error = "No agent run to re-run on this sheet yet — use 🤖 Agent auto-run first.";
    drawAutoRunStatus();
    return;
  }
  try {
    const r = await api("POST", "/auto-run/" + id + "/rerun", {});
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
      RV.data.can_measure ? "No measurements yet. Pick a tool (📏 Length, ⬠ Area…) and draw on the plan, or click rooms and walls and make a measurement from them." :
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
}

// ------------------------------------------------------------------ guided takeoff: what to measure, with which tool
// A persistent panel above the plan (not a one-off tour): for every measurement-backed question
// of each trade on this project, the quantity, the tool that measures it, and why — plus whether
// it is measured yet. David's first live takeoff (NSB shed slab) had no such list: he used
// Rectangle on the footing, which gives an area, not the linear feet the footing is priced by.
// The list comes from the questions the takeoff call already returns (RV.data.trades — number and
// integer questions only, see _trade in estimator/api/takeoff_api.py), so no new endpoint.
const GUIDE_TOOLS = {
  area: { tool: "rect", label: "▭ Rectangle or ⬠ Area" },
  length: { tool: "length", label: "📏 Length" },
  count: { tool: "count", label: "✚ Count" },
};
// Why this quantity needs that tool. The concrete lines are the ones David tripped over;
// everything else falls back to the unit: sqft is priced by the square foot, lf by the foot.
const GUIDE_WHY = {
  "concrete.area_sqft": "the slab's area — it sets the concrete, gravel, mesh, and finish, all priced by the square foot",
  "concrete.perimeter_lf": "forms are the boards around the slab edge that hold wet concrete in place, priced per foot — if left at 0 the app guesses a square slab's perimeter, badly wrong for a long narrow slab",
  "concrete.footing_lf": "the thickened edge under the slab's rim — its length sets the digging, forms, and rebar, priced by the linear foot; click all four corners AND back to the start to close the loop",
};
function guideToolFor(q) {
  const u = (q.unit || "").toLowerCase();
  if (/sq|sf/.test(u)) return "area";
  if (/lf|ft|feet/.test(u)) return "length";
  return "count";                    // no unit: a count of things (outlets, doors, windows…)
}
function guideWhyFor(mod, q) {
  const key = mod + "." + q.id;
  if (GUIDE_WHY[key]) return GUIDE_WHY[key];
  const kind = guideToolFor(q);
  if (kind === "area") return "priced by the square foot — Rectangle for a straight-sided shape, Area for an odd one";
  if (kind === "length") return "priced by the linear foot — click along it";
  return "priced each — click every one";
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
    const same = waiting.filter(m => m.unit === q.unit);
    const total = same.reduce((a, m) => a + parseFloat(m.qty || 0), 0);
    const text = same.length ? num(total) + (q.unit ? " " + q.unit : "") : waiting.length + " measurement(s)";
    const remeasure = waiting.some(m => m.needs_remeasure) ? " · ⚠ re-measure" : "";
    return ["proposed", "to review — " + text + remeasure];
  }
  return ["missing", "not yet measured"];
}
// Calibration is the first step: until a view has a scale, nothing measured on
// it has real feet. Uses the viewport state the sheet already carries — no new
// endpoint. NTS views cannot be calibrated, so they do not count.
function guideCalibration() {
  const views = (RV.viewports || []).filter(v => !v.is_nts);
  if (!views.length) return ["missing", "not to scale — nothing to calibrate"];
  if (views.some(v => !v.measurable)) return ["missing", "not calibrated — calibrate before measuring"];
  const scaled = views.find(v => parseFloat(v.scale_ratio));
  return ["approved", "✓ calibrated" + (scaled ? " — 1″ = " + scaled.scale_ratio + "″" : "")];
}

function drawTakeoffGuide() {
  const slot = $("bp-guide-slot");
  if (!slot || !RV.data) return;
  const trades = RV.data.trades || [];
  const head = el("summary", {}, "📋 What to measure — and which tool");
  if (!trades.length) {
    slot.replaceChildren(el("details", { class: "card section", id: "bp-guide", open: true }, head,
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
  if (RV.data.can_measure) {
    const pickCal = () => setTool("calibrate", $("review-message"));
    calRow.addEventListener("click", pickCal);
    calRow.addEventListener("keydown", ev => { if (ev.key === "Enter") pickCal(); });
  }
  parts.push(el("ul", { class: "bp-rows", id: "bp-guide-calibration" }, calRow));
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
      const li = el("li", { class: "bp-row", "data-module": tr.module_id, "data-question": q.id,
        tabindex: RV.data.can_measure ? "0" : null,
        title: RV.data.can_measure ? "Use the " + tool.label + " tool" : null },
        el("span", { class: "bp-row-name" }, q.label, el("br", {}),
          el("span", { class: "muted small" }, guideWhyFor(tr.module_id, q))),
        el("span", { class: "bp-row-qty" }, tool.label),
        el("span", { class: "status" + (state === "approved" ? "" : " sample") }, text));
      if (RV.data.can_measure) {
        const pick = () => setTool(tool.tool, $("review-message"));
        li.addEventListener("click", pick);
        li.addEventListener("keydown", ev => { if (ev.key === "Enter") pick(); });
      }
      return li;
    });
    parts.push(el("ul", { class: "bp-rows", id: "bp-guide-" + tr.module_id }, rows));
  }
  slot.replaceChildren(el("details", { class: "card section", id: "bp-guide", open: true }, ...parts));
}

function totalsText(ms) {
  const by = {};
  for (const m of ms) if (m.status !== "rejected") by[m.unit] = (by[m.unit] || 0) + parseFloat(m.qty || 0);
  const s = Object.entries(by).map(([u, v]) => num(v) + " " + u).join(" + ");
  return s || "nothing yet";
}

function measurementRow(m, msg) {
  const flags = [m.locked ? "🔒" : "", m.suggested_qty !== null && m.suggested_qty !== undefined ? "✎ suggestion" : "", m.needs_remeasure ? "⚠ re-measure" : ""].filter(Boolean).join(" ");
  const agent = m.proposed_by === AGENT || m.proposed_by === LLM_AGENT;
  const llm = m.proposed_by === LLM_AGENT;
  const li = el("li", { class: "bp-row " + m.status + (RV.measurementId === m.id ? " active" : ""), "data-mid": m.id, tabindex: "0" },
    el("span", { class: "bp-row-name" }, agent ? el("span", { class: "bp-agent", title: llm ? "Read from the plan by the AI (LLM takeoff)" : "Proposed by the Concrete agent" }, "🤖 ") : null, measurementName(m)),
    el("span", { class: "bp-row-qty" }, num(m.qty) + " " + m.unit),
    el("span", { class: "status " + (m.status === "approved" ? "" : "sample") }, m.status === "proposed" ? "to review" : words(m.status)),
    el("span", { class: "muted small" }, pct(m.confidence) + " · " + words(m.method) + (flags ? " · " + flags : "") + (agent ? " · " + agentSourceText(m) : "")));
  if (m.proposed_by === AGENT) {   // LLM measurements have no outline to show
    const show = el("button", { class: "button", type: "button", id: "bp-show-outline-" + m.id }, "Show outline");
    show.addEventListener("click", ev => { ev.stopPropagation(); showAgentOutline(m); });
    li.append(show);
  }
  const open = () => showDetail(m.id, msg, true);
  li.addEventListener("click", open);
  li.addEventListener("keydown", ev => { if (ev.key === "Enter") open(); });
  return li;
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
async function showDetail(id, msg, zoom) {
  RV.measurementId = id;
  const m = RV.data.takeoff.measurements.find(x => x.id === id);
  if (m && m.sheet_id && m.sheet_id !== RV.sheetId && $("review-sheet") && RV.data.sheets.some(s => s.id === m.sheet_id)) {
    $("review-sheet").value = m.sheet_id;
    await openSheet(m.sheet_id, msg);
  }
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
    ["Proposed by", x.proposed_by || "—"],
    agentOutline ? ["Agent outline", agentOutline] : null,
    aiReading ? ["AI reading", aiReading] : null,
    aiReading && c.auto_run_id ? ["AI Log", el("a", { href: "#/agents/ai-log?auto_run_id=" + c.auto_run_id, id: "bp-detail-ai-log" }, "What the AI was given and what it returned")] : null,
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
  if (x.status === "proposed" && d.can_approve) {
    btn("bp-approve-one", "✓ Approve…", b => reviewAsk(out, b, "/measurements/approve", { measurement_ids: [x.id] }, () => "Approved and locked", "bp-approve"));
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
  if (x.status !== "rejected" && d.can_correct) {
    btn("bp-edit", "Correct…", () => correctForm(x, out));
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
    return el("tr", { "data-group": g.id }, el("td", {}, swatch, " " + g.label), el("td", {}, g.id === "measurements" ? "" : g.count), el("td", {}, show), el("td", {}, lock));
  });
  pane.replaceChildren(el("table", { class: "list", id: "bp-layers" },
    el("thead", {}, el("tr", {}, el("th", {}, "Layer"), el("th", {}, "Items"), el("th", {}, "Show"), el("th", {}, "Lock"))), el("tbody", {}, rows)),
    el("p", { class: "muted small" }, "CAD layers are sorted into these groups by their names (A-WALL → Walls, E-LITE → Electrical…). A locked layer can't be selected. What's shown is remembered on this browser."));
}

window.addEventListener("resize", () => { if (RV.viewer && RV.viewer.box.isConnected) RV.viewer.render(); });

SCREENS.takeoffs = renderTakeoffs;
PAGES.takeoff = renderReview;
