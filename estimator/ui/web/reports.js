/* Reports screen and the plan revision overlay (Coder 2 Sprint 17).
 *
 * Loaded after app.js (el, api, apiImage, money, when, words, tile, helpLink, errorBox, go, toast, canOpen, can).
 * Routes:  #/reports?tab=winloss|takeoff|revisions|actuals|exports&estimate=<id>
 *          #/revisions/<report id>?sheet=<n>&old=1     one revision report drawn over the sheets
 * Read only, except: exporting writes a file to the exports folder, and comparing two plan sets (asks first) saves a
 * revision report and flags measurements to re-measure (Coder 1's plan_compare_revisions).
 */
"use strict";

const REPORT_TABS = [["winloss", "🏆 Win / loss"], ["takeoff", "📏 Takeoff report"], ["revisions", "🔀 Plan revisions"],
                     ["actuals", "💵 Estimate vs actual"], ["exports", "⬇ Exports"]];
const REV_KINDS = [["added", "Added", "rev-added"], ["removed", "Removed", "rev-removed"], ["changed", "Changed", "rev-changed"],
                   ["moved", "Moved", "rev-moved"]];
function svgEl(tag, attrs, ...kids) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined) continue;
    if (k === "class") n.setAttribute("class", v); else n.setAttribute(k, String(v));
  }
  for (const k of kids.flat()) if (k) n.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return n;
}

function repPct(v) { return v === null || v === undefined ? "—" : Math.round(Number(v) * 100) + "%"; }

function hashQuery() { return new URLSearchParams(location.hash.split("?")[1] || ""); }

// Ask the server's question (needs_confirmation, with its list of changes), then send confirm=true and call after().
async function askConfirm(msg, btn, path, body, after, prefix) {
  const p = prefix || "rep";
  btn.disabled = true;
  state.busy = true;
  msg.replaceChildren();
  const done = r => { state.busy = false; after(r); };
  try {
    const r = await api("POST", path, body);
    if (!r.needs_confirmation) { done(r); return; }
    const yes = el("button", { class: "primary", type: "button", id: p + "-confirm" }, "Yes");
    const no = el("button", { class: "button", type: "button", id: p + "-cancel" }, "Cancel");
    const changes = (r.changes || []).filter(c => typeof c === "string");
    msg.replaceChildren(el("div", { class: "confirm", id: p + "-confirm-box" }, el("p", {}, el("strong", {}, r.question)),
      changes.length ? el("ul", {}, changes.map(c => el("li", {}, c))) : null, el("div", { class: "row" }, yes, no)));
    yes.focus();
    no.addEventListener("click", () => { state.busy = false; msg.replaceChildren(el("p", { class: "muted" }, "Cancelled — nothing changed.")); });
    yes.addEventListener("click", async () => {
      yes.disabled = no.disabled = true;
      try { done(await api("POST", path, { ...body, confirm: true })); }
      catch (e) { state.busy = false; if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
    });
  } catch (e) {
    state.busy = false;
    if (e.status !== 401) msg.replaceChildren(errorBox(e));
  } finally { btn.disabled = false; }
}

// A file from the API saved to the user's computer (works with the Jobs app's token too).
async function downloadFile(url, name) {
  const opts = { credentials: "same-origin", headers: {} };
  if (APP_TOKEN) opts.headers.Authorization = "Bearer " + APP_TOKEN;
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error("the download failed (HTTP " + r.status + ")");
  const u = URL.createObjectURL(await r.blob());
  const a = el("a", { href: u, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(u), 10000);
}

async function projectPicker(id, selected, withAll) {
  const r = await api("GET", "/estimates?limit=200");
  return el("select", { id, "aria-label": "Project" },
    withAll ? el("option", { value: "" }, withAll) : el("option", { value: "" }, "Pick a project"),
    r.estimates.map(e => el("option", { value: e.id, selected: String(e.id) === String(selected || "") },
      "#" + e.id + " " + (e.title || "untitled") + " (" + words(e.status) + ")")));
}

// ------------------------------------------------------------------ the Reports screen
async function renderReports(main, screen) {
  const q = hashQuery();
  const tab = REPORT_TABS.some(t => t[0] === q.get("tab")) ? q.get("tab") : "winloss";
  const estimate = q.get("estimate") || "";
  const tabs = el("div", { class: "tabs", id: "report-tabs", role: "tablist" }, REPORT_TABS.map(([id, label]) =>
    el("a", { href: "#/reports?tab=" + id + (estimate ? "&estimate=" + estimate : ""), role: "tab", "data-tab": id,
              class: id === tab ? "active" : "", "aria-selected": id === tab ? "true" : "false" }, label)));
  const body = el("div", { id: "report-body" }, el("p", { class: "muted" }, "Loading…"));
  main.replaceChildren(el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("reports")), tabs, body);
  const draw = { winloss: reportWinLoss, takeoff: reportTakeoff, revisions: reportRevisions, actuals: reportActuals,
                 exports: reportExports }[tab];
  try { await draw(body, estimate); } catch (e) { if (e.status !== 401) body.replaceChildren(errorBox(e)); }
}

async function reportWinLoss(body) {
  const r = await api("GET", "/reports/summary");
  const parts = [el("div", { class: "grid tiles", id: "wl-tiles" },
    tile(repPct(r.win_rate), "Win rate (won ÷ won + lost)"), tile(r.won, "Won"), tile(r.lost, "Lost"),
    tile(money(r.won_cents), "Value won"), tile(money(r.lost_cents), "Value lost"), tile(money(r.open_bids_cents), "Bids out now"))];
  if (r.note) parts.push(el("p", { class: "note" }, r.note));
  parts.push(el("h3", {}, "By month"), el("table", { class: "list", id: "wl-months" },
    el("thead", {}, el("tr", {}, ["Month", "Won", "Lost", "Win rate", "", "Value won"].map(h => el("th", {}, h)))),
    el("tbody", {}, r.by_month.map(m => el("tr", { "data-month": m.month }, el("td", {}, m.month), el("td", { class: "num" }, m.won),
      el("td", { class: "num" }, m.lost), el("td", { class: "num" }, repPct(m.win_rate)),
      el("td", {}, m.win_rate === null ? "" : el("meter", { min: 0, max: 1, value: m.win_rate, "aria-label": "win rate" })),
      el("td", { class: "num" }, money(m.won_cents)))))));
  parts.push(el("h3", {}, "By trade"), r.by_trade.length ? el("table", { class: "list", id: "wl-trades" },
    el("thead", {}, el("tr", {}, ["Trade", "Won", "Lost", "Win rate", "Value won"].map(h => el("th", {}, h)))),
    el("tbody", {}, r.by_trade.map(t => el("tr", { "data-trade": t.module_id }, el("td", {}, words(t.module_id)),
      el("td", { class: "num" }, t.won), el("td", { class: "num" }, t.lost), el("td", { class: "num" }, repPct(t.win_rate)),
      el("td", { class: "num" }, money(t.won_cents)))))) : el("p", { class: "muted" }, "Nothing won or lost yet."));
  parts.push(el("h3", {}, "All estimates by status"), el("p", { id: "wl-status" },
    Object.entries(r.by_status).map(([k, v]) => words(k) + " " + v).join(" · ") || "No estimates yet."));
  body.replaceChildren(...parts);
}

async function reportTakeoff(body, estimate) {
  const pick = await projectPicker("tr-project", estimate);
  pick.addEventListener("change", () => go("#/reports?tab=takeoff&estimate=" + pick.value));
  const parts = [el("div", { class: "row filters" }, el("label", {}, "Project", pick))];
  if (!estimate) { body.replaceChildren(...parts, el("p", { class: "muted" }, "Pick a project to see every measurement by trade.")); return; }
  const r = await api("GET", "/reports/takeoff/" + estimate);
  const t = r.totals;
  parts.push(el("div", { class: "grid tiles", id: "tr-tiles" }, tile(t.measurements, "Measurements"), tile(t.approved, "Approved (priced)"),
    tile(t.waiting, "Waiting for approval"), tile(t.remeasure, "To re-measure", t.remeasure ? "warn" : ""),
    tile(t.raster, "From scans or photos", t.raster ? "warn" : "")));
  r.notes.forEach(n => parts.push(el("p", { class: "note" }, n)));
  parts.push(el("p", {}, el("a", { href: "#/takeoffs/" + r.estimate_id }, "📏 Open in Blueprint Review"), " · ",
    el("a", { href: "#/estimates/" + r.estimate_id }, "🧮 Open the estimate")));
  if (!r.trades.length) parts.push(el("div", { class: "card empty" }, "No measurements on this project yet. ",
    el("a", { href: "#/takeoffs/" + r.estimate_id }, "Open Blueprint Review"), " and measure the plans."));
  for (const tr of r.trades) {
    parts.push(el("div", { class: "card section", "data-trade": tr.module_id },
      el("h3", {}, words(tr.module_id) + " — " + tr.approved + " approved, " + tr.waiting + " waiting"),
      el("table", { class: "list" }, el("thead", {}, el("tr", {}, ["Quantity for", "Approved", "Waiting", "Unit", "Count"].map(h => el("th", {}, h)))),
        el("tbody", {}, tr.questions.map(qd => el("tr", {}, el("td", {}, words(qd.feeds || qd.label || "other")),
          el("td", { class: "num" }, qd.approved_qty), el("td", { class: "num" }, qd.waiting_qty), el("td", {}, qd.unit),
          el("td", { class: "num" }, qd.count))))),
      el("details", {}, el("summary", {}, "Each measurement (" + tr.measurements.length + ")"),
        el("table", { class: "list" }, el("tbody", {}, tr.measurements.map(m => el("tr", { "data-m": m.id },
          el("td", {}, el("a", { href: "#/takeoffs/" + r.estimate_id + "?m=" + m.id }, m.label || words(m.feeds) || "measurement")),
          el("td", {}, m.room || ""), el("td", { class: "num" }, m.qty + " " + m.unit), el("td", {}, words(m.status)),
          el("td", {}, m.method, m.method === "raster" ? el("span", { class: "status sample" }, " needs review") : null),
          el("td", {}, m.sheet_no || ""),
          el("td", {}, m.needs_remeasure ? el("span", { class: "status sample" }, "re-measure") : ""))))))));
  }
  if (r.rejected.length) parts.push(el("p", { class: "muted" }, r.rejected.length + " measurement(s) were taken out (rejected) and aren't counted."));
  body.replaceChildren(...parts);
}

async function reportRevisions(body, estimate) {
  const pick = await projectPicker("rv-project", estimate, "All projects");
  pick.addEventListener("change", () => go("#/reports?tab=revisions" + (pick.value ? "&estimate=" + pick.value : "")));
  const r = await api("GET", "/reports/revisions" + (estimate ? "?estimate_id=" + estimate : ""));
  const parts = [el("div", { class: "row filters" }, el("label", {}, "Project", pick)),
    el("p", { class: "muted" }, "When a revised plan set is uploaded (Rev A → Rev B), compare it with the one it replaces: " +
      "the sheets are matched, every change is drawn over the plan, measurements on unchanged work carry over and the rest are flagged to re-measure.")];
  if (r.not_compared.length) {
    parts.push(el("h3", {}, "Revised plans not compared yet"));
    const list = el("div", { id: "rv-waiting" });
    for (const w of r.not_compared) {
      const msg = el("div", { role: "status" });
      const btn = el("button", { class: "primary", type: "button", "data-new": w.new_plan_set_id }, "Compare Rev " + w.from_rev + " → Rev " + w.to_rev + "…");
      btn.disabled = !w.ready || !r.can_compare;
      btn.addEventListener("click", () => askConfirm(msg, btn, "/reports/revisions", { new_plan_set_id: w.new_plan_set_id },
        done => { toast("Revision report saved."); go("#/revisions/" + done.report_id); }, "rv"));
      list.append(el("div", { class: "card section row" }, el("span", {}, el("strong", {}, w.estimate_title), " · " + w.name),
        btn, w.ready ? null : el("span", { class: "muted small" }, w.why_not), msg));
    }
    parts.push(list);
  }
  parts.push(el("h3", {}, "Revision reports"));
  parts.push(r.reports.length ? el("table", { class: "list clickable", id: "rv-reports" },
    el("thead", {}, el("tr", {}, ["Project", "What changed", "Re-measure", "Carried over", "Compared"].map(h => el("th", {}, h)))),
    el("tbody", {}, r.reports.map(x => el("tr", { "data-id": x.report_id, onclick: () => go("#/revisions/" + x.report_id) },
      el("td", {}, el("a", { href: "#/revisions/" + x.report_id }, x.estimate_title)), el("td", {}, x.said || ""),
      el("td", { class: "num" }, x.flagged), el("td", { class: "num" }, x.carried), el("td", {}, when(x.created_at) + " · " + x.created_by)))))
    : el("p", { class: "muted", id: "rv-none" }, "No revision reports yet."));
  body.replaceChildren(...parts);
}

async function reportActuals(body, estimate) {
  const pick = await projectPicker("ac-project", estimate, "Every price with job costs");
  pick.addEventListener("change", () => go("#/reports?tab=actuals" + (pick.value ? "&estimate=" + pick.value : "")));
  const r = await api("GET", "/reports/actuals" + (estimate ? "?estimate_id=" + estimate : ""));
  const parts = [el("div", { class: "row filters" }, el("label", {}, "Show", pick)),
    el("p", { class: "muted" }, "Your unit costs against past estimates and what jobs really cost (recorded with est_record_actuals). Nothing changes here.")];
  if (r.note) parts.push(el("p", { class: "note" }, r.note));
  if (r.whole_jobs) parts.push(el("p", { id: "ac-whole" }, r.whole_jobs.count + " whole job(s): on average " + r.whole_jobs.average + "."));
  if (r.lines) {
    parts.push(el("table", { class: "list", id: "ac-lines" },
      el("thead", {}, el("tr", {}, ["Line", "Unit cost", "Usual", "Past estimates", "Jobs", ""].map(h => el("th", {}, h)))),
      el("tbody", {}, r.lines.map(l => el("tr", { "data-key": l.price_key }, el("td", {}, l.description),
        el("td", { class: "num" }, l.unit_cost + " / " + l.unit), el("td", { class: "num" }, l.usual_unit_cost || "—"),
        el("td", { class: "num" }, l.past_estimates), el("td", { class: "num" }, l.jobs_with_actuals),
        el("td", {}, l.flag ? el("span", { class: "status sample" }, words(l.flag)) : ""))))));
  } else if (r.prices && r.prices.length) {
    parts.push(el("table", { class: "list", id: "ac-prices" },
      el("thead", {}, el("tr", {}, ["Price", "Price book", "Estimated (usual)", "Jobs paid", "Jobs ran"].map(h => el("th", {}, h)))),
      el("tbody", {}, r.prices.map(p => el("tr", { "data-key": p.price_key }, el("td", {}, p.price_key),
        el("td", { class: "num" }, (p.price_book || "—") + (p.unit ? " / " + p.unit : "")), el("td", { class: "num" }, p.usual_estimated_unit_cost || "—"),
        el("td", { class: "num" }, p.actual_unit_cost || "—"), el("td", {}, p.jobs_run || ""))))));
  }
  if (r.suggestions && r.suggestions.length) {
    parts.push(el("h3", {}, "Worth a look"), el("ul", { id: "ac-suggestions" }, r.suggestions.map(s => el("li", {}, s.message))),
      canOpen("price_book") ? el("p", {}, el("a", { href: "#/price_book" }, "💲 Open the Price Book")) : null);
  }
  body.replaceChildren(...parts);
}

async function reportExports(body, estimate) {
  const pick = await projectPicker("ex-project", estimate, "A list of every estimate");
  const status = el("select", { id: "ex-status", "aria-label": "Status" }, el("option", { value: "" }, "any status"),
    STATUSES.map(s => el("option", { value: s }, words(s))));
  const fmt = el("select", { id: "ex-format", "aria-label": "Format" }, el("option", { value: "xlsx" }, "Excel (.xlsx)"),
    el("option", { value: "csv" }, "CSV"));
  const btn = el("button", { class: "primary", type: "button", id: "ex-go" }, "⬇ Export");
  const msg = el("div", { id: "ex-message", role: "status" });
  const statusLabel = el("label", {}, "Only", status);
  const sync = () => { statusLabel.hidden = !!pick.value; };
  pick.addEventListener("change", sync);
  sync();
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    msg.replaceChildren();
    try {
      const r = await api("POST", "/reports/export", { estimate_id: pick.value ? Number(pick.value) : null,
        status: pick.value ? null : (status.value || null), format: fmt.value });
      await downloadFile(r.url, r.file);
      msg.replaceChildren(el("p", {}, "Exported " + r.what + " → ", el("strong", { id: "ex-file" }, r.file),
        el("span", { class: "muted" }, " (also kept in the Estimator's exports folder).")));
    } catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
    finally { btn.disabled = false; }
  });
  body.replaceChildren(el("p", { class: "muted" }, "One project's line items and totals, or a list of estimates, as an Excel or CSV file. " +
      "For QuickBooks, import the CSV (or use AI-Prowler's own QuickBooks export for invoices)."),
    el("div", { class: "card section row filters" }, el("label", {}, "Export", pick), statusLabel, el("label", {}, "As", fmt), btn), msg);
}

// ------------------------------------------------------------------ one revision report over the sheets
function revBox(b, w, h) {
  if (!b) return null;
  const pad = Math.max(w, h) * 0.004;
  return { x: b[0] - pad, y: b[1] - pad, w: Math.max(b[2] - b[0], 0) + 2 * pad, h: Math.max(b[3] - b[1], 0) + 2 * pad };
}

async function renderRevision(main, id) {
  const q = hashQuery();
  const r = await api("GET", "/reports/revisions/" + id);
  const sheets = r.sheets || [];
  const n = Math.min(Math.max(Number(q.get("sheet") || 0), 0), Math.max(sheets.length - 1, 0));
  const old = q.get("old") === "1";
  const t = r.totals || {};
  const parts = [el("p", {}, el("a", { href: "#/reports?tab=revisions&estimate=" + r.estimate_id }, "← Plan revisions"), " · ",
      el("a", { href: "#/plan-sets/" + r.new_plan_set_id }, "Rev " + r.to_rev + " plans"), " · ",
      el("a", { href: "#/takeoffs/" + r.estimate_id }, "📏 Blueprint Review")),
    el("div", { class: "page-head" }, el("h2", {}, "🔀 Rev " + r.from_rev + " → Rev " + r.to_rev), helpLink("reports")),
    el("p", { id: "rev-said" }, r.said || ""),
    el("div", { class: "grid tiles", id: "rev-tiles" }, tile(t.added || 0, "Added", "rev-added"), tile(t.removed || 0, "Removed", "rev-removed"),
      tile(t.changed || 0, "Changed", "rev-changed"), tile(t.moved || 0, "Moved", "rev-moved"), tile(t.unchanged || 0, "Unchanged"),
      tile((r.flagged || []).length, "To re-measure", (r.flagged || []).length ? "warn" : ""))];
  if (!sheets.length) {
    parts.push(el("div", { class: "card empty" }, "No sheets of the two sets could be matched. The two plan sets have no sheets in common, so there is nothing to compare - compare a different revision pair from the plan set page."));
  } else {
    const s = sheets[n];
    const pick = el("select", { id: "rev-sheet", "aria-label": "Sheet" }, sheets.map((x, i) =>
      el("option", { value: i, selected: i === n }, (x.sheet_no || "sheet " + (i + 1)) + (x.title ? " · " + x.title : "") +
        (x.changed_anything ? "  (" + ["added", "removed", "changed", "moved"].filter(k => x[k]).map(k => x[k] + " " + k).join(", ") + ")" : "  (no change)"))));
    const flip = el("button", { class: "button", type: "button", id: "rev-flip" }, old ? "Show Rev " + r.to_rev + " (new)" : "Show Rev " + r.from_rev + " (old)");
    const goTo = (i, o) => go("#/revisions/" + id + "?sheet=" + i + (o ? "&old=1" : ""));
    pick.addEventListener("change", () => goTo(pick.value, old));
    flip.addEventListener("click", () => goTo(n, !old));
    const shows = {};
    const boxes = el("div", { class: "row filters", id: "rev-kinds" }, REV_KINDS.map(([k, label, cls]) => {
      const c = el("input", { type: "checkbox", checked: true, "data-kind": k });
      shows[k] = c;
      return el("label", { class: "check " + cls }, c, " " + label + " (" + (s[k] || 0) + ")");
    }));
    parts.push(el("div", { class: "row filters" }, el("label", {}, "Sheet", pick), flip), boxes);
    const sheet = old ? s.old_sheet : s.new_sheet;
    const sheetId = old ? s.old_sheet_id : s.new_sheet_id;
    const W = Number((sheet || {}).width) || 36, H = Number((sheet || {}).height) || 24;
    const svg = svgEl("svg", { class: "rev-overlay", viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none", id: "rev-svg" });
    for (const [k, label, cls] of REV_KINDS) {
      const g = svgEl("g", { class: cls, "data-kind": k });
      for (const it of s[k + "_items"] || []) {
        const side = old ? it.old : (it.new || (k === "removed" ? it.old : null));
        if (!side || (old && k === "added")) continue;
        const b = revBox(side.bbox, W, H);
        if (!b) continue;
        g.append(svgEl("rect", { x: b.x, y: b.y, width: b.w, height: b.h, "vector-effect": "non-scaling-stroke" },
          svgEl("title", {}, label + ": " + [side.kind, side.label, side.tag].filter(Boolean).join(" · "))));
      }
      svg.append(g);
      shows[k].addEventListener("change", () => g.classList.toggle("hidden", !shows[k].checked));
    }
    const img = el("img", { class: "rev-sheet", alt: "Sheet " + ((sheet || {}).sheet_no || "") });
    img.addEventListener("error", () => img.replaceWith(el("div", { class: "card empty" }, "The sheet picture isn't available; the changes are listed below.")));
    if (sheet && sheet.has_image) apiImage(img, API + "/sheets/" + sheetId + "/image");
    parts.push(el("div", { class: "rev-stage", id: "rev-stage" }, sheet && sheet.has_image ? img : el("div", { class: "rev-blank" }), svg),
      el("p", { class: "muted small" }, old ? "Rev " + r.from_rev + ": red was removed, orange changed or moved in the new set." :
        "Rev " + r.to_rev + ": green is new, orange changed or moved, red outlines what was removed."));
    const rows = [];
    for (const [k] of REV_KINDS) for (const it of s[k + "_items"] || []) {
      const o = it.new || it.old || {};
      const size = it.old && it.new && it.old.real_units && it.new.real_units ?
        Object.keys(it.new.real_units).filter(u => it.new.real_units[u] !== it.old.real_units[u])
          .map(u => words(u) + " " + it.old.real_units[u] + " → " + it.new.real_units[u]).join("; ") : "";
      rows.push(el("tr", { "data-kind": k }, el("td", {}, el("span", { class: "rev-tag rev-" + k }, words(k))), el("td", {}, words(o.kind)),
        el("td", {}, o.label || ""), el("td", {}, o.tag || ""), el("td", {}, size)));
    }
    parts.push(el("details", { id: "rev-items" }, el("summary", {}, "Changes on this sheet (" + rows.length + ")"),
      rows.length ? el("table", { class: "list" }, el("tbody", {}, rows)) : el("p", { class: "muted" }, "No changes on this sheet.")));
  }
  if ((r.flagged || []).length) {
    parts.push(el("h3", {}, "Measurements to re-measure"), el("table", { class: "list", id: "rev-flagged" },
      el("thead", {}, el("tr", {}, ["Measurement", "Trade", "Quantity", "Why", ""].map(h => el("th", {}, h)))),
      el("tbody", {}, r.flagged.map(m => el("tr", { "data-m": m.id },
        el("td", {}, el("a", { href: "#/takeoffs/" + r.estimate_id + "?m=" + m.id }, m.label || words(m.feeds) || "measurement")),
        el("td", {}, words(m.module_id)), el("td", { class: "num" }, m.qty + " " + m.unit), el("td", {}, (m.why || []).join(", ")),
        el("td", {}, m.still_flagged ? el("span", { class: "status sample" }, "re-measure") : "done"))))));
  }
  const sc = r.schedules || {};
  if ((sc.added || []).length || (sc.removed || []).length || (sc.changed || []).length) {
    parts.push(el("h3", {}, "Schedule changes"), el("ul", { id: "rev-schedules" },
      (sc.added || []).map(mk => el("li", {}, "Added " + mk)), (sc.removed || []).map(mk => el("li", {}, "Removed " + mk)),
      (sc.changed || []).map(c => el("li", {}, words(c.type) + " " + c.mark + ": " + Object.entries(c.fields).map(([f, v]) =>
        f + " " + (v[0] || "—") + " → " + (v[1] || "—")).join("; ")))));
  }
  if ((r.sheets_added || []).length || (r.sheets_removed || []).length) {
    parts.push(el("p", { class: "note" }, [(r.sheets_added || []).length ? "New sheets: " + r.sheets_added.map(x => x.sheet_no || x.title).join(", ") : "",
      (r.sheets_removed || []).length ? "Sheets no longer in the set: " + r.sheets_removed.map(x => x.sheet_no || x.title).join(", ") : ""].filter(Boolean).join(". ")));
  }
  parts.push(el("p", { class: "muted small" }, "Compared " + when(r.created_at) + " by " + r.created_by + ". " +
    (r.revision_marks ? r.revision_marks + " revision cloud or delta mark(s) on the new set. " : "") + "The old set stays on file."));
  main.replaceChildren(...parts);
}

SCREENS.reports = renderReports;
PAGES.revision = renderRevision;
