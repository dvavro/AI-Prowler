/* Reviews, Symbol Library and Agents screens (Coder 2 Sprint 11): visual verification of what the plan engine found.
 *
 * Loaded after app.js (el, api, words, when, go, toast, errorBox, askThen, helpLink, tile, route ...).
 * Routes: #/reviews                 plan sets with symbols found, most needing a person first
 *         #/reviews/<plan set id>   the detection panel: thumbnails, filters, select, approve / take out / relabel,
 *                                   find similar, open on the plan; ?type=<item type> opens one type
 *         #/symbol_library          the company library and AI-Prowler's standard one, by trade; define, export, import
 *         #/agents                  Agent Manager (each trade agent's settings) and the takeoff runs
 * Every change asks first (askThen). Field staff can look; only owner, estimator and reviewer decide, never an agent.
 */
"use strict";

const SYM_STATUS = { proposed: "to check", approved: "✓ approved", rejected: "✗ taken out" };
const SYM_ORIGIN = { engine: "found by the plan engine", library: "found from the company library",
                     similar: "found with Find similar", manual: "added by a person" };

const LIB_NAMES = { company: "Your company's symbols", firm: "Design firm", standard: "AI-Prowler standard symbols" };

function symName(t) { return t ? words(t) : "unidentified symbol"; }
// pct(confidence) comes from review.js (loaded before this file).

// ------------------------------------------------------------------ Reviews: the list of plan sets
async function renderReviews(main, screen) {
  const r = await api("GET", "/symbol-reviews");
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("reviews")),
    el("p", { class: "muted" }, "Symbols the plan engine counted from each plan set's legend. Check them here before they're priced: approve, take out the wrong ones, give unknown ones a name, or find more like one.")];
  const rows = r.plan_sets || [];
  parts.push(rows.length ? el("table", { class: "list clickable", id: "reviews-list" },
    el("thead", {}, el("tr", {}, el("th", {}, "Plan set"), el("th", {}, "Project"), el("th", {}, "Found"),
      el("th", {}, "To check"), el("th", {}, "Approved"), el("th", {}, "Taken out"))),
    el("tbody", {}, rows.map(p => el("tr", { "data-id": p.plan_set_id, onclick: () => go("#/reviews/" + p.plan_set_id) },
      el("td", {}, el("a", { href: "#/reviews/" + p.plan_set_id }, p.original_name), p.revision > 1 ? " (rev " + p.revision + ")" : ""),
      el("td", {}, p.estimate_title),
      el("td", { class: "num" }, p.found - p.rejected),
      el("td", { class: "num" }, p.proposed ? el("span", { class: "chip warn" }, p.proposed) : "0"),
      el("td", { class: "num" }, p.approved), el("td", { class: "num" }, p.rejected)))))
    : el("div", { class: "card empty", id: "reviews-empty" }, "No symbols found yet. Upload plans with a legend on the Plans screen and they're counted when the plans are read."));
  main.replaceChildren(...parts);
}

// ------------------------------------------------------------------ Reviews: one plan set's detection panel
async function renderSymbolReview(main, planSetId) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const want = { type: q.get("type") || "", status: q.get("status") || "", sheet: q.get("sheet") || "",
                 sort: q.get("sort") || "confidence" };
  const [ps, all, revs] = await Promise.all([api("GET", "/plan-sets/" + planSetId),
    api("GET", "/plan-sets/" + planSetId + "/symbols?limit=2000"), api("GET", "/symbol-reviews")]);
  const canReview = !!revs.can_review;
  const estId = ps.estimate.id;
  const msg = el("div", { id: "symrev-message", role: "status" });
  const parts = [el("p", {}, el("a", { href: "#/reviews" }, "← All reviews"), " · ",
      el("a", { href: "#/projects/" + estId }, "Project page"), " · ", el("a", { href: "#/takeoffs/" + estId }, "📏 Blueprint Review")),
    el("div", { class: "page-head" }, el("h2", {}, "✅ " + ps.plan_set.original_name), helpLink("reviews")),
    el("p", { class: "muted" }, ps.estimate.title)];

  // Counts by type: a chip per type, click to look at just that type.
  const types = all.counts.by_type;
  const tiles = el("div", { class: "tiles", id: "symrev-types" },
    el("a", { class: "card tile" + (!want.type ? " active" : ""), href: hashWith({ type: "" }) },
      el("div", { class: "num" }, all.count - types.reduce((n, t) => n + t.rejected, 0)), el("div", { class: "lbl" }, "all symbols")),
    types.map(t => el("a", { class: "card tile" + (want.type === (t.item_type || "unknown") ? " active" : ""),
      href: hashWith({ type: t.item_type || "unknown" }), "data-type": t.item_type || "unknown" },
      el("div", { class: "num" }, t.count), el("div", { class: "lbl" }, t.label || symName(t.item_type)),
      t.needs_review ? el("div", { class: "small warn" }, t.needs_review + " to check") : null)));
  parts.push(tiles);

  // Filters.
  const sheets = all.counts.by_sheet;
  const fStatus = el("select", { id: "symrev-status", "aria-label": "Status" }, el("option", { value: "" }, "Any"),
    Object.entries(SYM_STATUS).map(([k, v]) => el("option", { value: k, selected: k === want.status }, v)));
  const fSheet = el("select", { id: "symrev-sheet", "aria-label": "Sheet" }, el("option", { value: "" }, "All sheets"),
    sheets.map(s => el("option", { value: s.sheet_id, selected: String(s.sheet_id) === want.sheet }, (s.sheet_no || "Page " + s.page_no) + " (" + s.count + ")")));
  const fSort = el("select", { id: "symrev-sort", "aria-label": "Sort" },
    [["confidence", "Least sure first"], ["sheet", "By sheet"], ["type", "By type"]].map(([k, v]) => el("option", { value: k, selected: k === want.sort }, v)));
  for (const [sel, key] of [[fStatus, "status"], [fSheet, "sheet"], [fSort, "sort"]]) {
    sel.addEventListener("change", () => { location.hash = hashWith({ [key]: sel.value }); });
  }
  parts.push(el("div", { class: "row filters" }, el("label", {}, "Status", fStatus), el("label", {}, "Sheet", fSheet), el("label", {}, "Sort", fSort)));

  let list = all.detections.filter(d => (!want.type || (d.item_type || "unknown") === want.type)
    && (!want.status || d.status === want.status) && (!want.sheet || String(d.sheet_id) === want.sheet));
  if (want.sort === "confidence") list.sort((a, b) => (a.confidence ?? 0) - (b.confidence ?? 0) || a.id - b.id);
  else if (want.sort === "type") list.sort((a, b) => String(a.item_type).localeCompare(String(b.item_type)) || a.id - b.id);

  // Selection and the bulk actions.
  const selected = new Set();
  const countLine = el("p", { id: "symrev-count", class: "muted" });
  const showCount = () => { countLine.textContent = list.length + " match" + (list.length === 1 ? "" : "es") + ", " + selected.size + " selected"; };
  const grid = el("div", { class: "sym-grid", id: "symrev-grid" });
  const cards = new Map();
  for (const d of list) {
    const card = symbolCard(d, estId, canReview, () => {
      if (selected.has(d.id)) selected.delete(d.id); else selected.add(d.id);
      card.classList.toggle("selected", selected.has(d.id));
      card.setAttribute("aria-pressed", selected.has(d.id) ? "true" : "false");
      showCount();
    });
    cards.set(d.id, card);
    grid.append(card);
  }
  showCount();
  const detail = el("div", { id: "symrev-detail" });
  if (canReview && list.length) parts.push(bulkBar(list, selected, cards, showCount, msg, detail, types));
  else if (!canReview) parts.push(el("p", { class: "note" }, "You can look at the symbols here; an owner, estimator or reviewer approves them."));
  parts.push(countLine, msg, detail,
    list.length ? grid : el("div", { class: "card empty", id: "symrev-empty" }, "Nothing matches these filters. ",
      el("a", { href: location.hash.split("?")[0] }, "Clear the filters"), " and try again."));
  if (canReview) parts.push(addMissedForm(sheets, msg));
  main.replaceChildren(...parts);
}

function hashWith(changes) {
  const [path, query] = location.hash.split("?");
  const q = new URLSearchParams(query || "");
  for (const [k, v] of Object.entries(changes)) { if (v) q.set(k, v); else q.delete(k); }
  const s = q.toString();
  return path + (s ? "?" + s : "");
}

function symbolCard(d, estId, canReview, toggle) {
  const img = el("img", { alt: symName(d.item_type) + " on " + (d.sheet_no || "the sheet"), loading: "lazy", class: "sym-thumb" });
  img.addEventListener("error", () => { img.replaceWith(el("div", { class: "sym-thumb none" }, "no picture")); }, { once: true });
  apiImage(img, "/estimator-api/symbol-detections/" + d.id + "/crop.png");   // with the Jobs app's token (Sprint 13)
  const card = el("div", { class: "sym-card " + d.status, "data-id": d.id, "data-status": d.status, tabindex: "0",
                           role: canReview ? "button" : null, "aria-pressed": canReview ? "false" : null },
    img,
    el("div", { class: "sym-name" }, d.label || symName(d.item_type)),
    el("div", { class: "small muted" }, (d.sheet_no || "") + (d.room ? " · " + d.room : "") + " · " + pct(d.confidence)),
    el("div", { class: "small" }, el("span", { class: "status" }, SYM_STATUS[d.status] || d.status),
      d.origin && d.origin !== "engine" ? el("span", { class: "muted" }, " · " + (SYM_ORIGIN[d.origin] || d.origin)) : null),
    d.original ? el("div", { class: "small muted sym-history" }, "was " + symName(d.original.item_type) + ", " + (SYM_STATUS[d.original.status] || d.original.status)) : null,
    el("a", { class: "small", href: "#/takeoffs/" + estId + "?sheet=" + d.sheet_id + "&symbol=" + d.id, onclick: ev => ev.stopPropagation() }, "open on the plan"));
  if (canReview) {
    card.addEventListener("click", toggle);
    card.addEventListener("keydown", ev => { if (ev.key === " " || ev.key === "Enter") { ev.preventDefault(); toggle(); } });
  }
  return card;
}

function bulkBar(list, selected, cards, showCount, msg, detail, types) {
  const btn = (id, text, cls) => el("button", { class: cls || "button", type: "button", id: "symrev-" + id }, text);
  const all = btn("all", "Select all"), none = btn("none", "Select none");
  const approve = btn("approve", "✓ Approve", "primary"), reject = btn("reject", "✗ Take out");
  const relabel = btn("relabel", "Relabel…"), reset = btn("reset", "Back to “to check”"), similar = btn("similar", "Find similar…");
  const pick = () => { const ids = [...selected]; if (!ids.length) { msg.replaceChildren(el("p", { class: "note warn" }, "Select one or more symbols first.")); } return ids; };
  all.addEventListener("click", () => { for (const d of list) { selected.add(d.id); cards.get(d.id).classList.add("selected"); } showCount(); });
  none.addEventListener("click", () => { selected.clear(); for (const c of cards.values()) c.classList.remove("selected"); showCount(); });
  const act = (b, action) => b.addEventListener("click", () => {
    const ids = pick(); if (!ids.length) return;
    askThen(msg, b, "/symbol-detections/review", { detection_ids: ids, action },
      r => r.changed + " symbol" + (r.changed === 1 ? "" : "s") + " " + (action === "approve" ? "approved" : action === "reject" ? "taken out" : "back to check"), "symrev");
  });
  act(approve, "approve"); act(reject, "reject"); act(reset, "reset");
  relabel.addEventListener("click", () => {
    const ids = pick(); if (!ids.length) return;
    const known = el("datalist", { id: "symrev-types-list" }, types.filter(t => t.item_type).map(t => el("option", { value: t.item_type })));
    const name = el("input", { id: "symrev-relabel-type", list: "symrev-types-list", maxlength: 60, placeholder: "e.g. floor_box", "aria-label": "What it is" });
    const matches = el("input", { type: "checkbox", id: "symrev-relabel-all" });
    const goBtn = el("button", { class: "primary", type: "button", id: "symrev-relabel-go" }, "Relabel…");
    const ask = el("div", {});
    detail.replaceChildren(el("div", { class: "card section" }, el("strong", {}, "What are these " + ids.length + "?"),
      el("div", { class: "row" }, el("label", {}, "Item type", name, known), el("label", { class: "check" }, matches, "every identical match on this plan set"), goBtn),
      el("p", { class: "small muted" }, "The company library learns this shape, so the next plan set finds it too."), ask));
    name.focus();
    goBtn.addEventListener("click", () => {
      const it = name.value.trim().toLowerCase().replace(/[\s-]+/g, "_");
      if (!it) { name.focus(); return; }
      askThen(ask, goBtn, "/symbol-detections/review", { detection_ids: ids, action: "relabel", item_type: it, apply_to_matches: matches.checked },
        r => r.changed + " relabelled as " + words(it), "symrev");
    });
  });
  similar.addEventListener("click", () => {
    const ids = pick(); if (!ids.length) return;
    if (ids.length > 1) { msg.replaceChildren(el("p", { class: "note warn" }, "Pick one symbol to find more like it.")); return; }
    askThen(msg, similar, "/symbol-detections/similar", { detection_id: ids[0] },
      r => r.added + " more found — they're waiting to be checked", "symrev");
  });
  return el("div", { class: "row sym-actions", id: "symrev-actions" }, all, none, approve, reject, relabel, reset, similar);
}

function addMissedForm(sheets, msg) {
  const sheet = el("select", { id: "symrev-add-sheet", "aria-label": "Sheet" }, sheets.map(s => el("option", { value: s.sheet_id }, s.sheet_no || "Page " + s.page_no)));
  const x = el("input", { id: "symrev-add-x", type: "number", step: "0.01", min: "0", placeholder: "x", "aria-label": "Across (inches)" });
  const y = el("input", { id: "symrev-add-y", type: "number", step: "0.01", min: "0", placeholder: "y", "aria-label": "Down (inches)" });
  const it = el("input", { id: "symrev-add-type", maxlength: 60, placeholder: "e.g. duplex_receptacle", "aria-label": "Item type" });
  const b = el("button", { class: "button", type: "button", id: "symrev-add-go" }, "Add…");
  const ask = el("div", {});
  b.addEventListener("click", () => {
    if (!sheets.length || x.value === "" || y.value === "" || !it.value.trim()) { msg.replaceChildren(el("p", { class: "note warn" }, "Give the sheet, where it is and what it is.")); return; }
    askThen(ask, b, "/symbol-detections/review", { action: "add", sheet_id: +sheet.value, point: [+x.value, +y.value],
      item_type: it.value.trim().toLowerCase().replace(/[\s-]+/g, "_") }, () => "Symbol added", "symrev");
  });
  return el("details", { class: "card section", id: "symrev-add" }, el("summary", {}, "Add a symbol the engine missed"),
    el("p", { class: "small muted" }, "Where it is on the sheet, in inches from the top-left corner (Blueprint Review shows the position as you point)."),
    el("div", { class: "row" }, el("label", {}, "Sheet", sheet), el("label", {}, "Across", x), el("label", {}, "Down", y), el("label", {}, "Item type", it), b), ask);
}

// ------------------------------------------------------------------ Symbol Library
async function renderSymbolLibrary(main, screen) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const trade = q.get("trade") || "";
  const r = await api("GET", "/symbol-library" + (trade ? "?trade=" + encodeURIComponent(trade) : ""));
  const msg = el("div", { id: "symlib-message", role: "status" });
  const pickTrade = el("select", { id: "symlib-trade", "aria-label": "Trade" }, el("option", { value: "" }, "All trades"),
    r.trades.map(t => el("option", { value: t, selected: t === trade }, words(t))));
  pickTrade.addEventListener("change", () => { location.hash = "#/symbol_library" + (pickTrade.value ? "?trade=" + pickTrade.value : ""); });
  const head = el("div", { class: "row" }, helpLink("symbol_library"));
  if (r.can_define) {
    const exp = el("a", { class: "button", id: "symlib-export", href: "/estimator-api/symbol-library/export", download: "symbol-library.json" }, "Export");
    const file = el("input", { type: "file", id: "symlib-import-file", accept: ".json,application/json", class: "hidden" });
    const imp = el("button", { class: "button", type: "button", id: "symlib-import" }, "Import…");
    imp.addEventListener("click", () => file.click());
    file.addEventListener("change", async () => {
      const f = file.files[0]; if (!f) return;
      let data;
      try { data = JSON.parse(await f.text()); } catch (e) { msg.replaceChildren(el("p", { class: "error" }, "That isn't a symbol library file.")); return; }
      askThen(msg, imp, "/symbol-library/import", { data }, out => out.imported + " symbol" + (out.imported === 1 ? "" : "s") + " imported", "symlib");
    });
    head.prepend(exp, imp, file);
  }
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label), head),
    el("p", { class: "muted" }, "What each symbol on a plan means. A plan set's own legend always wins; then your company's symbols (learned when someone relabels or approves one in Reviews); then AI-Prowler's standard symbols."),
    el("p", { class: "muted small", id: "symlib-columns" }, "Learned examples: pictures of the symbol saved from your own plans when someone approves or relabels it in Reviews — the more it has, the better it's found. Found on your plans: how many times it has been counted on your plans so far. Both start at 0 and grow as you review plans."),
    el("div", { class: "row filters" }, el("label", {}, "Trade", pickTrade)), msg];
  const form = el("div", { id: "symlib-form" });
  if (r.can_define) {
    const add = el("button", { class: "primary", type: "button", id: "symlib-new" }, "New symbol…");
    add.addEventListener("click", () => form.replaceChildren(defineForm(r.trades, null)));
    parts.push(el("div", { class: "row" }, add), form);
  }
  for (const lib of r.libraries) {
    const sec = el("div", { class: "card section", id: "symlib-" + lib.level, "data-level": lib.level },
      el("h3", {}, (LIB_NAMES[lib.level] || words(lib.level)) + (lib.firm_name ? ": " + lib.firm_name : "") + " ", el("span", { class: "muted small" }, lib.count + " symbol" + (lib.count === 1 ? "" : "s"))));
    const trades = Object.keys(lib.by_trade);
    if (!trades.length) sec.append(el("p", { class: "muted" }, lib.level === "company"
      ? "Nothing yet. Relabel or approve symbols in Reviews, or add one here." : "No symbols for this trade."));
    for (const t of trades) {
      sec.append(el("h4", {}, words(t)), el("table", { class: "list" },
        el("thead", {}, el("tr", {}, el("th", {}, "Picture"), el("th", {}, "Symbol"), el("th", {}, "Code"),
          el("th", { title: "Pictures of this symbol saved from your own plans (each time someone approves or relabels one in Reviews). The plan engine looks for these on every new plan set." }, "Learned examples"),
          el("th", { title: "How many times this symbol has been counted on your plans (not counting ones taken out in Reviews)." }, "Found on your plans"),
          el("th", {}, ""))),
        el("tbody", {}, lib.by_trade[t].map(dfn => el("tr", { "data-id": dfn.id, "data-type": dfn.item_type },
          el("td", { class: "sym-pic" }, symbolThumb(dfn)),
          el("td", {}, el("strong", {}, dfn.description || words(dfn.item_type)), el("div", { class: "small muted" }, dfn.item_type + (dfn.version > 1 ? " · v" + dfn.version : ""))),
          el("td", {}, (dfn.aliases || []).join(", ") || dfn.code || "—"),
          el("td", { class: "num" }, dfn.examples || 0), el("td", { class: "num" }, dfn.found || 0),
          el("td", {}, r.can_define && lib.level === "company" ? editButton(form, r.trades, dfn) : null))))));
    }
    parts.push(sec);
  }
  main.replaceChildren(...parts);
}

// The Symbol Library's picture: a symbol learned from your plans shows the real one (its first example), otherwise
// AI-Prowler's own drawing of the standard symbol (symbol_art.js).
function symbolThumb(dfn) {
  const drawing = () => symbolPicture(dfn.item_type, (dfn.aliases || [])[0] || dfn.code);
  if (!dfn.example_detection_id) return drawing();
  const img = el("img", { alt: words(dfn.item_type) + " from your plans", loading: "lazy", class: "sym-thumb small" });
  img.addEventListener("error", () => { img.replaceWith(drawing()); }, { once: true });
  apiImage(img, "/estimator-api/symbol-detections/" + dfn.example_detection_id + "/crop.png");
  return img;
}

function editButton(form, trades, dfn) {
  const b = el("button", { class: "button small", type: "button", "data-edit": dfn.id }, "Edit…");
  b.addEventListener("click", () => { form.replaceChildren(defineForm(trades, dfn)); form.scrollIntoView({ block: "center" }); });
  return b;
}

function defineForm(trades, dfn) {
  const it = el("input", { id: "symlib-type", maxlength: 60, value: dfn ? dfn.item_type : "", placeholder: "e.g. floor_box", "aria-label": "Item type", readonly: !!dfn });
  const desc = el("input", { id: "symlib-desc", maxlength: 200, value: dfn ? dfn.description || "" : "", placeholder: "e.g. Floor box, flush", "aria-label": "Description" });
  const trade = el("select", { id: "symlib-trade-pick", "aria-label": "Trade" }, trades.map(t => el("option", { value: t, selected: dfn && dfn.trade === t }, words(t))));
  const code = el("input", { id: "symlib-code", maxlength: 12, value: dfn ? dfn.code || "" : "", placeholder: "e.g. FB", "aria-label": "Code" });
  const asm = el("input", { id: "symlib-assembly", maxlength: 60, value: dfn ? dfn.assembly_id || "" : "", placeholder: "assembly it prices with (optional)", "aria-label": "Assembly" });
  const b = el("button", { class: "primary", type: "button", id: "symlib-save" }, dfn ? "Save a new version…" : "Save…");
  const ask = el("div", {});
  b.addEventListener("click", () => {
    const t = it.value.trim().toLowerCase().replace(/[\s-]+/g, "_");
    if (!t) { it.focus(); return; }
    const body = { item_type: t, description: desc.value.trim(), trade: trade.value, code: code.value.trim(), assembly_id: asm.value.trim() };
    if (dfn) body.definition_id = dfn.id;
    askThen(ask, b, "/symbol-library/define", body, out => (out.definition ? words(out.definition.item_type) + " saved" : "Saved"), "symlib");
  });
  return el("div", { class: "card section" }, el("strong", {}, dfn ? "Edit " + (dfn.description || words(dfn.item_type)) : "New company symbol"),
    el("div", { class: "row" }, el("label", {}, "Item type", it), el("label", {}, "Description", desc), el("label", {}, "Trade", trade),
      el("label", {}, "Code beside it", code), el("label", {}, "Assembly", asm), b),
    el("p", { class: "small muted" }, "Its shape is learned from symbols you approve or relabel in Reviews. Saving a new version doesn't change counts already approved."), ask);
}

// ------------------------------------------------------------------ Agents: Agent Manager and the takeoff runs
async function renderAgents(main, screen) {
  const r = await api("GET", "/agents");
  const msg = el("div", { id: "agents-message", role: "status" });
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("agents")),
    el("p", { class: "muted" }, "Each trade has a takeoff agent. Turn trades off, set how sure an agent must be before its quantities can go through, and watch the takeoff runs."),
    msg];
  if (!r.can_configure) parts.push(el("p", { class: "note" }, "Only the owner changes these settings."));
  parts.push(r.agents.length ? el("table", { class: "list", id: "agents-list" },
    el("thead", {}, el("tr", {}, el("th", {}, "Trade"), el("th", {}, "On"), el("th", {}, "Sure enough at"), el("th", {}, "Approve by itself"), el("th", {}, "Reads sheets"), el("th", {}, ""))),
    el("tbody", {}, r.agents.map(a => agentRow(a, r.can_configure, msg))))
    : el("div", { class: "card empty", id: "agents-empty" }, "No takeoff agents yet. Ask your AI to set up the trades - each trade gets an agent."));

  // Runs.
  parts.push(el("h3", {}, "Takeoff runs"));
  parts.push(r.runs.length ? el("div", { id: "runs-list" }, r.runs.map(run => runCard(run, r.can_start, msg)))
    : el("div", { class: "card empty", id: "runs-empty" }, "No takeoff runs yet. The Director starts one for each plan job, or start one from ",
      el("a", { href: "#/projects" }, "a project's estimate"), "."));

  // AI Log: every call the Estimator made to the AI, and what came back.
  parts.push(el("h3", {}, "AI Log"));
  parts.push(el("p", {}, el("a", { href: "#/agents/ai-log", id: "agents-ai-log-link" }, "📋 What was sent to the AI and what came back"),
    " — every LLM call (the LLM takeoff reading a plan, the Reviewer, Bid Writer and Follow-up agents), newest first, with the prompt, the plan images, the reply and the cost."));
  main.replaceChildren(...parts);
}

function agentRow(a, canConfigure, msg) {
  const on = el("input", { type: "checkbox", checked: a.enabled, disabled: !canConfigure, "aria-label": a.name + " on" });
  const thr = el("input", { type: "number", min: "0", max: "100", step: "1", value: a.confidence_threshold, disabled: !canConfigure, class: "narrow", "aria-label": a.name + " confidence" });
  const auto = el("input", { type: "checkbox", checked: a.auto_advance, disabled: !canConfigure, "aria-label": a.name + " approves by itself" });
  const save = canConfigure ? el("button", { class: "button small", type: "button", "data-save": a.module_id }, "Save…") : null;
  const rules = a.sheet_rules || {};
  if (save) save.addEventListener("click", () => {
    const changes = {};
    if (on.checked !== a.enabled) changes.enabled = on.checked;
    if (+thr.value !== a.confidence_threshold) changes.confidence_threshold = +thr.value;
    if (auto.checked !== a.auto_advance) changes.auto_advance = auto.checked;
    if (!Object.keys(changes).length) { msg.replaceChildren(el("p", { class: "muted" }, "Nothing changed for " + a.name + ".")); return; }
    askThen(msg, save, "/agents/" + a.module_id, { changes }, () => a.name + " saved", "agents");
  });
  return el("tr", { "data-module": a.module_id, class: a.enabled ? "" : "muted" },
    el("td", {}, el("strong", {}, a.name), a.changed ? el("span", { class: "small muted" }, " · changed") : null),
    el("td", {}, on), el("td", {}, thr, "%"), el("td", {}, auto),
    el("td", { class: "small" }, [(rules.prefixes || []).join(", "), (rules.titles || []).join(", ")].filter(Boolean).join(" · ") || "—"),
    el("td", {}, save));
}

function runCard(run, canStart, msg) {
  const body = el("div", { class: "run-tasks" });
  const card = el("details", { class: "card section", "data-run": run.id },
    el("summary", {}, el("strong", {}, run.estimate_title), " · run " + run.id + " · ", el("span", { class: "status" }, words(run.state)),
      " · ", el("progress", { max: "100", value: run.progress, "aria-label": "progress" }), " " + run.progress + "% · " + when(run.created_at)),
    body);
  card.addEventListener("toggle", async () => {
    if (!card.open || body.childElementCount) return;
    try {
      const s = await api("GET", "/runs/" + run.id);
      body.replaceChildren(el("p", { class: "small muted" }, s.summary), el("table", { class: "list" },
        el("thead", {}, el("tr", {}, el("th", {}, "Trade"), el("th", {}, "State"), el("th", {}, "Next"), el("th", {}, ""))),
        el("tbody", {}, s.tasks.map(t => {
          let retry = null;
          if (canStart && (t.state === "failed" || t.state === "blocked")) {
            retry = el("button", { class: "button small", type: "button", "data-retry": t.task_id }, "Try again…");
            retry.addEventListener("click", () => askThen(msg, retry, "/runner-tasks/" + t.task_id + "/retry", {}, () => words(t.module_id) + " started again", "agents"));
          }
          return el("tr", { "data-task": t.task_id }, el("td", {}, words(t.module_id)), el("td", {}, el("span", { class: "status" }, words(t.state))),
            el("td", { class: "small" }, t.next), el("td", {}, retry));
        }))), el("p", {}, el("a", { href: "#/projects/" + run.estimate_id }, "Open the project")));
    } catch (e) { if (e.status !== 401) body.replaceChildren(errorBox(e)); }
  });
  return card;
}

// ------------------------------------------------------------------ AI Log: what was sent to the AI and what came back
// One card per LLM call (the LLM takeoff reading a plan, the Reviewer, Bid Writer and Follow-up agents),
// newest first. Expanding a card loads the full call: the prompt, the plan images the AI was shown,
// the raw reply and the parsed result, tokens and cost. ?auto_run_id=<id> shows one auto-run's calls -
// a run with no entries here never reached the AI.
async function renderAiLog(main) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const runId = q.get("auto_run_id") || "";
  const role = q.get("role") || "";
  const filter = new URLSearchParams();
  if (runId) filter.set("auto_run_id", runId);
  if (role) filter.set("role", role);
  const qs = filter.toString();
  const parts = [el("p", {}, el("a", { href: "#/agents" }, "← Agents")),
    el("div", { class: "page-head" }, el("h2", {}, "📋 AI Log")),
    el("p", { class: "muted" }, "Every call the Estimator made to the AI, newest first — what was sent (the prompt and the plan images), what came back, and what it cost. A run with no entries here never reached the AI.")];
  if (runId) parts.push(el("p", { class: "note", id: "ai-log-run" }, "Calls for auto-run " + runId + ". ",
    el("a", { href: "#/agents/ai-log" }, "Show all calls")));
  const list = el("div", { id: "ai-log-list" });
  const more = el("button", { class: "button", type: "button", id: "ai-log-more" }, "Load more…");
  let offset = 0, total = 0;
  async function load() {
    more.disabled = true;
    const r = await api("GET", "/ai-log?limit=25&offset=" + offset + (qs ? "&" + qs : ""));
    total = r.total;
    if (!r.entries.length && offset === 0) {
      list.replaceChildren(el("div", { class: "card empty", id: "ai-log-empty" },
        runId ? "No AI calls for this run — the AI never ran (the agent measured from the drawing, or LLM takeoff is off)."
              : "No AI calls yet — nothing has been sent to the AI."));
    } else {
      for (const e of r.entries) list.append(aiLogCard(e));
    }
    offset += r.entries.length;
    more.hidden = offset >= total;
    more.disabled = false;
  }
  more.addEventListener("click", () => load().catch(e => { if (e.status !== 401) list.append(errorBox(e)); }));
  parts.push(list, more);
  main.replaceChildren(...parts);
  try { await load(); } catch (e) { if (e.status !== 401) list.replaceChildren(errorBox(e)); }
}

function aiLogCost(micros) { return "$" + (Number(micros || 0) / 1000000).toFixed(4); }

function aiLogCard(e) {
  const body = el("div", { class: "ai-log-detail" });
  const card = el("details", { class: "card section", id: "ai-log-" + e.id, "data-entry": e.id },
    el("summary", {}, el("strong", {}, e.purpose), " · ", e.provider + " / " + (e.model || "?"), " · ",
      el("span", { class: "status " + (e.ok ? "" : "sample") }, e.ok ? "✓ answered" : "✗ failed"), " · ",
      (e.input_tokens + e.output_tokens) + " tokens · " + aiLogCost(e.cost_micros),
      (e.duration_ms !== null && e.duration_ms !== undefined) ? " · " + (e.duration_ms / 1000).toFixed(1) + "s" : "",
      " · " + when(e.created_at), e.image_count ? " · " + e.image_count + " image" + (e.image_count === 1 ? "" : "s") : ""),
    body);
  card.addEventListener("toggle", async () => {
    if (!card.open || body.childElementCount) return;
    body.replaceChildren(el("p", { class: "muted" }, "Loading…"));
    try {
      const d = await api("GET", "/ai-log/" + e.id);
      body.replaceChildren(aiLogDetail(d.entry));
    } catch (err) { if (err.status !== 401) body.replaceChildren(errorBox(err)); }
  });
  return card;
}

function aiLogDetail(e) {
  const out = el("div", {});
  if (!e.ok && e.error) out.append(el("p", { class: "error", id: "ai-log-error" }, "Failed — " + e.error));
  out.append(el("p", { class: "small muted" }, (e.input_tokens || 0) + " tokens in · " + (e.output_tokens || 0) + " out · "
    + aiLogCost(e.cost_micros) + (e.auto_run_id ? " · auto-run " + e.auto_run_id : "")
    + (e.task_id ? " · agent task " + e.task_id : "")));
  out.append(el("h4", {}, "What was sent"));
  out.append(el("p", { class: "small muted" }, "System"), el("pre", { class: "ai-log-text" }, e.system_prompt || "—"));
  out.append(el("p", { class: "small muted" }, "Prompt"), el("pre", { class: "ai-log-text" }, e.user_prompt || "—"));
  if (e.images && e.images.length) {
    out.append(el("h4", {}, "Images sent (" + e.images.length + ")"));
    for (const [i, img] of e.images.entries()) {
      const pic = el("img", { alt: "Image " + (i + 1) + " sent to the AI" + (img.sheet_no ? " (sheet " + img.sheet_no + ")" : ""), loading: "lazy", class: "ai-log-img" });
      pic.addEventListener("error", () => { pic.replaceWith(el("div", { class: "muted small" }, "This image is no longer on this PC.")); }, { once: true });
      apiImage(pic, "/estimator-api" + img.image_url);
      out.append(el("figure", { class: "ai-log-figure" }, pic,
        el("figcaption", { class: "small muted" }, (img.sheet_no ? "Sheet " + img.sheet_no : "Sheet " + (img.sheet_id || "?"))
          + " · " + words(img.kind) + " · " + img.width_px + "×" + img.height_px + " px"
          + (img.sent_max_px ? " · sent as a " + img.sent_max_px + " px thumbnail" : "")
          + " · AI send log #" + img.ai_send_log_id)));
    }
  }
  out.append(el("h4", {}, "What came back"));
  out.append(el("pre", { class: "ai-log-text" }, e.response_text === null || e.response_text === undefined ? "(no reply — the call failed)" : e.response_text));
  if (e.parsed !== null && e.parsed !== undefined) {
    out.append(el("h4", {}, "Parsed result"));
    out.append(el("pre", { class: "ai-log-text" }, JSON.stringify(e.parsed, null, 2)));
  }
  return out;
}

SCREENS.reviews = renderReviews;
SCREENS.symbol_library = renderSymbolLibrary;
SCREENS.agents = renderAgents;
PAGES.symbol_review = renderSymbolReview;
PAGES.ai_log = renderAiLog;
