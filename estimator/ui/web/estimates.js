/* Estimates screen (Coder 2 Sprint 8): the list, and one estimate with its trades and lines linked both ways to
 * the measurements behind them (spec "Two-way linking").
 *
 * Loaded after app.js (el, api, money, when, words, go, toast, errorBox, askThen, helpLink, canOpen ...).
 * Routes: #/estimates   #/estimates/<id>?line=<line id>
 * Each line shows the measurements that feed it (📏 n); a trade shows where each priced answer came from
 * (measured, differs, typed, waiting) and can be priced again from its approved measurements.
 * Costs and margins only show for roles that can see them (the server leaves them out for the others).
 */
"use strict";

const STATE_WORDS = { measured: "📏 measured", differs: "⚠ differs from the measurements", typed: "typed in",
                      waiting: "📏 measured, not priced yet", none: "—" };

async function renderEstimates(main, screen) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const status = q.get("status") || "";
  const r = await api("GET", "/estimates?" + new URLSearchParams({ status, limit: 200 }));
  const pick = el("select", { id: "estimates-status", "aria-label": "Status" },
    el("option", { value: "" }, "All"), STATUSES.map(s => el("option", { value: s, selected: s === status }, words(s))));
  pick.addEventListener("change", () => { location.hash = "#/estimates" + (pick.value ? "?status=" + pick.value : ""); });
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("estimates")),
    el("div", { class: "row filters" }, el("label", {}, "Status", pick))];
  const rows = r.estimates || [];
  parts.push(rows.length ? el("table", { class: "list clickable", id: "estimates-list" },
    el("thead", {}, el("tr", {}, el("th", {}, "Estimate"), el("th", {}, "Status"), el("th", {}, "Total"), el("th", {}, "Updated"))),
    el("tbody", {}, rows.map(e => el("tr", { "data-id": e.id, onclick: () => go("#/estimates/" + e.id) },
      el("td", {}, el("a", { href: "#/estimates/" + e.id }, e.title), e.practice ? el("span", { class: "status sample" }, " practice") : null),
      el("td", {}, el("span", { class: "status" }, words(e.status))),
      el("td", { class: "money" }, e.total_cents !== undefined && e.total_cents !== null ? money(e.total_cents) : "—"),
      el("td", {}, when(e.updated_at))))))
    : el("div", { class: "card empty", id: "estimates-empty" }, "No estimates" + (status ? " that are " + words(status) : "") + " yet. ",
      status ? el("a", { href: "#/estimates" }, "Show all estimates") : el("a", { href: "#/projects" }, "Create one from Projects"), "."));
  main.replaceChildren(...parts);
}

async function renderEstimate(main, id) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const focusLine = +(q.get("line") || 0);
  const d = await api("GET", "/estimates/" + id + "/detail");
  // The price book for "Add a line by hand" and the per-line edit form: a role that can't open it still gets the key box.
  let book = null;
  if (d.can_edit) { try { book = await api("GET", "/price-book"); } catch (e) { book = null; } }
  const est = d.estimate, links = d.links;
  const lineLinks = new Map(links.lines.map(l => [l.line_id, l]));
  const meas = new Map(links.measurements.map(m => [m.id, m]));
  const msg = el("div", { id: "estimate-message", role: "status" });
  const t = est.totals || {};
  const parts = [el("p", {}, el("a", { href: "#/projects/" + est.id }, "← Project page"), " · ", el("a", { href: "#/estimates" }, "All estimates")),
    el("div", { class: "page-head" }, el("h2", {}, "🧮 " + est.title + (est.revision > 1 ? " (v" + est.revision + ")" : "")),
      el("div", { class: "row" }, el("span", { class: "status big" }, words(est.status)), helpLink("estimates")))];
  if (est.editing_warning) parts.push(el("p", { class: "note warn" }, est.editing_warning));
  // A change order: which accepted quote it adds to (2026-11-16, David).
  const co = d.change_order;
  if (co) {
    parts.push(el("div", { class: "card section note", id: "change-order-of" },
      el("strong", {}, "➕ Change order " + co.n), " to ",
      el("a", { href: "#/estimates/" + co.of_estimate_id }, co.of_title),
      co.of_number ? " (accepted quote " + co.of_number + ", " + money(co.of_total_cents) + ")" : "",
      co.job_id ? " · job " + co.job_id : "",
      co.summary ? el("p", { class: "muted" }, "For: " + co.summary) : null,
      el("p", { class: "muted small" }, "Price only the extra or changed work here. Its quote tells the customer it's in addition to the accepted one; when they accept it, the job's amount goes up by it.")));
  } else if (est.change_summary) parts.push(el("p", { class: "muted" }, "What changed in this version: " + est.change_summary));
  // "Other lines" (lines added by hand) is a section but not a trade, so it isn't counted as one (2026-11-16, David).
  const tradeCount = est.sections.filter(s => s.module_id !== "custom").length;
  const handLines = est.sections.filter(s => s.module_id === "custom").reduce((n, s) => n + s.lines.length, 0);
  parts.push(el("div", { class: "tiles" }, tile(money(t.total_cents || 0), "total"),
    d.see_margins && t.margin_pct !== undefined ? tile(Math.round(parseFloat(t.margin_pct) * 1000) / 10 + "%", "margin") : null,
    Object.assign(tile(tradeCount, tradeCount === 1 ? "trade" : "trades"), { id: "tile-est-trades" }),
    handLines ? tile(handLines, handLines === 1 ? "line added by hand" : "lines added by hand") : null,
    tile(links.measurements.filter(m => m.status === "approved").length, "approved measurements")));
  // Reopened after approval: what changed since, so the next approval only checks that (2026-11-16, David).
  if (d.since_approval) parts.push(sinceApprovalCard(d.since_approval));
  if ((d.change_orders || []).length) {
    parts.push(el("div", { class: "card section", id: "change-orders" }, el("h3", {}, "➕ Change orders"),
      el("table", { class: "list" },
        el("thead", {}, el("tr", {}, el("th", {}, "#"), el("th", {}, "For"), el("th", {}, "Status"), el("th", {}, "Total"))),
        el("tbody", {}, d.change_orders.map(c => el("tr", { "data-change-order": c.id },
          el("td", {}, el("a", { href: "#/estimates/" + c.id }, "Change order " + c.n)), el("td", {}, c.summary || ""),
          el("td", {}, words(c.status)), el("td", { class: "money" }, money(c.total_cents || 0))))))));
  }
  // The project's Director: what to do next and why, and the Approve / Send buttons (2026-11-12, David).
  if (!est.practice && typeof directorPanel === "function") parts.push(directorPanel(est.id));
  parts.push(estimateActions(d, msg), msg);
  // Where each trade's quantities come from (measured / differs / typed / waiting), then its lines.
  const tradesWithoutLines = links.trades.filter(tr => !est.sections.some(s => s.module_id === tr.module_id));
  for (const sec of est.sections) {
    const tr = links.trades.find(x => x.module_id === sec.module_id);
    parts.push(sectionBlock(d, sec, tr, lineLinks, meas, focusLine, msg, book));
  }
  for (const tr of tradesWithoutLines) parts.push(sectionBlock(d, { id: null, module_id: tr.module_id, lines: [], subtotal_cents: 0 }, tr, lineLinks, meas, focusLine, msg, book));
  // The Inspector's code review lives inside each trade's section now (sectionBlock).
  if (!est.sections.length && !tradesWithoutLines.length) {
    const next = d.can_edit
      ? ["Open ", el("a", { href: "#/takeoffs/" + est.id }, "Measure from plans (takeoff)"), ", measure the plans and Recalculate, or add a line below."]
      : ["Ask an estimator to price it."];
    parts.push(el("div", { class: "card empty", id: "estimate-empty" }, "No trades priced yet. ", ...next));
  }
  if (est.sections.length) parts.push(totalsCard(d, links));
  if (d.can_edit) parts.push(addLineForm(d, msg, book));
  main.replaceChildren(...parts);
  if (focusLine) {
    const row = main.querySelector('[data-line="' + focusLine + '"]');
    if (row) { row.classList.add("focus"); row.scrollIntoView({ block: "center" }); const b = row.querySelector(".link-chip"); if (b) b.click(); }
  }
}

function estimateActions(d, msg) {
  const est = d.estimate, row = el("div", { class: "row", id: "estimate-actions" });
  const out = el("div", { id: "estimate-results" });
  // One button for "the plans changed, update the estimate" (2026-11-20, David: "add a button to update the estimate,
  // I can't figure out how to update the estimate with rev2 items/changes"). Shown when any trade differs from its
  // approved measurements; on an approved or sent estimate it reopens it first (the server asks, saying so).
  const stale = ((d.links || {}).trades || []).filter(t => t.can_use_measurements);
  const updAsk = el("div", { id: "update-plans-ask" });
  if (stale.length && (d.can_edit || d.can_reopen)) {
    const upd = el("button", { class: "primary", type: "button", id: "estimate-update-plans" }, "🔄 Update from the plans…");
    upd.addEventListener("click", () => askThen(updAsk, upd, "/estimates/" + est.id + "/update-from-plans", { rev: est.rev },
      r => "Updated from the plans: " + (r.updated || []).map(t => t.name).join(", ") + " · total " + money((r.totals || {}).total_cents || 0), "update-plans"));
    row.append(upd);
  }
  if (d.can_review) row.append(el("a", { class: "button", id: "estimate-review", href: "#/takeoffs/" + est.id }, "📏 Measure from plans (takeoff)"));
  if (d.can_edit) {
    const calc = el("button", { class: "button", type: "button", id: "estimate-calc" }, "Recalculate");
    calc.addEventListener("click", async () => {
      calc.disabled = true;
      try { await api("POST", "/estimates/" + est.id + "/calculate", { rev: est.rev }); toast("Recalculated"); route(); }
      catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); } finally { calc.disabled = false; }
    });
    row.append(calc);
  }
  const check = el("button", { class: "button", type: "button", id: "estimate-validate" }, "✓ Check it");
  check.addEventListener("click", async () => {
    try { out.replaceChildren(validateCard(await api("GET", "/estimates/" + est.id + "/validate"))); }
    catch (e) { if (e.status !== 401) out.replaceChildren(errorBox(e)); }
  });
  row.append(check);
  if (d.see_margins) {
    const hist = el("button", { class: "button", type: "button", id: "estimate-history" }, "Compare with past jobs");
    hist.addEventListener("click", async () => {
      try { out.replaceChildren(historyCard(await api("GET", "/estimates/" + est.id + "/history"))); }
      catch (e) { if (e.status !== 401) out.replaceChildren(errorBox(e)); }
    });
    row.append(hist);
  }
  // An approved or sent estimate (not won) can be reopened in place (same plans and measurements); the next approval
  // shows only what changed, and a sent quote is replaced by one saying what changed (2026-11-16, David).
  if (d.can_reopen) {
    const ro = el("button", { class: "button", type: "button", id: "estimate-reopen" }, "✏️ Reopen for changes…");
    ro.addEventListener("click", () => {
      const why = el("input", { id: "reopen-why", maxlength: 500, placeholder: "Why? e.g. revise the footer answers", "aria-label": "Why reopen" });
      const goBtn = el("button", { class: "primary", type: "button", id: "reopen-go" }, "Reopen it…");
      const ask = el("div", {});
      out.replaceChildren(el("div", { class: "card section" },
        el("p", { class: "muted small" }, "It goes back to draft so you can change answers and lines. When it's approved again, only what changed needs checking."
          + (est.status !== "approved" ? " The quote the customer was sent is kept on record as replaced, and the updated quote tells them what changed." : "")),
        el("div", { class: "row" }, el("label", {}, "Why (optional)", why), goBtn), ask));
      why.focus();
      goBtn.addEventListener("click", () => askThen(ask, goBtn, "/estimates/" + est.id + "/reopen", { rev: est.rev, reason: why.value.trim() },
        () => { setTimeout(route, 0); return "Reopened for changes"; }, "reopen"));
    });
    row.append(ro);
  }
  // The customer accepted, then wants more or different work: a change order, priced and quoted on its own.
  if (d.can_change_order) {
    const cb = el("button", { class: "button", type: "button", id: "estimate-change-order" }, "➕ Change order…");
    cb.addEventListener("click", () => {
      const why = el("input", { id: "change-order-why", maxlength: 500, placeholder: "What does the customer want? e.g. extend the patio 10 ft", "aria-label": "What's added or changed" });
      const goBtn = el("button", { class: "primary", type: "button", id: "change-order-go" }, "Make the change order…");
      const ask = el("div", {});
      out.replaceChildren(el("div", { class: "card section" },
        el("p", { class: "muted small" }, "A new estimate just for the extra or changed work. The accepted quote stays as signed; when the customer accepts the change order, the job's amount goes up by it."),
        el("div", { class: "row" }, el("label", {}, "What's added or changed", why), goBtn), ask));
      why.focus();
      goBtn.addEventListener("click", () => {
        if (!why.value.trim()) { why.focus(); return; }
        askThen(ask, goBtn, "/estimates/" + est.id + "/change-order", { change_summary: why.value.trim() },
          r => { setTimeout(() => go("#/estimates/" + r.id), 0); return "Change order " + ((r.change_order || {}).n || "") + " made"; }, "change-order");
      });
    });
    row.append(cb);
  }
  if (d.can_revise) {
    const rev = el("button", { class: "button", type: "button", id: "estimate-revise" }, "New version…");
    rev.addEventListener("click", () => {
      const why = el("input", { id: "revise-why", maxlength: 500, placeholder: "What's changing? e.g. customer added the back patio", "aria-label": "What's changing" });
      const goBtn = el("button", { class: "primary", type: "button", id: "revise-go" }, "Make the new version…");
      const ask = el("div", {});
      out.replaceChildren(el("div", { class: "card section" }, el("div", { class: "row" }, el("label", {}, "What's changing", why), goBtn), ask));
      why.focus();
      goBtn.addEventListener("click", () => {
        if (!why.value.trim()) { why.focus(); return; }
        askThen(ask, goBtn, "/estimates/" + est.id + "/revision", { change_summary: why.value.trim() },
          r => { setTimeout(() => go("#/estimates/" + r.id), 0); return "Version " + r.revision + " made"; }, "revise");
      });
    });
    row.append(rev);
  }
  return el("div", { class: "section" }, row, updAsk, out);
}

function sectionBlock(d, sec, tr, lineLinks, meas, focusLine, msg, book) {
  const est = d.estimate, box = el("div", { class: "card section estimate-trade", "data-module": sec.module_id });
  const name = tr ? tr.name : (sec.module_id === "custom" ? "Other lines" : words(sec.module_id));
  const head = el("div", { class: "page-head" }, el("h3", {}, name), el("strong", { class: "money" }, money(sec.subtotal_cents || 0)));
  box.append(head);
  if (tr) box.append(sourcesTable(d, tr, meas, msg));
  if (tr && d.can_edit && tr.can_use_measurements) {
    const use = el("button", { class: "primary", type: "button", id: "use-" + sec.module_id }, "Price it with the approved measurements…");
    const ask = el("div", {});
    use.addEventListener("click", () => askThen(ask, use, "/estimates/" + est.id + "/use-measurements", { module_id: sec.module_id, rev: est.rev },
      r => name + " priced from the measurements: " + money(r.totals.total_cents) + " in all", "use"));
    box.append(el("div", { class: "row" }, use), ask);
  }
  if (tr && d.can_edit && sec.module_id !== "custom") {
    const edit = el("button", { class: "button", type: "button", id: "edit-answers-" + sec.module_id }, "Edit answers\u2026");
    const form = el("div", {});
    edit.addEventListener("click", () => editAnswers(d, sec, tr, form));
    box.append(el("div", { class: "row" }, edit), form);
  }
  if (sec.id && d.can_options && sec.module_id !== "custom") box.append(optionsBlock(d, sec, msg));
  const bom = bomBlock(d, sec, msg); if (bom) box.append(bom);
  if (sec.id && (d.reviewable_trades || []).includes(sec.module_id) && ((d.inspector || {}).enabled || (d.inspection_reviews || []).some(r => r.module_id === sec.module_id))) box.append(inspectionReviewCard(d, sec, msg));
  if (!sec.lines.length) { box.append(el("p", { class: "muted" }, "No lines priced for this trade yet.")); return box; }
  const see = d.see_margins;
  const cols = 4 + (see ? 3 : 0) + (d.can_edit ? 1 : 0);
  const tbl = el("table", { class: "list", id: "lines-" + sec.module_id },
    el("thead", {}, el("tr", {}, el("th", {}, "Line"), el("th", {}, "Quantity"), see ? el("th", {}, "Unit cost") : null,
      see ? el("th", {}, "Waste") : null,
      see ? el("th", { title: "Quantity × unit cost, plus waste and labor burden" }, "Cost") : null,
      el("th", see ? { title: "Cost plus overhead, profit and tax" } : {}, see ? "Price (with markups)" : "Price"),
      el("th", {}, "From the plans"),
      d.can_edit ? el("th", {}, "") : null)));
  const body = el("tbody", {});
  for (const ln of sec.lines) {
    const lk = lineLinks.get(ln.id) || { measurement_ids: [], proposed_ids: [], questions: [] };
    const ids = lk.measurement_ids.concat(lk.proposed_ids);
    const sub = el("tr", { class: "line-links", hidden: true }, el("td", { colspan: cols }, lineMeasurementList(est, ln, lk, meas, d)));
    let chip;
    if (ids.length) {
      chip = el("button", { class: "link-chip", type: "button", "data-line-chip": ln.id, title: "Show the measurements behind this line" },
        "📏 " + lk.measurement_ids.length + (lk.proposed_ids.length ? " (+" + lk.proposed_ids.length + " to review)" : ""));
      chip.addEventListener("click", () => { sub.hidden = !sub.hidden; chip.classList.toggle("open", !sub.hidden); });
    } else {
      chip = el("span", { class: "muted small" }, lk.questions.length ? "not measured" : "entered by hand");
    }
    const row = el("tr", { "data-line": ln.id },
      el("td", {}, ln.description, el("span", { class: "muted small" }, " · " + words(ln.kind))),
      el("td", {}, num2(ln.quantity) + " " + ln.unit),
      see ? el("td", { class: "money" }, ln.unit_cost_cents !== undefined ? money(ln.unit_cost_cents) : "—") : null,
      see ? el("td", {}, Math.round(parseFloat(ln.waste_pct || 0) * 1000) / 10 + "%") : null,
      see ? el("td", { class: "money", "data-line-cost": ln.id }, linePrice(ln) ? money(linePrice(ln).cost_cents || 0) : "—") : null,
      el("td", Object.assign({ class: "money" }, see && linePrice(ln) ? { title: markupNote(linePrice(ln)) } : {}),
        money(ln.total_cents || 0),
        see && linePrice(ln) ? el("div", { class: "muted small", "data-line-markup": ln.id }, markupNote(linePrice(ln))) : null),
      el("td", {}, chip));
    body.append(row, sub);
    if (d.can_edit) {
      const cell = el("td", {});
      const editBtn = el("button", { class: "button", type: "button", "data-line-edit": ln.id }, "Edit\u2026");
      const delBtn = el("button", { class: "button", type: "button", "data-line-del": ln.id }, "Delete\u2026");
      cell.append(editBtn, " ", delBtn);
      row.append(cell);
      let formRow = null;
      const closeForm = () => { if (formRow) { formRow.remove(); formRow = null; } };
      editBtn.addEventListener("click", () => { closeForm(); formRow = lineEditRow(d, sec, ln, cols, closeForm, book); row.after(formRow); });
      delBtn.addEventListener("click", () => { closeForm(); formRow = lineDeleteRow(d, sec, ln, cols, closeForm); row.after(formRow); });
    }
  }
  tbl.append(body);
  box.append(tbl);
  return box;
}

function linePrice(ln) { return ln.calc && ln.calc.price ? ln.calc.price : null; }

function markupNote(p) {
  const parts = ["cost " + money(p.cost_cents || 0)];
  if (p.burden_cents) parts.push("incl. labor burden " + money(p.burden_cents));
  if (p.overhead_cents) parts.push("+ overhead " + money(p.overhead_cents));
  if (p.profit_cents) parts.push("+ profit " + money(p.profit_cents));
  if (p.tax_cents) parts.push("+ tax " + money(p.tax_cents));
  return parts.join(" ");
}

// The whole estimate at the bottom: each trade and the lines added by hand, then the markups and the total
// (2026-11-16, David).
function totalsCard(d, links) {
  const est = d.estimate, t = est.totals || {}, see = d.see_margins;
  const nameOf = s => {
    const tr = links.trades.find(x => x.module_id === s.module_id);
    return tr ? tr.name : (s.module_id === "custom" ? "Other lines (added by hand)" : words(s.module_id));
  };
  const costOf = s => s.lines.reduce((n, ln) => n + ((linePrice(ln) || {}).cost_cents || 0), 0);
  const row = (label, cost, price, cls) => el("tr", cls ? { class: cls } : {}, el("th", {}, label),
    see ? el("td", { class: "money" }, cost === null ? "" : money(cost)) : null, el("td", { class: "money" }, price === null ? "" : money(price)));
  const rows = est.sections.map(s => row(nameOf(s), costOf(s), s.subtotal_cents || 0));
  rows.forEach((r, i) => r.setAttribute("data-section", est.sections[i].module_id));
  const sum = est.sections.reduce((n, s) => n + (s.subtotal_cents || 0), 0);
  rows.push(row("Subtotal", see ? (t.cost_cents || 0) : null, sum, "subtotal"));
  if (see) {
    rows.push(el("tr", { class: "muted" }, el("th", {}, "Of which: overhead"), el("td", {}, ""), el("td", { class: "money" }, money(t.overhead_cents || 0))));
    rows.push(el("tr", { class: "muted" }, el("th", {}, "Of which: profit"), el("td", {}, ""), el("td", { class: "money" }, money(t.profit_cents || 0))));
    rows.push(el("tr", { class: "muted" }, el("th", {}, "Of which: tax"), el("td", {}, ""), el("td", { class: "money" }, money(t.tax_cents || 0))));
  }
  if (t.minimum_charge_adjustment_cents) rows.push(row("Minimum charge adjustment", null, t.minimum_charge_adjustment_cents));
  if (t.rounding_adjustment_cents) rows.push(row("Rounding", null, t.rounding_adjustment_cents));
  rows.push(row("Total", null, t.total_cents || 0, "total"));
  return el("div", { class: "card section", id: "estimate-totals" }, el("h3", {}, "Estimate total"),
    el("table", { class: "list totals" },
      el("thead", {}, el("tr", {}, el("th", {}, "Trade / section"), see ? el("th", {}, "Cost") : null, el("th", {}, "Price (with markups)"))),
      el("tbody", {}, rows)));
}

// What changed since the estimate was last approved (it was reopened): only these need checking again.
function sinceApprovalCard(s) {
  const items = s.answers.map(a => el("li", {}, el("strong", {}, a.trade + ": "), a.label + " ",
      el("span", { class: "muted" }, (a.from === null ? "none" : a.from) + " → "), a.to === null ? "none" : a.to))
    .concat(s.lines.map(l => el("li", {}, el("strong", {}, l.trade + ": "), l.description + " ",
      el("span", { class: "muted" }, l.change + (l.fields ? " (" + l.fields.join(", ").replace(/_/g, " ") + ")" : "") + ", "),
      (l.from || "—") + " → " + (l.to || "—"))));
  return el("div", { class: "card section note", id: "since-approval" },
    el("h3", {}, "✏️ Changed since it was approved"),
    el("p", {}, s.summary + "."),
    items.length ? el("ul", {}, items) : null,
    s.unchanged_lines ? el("p", { class: "muted small" }, "The other " + s.unchanged_lines + " line(s) are as approved; only the changes above need checking.") : null);
}

function num2(v) { const n = parseFloat(v); return isNaN(n) ? String(v) : n.toLocaleString(undefined, { maximumFractionDigits: 2 }); }

function sourcesTable(d, tr, meas, msg) {
  const rows = tr.questions.filter(q => q.state !== "none" || q.measurement_ids.length || q.proposed_ids.length);
  if (!rows.length) return el("p", { class: "muted small" }, "Nothing on this trade comes from the plans yet.");
  return el("table", { class: "kv sources", id: "sources-" + tr.module_id },
    rows.map(q => el("tr", { "data-question": q.id, class: "state-" + q.state },
      el("th", {}, q.label),
      el("td", {}, (q.answer !== null && q.answer !== undefined ? "priced at " + num2(q.answer) + (q.unit ? " " + q.unit : "") : "not priced"),
        q.measured !== null && q.measured !== undefined ? " · measured " + num2(q.measured) + (q.unit ? " " + q.unit : "") : "",
        " · ", el("span", { class: "status" + (q.state === "differs" ? " sample" : "") }, STATE_WORDS[q.state] || q.state),
        q.proposed_ids.length ? el("span", { class: "muted small" }, " · " + q.proposed_ids.length + " waiting for approval") : null))));
}

// (Not lineMeasurements: the web scripts share one global scope, and review.js has a function of that name.)
function lineMeasurementList(est, ln, lk, meas, d) {
  const ids = lk.measurement_ids.concat(lk.proposed_ids);
  const list = el("ul", { class: "plain line-measurements", "data-line-list": ln.id },
    ids.map(mid => {
      const m = meas.get(mid) || { id: mid };
      return el("li", { "data-mid": mid },
        (m.status === "approved" ? "🔒 " : "⏳ ") + (m.label || words(m.feeds)) + (m.room ? " (" + m.room + ")" : "") + " · " +
        num2(m.qty) + " " + (m.unit || "") + " · " + (m.status === "approved" ? "approved" : "waiting for approval") + " ",
        d.can_review && m.sheet_id ? el("a", { href: "#/takeoffs/" + est.id + "?m=" + mid }, "show on the plan") :
          el("span", { class: "muted small" }, m.sheet_id ? "" : "typed, not on a sheet"));
    }));
  const parts = [el("p", { class: "small" }, "Its quantity comes from " + lk.questions.map(words).join(", ") + ". Only approved measurements are priced.")];
  if (d.can_review && ids.some(mid => (meas.get(mid) || {}).sheet_id)) {
    parts.push(el("p", {}, el("a", { class: "button", href: "#/takeoffs/" + est.id + "?line=" + ln.id, id: "line-on-plan-" + ln.id }, "Show all of them on the plan")));
  }
  return el("div", {}, ...parts, list);
}

function optionsBlock(d, sec, msg) {
  const est = d.estimate, saved = (d.options || []).filter(o => o.module_id === sec.module_id);
  const defs = ((d.scenario_defs || {})[sec.module_id]) || [];
  const tip = el("div", { class: "options-tip", id: "options-tip-" + sec.module_id, hidden: true },
    el("p", {}, "Good / better / best prices different versions of this trade \u2014 for example, different materials or finishes \u2014 so you can offer the customer a choice. Nothing changes until you pick one with \u201CUse this one\u2026\u201D."),
    defs.length
      ? el("ul", {}, defs.map(o => el("li", {}, o.label)))
      : el("p", { class: "muted" }, "This trade has no built-in options yet."));
  const sum = el("summary", { class: "options-tip-target", id: "options-summary-" + sec.module_id },
    "Good / better / best options", tip);
  sum.addEventListener("mouseenter", () => { tip.hidden = false; });
  sum.addEventListener("mouseleave", () => { tip.hidden = true; });
  const wrap = el("details", { class: "options", id: "options-" + sec.module_id, open: saved.length > 0 }, sum);
  const out = el("div", {});
  const show = opts => out.replaceChildren(el("table", { class: "list" },
    el("thead", {}, el("tr", {}, el("th", {}, "Option"), el("th", {}, "Total"), el("th", {}, ""))),
    el("tbody", {}, opts.map(o => {
      const ask = el("div", {});
      const choose = o.current || o.chosen ? el("span", { class: "status" }, "this quote")
        : el("button", { class: "button", type: "button", "data-option": o.id }, "Use this one…");
      if (choose.tagName === "BUTTON") {
        choose.addEventListener("click", () => askThen(ask, choose, "/estimates/" + est.id + "/options/choose",
          { option_id: o.id, module_id: sec.module_id, rev: est.rev }, () => "Switched to " + o.label, "option"));
      }
      return el("tr", {}, el("td", {}, o.label), el("td", { class: "money" }, money(o.total_cents)), el("td", {}, choose, ask));
    }))));
  if (saved.length) show(saved);
  const price = el("button", { class: "button", type: "button", id: "options-price-" + sec.module_id }, saved.length ? "Price them again" : "Price the options");
  price.addEventListener("click", async () => {
    price.disabled = true;
    try { show((await api("POST", "/estimates/" + est.id + "/options", { module_id: sec.module_id })).options); }
    catch (e) { if (e.status !== 401) out.replaceChildren(errorBox(e)); } finally { price.disabled = false; }
  });
  wrap.append(el("div", { class: "row" }, price), out);
  return wrap;
}

// The Bill of Materials for one construction trade: the material lines, aggregated by price book item,
// with the quantity to order (waste included) and a checklist of what's ordered already. Service trades
// and "Other lines" have no list, so nothing renders for them.
function bomBlock(d, sec, msg) {
  const est = d.estimate, see = d.see_margins;
  const entry = (d.bom || []).find(b => b.module_id === sec.module_id);
  const items = (entry && entry.items) || [];
  if (!items.length) return null;
  const costOf = item => item.unit_cost_cents === undefined || item.unit_cost_cents === null ? null
    : Math.round(item.unit_cost_cents * parseFloat(item.order_quantity));
  const rows = items.map(item => {
    const box = el("input", { type: "checkbox", checked: item.ordered, "aria-label": "Ordered: " + item.description,
      "data-bom-ordered": item.item_key });
    box.addEventListener("change", async () => {
      const ordered = box.checked;
      box.disabled = true;
      try {
        await api("POST", "/estimates/" + est.id + "/bom/ordered",
          { section_id: entry.section_id, item_key: item.item_key, ordered });
      } catch (e) {
        box.checked = !ordered;
        if (e.status !== 401) msg.replaceChildren(errorBox(e));
      } finally { box.disabled = false; }
    });
    const cost = costOf(item);
    return el("tr", { "data-bom-item": item.item_key },
      el("td", {}, item.description),
      el("td", {}, num2(item.order_quantity)),
      el("td", {}, item.unit),
      el("td", {}, item.supplier || "\u2014"),
      see ? el("td", { class: "money" }, cost === null ? "\u2014" : money(cost)) : null,
      el("td", {}, box));
  });
  const csvCell = v => { const s = String(v === null || v === undefined ? "" : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  // The total material cost: every priced item; unpriced ones are counted so the total isn't read as complete.
  const costs = items.map(costOf);
  const total = costs.reduce((a, c) => a + (c === null ? 0 : c), 0);
  const unpriced = costs.filter(c => c === null).length;
  const totalNote = unpriced ? " (" + unpriced + " item" + (unpriced === 1 ? "" : "s") + " not priced)" : "";
  const totalRow = see ? [["Total" + totalNote, "", "", "", "", (total / 100).toFixed(2)]] : [];
  const csv = [["Item", "Qty to order", "Unit", "Supplier", "Unit cost", "Cost"]]
    .concat(items.map(item => {
      const cost = costOf(item);
      return [item.description, item.order_quantity, item.unit, item.supplier || "",
        item.unit_cost_cents === undefined || item.unit_cost_cents === null ? "" : (item.unit_cost_cents / 100).toFixed(2),
        cost === null ? "" : (cost / 100).toFixed(2)];
    }))
    .concat(totalRow)
    .map(r => r.map(csvCell).join(",")).join("\r\n");
  const copy = el("button", { class: "button", type: "button", id: "bom-copy-" + sec.module_id }, "Copy list");
  copy.addEventListener("click", async () => {
    const text = items.map(item => item.order_quantity + " " + item.unit + " \u2014 " + item.description).join("\n");
    const withTotal = see ? text + String.fromCharCode(10) + "Total: " + money(total) + totalNote : text;
    try { await navigator.clipboard.writeText(withTotal); toast("Bill of materials copied"); }
    catch (e) { msg.replaceChildren(errorBox(e)); }
  });
  const download = el("button", { class: "button", type: "button", id: "bom-csv-" + sec.module_id }, "Download CSV");
  download.addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = el("a", { href: url, download: "bom-" + est.id + "-" + sec.module_id + ".csv" });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  return el("details", { class: "bom", id: "bom-" + sec.module_id },
    el("summary", {}, "Bill of Materials (" + items.length + (items.length === 1 ? " item" : " items")
      + (see ? " · " + money(total) : "") + ")"),
    el("div", { class: "row" }, copy, download),
    el("table", { class: "list", id: "bom-table-" + sec.module_id },
      el("thead", {}, el("tr", {}, el("th", {}, "Item"), el("th", {}, "Qty to order"), el("th", {}, "Unit"),
        el("th", {}, "Supplier"), see ? el("th", {}, "Cost") : null, el("th", {}, "Ordered"))),
      el("tbody", {}, rows),
      see ? el("tfoot", {}, el("tr", { id: "bom-total-" + sec.module_id },
        el("th", {}, "Total materials" + totalNote), el("td", {}), el("td", {}), el("td", {}),
        el("th", { class: "money" }, money(total)), el("td", {}))) : null));
}

// The Inspector's code review of one trade: run it, read the checklist, add what's missing.
function inspectionReviewCard(d, sec, msg) {
  const est = d.estimate, insp = d.inspector || {},
    review = (d.inspection_reviews || []).find(r => r.module_id === sec.module_id) || null;
  const box = el("div", { class: "card section", id: "inspection-review-" + sec.module_id },
    el("h3", {}, "🔍 Inspection review"));
  const zips = (est.address || "").match(/\b\d{5}\b/g) || [];
  const zipFromAddress = zips.length ? zips[zips.length - 1] : "";
  const zip = (review && review.zip_code) || zipFromAddress;
  if (review) {
    const j = review.jurisdiction || {};
    const place = j.city ? j.city + ", " + j.state_abbr : "Zip " + review.zip_code;
    const edition = (j.edition || {}).code || "Code edition not in the local table";
    box.append(el("p", { class: "muted", id: "inspection-jurisdiction-" + sec.module_id },
      place + " — " + edition + (j.verified === false ? " (unverified — the zip lookup was unreachable)" : ""),
      " · reviewed " + when(review.created_at)));
  }
  const runRow = el("div", { class: "row" });
  let zipInput = null;
  if (!zipFromAddress) {
    zipInput = el("input", { id: "inspection-zip-" + sec.module_id, maxlength: 5, inputmode: "numeric", value: zip || "",
      placeholder: "Zip code", "aria-label": "Zip code" });
    runRow.append(el("label", {}, "Zip code", zipInput));
  } else if (!review) {
    runRow.append(el("span", { class: "muted" }, "Zip " + zipFromAddress + " (from the address)"));
  }
  const run = el("button", { class: "button", type: "button", id: "inspection-run-" + sec.module_id },
    review ? "Run the review again" : "Run inspection review");
  runRow.append(run);
  let whyDisabled = "";
  if (!d.can_edit) whyDisabled = "Only owners and estimators can run a review.";
  else if (!insp.enabled) whyDisabled = "Turn on the Inspector agent in 🤖 AI agents to run a code review.";
  else if (!insp.ready) whyDisabled = "The Inspector agent can't run yet: " + (insp.why_not || "its provider is not ready.");
  run.disabled = !!whyDisabled;
  if (whyDisabled) runRow.append(el("span", { class: "muted small" }, whyDisabled));
  run.addEventListener("click", async () => {
    const z = zipInput ? zipInput.value.trim() : zipFromAddress;
    if (!z) { if (zipInput) zipInput.focus(); return; }
    run.disabled = true;
    try {
      await api("POST", "/estimates/" + est.id + "/inspection-review", { zip_code: z, module_id: sec.module_id });
      toast("Inspection review done");
      route();
    } catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); run.disabled = false; }
  });
  box.append(runRow);
  if (review) {
    const icon = { pass: "✓", flag: "⚠", missing: "✗" };
    // 2026-11-23 (David: "when I review the inspection and click add to the estimate, nothing happens"): the AI had
    // named items that aren't in the price book, and the refusal showed at the top of the page. Now an item in the
    // price book adds in one click; one that isn't opens a picker right under its row (the closest items, or type a
    // price), and anything that goes wrong is said beside the button.
    const apply = async (btn, out, item, extra) => {
      btn.disabled = true;
      out.replaceChildren();
      try {
        await api("POST", "/estimates/" + est.id + "/inspection-review/" + review.id + "/apply",
          { item_id: item.id, rev: est.rev, ...extra });
        toast("Added to the estimate — see Other lines");
        route();
      } catch (e) {
        if (e.status !== 401) out.replaceChildren(errorBox(e));
        btn.disabled = false;
      }
    };
    const pickerRow = (item, action, cols) => {
      const tr = el("tr", { class: "inspection-pick", "data-inspection-pick": item.id, hidden: "" });
      const matches = action.matches || [];
      const pick = el("select", { "data-inspection-price": item.id, "aria-label": "Price book item" },
        ...matches.map(p => el("option", { value: p.price_key },
          p.description + " — " + money(p.cost_cents) + " / " + p.unit + (p.sample ? " (sample)" : ""))),
        el("option", { value: "" }, "None of these — type a price"));
      const qty = el("input", { "data-inspection-qty": item.id, inputmode: "decimal", maxlength: 20, size: 5,
        value: String(action.quantity || 1), "aria-label": "Quantity" });
      const cost = el("input", { "data-inspection-cost": item.id, inputmode: "decimal", maxlength: 20, size: 8,
        placeholder: "$ each", "aria-label": "Unit cost in dollars" });
      const costLabel = el("label", { class: "small" }, "Unit cost ", cost);
      const sync = () => { costLabel.hidden = !!pick.value; };
      pick.addEventListener("change", sync);
      sync();
      const out = el("div", {});
      const go = el("button", { class: "primary", type: "button", "data-inspection-pick-go": item.id }, "Add it");
      const cancel = el("button", { class: "button", type: "button" }, "Cancel");
      cancel.addEventListener("click", () => { tr.hidden = true; });
      go.addEventListener("click", () => {
        const extra = { quantity: qty.value.trim() };
        if (pick.value) extra.price_key = pick.value;
        else {
          const dollarsTyped = parseFloat(cost.value.replace(/[$,]/g, ""));
          if (isNaN(dollarsTyped) || dollarsTyped < 0) {
            out.replaceChildren(el("p", { class: "error" }, "Type the unit cost in dollars, or pick a price book item."));
            cost.focus();
            return;
          }
          extra.unit_cost_cents = Math.round(dollarsTyped * 100);
        }
        apply(go, out, item, extra);
      });
      tr.append(el("td", {}), el("td", { colspan: String(cols - 1) },
        el("p", { class: "small" }, (action.price_key ? "“" + action.price_key + "” isn't in your price book. " : "") +
          (matches.length ? "Pick the closest item, or type a price:" : "Nothing close in your price book — type a price:")),
        el("div", { class: "row" }, matches.length ? pick : null, el("label", { class: "small" }, "Qty ", qty),
          costLabel, go, cancel),
        out));
      // only a close match is chosen for you; otherwise it starts on "type a price" (the list is still there)
      pick.value = matches.length && matches[0].strong ? matches[0].price_key : "";
      sync();
      return tr;
    };
    const rows = [];
    (review.checklist || []).forEach(item => {
      const action = item.suggested_action;
      let cell = null, picker = null;
      if (action && d.can_edit) {
        const out = el("div", {});
        const missing = action.in_price_book === false;
        const add = el("button", { class: "button", type: "button", "data-inspection-add": item.id },
          missing ? "Add to estimate…" : "Add to estimate");
        if (missing) {
          picker = pickerRow(item, action, 5);
          add.addEventListener("click", () => {
            picker.hidden = !picker.hidden;
            if (!picker.hidden) { const f = picker.querySelector("select, input"); if (f) f.focus(); }
          });
        } else add.addEventListener("click", () => apply(add, out, item, {}));
        cell = el("div", {}, add, out);
      }
      const price = action && action.price ? " — " + money(action.price.cost_cents) + " / " + action.price.unit +
        (action.price.sample ? " (sample price)" : "") : "";
      rows.push(el("tr", { "data-inspection-item": item.id },
        el("td", {}, icon[item.status] || "?"),
        el("td", {}, item.description,
          action ? el("div", { class: "muted small" },
            "Add: " + (action.quantity || 1) + " " + (action.unit || "") + " " + (action.description || action.price_key) +
            price + (action.in_price_book === false ? " (not in your price book)" : "")) : null),
        el("td", {}, item.code_ref),
        el("td", {}, item.note || ""),
        el("td", {}, cell)));
      if (picker) rows.push(picker);
    });
    box.append(el("table", { class: "list", id: "inspection-checklist-" + sec.module_id },
      el("thead", {}, el("tr", {}, el("th", {}, ""), el("th", {}, "Check"), el("th", {}, "Code"), el("th", {}, "Note"), el("th", {}, ""))),
      el("tbody", {}, rows)));
  }
  box.append(el("p", { class: "muted small" },
    "Local amendments vary — confirm with the building department before submitting."));
  return box;
}

function addLineForm(d, msg, book) {
  const est = d.estimate;
  const kind = el("select", { id: "line-kind", "aria-label": "Kind" }, d.line_kinds.map(k => el("option", { value: k }, words(k))));
  const desc = el("input", { id: "line-desc", maxlength: 200, placeholder: "e.g. Dumpster rental", "aria-label": "Description" });
  const qty = el("input", { id: "line-qty", inputmode: "decimal", maxlength: 20, value: "1", "aria-label": "Quantity" });
  const unit = el("input", { id: "line-unit", maxlength: 20, value: "ea", "aria-label": "Unit" });
  const cost = el("input", { id: "line-cost", inputmode: "decimal", maxlength: 20, placeholder: "450.00", "aria-label": "Unit cost in dollars" });
  const key = el("input", { id: "line-key", maxlength: 100, placeholder: "or a price book key", "aria-label": "Price book key" });
  const waste = el("input", { id: "line-waste", inputmode: "decimal", maxlength: 6, value: "0", "aria-label": "Waste percent" });
  // Pick a price book item instead of typing its key: fills description, unit, cost and key.
  const prices = ((book && book.prices) || []).slice().sort((a, b) => String(a.description).localeCompare(String(b.description)));
  let picked = null;
  const pick = prices.length ? el("select", { id: "line-pick", "aria-label": "Price book item" },
    el("option", { value: "" }, "Pick a price book item\u2026"),
    prices.map(p => el("option", { value: p.price_key },
      p.description + " \u2014 " + money(p.cost_cents) + " / " + p.unit + (p.sample ? " (sample)" : "")))) : null;
  if (pick) {
    pick.addEventListener("change", () => {
      picked = prices.find(x => x.price_key === pick.value) || null;
      if (!picked) return;
      desc.value = picked.description; unit.value = picked.unit;
      cost.value = dollars(picked.cost_cents); key.value = picked.price_key;
      // The item's own kind (a pump truck is equipment or a sub, not material), so labor and tax come out right.
      if (picked.kind && d.line_kinds.includes(picked.kind)) kind.value = picked.kind;
    });
    // A hand-edited cost is a hand cost, not the price book's: drop the key so the typed cost is used.
    cost.addEventListener("input", () => {
      if (picked && key.value === picked.price_key && cost.value.trim() !== dollars(picked.cost_cents)) {
        key.value = ""; pick.value = ""; picked = null;
      }
    });
  }
  const add = el("button", { class: "primary", type: "button", id: "line-add" }, "Add the line");
  const out = el("div", {});
  add.addEventListener("click", async () => {
    const body = { rev: est.rev, kind: kind.value, description: desc.value.trim(), quantity: qty.value.trim(), unit: unit.value.trim(),
                   waste_pct: String((parseFloat(waste.value) || 0) / 100) };
    if (key.value.trim()) body.price_key = key.value.trim();
    else {
      const dollars = parseFloat(cost.value.replace(/[$,]/g, ""));
      if (isNaN(dollars)) { out.replaceChildren(el("p", { class: "error" }, "Give a unit cost or a price book key.")); cost.focus(); return; }
      body.unit_cost_cents = Math.round(dollars * 100);
    }
    add.disabled = true;
    try { await api("POST", "/estimates/" + est.id + "/lines", body); toast("Line added"); route(); }
    catch (e) { if (e.status !== 401) out.replaceChildren(errorBox(e)); } finally { add.disabled = false; }
  });
  return el("details", { class: "card section", id: "add-line" }, el("summary", {}, "＋ Add a line by hand"),
    el("div", { class: "qgrid" }, el("label", {}, "Kind", kind), el("label", {}, "Description", desc), el("label", {}, "Quantity", qty),
      el("label", {}, "Unit", unit), el("label", {}, "Unit cost ($)", cost), el("label", {}, "Price book key", key), el("label", {}, "Waste %", waste),
      pick ? el("label", {}, "Price book item", pick) : null),
    el("div", { class: "row" }, add), out);
}


// Change one priced line in place (quantity, unit cost, waste, description, price book item), with the reason the
// override needs; the server asks first, showing the change, then applies it. Picking another price book item fills
// the description and cost from it, and the picked item stays on the line when the trade is priced again;
// "Back to the module default" clears a pick back to the trade's own item.
function lineEditRow(d, sec, ln, cols, close, book) {
  const est = d.estimate, see = d.see_margins, fromAssembly = sec.module_id !== "custom";
  const desc = el("input", { maxlength: 200, value: ln.description, "aria-label": "Description" });
  const qty = el("input", { inputmode: "decimal", maxlength: 20, value: ln.quantity, "aria-label": "Quantity" });
  const cost = el("input", { inputmode: "decimal", maxlength: 20, placeholder: "unit cost $",
    value: ln.unit_cost_cents !== undefined && ln.unit_cost_cents !== null ? dollars(ln.unit_cost_cents) : "", "aria-label": "Unit cost in dollars" });
  const waste = el("input", { inputmode: "decimal", maxlength: 6, value: Math.round(parseFloat(ln.waste_pct || 0) * 1000) / 10, "aria-label": "Waste percent" });
  const reason = el("input", { maxlength: 300, placeholder: fromAssembly ? "Why this changes (needed)" : "Why (optional)", "aria-label": "Reason" });
  // Pick a price book item instead of the one the line has: fills description and cost, and sets the price key.
  // Only items priced per this line's unit can be picked (the line's unit doesn't change here); the line's
  // current item is selected. A picked item can be cleared back to the trade's own item.
  const swapped = !!(ln.override && ln.override.changed && ln.override.changed.price_key);
  const prices = ((book && book.prices) || []).filter(p => p.unit === ln.unit)
    .slice().sort((a, b) => String(a.description).localeCompare(String(b.description)));
  let picked = null, toDefault = false, pick = null;
  if (prices.length || (fromAssembly && swapped)) {
    const options = [];
    if (!ln.price_key) options.push(el("option", { value: "" }, "Pick a price book item\u2026"));
    if (ln.price_key && !prices.some(p => p.price_key === ln.price_key)) {
      options.push(el("option", { value: ln.price_key, selected: true }, ln.price_key + " (not in the price book)"));
    }
    for (const p of prices) options.push(el("option", { value: p.price_key, selected: p.price_key === ln.price_key },
      p.description + " \u2014 " + money(p.cost_cents) + " / " + p.unit + (p.sample ? " (sample)" : "")));
    if (fromAssembly && swapped) options.push(el("option", { value: "__default__" }, "\u21A9 Back to the module default item"));
    pick = el("select", { id: "line-edit-pick-" + ln.id, "aria-label": "Price book item" }, ...options);
    pick.addEventListener("change", () => {
      toDefault = pick.value === "__default__";
      picked = toDefault ? null : prices.find(x => x.price_key === pick.value) || null;
      if (!picked) return;
      desc.value = picked.description;
      if (see) cost.value = dollars(picked.cost_cents);
    });
    // A hand-edited cost is a hand cost, not the price book's: drop the pick so the typed cost is used.
    cost.addEventListener("input", () => {
      if (picked && cost.value.trim() !== dollars(picked.cost_cents)) {
        pick.value = ln.price_key || ""; picked = null;
      }
    });
  }
  const save = el("button", { class: "primary", type: "button" }, "Save the change\u2026");
  const cancel = el("button", { class: "button", type: "button" }, "Cancel");
  const ask = el("div", {});
  cancel.addEventListener("click", close);
  save.addEventListener("click", () => {
    const body = { rev: est.rev };
    if (qty.value.trim() !== String(ln.quantity)) body.quantity = qty.value.trim();
    if (desc.value.trim() !== ln.description) body.description = desc.value.trim();
    if (see) {
      const c = parseFloat(cost.value.replace(/[$,]/g, ""));
      if (!isNaN(c) && Math.round(c * 100) !== ln.unit_cost_cents) body.unit_cost_cents = Math.round(c * 100);
      const w = parseFloat(waste.value);
      if (!isNaN(w) && String(w / 100) !== String(ln.waste_pct)) body.waste_pct = String(w / 100);
    }
    if (toDefault) body.price_default = true;
    else if (picked && picked.price_key !== (ln.price_key || null)) body.price_key = picked.price_key;
    if (fromAssembly && !reason.value.trim()) { ask.replaceChildren(el("p", { class: "error" }, "Say why this priced line changes.")); reason.focus(); return; }
    if (reason.value.trim()) body.reason = reason.value.trim();
    if (!("quantity" in body || "description" in body || "unit_cost_cents" in body || "waste_pct" in body || "price_key" in body || "price_default" in body)) {
      ask.replaceChildren(el("p", { class: "muted" }, "Nothing changed.")); return;
    }
    askThen(ask, save, "/estimates/" + est.id + "/lines/" + ln.id, body, () => "Line changed", "line");
  });
  const fields = [el("label", {}, "Description", desc), el("label", {}, "Quantity", qty)];
  if (see) fields.push(el("label", {}, "Unit cost ($)", cost), el("label", {}, "Waste %", waste));
  if (pick) fields.push(el("label", {}, "Price book item", pick));
  fields.push(el("label", {}, "Reason", reason));
  const note = pick && fromAssembly ? el("p", { class: "muted small" },
    "The item you pick stays on this line when this trade is priced again.") : null;
  // The line's own price book item changed since the line was priced (2026-11-17, David): picking it again does
  // nothing (it's already the one selected), so say what the price book has now and fill it in with one click.
  const mine = prices.find(p => p.price_key === ln.price_key);
  let drift = null;
  // A trade's lines are named by the trade ("Place and finish concrete"), not by their price book item, so for them
  // only a different cost counts; a line added by hand is named after its item, so a new name counts too.
  if (mine && ((see && mine.cost_cents !== ln.unit_cost_cents) || (!fromAssembly && mine.description !== ln.description))) {
    const useIt = el("button", { class: "button", type: "button", id: "line-edit-use-book-" + ln.id }, "Use the price book's");
    useIt.addEventListener("click", () => {
      desc.value = mine.description;
      if (see) cost.value = dollars(mine.cost_cents);
      picked = mine;
      useIt.disabled = true;
    });
    drift = el("p", { class: "note", "data-line-drift": ln.id },
      "The price book's " + ln.price_key + " is now “" + mine.description + "”" + (see ? " at " + money(mine.cost_cents) + " / " + mine.unit : "")
      + "; this line still has “" + ln.description + "”" + (see ? " at " + money(ln.unit_cost_cents) : "") + ". ", useIt);
  }
  return el("tr", { class: "line-edit" }, el("td", { colspan: cols },
    drift, el("div", { class: "qgrid" }, ...fields), note, el("div", { class: "row" }, save, cancel), ask));
}

// Take one priced line off: the reason comes first (the trade's assembly made it), then the server asks.
function lineDeleteRow(d, sec, ln, cols, close) {
  const est = d.estimate, fromAssembly = sec.module_id !== "custom";
  const reason = el("input", { maxlength: 300, placeholder: fromAssembly ? "Why this line comes off (needed)" : "Why (optional)", "aria-label": "Reason" });
  const take = el("button", { class: "primary", type: "button" }, "Take this line off\u2026");
  const cancel = el("button", { class: "button", type: "button" }, "Cancel");
  const ask = el("div", {});
  cancel.addEventListener("click", close);
  take.addEventListener("click", () => {
    if (fromAssembly && !reason.value.trim()) { ask.replaceChildren(el("p", { class: "error" }, "Say why this priced line comes off.")); reason.focus(); return; }
    const body = { rev: est.rev, remove: true };
    if (reason.value.trim()) body.reason = reason.value.trim();
    askThen(ask, take, "/estimates/" + est.id + "/lines/" + ln.id, body, () => "Line taken off", "line");
  });
  return el("tr", { class: "line-edit" }, el("td", { colspan: cols },
    el("p", {}, "Take off \u201c" + ln.description + "\u201d (" + num2(ln.quantity) + " " + ln.unit + ")?"),
    el("div", { class: "qgrid" }, el("label", {}, "Reason", reason)),
    el("div", { class: "row" }, take, cancel), ask));
}

// Re-open a trade's question form with its current answers, and price the trade again on submit
// (quick.answer replaces the trade's lines, so no duplicates).
async function editAnswers(d, sec, tr, form) {
  const est = d.estimate;
  form.replaceChildren(el("p", { class: "muted" }, "Loading the questions\u2026"));
  let q;
  try { q = await api("GET", "/modules/" + encodeURIComponent(sec.module_id) + "/questions"); }
  catch (e) { if (e.status !== 401) form.replaceChildren(errorBox(e)); return; }
  // Every saved answer comes from the trade's section: tr.questions only lists the questions a line's quantity
  // formula uses, so yes/no and choice answers (vapor barrier, rebar size, pump...) came back blank (2026-11-17, David).
  const current = new Map((tr.questions || []).map(x => [x.id, x.answer]));
  for (const [k, v] of Object.entries(sec.answers || {})) current.set(k, v);
  for (const qq of q.questions) {
    if (current.has(qq.id) && current.get(qq.id) !== null && current.get(qq.id) !== undefined) qq.default = current.get(qq.id);
  }
  const btn = el("button", { class: "primary", type: "submit", id: "edit-answers-price-" + sec.module_id }, "Price it again");
  const cancel = el("button", { class: "button", type: "button" }, "Cancel");
  const out = el("div", {});
  const f = el("form", { class: "card section", id: "edit-answers-form-" + sec.module_id },
    el("strong", {}, q.module.name + " \u2014 answers"), el("div", { class: "qgrid" }, q.questions.map(questionInput)),
    el("div", { class: "row" }, btn, cancel), out);
  cancel.addEventListener("click", () => form.replaceChildren());
  f.onsubmit = async ev => {
    ev.preventDefault();
    const answers = {};
    for (const i of f.querySelectorAll("[data-q]")) {
      if (i.type === "checkbox") answers[i.dataset.q] = i.checked;
      else if (i.value !== "") answers[i.dataset.q] = i.tagName === "SELECT" ? i.value : Number(i.value);
    }
    btn.disabled = true;
    try {
      await api("POST", "/quick", { module_id: q.module.id, answers, estimate_id: est.id, rev: est.rev });
      toast(q.module.name + " priced again"); route();
    } catch (e) { if (e.status !== 401) out.replaceChildren(errorBox(e)); } finally { btn.disabled = false; }
  };
  form.replaceChildren(f);
}

function validateCard(r) {
  const icon = { error: "⛔", warning: "⚠", info: "ℹ" };
  return el("div", { class: "card section", id: "validate-result" },
    el("strong", {}, r.passed ? "✓ Ready to approve" : "⛔ Fix the errors before approving"),
    el("span", { class: "muted" }, " · " + r.errors + " error(s), " + r.warnings + " warning(s)"),
    r.findings.length ? el("ul", { class: "plain" }, r.findings.map(f => el("li", { class: "finding " + f.level }, (icon[f.level] || "") + " " + f.message)))
      : el("p", { class: "muted" }, "Nothing to look at."));
}

function historyCard(r) {
  const lines = r.lines || [];
  return el("div", { class: "card section", id: "history-result" },
    el("strong", {}, "Against past estimates and real job costs"), r.summary ? el("p", { class: "muted" }, r.summary) : null,
    lines.length ? el("table", { class: "list" },
      el("thead", {}, el("tr", {}, el("th", {}, "Line"), el("th", {}, "Unit cost"), el("th", {}, "Past estimates"), el("th", {}, "Jobs"), el("th", {}, ""))),
      el("tbody", {}, lines.map(l => el("tr", { "data-line": l.line_id }, el("td", {}, l.description), el("td", {}, l.unit_cost + " / " + l.unit),
        el("td", {}, l.past_estimates), el("td", {}, l.jobs_with_actuals),
        el("td", {}, l.flag ? el("span", { class: "status sample" }, l.message || words(l.flag)) : "")))))
      : el("p", { class: "muted" }, "No price-book lines to compare."));
}

SCREENS.estimates = renderEstimates;
PAGES.estimate = renderEstimate;
