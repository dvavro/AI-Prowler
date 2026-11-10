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
  const est = d.estimate, links = d.links;
  const lineLinks = new Map(links.lines.map(l => [l.line_id, l]));
  const meas = new Map(links.measurements.map(m => [m.id, m]));
  const msg = el("div", { id: "estimate-message", role: "status" });
  const t = est.totals || {};
  const parts = [el("p", {}, el("a", { href: "#/projects/" + est.id }, "← Project page"), " · ", el("a", { href: "#/estimates" }, "All estimates")),
    el("div", { class: "page-head" }, el("h2", {}, "🧮 " + est.title + (est.revision > 1 ? " (v" + est.revision + ")" : "")),
      el("div", { class: "row" }, el("span", { class: "status big" }, words(est.status)), helpLink("estimates")))];
  if (est.editing_warning) parts.push(el("p", { class: "note warn" }, est.editing_warning));
  if (est.change_summary) parts.push(el("p", { class: "muted" }, "What changed in this version: " + est.change_summary));
  parts.push(el("div", { class: "tiles" }, tile(money(t.total_cents || 0), "total"),
    d.see_margins && t.margin_pct !== undefined ? tile(Math.round(parseFloat(t.margin_pct) * 1000) / 10 + "%", "margin") : null,
    tile(est.sections.length, "trades"), tile(links.measurements.filter(m => m.status === "approved").length, "approved measurements")));
  parts.push(estimateActions(d, msg), msg);
  // Where each trade's quantities come from (measured / differs / typed / waiting), then its lines.
  const tradesWithoutLines = links.trades.filter(tr => !est.sections.some(s => s.module_id === tr.module_id));
  for (const sec of est.sections) {
    const tr = links.trades.find(x => x.module_id === sec.module_id);
    parts.push(sectionBlock(d, sec, tr, lineLinks, meas, focusLine, msg));
  }
  for (const tr of tradesWithoutLines) parts.push(sectionBlock(d, { id: null, module_id: tr.module_id, lines: [], subtotal_cents: 0 }, tr, lineLinks, meas, focusLine, msg));
  if (!est.sections.length && !tradesWithoutLines.length) {
    const next = d.can_edit
      ? ["Measure the plans in ", el("a", { href: "#/takeoffs/" + est.id }, "Blueprint Review"), " and Recalculate, or add a line below."]
      : ["Ask an estimator to price it."];
    parts.push(el("div", { class: "card empty", id: "estimate-empty" }, "No trades priced yet. ", ...next));
  }
  if (d.can_edit) parts.push(addLineForm(d, msg));
  main.replaceChildren(...parts);
  if (focusLine) {
    const row = main.querySelector('[data-line="' + focusLine + '"]');
    if (row) { row.classList.add("focus"); row.scrollIntoView({ block: "center" }); const b = row.querySelector(".link-chip"); if (b) b.click(); }
  }
}

function estimateActions(d, msg) {
  const est = d.estimate, row = el("div", { class: "row", id: "estimate-actions" });
  const out = el("div", { id: "estimate-results" });
  if (d.can_review) row.append(el("a", { class: "button", id: "estimate-review", href: "#/takeoffs/" + est.id }, "📏 Blueprint Review"));
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
  return el("div", { class: "section" }, row, out);
}

function sectionBlock(d, sec, tr, lineLinks, meas, focusLine, msg) {
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
  if (sec.id && d.can_options && sec.module_id !== "custom") box.append(optionsBlock(d, sec, msg));
  if (!sec.lines.length) { box.append(el("p", { class: "muted" }, "No lines priced for this trade yet.")); return box; }
  const see = d.see_margins;
  const tbl = el("table", { class: "list", id: "lines-" + sec.module_id },
    el("thead", {}, el("tr", {}, el("th", {}, "Line"), el("th", {}, "Quantity"), see ? el("th", {}, "Unit cost") : null,
      see ? el("th", {}, "Waste") : null, el("th", {}, "Price"), el("th", {}, "From the plans"))));
  const body = el("tbody", {});
  for (const ln of sec.lines) {
    const lk = lineLinks.get(ln.id) || { measurement_ids: [], proposed_ids: [], questions: [] };
    const ids = lk.measurement_ids.concat(lk.proposed_ids);
    const sub = el("tr", { class: "line-links", hidden: true }, el("td", { colspan: see ? 6 : 4 }, lineMeasurementList(est, ln, lk, meas, d)));
    let chip;
    if (ids.length) {
      chip = el("button", { class: "link-chip", type: "button", "data-line-chip": ln.id, title: "Show the measurements behind this line" },
        "📏 " + lk.measurement_ids.length + (lk.proposed_ids.length ? " (+" + lk.proposed_ids.length + " to review)" : ""));
      chip.addEventListener("click", () => { sub.hidden = !sub.hidden; chip.classList.toggle("open", !sub.hidden); });
    } else {
      chip = el("span", { class: "muted small" }, lk.questions.length ? "not measured" : "entered by hand");
    }
    body.append(el("tr", { "data-line": ln.id },
      el("td", {}, ln.description, el("span", { class: "muted small" }, " · " + words(ln.kind))),
      el("td", {}, num2(ln.quantity) + " " + ln.unit),
      see ? el("td", { class: "money" }, ln.unit_cost_cents !== undefined ? money(ln.unit_cost_cents) : "—") : null,
      see ? el("td", {}, Math.round(parseFloat(ln.waste_pct || 0) * 1000) / 10 + "%") : null,
      el("td", { class: "money" }, money(ln.total_cents || 0)),
      el("td", {}, chip)), sub);
  }
  tbl.append(body);
  box.append(tbl);
  return box;
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
  const wrap = el("details", { class: "options", id: "options-" + sec.module_id, open: saved.length > 0 },
    el("summary", {}, "Good / better / best options"));
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

function addLineForm(d, msg) {
  const est = d.estimate;
  const kind = el("select", { id: "line-kind", "aria-label": "Kind" }, d.line_kinds.map(k => el("option", { value: k }, words(k))));
  const desc = el("input", { id: "line-desc", maxlength: 200, placeholder: "e.g. Dumpster rental", "aria-label": "Description" });
  const qty = el("input", { id: "line-qty", inputmode: "decimal", maxlength: 20, value: "1", "aria-label": "Quantity" });
  const unit = el("input", { id: "line-unit", maxlength: 20, value: "ea", "aria-label": "Unit" });
  const cost = el("input", { id: "line-cost", inputmode: "decimal", maxlength: 20, placeholder: "450.00", "aria-label": "Unit cost in dollars" });
  const key = el("input", { id: "line-key", maxlength: 100, placeholder: "or a price book key", "aria-label": "Price book key" });
  const waste = el("input", { id: "line-waste", inputmode: "decimal", maxlength: 6, value: "0", "aria-label": "Waste percent" });
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
      el("label", {}, "Unit", unit), el("label", {}, "Unit cost ($)", cost), el("label", {}, "Price book key", key), el("label", {}, "Waste %", waste)),
    el("div", { class: "row" }, add), out);
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
