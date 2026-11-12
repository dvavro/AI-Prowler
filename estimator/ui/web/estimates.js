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
  if (est.change_summary) parts.push(el("p", { class: "muted" }, "What changed in this version: " + est.change_summary));
  parts.push(el("div", { class: "tiles" }, tile(money(t.total_cents || 0), "total"),
    d.see_margins && t.margin_pct !== undefined ? tile(Math.round(parseFloat(t.margin_pct) * 1000) / 10 + "%", "margin") : null,
    tile(est.sections.length, "trades"), tile(links.measurements.filter(m => m.status === "approved").length, "approved measurements")));
  parts.push(estimateActions(d, msg), msg);
  // Where each trade's quantities come from (measured / differs / typed / waiting), then its lines.
  const tradesWithoutLines = links.trades.filter(tr => !est.sections.some(s => s.module_id === tr.module_id));
  for (const sec of est.sections) {
    const tr = links.trades.find(x => x.module_id === sec.module_id);
    parts.push(sectionBlock(d, sec, tr, lineLinks, meas, focusLine, msg, book));
  }
  for (const tr of tradesWithoutLines) parts.push(sectionBlock(d, { id: null, module_id: tr.module_id, lines: [], subtotal_cents: 0 }, tr, lineLinks, meas, focusLine, msg, book));
  if (!est.sections.length && !tradesWithoutLines.length) {
    const next = d.can_edit
      ? ["Measure the plans in ", el("a", { href: "#/takeoffs/" + est.id }, "Blueprint Review"), " and Recalculate, or add a line below."]
      : ["Ask an estimator to price it."];
    parts.push(el("div", { class: "card empty", id: "estimate-empty" }, "No trades priced yet. ", ...next));
  }
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
  if (!sec.lines.length) { box.append(el("p", { class: "muted" }, "No lines priced for this trade yet.")); return box; }
  const see = d.see_margins;
  const cols = 4 + (see ? 2 : 0) + (d.can_edit ? 1 : 0);
  const tbl = el("table", { class: "list", id: "lines-" + sec.module_id },
    el("thead", {}, el("tr", {}, el("th", {}, "Line"), el("th", {}, "Quantity"), see ? el("th", {}, "Unit cost") : null,
      see ? el("th", {}, "Waste") : null, el("th", {}, "Price"), el("th", {}, "From the plans"),
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
      el("td", { class: "money" }, money(ln.total_cents || 0)),
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
  return el("tr", { class: "line-edit" }, el("td", { colspan: cols },
    el("div", { class: "qgrid" }, ...fields), note, el("div", { class: "row" }, save, cancel), ask));
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
  const current = new Map((tr.questions || []).map(x => [x.id, x.answer]));
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
