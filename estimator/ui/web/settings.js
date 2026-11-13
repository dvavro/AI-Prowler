/* Settings screen (Coder 2 Sprint 17). Owner only.
 *
 * Loaded after app.js and reports.js (el, api, money, dollars, words, when, helpLink, errorBox, toast, route, askConfirm).
 * Route: #/settings?section=<id>   sections: company, money (tax, markups, labor rates), bids, approvals, ai, people, data, audit
 * Every change asks first: the server lists each change (old → new), then saves on Yes through the same calls the AI
 * uses (est_setup_step, Director settings, est_ai_privacy, pricebook_update).
 */
"use strict";

const SETTINGS_SECTIONS = [["company", "🏢 Company"], ["money", "💲 Tax, markups and labor"], ["bids", "📨 Bid template"],
                           ["approvals", "✅ Approval rules"], ["ai", "🤖 AI and privacy"], ["people", "👥 Users and roles"],
                           ["data", "💾 Data and backups"], ["tours", "🎓 Guided tours"], ["audit", "📜 Audit log"]];

function field(label, input, hint) {
  return el("label", { class: "field" }, label, input, hint ? el("span", { class: "muted small" }, hint) : null);
}

function textInput(id, value, attrs) {
  return el("input", { id, type: "text", value: value === null || value === undefined ? "" : value, ...(attrs || {}) });
}

// One form section: inputs -> data (only the fields that changed) -> POST /settings/<section>, asked first.
function settingsForm(id, section, title, rows, collect, help) {
  const msg = el("div", { role: "status", id: id + "-message" });
  const save = el("button", { class: "primary", type: "button", id: id + "-save" }, "Save…");
  save.addEventListener("click", () => {
    let data;
    try { data = collect(); } catch (e) { msg.replaceChildren(el("p", { class: "error" }, e.message)); return; }
    if (!Object.keys(data).length) { msg.replaceChildren(el("p", { class: "muted" }, "Nothing changed.")); return; }
    askConfirm(msg, save, "/settings/" + section, { data }, () => { toast(title + " saved."); route(); }, id);
  });
  return el("div", { class: "card section", id }, el("h3", {}, title), help ? el("p", { class: "muted" }, help) : null,
    el("div", { class: "form-grid" }, rows), el("div", { class: "row" }, save), msg);
}

function changed(inputs, current) {
  const out = {};
  for (const [k, inp] of Object.entries(inputs)) {
    const v = inp.type === "checkbox" ? inp.checked : inp.value.trim();
    const was = current[k] === null || current[k] === undefined ? "" : current[k];
    if (inp.type === "checkbox" ? v !== !!was : String(v) !== String(was)) out[k] = v;
  }
  return out;
}

async function renderSettings(main, screen) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const section = SETTINGS_SECTIONS.some(s => s[0] === q.get("section")) ? q.get("section") : "company";
  const tabs = el("div", { class: "tabs", id: "settings-tabs", role: "tablist" }, SETTINGS_SECTIONS.map(([id, label]) =>
    el("a", { href: "#/settings?section=" + id, role: "tab", "data-tab": id, class: id === section ? "active" : "",
              "aria-selected": id === section ? "true" : "false" }, label)));
  const body = el("div", { id: "settings-body" }, el("p", { class: "muted" }, "Loading…"));
  main.replaceChildren(el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("settings")), tabs, body);
  try {
    if (section === "audit") { await settingsAudit(body); return; }
    if (section === "tours") { await settingsTours(body); return; }
    const s = await api("GET", "/settings");
    const draw = { company: settingsCompany, money: settingsMoney, bids: settingsBids, approvals: settingsApprovals,
                   ai: settingsAi, people: settingsPeople, data: settingsData }[section];
    body.replaceChildren(...draw(s));
  } catch (e) { if (e.status !== 401) body.replaceChildren(errorBox(e)); }
}

function settingsCompany(s) {
  const p = s.company_profile;
  const inputs = { name: textInput("set-name", p.name, { required: true }), address: textInput("set-address", p.address),
                   phone: textInput("set-phone", p.phone), license_no: textInput("set-license", p.license_no),
                   logo_path: textInput("set-logo", p.logo_path, { placeholder: "C:\\Users\\you\\Pictures\\logo.png" }) };
  return [settingsForm("set-company", "company_profile", "Company profile", [field("Company name", inputs.name),
      field("Address", inputs.address), field("Phone", inputs.phone), field("License number", inputs.license_no),
      field("Logo file", inputs.logo_path, "The full path of a PNG or JPG on this PC; it goes on your bids.")],
    () => changed(inputs, p), "Shown at the top of every bid."),
    el("p", { class: "muted small" }, "Setup: " + s.setup.done + " of " + s.setup.total + " steps done.")];
}

function settingsMoney(s) {
  const t = s.tax, m = s.markups;
  const tax = { tax_pct: textInput("set-tax", t.tax_pct, { inputmode: "decimal" }),
                tax_base: el("select", { id: "set-tax-base" }, ["cost", "price"].map(v => el("option", { value: v, selected: v === t.tax_base }, "on " + v))) };
  const kinds = s.kinds.map(k => el("input", { type: "checkbox", value: k, checked: t.taxable_kinds.includes(k), "data-kind": k }));
  const taxForm = settingsForm("set-taxes", "tax", "Sales tax", [field("Tax rate (%)", tax.tax_pct), field("Figured", tax.tax_base),
      el("div", { class: "field" }, "Taxed", el("div", { class: "row", id: "set-tax-kinds" },
        kinds.map(c => el("label", { class: "check" }, c, " " + words(c.value)))))],
    () => {
      const out = changed(tax, t);
      const picked = kinds.filter(c => c.checked).map(c => c.value);
      if (picked.join(",") !== t.taxable_kinds.join(",")) out.taxable_kinds = picked;
      return out;
    });
  const mk = { overhead_pct: textInput("set-overhead", m.overhead_pct, { inputmode: "decimal" }),
               profit_pct: textInput("set-profit", m.profit_pct, { inputmode: "decimal" }),
               labor_burden_pct: textInput("set-burden", m.labor_burden_pct, { inputmode: "decimal" }),
               minimum_charge: textInput("set-minimum", m.minimum_charge_cents === null ? "" : dollars(m.minimum_charge_cents), { inputmode: "decimal" }),
               round_to_cents: el("select", { id: "set-round" }, [["", "don't round"], ["100", "whole dollars"], ["500", "$5"], ["1000", "$10"],
                 ["25", "25 cents"], ["50", "50 cents"]].map(([v, l]) => el("option", { value: v, selected: String(m.round_to_cents || "") === v }, l))) };
  const cur = { ...m, minimum_charge: m.minimum_charge_cents === null ? "" : dollars(m.minimum_charge_cents),
                round_to_cents: m.round_to_cents || "" };
  const mkForm = settingsForm("set-markups", "markups", "Overhead, profit and minimum charge", [field("Overhead (%)", mk.overhead_pct),
      field("Profit (%)", mk.profit_pct), field("Labor burden (%)", mk.labor_burden_pct, "Payroll taxes and insurance on labor"),
      field("Minimum charge ($)", mk.minimum_charge, "Blank: none"), field("Round totals to", mk.round_to_cents)],
    () => changed(mk, cur), "Applied to new and re-priced estimates; bids already made keep their numbers.");
  const rates = {};
  const labor = s.labor_rates.length ? el("table", { class: "list", id: "set-labor" }, el("tbody", {}, s.labor_rates.map(p => {
    rates[p.price_key] = textInput("rate-" + p.price_key, dollars(p.cost_cents), { inputmode: "decimal", class: "cost", "data-key": p.price_key });
    return el("tr", {}, el("td", {}, p.description, el("div", { class: "muted small" }, p.price_key)), el("td", {}, "$", rates[p.price_key]),
      el("td", {}, "per " + p.unit), el("td", {}, p.sample ? el("span", { class: "status sample" }, "sample") : "yours"));
  }))) : el("p", { class: "muted" }, "No labor prices yet.");
  const laborForm = settingsForm("set-rates", "labor_rates", "Labor rates", [labor], () => {
    const prices = {};
    for (const p of s.labor_rates) if (rates[p.price_key].value.trim() !== dollars(p.cost_cents)) prices[p.price_key] = rates[p.price_key].value.trim();
    return Object.keys(prices).length ? { prices } : {};
  }, "Your cost per hour for each kind of labor; every other price is in the Price Book.");
  return [taxForm, mkForm, laborForm, s.samples_in_use ? el("p", { class: "note warn" }, s.samples_in_use + " sample price(s) are still in use. ",
    el("a", { href: "#/price_book?samples=1" }, "Set your own in the Price Book")) : null];
}

function settingsBids(s) {
  const t = s.bid_template;
  const inputs = { valid_days: textInput("set-valid", t.valid_days, { inputmode: "numeric" }),
                   price_detail: el("select", { id: "set-detail" }, t.price_details.map(v => el("option", { value: v, selected: v === t.price_detail },
                     v === "lines" ? "every line priced" : "one price per trade"))),
                   terms: el("textarea", { id: "set-terms", rows: 4 }, t.terms),
                   inclusions: el("textarea", { id: "set-inclusions", rows: 3 }, (t.inclusions || []).join("\n")),
                   exclusions: el("textarea", { id: "set-exclusions", rows: 3 }, (t.exclusions || []).join("\n")) };
  const cur = { ...t, inclusions: (t.inclusions || []).join("\n"), exclusions: (t.exclusions || []).join("\n") };
  return [settingsForm("set-bids", "bid_template", "Bid template and terms", [field("Valid for (days)", inputs.valid_days),
      field("Prices shown", inputs.price_detail), field("Terms", inputs.terms, "{valid_until} becomes the quote's end date."),
      field("Always included (one per line)", inputs.inclusions), field("Never included (one per line)", inputs.exclusions)],
    () => changed(inputs, cur), "Used for every new bid; you can still change a single bid before sending it.")];
}

function settingsApprovals(s) {
  const a = s.approvals;
  const cur = { review_required_over: dollars(a.review_required_over_cents), quick_send_limit: dollars(a.quick_send_limit_cents),
                follow_up_days: a.follow_up_days, review_reminder_days: a.review_reminder_days, auto_expire_bids: a.auto_expire_bids };
  const inputs = { review_required_over: textInput("set-review-over", cur.review_required_over, { inputmode: "decimal" }),
                   quick_send_limit: textInput("set-quick-limit", cur.quick_send_limit, { inputmode: "decimal" }),
                   follow_up_days: textInput("set-follow-up", cur.follow_up_days, { inputmode: "numeric" }),
                   review_reminder_days: textInput("set-review-remind", cur.review_reminder_days, { inputmode: "numeric" }),
                   auto_expire_bids: el("input", { type: "checkbox", id: "set-expire", checked: !!cur.auto_expire_bids }) };
  return [settingsForm("set-approvals", "approvals", "Approval rules", [
      field("A reviewer signs off on estimates over ($)", inputs.review_required_over),
      field("Quick quotes up to this send with one tap ($)", inputs.quick_send_limit),
      field("Follow up on a sent quote after (days)", inputs.follow_up_days),
      field("Remind a reviewer after (days)", inputs.review_reminder_days),
      el("label", { class: "check" }, inputs.auto_expire_bids, " Mark quotes expired after their valid-until date")],
    () => {
      const out = changed(inputs, cur);
      for (const k of ["follow_up_days", "review_reminder_days"]) if (k in out) out[k] = Number(out[k]);
      return out;
    }, "Who may estimate, review, approve and send comes from their role (Users and roles).")];
}

function settingsAi(s) {
  const p = s.ai_privacy;
  const msg = el("div", { role: "status", id: "set-ai-message" });
  const btn = el("button", { class: p.crop_sending_enabled ? "button" : "primary", type: "button", id: "set-ai-toggle" },
    p.crop_sending_enabled ? "Turn symbol-crop sending off…" : "Turn symbol-crop sending on…");
  btn.addEventListener("click", () => askConfirm(msg, btn, "/settings/ai_privacy", { data: { crop_sending: !p.crop_sending_enabled } },
    () => { toast("AI and privacy saved."); route(); }, "set-ai"));
  return [el("div", { class: "card section", id: "set-ai" }, el("h3", {}, "AI and privacy"),
    el("p", {}, "Symbol-crop sending is ", el("strong", { id: "set-ai-state" }, p.crop_sending_enabled ? "on" : "off"), "."),
    el("p", { class: "muted" }, p.notice || ""),
    el("ul", { class: "small" }, el("li", {}, "A crop is at most " + Math.round(p.limits.crop_max_share_of_sheet * 100) + "% of a sheet and " + p.limits.crop_max_px + " px."),
      el("li", {}, "A whole sheet is sent " + p.limits.whole_sheet + "."),
      el("li", {}, p.sent_so_far + " image(s) sent so far" + (p.last_sent_at ? ", last " + when(p.last_sent_at) : "") + ".")),
    el("div", { class: "row" }, btn), msg)];
}

function settingsPeople(s) {
  const perms = ["create_estimate", "edit_estimate", "see_margins", "edit_margins", "approve", "send_bids", "settings"];
  return [el("div", { class: "card section", id: "set-people" }, el("h3", {}, "Users and roles"), el("p", {}, s.roles_note),
    el("table", { class: "list", id: "set-roles" }, el("thead", {}, el("tr", {}, el("th", {}, "Role"), perms.map(p => el("th", {}, words(p))), el("th", {}, "Screens"))),
      el("tbody", {}, s.roles.map(r => el("tr", { "data-role": r.role }, el("td", {}, words(r.role)),
        perms.map(p => el("td", {}, r[p] ? "✓" : "—")), el("td", { class: "small" }, r.screens.join(", ")))))),
    el("p", { class: "muted small" }, s.mode === "server" ? "Add people and change roles in AI-Prowler's Admin (Users, Manage Scopes)." :
      "On a single PC you sign in as the owner. Turn on Server mode in AI-Prowler to add your team."))];
}

function settingsData(s) {
  const msg = el("div", { role: "status", id: "set-backup-message" });
  const btn = el("button", { class: "primary", type: "button", id: "set-backup" }, "💾 Back up now…");
  btn.addEventListener("click", () => askConfirm(msg, btn, "/settings/backup", {}, r => { toast("Backed up: " + r.file); route(); }, "set-backup"));
  return [el("div", { class: "card section", id: "set-data" }, el("h3", {}, "Data folder"),
      el("p", {}, el("code", { id: "set-folder" }, s.data_folder)),
      el("p", { class: "muted small" }, "Plans, bids, exports and backups are kept here. To move it, use the Estimator tab on this PC (Data folder).")),
    el("div", { class: "card section", id: "set-backups" }, el("h3", {}, "Backups"),
      el("p", {}, s.backup_count + " backup(s) kept (the newest 30)."),
      s.backups.length ? el("ul", { class: "small" }, s.backups.map(b => el("li", {}, b.file + " · " + mb(b.size)))) : null,
      el("div", { class: "row" }, btn), msg,
      el("p", { class: "muted small" }, "Restoring a backup is done on this PC, in the Estimator tab, so nothing is replaced from a phone."))];
}

async function settingsAudit(body) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const action = q.get("action") || "";
  const r = await api("GET", "/settings/audit?limit=200" + (action ? "&action=" + encodeURIComponent(action) : ""));
  const pick = el("select", { id: "audit-action", "aria-label": "What" }, el("option", { value: "" }, "everything"),
    r.actions.map(a => el("option", { value: a, selected: a === action }, words(a))));
  pick.addEventListener("change", () => { location.hash = "#/settings?section=audit" + (pick.value ? "&action=" + pick.value : ""); });
  body.replaceChildren(el("div", { class: "row filters" }, el("label", {}, "Show", pick)),
    r.events.length ? el("table", { class: "list", id: "audit" }, el("thead", {}, el("tr", {}, ["When", "Who", "What", "Project", "Detail"].map(h => el("th", {}, h)))),
      el("tbody", {}, r.events.map(e => el("tr", { "data-id": e.id }, el("td", {}, when(e.at)),
        el("td", {}, e.actor + (e.on_behalf_of ? " for " + e.on_behalf_of : "")), el("td", {}, words(e.action)),
        el("td", {}, e.estimate_id ? el("a", { href: "#/projects/" + e.estimate_id }, e.estimate_title || "#" + e.estimate_id) : ""),
        el("td", { class: "small muted" }, e.detail || ""))))) : el("p", { class: "muted" }, "Nothing logged yet."),
    el("p", { class: "muted small" }, "The newest 200. Every change by a person or an agent is logged and can't be edited."));
}

// Guided tours (2026-11-12, David): once you know the Estimator, the tour that pops up on each screen's first open
// gets in the way. This is for the person signed in only; tours can still be replayed from Help.
async function settingsTours(body) {
  const r = await api("GET", "/help/tours/auto");
  const box = el("input", { type: "checkbox", id: "set-tours-auto", checked: r.enabled });
  const msg = el("div", { role: "status", id: "set-tours-message" });
  box.addEventListener("change", async () => {
    box.disabled = true;
    try {
      if (typeof setToursAuto === "function") await setToursAuto(box.checked);
      else await api("POST", "/help/tours/auto", { enabled: box.checked });
      toast(box.checked ? "Guided tours are on." : "Guided tours are off.");
      msg.replaceChildren();
    } catch (e) { box.checked = !box.checked; if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
    finally { box.disabled = false; }
  });
  body.replaceChildren(el("div", { class: "card section", id: "set-tours" }, el("h3", {}, "Guided tours"),
    el("label", { class: "check" }, box, " Show the guided tour the first time I open each screen"),
    el("p", { class: "muted small" }, "Turn this off once you know your way around. You can still replay any tour from " +
      "Help (or the Help button on each screen). This setting is just for you."), msg));
}

SCREENS.settings = renderSettings;
