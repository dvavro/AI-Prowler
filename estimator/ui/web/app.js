/* AI-Prowler Estimator web app (Coder 2: Sprint 1 shell, Sprint 2 screens).
 *
 * Plain JavaScript, no libraries (spec: self-contained, works offline).
 * - Every call goes to /estimator-api with the X-Estimator-Request header on writes.
 * - 401 shows the sign-in form; same-PC Personal mode opens straight in.
 * - The left menu comes from the server (/me), already filtered by role. Buttons are hidden with the
 *   permissions from /me, but the server checks every call itself.
 * - Live updates: server-sent events, falling back to polling /updates.
 * - All text goes in as text nodes (never parsed as HTML), so names from users or plans can't inject script.
 *
 * Routes:  #/dashboard  #/projects  #/projects/<id> (project page)  #/quick  #/quick/<estimate id>
 */
"use strict";

const API = "/estimator-api";
const MAX_PLAN_BYTES = 300 * 1024 * 1024;
const PLAN_TYPES = [".pdf", ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".dxf", ".dwg"];
const STATUSES = ["draft", "in_review", "approved", "sent", "won", "lost", "expired", "archived"];
const state = { me: null, screen: "dashboard", page: null, pageArg: null, cursor: null, es: null, pollTimer: null,
                busy: false };

// ------------------------------------------------------------------ helpers
function $(id) { return document.getElementById(id); }

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : String(v));
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined || k === false) continue;
    n.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return n;
}

function money(cents) {
  const n = Number(cents || 0) / 100;
  return n.toLocaleString(undefined, { style: "currency", currency: "USD" });
}

function when(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

function words(s) { return String(s || "").replace(/_/g, " "); }

function mb(bytes) { return (Number(bytes || 0) / (1024 * 1024)).toFixed(1) + " MB"; }

let toastTimer = null;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 5000);
}

class ApiError extends Error {
  constructor(status, body) { super((body && body.message) || ("HTTP " + status)); this.status = status; this.body = body; }
}

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") {
    opts.headers["X-Estimator-Request"] = "1";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body || {});
  }
  const r = await fetch(API + path, opts);
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  if (r.status === 401) { showLogin(data && data.message); throw new ApiError(401, data); }
  if (!r.ok || (data && data.ok === false)) throw new ApiError(r.status, data);
  return data;
}

function can(perm) { return !!(state.me && state.me.permissions && state.me.permissions[perm]); }

function go(hash) { if (location.hash === hash) route(); else location.hash = hash; }

function errorBox(e) { return el("p", { class: "error", role: "alert" }, e.message); }

// ------------------------------------------------------------------ sign in / out
function showLogin(msg) {
  stopLive();
  $("app").hidden = true;
  $("login").hidden = false;
  if (msg) $("login-hint").textContent = msg;
  $("login-user").focus();
}

async function doLogin(ev) {
  ev.preventDefault();
  const btn = $("login-btn"), err = $("login-error");
  btn.disabled = true; err.hidden = true;
  try {
    const r = await api("POST", "/auth/login", { username: $("login-user").value, password: $("login-pass").value });
    $("login-pass").value = "";
    start(r.me);
  } catch (e) {
    err.textContent = e.message; err.hidden = false;
  } finally { btn.disabled = false; }
}

async function doLogout() {
  try { await api("POST", "/auth/logout"); } catch (e) { /* signed out either way */ }
  state.me = null;
  showLogin("You're signed out.");
}

// ------------------------------------------------------------------ shell
function start(me) {
  state.me = me;
  $("login").hidden = true;
  $("app").hidden = false;
  $("user").textContent = me.name + " · " + me.role + (me.mode === "server" ? "" : " · Personal");
  $("logout").hidden = !me.can_sign_out;
  buildNav();
  route();
  startLive();
}

function buildNav() {
  const nav = $("nav");
  nav.replaceChildren();
  for (const s of state.me.menu) {
    nav.append(el("a", { href: "#/" + s.id, "data-screen": s.id, class: s.status === "ready" ? "" : "coming",
                         title: s.status === "ready" ? s.label : s.label + " (coming in Sprint " + s.sprint + ")" },
      el("span", { "aria-hidden": "true" }, s.icon), s.label));
  }
}

function parseHash() {
  const parts = location.hash.replace(/^#\/?/, "").split("?")[0].split("/").filter(Boolean);
  if (parts[0] === "projects" && /^\d+$/.test(parts[1] || "")) return { screen: "projects", page: "project", arg: +parts[1] };
  if (parts[0] === "quick") return { screen: "dashboard", page: "quick", arg: /^\d+$/.test(parts[1] || "") ? +parts[1] : null };
  return { screen: parts[0] || "dashboard", page: null, arg: null };
}

function route() {
  if (!state.me) return;
  const want = parseHash();
  const screen = state.me.menu.find(s => s.id === want.screen) || state.me.menu[0];
  state.screen = screen.id;
  state.page = want.page && PAGES[want.page] ? want.page : null;
  state.pageArg = want.arg;
  for (const a of $("nav").querySelectorAll("a")) a.classList.toggle("active", a.dataset.screen === screen.id);
  $("nav").classList.remove("open");
  const main = $("main");
  main.replaceChildren(el("p", { class: "muted" }, "Loading…"));
  const render = state.page ? (m => PAGES[state.page](m, state.pageArg)) : (SCREENS[screen.id] || renderComing);
  Promise.resolve(render(main, screen)).catch(e => {
    if (e.status === 401) return;
    main.replaceChildren(el("h2", {}, state.page ? "Estimator" : screen.label), errorBox(e),
      el("p", {}, el("a", { href: "#/dashboard" }, "Back to the dashboard")));
  });
  main.focus();
}

// ------------------------------------------------------------------ Dashboard
async function renderDashboard(main, screen) {
  const d = await api("GET", "/dashboard");
  const head = el("div", { class: "page-head" }, el("h2", {}, screen.label),
    d.can_quick ? el("a", { class: "primary button", href: "#/quick", id: "dash-quick" }, "⚡ Quick estimate") : null);
  const tiles = el("div", { class: "tiles" },
    el("div", { class: "card tile" }, el("div", { class: "num" }, d.total), el("div", { class: "lbl" }, "estimates")),
    ...Object.entries(d.counts).map(([k, v]) =>
      el("a", { class: "card tile", href: "#/projects?status=" + k },
        el("div", { class: "num" }, v), el("div", { class: "lbl" }, words(k)))));
  const parts = [head, tiles];

  const attention = [];
  for (const e of d.attention || []) {
    attention.push(el("li", {}, el("a", { href: "#/projects/" + e.id }, e.title || "Estimate " + e.id), " — waiting for review"));
  }
  const mine = d.my_work;
  if (mine) {
    for (const e of mine.estimates) {
      attention.push(el("li", {}, el("a", { href: "#/projects/" + e.id }, e.title || "Estimate " + e.id),
        " — assigned to you" + (e.due_date ? ", due " + e.due_date : "")));
    }
    for (const n of mine.notices) {
      attention.push(el("li", {}, n.estimate_id ? el("a", { href: "#/projects/" + n.estimate_id }, n.message) : n.message));
    }
  }
  parts.push(el("div", { class: "card section", id: "attention" }, el("strong", {}, "Needs attention"),
    attention.length ? el("ul", { class: "checklist" }, attention) : el("p", { class: "muted" }, "Nothing waiting on you.")));

  if (d.setup && Array.isArray(d.setup.steps)) {
    const todo = d.setup.steps.filter(s => s.status !== "done");
    if (todo.length) {
      parts.push(el("div", { class: "card section" },
        el("strong", {}, "Setup checklist"),
        el("p", { class: "muted" }, "Finish setup in the 🏗 Estimator tab of AI-Prowler."),
        el("ul", { class: "checklist" }, todo.map(s => el("li", {}, (s.label || s.step) + " — " + words(s.status))))));
    }
  }
  parts.push(el("h3", {}, "Recent"), estimateTable(d.recent));
  main.replaceChildren(...parts);
}

// ------------------------------------------------------------------ Projects
async function renderProjects(main, screen) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const status = STATUSES.includes(q.get("status")) ? q.get("status") : "";
  const list = await api("GET", "/estimates?limit=500" + (status ? "&status=" + status : ""));
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label),
    can("quick_estimate") ? el("a", { class: "button", href: "#/quick" }, "⚡ Quick estimate") : null)];

  if (can("create_estimate")) {
    const title = el("input", { id: "new-title", placeholder: "e.g. Miller – 123 Main St", maxlength: 200, required: true });
    const addr = el("input", { id: "new-address", placeholder: "Job address", maxlength: 500 });
    const due = el("input", { id: "new-due", type: "date" });
    const btn = el("button", { class: "primary", type: "submit", id: "new-create" }, "Create project");
    const form = el("form", { class: "card section", id: "new-project" },
      el("strong", {}, "New project"),
      el("div", { class: "row" }, el("label", {}, "Name", title), el("label", {}, "Address", addr),
         el("label", {}, "Due date", due), btn));
    form.addEventListener("submit", async ev => {
      ev.preventDefault();
      btn.disabled = true;
      try {
        const est = await api("POST", "/estimates", { title: title.value, address: addr.value, due_date: due.value });
        toast("Created " + est.title);
        go("#/projects/" + est.id);
      } catch (e) { if (e.status !== 401) toast(e.message); }
      finally { btn.disabled = false; }
    });
    parts.push(form);
  }

  const pick = el("select", { id: "filter-status", "aria-label": "Status" },
    el("option", { value: "" }, "All statuses"),
    STATUSES.map(s => el("option", { value: s, selected: s === status }, words(s))));
  pick.addEventListener("change", () => { location.hash = "#/projects" + (pick.value ? "?status=" + pick.value : ""); });
  const find = el("input", { id: "filter-text", type: "search", placeholder: "Filter by name or #", "aria-label": "Filter" });
  const table = estimateTable(list.estimates);
  find.addEventListener("input", () => {
    const t = find.value.trim().toLowerCase();
    for (const tr of table.querySelectorAll("tbody tr")) {
      tr.hidden = !!t && !tr.textContent.toLowerCase().includes(t);
    }
  });
  parts.push(el("div", { class: "row filters" }, el("label", {}, "Status", pick), el("label", {}, "Find", find)), table);
  main.replaceChildren(...parts);
}

function estimateTable(rows) {
  if (!rows || !rows.length) return el("div", { class: "card empty" }, "No projects yet — create one to start.");
  const see = can("see_margins");
  return el("table", { class: "list clickable" },
    el("thead", {}, el("tr", {}, el("th", {}, "#"), el("th", {}, "Project"), el("th", {}, "Status"),
      el("th", {}, "Total"), el("th", {}, "Updated"))),
    el("tbody", {}, rows.map(r => el("tr", { "data-id": r.id, onclick: () => go("#/projects/" + r.id) },
      el("td", {}, r.id),
      el("td", {}, el("a", { href: "#/projects/" + r.id }, r.title || "(untitled)"), r.practice ? " 🎓" : ""),
      el("td", {}, el("span", { class: "status" }, words(r.status))),
      el("td", { class: "money" }, r.total_cents === undefined && !see ? "—" : money(r.total_cents)),
      el("td", {}, when(r.updated_at))))));
}

// ------------------------------------------------------------------ Project page (Sprint 2)
async function renderProject(main, id) {
  const p = await api("GET", "/estimates/" + id + "/project");
  const est = p.estimate, st = p.status;
  const parts = [
    el("p", {}, el("a", { href: "#/projects" }, "← Projects")),
    el("div", { class: "page-head" }, el("h2", {}, est.title || "Estimate " + est.id),
      el("span", { class: "status big" }, words(est.status))),
  ];
  if (est.practice) parts.push(el("p", { class: "note" }, "🎓 Practice project — not a real job."));
  if (est.editing_warning) parts.push(el("p", { class: "note warn" }, est.editing_warning));
  parts.push(el("div", { class: "tiles" },
    tile(money(st.estimate.total_cents), "total"),
    tile(st.trades.length, "trades"),
    tile(p.plan_sets.length, "plan sets"),
    tile(est.due_date || "—", "due"),
    est.address ? tile(est.address, "address", "wide") : null));

  // Trades: per-trade subtotal and headline quantities (est_project_status)
  const trades = st.trades.length
    ? el("table", { class: "list", id: "trades" },
        el("thead", {}, el("tr", {}, el("th", {}, "Trade"), el("th", {}, "Biggest lines"), el("th", {}, "Subtotal"))),
        el("tbody", {}, st.trades.map(t => el("tr", {},
          el("td", {}, t.name), el("td", {}, el("ul", { class: "plain" }, t.headline.map(h => el("li", {}, h)))),
          el("td", { class: "money" }, money(t.subtotal_cents))))))
    : el("div", { class: "card empty" }, "No trades priced yet.");
  const tradeHead = el("div", { class: "page-head" }, el("h3", {}, "Trades"),
    p.can_quick && p.editable ? el("a", { class: "button", href: "#/quick/" + est.id, id: "add-quick" }, "⚡ Add a quick estimate") : null);
  parts.push(tradeHead, trades);
  if (st.summary) parts.push(el("p", { class: "muted" }, st.summary));
  if (st.run) {
    parts.push(el("h3", {}, "Takeoff run"), el("table", { class: "list" },
      el("thead", {}, el("tr", {}, el("th", {}, "Trade"), el("th", {}, "State"), el("th", {}, "Next"))),
      el("tbody", {}, st.run.tasks.map(t => el("tr", {}, el("td", {}, t.module_id),
        el("td", {}, el("span", { class: "status" }, words(t.state))), el("td", {}, t.next || ""))))));
  }
  if (st.job) parts.push(el("p", { class: "muted" }, "Director: " + words(st.job.lane) + " lane, " + words(st.job.stage) +
    (st.job.waiting_on ? " — waiting on " + st.job.waiting_on : "")));

  // Plans: list + upload (Documents)
  parts.push(el("h3", {}, "Plans and documents"), planTable(p.plan_sets));
  if (p.can_upload) parts.push(uploadBox(est.id, p.plan_sets));

  // History
  const hist = el("details", { class: "card section", id: "history" }, el("summary", {}, "History"));
  hist.addEventListener("toggle", async () => {
    if (!hist.open || hist.dataset.loaded) return;
    hist.dataset.loaded = "1";
    try {
      const ev = await api("GET", "/estimates/" + est.id + "/events");
      hist.append(el("ul", { class: "plain" }, ev.events.slice().reverse().map(e =>
        el("li", {}, when(e.at) + " — " + words(e.action || "change") + " by " + (e.actor || "?") +
          (e.on_behalf_of ? " for " + e.on_behalf_of : "")))));
    } catch (e) { hist.append(errorBox(e)); }
  });
  parts.push(hist);
  main.replaceChildren(...parts);
}

function tile(value, label, cls) {
  return el("div", { class: "card tile" + (cls ? " " + cls : "") }, el("div", { class: "num" }, value),
    el("div", { class: "lbl" }, label));
}

function planTable(rows) {
  if (!rows.length) return el("div", { class: "card empty", id: "plans-empty" }, "No plans yet — upload a PDF, DXF or photo to start.");
  return el("table", { class: "list", id: "plans" },
    el("thead", {}, el("tr", {}, el("th", {}, "#"), el("th", {}, "File"), el("th", {}, "Type"), el("th", {}, "Rev"),
      el("th", {}, "Status"), el("th", {}, "Sheets"), el("th", {}, "Uploaded"))),
    el("tbody", {}, rows.map(r => el("tr", {},
      el("td", {}, r.id),
      el("td", {}, r.file, r.warnings && r.warnings.length ? el("div", { class: "muted small" }, "⚠ " + r.warnings.join(" · ")) : null),
      el("td", {}, String(r.file_type || "").toUpperCase()),
      el("td", {}, r.revision),
      el("td", {}, el("span", { class: "status" }, words(r.status)), r.error ? el("div", { class: "error small" }, r.error) : null),
      el("td", {}, r.sheets || "—"),
      el("td", {}, when(r.created_at) + " · " + (r.uploaded_by || ""))))));
}

function uploadBox(estimateId, planSets) {
  const file = el("input", { type: "file", id: "plan-file", accept: PLAN_TYPES.join(",") });
  const replaces = el("select", { id: "plan-replaces", "aria-label": "Replaces" },
    el("option", { value: "" }, "New plan set"),
    planSets.map(ps => el("option", { value: ps.id }, "Revised set — replaces #" + ps.id + " " + ps.file)));
  const send = el("button", { class: "primary", type: "submit", id: "plan-upload" }, "Upload and check");
  const bar = el("progress", { id: "plan-progress", max: 100, value: 0, hidden: true });
  const msg = el("div", { id: "plan-message", role: "status" });
  const box = el("form", { class: "card section", id: "upload-box" },
    el("strong", {}, "Upload plans"),
    el("p", { class: "muted" }, "PDF, PNG, JPG, TIFF, DXF or DWG, up to 300 MB. The file is checked first; nothing is attached until you say so."),
    el("div", { class: "row" }, el("label", {}, "File", file), planSets.length ? el("label", {}, "This is", replaces) : null, send),
    bar, msg);
  box.addEventListener("submit", async ev => {
    ev.preventDefault();
    const f = file.files && file.files[0];
    msg.replaceChildren();
    if (!f) { msg.append(el("p", { class: "error" }, "Choose a file first.")); return; }
    const ext = (f.name.match(/\.[^.]+$/) || [""])[0].toLowerCase();
    if (!PLAN_TYPES.includes(ext)) { msg.append(el("p", { class: "error" }, (ext || "That file") + " can't be used; plans can be PDF, PNG, JPG, TIFF, DXF or DWG.")); return; }
    if (f.size > MAX_PLAN_BYTES) { msg.append(el("p", { class: "error" }, f.name + " is " + mb(f.size) + "; the limit is 300 MB.")); return; }
    if (!f.size) { msg.append(el("p", { class: "error" }, f.name + " is empty.")); return; }
    send.disabled = true; bar.hidden = false; bar.value = 0;
    state.busy = true;
    try {
      const staged = await uploadRaw(estimateId, f, replaces.value, pct => { bar.value = pct; });
      showConfirm(msg, estimateId, staged, replaces.value, () => { send.disabled = false; });
    } catch (e) {
      if (e.status !== 401) msg.append(errorBox(e));
      send.disabled = false;
      state.busy = false;
    } finally { bar.hidden = true; }
  });
  return box;
}

function uploadRaw(estimateId, f, replaces, onProgress) {
  // XMLHttpRequest (not fetch) so a big plan set shows upload progress. The file goes as the raw body.
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    const qs = "?name=" + encodeURIComponent(f.name) + (replaces ? "&supersedes=" + encodeURIComponent(replaces) : "");
    x.open("POST", API + "/estimates/" + estimateId + "/plans/stage" + qs);
    x.withCredentials = true;
    x.setRequestHeader("X-Estimator-Request", "1");
    x.setRequestHeader("Content-Type", "application/octet-stream");
    x.upload.onprogress = ev => { if (ev.lengthComputable) onProgress(Math.round(ev.loaded * 100 / ev.total)); };
    x.onload = () => {
      let data = null;
      try { data = JSON.parse(x.responseText); } catch (e) { data = null; }
      if (x.status === 401) { showLogin(data && data.message); reject(new ApiError(401, data)); return; }
      if (x.status >= 400 || !data || data.ok === false) { reject(new ApiError(x.status, data)); return; }
      resolve(data);
    };
    x.onerror = () => reject(new ApiError(0, { message: "the upload didn't reach the Estimator; check the connection and try again" }));
    x.send(f);
  });
}

function showConfirm(msg, estimateId, staged, replaces, done) {
  const d = staged.details || {};
  const yes = el("button", { class: "primary", type: "button", id: "plan-attach" }, "Attach");
  const no = el("button", { class: "button", type: "button", id: "plan-cancel" }, "Cancel");
  const finish = () => { state.busy = false; done(); };
  yes.addEventListener("click", async () => {
    yes.disabled = no.disabled = true;
    try {
      const r = await api("POST", "/estimates/" + estimateId + "/plans/attach",
        { stage_id: staged.stage_id, supersedes_plan_set_id: replaces || null });
      finish();
      toast("Attached " + r.file + " as plan set " + r.plan_set_id);
      route();
    } catch (e) {
      finish();
      if (e.status !== 401) msg.replaceChildren(errorBox(e));
    }
  });
  no.addEventListener("click", async () => {
    yes.disabled = no.disabled = true;
    try { await api("DELETE", "/estimates/" + estimateId + "/plans/stage/" + staged.stage_id); } catch (e) { /* expires anyway */ }
    finish();
    msg.replaceChildren(el("p", { class: "muted" }, "Cancelled — nothing was attached."));
  });
  msg.replaceChildren(el("div", { class: "confirm", id: "plan-confirm" },
    el("p", {}, el("strong", {}, staged.question)),
    (d.warnings && d.warnings.length) ? el("ul", { class: "warn" }, d.warnings.map(w => el("li", {}, "⚠ " + w))) : null,
    el("div", { class: "row" }, yes, no)));
  yes.focus();
}

// ------------------------------------------------------------------ Quick estimate (Sprint 2)
async function renderQuick(main, estimateId) {
  const mods = await api("GET", "/modules?path=quick");
  let est = null;
  if (estimateId) est = (await api("GET", "/estimates/" + estimateId + "/project")).estimate;
  const parts = [el("p", {}, est ? el("a", { href: "#/projects/" + est.id }, "← " + (est.title || "Estimate " + est.id))
                                : el("a", { href: "#/dashboard" }, "← Dashboard")),
                 el("h2", {}, "⚡ Quick estimate" + (est ? " for " + (est.title || "estimate " + est.id) : ""))];
  if (!can("quick_estimate")) {
    main.replaceChildren(...parts, el("p", { class: "error" }, "Your role can't give quick quotes."));
    return;
  }
  const services = mods.modules.filter(m => m.category === "service");
  const others = mods.modules.filter(m => m.category !== "service");
  const pick = el("select", { id: "quick-module", "aria-label": "Service" },
    el("option", { value: "" }, "Choose a service…"),
    services.length ? el("optgroup", { label: "Services" }, services.map(m => el("option", { value: m.id }, m.name))) : null,
    others.length ? el("optgroup", { label: "Trades" }, others.map(m => el("option", { value: m.id }, m.name))) : null);
  const form = el("form", { class: "card section", id: "quick-form" });
  const result = el("div", { id: "quick-result" });
  parts.push(el("div", { class: "card section" }, el("label", {}, "What's the job?", pick)), form, result);
  main.replaceChildren(...parts);

  pick.addEventListener("change", async () => {
    form.replaceChildren(); result.replaceChildren();
    if (!pick.value) return;
    try {
      const q = await api("GET", "/modules/" + encodeURIComponent(pick.value) + "/questions");
      buildQuickForm(form, result, q, est);
    } catch (e) { if (e.status !== 401) form.replaceChildren(errorBox(e)); }
  });
  const want = new URLSearchParams(location.hash.split("?")[1] || "").get("module");
  if (want && mods.modules.some(m => m.id === want)) { pick.value = want; pick.dispatchEvent(new Event("change")); }
}

function questionInput(q) {
  const id = "q-" + q.id;
  if (q.type === "boolean") {
    return el("label", { class: "check" }, el("input", { type: "checkbox", id, "data-q": q.id, checked: q.default === true }),
      " " + q.label);
  }
  let input;
  if (q.type === "choice") {
    input = el("select", { id, "data-q": q.id, required: q.required },
      q.required && (q.default === null || q.default === undefined) ? el("option", { value: "" }, "Choose…") : null,
      (q.choices || []).map(c => el("option", { value: c.value, selected: String(q.default) === String(c.value) }, c.label)));
  } else {
    input = el("input", { id, "data-q": q.id, type: "number", inputmode: "decimal", required: q.required,
      step: q.type === "integer" ? "1" : "any", min: q.min, max: q.max,
      value: q.default === null || q.default === undefined ? null : q.default });
  }
  return el("label", {}, q.label + (q.unit ? " (" + q.unit + ")" : "") + (q.required ? " *" : ""), input,
    q.help ? el("span", { class: "muted small" }, q.help) : null);
}

function buildQuickForm(form, result, q, est) {
  const fields = q.questions.map(questionInput);
  const extras = [];
  let title = null, addr = null;
  if (!est) {
    title = el("input", { id: "quick-title", maxlength: 200, placeholder: q.module.name + " – customer or address" });
    addr = el("input", { id: "quick-address", maxlength: 500, placeholder: "Job address" });
    extras.push(el("div", { class: "row" }, el("label", {}, "Project name (optional)", title), el("label", {}, "Address", addr)));
  }
  const btn = el("button", { class: "primary", type: "submit", id: "quick-price" }, "Price it");
  form.replaceChildren(el("strong", {}, q.module.name), q.module.description ? el("p", { class: "muted" }, q.module.description) : null,
    el("div", { class: "qgrid" }, fields), ...extras, btn);
  form.onsubmit = async ev => {
    ev.preventDefault();
    const answers = {};
    for (const i of form.querySelectorAll("[data-q]")) {
      if (i.type === "checkbox") answers[i.dataset.q] = i.checked;
      else if (i.value !== "") answers[i.dataset.q] = i.tagName === "SELECT" ? i.value : Number(i.value);
    }
    const body = { module_id: q.module.id, answers };
    if (est) { body.estimate_id = est.id; body.rev = est.rev; }
    else { body.title = title.value; body.address = addr.value; }
    btn.disabled = true;
    result.replaceChildren();
    try {
      const r = await api("POST", "/quick", body);
      if (est) est.rev = r.rev;                        // a second "Price it" uses the new rev
      showQuickResult(result, r, q.module);
    } catch (e) {
      if (e.status === 401) return;
      const extra = e.body && e.body.missing ? " (" + e.body.missing.join(", ") + ")" : "";
      result.replaceChildren(el("p", { class: "error", role: "alert" }, e.message + extra));
    } finally { btn.disabled = false; }
  };
}

function showQuickResult(box, r, mod) {
  const section = (r.sections || []).find(s => s.module_id === mod.id);
  const lines = section ? section.lines : [];
  const total = r.totals ? r.totals.total_cents : 0;
  box.replaceChildren(el("div", { class: "card section result", id: "quick-total" },
    el("div", { class: "big-money" }, money(total)),
    el("p", { class: "muted" }, (r.created ? "New project " : "Updated ") + "#" + r.id + " · " + (r.title || "")),
    (r.warnings || []).map(w => el("p", { class: "note warn" }, "⚠ " + w)),
    lines.length ? el("table", { class: "list" },
      el("thead", {}, el("tr", {}, el("th", {}, "Item"), el("th", {}, "Qty"), el("th", {}, "Line total"))),
      el("tbody", {}, lines.map(l => el("tr", {}, el("td", {}, l.description), el("td", {}, l.quantity + " " + l.unit),
        el("td", { class: "money" }, money(l.total_cents)))))) : null,
    el("div", { class: "row" },
      el("a", { class: "primary button", href: "#/projects/" + r.id, id: "quick-open" }, "Open the project"),
      el("a", { class: "button", href: "#/quick" }, "Another quick estimate")),
    el("p", { class: "muted small" }, "To turn this into a quote and send it, ask your AI (bid_generate, bid_send) — the Bids screen comes in Sprint 4.")));
}

function renderComing(main, screen) {
  main.replaceChildren(el("div", { class: "coming-page" },
    el("h2", {}, screen.icon + " " + screen.label),
    el("p", {}, "This screen is coming in Sprint " + screen.sprint + "."),
    el("p", { class: "muted" }, "Until then you can do the same things by asking your AI (Claude, Grok or Muse) — it uses these Estimator tools:"),
    el("ul", {}, screen.tools.map(t => el("li", {}, el("code", {}, t))))));
}

const SCREENS = { dashboard: renderDashboard, projects: renderProjects };
const PAGES = { project: renderProject, quick: renderQuick };

// ------------------------------------------------------------------ live updates
function setLive(cls, title) { const l = $("live"); l.className = "live " + cls; l.title = title; }

let refreshTimer = null;
function onChange(ev) {
  state.cursor = ev.id;
  if (ev.actor && state.me && ev.actor !== state.me.user_id) {
    toast("Updated by " + ev.actor + (ev.estimate_id ? " (estimate " + ev.estimate_id + ")" : ""));
  }
  const listScreen = !state.page && (state.screen === "dashboard" || state.screen === "projects");
  const thisProject = state.page === "project" && ev.estimate_id === state.pageArg;
  if (!listScreen && !thisProject) return;              // never redraw the quick-estimate form under the user
  // One redraw for a burst of changes (e.g. an agent pricing many lines).
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    if (state.busy) return;                             // an upload is waiting for "Attach"
    const a = document.activeElement;                   // never wipe a form someone is typing in
    if (a && $("main").contains(a) && (a.tagName === "INPUT" || a.tagName === "SELECT")) return;
    route();
  }, 400);
}

function startLive() {
  stopLive();
  if (window.EventSource) {
    const es = new EventSource(API + "/events");
    state.es = es;
    es.addEventListener("open", () => setLive("on", "Live updates on"));
    es.addEventListener("change", m => { try { onChange(JSON.parse(m.data)); } catch (e) { /* ignore bad event */ } });
    es.addEventListener("error", () => {
      setLive("retry", "Reconnecting…");
      if (es.readyState === EventSource.CLOSED) { state.es = null; startPolling(); }
    });
  } else {
    startPolling();
  }
}

async function startPolling() {
  setLive("on", "Live updates on (polling)");
  const tick = async () => {
    try {
      const u = await api("GET", "/updates" + (state.cursor === null ? "" : "?since=" + state.cursor));
      if (state.cursor !== null) u.events.forEach(onChange);
      state.cursor = u.cursor;
    } catch (e) { if (e.status === 401) return; setLive("retry", "Reconnecting…"); }
    state.pollTimer = setTimeout(tick, 5000);
  };
  tick();
}

function stopLive() {
  if (state.es) { state.es.close(); state.es = null; }
  clearTimeout(state.pollTimer);
  setLive("off", "Live updates off");
}

// ------------------------------------------------------------------ boot
async function boot() {
  $("login-form").addEventListener("submit", doLogin);
  $("logout").addEventListener("click", doLogout);
  $("menu-toggle").addEventListener("click", () => $("nav").classList.toggle("open"));
  window.addEventListener("hashchange", route);
  try {
    const r = await api("GET", "/me");
    start(r.me);
  } catch (e) {
    if (e.status !== 401) {
      document.body.replaceChildren(el("div", { class: "login" }, el("div", { class: "card login-card" },
        el("h1", {}, "🏗 AI-Prowler Estimator"), el("p", { class: "error" }, "Can't reach the Estimator: " + e.message))));
    }
  }
}

document.addEventListener("DOMContentLoaded", boot);
