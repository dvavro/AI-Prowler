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
 *          Sprint 4: #/jobs (Jobs board)  #/jobs/<id> (one job's next step)  #/bids  #/bids/<id>  #/help  #/help/<guide>
 * Sending a quote and making a job ask a yes/no question first (the server returns needs_confirmation).
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

// Sprint 3: inside AI-Prowler's own site (port 8000 / Remote Access) the Jobs app keeps its sign-in in
// localStorage "ap_auth" (same site, so this page can read it). Sending it as a Bearer token lets the
// Estimates tab open without a second sign-in. On the Estimator's own port there is no ap_auth.
const EMBEDDED = window.self !== window.top || new URLSearchParams(location.search).has("embed");
function appToken() {
  try {
    const s = JSON.parse(localStorage.getItem("ap_auth") || "null");
    if (!s) return "";
    return (s.mode === "server" ? s.access_token : s.token) || "";
  } catch (e) { return ""; }
}
let APP_TOKEN = appToken();

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (APP_TOKEN) opts.headers["Authorization"] = "Bearer " + APP_TOKEN;
  if (method !== "GET") {
    opts.headers["X-Estimator-Request"] = "1";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body || {});
  }
  const r = await fetch(API + path, opts);
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  if (r.status === 401) {
    // A Jobs app token that no longer works (signed out, idle timeout) must not hide the Estimator's own
    // sign-in cookie, so it's dropped and the sign-in form shows.
    APP_TOKEN = "";
    showLogin(data && data.message);
    throw new ApiError(401, data);
  }
  if (!r.ok || (data && data.ok === false)) throw new ApiError(r.status, data);
  return data;
}

// Sprint 13: a picture from the API. Inside the Jobs app the Estimator is signed in by that app's token (no cookie),
// and an <img src> can't send a token, so the picture is fetched with it and shown from a blob URL. Elsewhere the
// cookie or same-PC access is enough and src is set as usual. A failed load fires the img's "error" event.
function apiImage(img, url) {
  if (!APP_TOKEN) { img.src = url; return img; }
  fetch(url, { credentials: "same-origin", headers: { Authorization: "Bearer " + APP_TOKEN } })
    .then(r => (r.ok ? r.blob() : Promise.reject(new Error("HTTP " + r.status))))
    .then(b => {
      const u = URL.createObjectURL(b);
      img.addEventListener("load", () => URL.revokeObjectURL(u), { once: true });
      img.src = u;
    })
    .catch(() => img.dispatchEvent(new Event("error")));
  return img;
}

function can(perm) { return !!(state.me && state.me.permissions && state.me.permissions[perm]); }
function canOpen(screenId) { return !!(state.me && state.me.menu.some(s => s.id === screenId && s.status === "ready")); }

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
  if (parts[0] === "quick" && /^\d+$/.test(parts[1] || "")) return { screen: "quick", page: "quick", arg: +parts[1] };
  if (parts[0] === "quick") return { screen: "quick", page: null, arg: null };
  // 2026-11-12: the Director's "Start a new quote or estimate" (renderStart).
  if (parts[0] === "start") return { screen: "dashboard", page: "start", arg: null };
  // Sprint 4: Jobs board is a left-menu screen; a job page hangs off it, a bid page off Bids, a guide off Help.
  if (parts[0] === "jobs" && /^\d+$/.test(parts[1] || "")) return { screen: "jobs", page: "job", arg: +parts[1] };
  if (parts[0] === "jobs") return { screen: "jobs", page: null, arg: null };
  if (parts[0] === "bids" && /^\d+$/.test(parts[1] || "")) return { screen: "bids", page: "bid", arg: +parts[1] };
  if (parts[0] === "help" && /^[a-z0-9_]+$/.test(parts[1] || "")) return { screen: "help", page: "guide", arg: parts[1] };
  // Sprint 5: a plan set's sheets, and one sheet (viewports, scales, calibration).
  if (parts[0] === "plan-sets" && /^\d+$/.test(parts[1] || "")) return { screen: "plans", page: "plan_set", arg: +parts[1] };
  if (parts[0] === "sheets" && /^\d+$/.test(parts[1] || "")) return { screen: "plans", page: "sheet", arg: +parts[1] };
  // Sprint 7: Blueprint Review for one project (review.js); ?sheet=<id>&m=<measurement> open a sheet or measurement.
  if (parts[0] === "takeoffs" && /^\d+$/.test(parts[1] || "")) return { screen: "takeoffs", page: "takeoff", arg: +parts[1] };
  // Sprint 8: one estimate (estimates.js), linked to its measurements; ?line=<id> opens that line.
  if (parts[0] === "estimates" && /^\d+$/.test(parts[1] || "")) return { screen: "estimates", page: "estimate", arg: +parts[1] };
  // Sprint 11: one plan set's symbols to check (verify.js); ?type=&status=&sheet=&sort= filter the detection panel.
  if (parts[0] === "reviews" && /^\d+$/.test(parts[1] || "")) return { screen: "reviews", page: "symbol_review", arg: +parts[1] };
  // Sprint 12: one project's plan quantities (quantities.js); ?height=&proposed=1.
  if (parts[0] === "quantities" && /^\d+$/.test(parts[1] || "")) return { screen: "takeoffs", page: "quantities", arg: +parts[1] };
  // Sprint 13: reviews on a phone or tablet (mobile.js), from the Jobs app's Estimates tab; ?kind=&estimate=&i=.
  if (parts[0] === "m" && parts[1] === "reviews") return { screen: "reviews", page: "mobile_reviews", arg: null };
  // Sprint 17: one plan revision report drawn over the sheets (reports.js); ?sheet=<n>&old=1.
  if (parts[0] === "revisions" && /^\d+$/.test(parts[1] || "")) return { screen: "reports", page: "revision", arg: +parts[1] };
  // AI Log (from the Agents screen, verify.js): what the AI was sent and what it returned; ?auto_run_id=<id> shows one run's calls.
  if (parts[0] === "agents" && parts[1] === "ai-log") return { screen: "agents", page: "ai_log", arg: null };
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
  Promise.resolve(render(main, screen)).then(() => {
    // Sprint 18: a tour auto-starts on first open (tour.js). Guarded so a failed tour.js never breaks routing.
    if (typeof maybeStartTour === "function") { const p = maybeStartTour(); if (p && p.catch) p.catch(() => {}); }
  }).catch(e => {
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
    el("div", { class: "row" },
      d.can_quick ? el("a", { class: "primary button", href: "#/start", id: "dash-start" }, "🧭 AI Director Agent — get estimate started") : null,
      el("a", { class: "button", href: "#/jobs", id: "dash-jobs" }, "📋 Jobs board"),
      d.can_quick ? el("a", { class: "button", href: "#/quick", id: "dash-quick" }, "⚡ Quick estimate") : null,
      helpLink("dashboard")));
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
      // A notice about a Director job opens the job, where its Approve / Send buttons are (2026-11-12, David).
      const href = n.job_id ? "#/jobs/" + n.job_id : n.estimate_id ? "#/projects/" + n.estimate_id : null;
      attention.push(el("li", {}, href ? el("a", { href }, n.message) : n.message));
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
  parts.push(el("h3", {}, "Recent"), estimateTable((d.recent || []).filter(e => e.status !== "archived")));
  main.replaceChildren(...parts);
}

// ------------------------------------------------------------------ Projects
async function renderProjects(main, screen) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const status = STATUSES.includes(q.get("status")) ? q.get("status") : "";
  const list = await api("GET", "/estimates?limit=500" + (status ? "&status=" + status : ""));
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label),
    can("quick_estimate") ? el("a", { class: "primary button", href: "#/start", id: "projects-start" }, "🧭 AI Director Agent — get estimate started") : null,
    can("quick_estimate") ? el("a", { class: "button", href: "#/quick" }, "⚡ Quick estimate") : null,
    helpLink("projects"))];

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
  // Archived projects stay out of "All statuses"; pick Archived to see them (2026-11-12).
  const rows = status ? list.estimates : list.estimates.filter(e => e.status !== "archived");
  const hidden = list.estimates.length - rows.length;
  const table = estimateTable(rows);
  find.addEventListener("input", () => {
    const t = find.value.trim().toLowerCase();
    for (const tr of table.querySelectorAll("tbody tr")) {
      tr.hidden = !!t && !tr.textContent.toLowerCase().includes(t);
    }
  });
  parts.push(el("div", { class: "row filters" }, el("label", {}, "Status", pick), el("label", {}, "Find", find)), table);
  if (hidden) parts.push(el("p", { class: "muted small", id: "archived-hidden" },
    el("a", { href: "#/projects?status=archived" }, hidden + " archived project(s)"), " not shown."));
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
      el("span", { class: "status big" }, words(est.status)), helpLink("project")),
  ];
  if (est.practice) parts.push(el("p", { class: "note" }, "🎓 Practice project — not a real job."));
  if (est.editing_warning) parts.push(el("p", { class: "note warn" }, est.editing_warning));
  parts.push(el("div", { class: "tiles" },
    tile(money(st.estimate.total_cents), "total"),
    tile(st.trades.length, "trades"),
    tile(p.plan_sets.length, "plan sets"),
    tile(est.due_date || "—", "due"),
    est.address ? tile(est.address, "address", "wide") : null));
  if (!est.practice) parts.push(directorPanel(est.id));
  const go2 = el("p", { class: "row" });
  if (canOpen("estimates")) go2.append(el("a", { class: "button", id: "project-estimate", href: "#/estimates/" + est.id }, "🧮 Open the estimate"));
  if (canOpen("takeoffs") && p.plan_sets.length) {
    go2.append(el("a", { class: "button", id: "project-review", href: "#/takeoffs/" + est.id }, "📏 Blueprint Review — measure and approve"));
  }
  if (go2.childNodes.length) parts.push(go2);

  // Trades: per-trade subtotal and headline quantities (est_project_status)
  const trades = st.trades.length
    ? el("table", { class: "list", id: "trades" },
        el("thead", {}, el("tr", {}, el("th", {}, "Trade"), el("th", {}, "Biggest lines"), el("th", {}, "Subtotal"))),
        el("tbody", {}, st.trades.map(t => el("tr", {},
          el("td", {}, t.name), el("td", {}, el("ul", { class: "plain" }, t.headline.map(h => el("li", {}, h)))),
          el("td", { class: "money" }, money(t.subtotal_cents))))))
    : el("div", { class: "card empty" }, "No trades priced yet. ",
      el("a", { href: "#/estimates/" + est.id }, "Open the estimate"),
      " and price a trade, or ", el("a", { href: "#/quick/" + est.id }, "start a quick estimate"), ".");
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
  if (state.me && state.me.role === "owner" && !est.practice) parts.push(projectAdminBox(est));
  main.replaceChildren(...parts);
}

// Archive / restore / delete the project (owner; 2026-11-12, David). Every action asks first; delete needs the name.
function projectAdminBox(est) {
  const msg = el("div", { id: "proj-admin-message", role: "status" });
  const kids = [el("h3", {}, "Archive or delete this project")];
  if (est.status === "archived") {
    const restore = el("button", { class: "primary", type: "button", id: "proj-restore" }, "↩ Restore project…");
    restore.addEventListener("click", () => askConfirm(msg, restore, "/estimates/" + est.id + "/restore", {},
      r => { toast(r.message); route(); }, "proj-restore"));
    kids.push(el("p", { class: "muted" }, "This project is archived: it's hidden from Projects and the Dashboard."),
      el("div", { class: "row" }, restore));
  } else {
    const archive = el("button", { class: "button", type: "button", id: "proj-archive" }, "🗄 Archive project…");
    archive.addEventListener("click", () => askConfirm(msg, archive, "/estimates/" + est.id + "/archive", {},
      r => { toast(r.message); go("#/projects"); }, "proj-archive"));
    kids.push(el("p", { class: "muted" }, "Archive hides the project and keeps everything; you can restore it any time. " +
      "Delete removes it and its plans, measurements, quotes and history for good (a backup is made first)."),
      el("div", { class: "row" }, archive));
  }
  const del = el("button", { class: "button danger", type: "button", id: "proj-delete" }, "🗑 Delete project…");
  del.addEventListener("click", async () => {
    del.disabled = true;
    msg.replaceChildren();
    try {
      const r = await api("POST", "/estimates/" + est.id + "/delete", {});
      if (!r.needs_confirmation) { toast(r.message); go("#/projects"); return; }
      const name = el("input", { id: "proj-delete-name", maxlength: 200, placeholder: est.title, "aria-label": "Project name" });
      const yes = el("button", { class: "primary danger", type: "button", id: "proj-delete-confirm" }, "Delete for good");
      const no = el("button", { class: "button", type: "button", id: "proj-delete-cancel" }, "Cancel");
      const err = el("div", { id: "proj-delete-error", role: "alert" });
      no.addEventListener("click", () => msg.replaceChildren(el("p", { class: "muted" }, "Cancelled — nothing was deleted.")));
      yes.addEventListener("click", async () => {
        yes.disabled = no.disabled = true;
        try {
          const done = await api("POST", "/estimates/" + est.id + "/delete", { confirm: true, title: name.value });
          toast(done.message);
          go("#/projects");
        } catch (e) { yes.disabled = no.disabled = false; if (e.status !== 401) err.replaceChildren(errorBox(e)); }
      });
      msg.replaceChildren(el("div", { class: "confirm", id: "proj-delete-box" }, el("p", {}, el("strong", {}, r.question)),
        (r.changes || []).length ? el("ul", {}, r.changes.map(c => el("li", {}, c))) : null,
        el("label", {}, "Type the project's name to confirm: " + est.title, name), err, el("div", { class: "row" }, yes, no)));
      name.focus();
    } catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
    finally { del.disabled = false; }
  });
  kids[kids.length - 1].append(del);
  kids.push(msg);
  return el("div", { class: "card section", id: "project-admin" }, ...kids);
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
      el("td", {}, canOpen("plans") ? el("a", { href: "#/plan-sets/" + r.id }, r.file) : r.file,
        r.warnings && r.warnings.length ? el("div", { class: "muted small" }, "⚠ " + r.warnings.join(" · ")) : null),
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
    if (APP_TOKEN) x.setRequestHeader("Authorization", "Bearer " + APP_TOKEN);
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

function uploadPriceList(f) {
  // Like uploadRaw, but for a supplier price list: the file goes as the raw body and the server
  // stages it, checks it reads, and returns its columns and sheet names.
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("POST", API + "/price-book/import/stage?name=" + encodeURIComponent(f.name));
    x.withCredentials = true;
    if (APP_TOKEN) x.setRequestHeader("Authorization", "Bearer " + APP_TOKEN);
    x.setRequestHeader("X-Estimator-Request", "1");
    x.setRequestHeader("Content-Type", "application/octet-stream");
    x.onload = () => {
      let data = null;
      try { data = JSON.parse(x.responseText); } catch (e) { data = null; }
      if (x.status === 401) { showLogin(data && data.message); reject(new ApiError(401, data)); return; }
      if (x.status >= 400 || !data || data.ok === false) { reject(new ApiError(x.status, data)); return; }
      resolve(data);
    };
    x.onerror = () => reject(new ApiError(0, { message: "the upload did not reach the Estimator; check the connection and try again" }));
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

// ------------------------------------------------------------------ Start a new quote or estimate (2026-11-12, David)
// The Director asks, one question at a time: what's the job, are there plans, who's it for. Then it starts the right
// job (a quick quote, or a project with its own Director job) and goes to the next page.
async function renderStart(main) {
  const parts = [el("p", {}, el("a", { href: "#/dashboard" }, "← Dashboard")),
    el("div", { class: "page-head" }, el("h2", {}, "🧭 Start a new quote or estimate"), helpLink("dashboard"))];
  if (!can("quick_estimate")) {
    main.replaceChildren(...parts, el("p", { class: "error" }, "Your role can't start quotes or estimates."));
    return;
  }
  const talk = el("div", { class: "card section director-panel", id: "start-talk" });
  const msg = el("div", { id: "start-message", role: "status" });
  parts.push(talk, msg);
  main.replaceChildren(...parts);
  const said = [];
  const st = { request: "", preview: null, has_plans: null };
  const director = text => said.push(el("p", { class: "start-director" }, el("strong", {}, "🧭 Director: "), text));
  const you = text => said.push(el("p", { class: "start-you muted" }, "You: " + text));
  const show = (...controls) => talk.replaceChildren(...said, ...controls);

  // 1. What's the job?
  director("Hi! What's the job? Describe it the way the customer did, e.g. \"pour a 30 x 70 ft shed slab with fill\", " +
           "\"wash a driveway and the house\", or \"bid the framing and drywall from the plans\".");
  const job = el("textarea", { id: "start-request", rows: 3, maxlength: 2000, "aria-label": "What's the job?" });
  const next1 = el("button", { class: "primary", type: "button", id: "start-next" }, "Next →");
  next1.addEventListener("click", async () => {
    const text = job.value.trim();
    if (!text) { msg.replaceChildren(el("p", { class: "error" }, "Tell me what the job is first.")); job.focus(); return; }
    next1.disabled = true; msg.replaceChildren();
    try {
      st.request = text;
      st.preview = await api("POST", "/director/intake", { request: text, preview: true });
      you(text);
      director(st.preview.say);
      st.preview.ask_plans ? askPlans() : askCustomer();
    } catch (e) { next1.disabled = false; if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
  });
  show(el("label", {}, "The job", job), el("div", { class: "row" }, next1));
  job.focus();

  // 2. Do you have plans?
  function askPlans() {
    const yes = el("button", { class: "primary", type: "button", id: "start-plans-yes" }, "📐 Yes, I have plans to upload");
    const no = el("button", { class: "button", type: "button", id: "start-plans-no" }, "✏ No, I'll type the measurements");
    yes.addEventListener("click", () => { st.has_plans = true; you("Yes, I have plans."); director("Good — after this I'll take you to the project page to upload them (PDF, DWG or photos)."); askCustomer(); });
    no.addEventListener("click", () => { st.has_plans = false; you("No plans."); director("No problem — I'll take you to the form to type the measurements."); askCustomer(); });
    show(el("div", { class: "row", id: "start-plans" }, yes, no));
  }

  // 3. Who's it for?
  function askCustomer() {
    director("Who's it for? I need their email to send the quote later. You can skip this and add it later.");
    const name = el("input", { id: "start-cust-name", maxlength: 200, placeholder: "Customer name" });
    const email = el("input", { id: "start-cust-email", type: "email", maxlength: 200, placeholder: "customer@example.com" });
    const phone = el("input", { id: "start-cust-phone", maxlength: 40, placeholder: "Phone" });
    const addr = el("input", { id: "start-address", maxlength: 500, placeholder: "Job address" });
    const due = el("input", { id: "start-due", type: "date" });
    const go1 = el("button", { class: "primary", type: "button", id: "start-go" }, "Start →");
    go1.addEventListener("click", async () => {
      go1.disabled = true; msg.replaceChildren(el("p", { class: "muted" }, "Starting…"));
      const customer = { name: name.value.trim(), email: email.value.trim(), phone: phone.value.trim(), address: addr.value.trim() };
      try {
        const r = await api("POST", "/director/intake", { request: st.request, has_plans: st.has_plans === true,
          customer, address: addr.value.trim() || null, due_date: due.value || null });
        toast(r.say);
        go(r.route);
      } catch (e) { go1.disabled = false; if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
    });
    show(el("div", { class: "row", id: "start-customer" }, el("label", {}, "Customer", name), el("label", {}, "Email", email),
           el("label", {}, "Phone", phone)),
         el("div", { class: "row" }, el("label", {}, "Job address", addr), el("label", {}, "Due date (optional)", due)),
         el("div", { class: "row" }, go1));
    name.focus();
  }
}

// ------------------------------------------------------------------ Quick estimate (Sprint 2)
async function renderQuick(main, estimateId) {
  const mods = await api("GET", "/modules?path=quick");
  let est = null;
  if (estimateId) est = (await api("GET", "/estimates/" + estimateId + "/project")).estimate;
  const parts = [el("p", {}, est ? el("a", { href: "#/projects/" + est.id }, "← " + (est.title || "Estimate " + est.id))
                                : el("a", { href: "#/dashboard" }, "← Dashboard")),
                 el("div", { class: "page-head" },
                   el("h2", {}, "⚡ Quick estimate" + (est ? " for " + (est.title || "estimate " + est.id) : "")), helpLink("quick"))];
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
  const steps = el("p", { class: "muted", id: "quick-steps" }, "1 Pick a service → 2 Answer the questions → 3 Price it → 4 Approve and send");
  const next = el("p", { class: "note", id: "quick-next-hint" }, "Next: choose a service above.");
  parts.push(el("p", { class: "muted" }, "Price a small service job in a few taps — no plans needed. Pick a service, answer a few questions, and get a price from your Price Book."),
             steps, next,
             el("div", { class: "card section" }, el("label", {}, "What's the job?", pick)), form, result);
  main.replaceChildren(...parts);

  pick.addEventListener("change", async () => {
    form.replaceChildren(); result.replaceChildren();
    next.textContent = pick.value ? "Next: answer the questions below, then press Price it." : "Next: choose a service above.";
    if (!pick.value) return;
    try {
      const q = await api("GET", "/modules/" + encodeURIComponent(pick.value) + "/questions");
      buildQuickForm(form, result, q, est, next);
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

function buildQuickForm(form, result, q, est, next) {
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
      if (next) next.textContent = r.job ? "Priced. Next: approve and send the quote." : "Priced. Next: open the project to carry on.";
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
    r.next_step && r.next_step.say ? el("p", { class: "note" }, r.next_step.say) : null,
    el("div", { class: "row" },
      // Sprint 4: a new quick quote is a Director job - its page carries on to approve, send and convert.
      r.job ? el("a", { class: "primary button", href: "#/jobs/" + r.job.id, id: "quick-next" }, "Next: approve and send →") : null,
      el("a", { class: r.job ? "button" : "primary button", href: "#/projects/" + r.id, id: "quick-open" }, "Open the project"),
      el("a", { class: "button", href: "#/quick" }, "Another quick estimate"))));
}

// ------------------------------------------------------------------ Price Book (Sprint 3, basic)
function dollars(cents) { return (Number(cents || 0) / 100).toFixed(2); }

async function renderPriceBook(main, screen) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const moduleId = q.get("module") || "", samples = q.get("samples") === "1";
  const [book, mods, marks] = await Promise.all([
    api("GET", "/price-book?" + (moduleId ? "module_id=" + encodeURIComponent(moduleId) + "&" : "") + (samples ? "samples_only=1" : "")),
    api("GET", "/modules"), api("GET", "/price-book/markups")]);
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("price_book")),
    el("p", { class: "muted" }, "Your costs per unit. Prices marked sample are placeholders shipped with a trade — set your own before sending bids. " +
      "Changing a price never changes a bid already made."),
    book.samples_left ? el("p", { class: "note warn", id: "samples-left" }, book.samples_left + " price(s) here are still samples.") : null,
    // Sprint 17: what's added on top of these costs.
    el("div", { class: "card section row", id: "pb-markups" }, el("strong", {}, "On top of these costs:"),
      el("span", {}, "overhead " + marks.overhead_pct + "%"), el("span", {}, "profit " + marks.profit_pct + "%"),
      el("span", {}, "labor burden " + marks.labor_burden_pct + "%"),
      el("span", {}, "tax " + marks.tax_pct + "% on " + marks.taxable_kinds.map(words).join(", ") + " (" + marks.tax_base + ")"),
      marks.minimum_charge_cents ? el("span", {}, "minimum " + money(marks.minimum_charge_cents)) : null,
      marks.can_change ? el("a", { href: "#/settings?section=money", id: "pb-markups-edit" }, "Change in Settings") : null)];

  const pickMod = el("select", { id: "pb-module", "aria-label": "Trade or service" }, el("option", { value: "" }, "All trades and services"),
    mods.modules.map(m => el("option", { value: m.id, selected: m.id === moduleId }, m.name)));
  const onlySamples = el("input", { type: "checkbox", id: "pb-samples", checked: samples });
  const refilter = () => { location.hash = "#/price_book?" + new URLSearchParams({ module: pickMod.value, samples: onlySamples.checked ? "1" : "" }); };
  pickMod.addEventListener("change", refilter);
  onlySamples.addEventListener("change", refilter);
  const find = el("input", { type: "search", id: "pb-find", placeholder: "Find a price", "aria-label": "Find" });
  const kinds = [...new Set(book.prices.map(p => p.kind))].sort();
  const pickKind = el("select", { id: "pb-kind", "aria-label": "Kind" }, el("option", { value: "" }, "all kinds"),
    kinds.map(k => el("option", { value: k }, words(k))));
  parts.push(el("div", { class: "row filters" }, el("label", {}, "Show", pickMod), el("label", {}, "Kind", pickKind),
    el("label", {}, "Find", find), el("label", { class: "check" }, onlySamples, " Samples only")));

  if (!book.prices.length) {
    parts.push(el("div", { class: "card empty" }, "No prices here. ",
      el("a", { href: "#/help/set_up_your_price_book" }, "See how to add prices"),
      " or paste a supplier's list below."));
  } else {
    const tradeName = Object.fromEntries((mods.modules || []).map(m => [m.id, m.name]));
    const tbody = el("tbody", {}, book.prices.map(p => {
      // 2026-11-12, David: the cost here is read-only; a price changes only through ✏️ Edit (which asks first).
      const input = el("input", { type: "text", class: "cost", readonly: true, tabindex: "-1", "data-key": p.price_key,
                                  value: dollars(p.cost_cents), "aria-label": "Cost for " + p.description,
                                  title: "Click ✏️ Edit to change the cost" });
      const edit = el("button", { class: "link-btn", type: "button", "data-edit": p.price_key, title: "Change the cost, description, kind, unit, trade or sample mark" }, "✏️ Edit");
      const remove = el("button", { class: "link-btn", type: "button", "data-remove": p.price_key, title: "Remove this price" }, "🗑️ Remove");
      const hist = el("button", { class: "link-btn", type: "button", "data-history": p.price_key, title: "Price history and job costs" }, "📈 History");
      const row = el("tr", { "data-key": p.price_key, "data-kind": p.kind },
        el("td", {}, p.description, el("div", { class: "muted small" }, p.price_key)),
        el("td", {}, p.kind), el("td", {}, p.unit),
        el("td", { "data-trade": p.module_id || "" }, p.module_id ? (tradeName[p.module_id] || p.module_id) : "—"),
        el("td", { class: "money" }, "$", input),
        el("td", {}, el("span", { class: "status" + (p.sample ? " sample" : "") }, p.sample ? "sample" : "yours"),
          p.effective_date ? el("div", { class: "muted small" }, "from " + p.effective_date) : null),
        el("td", {}, edit, " ", remove, " ", hist));
      edit.addEventListener("click", () => priceEdit(row, p, mods.modules));
      remove.addEventListener("click", () => priceRemove(row, p, remove));
      hist.addEventListener("click", () => priceHistory(row, p));
      return row;
    }));
    const table = el("table", { class: "list", id: "prices" },
      el("thead", {}, el("tr", {}, el("th", {}, "Item"), el("th", {}, "Kind"), el("th", {}, "Unit"),
        el("th", {}, "Trade"), el("th", {}, "Cost per unit"), el("th", {}, "Source"), el("th", {}, ""))), tbody);
    const narrow = () => {
      const t = find.value.trim().toLowerCase(), k = pickKind.value;
      for (const tr of tbody.querySelectorAll("tr[data-key]")) {
        tr.hidden = (!!t && !tr.textContent.toLowerCase().includes(t)) || (!!k && tr.dataset.kind !== k);
        const next = tr.nextElementSibling;
        if (next && (next.classList.contains("pb-history") || next.classList.contains("pb-edit"))) next.hidden = tr.hidden;
      }
    };
    find.addEventListener("input", narrow);
    pickKind.addEventListener("change", narrow);
    parts.push(table, el("p", { class: "muted small", id: "pb-edit-hint" },
      "To change a price, click ✏️ Edit on its row. Every change asks before it's saved."));
  }
  parts.push(addPriceForm(mods.modules, moduleId), importBox(mods.modules, moduleId));
  main.replaceChildren(...parts);
}

async function askThenSave(msg, btn, path, body, doneText) {
  // Every money change asks first (spec: money writes need a person): show old -> new, then confirm.
  btn.disabled = true;
  state.busy = true;
  try {
    const r = await api("POST", path, body);
    if (!r.needs_confirmation) {
      // Fix 5: when nothing saved, say why — e.g. the Add form's code already
      // exists with a different unit, so the import skipped the row.
      const skipped = (r.skipped_rows || []).map(s => el("li", {}, "Row " + s.row + (s.item ? " (" + s.item + ")" : "") + ": " + s.reason));
      // (replaceChildren would print a null as the word "null" - 2026-11-12)
      msg.replaceChildren(...[el("p", {}, r.message || "Nothing to change."),
        skipped.length ? el("ul", {}, skipped) : null].filter(Boolean));
      return;
    }
    const yes = el("button", { class: "primary", type: "button", id: "pb-confirm" }, "Yes, save");
    const no = el("button", { class: "button", type: "button", id: "pb-cancel" }, "Cancel");
    const lines = (r.changes || []).map(c => typeof c === "string" ? el("li", {}, c) : el("li", {}, (c.description || c.price_key) + ": " +
      (c.old_cents === null || c.old_cents === undefined ? "new" : money(c.old_cents)) + " → " + money(c.new_cents) + " per " + c.unit +
      (c.was_sample ? " (was a sample)" : "")));
    const skipped = (r.skipped_rows || []).map(s => el("li", {}, "Row " + s.row + (s.item ? " (" + s.item + ")" : "") + ": " + s.reason));
    msg.replaceChildren(el("div", { class: "confirm", id: "pb-confirm-box" },
      el("p", {}, el("strong", {}, r.question)),
      lines.length ? el("ul", {}, lines) : null,
      r.more_not_shown ? el("p", { class: "muted" }, "…and " + r.more_not_shown + " more.") : null,
      skipped.length ? el("details", {}, el("summary", {}, skipped.length + " row(s) skipped"), el("ul", {}, skipped)) : null,
      el("div", { class: "row" }, yes, no)));
    yes.focus();
    await new Promise(resolve => {
      no.addEventListener("click", () => { msg.replaceChildren(el("p", { class: "muted" }, "Cancelled — nothing changed.")); resolve(); });
      yes.addEventListener("click", async () => {
        yes.disabled = no.disabled = true;
        try {
          const done = await api("POST", path, { ...body, confirm: true });
          state.busy = false;
          toast(doneText(done));
          route();
        } catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
        resolve();
      });
    });
  } catch (e) {
    if (e.status !== 401) msg.replaceChildren(errorBox(e));
  } finally { btn.disabled = false; state.busy = false; }
}

// Sprint 17: one price's dated history and what jobs really paid, opened under its row.
async function priceHistory(row, p) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("pb-history")) { next.remove(); return; }
  if (next && next.classList.contains("pb-edit")) next.remove();
  const cell = el("td", { colspan: 7 }, el("p", { class: "muted" }, "Loading…"));
  row.after(el("tr", { class: "pb-history", "data-history-for": p.price_key }, cell));
  try {
    const h = await api("GET", "/price-book/history/" + encodeURIComponent(p.price_key));
    const j = h.jobs || {};
    cell.replaceChildren(
      h.history.length ? el("table", { class: "list small" }, el("thead", {}, el("tr", {}, ["From", "Cost", "Source", "Set by"].map(x => el("th", {}, x)))),
        el("tbody", {}, h.history.map(x => el("tr", {}, el("td", {}, x.effective_date), el("td", { class: "num" }, money(x.cost_cents) + " / " + x.unit),
          el("td", {}, x.sample ? "sample" : (x.supplier || "yours")), el("td", {}, x.created_by || "")))))
        : el("p", { class: "muted" }, h.note || "No history yet."),
      el("p", { class: "small" }, (j.estimates_using_it || 0) + " estimate(s) used it" +
        (j.usual_estimated_unit_cost ? ", usually at " + j.usual_estimated_unit_cost : "") +
        (j.jobs_with_actuals ? "; " + j.jobs_with_actuals + " job(s) recorded, paying " + (j.actual_unit_cost || "—") + " per unit" +
          (j.jobs_run ? " (" + j.jobs_run + ")" : "") : "; no job costs recorded yet") + "."),
      ...(h.suggestions || []).map(s => el("p", { class: "note warn" }, s.message)));
  } catch (e) { if (e.status !== 401) cell.replaceChildren(errorBox(e)); }
}

// One price's details — description, kind, unit, trade — edited under its row.
// The code (price_key) is the identifier and never changes; the cost stays
// inline-editable in the table. Saving asks first, like every money change.
function priceEdit(row, p, modules) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("pb-edit")) { next.remove(); return; }
  if (next && next.classList.contains("pb-history")) next.remove();
  const desc = el("input", { type: "text", id: "pb-edit-desc", value: p.description, "aria-label": "Description" });
  const kind = el("select", { id: "pb-edit-kind", "aria-label": "Kind" },
    ["material", "labor", "equipment", "sub", "other"].map(k => el("option", { value: k, selected: k === p.kind }, words(k))));
  const unit = el("input", { type: "text", id: "pb-edit-unit", value: p.unit, "aria-label": "Unit" });
  const trade = tradeSelect("pb-edit-trade", modules, p.module_id || "");
  // 2026-11-12: every field is editable here, the cost and the sample mark too. The cost starts from what's typed in
  // the table (so a cost typed there isn't lost), and unticking Sample keeps the price as your own.
  const tableCost = row.querySelector("input.cost");
  const cost = el("input", { type: "text", inputmode: "decimal", id: "pb-edit-cost",   // not .cost: the table's Save reads those
                             value: tableCost ? tableCost.value : dollars(p.cost_cents), "aria-label": "Cost per unit" });
  const sample = el("input", { type: "checkbox", id: "pb-edit-sample", checked: !!p.sample });
  const eff = el("input", { type: "date", id: "pb-edit-effective", "aria-label": "Takes effect" });
  const save = el("button", { class: "primary", type: "button", id: "pb-edit-save" }, "Save…");
  const cancel = el("button", { class: "button", type: "button", id: "pb-edit-cancel" }, "Cancel");
  const msg = el("div", { id: "pb-edit-message", role: "status" });
  const cell = el("td", { colspan: 7 },
    el("div", { class: "row filters" },
      el("label", {}, "Item ", el("span", { class: "muted" }, p.price_key)),
      el("label", {}, "Description", desc),
      el("label", {}, "Kind", kind),
      el("label", {}, "Unit", unit),
      el("label", {}, "Trade", trade),
      el("label", {}, "Cost per unit ($)", cost),
      el("label", {}, "Takes effect (optional)", eff),
      el("label", { class: "check", title: "A sample is a placeholder shipped with the trade. Untick to keep this price as your own." },
        sample, " Sample (placeholder)"),
      el("span", {}, save, " ", cancel)),
    p.sample ? el("p", { class: "muted small" }, "Happy with this price? Untick Sample and click Save… to keep it as your own.") : null,
    msg);
  row.after(el("tr", { class: "pb-edit", "data-edit-for": p.price_key }, cell));
  cancel.addEventListener("click", () => cell.closest("tr").remove());
  save.addEventListener("click", async () => {
    msg.replaceChildren();
    const d = desc.value.trim(), u = unit.value.trim(), c = cost.value.trim().replace(/^\$/, "").replace(/,/g, "");
    if (!d) { msg.replaceChildren(errorBox({ message: "Give the item a description." })); return; }
    if (!u) { msg.replaceChildren(errorBox({ message: "Give the item a unit, e.g. sqft." })); return; }
    if (c === "" || isNaN(Number(c)) || Number(c) < 0) { msg.replaceChildren(errorBox({ message: "Give the cost as dollars, e.g. 250.00." })); return; }
    cancel.disabled = true;
    await askThenSave(msg, save, "/price-book/" + encodeURIComponent(p.price_key) + "/edit",
      { description: d, kind: kind.value, unit: u, module_id: trade.value || null, cost: c, sample: sample.checked,
        effective_date: eff.value || null },
      () => "Price updated.");
    cancel.disabled = false;
  });
}

// Remove one price, asking first. A module key goes back to its sample price;
// a price added by hand is gone from the Price Book entirely.
function priceRemove(row, p, btn) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("pb-edit")) { next.remove(); return; }
  if (next && next.classList.contains("pb-history")) next.remove();
  const msg = el("div", { id: "pb-remove-message", role: "status" });
  row.after(el("tr", { class: "pb-edit", "data-remove-for": p.price_key }, el("td", { colspan: 7 }, msg)));
  askThenSave(msg, btn, "/price-book/" + encodeURIComponent(p.price_key) + "/remove", {},
    () => "Price removed.");
}

// Fix 5: add one price by hand. The table only edits prices that already exist,
// and the import box was the only way a new price got in. This sends one CSV row
// to /price-book/import with add_new, through the same ask-then-save confirm as
// the table and the import box — POST /price-book itself refuses unknown keys
// (price_book.py update_prices: no price called '<key>'), so it cannot add items.
// The trade a new price belongs to: it shows under that trade's filter in the Price Book.
// Blank (No trade) means the price only shows under All trades.
function tradeSelect(id, modules, currentModule) {
  return el("select", { id, "aria-label": "Trade" }, el("option", { value: "" }, "No trade"),
    (modules || []).map(m => el("option", { value: m.id, selected: m.id === currentModule }, m.name)));
}

function addPriceForm(modules, currentModule) {
  const key = el("input", { type: "text", id: "pb-add-key", placeholder: "e.g. cc_fibermesh_sqft", "aria-label": "Item code" });
  const desc = el("input", { type: "text", id: "pb-add-desc", placeholder: "Description", "aria-label": "Description" });
  const kind = el("select", { id: "pb-add-kind", "aria-label": "Kind" },
    ["material", "labor", "equipment", "sub", "other"].map(k => el("option", { value: k }, words(k))));
  const unit = el("input", { type: "text", id: "pb-add-unit", placeholder: "Unit, e.g. sqft", "aria-label": "Unit" });
  const cost = el("input", { type: "text", inputmode: "decimal", id: "pb-add-cost", placeholder: "Cost per unit", "aria-label": "Cost per unit" });
  const trade = tradeSelect("pb-add-trade", modules, currentModule);
  const add = el("button", { class: "primary", type: "button", id: "pb-add" }, "Add item");
  const msg = el("div", { id: "pb-add-message", role: "status" });
  const cell = v => { v = String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  add.addEventListener("click", async () => {
    msg.replaceChildren();
    const k = key.value.trim(), d = desc.value.trim(), u = unit.value.trim(), c = cost.value.trim().replace(/^\$/, "");
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(k)) {
      msg.replaceChildren(errorBox({ message: "Give the item a code using letters, numbers, _ . or - (up to 64 characters)." }));
      return;
    }
    if (!d) { msg.replaceChildren(errorBox({ message: "Give the item a description." })); return; }
    if (!u) { msg.replaceChildren(errorBox({ message: "Give the item a unit, e.g. sqft." })); return; }
    if (c === "" || isNaN(Number(c)) || Number(c) < 0) {
      msg.replaceChildren(errorBox({ message: "Give the cost as dollars, e.g. 0.18." }));
      return;
    }
    const csv = "Item code,Description,Unit,Cost,Kind\n" + [k, d, u, c, kind.value].map(cell).join(",") + "\n";
    await askThenSave(msg, add, "/price-book/import",
      { csv_text: csv, mapping: { price_key: "Item code", description: "Description", unit: "Unit", cost: "Cost", kind: "Kind" },
        add_new: true, module_id: trade.value || null },
      r => (r.saved || 0) + " price(s) saved.");
  });
  return el("details", { class: "card section", id: "pb-add-box", open: true }, el("summary", {}, "Add an item"),
    el("p", { class: "muted" }, "One price, by hand. If the item code already exists, saving updates that price instead — " +
      "you'll be asked to confirm the old cost → new cost first, and a different unit is skipped, never converted. Pick a trade and the price shows under that trade's filter; leave it on No trade and it only shows under All trades."),
    el("div", { class: "row filters" },
      el("label", {}, "Item code", key), el("label", {}, "Description", desc), el("label", {}, "Kind", kind),
      el("label", {}, "Trade", trade), el("label", {}, "Unit", unit), el("label", {}, "Cost per unit", cost), add),
    msg);
}

function importBox(modules, currentModule) {
  const text = el("textarea", { id: "pb-csv", rows: 6, placeholder: "Item,Unit,Unit Price\nDriveway cleaning,sqft,0.18" });
  const addNew = el("input", { type: "checkbox", id: "pb-addnew" });
  const trade = tradeSelect("pb-import-trade", modules, currentModule);
  const eff = el("input", { type: "date", id: "pb-import-effective", "aria-label": "Effective date" });
  const check = el("button", { class: "button", type: "button", id: "pb-columns" }, "1. Check the columns…");
  const go = el("button", { class: "primary", type: "button", id: "pb-import" }, "2. Check the list…");
  const cols = el("div", { id: "pb-mapping" });
  const msg = el("div", { id: "pb-import-message", role: "status" });
  const pickers = {};
  const file = el("input", { type: "file", id: "pb-file", accept: ".csv,.txt,.xlsx,.xlsm" });
  const sheet = el("select", { id: "pb-sheet", hidden: true, "aria-label": "Sheet" });
  let staged = null; // The staged file from the stage endpoint, or null when pasting CSV.
  file.addEventListener("change", async () => {
    const f = file.files[0];
    if (!f) return;
    msg.replaceChildren();
    staged = null;
    sheet.hidden = true;
    sheet.replaceChildren();
      const ext = (f.name.split(".").pop() || "").toLowerCase();
      // Check size and type before uploading: the server answers 413/400 before
      // reading the body, so the browser sees a dropped connection instead of
      // the message - and any 4xx response fails the E2E console guard.
      // Worded to match the server stage errors (router.py _stage_price_list).
      if (f.size > 5 * 1024 * 1024) {
        msg.replaceChildren(errorBox({ message: f.name + " is " + Math.floor(f.size / 1048576) +
          " MB; the limit is 5 MB. Split the list or save just the columns you need" }));
        return;
      }
      if (!["csv", "txt", "xlsx", "xlsm"].includes(ext)) {
        msg.replaceChildren(errorBox({ message: "." + ext +
          " cannot be used; price lists can be CSV or Excel (.csv, .txt, .xlsx, .xlsm)" }));
        return;
      }
      if (ext === "csv" || ext === "txt") { text.value = await f.text(); return; }
    try {
      const r = await uploadPriceList(f);
      staged = r;
      if ((r.sheets || []).length > 1) {
        // NB: replaceChildren takes nodes, not an array — without the spread
        // the array stringifies to a text node and the select gets 0 options.
        sheet.replaceChildren(...r.sheets.map(s => el("option", { value: s }, s)));
        sheet.hidden = false;
      }
      msg.replaceChildren(el("p", { class: "muted" }, f.name + ": " + r.row_count + " row(s), " + r.columns.length + " column(s)."));
    } catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
  });
  sheet.addEventListener("change", () => check.click());
  text.addEventListener("input", () => { staged = null; sheet.hidden = true; });
  // Sprint 17: column mapping - the server guesses each column from its name; the user can change any of them.
  check.addEventListener("click", async () => {
    msg.replaceChildren();
    if (!staged && !text.value.trim()) { msg.append(el("p", { class: "error" }, "Paste the price list or choose a file first.")); return; }
    try {
      const body = staged ? { file_path: staged.stage_id } : { csv_text: text.value };
      if (staged && !sheet.hidden) body.sheet = sheet.value;
      const r = await api("POST", "/price-book/import/preview", body);
      for (const k of Object.keys(pickers)) delete pickers[k];
      const LABELS = { price_key: "Item code", cost: "Cost", description: "Description", unit: "Unit", kind: "Kind", supplier: "Supplier" };
      cols.replaceChildren(el("p", { class: "muted small" }, r.row_count + " row(s). Which column holds what:"),
        el("div", { class: "row filters" }, r.fields.map(f => {
          pickers[f] = el("select", { "data-field": f, "aria-label": LABELS[f] || f }, el("option", { value: "" }, "(none)"),
            r.columns.map(c => el("option", { value: c, selected: r.mapping[f] === c }, c)));
          return el("label", {}, LABELS[f] || words(f), pickers[f]);
        })),
        r.rows.length ? el("table", { class: "list small" }, el("thead", {}, el("tr", {}, r.columns.map(c => el("th", {}, c)))),
          el("tbody", {}, r.rows.map(row => el("tr", {}, r.columns.map(c => el("td", {}, row[c] || "")))))) : null);
    } catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
  });
  go.addEventListener("click", async () => {
    msg.replaceChildren();
    if (!staged && !text.value.trim()) { msg.append(el("p", { class: "error" }, "Paste the price list or choose a file first.")); return; }
    const mapping = {};
    for (const [f, s] of Object.entries(pickers)) if (s.value) mapping[f] = s.value;
    const body = { add_new: addNew.checked, effective_date: eff.value || null,
      mapping: Object.keys(mapping).length ? mapping : null, module_id: trade.value || null };
    if (staged) { body.file_path = staged.stage_id; if (!sheet.hidden) body.sheet = sheet.value; }
    else body.csv_text = text.value;
    await askThenSave(msg, go, "/price-book/import", body,
      r => "Imported " + (r.saved !== undefined ? r.saved : "") + " price(s).");
  });
  return el("details", { class: "card section", id: "pb-import-box" }, el("summary", {}, "Import a supplier price list (CSV or Excel file)"),
    el("p", { class: "muted" }, "Paste the rows from your supplier spreadsheet, header row first, or choose a CSV or Excel file. " +
      "Columns are found by name (item code, description, unit, unit price / cost); check them and change any that are wrong. " +
      "Rows with a different unit are skipped, never converted."),
    el("div", { class: "row" }, el("label", {}, "Or choose a file: ", file), sheet),
    text, el("div", { class: "row" }, check), cols,
    el("label", { class: "check" }, addNew, " Add rows that don't match a price as new prices"),
    el("label", {}, "Trade for new prices", trade),
    el("label", {}, "Takes effect (optional)", eff), go, msg);
}

// ------------------------------------------------------------------ Plans (Sprint 5: plan engine, sheets, scales)
const DISCIPLINE_ICON = { architectural: "🏠", structural: "🧱", plumbing: "🚰", electrical: "⚡", mechanical: "🌀",
  landscape: "🌳", roof: "🏚", site: "🗺", civil: "🛣", fire: "🔥", general: "📄", other: "📄" };

async function renderPlans(main, screen) {
  const r = await api("GET", "/plans");
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("plans")),
    el("p", { class: "muted" }, "Plan sets on your projects. Upload plans from a project's page; open a set to read it and check its sheets and scales.")];
  if (!r.engine.installed) parts.push(el("p", { class: "note warn" }, "The plan engine isn't installed on this PC, so plans can be uploaded but not read yet."));
  if (!r.plan_sets.length) {
    parts.push(el("div", { class: "card empty", id: "plans-empty" }, "No plans yet — open a project and upload a PDF, DXF or photo."));
  } else {
    parts.push(el("table", { class: "list clickable", id: "plan-sets" },
      el("thead", {}, el("tr", {}, el("th", {}, "Project"), el("th", {}, "File"), el("th", {}, "Rev"), el("th", {}, "Status"),
        el("th", {}, "Sheets"), el("th", {}, "Uploaded"))),
      el("tbody", {}, r.plan_sets.map(p => el("tr", { "data-id": p.id, onclick: () => go("#/plan-sets/" + p.id) },
        el("td", {}, el("a", { href: "#/projects/" + p.estimate_id, onclick: ev => ev.stopPropagation() }, p.estimate_title)),
        el("td", {}, el("a", { href: "#/plan-sets/" + p.id }, p.file)),
        el("td", {}, p.revision),
        el("td", {}, el("span", { class: "status" }, words(p.status))),
        el("td", {}, p.sheets || "—"),
        el("td", {}, when(p.created_at)))))));
  }
  main.replaceChildren(...parts);
}

// Per-trade sheet activation: the trade the plan-set sheet list shows takeoff switches for.
// Concrete first — it is the trade with the takeoff agent — and it stays put while the page is open.
let planTradeId = "concrete";
let planPoll = null;
async function renderPlanSet(main, id) {
  clearTimeout(planPoll);
  const [r, mods] = await Promise.all([api("GET", "/plan-sets/" + id + "?module_id=" + encodeURIComponent(planTradeId)),
    api("GET", "/modules")]);
  const tradeMods = (mods.modules || []).filter(m => m.path === "plan_takeoff" || m.path === "both");
  const trade = tradeMods.find(m => m.id === planTradeId) || tradeMods[0];
  const tradeId = trade ? trade.id : planTradeId, tradeName = trade ? trade.name : words(planTradeId);
  const ps = r.plan_set;
  const msg = el("div", { id: "plan-message", role: "status" });
  const parts = [el("p", {}, el("a", { href: "#/projects/" + r.estimate.id }, "← " + r.estimate.title)),
    el("div", { class: "page-head" }, el("h2", {}, "📐 " + ps.file + (ps.revision > 1 ? " (revision " + ps.revision + ")" : "")), helpLink("plans")),
    el("p", { class: "muted", id: "plan-say" }, ps.say)];
  if (ps.status === "failed") parts.push(el("p", { class: "error" }, ps.error || "Reading failed."));
  if (r.can_edit && ps.status !== "processing") {
    if (!r.engine.installed) {
      parts.push(el("p", { class: "note warn" }, "The plan engine isn't installed on this PC."));
    } else {
      const read = el("button", { class: "primary", type: "button", id: "plan-read" },
        ps.status === "processed" ? "Read the plans again…" : "📖 Read the plans…");
      read.addEventListener("click", () => askThen(msg, read, "/plan-sets/" + id + "/process", {},
        () => "Reading the plans in the background…", "plan"));
      const row = el("div", { class: "row" }, read);
      // Sprint 17: a revised set (Rev B) is compared with the one it replaces, then drawn over the sheets.
      if (ps.supersedes_plan_set_id && ps.status === "processed" && canOpen("reports")) {
        const cmp = el("button", { class: "button", type: "button", id: "plan-compare" }, "🔀 Compare with the plans it replaces…");
        cmp.addEventListener("click", () => askConfirm(msg, cmp, "/reports/revisions", { new_plan_set_id: id },
          done => { toast("Revision report saved."); go("#/revisions/" + done.report_id); }, "plan-compare"));
        row.append(cmp, el("a", { class: "button", href: "#/reports?tab=revisions&estimate=" + r.estimate.id, id: "plan-revisions" },
          "Revision reports"));
      }
      parts.push(row);
    }
  }
  if (r.can_edit && ps.status !== "processing") {
    // Removing a plan set asks first and lists everything that goes with it; once it is gone the page
    // goes back to the Plans list (this set no longer exists to show).
    const del = el("button", { class: "button danger", type: "button", id: "plan-remove" }, "🗑️ Remove this plan set…");
    del.addEventListener("click", () => askConfirm(msg, del, "/plan-sets/" + id + "/remove", {},
      done => { toast(done.summary || "Plan set removed."); go("#/plans"); }, "plan-remove"));
    parts.push(el("div", { class: "row" }, del));
  }
  parts.push(msg);
  if (ps.status === "processing") {
    parts.push(el("p", { class: "note", id: "plan-processing" }, "⏳ The plan engine is reading the sheets. This page updates by itself."));
    planPoll = setTimeout(() => { if (state.page === "plan_set" && state.pageArg === id && !state.busy) route(); }, 3000);
  }
  if (r.sheets.length) {
    const need = r.sheets.filter(s => s.needs_scale).length;
    if (need) parts.push(el("p", { class: "note warn", id: "plan-need-scale" }, need + " sheet(s) need a scale before anything on them can be measured — open the sheet to set or calibrate it."));
    // Per-trade sheet activation: pick the trade, then switch sheets on or off for its takeoff.
    // A sheet switched off is skipped by that trade's agent — it stays openable and measurable by hand.
    const pickTrade = el("select", { id: "plan-trade", "aria-label": "Trade" },
      tradeMods.map(m => el("option", { value: m.id, selected: m.id === tradeId }, m.name)));
    pickTrade.addEventListener("change", () => { planTradeId = pickTrade.value; route(); });
    parts.push(el("div", { class: "row filters", id: "plan-trade-row" },
      el("label", {}, "Takeoff for ", pickTrade),
      el("span", { class: "muted small" }, "Sheets switched off are skipped by the " + tradeName + " takeoff — you can still open and measure them by hand.")));
    const toggleCell = s => {
      const on = s.active_for_trade !== false;
      if (!r.can_edit) return el("td", {}, on ? "" : el("span", { class: "status sample" }, "off for " + tradeName));
      const off = el("span", { class: "status sample", hidden: on }, " off");
      const box = el("input", { type: "checkbox", class: "sheet-trade-toggle", "data-sheet": s.id, checked: on,
        "aria-label": "Use this sheet for " + tradeName,
        title: on ? "This sheet counts for " + tradeName : "Switched off for " + tradeName + " — the agent skips it" });
      box.addEventListener("click", ev => ev.stopPropagation());
      box.addEventListener("change", async () => {
        const want = box.checked;
        box.disabled = true;
        try {
          await api("POST", "/sheets/" + s.id + "/trade-active", { module_id: tradeId, active: want });
          off.hidden = want;
          box.title = want ? "This sheet counts for " + tradeName : "Switched off for " + tradeName + " — the agent skips it";
          toast(want ? "Sheet switched on for " + tradeName + "." : "Sheet switched off for " + tradeName + " — the takeoff agent will skip it.");
        } catch (e) { box.checked = !want; toast(e.message); }
        box.disabled = false;
      });
      return el("td", {}, box, off);
    };
    // Removing a sheet asks first and lists everything measured on it; the plan set stays.
    const delCell = s => {
      if (!r.can_edit) return el("td", {});
      const del = el("button", { class: "button small", type: "button", "data-remove-sheet": s.id,
        "aria-label": "Remove sheet " + (s.sheet_no || ("page " + s.page_no)),
        title: "Remove this sheet and everything measured on it" }, "🗑️");
      del.addEventListener("click", ev => {
        ev.stopPropagation();                       // the row itself opens the sheet
        askConfirm(msg, del, "/sheets/" + s.id + "/remove", {},
          done => { toast(done.summary || "Sheet removed."); route(); }, "sheet-remove");
      });
      return el("td", {}, del);
    };
    parts.push(el("table", { class: "list clickable", id: "sheets" },
      el("thead", {}, el("tr", {}, el("th", {}, "Page"), el("th", {}, "Sheet"), el("th", {}, "Title"), el("th", {}, "Discipline"),
        el("th", {}, "Scales"), el("th", {}, "Rev"), el("th", {}, "Takeoff"), el("th", {}, ""))),
      el("tbody", {}, r.sheets.map(s => el("tr", { "data-id": s.id, onclick: () => go("#/sheets/" + s.id) },
        el("td", {}, s.page_no),
        el("td", {}, el("a", { href: "#/sheets/" + s.id }, s.sheet_no || "page " + s.page_no)),
        el("td", {}, s.title || "—"),
        el("td", {}, (DISCIPLINE_ICON[s.discipline] || "") + " " + words(s.discipline)),
        el("td", {}, s.viewports.map(v => v.is_nts ? "NTS" : (v.scale_note || (v.measurable ? "1:" + v.scale_ratio : "—"))).join(" · "),
          s.needs_scale ? el("span", { class: "status sample" }, " needs a scale") : null),
        el("td", {}, s.revision || ""), toggleCell(s), delCell(s))))));
  } else if (ps.status === "processed") {
    parts.push(el("div", { class: "card empty" }, "No sheets were found in this file. "
      + "Upload a different file (a PDF, a photo, or a DXF/DWG) from the project page."));
  }
  if (ps.status === "processed" && r.sheets.length) {
    const tables = el("div", { id: "plan-tables" });
    parts.push(tables);
    planTables(tables, id, r.can_edit);
  }
  main.replaceChildren(...parts);
}

// Sprint 9: schedules read from the plans (rows linked to plan tags) and legends with the symbol dictionary.
async function planTables(box, id, canEdit) {
  let s, l, y;
  try {
    [s, l, y] = await Promise.all([api("GET", "/plan-sets/" + id + "/schedules"), api("GET", "/plan-sets/" + id + "/legends"),
      api("GET", "/plan-sets/" + id + "/symbols?limit=1")]);
  } catch (e) { if (e.status !== 401) box.replaceChildren(errorBox(e)); return; }
  const parts = [];
  if (y.count) parts.push(symbolCounts(y));
  if (s.schedules.length) {
    parts.push(el("h3", {}, "Schedules"));
    s.schedules.forEach(sc => parts.push(scheduleCard(sc, canEdit)));
  }
  if (l.legends.length) {
    parts.push(el("h3", {}, "Legends"));
    const dict = l.symbol_dictionary || [];
    l.legends.forEach(lg => {
      const entries = dict.filter(e => e.legend === lg.title && e.sheet_no === lg.sheet_no);
      parts.push(el("div", { class: "card section", "data-legend": lg.id },
        el("h4", {}, lg.title + " — " + (lg.sheet_no || "sheet") + (lg.discipline ? " · " + words(lg.discipline) : "")),
        entries.length ? el("table", { class: "list legend-entries" },
          el("thead", {}, el("tr", {}, el("th", {}, "Code"), el("th", {}, "Description"), el("th", {}, "Item"), el("th", {}, "Trade"),
            el("th", {}, "Found"))),
          el("tbody", {}, entries.map(e => el("tr", { class: e.needs_confirming ? "needs-confirming" : "" },
            el("td", {}, e.code || (e.has_symbol ? "(symbol)" : "—")),
            el("td", {}, e.description),
            el("td", {}, e.item_type ? words(e.item_type) : el("span", { class: "status sample" }, "needs a person")),
            el("td", {}, e.trade ? words(e.trade) : "—"),
            el("td", {}, e.found === undefined || e.found === null ? "" : String(e.found)))))) : el("p", { class: "muted" }, "No entries were read.")));
    });
    parts.push(el("p", { class: "muted small" }, l.note));
  }
  box.replaceChildren(...parts);
}

// Sprint 10: what the Symbol Recognition Engine counted from the legend, by type and sheet. Proposals until approved.
function symbolCounts(y) {
  const sheets = y.counts.by_sheet;
  const head = el("tr", {}, el("th", {}, "Symbol"), el("th", {}, "Trade"), el("th", {}, "Found"), el("th", {}, "To check"),
    ...sheets.map(sh => el("th", {}, sh.sheet_no || "page " + sh.page_no)));
  const rows = y.counts.by_type.map(t => el("tr", { "data-item": t.item_type || "unknown" },
    el("td", {}, t.item_type ? words(t.item_type) : el("span", { class: "status sample" }, (t.label || "unknown") + " — needs a person")),
    el("td", {}, t.trade ? words(t.trade) : "—"),
    el("td", {}, String(t.count)),
    el("td", {}, t.needs_review ? el("span", { class: "status sample" }, String(t.needs_review)) : "0"),
    ...sheets.map(sh => el("td", {}, String(sh.by_type[t.item_type || "unknown"] || "")))));
  return el("div", { class: "card section", id: "plan-symbols" },
    el("h3", {}, "Symbols found from the legend"),
    el("p", { class: "muted small" }, y.count + " symbol(s). These are proposals: approve them in Blueprint Review before they're priced."),
    el("table", { class: "list symbol-counts" }, el("thead", {}, head), el("tbody", {}, rows)));
}

function scheduleCard(sc, canEdit) {
  const msg = el("div", { role: "status" });
  const cols = [];
  sc.rows.forEach(r => Object.keys(r.fields).forEach(k => { if (!cols.includes(k)) cols.push(k); }));
  const body = el("tbody", {}, sc.rows.map(r => {
    const tr = el("tr", { "data-row": r.id },
      el("td", {}, r.mark || "—"),
      ...cols.slice(1).map(c => el("td", {}, r.fields[c] || "")),
      el("td", {}, r.linked_object_ids.length ? r.linked_object_ids.length + " on plans" : el("span", { class: "status sample" }, "not found")),
      el("td", {}, r.reviewed_by ? "✓ " + r.reviewed_by : ""));
    if (canEdit) {
      const fix = el("button", { class: "button small", type: "button", "data-fix": r.id }, "Correct…");
      fix.addEventListener("click", () => { fix.disabled = true; scheduleRowForm(tr, r, cols, msg); });
      tr.append(el("td", {}, fix));
    }
    return tr;
  }));
  const head = el("tr", {}, el("th", {}, cols[0] || "Mark"), ...cols.slice(1).map(c => el("th", {}, c)),
    el("th", {}, "On the plans"), el("th", {}, "Checked"), canEdit ? el("th", {}, "") : null);
  return el("div", { class: "card section", "data-schedule": sc.id },
    el("h4", {}, sc.title + " — " + (sc.sheet_no || "page " + sc.page_no) + " · " + words(sc.schedule_type)),
    sc.unlinked_marks.length ? el("p", { class: "note warn" }, "Not found on the plans: " + sc.unlinked_marks.join(", ")) : null,
    el("table", { class: "list schedule-rows" }, el("thead", {}, head), body), msg);
}

function scheduleRowForm(tr, row, cols, msg) {
  const mark = el("input", { type: "text", value: row.mark || "", "aria-label": "Mark", id: "sr-mark" });
  const inputs = cols.slice(1).map(c => [c, el("input", { type: "text", value: row.fields[c] || "", "aria-label": c })]);
  const save = el("button", { class: "primary", type: "button", id: "sr-save" }, "Save…");
  save.addEventListener("click", () => {
    const fields = {};
    inputs.forEach(([c, inp]) => { if ((inp.value || "") !== (row.fields[c] || "")) fields[c] = inp.value; });
    const body = {};
    if (Object.keys(fields).length) body.fields = fields;
    if (mark.value.trim() !== (row.mark || "")) body.mark = mark.value.trim();
    if (!Object.keys(body).length) { msg.replaceChildren(el("p", { class: "muted" }, "Nothing changed.")); return; }
    askThen(msg, save, "/schedule-rows/" + row.id, body, () => "Schedule row corrected.", "schedule");
  });
  const form = el("tr", { class: "schedule-row-form" }, el("td", { colspan: String(cols.length + 3) },
    el("div", { class: "row" }, el("label", {}, "Mark", mark), ...inputs.map(([c, inp]) => el("label", {}, c, inp)), save)));
  tr.after(form);
}

// The sheet image comes through the API with the same sign-in as everything else (cookie or the Jobs app's token).
async function sheetImageUrl(sheetId) {
  const headers = APP_TOKEN ? { Authorization: "Bearer " + APP_TOKEN } : {};
  const r = await fetch(API + "/sheets/" + sheetId + "/image", { credentials: "same-origin", headers });
  if (!r.ok) throw new Error("the sheet image couldn't be loaded (" + r.status + ")");
  return URL.createObjectURL(await r.blob());
}

function placeBox(node, box, sheet) {
  // Inline style attributes are blocked by the page's CSP; setting styles from script is allowed.
  const w = parseFloat(sheet.width), h = parseFloat(sheet.height);
  node.style.left = (box[0] / w * 100) + "%";
  node.style.top = (box[1] / h * 100) + "%";
  node.style.width = ((box[2] - box[0]) / w * 100) + "%";
  node.style.height = ((box[3] - box[1]) / h * 100) + "%";
  return node;
}

async function renderSheet(main, id) {
  const r = await api("GET", "/sheets/" + id);
  const s = r.sheet;
  const msg = el("div", { id: "sheet-message", role: "status" });
  const head = [el("p", {}, el("a", { href: "#/plan-sets/" + r.plan_set.id }, "← " + r.plan_set.file)),
    el("div", { class: "page-head" }, el("h2", {}, (s.sheet_no || "Page " + s.page_no) + (s.title ? " — " + s.title : "")), helpLink("plans")),
    el("p", { class: "muted" }, (DISCIPLINE_ICON[s.discipline] || "") + " " + words(s.discipline) +
      (s.revision ? " · rev " + s.revision : "") + (s.revision_date ? " · " + s.revision_date : "") +
      (s.units === "paper_in" && s.width ? " · " + parseFloat(s.width) + "″ × " + parseFloat(s.height) + "″ sheet" : " · drawn in " + s.units))];
  const stage = el("div", { class: "sheet-stage", id: "sheet-stage" });
  const img = el("img", { id: "sheet-image", alt: "Sheet " + (s.sheet_no || s.page_no) });
  stage.append(img);
  for (const v of r.viewports) {
    if (!v.bbox) continue;
    stage.append(placeBox(el("div", { class: "vp-box" + (v.measurable ? "" : v.is_nts ? " nts" : " unscaled"), "data-vp": v.id },
      el("span", {}, (v.label || "View") + " · " + (v.is_nts ? "NTS" : v.scale_note || (v.measurable ? "1:" + v.scale_ratio : "no scale")))), v.bbox, s));
  }
  const parts = [...head];
  if (canOpen("takeoffs")) {
    parts.push(el("p", {}, el("a", { class: "button", id: "sheet-review", href: "#/takeoffs/" + r.plan_set.estimate_id + "?sheet=" + s.id },
      "📏 Measure and approve in Blueprint Review")));
  }
  if (r.found && r.found.length) parts.push(foundSummary(r.found));
  if (s.has_image) {
    // 2026-11-13: zoom and pan to read details (wheel / pinch / buttons / drag). Looking never changes anything,
    // so everyone who can open the plans gets it; changes below stay owner and estimator only (r.can_edit).
    const viewer = el("div", { class: "sheet-viewer", id: "sheet-viewer" }, stage);
    if (s.width && s.height) stage.style.setProperty("--aspect", parseFloat(s.width) / parseFloat(s.height));
    const bar = zoomBar(makeZoomable(viewer, stage, img, { tiles: r.tiles, sheetId: id }));
    bar.insertBefore(viewOnlyButton(stage, !r.can_edit), bar.lastChild);
    parts.push(el("div", { class: "sheet-zoom", id: "sheet-zoom" }, bar, viewer));
    if (!r.can_edit) parts.push(el("p", { class: "muted small", id: "sheet-view-only" }, "View only — your role can look at the plans but not change them."));
    sheetImageUrl(id).then(u => { img.src = u; }).catch(e => stage.replaceChildren(errorBox(e)));
  } else {
    parts.push(el("p", { class: "muted" }, "This sheet has no image yet."));
  }
  parts.push(el("h3", {}, "Views and scales"), viewportTable(r, s, stage, img, msg), msg);
  main.replaceChildren(...parts);
}

// ------------------------------------------------------------------ Sheet viewer: zoom and pan (2026-11-13)
// The stage (image + view boxes + calibration dots, all placed in %) is scaled and moved with a CSS transform inside
// the viewer, so clicks on it still land on the right spot of the drawing (calibration reads getBoundingClientRect).
// Mouse: scroll to zoom at the pointer (scrolling down at full view scrolls the page), drag to move, double-click
// zooms in. Touch: pinch to zoom, drag with one finger once zoomed in. Keys: + − 0 and the arrows.
function makeZoomable(viewer, stage, img, sharp) {
  const MAX = 8;
  const z = { k: 1, x: 0, y: 0, onChange: null };
  // Sharp when zoomed (2026-11-13): the saved sheet picture is at most 150 dpi, so past ~2x it goes soft (worst on a
  // phone, whose screen packs 2-3 pixels per point). Zoomed in, the part on screen is laid over with the same 512 px
  // tiles Blueprint Review uses - re-drawn from the PDF at up to 300 dpi - once the zoom settles.
  const tiles = sharp && sharp.tiles, tileLayer = tiles ? el("div", { class: "sheet-tiles", id: "sheet-tiles" }) : null;
  if (tileLayer) img.after(tileLayer);
  const tileEls = new Map();
  let tileLevel = -1, tileTimer = null;
  const dropTile = (k, n) => { if (n.src && n.src.startsWith("blob:")) URL.revokeObjectURL(n.src); n.remove(); tileEls.delete(k); };
  const updateTiles = () => {
    if (!tiles || !stage.offsetWidth) return;
    const long = Math.max(tiles.width, tiles.height);
    const dpr = window.devicePixelRatio || 1;
    const shownPx = Math.max(stage.offsetWidth, stage.offsetHeight) * z.k * dpr;      // device pixels on the long side
    const basePx = Math.max(img.naturalWidth || 0, img.naturalHeight || 0);
    const want = Math.max(0, Math.min(tiles.max_level, Math.ceil(Math.log2(Math.max(1, shownPx / tiles.tile)))));
    if (shownPx <= basePx * 1.15 || want === 0) { tileEls.forEach((n, k) => dropTile(k, n)); tileLevel = -1; return; }
    if (want !== tileLevel) { tileEls.forEach((n, k) => { if (!k.startsWith(want + "/")) dropTile(k, n); }); tileLevel = want; }
    const size = long / Math.pow(2, want), perPx = tiles.width / stage.offsetWidth;    // sheet units per stage px
    const sx0 = (-z.x / z.k) * perPx, sx1 = ((viewer.clientWidth - z.x) / z.k) * perPx;
    const sy0 = (-z.y / z.k) * perPx, sy1 = ((viewer.clientHeight - z.y) / z.k) * perPx;
    const cols = Math.ceil(tiles.width / size - 1e-9), rows = Math.ceil(tiles.height / size - 1e-9);
    const cx0 = Math.max(0, Math.floor(sx0 / size)), cx1 = Math.min(cols - 1, Math.floor(sx1 / size));
    const cy0 = Math.max(0, Math.floor(sy0 / size)), cy1 = Math.min(rows - 1, Math.floor(sy1 / size));
    if ((cx1 - cx0 + 1) * (cy1 - cy0 + 1) > 120) return;                               // never a flood of requests
    for (let x = cx0; x <= cx1; x++) for (let y = cy0; y <= cy1; y++) {
      const k = want + "/" + x + "/" + y;
      if (tileEls.has(k)) continue;
      const w = Math.min(size, tiles.width - x * size), h = Math.min(size, tiles.height - y * size);
      const n = el("img", { class: "sheet-tile", alt: "", draggable: "false", "data-tile": k });
      n.style.left = (x * size / tiles.width * 100) + "%"; n.style.top = (y * size / tiles.height * 100) + "%";
      n.style.width = (w / tiles.width * 100) + "%"; n.style.height = (h / tiles.height * 100) + "%";
      n.addEventListener("load", () => n.classList.add("ready"), { once: true });
      tileEls.set(k, n);
      tileLayer.append(n);
      const path = "/estimator-api/sheets/" + sharp.sheetId + "/tiles/" + want + "/" + x + "/" + y + ".png";
      (typeof tileUrl === "function" ? tileUrl(sharp.sheetId, want, x, y) : Promise.resolve(path))
        .then(u => { if (tileEls.get(k) === n) n.src = u; }).catch(() => dropTile(k, n));
    }
  };
  const scheduleTiles = () => { if (!tiles) return; clearTimeout(tileTimer); tileTimer = setTimeout(updateTiles, 150); };
  const size = () => ({ vw: viewer.clientWidth, vh: viewer.clientHeight, w: stage.offsetWidth, h: stage.offsetHeight });
  const fit1 = (pos, content, box) => content <= box ? (box - content) / 2 : Math.min(0, Math.max(box - content, pos));
  const apply = () => {
    const { vw, vh, w, h } = size();
    if (z.k <= 1.0001) z.k = 1;
    z.x = fit1(z.x, w * z.k, vw); z.y = fit1(z.y, h * z.k, vh);      // smaller than the viewer: centred
    stage.style.transform = "translate(" + z.x + "px, " + z.y + "px) scale(" + z.k + ")";
    viewer.classList.toggle("zoomed", z.k > 1);
    viewer.style.touchAction = z.k > 1 ? "none" : "pan-y";        // at full view one finger still scrolls the page
    if (z.onChange) z.onChange(z.k);
    scheduleTiles();
  };
  const zoomAt = (factor, cx, cy) => {
    const k = Math.min(MAX, Math.max(1, z.k * factor));
    z.x = cx - (cx - z.x) * k / z.k;
    z.y = cy - (cy - z.y) * k / z.k;
    z.k = k;
    apply();
  };
  const local = ev => { const b = viewer.getBoundingClientRect(); return [ev.clientX - b.left, ev.clientY - b.top]; };
  const centre = () => [viewer.clientWidth / 2, viewer.clientHeight / 2];

  viewer.addEventListener("wheel", ev => {
    if (z.k === 1 && ev.deltaY > 0) return;                       // let the page scroll past the sheet
    ev.preventDefault();
    zoomAt(Math.exp(-ev.deltaY * 0.0015), ...local(ev));
  }, { passive: false });

  const pts = new Map();
  let last = null, pinch = null, moved = 0;
  const onMove = ev => {
    if (!pts.has(ev.pointerId)) return;
    pts.set(ev.pointerId, [ev.clientX, ev.clientY]);
    if (pts.size >= 2) {
      const [a, b] = [...pts.values()];
      const d = Math.hypot(a[0] - b[0], a[1] - b[1]);
      const box = viewer.getBoundingClientRect();
      const mid = [(a[0] + b[0]) / 2 - box.left, (a[1] + b[1]) / 2 - box.top];
      if (pinch) { zoomAt(d / pinch.d, ...mid); z.x += mid[0] - pinch.mid[0]; z.y += mid[1] - pinch.mid[1]; apply(); }
      pinch = { d, mid }; moved += 10;
      return;
    }
    if (!last || z.k === 1) return;
    const dx = ev.clientX - last[0], dy = ev.clientY - last[1];
    moved += Math.abs(dx) + Math.abs(dy);
    last = [ev.clientX, ev.clientY];
    if (moved > 4) { viewer.classList.add("panning"); z.x += dx; z.y += dy; apply(); }
  };
  const onUp = ev => {
    pts.delete(ev.pointerId);
    pinch = null;
    last = pts.size === 1 ? [...pts.values()][0] : null;
    if (!pts.size) {
      viewer.classList.remove("panning");
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    }
  };
  viewer.addEventListener("pointerdown", ev => {
    if (ev.button > 0) return;
    if (!pts.size) {
      moved = 0;
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
      window.addEventListener("pointercancel", onUp);
    }
    pts.set(ev.pointerId, [ev.clientX, ev.clientY]);
    last = [ev.clientX, ev.clientY];
    if (z.k > 1) ev.preventDefault();                             // no image drag / text selection while moving
  });
  // A drag isn't a click: don't let the end of a pan place a calibration point.
  viewer.addEventListener("click", ev => { if (moved > 4) { ev.stopPropagation(); ev.preventDefault(); moved = 0; } }, true);
  viewer.addEventListener("dblclick", ev => {
    if (stage.classList.contains("calibrating")) return;
    ev.preventDefault();
    zoomAt(2, ...local(ev));
  });
  img.addEventListener("dragstart", ev => ev.preventDefault());
  viewer.tabIndex = 0;
  viewer.setAttribute("aria-label", "Plan sheet — use + and − to zoom, the arrow keys to move, 0 to see the whole sheet");
  viewer.addEventListener("keydown", ev => {
    const step = 60;
    const keys = { "+": () => zoomAt(1.4, ...centre()), "=": () => zoomAt(1.4, ...centre()), "-": () => zoomAt(1 / 1.4, ...centre()),
                   "0": () => { z.k = 1; apply(); }, ArrowLeft: () => { z.x += step; apply(); }, ArrowRight: () => { z.x -= step; apply(); },
                   ArrowUp: () => { z.y += step; apply(); }, ArrowDown: () => { z.y -= step; apply(); } };
    if (keys[ev.key] && (z.k > 1 || !ev.key.startsWith("Arrow"))) { ev.preventDefault(); keys[ev.key](); }
  });
  window.addEventListener("resize", () => { if (viewer.isConnected) apply(); });
  return {
    zoomIn: () => zoomAt(1.4, ...centre()), zoomOut: () => zoomAt(1 / 1.4, ...centre()),
    fit: () => { z.k = 1; apply(); }, get k() { return z.k; },
    set onChange(f) { z.onChange = f; }, refresh: apply, viewer,
  };
}

// "View only" (2026-11-13): hides the boxes AI-Prowler draws over the sheet (each view it found, with its scale or
// NTS) so the plan reads like the original drawing. On by default for people who can't change the plans (field
// crew); each person's choice is kept by this browser.
function viewOnlyButton(stage, defaultOn) {
  const KEY = "est_sheet_view_only";
  let on = defaultOn;
  try { const saved = localStorage.getItem(KEY); if (saved !== null) on = saved === "1"; } catch (e) { /* private mode */ }
  const b = el("button", { class: "button small", type: "button", id: "view-only",
    title: "Hide the view boxes AI-Prowler draws over the sheet (they show each view's scale, or NTS = not to scale)" });
  const set = v => {
    on = v;
    stage.classList.toggle("views-hidden", on);
    b.setAttribute("aria-pressed", on ? "true" : "false");
    b.textContent = on ? "👁 View only: on" : "👁 View only: off";
  };
  b.addEventListener("click", () => { set(!on); try { localStorage.setItem(KEY, on ? "1" : "0"); } catch (e) { /* ignore */ } });
  set(on);
  return b;
}

function zoomBar(zoom) {
  const pct = el("span", { class: "zoom-pct", id: "zoom-pct" }, "100%");
  zoom.onChange = k => { pct.textContent = Math.round(k * 100) + "%"; };
  const btn = (id, label, title, fn) => el("button", { class: "button small", type: "button", id, title, "aria-label": title, onclick: fn }, label);
  const bar = el("div", { class: "row zoom-bar", id: "zoom-bar" },
    btn("zoom-out", "−", "Zoom out", () => zoom.zoomOut()), pct, btn("zoom-in", "+", "Zoom in", () => zoom.zoomIn()),
    btn("zoom-fit", "Fit", "See the whole sheet", () => zoom.fit()));
  const box = zoom.viewer;
  if (document.fullscreenEnabled) {
    const full = btn("zoom-full", "⛶ Full screen", "Full screen (Esc to leave)", () => {
      const wrap = box.parentElement;
      if (document.fullscreenElement) document.exitFullscreen(); else if (wrap) wrap.requestFullscreen().catch(() => {});
    });
    document.addEventListener("fullscreenchange", () => {
      if (!box.isConnected) return;
      full.textContent = document.fullscreenElement ? "✕ Exit full screen" : "⛶ Full screen";
      zoom.fit();
    });
    bar.append(full);
  }
  bar.append(el("span", { class: "muted small" }, "Scroll or pinch to zoom · drag to move · double-click to zoom in"));
  return bar;
}

// Sprint 6: what the plan engine found on the sheet (walls, rooms, symbols...), with measured totals.
const KIND_WORDS = { room: "rooms", wall: "walls", symbol: "symbols", dimension: "dimensions", text: "notes",
                     polygon: "shapes", polyline: "paths", line: "lines", opening: "openings" };
function foundSummary(found) {
  const items = found.map(f => {
    const parts = [f.count + " " + (KIND_WORDS[f.kind] || words(f.kind))];
    if (f.measured && parseFloat(f.area_sqft) > 0) parts.push(Math.round(parseFloat(f.area_sqft)).toLocaleString() + " sq ft");
    else if (f.measured && parseFloat(f.length_ft) > 0) parts.push(Math.round(parseFloat(f.length_ft)).toLocaleString() + " ft");
    if (f.measured < f.count && ["room", "wall"].includes(f.kind)) parts.push((f.count - f.measured) + " not measured yet — set the scale");
    return el("li", { "data-kind": f.kind }, parts.join(" · "));
  });
  return el("div", { class: "card section", id: "sheet-found" }, el("strong", {}, "Found on this sheet"),
    el("ul", { class: "checklist" }, items));
}

function viewportTable(r, s, stage, img, msg) {
  if (!r.viewports.length) return el("div", { class: "card empty" }, "No views were found on this sheet. "
    + "The plan engine couldn't find a scaled view - try re-reading the plan set, or upload a clearer copy.");
  const paper = s.units === "paper_in";
  return el("table", { class: "list", id: "viewports" },
    el("thead", {}, el("tr", {}, el("th", {}, "View"), el("th", {}, "Scale"), el("th", {}, "How it was found"),
      r.can_edit && paper ? el("th", {}, "Change it") : null)),
    el("tbody", {}, r.viewports.map(v => el("tr", { "data-vp": v.id },
      el("td", {}, v.label || "View " + v.id),
      el("td", {}, v.is_nts ? "Not to scale (NTS)" : v.measurable ? (v.scale_note || "1 : " + v.scale_ratio) + " — 1″ = " + v.scale_ratio + "″" :
        el("span", { class: "status sample" }, "no scale yet")),
      el("td", {}, words(v.scale_method) + (v.scale_confidence && v.scale_method !== "none" ? " (" + Math.round(parseFloat(v.scale_confidence) * 100) + "%)" : "") +
        (v.scale_set_by ? " · set by " + v.scale_set_by : "")),
      r.can_edit && paper ? el("td", {}, scaleControls(v, s, stage, img, msg)) : null))));
}

function scaleControls(v, s, stage, img, msg) {
  const note = el("input", { class: "scale-note", "data-vp": v.id, maxlength: 60, placeholder: "1/4\" = 1'-0\"  ·  1:100  ·  NTS",
                             "aria-label": "Scale note for " + (v.label || "this view") });
  const set = el("button", { class: "button", type: "button", "data-set": v.id }, "Set…");
  set.addEventListener("click", () => {
    if (!note.value.trim()) { msg.replaceChildren(el("p", { class: "error" }, "Type the scale as written on the drawing, e.g. 1/4\" = 1'-0\".")); note.focus(); return; }
    askThen(msg, set, "/viewports/" + v.id + "/scale", { scale_note: note.value.trim() }, x => "Scale set; " + x.measured + " object(s) re-measured.", "scale");
  });
  const cal = el("button", { class: "button", type: "button", "data-calibrate": v.id }, "📏 Calibrate…");
  cal.addEventListener("click", () => startCalibration(v, s, stage, img, msg));
  return el("div", { class: "row" }, note, set, cal);
}

// Two-point calibration: click both ends of something whose real length you know, then type that length.
function startCalibration(v, s, stage, img, msg) {
  if (!img.src) { msg.replaceChildren(el("p", { class: "error" }, "Wait for the sheet image to load.")); return; }
  for (const m of stage.querySelectorAll(".cal-dot")) m.remove();
  const points = [];
  stage.classList.add("calibrating");
  msg.replaceChildren(el("p", { class: "note", id: "cal-help" }, "Click one end of a known distance on the drawing (a dimension line or a door), then the other end."));
  stage.scrollIntoView({ block: "nearest" });
  const onClick = ev => {
    const box = img.getBoundingClientRect();
    if (ev.clientX < box.left || ev.clientX > box.right || ev.clientY < box.top || ev.clientY > box.bottom) return;
    const x = (ev.clientX - box.left) / box.width * parseFloat(s.width);
    const y = (ev.clientY - box.top) / box.height * parseFloat(s.height);
    points.push([Math.round(x * 1000) / 1000, Math.round(y * 1000) / 1000]);
    stage.append(placeBox(el("div", { class: "cal-dot" }), [x, y, x, y], s));
    if (points.length < 2) return;
    stage.removeEventListener("click", onClick);
    stage.classList.remove("calibrating");
    const dist = el("input", { id: "cal-distance", maxlength: 30, placeholder: "12'-6\"", "aria-label": "Real distance" });
    const ok = el("button", { class: "primary", type: "button", id: "cal-set" }, "Set the scale…");
    const again = el("button", { class: "button", type: "button", id: "cal-again" }, "Start over");
    const paperIn = Math.hypot(points[1][0] - points[0][0], points[1][1] - points[0][1]);
    msg.replaceChildren(el("div", { class: "card section", id: "cal-box" },
      el("p", {}, "The two points are " + paperIn.toFixed(2) + "″ apart on the paper. How long is that in real life?"),
      el("div", { class: "row" }, el("label", {}, "Real distance", dist), ok, again)));
    dist.focus();
    again.addEventListener("click", () => startCalibration(v, s, stage, img, msg));
    ok.addEventListener("click", () => {
      if (!dist.value.trim()) { dist.focus(); return; }
      const box2 = el("div", { id: "cal-confirm" });
      msg.append(box2);
      askThen(box2, ok, "/viewports/" + v.id + "/scale", { calibration: { p1: points[0], p2: points[1], distance: dist.value.trim() } },
        x => "Calibrated: 1″ = " + x.viewport.scale_ratio + "″; " + x.measured + " object(s) re-measured.", "cal");
    });
  };
  stage.addEventListener("click", onClick);
}

// ------------------------------------------------------------------ Help link ("?" on each screen, Sprint 4)
function helpLink(screenId) {
  // Sprint 18: "?" opens the help panel (guides for this screen + Replay tour) without leaving
  // the screen. If tour.js failed to load, fall back to the full Help screen.
  return el("button", { class: "button help-link", type: "button", id: "help-link", title: "How-to guides for this screen",
    "aria-label": "Help for this screen",
    onclick: () => { if (typeof openHelpPanel === "function") openHelpPanel(screenId); else go("#/help?screen=" + screenId); } }, "❓ Help");   // 2026-11-12: a word, not just "?"
}

// ------------------------------------------------------------------ Jobs board (Sprint 4, quick lane)
const LANES = [["needs_triage", "Needs a decision"], ["project", "Projects"], ["quick_quote", "Quick quotes"],
               ["standard_estimate", "Standard estimates"], ["full_takeoff", "Plan takeoffs"]];
const WAITING = { user: "you", approver: "an approver", staff: "office staff", customer: "the customer", feature: "a later feature" };

async function renderJobs(main) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const mine = q.get("mine") === "1", done = q.get("done") === "1";
  const b = await api("GET", "/jobs?" + new URLSearchParams({ mine: mine ? "1" : "", done: done ? "1" : "" }));
  const parts = [el("p", {}, el("a", { href: "#/dashboard" }, "← Dashboard")),
    el("div", { class: "page-head" }, el("h2", {}, "📋 Jobs board"),
      el("div", { class: "row" }, b.can_start ? el("a", { class: "primary button", href: "#/quick", id: "jobs-quick" }, "⚡ New quick quote") : null,
        helpLink("jobs"))),
    el("p", { class: "muted" }, "Every job the Director is running, by lane: what it's on and who it's waiting for. " +
      "Chat jobs (est_director_start) show here too.")];
  const mineBox = el("input", { type: "checkbox", id: "jobs-mine", checked: mine });
  const doneBox = el("input", { type: "checkbox", id: "jobs-done", checked: done });
  const refilter = () => { location.hash = "#/jobs?" + new URLSearchParams({ mine: mineBox.checked ? "1" : "", done: doneBox.checked ? "1" : "" }); };
  mineBox.addEventListener("change", refilter);
  doneBox.addEventListener("change", refilter);
  parts.push(el("div", { class: "row filters" }, el("label", { class: "check" }, mineBox, " Mine only"),
    el("label", { class: "check" }, doneBox, " Show finished")));
  if (!b.count) {
    parts.push(el("div", { class: "card empty", id: "jobs-empty" }, "No jobs yet — start one with ⚡ New quick quote, or ask your AI to quote a job."));
  } else if (b.summary) {
    const w = b.summary.waiting;
    parts.push(el("p", { class: "row", id: "jobs-summary" },
      ...LANES.filter(([lane]) => b.summary.by_lane[lane]).map(([lane, label]) => el("span", { class: "chip" }, label + ": " + b.summary.by_lane[lane])),
      w.you ? el("span", { class: "chip warn" }, w.you + " waiting on you") : null,
      w.customer ? el("span", { class: "chip" }, w.customer + " waiting on the customer") : null));
  }
  for (const [lane, label] of LANES) {
    const rows = (b.by_lane || {})[lane];
    if (!rows || !rows.length) continue;
    const plansLane = lane === "full_takeoff" || lane === "standard_estimate" || lane === "project";
    parts.push(el("h3", {}, label + " (" + rows.length + ")"), el("table", { class: "list clickable", "data-lane": lane },
      el("thead", {}, el("tr", {}, el("th", {}, "#"), el("th", {}, "Job"), el("th", {}, "Step"), el("th", {}, "Waiting on"),
        plansLane ? el("th", {}, "Progress") : null, el("th", {}, "Updated"))),
      el("tbody", {}, rows.map(r => el("tr", { "data-id": r.id, onclick: () => go("#/jobs/" + r.id) },
        el("td", {}, r.id),
        el("td", {}, el("a", { href: "#/jobs/" + r.id }, r.request_text || words(r.module_id) || "Job " + r.id)),
        el("td", {}, el("span", { class: "status" }, words(r.stage)), r.state === "done" ? " ✓" : "",
          r.progress && r.progress.step ? el("div", { class: "muted small" }, "step " + r.progress.step.number + " of " + r.progress.step.of +
            (r.progress.step.next && r.state !== "done" ? " · then " + r.progress.step.next : "")) : null),
        el("td", {}, r.state === "done" ? "—" : (WAITING[r.waiting_on] || words(r.waiting_on) || "—")),
        plansLane ? el("td", { class: "job-progress" }, ...jobProgress(r, b.links || {})) : null,
        el("td", {}, when(r.updated_at)))))));
  }
  main.replaceChildren(...parts);
}

// Sprint 10: where a plans job stands - plans read, symbols found, measurements approved, the runner's trades, reviews.
function jobProgress(r, links) {
  const p = r.progress || {}, out = [], eid = r.estimate_id;
  const stop = ev => ev.stopPropagation();
  if (p.plans) {
    const pl = p.plans;
    const text = "📐 " + pl.sheets + " sheet(s)" + (pl.processing ? " · reading…" : "") + (pl.failed ? " · " + pl.failed + " failed" : "") +
      (pl.need_scale ? " · " + pl.need_scale + " need a scale" : "");
    out.push(el("div", {}, links.plans && eid ? el("a", { href: "#/projects/" + eid, onclick: stop }, text) : text));
  } else if (eid) {
    out.push(el("div", { class: "muted" }, "📐 no plans yet"));
  }
  if (p.symbols) out.push(el("div", {}, "🔣 " + p.symbols.found + " symbol(s)" + (p.symbols.to_check ? " · " + p.symbols.to_check + " to check" : "")));
  if (p.takeoff) {
    const t = p.takeoff;
    const text = "📏 " + t.approved + " approved" + (t.proposed ? " · " + t.proposed + " waiting" : "") + (t.suggested ? " · " + t.suggested + " suggested change(s)" : "");
    out.push(el("div", {}, links.takeoffs && eid ? el("a", { href: "#/takeoffs/" + eid, onclick: stop }, text) : text));
  }
  if (p.runner) {
    const rn = p.runner;
    out.push(el("div", {}, "⚙ " + rn.completed + "/" + rn.trades + " trade(s) done" + (rn.needs_review ? " · " + rn.needs_review + " to review" : "") +
      (rn.failed ? " · " + rn.failed + " failed" : "")));
  }
  if (p.reviews) out.push(el("div", {}, "🔍 " + p.reviews.in_review + " review(s) open"));
  if (links.estimates && eid) out.push(el("div", {}, el("a", { href: "#/estimates/" + eid, onclick: stop }, "🧮 estimate")));
  return out.length ? out : ["—"];
}

// One job: what the Director needs next, with the controls to give it.
async function renderJob(main, id) {
  const j = await api("GET", "/jobs/" + id);
  state.jobEstimate = j.job.estimate_id;
  const ns = j.next_step || {};
  const est = j.estimate_detail;
  const parts = [el("p", {}, el("a", { href: "#/jobs" }, "← Jobs board")),
    el("div", { class: "page-head" }, el("h2", {}, j.job.request_text || ("Job " + j.job.id)), helpLink("jobs")),
    el("p", { class: "muted" }, words(j.job.lane || "needs triage") + " · step: " + words(j.job.stage) +
      (est ? " · estimate #" + est.id + " (" + words(est.status) + ")" : ""))];
  if (est && est.totals) parts.push(el("div", { class: "big-money", id: "job-total" }, money(est.totals.total_cents)));
  const box = el("div", { class: "card section", id: "job-next" });
  if (j.job.lane === "project" && est) parts.push(directorPanel(est.id));   // a project job: the same panel as the project page
  else {
    parts.push(box);
    nextStepBox(box, j, ns);
  }
  if (j.bid) {
    parts.push(el("div", { class: "card section", id: "job-bid" }, el("strong", {}, "Quote " + j.bid.number),
      " · " + words(j.bid.status) + " · " + money(j.bid.total_cents) + (j.bid.sent_to ? " · sent to " + j.bid.sent_to : ""),
      j.can_open_bids ? el("p", {}, el("a", { href: "#/bids/" + j.bid.id, id: "job-open-bid" }, "Open the quote")) : null));
  }
  const links = el("p", {}, est ? el("a", { href: "#/projects/" + est.id }, "Open the project") : null);
  parts.push(links);
  if (j.steps && j.steps.length) {
    parts.push(el("details", { class: "card section", id: "job-steps" }, el("summary", {}, "What's been done (" + j.steps.length + ")"),
      el("ul", { class: "checklist" }, j.steps.map(s => el("li", {}, words(s.stage) + " — " + words(s.state) +
        (s.input_summary ? ": " + s.input_summary : "") + " (" + (s.actor || "") + ", " + when(s.started_at) + ")")))));
  }
  main.replaceChildren(...parts);
}

function nextStepBox(box, j, ns, notes) {
  const done = j.job.state === "done" || j.job.state === "cancelled";
  const kids = [el("strong", {}, done ? "Finished" : "Next step")];
  for (const n of notes || []) kids.push(el("p", { class: "note warn" }, n));
  if (ns.say) kids.push(el("p", { id: "job-say" }, ns.say));
  if (ns.error) kids.push(el("p", { class: "error" }, "The last step didn't work (" + words(ns.error) + ")."));
  const msg = el("div", { id: "job-message", role: "status" });
  if (!done) kids.push(...nextControls(j, ns, msg));
  kids.push(msg);
  box.replaceChildren(...kids);
}

// The Director's next step decides which controls show: questions, a module choice, approve, send, won/lost, convert.
function nextControls(j, ns, msg) {
  const out = [];
  const asks = Array.isArray(ns.ask) ? ns.ask : [];
  const questions = asks.filter(a => a && typeof a === "object" && a.type);
  const choices = asks.filter(a => typeof a === "string" || (a && typeof a === "object" && !a.type && a.id));
  if (questions.length) {
    const form = el("form", { id: "job-answers" }, el("div", { class: "qgrid" }, questions.concat(ns.optional || []).map(questionInput)),
      el("button", { class: "primary", type: "submit", id: "job-answer" }, "Send answers"));
    form.addEventListener("submit", ev => {
      ev.preventDefault();
      const answers = {};
      for (const i of form.querySelectorAll("[data-q]")) {
        if (i.type === "checkbox") answers[i.dataset.q] = i.checked;
        else if (i.value !== "") answers[i.dataset.q] = i.tagName === "SELECT" ? i.value : Number(i.value);
      }
      step(j, { answers }, msg);
    });
    out.push(form);
  }
  if (choices.length) {
    out.push(el("div", { class: "row", id: "job-choices" }, choices.map(c => {
      const mid = typeof c === "string" ? c : c.id;
      return el("button", { class: "button", type: "button", "data-module": mid,
                            onclick: () => step(j, { module_id: mid }, msg) }, typeof c === "string" ? words(c) : (c.name || words(mid)));
    })));
  }
  if (ns.stage === "approve" || ns.approval) {
    const checks = [];
    let checklist = null, samples = null;
    if (ns.checklist && ns.checklist.length) {
      checklist = el("input", { type: "checkbox", id: "job-checklist" });
      checks.push(el("label", { class: "check" }, checklist, " Checked: " + ns.checklist.join("; ")));
    }
    if (ns.sample_prices && ns.sample_prices.length) {
      samples = el("input", { type: "checkbox", id: "job-samples" });
      checks.push(el("label", { class: "check" }, samples, " Use the sample prices anyway (" + ns.sample_prices.join(", ") + ")"));
    }
    const roles = ns.approver_roles || [];
    const mayApprove = !roles.length || roles.includes(state.me.role);
    const approve = el("button", { class: "primary", type: "button", id: "job-approve", disabled: !mayApprove,
                                   title: mayApprove ? null : "Only " + roles.join(" or ") + " can approve this" }, "✓ Approve");
    approve.addEventListener("click", () => step(j, { approve: true, checklist_done: checklist ? checklist.checked : false,
                                                      confirm_sample_prices: samples ? samples.checked : false }, msg));
    out.push(...checks, el("div", { class: "row" }, approve,
      mayApprove ? null : el("span", { class: "muted" }, "Waiting for " + roles.join(" or ") + " to approve.")));
  }
  if (ns.stage === "review" || ns.reviewer_roles) {
    const ok = (ns.reviewer_roles || []).includes(state.me.role);
    const sign = el("button", { class: "primary", type: "button", id: "job-review", disabled: !ok }, "Sign off the review");
    sign.addEventListener("click", () => step(j, { reviewed: true }, msg));
    out.push(el("div", { class: "row" }, sign, ok ? null : el("span", { class: "muted" }, "An owner or reviewer signs this off.")));
  }
  if (ns.bid_id && ns.stage !== "follow_up" && !ns.follow_up_on && j.bid && j.bid.status === "draft") {
    const to = el("input", { type: "email", id: "job-send-to", value: ns.send_to || "", placeholder: "customer@example.com",
                             "aria-label": "Customer email" });
    const send = el("button", { class: "primary", type: "button", id: "job-send" }, "📨 Send the quote…");
    send.addEventListener("click", () => {
      if (!to.value.trim()) { msg.replaceChildren(el("p", { class: "error" }, "Enter the customer's email address.")); to.focus(); return; }
      step(j, { send: true, send_to: to.value.trim() }, msg);
    });
    out.push(el("div", { class: "row" }, el("label", {}, "Send to", to), send));
  }
  const followUp = ns.follow_up_on !== undefined || ns.stage === "follow_up";
  if (followUp && j.bid && j.bid.status !== "won") {
    out.push(el("div", { class: "row", id: "job-outcome" },
      el("button", { class: "primary", type: "button", id: "job-won", onclick: () => step(j, { outcome: "won" }, msg) }, "👍 Customer said yes"),
      el("button", { class: "button", type: "button", id: "job-lost", onclick: () => step(j, { outcome: "lost" }, msg) }, "Customer said no")));
  }
  if (j.bid && j.bid.status === "won" && !j.bid.job_id) {
    const date = el("input", { type: "date", id: "job-service-date", "aria-label": "Service date" });
    const name = el("input", { id: "job-customer-name", maxlength: 200, value: (j.bid.customer && j.bid.customer.name) || "",
                               placeholder: "Customer name", "aria-label": "Customer name" });
    const conv = el("button", { class: "primary", type: "button", id: "job-convert" }, "Make it a job in AI-Prowler…");
    conv.addEventListener("click", () => step(j, { convert: true, service_date: date.value || null,
                                                   ...(name.value.trim() ? { customer: { name: name.value.trim() } } : {}) }, msg));
    out.push(el("div", { class: "row" }, el("label", {}, "Customer", name), el("label", {}, "Service date (optional)", date), conv));
  }
  return out;
}

// Send one est_director_next step. Emailing a customer or creating a job asks a yes/no question first.
async function step(j, body, msg, confirmed) {
  state.busy = true;
  msg.replaceChildren(el("p", { class: "muted" }, "Working…"));
  try {
    const r = await api("POST", "/jobs/" + j.job.id + "/next", { ...body, rev: j.job.rev, ...(confirmed ? { confirm: true } : {}) });
    if (r.needs_confirmation) {
      const yes = el("button", { class: "primary", type: "button", id: "job-confirm" }, "Yes");
      const no = el("button", { class: "button", type: "button", id: "job-cancel" }, "Cancel");
      msg.replaceChildren(el("div", { class: "confirm", id: "job-confirm-box" }, el("p", {}, el("strong", {}, r.question)),
        el("div", { class: "row" }, yes, no)));
      no.addEventListener("click", () => { state.busy = false; msg.replaceChildren(el("p", { class: "muted" }, "Cancelled — nothing was sent.")); });
      yes.addEventListener("click", () => { yes.disabled = no.disabled = true; step(j, body, msg, true); });
      yes.focus();
      return;
    }
    state.busy = false;
    if (j.after) await j.after(r.notes || []);           // the Director panel on a project or estimate page
    else await renderJobKeepNotes(j.job.id, r.notes || []);
  } catch (e) {
    state.busy = false;
    if (e.status === 401) return;
    msg.replaceChildren(errorBox(e));
  }
}

// Redraw the job and keep the Director's notes (e.g. "not approved: it still uses sample prices") on top.
async function renderJobKeepNotes(id, notes) {
  await renderJob($("main"), id);
  const box = $("job-next");
  if (box && notes.length) box.insertBefore(el("div", { id: "job-notes" }, notes.map(n => el("p", { class: "note warn" }, n))), box.children[1] || null);
}

// ------------------------------------------------------------------ Director panel (2026-11-12, David)
// Every project has a Director job. The panel on the project and estimate pages says what to do next and why, ticks
// off the steps done, and carries the buttons through to approving, sending the quote and the customer's answer.
function directorPanel(eid) {
  const card = el("div", { class: "card section director-panel", id: "director-panel" },
    el("p", { class: "muted" }, "🧭 Director: looking at where this project stands…"));
  loadDirectorPanel(card, eid, []);
  return card;
}

async function loadDirectorPanel(card, eid, notes) {
  let d;
  try { d = await api("POST", "/estimates/" + eid + "/director", {}); }
  catch (e) {
    if (e.status === 401) return;
    card.replaceChildren(el("strong", {}, "🧭 Director"), errorBox(e));
    return;
  }
  if (!d.job) { card.replaceChildren(el("strong", {}, "🧭 Director"), el("p", { class: "muted" }, "This project is finished.")); return; }
  const j = { ...d, after: n => loadDirectorPanel(card, eid, n) };
  const ns = d.next_step || {};
  const done = d.job.state === "done" || d.job.state === "cancelled";
  const kids = [el("div", { class: "page-head" }, el("strong", {}, "🧭 Director — " + (done ? "finished" : "next step")),
    el("a", { href: "#/jobs/" + d.job.id, id: "director-job-link", class: "small" }, "Job " + d.job.id + " · all steps →"))];
  for (const n of notes || []) kids.push(el("p", { class: "note warn" }, n));
  if (ns.say) kids.push(el("p", { id: "director-say" }, el("strong", {}, ns.say)));
  if (ns.why) kids.push(el("p", { class: "muted small", id: "director-why" }, "Why: " + ns.why + "."));
  if (ns.error) kids.push(el("p", { class: "error" }, "The last step didn't work (" + words(ns.error) + ")."));
  if (Array.isArray(ns.todo) && ns.todo.length) {
    kids.push(el("ul", { class: "checklist", id: "director-todo" }, ns.todo.map(t => el("li", { "data-key": t.key, class: t.done ? "done" : "" },
      (t.done ? "✅ " : "⬜ ") , t.link && !t.done ? el("a", { href: t.link }, t.text) : t.text))));
  }
  const msg = el("div", { id: "director-message", role: "status" });
  if (!done && ns.stage === "build") {
    if (ns.needs_customer) {
      const name = el("input", { id: "director-cust-name", maxlength: 200, placeholder: "Customer name", "aria-label": "Customer name" });
      const email = el("input", { id: "director-cust-email", type: "email", maxlength: 200, placeholder: "customer@example.com",
                                  "aria-label": "Customer email" });
      const save = el("button", { class: "button", type: "button", id: "director-cust-save" }, "Save the customer");
      save.addEventListener("click", () => {
        const c = { name: name.value.trim(), email: email.value.trim() };
        if (!c.name && !c.email) { msg.replaceChildren(el("p", { class: "error" }, "Enter a name or an email.")); return; }
        step(j, { customer: c }, msg);
      });
      kids.push(el("div", { class: "row", id: "director-customer" }, el("label", {}, "Customer", name), el("label", {}, "Email", email), save));
    }
    const ready = el("button", { class: "primary", type: "button", id: "director-ready", disabled: !ns.ready_ok,
                                 title: ns.ready_ok ? null : "Price something on the estimate first" },
      "✓ The estimate is ready — check it and get it approved");
    ready.addEventListener("click", () => step(j, { ready: true }, msg));
    kids.push(el("div", { class: "row" }, ready));
  } else if (!done) {
    kids.push(...nextControls(j, ns, msg));
  }
  if (d.bid && d.can_open_bids) kids.push(el("p", {}, el("a", { href: "#/bids/" + d.bid.id, id: "director-open-bid" },
    "Quote " + d.bid.number + " · " + words(d.bid.status) + " · " + money(d.bid.total_cents))));
  kids.push(msg);
  card.replaceChildren(...kids);
}

// ------------------------------------------------------------------ Bids (Sprint 4)
const BID_STATUSES = ["draft", "sent", "viewed", "won", "lost", "expired", "void"];

async function renderBids(main, screen) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const status = BID_STATUSES.includes(q.get("status")) ? q.get("status") : "";
  const list = await api("GET", "/bids" + (status ? "?status=" + status : ""));
  const pick = el("select", { id: "bids-status", "aria-label": "Status" }, el("option", { value: "" }, "All quotes"),
    BID_STATUSES.map(s => el("option", { value: s, selected: s === status }, words(s))));
  pick.addEventListener("change", () => { location.hash = "#/bids" + (pick.value ? "?status=" + pick.value : ""); });
  const parts = [el("div", { class: "page-head" }, el("h2", {}, screen.label), helpLink("bids")),
    el("p", { class: "muted" }, "Quotes made from estimates. Open one to see it as the customer will, send it, mark the answer, or make it a job."),
    el("div", { class: "row filters" }, el("label", {}, "Status", pick))];
  if (!list.bids.length) {
    parts.push(el("div", { class: "card empty", id: "bids-empty" }, "No quotes yet — price a job (⚡ Quick estimate), approve it, and the quote is made for you."));
  } else {
    parts.push(el("table", { class: "list clickable", id: "bids" },
      el("thead", {}, el("tr", {}, el("th", {}, "Quote"), el("th", {}, "Customer"), el("th", {}, "Status"), el("th", {}, "Total"),
        el("th", {}, "Valid until"))),
      el("tbody", {}, list.bids.map(b => el("tr", { "data-id": b.id, onclick: () => go("#/bids/" + b.id) },
        el("td", {}, el("a", { href: "#/bids/" + b.id }, b.number), b.version > 1 ? " (v" + b.version + ")" : ""),
        el("td", {}, (b.customer && (b.customer.name || b.customer.email)) || "—"),
        el("td", {}, el("span", { class: "status" }, words(b.status)), b.job_id ? " → " + b.job_id : ""),
        el("td", { class: "money" }, money(b.total_cents)),
        el("td", {}, b.valid_until || ""))))));
  }
  main.replaceChildren(...parts);
}

async function renderBid(main, id) {
  const b = await api("GET", "/bids/" + id);
  const msg = el("div", { id: "bid-message", role: "status" });
  const parts = [el("p", {}, el("a", { href: "#/bids" }, "← Bids")),
    el("div", { class: "page-head" }, el("h2", {}, "Quote " + b.number), helpLink("bids")),
    el("p", { class: "muted" }, words(b.status) + " · " + money(b.total_cents) + " · valid until " + (b.valid_until || "—") +
      (b.sent_to ? " · sent to " + b.sent_to + " " + when(b.sent_at) : "") + (b.job_id ? " · job " + b.job_id : ""))];
  const fileUrl = API + "/bids/" + b.id + "/file?kind=";
  if (!APP_TOKEN) {
    // The quote as the customer sees it: its own HTML, in a sandboxed frame (no scripts, nothing from outside).
    parts.push(el("iframe", { class: "bid-frame", id: "bid-frame", title: "Quote " + b.number, sandbox: "", src: fileUrl + "html" }),
      el("p", {}, el("a", { href: fileUrl + "html", target: "_blank", rel: "noopener" }, "Open in a new tab"),
        b.has_pdf ? " · " : null, b.has_pdf ? el("a", { href: fileUrl + "pdf", id: "bid-pdf" }, "Download the PDF") : null));
  } else {
    // Inside the Jobs app the sign-in is a Bearer token, which a frame or a plain link can't send: show the text
    // copy, and fetch the PDF with the token.
    parts.push(el("pre", { class: "bid-text card section", id: "bid-text-main" }, b.text || ""));
    if (b.has_pdf) {
      const dl = el("button", { class: "button", type: "button", id: "bid-pdf" }, "Download the PDF");
      dl.addEventListener("click", async () => {
        try {
          const r = await fetch(fileUrl + "pdf", { headers: { Authorization: "Bearer " + APP_TOKEN } });
          if (!r.ok) throw new Error("the PDF couldn't be downloaded (" + r.status + ")");
          const url = URL.createObjectURL(await r.blob());
          const a = el("a", { href: url, download: b.number + ".pdf" });
          document.body.append(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 10000);
        } catch (e) { msg.replaceChildren(errorBox(e)); }
      });
      parts.push(el("p", {}, dl));
    }
  }
  const acts = [];
  if (["draft", "sent", "viewed"].includes(b.status)) {
    const to = el("input", { type: "email", id: "bid-to", value: (b.customer && b.customer.email) || b.sent_to || "",
                             placeholder: "customer@example.com", "aria-label": "Customer email" });
    const note = el("input", { id: "bid-note", maxlength: 500, placeholder: "Short message (optional)", "aria-label": "Message" });
    const send = el("button", { class: "primary", type: "button", id: "bid-send" }, b.status === "draft" ? "📨 Send…" : "📨 Send again…");
    send.addEventListener("click", () => askThen(msg, send, "/bids/" + b.id + "/send", { to: to.value.trim() || null, message: note.value.trim() || null },
      r => "Sent " + b.number + " to " + r.sent_to + ((r.warnings || []).length ? " — " + r.warnings[0] : "")));
    acts.push(el("div", { class: "row" }, el("label", {}, "Send to", to), el("label", {}, "Message", note), send));
  }
  if (["sent", "viewed"].includes(b.status)) {
    acts.push(el("div", { class: "row", id: "bid-outcome" },
      statusButton(b, "won", "👍 Won", msg), statusButton(b, "lost", "Lost", msg), statusButton(b, "viewed", "Customer viewed it", msg)));
  }
  if (["draft", "sent", "viewed"].includes(b.status)) acts.push(el("div", { class: "row" }, statusButton(b, "void", "Void this quote", msg)));
  if (["sent", "viewed", "won"].includes(b.status) && !b.job_id) {
    const date = el("input", { type: "date", id: "bid-service-date", "aria-label": "Service date" });
    const name = el("input", { id: "bid-customer-name", maxlength: 200, value: (b.customer && b.customer.name) || "",
                               placeholder: "Customer name", "aria-label": "Customer name" });
    const conv = el("button", { class: "primary", type: "button", id: "bid-convert" }, "Make it a job in AI-Prowler…");
    conv.addEventListener("click", () => askThen(msg, conv, "/bids/" + b.id + "/convert",
      { service_date: date.value || null, customer: name.value.trim() ? { name: name.value.trim() } : null },
      r => r.already_converted ? "Already a job: " + r.job_id : "Created " + Object.entries(r.created || {}).filter(([, v]) => v).map(([k, v]) => k.replace(/_/g, " ") + " " + v).join(", ")));
    acts.push(el("div", { class: "row" }, el("label", {}, "Customer", name), el("label", {}, "Service date (optional)", date), conv));
  }
  parts.push(el("div", { class: "card section", id: "bid-actions" }, acts.length ? acts : el("p", { class: "muted" }, "Nothing more to do on this quote.")), msg);
  parts.push(el("details", { class: "card section" }, el("summary", {}, "Plain-text copy"), el("pre", { class: "bid-text" }, b.text || "")));
  main.replaceChildren(...parts);
}

function statusButton(b, status, label, msg) {
  const btn = el("button", { class: status === "won" ? "primary" : "button", type: "button", id: "bid-" + status }, label);
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      await api("POST", "/bids/" + b.id + "/status", { status });
      toast(b.number + " marked " + words(status));
      route();
    } catch (e) { if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
    finally { btn.disabled = false; }
  });
  return btn;
}

// Ask the server's yes/no question (needs_confirmation), then repeat the call with confirm=true.
async function askThen(msg, btn, path, body, doneText, prefix) {
  const p = prefix || "bid";                             // ids for the page's tests: bid-confirm, plan-confirm, ...
  btn.disabled = true;
  state.busy = true;
  msg.replaceChildren();
  try {
    const r = await api("POST", path, body);
    if (!r.needs_confirmation) { state.busy = false; toast(doneText(r)); route(); return; }
    const yes = el("button", { class: "primary", type: "button", id: p + "-confirm" }, "Yes");
    const no = el("button", { class: "button", type: "button", id: p + "-cancel" }, "Cancel");
    msg.replaceChildren(el("div", { class: "confirm", id: p + "-confirm-box" }, el("p", {}, el("strong", {}, r.question)), el("div", { class: "row" }, yes, no)));
    yes.focus();
    no.addEventListener("click", () => { state.busy = false; msg.replaceChildren(el("p", { class: "muted" }, "Cancelled — nothing changed.")); });
    yes.addEventListener("click", async () => {
      yes.disabled = no.disabled = true;
      try {
        const done = await api("POST", path, { ...body, confirm: true });
        state.busy = false;
        toast(doneText(done));
        route();
      } catch (e) { state.busy = false; if (e.status !== 401) msg.replaceChildren(errorBox(e)); }
    });
  } catch (e) {
    state.busy = false;
    if (e.status !== 401) msg.replaceChildren(errorBox(e));
  } finally { btn.disabled = false; }
}

// ------------------------------------------------------------------ Help: how-to guides (Sprint 4, first guides)
async function renderHelp(main, screen) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const text = (q.get("q") || "").slice(0, 200), forScreen = q.get("screen") || "";
  const r = await api("GET", "/help/guides?" + new URLSearchParams({ q: text, screen: forScreen }));
  const find = el("input", { type: "search", id: "help-find", value: text, placeholder: "e.g. how do I send a quote?", "aria-label": "Search the guides" });
  const form = el("form", { class: "row filters" }, el("label", {}, "Search", find), el("button", { class: "button", type: "submit" }, "Search"));
  form.addEventListener("submit", ev => { ev.preventDefault(); location.hash = "#/help?" + new URLSearchParams({ q: find.value.trim() }); });
  const parts = [el("h2", {}, screen.label), el("p", { class: "muted" }, "Step-by-step guides. You can also ask your AI — e.g. \"how do I send a quote?\""), form];
  if (forScreen) parts.push(el("p", {}, "Guides for the " + words(forScreen) + " screen · ", el("a", { href: "#/help" }, "all guides")));
  parts.push(r.guides.length
    ? el("ul", { class: "guides", id: "help-list" }, r.guides.map(g => el("li", {}, el("a", { href: "#/help/" + g.id }, g.title),
        g.steps ? el("span", { class: "muted small" }, " · " + g.steps + " steps") : null)))
    : el("div", { class: "card empty" }, "No guide matches that yet. Try fewer words, or ask your AI."));
  if (typeof TOUR_IDS !== "undefined" && typeof tourReplayBtn === "function") {
    // Sprint 18: replay any guided tour, with its done/skipped state.
    const prog = typeof tourLoadProgress === "function" ? await tourLoadProgress() : {};
    parts.push(el("h3", {}, "Guided tours"));
    parts.push(el("p", { class: "muted" }, "A short walkthrough of each screen, pointing at the real controls. "
      + "A tour runs the first time you open its screen; replay any of them here."));
    parts.push(el("ul", { class: "guides", id: "help-tours" }, TOUR_IDS.map(id =>
      el("li", {}, TOUR_BY_ID[id] ? TOUR_BY_ID[id].title : id,
        prog[id] === "completed" ? el("span", { class: "muted small" }, " - done") : null,
        prog[id] === "skipped" ? el("span", { class: "muted small" }, " - skipped") : null,
        " ", tourReplayBtn(id)))));
  }
  main.replaceChildren(...parts);
}

async function renderGuide(main, id) {
  const g = (await api("GET", "/help/guides/" + encodeURIComponent(id))).guide;
  main.replaceChildren(el("p", {}, el("a", { href: "#/help" }, "← All guides")), el("h2", {}, g.title),
    el("div", { class: "card section guide", id: "guide" }, markdown(g.text)));
}

// A tiny Markdown reader for the guides: headings, numbered steps, bullets, paragraphs, **bold** and `code`.
// Everything goes in as text nodes, so a guide can never inject HTML.
function markdown(text) {
  const out = [];
  let list = null, kind = "";
  const inline = s => s.split(/(\*\*[^*]+\*\*|`[^`]+`)/).filter(Boolean).map(p =>
    p.startsWith("**") ? el("strong", {}, p.slice(2, -2)) : p.startsWith("`") ? el("code", {}, p.slice(1, -1)) : p);
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    const num = line.match(/^\d+\.\s+(.*)$/), bullet = line.match(/^[-*]\s+(.*)$/), head = line.match(/^(#{2,4})\s+(.*)$/);
    if (num || bullet) {
      const want = num ? "ol" : "ul";
      if (!list || kind !== want) { list = el(want, {}); kind = want; out.push(list); }
      list.append(el("li", {}, inline((num || bullet)[1])));
      continue;
    }
    list = null;
    if (!line) continue;
    if (head) out.push(el(head[1].length === 2 ? "h3" : "h4", {}, head[2]));
    else out.push(el("p", {}, inline(line)));
  }
  return out;
}

function renderComing(main, screen) {
  main.replaceChildren(el("div", { class: "coming-page" },
    el("h2", {}, screen.icon + " " + screen.label),
    el("p", {}, "This screen is coming in Sprint " + screen.sprint + "."),
    el("p", { class: "muted" }, "Until then you can do the same things by asking your AI (Claude, Grok or Muse) — it uses these Estimator tools:"),
    el("ul", {}, screen.tools.map(t => el("li", {}, el("code", {}, t))))));
}

const SCREENS = { quick: (m) => renderQuick(m, null), jobs: (m) => renderJobs(m, null), dashboard: renderDashboard, projects: renderProjects, plans: renderPlans, price_book: renderPriceBook,
                  bids: renderBids, help: renderHelp };
const PAGES = { project: renderProject, quick: renderQuick, start: renderStart, jobs: renderJobs, job: renderJob, bid: renderBid, guide: renderGuide,
                plan_set: renderPlanSet, sheet: renderSheet };

// ------------------------------------------------------------------ live updates
function setLive(cls, title) { const l = $("live"); l.className = "live " + cls; l.title = title; }

let refreshTimer = null;
function onChange(ev) {
  state.cursor = ev.id;
  if (ev.actor && state.me && ev.actor !== state.me.user_id) {
    toast("Updated by " + ev.actor + (ev.estimate_id ? " (estimate " + ev.estimate_id + ")" : ""));
  }
  const listScreen = (!state.page && ["dashboard", "projects", "bids", "jobs"].includes(state.screen)) || state.page === "jobs";
  const thisProject = state.page === "project" && ev.estimate_id === state.pageArg;
  const thisJob = state.page === "job" && ev.estimate_id === state.jobEstimate;   // e.g. approved in chat
  if (!listScreen && !thisProject && !thisJob) return;             // never redraw the quick-estimate form under the user
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
  // EventSource can't send an Authorization header, so with the Jobs app's token the page polls instead.
  if (window.EventSource && !APP_TOKEN) {
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

// ------------------------------------------------------------------ "a new version is installed" (2026-11-13)
// An open page keeps running the code it loaded, so after an update is installed and AI-Prowler restarted, nothing
// changed until someone reloaded by hand. The server reports a hash of the web app's files (/health -> build); the
// page remembers the one it started with and checks again when it comes back into view, on a screen change (at
// most once a minute) and every 10 minutes. A different build shows a banner: Refresh now, or Later (it comes back
// on the next screen change, like the Jobs app's). Nothing reloads by itself - someone may be mid-edit.
// Inside the Jobs app the Jobs app's own banner covers this (its version includes the Estimator's files).
let webBuild = null, updateWaiting = false, lastUpdateCheck = 0;
async function checkForUpdate(force) {
  if (!force && Date.now() - lastUpdateCheck < 60000) return;
  lastUpdateCheck = Date.now();
  try {
    const r = await fetch(API + "/health", { cache: "no-store", credentials: "same-origin" });
    const b = r.ok ? (await r.json()).build : null;
    if (!b) return;
    if (webBuild === null) webBuild = b;
    else if (b !== webBuild) { updateWaiting = true; showUpdateBanner(); }
  } catch (e) { /* offline or restarting: try again later */ }
}
function showUpdateBanner() {
  if (!updateWaiting || document.getElementById("update-banner")) return;
  const later = el("button", { class: "button", type: "button", id: "update-later" }, "Later");
  const now = el("button", { class: "primary", type: "button", id: "update-refresh", onclick: () => location.reload() }, "🔄 Refresh now");
  const bar = el("div", { class: "update-banner", id: "update-banner", role: "status" },
    el("span", {}, "A newer version of the Estimator is installed."), now, later);
  later.addEventListener("click", () => bar.remove());
  document.body.append(bar);
}
function watchForUpdates() {
  if (EMBEDDED) return;
  checkForUpdate(true);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") checkForUpdate(true); });
  window.addEventListener("hashchange", () => { showUpdateBanner(); checkForUpdate(false); });
  setInterval(() => checkForUpdate(true), 10 * 60 * 1000);
}

// ------------------------------------------------------------------ boot
async function boot() {
  if (EMBEDDED) document.body.classList.add("embedded");   // inside the Jobs app's Estimates tab
  $("login-form").addEventListener("submit", doLogin);
  $("logout").addEventListener("click", doLogout);
  $("menu-toggle").addEventListener("click", () => $("nav").classList.toggle("open"));
  window.addEventListener("hashchange", route);
  watchForUpdates();
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
