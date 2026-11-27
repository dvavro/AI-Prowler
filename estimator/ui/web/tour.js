/* Guided tours and the help panel (Coder 2 Sprint 18; spec: How-to-use guide and guided tour).
 *
 * Loaded after app.js (el, $, api, state, words, go, helpLink) and after the other
 * screen scripts, so every SCREENS/PAGES render is already in place. Plain JavaScript,
 * no libraries (spec: self-contained, works offline). All text goes in as text nodes.
 *
 * - A tour is data: {id, title, steps: [{sel, title, body, go}]}. sel names a control
 *   that really exists on that screen; a step whose control isn't there (role-gated,
 *   empty list) is skipped. go navigates first (the practice tour walks across screens).
 * - 2026-11-21, David: tours only start when asked — "🎓 Show me this screen" beside each
 *   screen's Help button, the help panel, or the Help screen. The Director walks the user
 *   through the work, so the tours stick to explaining each screen's controls and never
 *   pop up on their own, and nothing is tracked (no done / skipped).
 * - The "?" on each screen (helpLink) opens the help panel: the guides for that screen,
 *   searchable, plus a Replay tour button. #/help stays the full-page route.
 */
"use strict";

// ------------------------------------------------------------------ tour data

// The spec's five first, in menu order, then the rest of the screens and pages.
const TOURS = [
  { id: "dashboard", title: "Dashboard", steps: [
    { sel: "#dash-quick", title: "Start a quote in two minutes",
      body: "⚡ Quick estimate asks a few questions and prices a service job — no plans needed." },
    { sel: "#dash-jobs", title: "The Jobs board",
      body: "📋 Jobs board shows every job the Director is running, and who each one is waiting for." },
    { sel: "#attention", title: "Needs attention",
      body: "Estimates waiting for review, and work assigned to you, land here first." },
    { sel: ".tiles", title: "Your numbers",
      body: "Click a number to see every estimate with that status." },
    { sel: "#nav a[data-screen=\"projects\"]", title: "The menu",
      body: "Every screen is in the left menu. On any screen, 🎓 Show me this screen walks you through its controls." },
  ]},
  // 2026-11-21: starting a project and uploading its plans are the Director's job (it walks the user
  // through them), so those steps came out; the tours explain the controls.
  { id: "projects", title: "Projects", steps: [
    { sel: "#filter-status", title: "Find by status",
      body: "Filter the list to one status — draft, approved, sent, won or lost." },
    { sel: "#filter-text", title: "Find by name",
      body: "Type a few letters of the customer or address to narrow the list." },
  ]},
  { id: "project", title: "Project page", steps: [
    { sel: "#project-estimate", title: "Open the estimate",
      body: "🧮 Open the estimate shows every trade, line and total, and which measurements each line came from." },
    { sel: "#project-review", title: "Measure from plans (takeoff)",
      body: "📏 Measure from plans (takeoff) is where plans get measured and approved — only after the plans have been read." },
    { sel: "#trades", title: "Trades priced so far",
      body: "Each trade's subtotal and biggest lines. Nothing shows here until a trade is priced." },
  ]},
  { id: "plans", title: "Plans", steps: [
    { sel: "#plan-sets", title: "Every plan set",
      body: "Each upload is a plan set, with its sheets, revision and whether it's been read." },
    { sel: "#nav a[data-screen=\"takeoffs\"]", title: "Next: measure them",
      body: "Once a set is read, its measurements are checked in Measure from plans (takeoff)." },
    { sel: ".help-link", title: "Stuck?",
      body: "❓ Help on any screen opens the guides for that screen, without leaving it. 🎓 Show me this screen, next to it, runs a walkthrough like this one." },
  ]},
  { id: "plan_set", title: "Plan set", steps: [
    { sel: "#plan-read", title: "Read the plans",
      body: "Read the plans runs the plan engine: sheets, scales, symbols and schedules. It asks first." },
    { sel: "#plan-compare", title: "Compare a revision",
      body: "When a revised set arrives, compare it with the one it replaces — every change is drawn over the plan." },
    { sel: "#sheets", title: "Sheets",
      body: "Click a sheet to see its viewports and scales, and to open it in Measure from plans (takeoff)." },
  ]},
  { id: "sheet", title: "Sheet", steps: [
    { sel: "#sheet-stage", title: "The sheet",
      body: "The plan itself, with each viewport outlined. Click a viewport to see what it holds." },
    { sel: "#viewports", title: "Views and scales",
      body: "Every view on this sheet and its scale. A view with no scale can't be measured until it's set." },
    { sel: "#sheet-review", title: "Open in Measure from plans (takeoff)",
      body: "Measure and approve from here — lengths, areas and counts, straight off the plan." },
  ]},
  { id: "takeoffs", title: "Measure", steps: [
    { sel: "#takeoff-projects", title: "Measurements by project",
      body: "Open a project to check the plans, measure, and approve what gets priced." },
    { sel: ".help-link", title: "How to measure",
      body: "The ? opens the measuring guide — lengths, areas, counts, and fixing a wrong number." },
  ]},
  { id: "takeoff", title: "Measure from plans (takeoff)", steps: [
    { sel: "#bp-viewer", title: "The plan, tiled",
      body: "Pan and zoom the sheet. Pick a tool (📏 Length, ⬠ Area…) and draw on the plan to measure." },
    { sel: "#bp-pane-list", title: "Measurements",
      body: "Click a number to see every item on the plan. Each measurement links back to where it was drawn." },
    { sel: "#bp-act-confirm", title: "Approve it",
      body: "Approve a measurement and it locks — that's what gets priced. Nothing is approved automatically." },
    { sel: "#bp-quantities", title: "Plan quantities",
      body: "📐 Plan quantities works out rooms, walls, doors and windows from the whole plan set." },
  ]},
  { id: "reviews", title: "Reviews", steps: [
    { sel: "#reviews-list", title: "Symbols to check",
      body: "Symbols the plan engine counted from each plan set's legend. Open one to approve, take out the wrong ones, or give unknown ones a name." },
    { sel: ".help-link", title: "How to check counts",
      body: "The ? opens the checking guide — approve, take out, relabel, and find more like one." },
  ]},
  { id: "symbol_review", title: "Check symbols", steps: [
    { sel: "#symrev-types", title: "Filter by type",
      body: "Narrow the grid to one kind of symbol — outlets, switches, fixtures — to check them in batches." },
    { sel: "#symrev-grid", title: "Each detection",
      body: "Click one to see it on the sheet. Approve the right ones, take out the wrong ones." },
    { sel: "#symrev-add", title: "Add a missed one",
      body: "A symbol the engine missed gets added here: pick its sheet, point at it, and name it." },
  ]},
  { id: "estimates", title: "Estimates", steps: [
    { sel: "#estimates-status", title: "Filter by status",
      body: "Show only drafts, or only sent or won estimates." },
    { sel: "#estimates-list", title: "Every estimate",
      body: "Open one to see its trades and lines — each line links back to the measurement that priced it." },
  ]},
  { id: "estimate", title: "Estimate", steps: [
    { sel: "#estimate-actions", title: "What you can do here",
      body: "Recalculate, check, look at the history, and once it's approved: reopen it for changes, or make a change order after the customer says yes." },
    { sel: "#estimate-calc", title: "Recalculate",
      body: "Works out every line from the approved measurements and your Price Book." },
    { sel: "#estimate-validate", title: "Check it",
      body: "Checks the estimate before it goes out — missing prices, lines with no measurement, totals that don't add up." },
    { sel: "#estimate-reopen", title: "Reopen for changes",
      body: "Change an approved or sent estimate in place. The next approval shows only what changed, and a sent quote is replaced by one that says what changed." },
    { sel: "#estimate-change-order", title: "Change order",
      body: "The customer said yes and now wants more or different work: a change order is priced and quoted on its own, and adds to the job." },
    { sel: "#estimate-revise", title: "New version",
      body: "A separate editable copy (v2, v3…) of an approved estimate. The original stays unchanged." },
    { sel: "#estimate-totals", title: "The total",
      body: "Every trade and the lines added by hand, with the cost, the price with markups, and the overhead, profit and tax inside the total." },
  ]},
  { id: "quantities", title: "Plan quantities", steps: [
    { sel: "#qty-height", title: "Ceiling height",
      body: "For rooms the finish schedule doesn't give a height for — 8 ft unless the plans say otherwise." },
    { sel: "#qty-apply", title: "Work it out again",
      body: "Change the height or the counting rules and work the quantities out again." },
    { sel: "#qty-totals", title: "The totals",
      body: "Floor and wall areas, wall lengths, doors and windows — from the whole plan set at once." },
  ]},
  { id: "bids", title: "Bids", steps: [
    { sel: "#bids-status", title: "Filter by status",
      body: "Show only the quotes still out, or the ones already won or lost." },
    { sel: "#bids", title: "Every quote",
      body: "Open one to preview it, send it, mark it won or lost, or turn a won quote into a job." },
  ]},
  { id: "bid", title: "Quote", steps: [
    { sel: "#bid-frame", title: "The quote itself",
      body: "This is what the customer sees — the same preview that goes in the email." },
    { sel: "#bid-send", title: "Send the quote",
      body: "Sends it to the customer by email. It asks first, and the send is logged." },
    { sel: "#bid-convert", title: "Won it? Make it a job",
      body: "Turns a won quote into a job in AI-Prowler — no re-typing the customer or the price." },
  ]},
  { id: "price_book", title: "Price Book", steps: [
    { sel: "#pb-module", title: "Pick a trade",
      body: "Filter the prices to one trade or service." },
    { sel: "#pb-find", title: "Find a price",
      body: "Type a few letters to find a price by name." },
    { sel: "#pb-markups", title: "On top of these costs",
      body: "Overhead, profit, labor burden and tax — what gets added to every cost. Change them in Settings." },
    { sel: "#pb-import-box", title: "Import a supplier's list",
      body: "Paste a supplier's prices and check the columns — new prices and changed ones are previewed before anything is saved." },
  ]},
  { id: "symbol_library", title: "Symbol Library", steps: [
    { sel: "#symlib-trade", title: "Filter by trade",
      body: "Show only one trade's symbols." },
    { sel: "#symlib-new", title: "Teach a new symbol",
      body: "New symbol… defines what a symbol means, so the plan engine counts it next time." },
    { sel: "#symlib-export", title: "Export and import",
      body: "Export the library to a file, or import one — handy for moving your symbols to another PC." },
  ]},
  { id: "agents", title: "Agents", steps: [
    { sel: "#agents-settings-where", title: "Trade settings",
      body: "Which trades you quote, and how sure each trade's measuring agent must be, are set once in AI-Prowler's 🏗 Estimator tab → 🏗 Trades. This screen shows them." },
    // 2026-11-21: the AI Auto Measure/Count runs are listed here too, every trade.
    { sel: "#auto-runs-head", title: "AI Auto Measure/Count runs",
      body: "Every 🤖 AI Auto Measure/Count from the Measure screen, for every trade: how it went, what it proposed, what its AI calls cost, and why it failed if it did." },
    { sel: "#runs-list", title: "Director measure runs",
      body: "The Director starts one run per plan job. Open one to see each trade's task and what it's waiting on." },
  ]},
  { id: "reports", title: "Reports", steps: [
    { sel: "#report-tabs", title: "Five reports",
      body: "Win / loss, the measurements report, plan revisions, estimate vs actual, and exports." },
    { sel: "#report-body", title: "Pick a project",
      body: "Most tabs start by picking a project — the numbers are for that project alone." },
  ]},
  { id: "revision", title: "Plan revision", steps: [
    { sel: "#rev-svg", title: "The overlay",
      body: "Green is added, red (dashed) is removed, orange is changed or moved — drawn over the new sheet." },
    { sel: "#rev-flagged", title: "Measure again",
      body: "Measurements touching a change are flagged to re-measure. Click one to open it in Measure from plans (takeoff)." },
    { sel: "#rev-sheet", title: "Old or new",
      body: "Flip between the old sheet and the new one to see what moved." },
  ]},
  { id: "settings", title: "Settings", steps: [
    { sel: "#settings-tabs", title: "Eight sections",
      body: "Company, money, bids, approvals, AI, people, data, and the audit log. Owner only." },
    { sel: "#settings-body", title: "Change one thing",
      body: "Every change asks first and shows the old and new values before it saves." },
  ]},
  { id: "jobs", title: "Jobs board", steps: [
    { sel: "#jobs-quick", title: "New quick quote",
      body: "⚡ New quick quote starts a service job — the same flow as Quick estimate, tracked here." },
    { sel: "#jobs-mine", title: "Mine only",
      body: "Show only the jobs assigned to you." },
    { sel: "#jobs-summary", title: "By lane",
      body: "Jobs grouped by lane — what each one is on, and who it's waiting for." },
  ]},
  { id: "job", title: "Job", steps: [
    { sel: "#job-next", title: "The next step",
      body: "One step at a time: what the job needs now, and who it's waiting on." },
    { sel: "#job-approve", title: "Approve it",
      body: "Approve the quote and the customer details, and the job moves on." },
    { sel: "#job-send", title: "Send it",
      body: "Sends the quote to the customer. The send is logged on the job." },
  ]},
  { id: "quick", title: "Quick estimate", steps: [
    { sel: "#quick-module", title: "Pick the service",
      body: "Pressure washing, roof cleaning, and the rest — one service per quote." },
    { sel: "#quick-title", title: "Name it",
      body: "The job name and address — what shows on the quote and the Jobs board." },
    { sel: "#quick-price", title: "Price it",
      body: "Answer the questions and the price works itself out from your Price Book." },
    { sel: "#quick-next", title: "Next step",
      body: "Next: approve and send takes you to the job page. Or open the project to price the estimate by hand." },
  ]},
  { id: "help", title: "Help", steps: [
    { sel: "#help-find", title: "Search the guides",
      body: "Type what you're trying to do — \"send a quote\", \"fix a missed outlet\" — and the guide shows up." },
    { sel: "#help-list", title: "Every guide",
      body: "Step-by-step guides for the common jobs. Guided tours are listed below — replay any of them." },
  ]},
  { id: "practice", title: "Practice project: first estimate end to end", steps: [
    { sel: "#project-estimate", go: "#/projects/{practice}", title: "Start on the practice project",
      body: "This is Practice: Garcia house - safe data, not a real job. It never counts in your win/loss numbers." },
    { sel: "#plan-upload", go: "#/projects/{practice}", title: "Upload the plans",
      body: "Plans go here — a PDF, a photo, or a DXF/DWG. Pick the file and AI-Prowler reads the sheets." },
    { sel: "#bp-viewer", go: "#/takeoffs/{practice}", title: "Check the scale",
      body: "Open a sheet and check its scale — every measurement depends on it. A view with no scale gets set with two clicks on a known distance." },
    { sel: "#bp-pane-list", go: "#/takeoffs/{practice}", title: "Review the counts",
      body: "Every measurement the plan engine found is listed here. Click a number to see it on the plan." },
    { sel: "#reviews-list", go: "#/reviews", title: "Fix a missed outlet",
      body: "In Reviews, check the symbols the legend gave. A missed outlet gets added here, a wrong one relabelled — counts only price once they're approved." },
    { sel: "#bp-act-confirm", go: "#/takeoffs/{practice}", title: "Approve the measurements",
      body: "Approve a measurement and it locks — that's what gets priced. Nothing is approved automatically." },
    { sel: "#estimate-calc", go: "#/estimates/{practice}", title: "Price it",
      body: "Recalculate works out every line from the approved measurements and your Price Book." },
    { sel: "#bids-status", go: "#/bids", title: "Send the quote",
      body: "Once the estimate is approved the quote is made for you. It shows here — open it, check it, and press Send." },
  ]},
];
// The phone tour lives in mobile.js (it knows the phone controls); pick it up here.
if (typeof MREV_TOUR !== "undefined" && MREV_TOUR) TOURS.push(MREV_TOUR);

const TOUR_BY_ID = {};
for (const t of TOURS) TOUR_BY_ID[t.id] = t;
const TOUR_IDS = TOURS.map(t => t.id);

// ------------------------------------------------------------------ engine

let tourCurrent = null;          // {def, step, practiceId, shown}
let tourPop = null;              // the pop-up element
// 2026-11-21: tours only run when asked, so done / skipped isn't tracked (the server's tour-progress endpoint is unused).

// Which tour belongs to the screen the user is on (app.js: state.screen/state.page).
const TOUR_SCREEN = { quick: "quick", jobs: "jobs", dashboard: "dashboard", projects: "projects", plans: "plans", takeoffs: "takeoffs",
  reviews: "reviews", estimates: "estimates", bids: "bids", price_book: "price_book",
  symbol_library: "symbol_library", agents: "agents", reports: "reports", settings: "settings", help: "help" };
const TOUR_PAGE = { project: "project", quick: "quick", jobs: "jobs", job: "job", bid: "bid",
  plan_set: "plan_set", sheet: "sheet", takeoff: "takeoff", estimate: "estimate",
  symbol_review: "symbol_review", quantities: "quantities", revision: "revision", mobile_reviews: "mobile" };
function tourIdForPage() {
  if (state.page) return TOUR_PAGE[state.page] || null;
  return TOUR_SCREEN[state.screen] || null;
}

async function tourPractice() {
  try { return await api("GET", "/help/practice"); } catch (e) { return { estimate_id: null, title: null }; }
}

// 2026-11-21: tours never start on their own any more (the Director guides the work).
// "🎓 Show me this screen" (helpLink in app.js) calls this: the tour for the screen the user is on.
function tourForThisScreen(fallback) {
  const id = tourIdForPage();
  if (id && TOUR_BY_ID[id]) return id;
  return fallback && TOUR_BY_ID[fallback] ? fallback : null;
}
function showMeThisScreen(fallback) {
  const id = tourForThisScreen(fallback);
  if (!id) { toast("There's no walkthrough for this screen yet — ❓ Help has its guides."); return; }
  if (typeof closeHelpPanel === "function") closeHelpPanel();
  if (tourCurrent) tourClose();
  startTour(id);
}

// Start a tour (from Show me this screen, the Help screen, or the help panel).
async function startTour(id) {
  const def = TOUR_BY_ID[id];
  if (!def || tourCurrent) return;
  if (id === "practice") {
    const p = await tourPractice();
    if (!p.estimate_id) {
      // No practice project yet: one step that says how to make it.
      tourCurrent = { def: { id: "practice", title: def.title, steps: [
        { title: "First, make the practice project",
          body: "Ask your AI for the sample project (\"make the practice project\"), or start it from Projects — the tour walks the practice project end to end once it exists." } ] },
        step: 0, practiceId: null };
      tourShow(0);
      return;
    }
    tourCurrent = { def: def, step: 0, practiceId: p.estimate_id };
    tourShow(0);
    return;
  }
  tourCurrent = { def: def, step: 0, practiceId: null };
  tourShow(0);
}

// Show step i of the running tour (i >= steps.length finishes it).
function tourShow(i) {
  const cur = tourCurrent;
  if (!cur) return;
  const steps = cur.def.steps;
  if (i >= steps.length) { tourFinish(); return; }
  const step = steps[i];
  cur.step = i;
    let go = step.go ? step.go.replace("{practice}", String(cur.practiceId || "")) : null;
    if (go && !go.includes("?")) {
      // Keep this screen’s filter: a step that goes to #/m/reviews while the
      // user is on #/m/reviews?kind=symbol must not drop ?kind=symbol (the
      // phone queue would show every waiting item, not the filtered kind).
      // Only the same path keeps its query — a step moving to another screen
      // must not carry this screen’s query with it.
      const qAt = location.hash.indexOf("?");
      if (qAt >= 0 && location.hash.slice(0, qAt) === go) go += location.hash.slice(qAt);
    }
    if (go && location.hash !== go) {
    tourPopHide();
    tourClearMark();
    location.hash = go;
    tourWaitFor(step, go, 0);
    return;
  }
  tourShowStep(step);
}

// After a tour-driven navigation, wait up to 3 s for the step's control to appear.
function tourWaitFor(step, go, tries) {
  const cur = tourCurrent;
  if (!cur) return;
  if (location.hash !== go) { tourClose(); return; }   // the user navigated away: stop the tour
  if (!step.sel || document.querySelector(step.sel)) { tourShowStep(step); return; }
  if (tries >= 25) { tourShow(cur.step + 1); return; } // control never appeared: skip the step
  setTimeout(() => tourWaitFor(step, go, tries + 1), 120);
}

// Show one step: anchor the pop-up on its control (or centre it for a step with no control).
function tourShowStep(step) {
  const cur = tourCurrent;
  if (!cur) return;
  const target = step.sel ? document.querySelector(step.sel) : null;
  if (step.sel && !target) { tourShow(cur.step + 1); return; }  // control not on this screen: skip
  if (target) target.scrollIntoView({ block: "center" });
  cur.shown = true;                       // at least one step was really shown (tourFinish)
  tourMark(target);
  const pop = tourPopEl();
  $("tour-title").textContent = step.title;
  $("tour-body").textContent = step.body;
  $("tour-count").textContent = "Step " + (cur.step + 1) + " of " + cur.def.steps.length + " — " + cur.def.title;
  $("tour-next").textContent = cur.step === cur.def.steps.length - 1 ? "Finish" : "Next";
  $("tour-back").disabled = cur.step === 0;
  pop.hidden = false;
  tourPlace(target);
}

function tourNext() { if (tourCurrent) tourShow(tourCurrent.step + 1); }
function tourBack() { if (tourCurrent && tourCurrent.step > 0) tourShow(tourCurrent.step - 1); }
// 2026-11-21, David: tours only run when asked, so finishing one isn't tracked any more (and "Skip tour" went:
// it was the same as ✕).
function tourFinish() {
  if (!tourCurrent) return;
  const shown = !!tourCurrent.shown;
  tourClose();
  // None of its controls were on this screen, so nothing showed - say so.
  if (!shown) toast("That walkthrough's controls aren't on this screen. Open its screen and click 🎓 Show me this screen.");
}
function tourClose() {   // X: close without saving anything
  tourPopHide();
  tourClearMark();
  tourCurrent = null;
}

function tourPopEl() {
  if (tourPop) return tourPop;
  tourPop = el("div", { id: "tour-pop", class: "tour-pop", role: "dialog", "aria-label": "Guided tour", hidden: true },
    el("div", { class: "tour-head" },
      el("strong", { id: "tour-title" }, ""),
      el("button", { class: "link-btn", type: "button", id: "tour-x", "aria-label": "Close the tour" }, "✕")),
    el("p", { id: "tour-body" }, ""),
    el("div", { class: "tour-foot" },
      el("span", { class: "muted small", id: "tour-count" }, ""),
      el("span", { class: "tour-btns" },
        el("button", { class: "button", type: "button", id: "tour-back" }, "← Back"),
        el("button", { class: "primary", type: "button", id: "tour-next" }, "Next"))));
  document.body.append(tourPop);
  $("tour-back").addEventListener("click", tourBack);
  $("tour-next").addEventListener("click", tourNext);
  $("tour-x").addEventListener("click", tourClose);
  window.addEventListener("resize", tourPlaceCurrent);
  document.addEventListener("scroll", tourPlaceCurrent, true);
  return tourPop;
}

function tourPopHide() { if (tourPop) tourPop.hidden = true; }
function tourPlaceCurrent() { if (tourCurrent && tourPop && !tourPop.hidden) tourPlace(tourMarked); }

let tourMarked = null;
function tourMark(target) {
  tourClearMark();
  tourMarked = target;
  if (target) target.classList.add("tour-mark");
}
function tourClearMark() {
  if (tourMarked) tourMarked.classList.remove("tour-mark");
  tourMarked = null;
}

// Anchor the pop-up under its control; fall back to the top of the viewport when
// there is no room, or centre it for a step with no control.
function tourPlace(target) {
  const pop = tourPop;
  if (!pop || pop.hidden) return;
  pop.style.transform = "";
  pop.style.top = "";
  pop.style.left = "";
  const w = Math.min(pop.offsetWidth, window.innerWidth - 16);
  const h = pop.offsetHeight;
  if (!target) {
    pop.style.left = "50%";
    pop.style.top = "18%";
    pop.style.transform = "translateX(-50%)";
    return;
  }
  const r = target.getBoundingClientRect();
  let left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8));
  let top = r.bottom + 10;
  if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 10);
  pop.style.left = left + "px";
  pop.style.top = top + "px";
}

// Replay buttons (Help screen).
// 2026-11-21, David: Replay used to run the tour right there on the Help screen, where none of its controls are, so
// every step was skipped and nothing showed. Now a screen's tour opens that screen first;
// a page that needs a particular project/estimate/sheet says to open one and use 🎓 Show me this screen.
const TOUR_HOME = {};            // tour id -> the menu screen it belongs to ("#/<screen>")
for (const [screen, id] of Object.entries(TOUR_SCREEN)) TOUR_HOME[id] = screen;
const TOUR_OPEN_FIRST = { project: "a project", plan_set: "a plan set", sheet: "a sheet", takeoff: "a project in Measure",
  estimate: "an estimate", symbol_review: "a plan set's symbols in Reviews", quantities: "Plan quantities on a project",
  revision: "a plan revision in Reports", job: "a job on the Jobs board", bid: "a quote in Bids" };

function tourReplay(tourId) {
  const def = TOUR_BY_ID[tourId];
  if (!def) return;
  if (tourCurrent) tourClose();
  if (tourIdForPage() === tourId || (def.steps[0] && def.steps[0].go)) { startTour(tourId); return; }  // here already, or it navigates itself
  const screen = TOUR_HOME[tourId];
  if (!screen) {
    toast("Open " + (TOUR_OPEN_FIRST[tourId] || "that page") + " first, then click 🎓 Show me this screen.");
    return;
  }
  const go = "#/" + screen;
  location.hash = go;
  tourStartWhenReady(tourId, go, 0);
}

// After Replay opens a screen, wait (up to ~5 s) for it to render, then start its tour.
function tourStartWhenReady(tourId, go, tries) {
  if (location.hash.split("?")[0] !== go) return;                 // the user went elsewhere
  const first = TOUR_BY_ID[tourId].steps.find(s => s.sel);
  const ready = tourIdForPage() === tourId && (!first || document.querySelector(first.sel) || tries >= 25);
  if (ready || tries >= 40) { startTour(tourId); return; }
  setTimeout(() => tourStartWhenReady(tourId, go, tries + 1), 120);
}

function tourReplayBtn(tourId) {
  const page = !TOUR_HOME[tourId] && TOUR_OPEN_FIRST[tourId];
  return el("button", { class: "button", type: "button", onclick: () => tourReplay(tourId),
    title: page ? "Open " + TOUR_OPEN_FIRST[tourId] + " first, then click 🎓 Show me this screen" : "Opens the screen and runs its tour" },
    "↻ Replay");
}

// ------------------------------------------------------------------ help panel

let helpPanel = null;         // the slide-over element
let helpPanelScreen = "";     // the screen the panel is showing guides for
let helpPanelGuides = [];     // guides fetched for that screen (unfiltered)

// Open the panel for a screen: its guides, searchable, plus a Replay tour button.
function openHelpPanel(screenId) {
  if (!helpPanel) helpPanel = helpPanelBuild();
  helpPanelScreen = screenId;
  helpPanel.hidden = false;
  helpPanelFill(screenId);
}

function closeHelpPanel() { if (helpPanel) helpPanel.hidden = true; }

function helpPanelBuild() {
  const panel = el("aside", { id: "help-panel", class: "help-panel", hidden: true, "aria-label": "Help" },
    el("div", { class: "help-panel-head" },
      el("strong", { id: "help-panel-title" }, "Help"),
      el("button", { class: "link-btn", type: "button", id: "help-panel-x", "aria-label": "Close help" }, "✕")),
    el("input", { type: "search", id: "help-panel-find", placeholder: "Search the guides…", "aria-label": "Search the guides" }),
    el("div", { class: "help-panel-replay", id: "help-panel-replay" }),
    el("ul", { class: "guides", id: "help-panel-list" }),
    el("p", { class: "muted small" }, el("a", { id: "help-panel-all", href: "#/help" }, "Open the full Help screen")));
  document.body.append(panel);
  $("help-panel-x").addEventListener("click", closeHelpPanel);
  $("help-panel-find").addEventListener("input", () => helpPanelFilter());
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && helpPanel && !helpPanel.hidden) closeHelpPanel();
  });
  window.addEventListener("hashchange", closeHelpPanel);
  return panel;
}

async function helpPanelFill(screenId) {
  const menu = (state.me && state.me.menu) || [];
  const label = (menu.find(s => s.id === screenId) || {}).label || words(screenId);
  $("help-panel-title").textContent = "Help — " + label;
  $("help-panel-find").value = "";
  $("help-panel-all").href = "#/help?screen=" + encodeURIComponent(screenId);
  const replay = $("help-panel-replay");
  replay.replaceChildren();
  const tourId = tourForThisScreen(screenId);      // a page (project, estimate…) has its own tour
  const tour = tourId ? TOUR_BY_ID[tourId] : null;
  if (tour) {
    replay.append(el("button", { class: "button", type: "button",
      onclick: () => { closeHelpPanel(); startTour(tourId); } }, "↻ Replay the " + tour.title + " tour"));
    if (screenId === "dashboard") {
      replay.append(el("button", { class: "button", type: "button",
        onclick: () => { closeHelpPanel(); startTour("practice"); } }, "▶ Practice project tour"));
    }
  }
  const list = $("help-panel-list");
  list.replaceChildren(el("li", { class: "muted" }, "Loading the guides…"));
  let guides = [];
  // The endpoint returns {guides: [...]} (see renderHelp); assigning the
  // whole response made helpPanelGuides.filter throw on every panel open.
  try { guides = (await api("GET", "/help/guides?screen=" + encodeURIComponent(screenId))).guides || []; } catch (e) { guides = []; }
  helpPanelGuides = guides;
  helpPanelFilter();
}

// Filter the fetched guides by the search box (title or id, case-insensitive).
function helpPanelFilter() {
  const list = $("help-panel-list");
  if (!list) return;
  const q = ($("help-panel-find").value || "").trim().toLowerCase();
  const shown = helpPanelGuides.filter(g => !q || g.title.toLowerCase().includes(q) || g.id.toLowerCase().includes(q));
  list.replaceChildren();
  if (shown.length === 0) {
    list.append(el("li", { class: "muted" },
      helpPanelGuides.length === 0 ? "No guide for this screen yet — open the full Help screen for every guide."
        : "Nothing matches that search — try fewer words."));
    return;
  }
  // NB: el(tag, attrs, ...kids) — the <a> is a child, not the attrs object.
  for (const g of shown) list.append(el("li", {}, el("a", { href: "#/help/" + g.id }, g.title)));
}
