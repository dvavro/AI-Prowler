/* Reviews on a phone or tablet (Coder 2 Sprint 13), opened from the Jobs app's Estimates tab (Reviews).
 *
 * Loaded after app.js (el, api, apiImage, words, askThen, helpLink, errorBox, go ...) and review.js (pct).
 * Route: #/m/reviews   ?kind=symbol|measurement  ?estimate=<id>  ?i=<position>
 * One item at a time, least sure first: its picture in place on the sheet (outlined in red), what it is, and big
 * buttons - ✓ Approve, ✗ Take out, Relabel… (symbols), Skip. Swipe right to approve, left to take out. Every change
 * asks first (askThen), the same rules as the desktop pages. Drawing and calibrating stay on the desktop.
 */
"use strict";

const MREV_SWIPE_PX = 80;

// Sprint 18: the short phone tour. tour.js (loaded after this file) picks it up and
// adds it to TOURS. The first step navigates to #/m/reviews so replaying it from the
// Help screen lands on the phone screen first.
const MREV_TOUR = { id: "mobile", title: "Reviews on your phone", steps: [
  { sel: "#mrev-kinds", go: "#/m/reviews", title: "What to check",
    body: "Symbols or measurements - the least sure ones come first." },
  { sel: "#mrev-card", title: "One item at a time",
    body: "Its picture in place on the sheet, outlined in red, and what the plan engine thinks it is." },
  { sel: "#mrev-approve", title: "Approve or take out",
    body: "Approve keeps it; Take out drops it. Every change asks first, the same as on the desktop." },
  { sel: "#mrev-skip", title: "Not sure? Skip it",
    body: "Skip leaves it for later. Swipe right to approve, left to take out." },
]};

function mrevHash(changes) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  for (const [k, v] of Object.entries(changes)) { if (v === "" || v === null || v === undefined) q.delete(k); else q.set(k, v); }
  const s = q.toString();
  return "#/m/reviews" + (s ? "?" + s : "");
}

function mrevRelabel(item, types, msg) {
  const sel = el("select", { id: "mrev-type", "aria-label": "What it is" }, el("option", { value: "" }, "Choose what it is…"));
  const trades = {};
  for (const t of types) (trades[t.trade || "other"] = trades[t.trade || "other"] || []).push(t);
  for (const [trade, list] of Object.entries(trades)) {
    sel.append(el("optgroup", { label: words(trade) }, list.map(t => el("option", { value: t.item_type, selected: t.item_type === item.item_type }, t.label))));
  }
  const all = el("input", { type: "checkbox", id: "mrev-all" });
  const go2 = el("button", { class: "primary big", type: "button", id: "mrev-relabel-go" }, "Relabel…");
  go2.addEventListener("click", () => {
    if (!sel.value) { msg.replaceChildren(el("p", { class: "error" }, "Choose what it is first.")); return; }
    askThen(msg, go2, "/symbol-detections/review", { detection_ids: [item.id], action: "relabel", item_type: sel.value,
      apply_to_matches: all.checked }, r => "Relabelled " + (r.changed || 1) + " as " + words(sel.value), "mrev");
  });
  return el("div", { class: "card mrev-relabel", id: "mrev-relabel-box" }, sel,
    el("label", { class: "mrev-check" }, all, " Every identical match on this plan set"), go2);
}

function mrevSwipe(card, onRight, onLeft) {
  let x0 = null;
  card.addEventListener("pointerdown", e => { x0 = e.clientX; });
  card.addEventListener("pointermove", e => {
    if (x0 === null) return;
    const dx = e.clientX - x0;
    card.classList.toggle("swipe-right", dx > MREV_SWIPE_PX / 2);
    card.classList.toggle("swipe-left", dx < -MREV_SWIPE_PX / 2);
  });
  const end = e => {
    if (x0 === null) return;
    const dx = e.clientX - x0;
    x0 = null;
    card.classList.remove("swipe-right", "swipe-left");
    if (dx > MREV_SWIPE_PX && onRight) onRight();
    else if (dx < -MREV_SWIPE_PX && onLeft) onLeft();
  };
  card.addEventListener("pointerup", end);
  card.addEventListener("pointercancel", () => { x0 = null; card.classList.remove("swipe-right", "swipe-left"); });
}

async function renderMobileReviews(main) {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const kind = q.get("kind") || "", estimate = q.get("estimate") || "";
  const qs = new URLSearchParams({ limit: "200" });
  if (kind) qs.set("kind", kind);
  if (estimate) qs.set("estimate_id", estimate);
  const r = await api("GET", "/mobile/reviews?" + qs);
  const items = r.items;
  const i = Math.min(Math.max(0, +(q.get("i") || 0) || 0), Math.max(0, items.length - 1));
  const parts = [el("div", { class: "page-head" }, el("h2", {}, "✅ Reviews"), helpLink("reviews")),
    el("p", { id: "mrev-waiting", class: "muted" }, r.waiting ? r.waiting + " waiting for a person · " + r.counts.symbols + " symbols, " + r.counts.measurements + " measurements"
      : "Nothing waiting.")];

  // Filters: what kind, which project.
  const chips = el("div", { class: "mrev-chips", id: "mrev-kinds" },
    [["", "All"], ["symbol", "Symbols"], ["measurement", "Measurements"]].filter(([k]) => !k || r.can[k]).map(([k, label]) =>
      el("a", { class: "chip" + (k === kind ? " active" : ""), href: mrevHash({ kind: k, i: "" }), "data-kind": k || "all" }, label)));
  parts.push(chips);
  if (r.projects.length > 1 || estimate) {
    const sel = el("select", { id: "mrev-project", "aria-label": "Project" }, el("option", { value: "" }, "All projects"),
      r.projects.map(p => el("option", { value: p.estimate_id, selected: String(p.estimate_id) === estimate }, p.title)));
    sel.addEventListener("change", () => { location.hash = mrevHash({ estimate: sel.value, i: "" }); });
    parts.push(sel);
  }

  if (!items.length) {
    parts.push(el("div", { class: "card empty", id: "mrev-empty" }, "All checked. New symbols and measurements show here when plans are read or measured."));
    main.replaceChildren(...parts);
    return;
  }

  const item = items[i];
  const isSym = item.kind === "symbol";
  const canDecide = isSym ? r.can.review_symbols : r.can.approve_measurements;
  const msg = el("div", { id: "mrev-message", role: "status" });
  const pic = item.picture
    ? apiImage(el("img", { class: "mrev-picture", id: "mrev-picture", alt: item.title + " on " + (item.sheet_no || "the plan") }), item.picture)
    : el("div", { class: "mrev-picture none", id: "mrev-picture" }, "Typed in — no place on the plan");
  if (item.picture) pic.addEventListener("error", () => { pic.replaceWith(el("div", { class: "mrev-picture none", id: "mrev-picture" }, "No picture of this sheet")); }, { once: true });
  const card = el("div", { class: "card mrev-card", id: "mrev-card", "data-kind": item.kind, "data-id": item.id },
    pic,
    el("div", { class: "mrev-title" }, el("strong", { id: "mrev-title" }, item.title), " ", el("span", { class: "chip" + (+item.confidence < 0.7 ? " warn" : "") }, pct(item.confidence))),
    el("div", { class: "muted", id: "mrev-detail" }, item.detail),
    el("div", { class: "small muted" }, item.estimate_title + (item.sheet_no ? " · " + item.sheet_no : "")),
    ...(item.notes || []).map(n => el("p", { class: "small note" }, n)));
  parts.push(el("div", { class: "row mrev-pos" },
    el("a", { class: "button", id: "mrev-prev", href: mrevHash({ i: i ? i - 1 : "" }), "aria-disabled": i ? null : "true" }, "◀"),
    el("span", { id: "mrev-position" }, (i + 1) + " of " + items.length),
    el("a", { class: "button", id: "mrev-next", href: mrevHash({ i: i + 1 < items.length ? i + 1 : i }), "aria-disabled": i + 1 < items.length ? null : "true" }, "▶")),
    card);

  if (canDecide) {
    const done = what => res => what + (res.changed > 1 || res.done > 1 ? " (" + (res.changed || res.done) + ")" : "");
    const approve = el("button", { class: "primary big", type: "button", id: "mrev-approve" }, "✓ Approve");
    const reject = el("button", { class: "danger big", type: "button", id: "mrev-reject" }, "✗ Take out");
    approve.addEventListener("click", () => isSym
      ? askThen(msg, approve, "/symbol-detections/review", { detection_ids: [item.id], action: "approve" }, done("Approved"), "mrev")
      : askThen(msg, approve, "/measurements/approve", { measurement_ids: [item.id] }, done("Approved and locked"), "mrev"));
    reject.addEventListener("click", () => isSym
      ? askThen(msg, reject, "/symbol-detections/review", { detection_ids: [item.id], action: "reject" }, done("Taken out"), "mrev")
      : askThen(msg, reject, "/measurements/" + item.id + "/reject", { reason: "taken out on the phone" }, done("Taken out"), "mrev"));
    const row = el("div", { class: "mrev-actions" }, approve, reject);
    let relabelBox = null;
    if (isSym) {
      const relabel = el("button", { class: "big", type: "button", id: "mrev-relabel" }, "Relabel…");
      relabel.addEventListener("click", () => {
        if (relabelBox) { relabelBox.remove(); relabelBox = null; return; }
        relabelBox = mrevRelabel(item, r.item_types, msg);
        row.after(relabelBox);
      });
      row.append(relabel);
    }
    const skip = el("button", { class: "big", type: "button", id: "mrev-skip" }, "Skip ▶");
    skip.addEventListener("click", () => { location.hash = mrevHash({ i: i + 1 < items.length ? i + 1 : 0 }); });
    row.append(skip);
    parts.push(row, msg, el("p", { class: "small muted" }, "Swipe the picture right to approve, left to take out."));
    mrevSwipe(card, () => approve.click(), () => reject.click());
  } else {
    parts.push(el("p", { class: "note", id: "mrev-look-only" }, "You can look at these here; an owner, estimator or reviewer approves them."));
  }
  parts.push(el("p", { class: "small" }, el("a", { href: item.plan_link, id: "mrev-plan-link" }, "Open on the plan (desktop)")));
  main.replaceChildren(...parts);
}

PAGES.mobile_reviews = renderMobileReviews;
