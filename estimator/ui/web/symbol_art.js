/* Pictures of AI-Prowler's standard plan symbols (Symbol Library thumbnails).
 *
 * Every picture is drawn here in code, in the common drafting conventions estimators see on US plan sets
 * (a circle with two lines for a duplex receptacle, S for a switch, a triangle for a data outlet...). They are
 * AI-Prowler's own drawings, not copied artwork, and they ship with the app, so the standard library has a picture
 * for every symbol from the first run. A design firm's own legend can draw a symbol differently: the plan set's
 * legend always wins when plans are read.
 *
 * Each picture is a list of shapes on a 40 x 40 grid:
 *   ["c", cx, cy, r]        circle            ["cf", ...]  filled circle
 *   ["l", x1, y1, x2, y2]   line              ["e", cx, cy, rx, ry]  ellipse
 *   ["r", x, y, w, h, rx?]  rectangle         ["rf", ...]  filled rectangle
 *   ["p", "path"]           path              ["pf", ...]  filled path
 *   ["t", x, y, "text", size?]  text (centred)
 * symbolPicture(itemType, code) returns an <svg> element; an item type without a drawing (a company's own symbol)
 * gets a dashed box with its code.
 */
"use strict";

const _DUP = [["c", 20, 20, 8], ["l", 16, 9, 16, 31], ["l", 24, 9, 24, 31]];
const _TRI = [["p", "M20 8 L32 30 L8 30 Z"]];
const _FAN = [["r", 6, 6, 28, 28], ["c", 20, 20, 9], ["l", 14, 14, 26, 26], ["l", 26, 14, 14, 26]];
const _sq = (txt, size) => [["r", 5, 9, 30, 22, 2], ["t", 20, 24.5, txt, size || 11]];
const _ci = (txt, size) => [["c", 20, 20, 13], ["t", 20, 24.5, txt, size || 11]];
const _sw = sub => sub ? [["t", 17, 27, "S", 22], ["t", 29, 32, sub, 10]] : [["t", 20, 28, "S", 22]];
const _valve = [["p", "M9 13 L20 20 L9 27 Z M31 13 L20 20 L31 27 Z"]];

const SYMBOL_ART = {
  // ----------------------------------------------------------------- electrical
  duplex_receptacle: _DUP,
  duplex_receptacle_gfci: [..._DUP, ["t", 20, 39, "GFI", 8]],
  duplex_receptacle_wp: [..._DUP, ["t", 20, 39, "WP", 8]],
  duplex_receptacle_usb: [..._DUP, ["t", 20, 39, "USB", 8]],
  receptacle_dedicated: [["c", 20, 20, 8], ["cf", 20, 20, 3], ["l", 16, 9, 16, 31], ["l", 24, 9, 24, 31]],
  quad_receptacle: [["c", 20, 20, 9], ["l", 14, 9, 14, 31], ["l", 18, 9, 18, 31], ["l", 22, 9, 22, 31], ["l", 26, 9, 26, 31]],
  receptacle_240v: [["c", 20, 20, 9], ["l", 13, 10, 13, 30], ["l", 20, 9, 20, 31], ["l", 27, 10, 27, 30], ["t", 20, 39, "240V", 7]],
  floor_box: [["r", 7, 7, 26, 26], ["c", 20, 20, 7], ["l", 17, 14, 17, 26], ["l", 23, 14, 23, 26]],
  switch: _sw(""),
  switch_3way: _sw("3"),
  switch_4way: _sw("4"),
  switch_dimmer: _sw("D"),
  switch_occupancy: _sw("OS"),
  light_fixture: [["c", 20, 20, 10], ["l", 13, 13, 27, 27], ["l", 27, 13, 13, 27]],
  light_recessed: [["r", 8, 8, 24, 24], ["c", 20, 20, 8]],
  light_wall: [["l", 6, 30, 34, 30, 0], ["p", "M9 30 A11 11 0 0 1 31 30"], ["l", 14, 22, 26, 22]],
  light_pendant: [["l", 20, 3, 20, 12], ["c", 20, 22, 10], ["l", 13, 15, 27, 29], ["l", 27, 15, 13, 29]],
  light_undercabinet: [["r", 3, 14, 34, 12], ["l", 8, 26, 14, 14], ["l", 16, 26, 22, 14], ["l", 24, 26, 30, 14]],
  light_exterior: [["c", 20, 20, 7], ["l", 20, 4, 20, 9], ["l", 20, 31, 20, 36], ["l", 4, 20, 9, 20], ["l", 31, 20, 36, 20],
    ["l", 9, 9, 12, 12], ["l", 28, 28, 31, 31], ["l", 31, 9, 28, 12], ["l", 9, 31, 12, 28]],
  exit_sign: [["r", 4, 11, 32, 18, 2], ["t", 20, 24, "EXIT", 10], ["pf", "M30 33 L36 36 L30 39 Z"], ["l", 22, 36, 30, 36]],
  emergency_light: [["r", 6, 13, 28, 14, 2], ["c", 13, 20, 4], ["c", 27, 20, 4], ["t", 20, 37, "EM", 8]],
  smoke_detector: _ci("SD"),
  co_detector: _ci("CO"),
  smoke_co_detector: _ci("S/CO", 8),
  data_outlet: [["pf", "M20 8 L32 30 L8 30 Z"]],
  phone_outlet: [..._TRI, ["t", 20, 28, "T", 10]],
  tv_outlet: [..._TRI, ["t", 20, 28.5, "TV", 8]],
  ceiling_fan: [["c", 20, 20, 4], ["e", 20, 9, 3.5, 6], ["e", 20, 31, 3.5, 6], ["e", 9, 20, 6, 3.5], ["e", 31, 20, 6, 3.5]],
  panel: [["r", 4, 12, 32, 16], ["pf", "M4 28 L36 12 L36 28 Z"]],
  junction_box: _ci("J", 14),
  ev_charger: [["r", 8, 5, 24, 30, 3], ["pf", "M22 9 L14 21 L19 21 L17 31 L26 18 L21 18 Z"]],
  disconnect: [["r", 7, 7, 26, 26], ["l", 7, 33, 33, 7], ["t", 20, 39, "DISC", 7]],
  doorbell: [["r", 8, 8, 24, 24], ["c", 20, 20, 6], ["cf", 20, 20, 2]],
  speaker: [["c", 20, 20, 13], ["c", 20, 20, 7], ["cf", 20, 20, 2]],
  // ----------------------------------------------------------------- low voltage (security and network)
  security_camera: [["r", 4, 12, 22, 14, 2], ["p", "M26 15 L35 11 L35 27 L26 23 Z"], ["l", 12, 26, 12, 34], ["l", 6, 34, 18, 34]],
  card_reader: [["r", 11, 4, 18, 32, 2], ["r", 15, 9, 10, 7], ["t", 20, 30, "CR", 8]],
  motion_sensor: [["cf", 20, 30, 3], ["p", "M13 23 A10 10 0 0 1 27 23"], ["p", "M8 18 A17 17 0 0 1 32 18"], ["t", 20, 10, "PIR", 7]],
  door_contact: [["r", 6, 12, 11, 14], ["r", 23, 12, 11, 14], ["t", 20, 37, "DC", 8]],
  keypad: [["r", 9, 4, 22, 32, 2], ["cf", 14, 12, 1.6], ["cf", 20, 12, 1.6], ["cf", 26, 12, 1.6], ["cf", 14, 19, 1.6],
    ["cf", 20, 19, 1.6], ["cf", 26, 19, 1.6], ["cf", 14, 26, 1.6], ["cf", 20, 26, 1.6], ["cf", 26, 26, 1.6]],
  intercom: [["r", 9, 4, 22, 32, 2], ["l", 13, 10, 27, 10], ["l", 13, 14, 27, 14], ["l", 13, 18, 27, 18], ["c", 20, 28, 3.5]],
  wireless_access_point: [["cf", 20, 30, 2.5], ["p", "M14 24 A8.5 8.5 0 0 1 26 24"], ["p", "M9 19 A15.5 15.5 0 0 1 31 19"],
    ["p", "M4 14 A22.6 22.6 0 0 1 36 14"]],
  // ----------------------------------------------------------------- architectural (plan view)
  door: [["l", 2, 34, 8, 34], ["l", 34, 34, 38, 34], ["l", 8, 34, 8, 8], ["p", "M8 8 A26 26 0 0 1 34 34"]],
  door_double: [["l", 1, 34, 4, 34], ["l", 36, 34, 39, 34], ["l", 4, 34, 4, 18], ["l", 36, 34, 36, 18],
    ["p", "M4 18 A16 16 0 0 1 20 34"], ["p", "M36 18 A16 16 0 0 0 20 34"]],
  door_sliding: [["l", 2, 20, 6, 20], ["l", 34, 20, 38, 20], ["r", 6, 16, 16, 3], ["r", 18, 21, 16, 3],
    ["l", 12, 30, 28, 30], ["pf", "M28 27.5 L33 30 L28 32.5 Z"]],
  door_pocket: [["r", 2, 16, 18, 8], ["rf", 6, 19, 26, 2], ["r", 34, 16, 4, 8]],
  door_garage: [["l", 1, 30, 5, 30], ["l", 35, 30, 39, 30], ["r", 5, 27, 30, 3], ["t", 20, 20, "GAR", 9]],
  window: [["l", 2, 15, 8, 15], ["l", 2, 25, 8, 25], ["l", 32, 15, 38, 15], ["l", 32, 25, 38, 25],
    ["r", 8, 15, 24, 10], ["l", 8, 19, 32, 19], ["l", 8, 21, 32, 21]],
  skylight: [["r", 6, 6, 28, 28], ["r", 10, 10, 20, 20], ["l", 10, 10, 30, 30], ["l", 30, 10, 10, 30]],
  column: [["l", 20, 2, 20, 38], ["l", 2, 20, 38, 20], ["rf", 13, 13, 14, 14]],
  // ----------------------------------------------------------------- mechanical / HVAC
  thermostat: _ci("T", 14),
  exhaust_fan: _FAN,
  supply_diffuser: [["r", 6, 6, 28, 28], ["l", 6, 6, 34, 34], ["l", 34, 6, 6, 34], ["r", 13, 13, 14, 14]],
  return_grille: [["r", 6, 6, 28, 28], ["l", 6, 34, 34, 6], ["l", 6, 22, 22, 6], ["l", 18, 34, 34, 18]],
  linear_diffuser: [["r", 2, 13, 36, 14], ["l", 4, 17, 36, 17], ["l", 4, 20, 36, 20], ["l", 4, 23, 36, 23]],
  floor_register: [["r", 5, 11, 30, 18], ["l", 10, 11, 10, 29], ["l", 15, 11, 15, 29], ["l", 20, 11, 20, 29],
    ["l", 25, 11, 25, 29], ["l", 30, 11, 30, 29]],
  transfer_grille: [["r", 6, 10, 28, 20], ["t", 20, 24, "TG", 10], ["l", 20, 1, 20, 9], ["l", 20, 31, 20, 39]],
  mini_split_head: [["r", 3, 12, 34, 14, 3], ["l", 7, 21, 33, 21], ["l", 9, 24, 31, 24], ["t", 20, 36, "IDU", 8]],
  condensing_unit: [["r", 5, 5, 30, 30], ["c", 20, 18, 9], ["l", 20, 9, 20, 27], ["l", 11, 18, 29, 18], ["t", 20, 33.5, "CU", 6]],
  heat_pump: [["r", 5, 5, 30, 30], ["c", 20, 18, 9], ["l", 20, 9, 20, 27], ["l", 11, 18, 29, 18], ["t", 20, 33.5, "HP", 6]],
  air_handler: _sq("AHU"),
  furnace: [["r", 7, 5, 26, 30], ["p", "M20 26 C13 21 18 16 20 10 C22 16 27 21 20 26 Z"], ["t", 20, 33, "F", 6]],
  package_unit: _sq("RTU"),
  duct_smoke_detector: [["r", 5, 9, 30, 22], ["l", 5, 31, 35, 9], ["t", 20, 39, "DSD", 7]],
  range_hood: [["p", "M4 30 L12 12 L28 12 L36 30 Z"], ["l", 4, 30, 36, 30], ["t", 20, 26, "RH", 8]],
  dryer_vent: _ci("DV"),
  // ----------------------------------------------------------------- plumbing
  water_closet: [["r", 9, 3, 22, 9, 2], ["e", 20, 25, 9, 12]],
  urinal: [["l", 6, 6, 34, 6], ["p", "M10 6 L10 22 A10 12 0 0 0 30 22 L30 6"], ["c", 20, 22, 2]],
  lavatory: [["r", 4, 8, 32, 24, 3], ["e", 20, 21, 11, 8], ["cf", 20, 21, 1.5]],
  sink: [["r", 5, 8, 30, 24], ["r", 9, 12, 22, 16, 2], ["cf", 20, 20, 1.5]],
  kitchen_sink: [["r", 2, 9, 36, 22], ["r", 5, 12, 14, 16, 2], ["r", 21, 12, 14, 16, 2], ["cf", 12, 20, 1.5], ["cf", 28, 20, 1.5]],
  bar_sink: [["r", 8, 8, 24, 24], ["r", 12, 12, 16, 16, 2], ["cf", 20, 20, 1.5]],
  laundry_sink: [["r", 5, 7, 30, 26], ["r", 8, 10, 24, 20, 1], ["l", 8, 10, 12, 14], ["l", 32, 10, 28, 14], ["cf", 20, 22, 1.5]],
  mop_sink: [["r", 6, 6, 28, 28], ["p", "M10 10 L30 10 L30 30 Z"], ["cf", 24, 18, 1.5]],
  shower: [["r", 5, 5, 30, 30], ["l", 5, 5, 35, 35], ["l", 35, 5, 5, 35], ["cf", 20, 20, 2.5]],
  tub: [["r", 2, 9, 36, 22], ["r", 5, 12, 30, 16, 7], ["cf", 9, 20, 1.5]],
  tub_shower: [["r", 2, 9, 36, 22], ["r", 5, 12, 30, 16, 7], ["cf", 9, 20, 1.5], ["l", 30, 3, 36, 9], ["l", 36, 3, 30, 9]],
  floor_drain: [["c", 20, 20, 10], ["l", 13, 13, 27, 27], ["l", 27, 13, 13, 27], ["t", 20, 39, "FD", 7]],
  cleanout: [["c", 20, 18, 9], ["cf", 20, 18, 4], ["t", 20, 37, "CO", 7]],
  hose_bibb: [["l", 4, 20, 22, 20], ["c", 26, 20, 4], ["l", 26, 12, 26, 16], ["l", 22, 12, 30, 12], ["t", 20, 37, "HB", 7]],
  water_heater: _ci("WH"),
  tankless_water_heater: _sq("TWH"),
  dishwasher: _sq("DW"),
  washer_box: [["r", 8, 9, 24, 22], ["c", 15, 20, 3.5], ["c", 25, 20, 3.5], ["t", 20, 39, "WB", 7]],
  ice_maker_box: [["r", 10, 10, 20, 20], ["c", 20, 20, 3.5], ["t", 20, 39, "IM", 7]],
  gas_outlet: [["l", 2, 20, 9, 20], ["l", 31, 20, 38, 20], ..._valve, ["t", 20, 37, "GAS", 7]],
  drinking_fountain: [["l", 6, 12, 34, 12], ["p", "M8 12 L8 18 A12 12 0 0 0 32 18 L32 12"], ["cf", 20, 20, 1.5], ["t", 20, 39, "DF", 7]],
  water_meter: _ci("M", 14),
  // ----------------------------------------------------------------- fire
  sprinkler_head: [["c", 20, 20, 7], ["cf", 20, 20, 2.5], ["l", 20, 5, 20, 11], ["l", 20, 29, 20, 35], ["l", 5, 20, 11, 20], ["l", 29, 20, 35, 20]],
  fire_extinguisher: [["r", 13, 9, 14, 26, 4], ["l", 20, 9, 20, 4], ["l", 20, 4, 28, 4], ["t", 20, 26, "FE", 8]],
  pull_station: [["r", 8, 8, 24, 24], ["t", 20, 26, "F", 16]],
  horn_strobe: [["r", 4, 10, 32, 20], ["t", 20, 24, "H/S", 10]],
  fire_alarm_panel: [["r", 3, 10, 34, 20], ["t", 20, 24, "FACP", 9]],
  // ----------------------------------------------------------------- landscape
  tree: [["p", "M20 4 Q26 2 28 8 Q35 9 34 16 Q39 21 34 26 Q35 33 28 33 Q25 39 20 36 Q14 39 12 33 Q5 33 6 26 Q1 21 6 16 Q5 9 12 8 Q14 2 20 4 Z"],
    ["cf", 20, 20, 1.5], ["l", 20, 20, 20, 9], ["l", 20, 20, 30, 24], ["l", 20, 20, 10, 24]],
  palm: [["cf", 20, 20, 2], ["p", "M20 20 Q24 9 20 3 M20 20 Q31 16 37 20 M20 20 Q24 31 20 37 M20 20 Q9 24 3 20 M20 20 Q28 10 32 8 M20 20 Q30 28 32 32 M20 20 Q12 30 8 32 M20 20 Q10 12 8 8"]],
  shrub: [["p", "M20 9 Q24 7 26 11 Q31 11 30 16 Q34 20 30 24 Q31 29 26 29 Q24 33 20 31 Q16 33 14 29 Q9 29 10 24 Q6 20 10 16 Q9 11 14 11 Q16 7 20 9 Z"], ["cf", 20, 20, 1.5]],
  drip_valve: [["c", 20, 20, 15], ..._valve, ["t", 20, 39, "DCV", 6]],
  irrigation_valve: [["c", 20, 20, 15], ..._valve, ["cf", 20, 20, 2], ["t", 20, 39, "RCV", 6]],
  irrigation_controller: [["r", 6, 6, 28, 28, 2], ["c", 20, 20, 8], ["l", 20, 20, 20, 15], ["l", 20, 20, 24, 22]],
};

const _SVGNS = "http://www.w3.org/2000/svg";

function _svgShape(s) {
  const k = s[0], fill = k.length === 2 && k[1] === "f";
  const mk = (tag, attrs) => { const n = document.createElementNS(_SVGNS, tag); for (const a in attrs) n.setAttribute(a, attrs[a]); return n; };
  const paint = { fill: fill ? "currentColor" : "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-linejoin": "round", "stroke-linecap": "round" };
  switch (k[0]) {
    case "c": return mk("circle", { cx: s[1], cy: s[2], r: s[3], ...paint });
    case "e": return mk("ellipse", { cx: s[1], cy: s[2], rx: s[3], ry: s[4], ...paint });
    case "l": return mk("line", { x1: s[1], y1: s[2], x2: s[3], y2: s[4], ...paint });
    case "r": return mk("rect", { x: s[1], y: s[2], width: s[3], height: s[4], rx: s[5] || 0, ...paint });
    case "p": return mk("path", { d: s[1], ...paint });
    case "t": { const t = mk("text", { x: s[1], y: s[2], "text-anchor": "middle", "font-size": s[4] || 11,
                  "font-family": "Arial, Helvetica, sans-serif", "font-weight": "bold", fill: "currentColor" });
                t.textContent = s[3]; return t; }
  }
  return null;
}

/** An <svg> picture of a standard symbol; a company's own symbol without a drawing gets a dashed box with its code. */
function symbolPicture(itemType, code) {
  const svg = document.createElementNS(_SVGNS, "svg");
  svg.setAttribute("viewBox", "0 0 40 40");
  svg.setAttribute("class", "sym-art");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", (itemType || "symbol").replace(/_/g, " ") + " symbol");
  const shapes = SYMBOL_ART[itemType] || [["p", "M4 4 H36 V36 H4 Z"], ["t", 20, 24.5, (code || "?").slice(0, 4), 10]];
  if (!SYMBOL_ART[itemType]) svg.classList.add("none");
  for (const s of shapes) { const n = _svgShape(s); if (n) svg.append(n); }
  return svg;
}
