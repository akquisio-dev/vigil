// The attackers map on the Attackers tab: the world on a plane that pans and
// zooms, countries shaded or as circles by attempts or addresses, filters
// by class, kind, network, campaign, target host and first sight, a side
// panel per country, a replay of the window, live arcs from the agents and
// a full screen wall for a monitor on the wall. It filters and sums on the
// page: /api/ui/attacks/map gives every address of the window in short rows,
// with where it is when the server has the city data. Zoomed in, a country
// splits into its provinces (regions/<CC>.json, loaded when first seen) and
// further in into places: the addresses as dots, grouped on screen.
// Attacker-controlled strings (user names, paths) only ever become text.

Object.assign(T.en, {
  amTitle: "Attack map", amShade: "Show", amArea: "Areas", amBubbles: "Circles", amBoth: "Both", amMetric: "Measure",
  amByCount: "attempts", amByIps: "addresses", amKind: "Kind", amAllKinds: "SSH and web", amNet: "Network", amAllNets: "all networks",
  amCamp: "Campaign", amAllCamps: "all campaigns", amHost: "Target", amAllHosts: "all hosts", amLabels: "Names", amLive: "Live",
  amWall: "Wall", amWallEnd: "End wall", amTour: "Tour", amShare: "Share", amCopied: "Link copied", amExport: "Picture",
  amWorld: "World", amTopCountries: "Countries", amShare_: "{p} of all", amClasses: "Classes", amTopNets: "Networks",
  amTopUsers: "Tried user names", amTargets: "Targets", amTopAddrs: "Busiest addresses", amCampaigns: "Campaigns",
  amInTable: "Addresses of {c} in the table", amFiltered: "{n} of {m} addresses after the filters", amNone: "No attacks match the filters",
  amReplay: "Replay", amPause: "Pause", amFirstSeen: "first seen up to {t}", amAll: "whole window", amTruncated: "The busiest {n} addresses of {m}",
  amPerMin: "per minute", amSeen: "seen live", amWaiting: "Waiting for the next report of the agents…",
  amHint: "Drag to move · Ctrl+wheel or two fingers zoom · click a country", amHintFull: "Wheel zooms · Esc ends",
  amLegend: "{m} per country", amLegendReg: "{m} per province", amHome: "our hosts", amPlace: "Place", amPlaceN: "{n} addresses here",
  amOfCountry: "{p} of the country", amRegions: "Provinces", amNoPlaces: "Places need the city data (geoip_city).", amListed: "on a block list", amClear: "Reset filters",
});
Object.assign(T.de, {
  amTitle: "Angriffskarte", amShade: "Darstellung", amArea: "Flächen", amBubbles: "Kreise", amBoth: "Beides", amMetric: "Maß",
  amByCount: "Versuche", amByIps: "Adressen", amKind: "Art", amAllKinds: "SSH und Web", amNet: "Netz", amAllNets: "alle Netze",
  amCamp: "Kampagne", amAllCamps: "alle Kampagnen", amHost: "Ziel", amAllHosts: "alle Hosts", amLabels: "Namen", amLive: "Live",
  amWall: "Wand", amWallEnd: "Wand beenden", amTour: "Rundgang", amShare: "Teilen", amCopied: "Link kopiert", amExport: "Bild",
  amWorld: "Welt", amTopCountries: "Länder", amShare_: "{p} von allen", amClasses: "Klassen", amTopNets: "Netze",
  amTopUsers: "Versuchte Benutzernamen", amTargets: "Ziele", amTopAddrs: "Aktivste Adressen", amCampaigns: "Kampagnen",
  amInTable: "Adressen aus {c} in der Tabelle", amFiltered: "{n} von {m} Adressen nach den Filtern", amNone: "Keine Angriffe passen zu den Filtern",
  amReplay: "Abspielen", amPause: "Pause", amFirstSeen: "zuerst gesehen bis {t}", amAll: "ganzer Zeitraum", amTruncated: "Die aktivsten {n} von {m} Adressen",
  amPerMin: "pro Minute", amSeen: "live gesehen", amWaiting: "Warte auf die nächste Meldung der Agents…",
  amHint: "Ziehen verschiebt · Strg+Mausrad oder zwei Finger zoomen · Klick auf ein Land", amHintFull: "Mausrad zoomt · Esc beendet",
  amLegend: "{m} pro Land", amLegendReg: "{m} pro Provinz", amHome: "unsere Hosts", amPlace: "Ort", amPlaceN: "{n} Adressen hier",
  amOfCountry: "{p} des Landes", amRegions: "Provinzen", amNoPlaces: "Orte brauchen die Stadtdaten (geoip_city).", amListed: "auf einer Sperrliste", amClear: "Filter zurücksetzen",
});

const amap = {
  view: null,  // {cx, cy, z}: centre in map units, zoom as a multiple of "fit"
  full: false, wall: false, tour: false,
  shade: store("vigil.amapShade") || "area",
  metric: store("vigil.amapMetric") || "count",
  labels: store("vigil.amapLabels") !== "0",
  live: store("vigil.amapLive") !== "0",
  cls: "all", kind: "all", net: "all", camp: "", host: "",
  sel: "", reg: "",
  cut: null,   // replay: only addresses first seen up to this time (ms)
  cache: null, // {key, at, d}
  inst: null,
};

// attackMap builds the map for the attackers view. cc preselects a country.
function attackMap(days, agent, cc, params) {
  const box = h("div", { class: "amap-wrap" + (amap.full ? " full" : "") + (amap.wall ? " wall" : "") }, h("div", { class: "empty small" }, "…"));
  if (amap.inst) amap.inst.stop();
  amap.inst = null;
  if (cc) { [amap.sel, amap.reg] = cc.split(":"); amap.reg = amap.reg || ""; }
  if (params && params.get("mv")) {
    const [cx, cy, z] = params.get("mv").split(",").map(Number);
    if ([cx, cy, z].every(Number.isFinite)) amap.view = { cx, cy, z };
  }
  const key = days + "|" + (agent || "");
  const load = amap.cache && amap.cache.key === key && Date.now() - amap.cache.at < 60000 ? Promise.resolve(amap.cache.d)
    : api("/api/ui/attacks/map?" + new URLSearchParams({ days, ...(agent ? { agent } : {}) })).then((d) => { amap.cache = { key, at: Date.now(), d }; return d; });
  Promise.all([load, loadWorld()]).then(([d, w]) => {
    if (!box.isConnected && !document.body.contains(box)) { /* still being mounted: carry on */ }
    amap.inst = makeAttackMap(box, d, w);
  }).catch((x) => { console.error(x); box.replaceChildren(h("div", { class: "empty small" }, t("amTitle") + ": " + x.message)); });
  return box;
}

// amapRows turns the short rows into objects.
function amapRows(d) {
  const ix = Object.fromEntries(d.cols.map((c, i) => [c, i]));
  return d.rows.map((r) => ({
    ip: r[ix.ip], cc: r[ix.cc] || "??", asn: r[ix.asn], net: r[ix.net] || "other", cls: r[ix.class], ssh: r[ix.ssh], web: r[ix.web],
    camp: r[ix.campaign], first: r[ix.first] * 1000, last: r[ix.last] * 1000, days: r[ix.days], users: r[ix.users] || [],
    hosts: r[ix.hosts] || [], kinds: r[ix.kinds] || [], listed: r[ix.listed] || "",
    lat: ix.lat == null ? null : r[ix.lat], lon: ix.lon == null ? null : r[ix.lon],
  }));
}

// amapRings reads an outline (M..L..Z parts) into flat x,y arrays with
// their boxes.
function amapRings(d) {
  const out = [];
  for (const part of d.split("M")) {
    if (!part) continue;
    const n = Float32Array.from(part.replace(/Z/g, "").split(/[L,]/), Number);
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (let i = 0; i + 1 < n.length; i += 2) {
      x0 = Math.min(x0, n[i]); x1 = Math.max(x1, n[i]); y0 = Math.min(y0, n[i + 1]); y1 = Math.max(y1, n[i + 1]);
    }
    out.push({ n, box: [x0, y0, x1, y1] });
  }
  return out;
}
// the box around the largest part (for labels and zoom) and around all parts
function amapBox(d) {
  let best = null, bestA = -1, all = [Infinity, Infinity, -Infinity, -Infinity];
  for (const { box: b } of amapRings(d)) {
    const a = (b[2] - b[0]) * (b[3] - b[1]);
    if (a > bestA) { bestA = a; best = b; }
    all = [Math.min(all[0], b[0]), Math.min(all[1], b[1]), Math.max(all[2], b[2]), Math.max(all[3], b[3])];
  }
  return { main: best, all };
}
function amapInRing(x, y, r) {
  let c = false;
  for (let i = 0, j = r.length - 2; i < r.length; j = i, i += 2) {
    const xi = r[i], yi = r[i + 1], xj = r[j], yj = r[j + 1];
    if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) c = !c;
  }
  return c;
}
const amapRegions = {}; // cc -> Promise of the provinces, null when there are none
function amapLoadRegions(cc) {
  if (!(cc in amapRegions)) {
    const own = document.querySelector('script[src^="app.js"]');
    const v = own ? (own.getAttribute("src").split("?v=")[1] || "") : "";
    amapRegions[cc] = fetch("regions/" + cc + ".json" + (v ? "?v=" + v : ""), { credentials: "same-origin" })
      .then((r) => r.ok ? r.json() : null)
      .then((j) => j && j.regions.map((g) => {
        const rings = amapRings(g.d);
        const box = rings.reduce((a, r) => [Math.min(a[0], r.box[0]), Math.min(a[1], r.box[1]), Math.max(a[2], r.box[2]), Math.max(a[3], r.box[3])], [Infinity, Infinity, -Infinity, -Infinity]);
        return { ...g, rings, box, at: g.at || [(box[0] + box[2]) / 2, (box[1] + box[3]) / 2] };
      }))
      .catch(() => { delete amapRegions[cc]; return null; });
  }
  return amapRegions[cc];
}

function makeAttackMap(wrap, d, w) {
  const all = amapRows(d);
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const proj = (lat, lon) => [(lon + 180) / 360 * w.w, (84 - lat) / 142 * w.h];
  const home = d.home ? proj(d.home[0], d.home[1]) : null;
  const boxes = {}, full = {};
  for (const [cc, p] of Object.entries(w.paths)) { const b = amapBox(p); boxes[cc] = b.main; full[cc] = b.all; }
  for (const a of all) a.p = a.lat == null ? null : proj(a.lat, a.lon);
  const placed = all.some((a) => a.p);
  // provinces from this zoom on, places from that
  const REG_Z = 2.6, PLACE_Z = 7;
  const regs = {}; // cc -> provinces, once loaded and drawn
  let byReg = {}, maxReg = 1;
  const tStart = all.length ? Math.min(...all.map((a) => a.first)) : Date.now();
  const tEnd = Math.max(Date.parse(d.generated) || Date.now(), tStart + 1);
  let stopped = false, rows = [], by = {}, max = 1, maxIps = 1, totalCount = 1;
  let liveT = null, tourT = null, playRaf = null, animRaf = null;
  const hadView = !!amap.view;
  if (!hadView) amap.view = { cx: w.w / 2, cy: w.h / 2, z: 1 };

  // ---------- DOM
  const svg = sv("svg", { class: "amap", role: "img", "aria-label": t("amTitle"), tabindex: 0 });
  const ocean = sv("rect", { class: "am-ocean", width: "100%", height: "100%" });
  const world = sv("g");
  const L = {};
  for (const k of ["grat", "land", "region", "bubble", "place", "home", "arc", "label"]) { L[k] = sv("g", { class: "am-" + k }); world.append(L[k]); }
  svg.append(ocean, world);
  const side = h("div", { class: "amap-side" });
  const legend = h("div", { class: "amap-legend" });
  const mini = sv("svg", { class: "amap-mini", "aria-hidden": "true" });
  const toastEl = h("div", { class: "amap-toast", hidden: true });
  const hint = h("div", { class: "amap-hint" });
  const wallEl = h("div", { class: "amap-wallbar" });
  const ticker = h("div", { class: "amap-ticker" });
  const stage = h("div", { class: "amap-stage" }, svg, legend, mini, hint, toastEl, wallEl);
  const bar = h("div", { class: "topo-bar amap-bar" });
  const time = h("div", { class: "amap-time" });
  const body = h("div", { class: "amap-body" }, stage, side);
  wrap.replaceChildren(bar, body, time, ticker);

  // graticule every 30 degrees of longitude and 20 of latitude
  let gd = "";
  for (let lon = -180; lon <= 180; lon += 30) { const [x] = proj(0, lon); gd += "M" + x.toFixed(1) + ",0V" + w.h; }
  for (let lat = -40; lat <= 80; lat += 20) { const [, y] = proj(lat, 0); gd += "M0," + y.toFixed(1) + "H" + w.w; }
  L.grat.append(sv("path", { d: gd }), sv("rect", { class: "am-edge", x: 0, y: 0, width: w.w, height: w.h }));

  const land = {};
  for (const [cc, p] of Object.entries(w.paths)) {
    const el = sv("path", { d: p, class: "land", "data-cc": cc });
    land[cc] = el;
    L.land.append(el);
  }
  if (home) L.home.append(sv("circle", { class: "am-homering", cx: home[0], cy: home[1], r: 6 }), sv("circle", { class: "am-homedot", cx: home[0], cy: home[1], r: 3 }));

  // ---------- view: pan and zoom
  const size = () => [svg.clientWidth || wrap.clientWidth || 800, svg.clientHeight || 520];
  const fitK = () => { const [W, H] = size(); return Math.min(W / w.w, H / w.h) * 0.98; };
  let k = 1, tx = 0, ty = 0;
  const zMin = 0.8, zMax = 36;
  function applyView() {
    const [W, H] = size(), fk = fitK();
    const v = amap.view;
    v.z = Math.max(zMin, Math.min(zMax, v.z));
    k = fk * v.z;
    // keep some of the world in sight
    v.cx = Math.max(0, Math.min(w.w, v.cx)); v.cy = Math.max(0, Math.min(w.h, v.cy));
    amap.view = v;
    tx = W / 2 - v.cx * k; ty = H / 2 - v.cy * k;
    world.setAttribute("transform", "translate(" + tx.toFixed(2) + "," + ty.toFixed(2) + ") scale(" + k.toFixed(5) + ")");
    scaleMarks();
    drawMini();
    placesSoon();
    if ((amap.view.z >= REG_Z) !== legend._reg) { legend._reg = amap.view.z >= REG_Z; drawLegend(); }
  }
  const toWorld = (sx, sy) => [(sx - tx) / k, (sy - ty) / k];
  const local = (e) => { const r = svg.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
  function zoomAt(f, sx, sy) {
    const [wx, wy] = toWorld(sx, sy), [W, H] = size();
    const z = Math.max(zMin, Math.min(zMax, amap.view.z * f)), nk = fitK() * z;
    // the point under the pointer stays put
    amap.view = { z, cx: wx - (sx - W / 2) / nk, cy: wy - (sy - H / 2) / nk };
    applyView();
  }
  function animateTo(target, ms = 900) {
    cancelAnimationFrame(animRaf);
    const from = { ...amap.view };
    if (still) { amap.view = target; applyView(); keepHash(); return; }
    const t0 = performance.now();
    const step = (now) => {
      const p = Math.min(1, (now - t0) / ms), e = p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2;
      // zoom moves in log space, so the speed looks even
      amap.view = { cx: from.cx + (target.cx - from.cx) * e, cy: from.cy + (target.cy - from.cy) * e, z: Math.exp(Math.log(from.z) + (Math.log(target.z) - Math.log(from.z)) * e) };
      applyView();
      if (p < 1) animRaf = requestAnimationFrame(step); else keepHash();
    };
    animRaf = requestAnimationFrame(step);
  }
  const fitWorld = () => animateTo({ cx: w.w / 2, cy: w.h / 2, z: 1 });
  function viewOf(cc, reg) {
    const g = reg && regs[cc] && regs[cc].find((r) => r.id === reg);
    const b = g ? g.box : boxes[cc];
    if (!b) return null;
    const [W, H] = size(), pw = W - 40, ph = H - 40;
    const z = Math.max(1, Math.min(zMax * 0.6, Math.min(pw / (b[2] - b[0] || 1), ph / (b[3] - b[1] || 1)) / fitK() * 0.6));
    return { cx: (b[0] + b[2]) / 2, cy: (b[1] + b[3]) / 2, z };
  }

  // marks that keep their size on screen: circles, labels, arcs
  function scaleMarks() {
    const z = amap.view.z, regOn = z >= REG_Z;
    for (const c of L.bubble.children) c.setAttribute("r", (+c.dataset.r / k).toFixed(3));
    for (const c of L.place.children) c.setAttribute("r", (+c.dataset.r / k).toFixed(3));
    for (const c of L.home.children) c.setAttribute("r", ((c.classList.contains("am-homering") ? 7 : 3.5) / k).toFixed(3));
    svg.classList.toggle("regz", regOn);
    const shown = [];
    const [W, H] = size();
    // a name shows when its area is wide enough on screen, or among the
    // busiest; overlapping names give way to the one before. Zoomed in,
    // provinces come first and the names of their countries step back.
    const deep = z >= REG_Z + 1.2;
    const els = [...L.label.children].map((el) => {
      const reg = !!el.dataset.reg;
      return { el, reg, pri: +el.dataset.rank + (reg ? (deep ? -1000 : 1000) : 0) };
    }).sort((a, b) => a.pri - b.pri);
    for (const { el, reg } of els) {
      el.setAttribute("font-size", ((reg ? 10 : 11) / k).toFixed(3));
      const wide = (+el.dataset.bw) * k > el.dataset.len * 6.4;
      const top = !reg && +el.dataset.rank < 6 + z * 4;
      let on = amap.labels && (wide || top) && (reg ? regOn && regs[el.dataset.cc] : !(deep && regs[el.dataset.cc] && wide));
      if (on) {
        const sx = +el.getAttribute("x") * k + tx, sy = +el.getAttribute("y") * k + ty, hw = el.dataset.len * 3.4;
        if (sx < -hw || sx > W + hw || sy < 0 || sy > H) on = false;
        else if (shown.some(([x, y]) => Math.abs(x - sx) < hw + 20 && Math.abs(y - sy) < 13)) on = false;
        else shown.push([sx, sy]);
      }
      el.classList.toggle("off", !on);
    }
    svg.classList.toggle("zoomed", z > 3);
  }

  // ---------- filters and sums
  const pass = (a) => (amap.cls === "all" || a.cls === amap.cls) && (amap.kind === "all" || (amap.kind === "ssh" ? a.ssh > 0 : a.web > 0))
    && (amap.net === "all" || a.net === amap.net) && (amap.camp === "" || a.camp === +amap.camp) && (!amap.host || a.hosts.includes(amap.host))
    && (amap.cut == null || a.first <= amap.cut);
  const tries = (a) => amap.kind === "ssh" ? a.ssh : amap.kind === "web" ? a.web : a.ssh + a.web;
  function sum() {
    rows = all.filter(pass);
    by = {};
    for (const a of rows) {
      const c = by[a.cc] || (by[a.cc] = { cc: a.cc, ips: 0, count: 0 });
      c.ips++;
      c.count += tries(a);
    }
    sumRegions();
    const list = Object.values(by);
    max = Math.max(1, ...list.map((c) => amap.metric === "ips" ? c.ips : c.count));
    maxIps = Math.max(1, ...list.map((c) => c.ips));
    totalCount = Math.max(1, list.reduce((s, c) => s + (amap.metric === "ips" ? c.ips : c.count), 0));
  }
  function sumRegions() {
    byReg = {};
    for (const a of rows) {
      if (!a.reg) continue;
      const key = a.cc + "|" + a.reg;
      const c = byReg[key] || (byReg[key] = { ips: 0, count: 0 });
      c.ips++;
      c.count += tries(a);
    }
    maxReg = Math.max(1, ...Object.values(byReg).map(val));
  }
  const val = (c) => c ? (amap.metric === "ips" ? c.ips : c.count) : 0;
  // log scale, squared so the middle stays apart from the top
  const level = (n, top = max) => n ? 0.14 + 0.86 * Math.pow(Math.log(1 + n) / Math.log(1 + top), 2) : 0;
  const pct = (n) => (n / totalCount * 100).toLocaleString(lang, { maximumFractionDigits: n / totalCount < 0.1 ? 1 : 0 }) + " %";

  function shade(flash) {
    const area = amap.shade !== "bubbles";
    for (const [cc, el] of Object.entries(land)) {
      const c = by[cc];
      const prev = el.dataset.v;
      el.setAttribute("class", "land" + (c && area ? " hit" : "") + (c ? " pick" : "") + (cc === amap.sel ? " sel" : "") + (amap.sel && cc !== amap.sel ? " dim" : "") + (regs[cc] ? " covered" : ""));
      el.style.fillOpacity = c && area ? level(val(c)) : "";
      el.dataset.v = val(c);
      if (flash && c && prev != null && +prev < val(c)) flashLand(cc);
    }
    L.bubble.replaceChildren();
    const ranked = Object.values(by).sort((a, b) => val(b) - val(a));
    for (const c of ranked.slice().reverse()) {
      const at = w.dots[c.cc];
      if (!at) continue;
      const small = !w.paths[c.cc] || w.paths[c.cc].length <= 160;
      if (amap.shade === "area" && !small) continue;
      const r = amap.shade === "area" ? 3 + 5 * level(val(c)) : 3 + 22 * Math.sqrt(val(c) / max);
      const dot = sv("circle", { cx: at[0], cy: at[1], class: "bub pick" + (c.cc === amap.sel ? " sel" : ""), "data-cc": c.cc, "data-r": r.toFixed(2) });
      L.bubble.append(dot);
    }
    L.label.replaceChildren();
    ranked.forEach((c, i) => {
      const at = w.dots[c.cc], b = boxes[c.cc];
      if (!at || !b || c.cc === "??") return;
      const name = countryName(c.cc);
      L.label.append(sv("text", { x: at[0], y: at[1], class: "am-name" + (c.cc === amap.sel ? " sel" : ""), "data-cc": c.cc, "data-rank": i, "data-len": name.length, "data-bw": (b[2] - b[0]).toFixed(2), dy: "-0.9em" }, name));
    });
    shadeRegions();
    scaleMarks();
    drawLegend();
    drawPlaces();
  }
  const regName = (g) => lang === "de" ? g.de : g.en;
  function shadeRegions() {
    for (const [cc, list] of Object.entries(regs)) {
      if (!list) continue;
      list.forEach((g) => {
        const c = byReg[cc + "|" + g.id], sel = cc === amap.sel && g.id === amap.reg;
        g.el.setAttribute("class", "reg" + (c && amap.shade !== "bubbles" ? " hit" : "") + (c ? " pick" : "") + (sel ? " sel" : "") + (amap.sel && cc !== amap.sel ? " dim" : ""));
        g.el.style.fillOpacity = c && amap.shade !== "bubbles" ? level(val(c), maxReg) : "";
      });
      const ranked = list.filter((g) => byReg[cc + "|" + g.id]).sort((a, b) => val(byReg[cc + "|" + b.id]) - val(byReg[cc + "|" + a.id]));
      ranked.forEach((g, i) => {
        const name = regName(g);
        L.label.append(sv("text", { x: g.at[0], y: g.at[1], class: "am-name reg" + (cc === amap.sel && g.id === amap.reg ? " sel" : ""), "data-cc": cc, "data-reg": g.id,
          "data-rank": i, "data-len": name.length, "data-bw": (g.box[2] - g.box[0]).toFixed(2) }, name));
      });
    }
  }
  // provinces of the countries in sight load once zoomed in
  function needRegions() {
    if (amap.view.z < REG_Z) return;
    const [W, H] = size(), [x0, y0] = toWorld(0, 0), [x1, y1] = toWorld(W, H);
    for (const [cc, b] of Object.entries(full)) {
      if (cc in regs || !(by[cc] || cc === amap.sel) || b[2] < x0 || b[0] > x1 || b[3] < y0 || b[1] > y1) continue;
      regs[cc] = null;
      amapLoadRegions(cc).then((list) => {
        if (stopped || !list) return;
        addRegions(cc, list);
      });
    }
  }
  function addRegions(cc, list) {
    const g = sv("g", { class: "am-regs", "data-cc": cc });
    for (const r of list) {
      r.el = sv("path", { d: r.d, class: "reg", "data-cc": cc, "data-reg": r.id });
      g.append(r.el);
    }
    // each placed address of the country goes to the province around it,
    // or the nearest one when the simplified coast leaves it outside
    for (const a of all) {
      if (a.cc !== cc || !a.p) continue;
      const [x, y] = a.p;
      let hit = list.find((r) => x >= r.box[0] && x <= r.box[2] && y >= r.box[1] && y <= r.box[3] && r.rings.some((q) => amapInRing(x, y, q.n)));
      if (!hit) hit = list.reduce((m, r) => { const dd = Math.hypot(r.at[0] - x, r.at[1] - y); return !m || dd < m[1] ? [r, dd] : m; }, null)[0];
      a.reg = hit.id;
    }
    regs[cc] = list;
    L.region.append(g);
    sum();
    shade();
    if (amap.sel === cc) drawSide();
  }

  // places: the addresses as dots, those close on screen as one
  let placeT = null, placeSel = null;
  function drawPlaces() {
    L.place.replaceChildren();
    if (amap.view.z < PLACE_Z || !placed) return;
    const [W, H] = size(), cell = 30, groups = {};
    for (const a of rows) {
      if (!a.p) continue;
      const sx = a.p[0] * k + tx, sy = a.p[1] * k + ty;
      if (sx < -cell || sx > W + cell || sy < -cell || sy > H + cell) continue;
      const key = Math.floor(sx / cell) + ":" + Math.floor(sy / cell);
      const g = groups[key] || (groups[key] = { list: [], x: 0, y: 0 });
      g.list.push(a); g.x += a.p[0]; g.y += a.p[1];
    }
    const top = Math.max(1, ...Object.values(groups).map((g) => g.list.length));
    for (const g of Object.values(groups)) {
      const n = g.list.length, r = 4 + 8 * Math.sqrt(n / top);
      const worst = g.list.some((a) => a.cls === "success") ? " critical" : g.list.some((a) => a.cls === "targeted") ? " high" : "";
      const dot = sv("circle", { cx: (g.x / n).toFixed(3), cy: (g.y / n).toFixed(3), r: (r / k).toFixed(3), "data-r": r.toFixed(2), class: "am-placedot pick" + worst, "data-place": "1" });
      dot._list = g.list;
      L.place.append(dot);
    }
  }
  const placesSoon = () => { clearTimeout(placeT); placeT = setTimeout(() => { if (!stopped) { drawPlaces(); needRegions(); } }, 90); };
  function flashLand(cc) {
    const el = land[cc];
    if (!el || still) return;
    el.classList.remove("flash");
    void el.getBoundingClientRect();
    el.classList.add("flash");
    setTimeout(() => el.classList.remove("flash"), 1300);
  }

  function drawLegend() {
    const ramp = h("span", { class: "amap-ramp" });
    const m = amap.metric === "ips" ? t("amByIps") : t("amByCount");
    const reg = amap.view.z >= REG_Z && Object.values(regs).some(Boolean);
    legend.replaceChildren(h("div", { class: "amap-lt" }, (reg ? t("amLegendReg") : t("amLegend")).replace("{m}", m)),
      h("div", { class: "amap-lr" }, h("span", null, "1"), ramp, h("span", null, num(reg ? maxReg : max))),
      home ? h("div", { class: "amap-lh" }, h("span", { class: "amap-homekey" }), t("amHome")) : null);
  }

  // ---------- side panel
  const sec = (title, ...kids) => h("div", { class: "amap-sec" }, h("h4", null, title), kids);
  function bars(items, opts = {}) {
    if (!items.length) return h("div", { class: "muted small" }, t("none"));
    const top = Math.max(1, ...items.map((i) => i.n));
    return h("div", { class: "amap-bars" }, items.map((it) => {
      const fill = h("span", { class: "amap-fill" + (opts.tone ? " " + opts.tone : "") });
      fill.style.width = (it.n / top * 100).toFixed(1) + "%";
      return h(it.on ? "button" : "div", { type: it.on ? "button" : null, class: "amap-row" + (it.on ? " click" : ""), onclick: it.on || null, title: it.title || null },
        h("span", { class: "amap-key" + (opts.mono ? " mono" : "") }, it.key), h("span", { class: "amap-n" }, num(it.n)),
        h("span", { class: "amap-track" }, fill), it.sub ? h("span", { class: "amap-sub" }, it.sub) : null);
    }));
  }
  const topOf = (counts, n) => Object.entries(counts).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, n);
  function classBar(list) {
    const counts = { success: 0, targeted: 0, persistent: 0, noise: 0 };
    list.forEach((a) => { counts[a.cls] = (counts[a.cls] || 0) + 1; });
    const total = Math.max(1, list.length);
    const strip = h("div", { class: "amap-strip" }, Object.entries(counts).filter(([, n]) => n).map(([c, n]) => {
      const s = h("span", { class: "dot-bg " + CLASS_DOT[c], title: t("cls_" + c) + ": " + n });
      s.style.flexGrow = n / total;
      return s;
    }));
    return h("div", null, strip, h("div", { class: "amap-clsleg" }, Object.entries(counts).filter(([, n]) => n).map(([c, n]) =>
      h("button", { type: "button", class: "chip click" + (amap.cls === c ? " on" : ""), onclick: () => setFilter("cls", amap.cls === c ? "all" : c) },
        h("span", { class: "dot " + CLASS_DOT[c] }), t("cls_" + c) + " " + num(n)))));
  }
  function drawSide() {
    const cc = amap.sel;
    const g = cc && amap.reg && regs[cc] ? regs[cc].find((r) => r.id === amap.reg) : null;
    const inPlace = placeSel && placeSel.filter((a) => rows.includes(a));
    const list = inPlace || (g ? rows.filter((a) => a.cc === cc && a.reg === g.id) : cc ? rows.filter((a) => a.cc === cc) : rows);
    const n = list.reduce((s, a) => s + tries(a), 0);
    const ofCountry = cc && by[cc] ? t("amOfCountry").replace("{p}", (val({ ips: list.length, count: n }) / Math.max(1, val(by[cc])) * 100).toLocaleString(lang, { maximumFractionDigits: 0 }) + " %") : "";
    const head = inPlace
      ? h("div", { class: "amap-head" }, h("button", { type: "button", class: "btn ghost small", onclick: () => { placeSel = null; drawSide(); } }, "← " + (g ? regName(g) : cc ? countryName(cc) : t("amWorld"))),
        h("h3", null, t("amPlace")), h("div", { class: "muted small" }, [t("amPlaceN").replace("{n}", num(list.length)), num(n) + " " + t("attemptsN"),
          [...new Set(list.map((a) => a.cc))].map(countryName).join(", ")].join("  ·  ")))
      : g
      ? h("div", { class: "amap-head" }, h("button", { type: "button", class: "btn ghost small", onclick: () => select(cc, true) }, "← " + countryName(cc)),
        h("h3", null, regName(g)), h("div", { class: "muted small" }, [t("addressesN").replace("{n}", num(list.length)), num(n) + " " + t("attemptsN"), ofCountry].join("  ·  ")))
      : cc
      ? h("div", { class: "amap-head" }, h("button", { type: "button", class: "btn ghost small", onclick: () => select("") }, "← " + t("amWorld")),
        h("h3", null, countryName(cc)), h("div", { class: "muted small" }, [t("addressesN").replace("{n}", num(list.length)), num(n) + " " + t("attemptsN"),
          t("amShare_").replace("{p}", pct(val(by[cc])))].join("  ·  ")))
      : h("div", { class: "amap-head" }, h("h3", null, t("amWorld")), h("div", { class: "muted small" },
        rows.length === all.length ? t("addressesN").replace("{n}", num(all.length)) : t("amFiltered").replace("{n}", num(rows.length)).replace("{m}", num(all.length))),
        d.truncated ? h("div", { class: "muted small" }, t("amTruncated").replace("{n}", num(all.length)).replace("{m}", num(d.total))) : null);
    if (!list.length) { side.replaceChildren(head, h("div", { class: "empty small" }, t("amNone"))); return; }
    const nets = {}, users = {}, hosts = {}, camps = {};
    for (const a of list) {
      if (a.asn) nets[a.asn] = (nets[a.asn] || 0) + 1;
      for (const u of a.users) users[u] = (users[u] || 0) + 1;
      for (const x of a.hosts) hosts[x] = (hosts[x] || 0) + 1;
      if (a.camp >= 0) camps[a.camp] = (camps[a.camp] || 0) + 1;
    }
    const out = [head, sec(t("amClasses"), classBar(list))];
    if (cc && !g && !inPlace && regs[cc]) {
      const top = regs[cc].map((r) => ({ r, c: byReg[cc + "|" + r.id] })).filter((x) => x.c).sort((a, b) => val(b.c) - val(a.c)).slice(0, 10);
      if (top.length) out.push(sec(t("amRegions"), bars(top.map(({ r, c }) => ({ key: regName(r), n: val(c), on: () => select(cc, true, r.id) })), { tone: "red" })));
    }
    if (!cc && !inPlace) {
      out.push(sec(t("amTopCountries"), bars(Object.values(by).sort((a, b) => val(b) - val(a)).slice(0, 12).map((c) =>
        ({ key: countryName(c.cc), n: val(c), sub: pct(val(c)), on: c.cc !== "??" ? () => select(c.cc, true) : null })), { tone: "red" })));
    }
    out.push(sec(t("amTopNets"), bars(topOf(nets, 6).map(([asn, n]) => ({ key: "AS" + asn + " " + (d.orgs[asn] || ""), n })))));
    if (Object.keys(users).length) out.push(sec(t("amTopUsers"), h("div", { class: "amap-words" }, topOf(users, 14).map(([u, n]) => h("span", { class: "chip mono", title: num(n) + " " + t("addresses") }, u + " " + n)))));
    if (Object.keys(hosts).length > 1 || amap.host) out.push(sec(t("amTargets"), bars(topOf(hosts, 8).map(([x, n]) => ({ key: x, n, on: () => setFilter("host", amap.host === x ? "" : x) })))));
    if (Object.keys(camps).length) out.push(sec(t("amCampaigns"), bars(topOf(camps, 5).map(([c, n]) => {
      const cp = d.campaigns[+c] || {};
      return { key: t("campaignN").replace("{n}", +c + 1), n, sub: (cp.signature || []).map((x) => x.slice(2)).slice(0, 4).join(", "), on: () => setFilter("camp", amap.camp === c ? "" : c) };
    }))));
    const busiest = list.slice().sort((a, b) => tries(b) - tries(a)).slice(0, inPlace ? 30 : 8);
    out.push(sec(t("amTopAddrs"), h("div", { class: "amap-addrs" }, busiest.map((a) => h("div", { class: "amap-addr" },
      h("a", { class: "mono", href: pivotHref("ip", a.ip) }, a.ip), h("span", { class: "dot " + CLASS_DOT[a.cls], title: t("cls_" + a.cls) }),
      h("span", { class: "muted small" }, [num(tries(a)), a.listed ? t("amListed") : "", cc ? "" : a.cc].filter(Boolean).join("  ·  ")))))));
    if (cc && !inPlace) out.push(h("a", { class: "btn ghost small", href: "#/attacks?" + new URLSearchParams({ days: d.days, country: cc }) }, t("amInTable").replace("{c}", countryName(cc))));
    if (cc && !placed) out.push(h("div", { class: "muted small" }, t("amNoPlaces")));
    side.replaceChildren(...out);
  }

  function select(cc, zoom, reg) {
    amap.sel = cc;
    amap.reg = cc && reg || "";
    placeSel = null;
    keepHash();
    shade();
    drawSide();
    if (cc && zoom !== false) { const v = viewOf(cc, amap.reg); if (v) animateTo(v); }
    else if (!cc && zoom) fitWorld();
  }
  function setFilter(key, v) {
    amap[key] = v;
    sum(); shade(); drawSide(); buildBar(); drawTime();
  }

  // ---------- pointer
  const pts = new Map();
  let act = null;
  svg.addEventListener("pointerdown", (e) => {
    if (e.button && e.pointerType === "mouse") return;
    svg.setPointerCapture(e.pointerId);
    svg.focus({ preventScroll: true });
    const p = local(e);
    pts.set(e.pointerId, p);
    stopTour();
    if (pts.size === 2) { act = { kind: "pinch" }; return; }
    const ds = e.target.dataset || {};
    act = { kind: "pan", sx: p[0], sy: p[1], v0: { ...amap.view }, cc: ds.cc, reg: ds.reg, place: ds.place ? e.target._list : null };
  });
  svg.addEventListener("pointermove", (e) => {
    const p = local(e);
    if (!pts.has(e.pointerId)) {
      const ds = e.target.dataset || {};
      if (ds.place) tip(e, placeText(e.target._list));
      else if (ds.cc) tip(e, tipText(ds.cc, ds.reg)); else tip(e, null);
      return;
    }
    pts.set(e.pointerId, p);
    if (!act) return;
    if (act.kind === "pinch" && pts.size === 2) {
      const [a, b] = [...pts.values()], dd = Math.hypot(a[0] - b[0], a[1] - b[1]);
      if (act.d) zoomAt(dd / act.d, (a[0] + b[0]) / 2, (a[1] + b[1]) / 2);
      act.d = dd;
      return;
    }
    if (act.kind !== "pan") return;
    if (!act.moved && Math.hypot(p[0] - act.sx, p[1] - act.sy) < 4) return;
    act.moved = true;
    tip(e, null);
    amap.view = { ...act.v0, cx: act.v0.cx - (p[0] - act.sx) / k, cy: act.v0.cy - (p[1] - act.sy) / k };
    applyView();
  });
  const up = (e) => {
    pts.delete(e.pointerId);
    if (act && act.kind === "pan" && !act.moved) {
      const { cc, reg } = act;
      if (act.place) { placeSel = act.place; drawSide(); }
      else if (cc && reg && byReg[cc + "|" + reg]) select(cc, false, cc === amap.sel && reg === amap.reg ? "" : reg);
      else if (cc && by[cc]) select(cc === amap.sel ? "" : cc, cc !== amap.sel);
      else if (!cc && (amap.sel || placeSel)) select("");
    }
    if (act && act.kind !== "pinch" || !pts.size) { act = null; keepHash(); }
  };
  svg.addEventListener("pointerup", up);
  svg.addEventListener("pointercancel", up);
  svg.addEventListener("pointerleave", (e) => tip(e, null));
  svg.addEventListener("dblclick", (e) => { const [sx, sy] = local(e); zoomAt(2, sx, sy); });
  // the wheel scrolls the page; with Ctrl (or a pinch on a touchpad), or in
  // full screen, it zooms the map
  svg.addEventListener("wheel", (e) => {
    if (!(e.ctrlKey || e.metaKey || amap.full)) { flashHint(); return; }
    e.preventDefault();
    stopTour();
    const [sx, sy] = local(e);
    zoomAt(Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.0018)), sx, sy);
    keepHashSoon();
  }, { passive: false });
  svg.addEventListener("keydown", (e) => {
    const [W, H] = size();
    if (e.key === "+" || e.key === "=") zoomAt(1.4, W / 2, H / 2);
    else if (e.key === "-") zoomAt(1 / 1.4, W / 2, H / 2);
    else if (e.key === "f" || e.key === "F" || e.key === "0") fitWorld();
    else if (e.key.startsWith("Arrow")) {
      const s = 60 / k, v = amap.view;
      amap.view = { ...v, cx: v.cx + (e.key === "ArrowLeft" ? -s : e.key === "ArrowRight" ? s : 0), cy: v.cy + (e.key === "ArrowUp" ? -s : e.key === "ArrowDown" ? s : 0) };
      applyView();
    } else if (e.key === "Escape") {
      if (amap.sel) select("", true);
      else if (amap.full) toggleFull();
      else return;
    } else return;
    e.preventDefault();
    keepHashSoon();
  });
  let hintT = null;
  function flashHint() {
    hint.textContent = t("amHint");
    hint.classList.add("on");
    clearTimeout(hintT);
    hintT = setTimeout(() => hint.classList.remove("on"), 1600);
  }
  function tipText(cc, reg) {
    if (reg) {
      const g = (regs[cc] || []).find((r) => r.id === reg), c = byReg[cc + "|" + reg];
      const name = (g ? regName(g) : reg) + ", " + countryName(cc);
      if (!c) return name;
      return name + "  ·  " + t("addressesN").replace("{n}", num(c.ips)) + ", " + num(c.count) + " " + t("attemptsN") + "  ·  " +
        t("amOfCountry").replace("{p}", (val(c) / Math.max(1, val(by[cc])) * 100).toLocaleString(lang, { maximumFractionDigits: 0 }) + " %");
    }
    const c = by[cc];
    if (!c) return countryName(cc);
    return countryName(cc) + "  ·  " + t("addressesN").replace("{n}", num(c.ips)) + ", " + num(c.count) + " " + t("attemptsN") + "  ·  " + pct(val(c));
  }
  function placeText(list) {
    const nets = {};
    list.forEach((a) => { if (a.asn) nets[a.asn] = (nets[a.asn] || 0) + 1; });
    const top = topOf(nets, 2).map(([asn]) => d.orgs[asn] || "AS" + asn);
    return t("amPlaceN").replace("{n}", num(list.length)) + ", " + num(list.reduce((s, a) => s + tries(a), 0)) + " " + t("attemptsN") + (top.length ? "\n" + top.join(", ") : "");
  }

  // the view and the selection go into the address, so a copied link opens
  // the same map; replaceState keeps the page from rendering again
  let hashT = null;
  function keepHash() {
    const p = new URLSearchParams(location.hash.split("?")[1] || "");
    const v = amap.view;
    if (v) p.set("mv", [v.cx.toFixed(1), v.cy.toFixed(1), v.z.toFixed(2)].join(","));
    if (amap.sel) p.set("sel", amap.sel + (amap.reg ? ":" + amap.reg : "")); else p.delete("sel");
    history.replaceState(null, "", "#/attacks?" + String(p).replace(/%2C/g, ",").replace(/%3A/g, ":"));
  }
  const keepHashSoon = () => { clearTimeout(hashT); hashT = setTimeout(keepHash, 400); };

  // ---------- minimap (full screen)
  const miniLand = sv("g");
  for (const p of Object.values(w.paths)) miniLand.append(sv("path", { d: p }));
  const miniView = sv("rect", { class: "amap-mview" });
  mini.setAttribute("viewBox", "0 0 " + w.w + " " + w.h);
  mini.append(miniLand, miniView);
  mini.addEventListener("pointerdown", (e) => {
    const r = mini.getBoundingClientRect();
    amap.view = { ...amap.view, cx: (e.clientX - r.left) / r.width * w.w, cy: (e.clientY - r.top) / r.height * w.h };
    applyView(); keepHashSoon();
  });
  function drawMini() {
    if (amap.view.z < 1.6) { mini.classList.add("off"); return; }
    mini.classList.remove("off");
    const [W, H] = size(), [x0, y0] = toWorld(0, 0), [x1, y1] = toWorld(W, H);
    miniView.setAttribute("x", x0.toFixed(1)); miniView.setAttribute("y", y0.toFixed(1));
    miniView.setAttribute("width", (x1 - x0).toFixed(1)); miniView.setAttribute("height", (y1 - y0).toFixed(1));
  }

  // ---------- replay: the addresses appear in the order they were first seen
  const BUCKETS = 72;
  function drawTime() {
    const span = tEnd - tStart, hist = new Array(BUCKETS).fill(0);
    const pass2 = (a) => (amap.cls === "all" || a.cls === amap.cls) && (amap.kind === "all" || (amap.kind === "ssh" ? a.ssh > 0 : a.web > 0))
      && (amap.net === "all" || a.net === amap.net) && (amap.camp === "" || a.camp === +amap.camp) && (!amap.host || a.hosts.includes(amap.host));
    for (const a of all) if (pass2(a)) hist[Math.min(BUCKETS - 1, Math.floor((a.first - tStart) / span * BUCKETS))]++;
    const top = Math.max(1, ...hist);
    const cut = amap.cut == null ? tEnd : amap.cut;
    const cols = h("div", { class: "amap-hist" }, hist.map((n, i) => {
      const b = h("span", { class: tStart + (i + 1) / BUCKETS * span <= cut + 1 ? "on" : null });
      b.style.height = (n ? 8 + 92 * n / top : 0) + "%";
      return b;
    }));
    const range = h("input", { type: "range", min: 0, max: 1000, value: Math.round((cut - tStart) / span * 1000), "aria-label": t("amReplay"),
      oninput: (e) => { stopPlay(); amap.cut = +e.target.value >= 1000 ? null : tStart + e.target.value / 1000 * span; sum(); shade(); drawSide(); timeLabel(); markHist(); } });
    const label = h("span", { class: "muted small amap-tl" });
    const timeLabel = () => { label.textContent = amap.cut == null ? t("amAll") : t("amFirstSeen").replace("{t}", new Date(amap.cut).toLocaleString(lang, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })); };
    const markHist = () => { const c = amap.cut == null ? tEnd : amap.cut; [...cols.children].forEach((b, i) => b.classList.toggle("on", tStart + (i + 1) / BUCKETS * span <= c + 1)); };
    timeLabel();
    const playBtn = h("button", { type: "button", class: "btn ghost small" }, playRaf ? t("amPause") : "▶ " + t("amReplay"));
    playBtn.onclick = () => { if (playRaf) stopPlay(); else play(); };
    time.replaceChildren(playBtn, h("div", { class: "amap-slider" }, cols, range), label);
    time._sync = () => { range.value = Math.round(((amap.cut == null ? tEnd : amap.cut) - tStart) / span * 1000); timeLabel(); markHist(); playBtn.textContent = playRaf ? t("amPause") : "▶ " + t("amReplay"); };
  }
  function play() {
    const span = tEnd - tStart, dur = 14000;
    let from = amap.cut == null || amap.cut >= tEnd ? tStart : amap.cut;
    const t0 = performance.now() - (from - tStart) / span * dur;
    let last = 0;
    const step = (now) => {
      const p = Math.min(1, (now - t0) / dur);
      amap.cut = p >= 1 ? null : tStart + p * span;
      if (now - last > 70 || p >= 1) { last = now; sum(); shade(true); if (p >= 1 || Math.round(p * 100) % 10 === 0) drawSide(); }
      if (time._sync) time._sync();
      if (p < 1 && !stopped) playRaf = requestAnimationFrame(step); else { playRaf = null; drawSide(); if (time._sync) time._sync(); }
    };
    playRaf = requestAnimationFrame(step);
    if (time._sync) time._sync();
  }
  function stopPlay() { if (playRaf) { cancelAnimationFrame(playRaf); playRaf = null; if (time._sync) time._sync(); } }

  // ---------- live: arcs from the country to our hosts, a ticker
  let cursor = null, seen = 0;
  const recent = [], perMin = [];
  function shoot(a) {
    const from = a.lat != null ? proj(a.lat, a.lon) : w.dots[a.country];
    if (!from || amap.kind !== "all" && a.kind !== amap.kind) return;
    flashLand(a.country);
    const [ox, oy] = from;
    const ring = sv("circle", { cx: ox, cy: oy, r: 3 / k, class: "am-pulse" });
    L.arc.append(ring);
    if (!still) ring.animate([{ r: 3 / k, opacity: 0.9 }, { r: 16 / k, opacity: 0 }], { duration: 1600, easing: "ease-out" }).finished.then(() => ring.remove(), () => ring.remove());
    else setTimeout(() => ring.remove(), 1600);
    if (!home) return;
    const [hx, hy] = home, dist = Math.hypot(hx - ox, hy - oy);
    const mx = (ox + hx) / 2, my = (oy + hy) / 2 - Math.min(120, dist * 0.35);
    const arc = sv("path", { d: "M" + ox.toFixed(1) + "," + oy.toFixed(1) + "Q" + mx.toFixed(1) + "," + my.toFixed(1) + " " + hx.toFixed(1) + "," + hy.toFixed(1), class: "am-arc " + a.kind, "stroke-width": (1.6 / k).toFixed(3) });
    L.arc.append(arc);
    if (still) { setTimeout(() => arc.remove(), 2500); return; }
    const len = arc.getTotalLength();
    arc.style.strokeDasharray = len.toFixed(1);
    arc.animate([{ strokeDashoffset: len, opacity: 1 }, { strokeDashoffset: 0, opacity: 1, offset: 0.6 }, { strokeDashoffset: 0, opacity: 0 }],
      { duration: 2600, easing: "ease-out" }).finished.then(() => arc.remove(), () => arc.remove());
    setTimeout(() => {
      if (stopped) return;
      const hit = sv("circle", { cx: hx, cy: hy, r: 2 / k, class: "am-impact" });
      L.arc.append(hit);
      hit.animate([{ r: 2 / k, opacity: 1 }, { r: 12 / k, opacity: 0 }], { duration: 900, easing: "ease-out" }).finished.then(() => hit.remove(), () => hit.remove());
    }, 1560);
  }
  function drawTicker() {
    if (!amap.live) { ticker.replaceChildren(); return; }
    const now = Date.now();
    while (perMin.length && now - perMin[0][0] > 300000) perMin.shift();
    const rate = perMin.reduce((s, x) => s + x[1], 0) / 5;
    const head = h("div", { class: "amap-th" }, h("span", { class: "livechip", title: t("liveHint") }, h("span", { class: "livedot" }), "LIVE"),
      h("span", { class: "muted small" }, num(seen) + " " + t("amSeen") + "  ·  " + rate.toLocaleString(lang, { maximumFractionDigits: 1 }) + " " + t("amPerMin")));
    const items = recent.slice(0, amap.wall ? 9 : 4).map((a) => h("div", { class: "frow" },
      h("span", { class: "muted mono" }, new Date(a.time).toLocaleTimeString(lang)),
      h("span", { class: "fcc", title: countryName(a.country) }, a.country || "?"),
      h("a", { class: "mono", href: pivotHref("ip", a.ip) }, a.ip),
      h("span", { class: "muted" }, "→ " + (a.host || "?")),
      h("span", { class: "fwhat mono" }, (a.kind === "ssh" ? "SSH " + (a.users || []).join(", ") : t("webAttack")) + "  ×" + a.count)));
    ticker.replaceChildren(head, items.length ? h("div", { class: "livefeed" }, items) : h("div", { class: "muted small" }, t("amWaiting")));
    if (amap.wall) drawWall();
  }
  async function poll() {
    if (stopped || !wrap.isConnected) { stop(); return; }
    if (!document.hidden && amap.live) {
      try {
        const r = await api("/api/ui/attacks/live" + (cursor == null ? "" : "?after=" + cursor));
        if (stopped) return;
        const fresh = cursor != null;
        cursor = r.cursor;
        if (fresh && r.attacks.length) {
          seen += r.attacks.length;
          perMin.push([Date.now(), r.attacks.length]);
          recent.unshift(...r.attacks.slice(-12).reverse());
          recent.length = Math.min(recent.length, 12);
          r.attacks.slice(-24).forEach((a, i) => setTimeout(() => { if (!stopped) shoot(a); }, i * 220));
        }
        drawTicker();
      } catch { /* the next poll tries again */ }
    }
    liveT = setTimeout(poll, 5000);
  }

  // ---------- the wall: big numbers and a clock over the map
  let clockT = null;
  function drawWall() {
    if (!amap.wall) { wallEl.replaceChildren(); return; }
    const tot = rows.reduce((s, a) => s + tries(a), 0);
    const ccs = Object.keys(by).filter((c) => c !== "??").length;
    const top = Object.values(by).sort((a, b) => val(b) - val(a)).slice(0, 5);
    const tile = (n, l) => h("div", { class: "amap-wt" }, h("div", { class: "amap-wn" }, n), h("div", { class: "amap-wl" }, l));
    wallEl.replaceChildren(
      h("div", { class: "amap-wclock" }, new Date().toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        h("div", { class: "amap-wl" }, new Date().toLocaleDateString(lang, { weekday: "long", day: "numeric", month: "long" }))),
      h("div", { class: "amap-wtiles" }, tile(num(rows.length), t("addressesTitle")), tile(num(tot), t("attemptsN")), tile(num(ccs), t("countries")),
        tile(num(seen), t("amSeen"))),
      h("div", { class: "amap-wtop" }, top.map((c, i) => h("div", { class: "amap-wrow" }, h("span", { class: "amap-wi" }, String(i + 1)),
        h("span", null, countryName(c.cc)), h("span", { class: "amap-wv" }, pct(val(c)))))));
  }
  function startTour() {
    amap.tour = true;
    const top = Object.values(by).filter((c) => c.cc !== "??").sort((a, b) => val(b) - val(a)).slice(0, 6).map((c) => c.cc);
    let i = 0;
    const next = () => {
      if (!amap.tour || stopped) return;
      if (i >= top.length) { i = 0; select(""); fitWorld(); }
      else select(top[i++]);
      tourT = setTimeout(next, 9000);
    };
    next();
    buildBar();
  }
  function stopTour() { if (!amap.tour) return; amap.tour = false; clearTimeout(tourT); buildBar(); }

  // ---------- full screen and wall
  function toggleFull() {
    amap.full = !amap.full;
    if (!amap.full) { amap.wall = false; stopTour(); if (document.fullscreenElement) document.exitFullscreen().catch(() => null); }
    wrap.classList.toggle("full", amap.full);
    wrap.classList.toggle("wall", amap.wall);
    document.body.classList.toggle("topo-noscroll", amap.full);
    buildBar();
    requestAnimationFrame(() => { applyView(); shade(); });
  }
  function toggleWall() {
    amap.wall = !amap.wall;
    if (amap.wall && !amap.full) { amap.full = true; document.body.classList.add("topo-noscroll"); }
    if (amap.wall) {
      if (wrap.requestFullscreen) wrap.requestFullscreen().catch(() => null);
      amap.live = true;
      clearInterval(clockT); clockT = setInterval(drawWall, 1000);
    } else {
      clearInterval(clockT);
      stopTour();
      if (document.fullscreenElement) document.exitFullscreen().catch(() => null);
    }
    wrap.classList.toggle("full", amap.full);
    wrap.classList.toggle("wall", amap.wall);
    buildBar(); drawWall(); drawTicker();
    requestAnimationFrame(() => { applyView(); shade(); });
  }
  document.addEventListener("fullscreenchange", onFs);
  function onFs() { if (!document.fullscreenElement && amap.wall && !stopped) toggleWall(); }

  // ---------- picture
  function exportPng() {
    const [W, H] = size();
    const copy = svg.cloneNode(true);
    const a = [svg, ...svg.querySelectorAll("*")], b = [copy, ...copy.querySelectorAll("*")];
    const props = ["fill", "fill-opacity", "stroke", "stroke-width", "stroke-opacity", "opacity", "font-size", "font-family", "font-weight", "display", "paint-order", "vector-effect"];
    const styles = a.map((el) => { const cs = getComputedStyle(el); return props.map((p) => p + ":" + cs.getPropertyValue(p)).join(";"); });
    b.forEach((el, i) => { el.removeAttribute("style"); el.setAttribute("data-xs", i); });
    copy.setAttribute("xmlns", SVG); copy.setAttribute("width", W); copy.setAttribute("height", H); copy.setAttribute("viewBox", "0 0 " + W + " " + H);
    const esc = (v) => v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
    const text = new XMLSerializer().serializeToString(copy).replace(/data-xs="(\d+)"/g, (_, i) => 'style="' + esc(styles[Number(i)] || "") + '"');
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas"); c.width = W * 2; c.height = H * 2;
      const g = c.getContext("2d"); g.scale(2, 2); g.drawImage(img, 0, 0);
      c.toBlob((bl) => {
        if (!bl) return;
        const l = h("a", { href: URL.createObjectURL(bl), download: "vigil-attacks-" + new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-") + ".png" });
        document.body.append(l); l.click(); setTimeout(() => { URL.revokeObjectURL(l.href); l.remove(); }, 1000);
      }, "image/png");
    };
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(text);
  }
  let toastT = null;
  function toast(msg) { toastEl.textContent = msg; toastEl.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => { toastEl.hidden = true; }, 2500); }

  // ---------- toolbar
  const btn = (label, title, onclick, cls) => h("button", { type: "button", class: "btn ghost small" + (cls ? " " + cls : ""), title, "aria-label": title, onclick }, label);
  const sel = (label, key, opts, after) => h("label", { class: "inline-l" }, label, h("select", { "aria-label": label, onchange: (e) => { if (after) after(e.target.value); else setFilter(key, e.target.value); } },
    opts.map(([v, l]) => h("option", { value: v, selected: String(amap[key]) === String(v) || null }, l))));
  function buildBar() {
    const hostsSeen = [...new Set(all.flatMap((a) => a.hosts))].sort();
    const shadeTabs = h("div", { class: "tabs" }, [["area", t("amArea")], ["bubbles", t("amBubbles")], ["both", t("amBoth")]].map(([v, l]) =>
      h("button", { type: "button", class: amap.shade === v ? "on" : null, onclick: () => { amap.shade = v; store("vigil.amapShade", v); buildBar(); shade(); } }, l)));
    const metricTabs = h("div", { class: "tabs" }, [["count", t("amByCount")], ["ips", t("amByIps")]].map(([v, l]) =>
      h("button", { type: "button", class: amap.metric === v ? "on" : null, onclick: () => { amap.metric = v; store("vigil.amapMetric", v); buildBar(); sum(); shade(); drawSide(); } }, l)));
    const filtered = amap.cls !== "all" || amap.kind !== "all" || amap.net !== "all" || amap.camp !== "" || amap.host;
    const check = (key, label, storeKey, after) => h("label", { class: "check" }, h("input", { type: "checkbox", checked: amap[key] || null,
      onchange: (e) => { amap[key] = e.target.checked; store(storeKey, amap[key] ? "1" : "0"); after(); } }), label);
    bar.replaceChildren(...[
      shadeTabs, metricTabs,
      sel(t("amKind"), "kind", [["all", t("amAllKinds")], ["ssh", "SSH"], ["web", "Web"]]),
      sel(t("classLabel"), "cls", ["all", "success", "targeted", "persistent", "noise"].map((c) => [c, t("cls_" + c)])),
      sel(t("amNet"), "net", [["all", t("amAllNets")], ["hosting", t("net_hosting").split(" (")[0]], ["tor", "Tor"], ["other", t("net_other")]]),
      d.campaigns.length ? sel(t("amCamp"), "camp", [["", t("amAllCamps")], ...d.campaigns.map((c, i) => [String(i), t("campaignN").replace("{n}", i + 1) + " (" + c.size + ")"])]) : null,
      hostsSeen.length > 1 ? sel(t("amHost"), "host", [["", t("amAllHosts")], ...hostsSeen.map((x) => [x, x])]) : null,
      filtered ? btn(t("amClear"), t("amClear"), () => { Object.assign(amap, { cls: "all", kind: "all", net: "all", camp: "", host: "" }); sum(); shade(); drawSide(); buildBar(); drawTime(); }) : null,
      check("labels", t("amLabels"), "vigil.amapLabels", scaleMarks),
      check("live", t("amLive"), "vigil.amapLive", () => { drawTicker(); if (amap.live && !liveT) poll(); }),
      h("span", { class: "topo-tools" },
        btn("−", t("topoZoomOut"), () => { const [W, H] = size(); zoomAt(1 / 1.4, W / 2, H / 2); keepHashSoon(); }),
        btn("+", t("topoZoomIn"), () => { const [W, H] = size(); zoomAt(1.4, W / 2, H / 2); keepHashSoon(); }),
        btn(t("topoFit"), t("topoFit"), fitWorld),
        amap.wall ? btn(amap.tour ? "■ " + t("amTour") : "▶ " + t("amTour"), t("amTour"), () => amap.tour ? stopTour() : startTour(), amap.tour ? "on" : null) : null,
        btn(t("amShare"), t("amShare"), () => { keepHash(); navigator.clipboard && navigator.clipboard.writeText(location.href).then(() => toast(t("amCopied")), () => toast(location.href)); }),
        btn(t("amExport"), t("amExport"), exportPng),
        btn(amap.wall ? t("amWallEnd") : t("amWall"), t("amWall"), toggleWall, amap.wall ? "on" : null),
        btn(amap.full ? t("topoFullEnd") : t("topoFull"), t("topoFull"), toggleFull)),
    ].filter(Boolean));
  }

  function stop() {
    stopped = true;
    clearTimeout(liveT); clearTimeout(tourT); clearInterval(clockT); clearTimeout(hashT); clearTimeout(placeT);
    cancelAnimationFrame(playRaf); cancelAnimationFrame(animRaf);
    document.removeEventListener("fullscreenchange", onFs);
    ro.disconnect();
    if (amap.full && !wrap.isConnected) document.body.classList.remove("topo-noscroll");
  }
  const ro = new ResizeObserver(() => { if (!stopped) { applyView(); } });
  ro.observe(stage);

  if (amap.sel && !w.paths[amap.sel] && amap.sel !== "??") amap.sel = "";
  sum();
  buildBar();
  drawTime();
  shade();
  drawSide();
  drawTicker();
  if (amap.full) document.body.classList.add("topo-noscroll");
  if (amap.wall) { clockT = setInterval(drawWall, 1000); drawWall(); }
  requestAnimationFrame(() => {
    applyView();
    needRegions();
    if (!hadView && amap.sel) { const v = viewOf(amap.sel); if (v) animateTo(v); }
  });
  poll();
  return { stop };
}
