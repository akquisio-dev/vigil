// The host map: the hosts as boxes on a dotted plane, grouped, the internet
// above them, every TCP link as a curve whose dots run from client to
// server. On top of it a shared document everyone sees live
// (/api/ui/map, its event stream): notes, zones, arrows, text, stamps,
// external and planned nodes, plans, comments, tasks and a note per host.
// Admins edit it; everyone may comment. Where a user dragged the boxes for
// themselves stays with the account ("my layout").

Object.assign(T.en, {
  mapTools: "Tools", mapShared: "Shared", mapMine: "My layout", mapLive: "Current state", mapLayer: "Layer", mapOverlay: "Colour by", mapOverlayOff: "nothing",
  mapAlerts: "open alerts", mapUpdates: "updates", mapVulns: "weaknesses", mapCursors: "Pointers", mapAttacks: "Attacks live",
  toolSelect: "Select", toolHand: "Hand", toolComment: "Comment", toolNote: "Note", toolZone: "Zone", toolArrow: "Arrow", toolText: "Text",
  toolStamp: "Symbol", toolExt: "External", toolPlanned: "Planned host", mapUndo: "Undo", mapRedo: "Redo", mapTime: "Time travel",
  mapPanel: "Side panel", mapHelp: "Shortcuts", mapShare: "Share", mapExport: "Export", mapImport: "Import JSON", mapCopied: "Link copied",
  mapTabSel: "Selection", mapTabTasks: "Tasks", mapTabPlans: "Plans", mapTabHistory: "History", mapTabMine: "For me",
  mapNothingSel: "Nothing selected", mapSelected: "{n} selected", mapDelete: "Delete", mapAlign: "Align", mapDistribute: "Distribute",
  mapText: "Text", mapColor: "Colour", mapStyle: "Kind", mapPorts: "Ports", mapLabel: "Label", mapSave: "Save", mapCancel: "Cancel",
  arrowFlow: "data flow", arrowPlanned: "planned", arrowAllow: "allowed", arrowBlock: "to be blocked",
  stFirewall: "Firewall", stDatabase: "Database", stRouter: "Router", stCloud: "Cloud", stUser: "User", stService: "Service", stBackup: "Backup",
  stLock: "Lock", stWarning: "Warning", stMail: "Mail",
  plProvider: "Provider", plSize: "Size", plOwner: "Owner", plStatus: "Status", plMatch: "Hostname", plPlanned: "planned", plOrdered: "ordered",
  plSetup: "set up", plFound: "Host found: {name}", plReplace: "Replace with the host", extOrg: "Network", extUrl: "Address",
  hnTitle: "Host note", hnPurpose: "Purpose", hnOwners: "Looked after by", hnServices: "Services", hnLinks: "Links", hnEdit: "Edit note",
  cmTitle: "Comments", cmNew: "Write a comment", cmReply: "Reply", cmSend: "Send", cmResolve: "Done", cmReopen: "Reopen", cmShowDone: "show done",
  tkTitle: "Tasks", tkNew: "New task", tkAssignee: "For", tkDue: "Due", tkOpen: "open", tkDoing: "in progress", tkDone: "done", tkAll: "all",
  tkNobody: "nobody", tkTarget: "On", tkLayerAll: "all layers", tkLayerHere: "this layer", tkOverdue: "overdue",
  plnNew: "New plan", plnName: "Name", plnDraft: "draft", plnActive: "active", plnDone: "done", plnDropped: "dropped", plnAlert: "alert on unplanned links",
  plnShow: "Show", plnCompare: "Compare with the current state", plnUnplanned: "unplanned", plnMissing: "missing", plnDelAsk: "Delete plan {name} with everything drawn in it?",
  hiRestore: "Restore to here", hiRestoreAsk: "Put the map back to how it was after this change?", hiMore: "older", hiUndo: "undo", hiChanges: "{n} changes",
  miMentions: "Mentions", miTasks: "My tasks", miNone: "Nothing for you",
  impTitle: "Depends on {name}", impNone: "Nothing depends on this host", impShow: "Impact", impEnd: "End impact view",
  mtTitle: "Maintenance", mtFor: "Maintenance for", mtUntil: "in maintenance until {t}",
  ctxOpen: "Open host", ctxDetails: "Details", ctxArrow: "Arrow from here", ctxCopy: "Copy", ctxPaste: "Paste here",
  tmNow: "now", tmPlay: "Play", tmPause: "Pause", tmNewSince: "New since", tmNew: "new", tmOff: "off", tm24h: "24 h", tm7d: "7 days", tmNoData: "No history yet",
  mapAdoptMine: "Use my layout for everyone", mapAdoptAsk: "Put the shared boxes where yours are?", mapReconnect: "Reconnecting…",
  mapLocked: "{user} is moving this", mapHere: "here now", mapConflict: "Changed by someone else", mapPng: "Picture (PNG)", mapSvg: "Drawing (SVG)",
  mapJson: "Map (JSON)", mapImportAsk: "Add {n} entries from the file to the map?", mapReadonly: "Only admins edit the map",
  helpKeys: "V select · H hand · C comment · N note · Z zone · A arrow · T text · S symbol · E external · P planned host\nShift+drag select an area · Shift+click add to selection\nCtrl+Z undo · Ctrl+Shift+Z or Ctrl+Y redo · Ctrl+C / Ctrl+V copy drawn objects\nDelete removes · arrows move by one grid step · F fit · + / − zoom · Esc ends\nCtrl+wheel or two fingers zoom · double click opens a host",
});
Object.assign(T.de, {
  mapTools: "Werkzeuge", mapShared: "Gemeinsam", mapMine: "Meine Anordnung", mapLive: "Ist-Zustand", mapLayer: "Ebene", mapOverlay: "Einfärben nach", mapOverlayOff: "nichts",
  mapAlerts: "offene Alarme", mapUpdates: "Updates", mapVulns: "Schwachstellen", mapCursors: "Zeiger", mapAttacks: "Angriffe live",
  toolSelect: "Auswählen", toolHand: "Hand", toolComment: "Kommentar", toolNote: "Notiz", toolZone: "Zone", toolArrow: "Pfeil", toolText: "Text",
  toolStamp: "Symbol", toolExt: "Extern", toolPlanned: "Geplanter Host", mapUndo: "Rückgängig", mapRedo: "Wiederholen", mapTime: "Zeitreise",
  mapPanel: "Seitenleiste", mapHelp: "Tastenkürzel", mapShare: "Teilen", mapExport: "Export", mapImport: "JSON einlesen", mapCopied: "Link kopiert",
  mapTabSel: "Auswahl", mapTabTasks: "Aufgaben", mapTabPlans: "Pläne", mapTabHistory: "Verlauf", mapTabMine: "Für mich",
  mapNothingSel: "Nichts ausgewählt", mapSelected: "{n} ausgewählt", mapDelete: "Löschen", mapAlign: "Ausrichten", mapDistribute: "Verteilen",
  mapText: "Text", mapColor: "Farbe", mapStyle: "Art", mapPorts: "Ports", mapLabel: "Beschriftung", mapSave: "Speichern", mapCancel: "Abbrechen",
  arrowFlow: "Datenfluss", arrowPlanned: "geplant", arrowAllow: "erlaubt", arrowBlock: "zu sperren",
  stFirewall: "Firewall", stDatabase: "Datenbank", stRouter: "Router", stCloud: "Cloud", stUser: "Nutzer", stService: "Dienst", stBackup: "Sicherung",
  stLock: "Schloss", stWarning: "Warnung", stMail: "Mail",
  plProvider: "Anbieter", plSize: "Größe", plOwner: "Besitzer", plStatus: "Stand", plMatch: "Rechnername", plPlanned: "geplant", plOrdered: "bestellt",
  plSetup: "eingerichtet", plFound: "Host gefunden: {name}", plReplace: "Durch den Host ersetzen", extOrg: "Netz", extUrl: "Adresse",
  hnTitle: "Steckbrief", hnPurpose: "Zweck", hnOwners: "Betreut von", hnServices: "Dienste", hnLinks: "Links", hnEdit: "Steckbrief bearbeiten",
  cmTitle: "Kommentare", cmNew: "Kommentar schreiben", cmReply: "Antworten", cmSend: "Senden", cmResolve: "Erledigt", cmReopen: "Wieder öffnen", cmShowDone: "erledigte zeigen",
  tkTitle: "Aufgaben", tkNew: "Neue Aufgabe", tkAssignee: "Für", tkDue: "Fällig", tkOpen: "offen", tkDoing: "in Arbeit", tkDone: "erledigt", tkAll: "alle",
  tkNobody: "niemand", tkTarget: "An", tkLayerAll: "alle Ebenen", tkLayerHere: "diese Ebene", tkOverdue: "überfällig",
  plnNew: "Neuer Plan", plnName: "Name", plnDraft: "Entwurf", plnActive: "aktiv", plnDone: "erledigt", plnDropped: "verworfen", plnAlert: "Alarm bei ungeplanten Verbindungen",
  plnShow: "Anzeigen", plnCompare: "Mit dem Ist-Zustand vergleichen", plnUnplanned: "ungeplant", plnMissing: "fehlt", plnDelAsk: "Plan {name} mit allem, was darin gezeichnet ist, löschen?",
  hiRestore: "Bis hier zurücksetzen", hiRestoreAsk: "Die Karte auf den Stand nach dieser Änderung zurücksetzen?", hiMore: "ältere", hiUndo: "rückgängig", hiChanges: "{n} Änderungen",
  miMentions: "Erwähnungen", miTasks: "Meine Aufgaben", miNone: "Nichts für dich",
  impTitle: "Hängt an {name}", impNone: "Nichts hängt an diesem Host", impShow: "Auswirkungen", impEnd: "Auswirkungen ausblenden",
  mtTitle: "Wartung", mtFor: "Wartung für", mtUntil: "in Wartung bis {t}",
  ctxOpen: "Host öffnen", ctxDetails: "Details", ctxArrow: "Pfeil von hier", ctxCopy: "Kopieren", ctxPaste: "Hier einfügen",
  tmNow: "jetzt", tmPlay: "Abspielen", tmPause: "Anhalten", tmNewSince: "Neu seit", tmNew: "neu", tmOff: "aus", tm24h: "24 h", tm7d: "7 Tagen", tmNoData: "Noch kein Verlauf",
  mapAdoptMine: "Meine Anordnung für alle übernehmen", mapAdoptAsk: "Die gemeinsamen Kacheln dorthin setzen, wo deine stehen?", mapReconnect: "Verbinde neu…",
  mapLocked: "{user} verschiebt das gerade", mapHere: "gerade da", mapConflict: "Inzwischen von jemand anderem geändert", mapPng: "Bild (PNG)", mapSvg: "Zeichnung (SVG)",
  mapJson: "Karte (JSON)", mapImportAsk: "{n} Einträge aus der Datei zur Karte hinzufügen?", mapReadonly: "Nur Admins bearbeiten die Karte",
  helpKeys: "V Auswählen · H Hand · C Kommentar · N Notiz · Z Zone · A Pfeil · T Text · S Symbol · E Extern · P geplanter Host\nUmschalt+Ziehen wählt einen Bereich · Umschalt+Klick erweitert die Auswahl\nStrg+Z rückgängig · Strg+Umschalt+Z oder Strg+Y wiederholen · Strg+C / Strg+V Zeichnungen kopieren\nEntf löscht · Pfeiltasten verschieben um ein Rasterfeld · F einpassen · + / − zoomen · Esc beendet\nStrg+Mausrad oder zwei Finger zoomen · Doppelklick öffnet einen Host",
});
const tf = (k, vars) => Object.entries(vars || {}).reduce((s, [a, b]) => s.replace("{" + a + "}", b), t(k));

const TOPO_GRID = 20, TOPO_W = 212, TOPO_H = 132;
const XHTML = "http://www.w3.org/1999/xhtml";
const MAP_COLORS = ["yellow", "blue", "green", "red", "purple", "orange", "grey"];
const MAP_STAMPS = ["firewall", "database", "router", "cloud", "user", "service", "backup", "lock", "warning", "mail"];
const MAP_ARROWS = ["flow", "planned", "allow", "block"];
const MAP_ICONS = {
  firewall: ICONS["shield-check"], service: ICONS.server, warning: ICONS["alert-triangle"],
  database: ["M12 6m-8 0a8 3 0 1 0 16 0a8 3 0 1 0 -16 0", "M4 6v6a8 3 0 0 0 16 0v-6", "M4 12v6a8 3 0 0 0 16 0v-6"],
  router: ["M3 13m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v4a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z", "M17 17l0 .01", "M13 17l0 .01", "M15 13l0 -2", "M11.75 8.75a4 4 0 0 1 6.5 0", "M8.5 6.5a8 8 0 0 1 13 0"],
  cloud: ["M6.657 18c-2.572 0 -4.657 -2.007 -4.657 -4.483c0 -2.475 2.085 -4.482 4.657 -4.482c.393 -1.762 1.794 -3.2 3.675 -3.773c1.88 -.572 3.956 -.193 5.444 1c1.488 1.19 2.162 3.007 1.77 4.769h.99c1.913 0 3.464 1.56 3.464 3.486c0 1.927 -1.551 3.487 -3.465 3.487h-11.878"],
  user: ["M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0", "M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2"],
  backup: ["M3 4m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v0a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z", "M5 8v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-10", "M10 12l4 0"],
  lock: ["M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6z", "M11 16a1 1 0 1 0 2 0a1 1 0 0 0 -2 0", "M8 11v-4a4 4 0 1 1 8 0v4"],
  mail: ["M3 7a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v10a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-10z", "M3 7l9 6l9 -6"],
};

// State kept across the page's 30 s refresh and across views.
const topo = { view: null, sel: [], full: false, pos: null, drag: false, saveT: null, find: "", inst: null,
  showVigil: store("vigil.topoVigil") !== "0", showNet: store("vigil.topoNet") !== "0",
  layer: store("vigil.mapLayer") || "", mine: store("vigil.mapMine") === "1", cursors: store("vigil.mapCursors") !== "0",
  overlay: store("vigil.mapOverlay") || "", attacks: store("vigil.mapAttacks") === "1", tool: "select", stamp: "firewall", arrow: "flow",
  panel: "", compare: false, impact: null, time: false, timeIdx: -1, newSince: store("vigil.mapNewSince") || "", clip: [], showDone: false,
  tkStatus: "open", tkWho: "", tkLayer: "here" };
const topoBusy = () => topo.drag;
const live = { doc: null, edit: false, users: [], me: "", es: null, conn: "", presence: [], cursors: {}, pulses: {}, lost: false, timeline: null };
const DB_PORTS = new Set([3306, 5432, 6379, 27017, 9200, 11211, 5672]);
const linkKind = (port, agentPort) => port === agentPort ? "vigil" : port === 22 ? "ssh" : DB_PORTS.has(port) ? "db" : "tcp";
const snap = (v) => Math.round(v / TOPO_GRID) * TOPO_GRID;
const midCut = (s, n) => s.length <= n ? s : s.slice(0, Math.ceil((n - 1) * 0.4)) + "…" + s.slice(s.length - Math.floor((n - 1) * 0.6));
const newMapID = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const userHue = (u) => { let x = 0; for (const c of u || "") x = (x * 31 + c.charCodeAt(0)) >>> 0; return x % 360; };
const userColor = (u) => "hsl(" + userHue(u) + " 65% 48%)";
const cloneObj = (o) => JSON.parse(JSON.stringify(o));
// the page's CSP allows no style attributes; a custom property set from
// script is fine
const withUC = (el, u) => { el.style.setProperty("--uc", userColor(u)); return el; };

// shortNames drops the words every host of a group shares, so two boxes
// named "Oracle 6GB 1vCPU 50GB - <ip>" show what tells them apart.
function shortNames(hosts) {
  const by = new Map();
  for (const x of hosts) { const g = primaryGroup(x); if (!by.has(g)) by.set(g, []); by.get(g).push(x); }
  const out = {};
  for (const list of by.values()) {
    const words = list.map((x) => x.name.split(/\s+/).filter(Boolean));
    const common = list.length > 1 ? new Set(words[0].filter((w) => words.every((ws) => ws.includes(w)))) : new Set();
    list.forEach((x, i) => {
      const kept = words[i].filter((w) => !common.has(w) && /[\p{L}\p{N}]/u.test(w));
      const last = kept[kept.length - 1];
      // too long for the box: the last word alone (often the address) if it tells the host apart
      out[x.id] = !kept.length ? x.name : kept.join(" ").length > 22 && words.filter((ws) => ws[ws.length - 1] === last).length === 1 ? last : kept.join(" ");
    });
  }
  return out;
}

// autoLayout places the boxes nobody has placed yet: the server's group in
// the middle, the other groups around it, a group's hosts side by side.
// Saved positions win; a new box is pushed off any box it lands on.
function autoLayout(hosts, centre, saved) {
  const by = new Map();
  for (const x of hosts) { const g = primaryGroup(x); if (!by.has(g)) by.set(g, []); by.get(g).push(x); }
  const mid = centre ? primaryGroup(centre) : null;
  const names = [...by.keys()].sort((a, b) => (a === mid ? -1 : b === mid ? 1 : (a === "") - (b === "") || a.localeCompare(b, lang)));
  const gx = TOPO_W + 40, gy = TOPO_H + 60;
  const block = (list) => { const cols = Math.min(list.length, list.length > 4 ? Math.ceil(Math.sqrt(list.length)) : list.length); return { cols, w: cols * gx, h: Math.ceil(list.length / cols) * gy }; };
  const pos = {};
  const place = (list, cx, cy) => {
    const b = block(list);
    if (centre) list = [...list].sort((a, z) => (z === centre) - (a === centre));
    list.forEach((x, i) => { pos[x.id] = [cx - b.w / 2 + gx / 2 + (i % b.cols) * gx, cy - b.h / 2 + gy / 2 + Math.floor(i / b.cols) * gy]; });
  };
  const ring = names.filter((g) => g !== mid);
  if (mid !== null && by.has(mid)) place(by.get(mid), 0, 0);
  else if (ring.length) place(by.get(ring.shift()), 0, 0);
  // up to four other groups on an arc below and beside the middle, more
  // in rows below it; the internet sits on top
  const span = ring.reduce((s, g) => s + block(by.get(g)).w + 80, 0);
  const midH = mid !== null && by.has(mid) ? block(by.get(mid)).h : gy;
  if (ring.length <= 4) {
    const R = Math.max(360, span / 2.4);
    ring.forEach((g, i) => {
      const th = (-10 + 200 * (i + 0.5) / ring.length) * Math.PI / 180;
      place(by.get(g), R * Math.cos(Math.PI - th), Math.max(0, Math.sin(th)) * (midH / 2 + block(by.get(g)).h / 2 + 40 + R * 0.12));
    });
  } else {
    const maxW = Math.max(1400, Math.sqrt(span * gy * ring.length) * 1.4);
    const rows = [[]];
    let w = 0;
    for (const g of ring) {
      const bw = block(by.get(g)).w + 80;
      if (w + bw > maxW && rows[rows.length - 1].length) { rows.push([]); w = 0; }
      rows[rows.length - 1].push(g); w += bw;
    }
    let y = midH / 2 + 120;
    for (const r of rows) {
      const rw = r.reduce((s, g) => s + block(by.get(g)).w + 80, -80), rh = Math.max(...r.map((g) => block(by.get(g)).h));
      let x = -rw / 2;
      for (const g of r) { const b = block(by.get(g)); place(by.get(g), x + b.w / 2, y + rh / 2); x += b.w + 80; }
      y += rh + 90;
    }
  }
  for (const id in pos) if (saved[id]) pos[id] = saved[id].slice();
  // push apart what overlaps; a saved box stays where its user put it
  const ids = Object.keys(pos), mx = TOPO_W + 24, my = TOPO_H + 34;
  for (let it = 0; it < 80; it++) {
    let moved = false;
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) {
      const a = pos[ids[i]], b = pos[ids[j]];
      const ox = mx - Math.abs(a[0] - b[0]), oy = my - Math.abs(a[1] - b[1]);
      if (ox <= 0 || oy <= 0) continue;
      const fa = saved[ids[i]] ? 0 : 1, fb = saved[ids[j]] ? 0 : 1;
      if (!fa && !fb) continue;
      moved = true;
      const k = 1 / (fa + fb);
      if (ox / mx < oy / my) { const s = (a[0] <= b[0] ? -1 : 1) * (ox + 1); a[0] += s * fa * k; b[0] -= s * fb * k; }
      else { const s = (a[1] <= b[1] ? -1 : 1) * (oy + 1); a[1] += s * fa * k; b[1] -= s * fb * k; }
    }
    if (!moved) break;
  }
  for (const id of ids) if (!saved[id]) pos[id] = [snap(pos[id][0]), snap(pos[id][1])];
  const top = Math.min(...ids.map((id) => pos[id][1]), 0);
  const cid = centre ? centre.id : ids[0];
  pos.net = saved.net ? saved.net.slice() : [snap(pos[cid] ? pos[cid][0] : 0), snap(top - TOPO_H / 2 - 120)];
  return pos;
}

function saveTopo() {
  clearTimeout(topo.saveT);
  topo.saveT = setTimeout(() => { post("/api/ui/account/topology", { pos: topo.pos }).catch((x) => console.error(x)); }, 600);
}

// ---------- the shared document, live

async function mapLoad() {
  const r = await api("/api/ui/map");
  live.doc = r.doc; live.edit = r.edit; live.users = r.users || []; live.me = r.me;
  for (const k of ["layers", "objects", "layout", "comments", "tasks", "notes"]) live.doc[k] = live.doc[k] || {};
  if (topo.layer && !live.doc.layers[topo.layer]) topo.layer = "";
}

function docPut(c, id, v) {
  if (!live.doc) return;
  if (v == null) delete live.doc[c][id]; else live.doc[c][id] = v;
}

function mapConnect() {
  if (live.es || typeof EventSource === "undefined") return;
  const es = new EventSource("/api/ui/map/stream");
  live.es = es;
  es.addEventListener("hello", async (e) => {
    const m = JSON.parse(e.data);
    live.conn = m.conn;
    if (live.lost || !live.doc || live.doc.rev !== m.rev) { await mapLoad().catch(() => null); }
    live.lost = false;
    if (topo.inst) topo.inst.redraw();
  });
  es.addEventListener("ops", (e) => {
    const m = JSON.parse(e.data);
    if (!live.doc) return;
    for (const x of m.entries) docPut(x.c, x.id, x.after == null ? null : x.after);
    live.doc.rev = Math.max(live.doc.rev || 0, m.rev);
    if (topo.inst) topo.inst.redraw();
  });
  es.addEventListener("presence", (e) => { live.presence = JSON.parse(e.data); if (topo.inst) topo.inst.people(); });
  es.addEventListener("cursor", (e) => {
    const c = JSON.parse(e.data);
    if (c.conn === live.conn) return;
    if (c.off) delete live.cursors[c.conn]; else live.cursors[c.conn] = { ...c, at: Date.now() };
    if (topo.inst) topo.inst.cursors();
  });
  es.addEventListener("alert", (e) => {
    for (const a of JSON.parse(e.data)) if (a.agent) live.pulses[a.agent] = { sev: a.severity, until: Date.now() + 9000, title: a.title };
    if (topo.inst) topo.inst.pulse();
  });
  es.onerror = () => { live.lost = true; if (topo.inst) topo.inst.people(); };
}

function mapClose() {
  if (live.es) { live.es.close(); live.es = null; }
  live.conn = ""; live.cursors = {}; live.presence = [];
  if (topo.inst) { topo.inst.stop(); topo.inst = null; }
}

// send applies the changes at once and hands them to the server; what it
// sends back over the stream wins. A refusal reloads the document.
async function mapSend(ops, quiet) {
  if (!ops.length) return;
  const now = new Date().toISOString();
  for (const o of ops) {
    const old = live.doc[o.c][o.id] || {};
    docPut(o.c, o.id, o.op === "del" ? null : o.c === "layout" ? o.v : { ...o.v, id: o.id, author: old.author || live.me, created: old.created || now, updated: now });
  }
  if (topo.inst) topo.inst.redraw();
  for (let i = 0; i < ops.length; i += 500) {
    try { await post("/api/ui/map/ops", { ops: ops.slice(i, i + 500) }); }
    catch (x) {
      if (!quiet && topo.inst) topo.inst.toast(x.message);
      await mapLoad().catch(() => null);
      if (topo.inst) topo.inst.redraw();
      return false;
    }
  }
  return true;
}
const putOp = (c, id, v) => ({ op: "put", c, id, v });
const delOp = (c, id) => ({ op: "del", c, id });

async function mapUndo(redo) {
  try { await post("/api/ui/map/undo", { redo: !!redo }); }
  catch (x) { if (topo.inst) topo.inst.toast(/changed/.test(x.message) ? t("mapConflict") : x.message); }
}

Object.assign(MAP_ICONS, {
  comment: ["M8 9h8", "M8 13h6", "M18 4a3 3 0 0 1 3 3v8a3 3 0 0 1 -3 3h-5l-5 3v-3h-2a3 3 0 0 1 -3 -3v-8a3 3 0 0 1 3 -3h12z"],
  task: ["M3.5 5.5l1.5 1.5l2.5 -2.5", "M3.5 11.5l1.5 1.5l2.5 -2.5", "M3.5 17.5l1.5 1.5l2.5 -2.5", "M11 6l9 0", "M11 12l9 0", "M11 18l9 0"],
  info: ["M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0", "M12 9h.01", "M11 12h1v4h1"],
  tool: ["M7 10h3v-3l-3.5 -3.5a6 6 0 0 1 8 8l6 6a2 2 0 0 1 -3 3l-6 -6a6 6 0 0 1 -8 -8l3.5 3.5"],
});
// a small icon inside the map's SVG
function mapIcon(name, x, y, size, cls) {
  const s = icon(null, "0 0 24 24", MAP_ICONS[name] || ICONS[name]);
  s.setAttribute("x", x); s.setAttribute("y", y); s.setAttribute("width", size); s.setAttribute("height", size);
  s.setAttribute("class", "mic" + (cls ? " " + cls : ""));
  return s;
}
// text that wraps, for notes, zones' labels and text objects
function foText(x, y, w, hgt, text, cls) {
  const fo = sv("foreignObject", { x, y, width: Math.max(1, w), height: Math.max(1, hgt) });
  const div = document.createElementNS(XHTML, "div");
  div.setAttribute("class", cls);
  // links in a note open in a new tab; only http(s), the rest stays text
  const parts = String(text || "").split(/(https?:\/\/[^\s<>"]+)/g);
  for (const p of parts) {
    if (/^https?:\/\//.test(p)) {
      const a = document.createElementNS(XHTML, "a");
      a.setAttribute("href", p); a.setAttribute("target", "_blank"); a.setAttribute("rel", "noopener noreferrer");
      a.textContent = p;
      div.append(a);
    } else if (p) div.append(document.createTextNode(p));
  }
  fo.append(div);
  return fo;
}
function presencePost(body) {
  if (!me) return;
  fetch("/api/ui/map/presence", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF": me.csrf }, body: JSON.stringify(body) }).catch(() => null);
}

function topology(d) {
  if (topo.inst) { topo.inst.update(d); return topo.inst.el; }
  topo.inst = makeMap(d);
  mapConnect();
  if (!live.doc) mapLoad().then(() => topo.inst && topo.inst.redraw()).catch((x) => console.error(x));
  return topo.inst.el;
}

function makeMap(d0) {
  let d = d0, hosts = [], byId = {}, centre = null, names = {}, agentPort = 0, pos = {};
  const tmp = {};     // objects being dragged: id -> {x, y, w, h}
  const linkMid = {}; // where each pair's label sits, for comment pins
  let hover = null, stopped = false, rafPending = false, dirty = false;
  const still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const canEdit = () => !!live.edit;
  const canMoveHosts = () => topo.mine || canEdit();
  const doc = () => live.doc || { layers: {}, objects: {}, layout: {}, comments: {}, tasks: {}, notes: {} };
  const inLayer = (l) => !l || l === topo.layer;
  const visObjects = () => Object.values(doc().objects).filter((o) => inLayer(o.layer));
  const objOf = (id) => { const o = doc().objects[id]; return o && tmp[id] ? { ...o, ...tmp[id] } : o; };

  function setData(nd) {
    d = nd;
    hosts = d.hosts; agentPort = d.agent_port;
    byId = Object.fromEntries(hosts.map((x) => [x.id, x]));
    centre = hosts.find((x) => x.server) || hosts[0];
    names = shortNames(hosts);
  }
  function layoutNow() {
    const saved = topo.mine ? (topo.pos || {}) : (doc().layout || {});
    const p = autoLayout(hosts, centre, saved);
    // keep boxes being dragged where the pointer is
    if (topo.drag && act && act.hosts) for (const id of act.hosts) if (pos[id]) p[id] = pos[id];
    pos = p;
  }
  setData(d0);

  // ---------- DOM
  const svg = sv("svg", { class: "topo", role: "img", "aria-label": t("topology"), tabindex: 0 });
  const defs = sv("defs", {}, sv("pattern", { id: "topo-dots", width: TOPO_GRID, height: TOPO_GRID, patternUnits: "userSpaceOnUse" },
    sv("circle", { cx: 1, cy: 1, r: 1, class: "tdot" })));
  const bg = sv("rect", { width: "100%", height: "100%", fill: "url(#topo-dots)", class: "topo-bg" });
  const world = sv("g");
  const L = {};
  for (const k of ["zone", "hull", "edge", "arrow", "label", "atk", "node", "obj", "pin", "temp", "cursor"]) { L[k] = sv("g", { class: "l-" + k }); world.append(L[k]); }
  svg.append(defs, bg, world);
  const side = h("div", { class: "topo-side", hidden: true });
  const mini = sv("svg", { class: "topo-mini", "aria-hidden": "true" });
  const timebar = h("div", { class: "topo-time", hidden: true });
  const toastEl = h("div", { class: "topo-toast", hidden: true });
  const ctx = h("div", { class: "topo-ctx", hidden: true });
  const stage = h("div", { class: "topo-stage" }, svg, side, mini, timebar, toastEl, ctx);
  const bar = h("div", { class: "topo-bar" });
  const tools = h("div", { class: "topo-tools-row" });
  const wrap = h("div", { class: "topo-wrap" + (topo.full ? " full" : "") }, bar, tools, stage);

  let toastT = null;
  function toast(msg) {
    toastEl.textContent = msg; toastEl.hidden = false;
    clearTimeout(toastT); toastT = setTimeout(() => { toastEl.hidden = true; }, 3500);
  }

  // ---------- view: pan and zoom
  const applyView = () => {
    const v = topo.view;
    if (!v) return;
    world.setAttribute("transform", "translate(" + v.x + "," + v.y + ") scale(" + v.k + ")");
    defs.firstChild.setAttribute("patternTransform", "translate(" + v.x + "," + v.y + ") scale(" + v.k + ")");
    drawCursors();
    drawMini();
  };
  function bbox(all) {
    const ps = [];
    for (const [id, p] of Object.entries(pos)) if (id !== "net" || topo.showNet) ps.push([p[0] - TOPO_W / 2, p[1] - TOPO_H / 2], [p[0] + TOPO_W / 2, p[1] + TOPO_H / 2]);
    if (all !== false) for (const o of visObjects()) { const b = objBox(o); ps.push([b[0], b[1]], [b[2], b[3]]); }
    if (!ps.length) return [-400, -300, 400, 300];
    return [Math.min(...ps.map((p) => p[0])) - 40, Math.min(...ps.map((p) => p[1])) - 50, Math.max(...ps.map((p) => p[0])) + 40, Math.max(...ps.map((p) => p[1])) + 40];
  }
  const fit = () => {
    const W = svg.clientWidth || wrap.clientWidth, H = svg.clientHeight || 520;
    if (!W) return;
    const [x0, y0, x1, y1] = bbox();
    const k = Math.max(0.2, Math.min(1.1, W / (x1 - x0), H / (y1 - y0)));
    topo.view = { k, x: W / 2 - (x0 + x1) / 2 * k, y: H / 2 - (y0 + y1) / 2 * k };
    // on a phone the whole map would be too small to read: start at the server
    if (k < 0.35 && W < 620 && centre && pos[centre.id]) topo.view = { k: 0.35, x: W / 2 - pos[centre.id][0] * 0.35, y: H / 2 - pos[centre.id][1] * 0.35 };
    applyView();
  };
  const zoomAt = (f, sx, sy) => {
    const v = topo.view, k = Math.max(0.15, Math.min(2.5, v.k * f));
    topo.view = { k, x: sx - (sx - v.x) * k / v.k, y: sy - (sy - v.y) * k / v.k };
    applyView();
  };
  const centreOn = (x, y) => { const v = topo.view; topo.view = { k: v.k, x: svg.clientWidth / 2 - x * v.k, y: svg.clientHeight / 2 - y * v.k }; applyView(); };
  const local = (e) => { const r = svg.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
  const toWorld = ([sx, sy]) => { const v = topo.view; return [(sx - v.x) / v.k, (sy - v.y) / v.k]; };

  // ---------- geometry of drawn objects
  const BOXED = { note: 1, zone: 1, text: 1 };
  function objBox(o) {
    if (BOXED[o.kind]) return [o.x, o.y, o.x + (o.w || 200), o.y + (o.h || 100)];
    if (o.kind === "stamp") return [o.x - 26, o.y - 26, o.x + 26, o.y + 40];
    if (o.kind === "ext") return [o.x - 80, o.y - 20, o.x + 80, o.y + 20];
    if (o.kind === "planned") return [o.x - TOPO_W / 2, o.y - TOPO_H / 2, o.x + TOPO_W / 2, o.y + TOPO_H / 2];
    if (o.kind === "arrow") { const [a, b] = arrowEnds(o); return [Math.min(a[0], b[0]), Math.min(a[1], b[1]), Math.max(a[0], b[0]), Math.max(a[1], b[1])]; }
    return [o.x, o.y, o.x, o.y];
  }
  const objCentre = (o) => { const b = objBox(o); return [(b[0] + b[2]) / 2, (b[1] + b[3]) / 2]; };
  function refPoint(ref) {
    if (!ref) return null;
    if (ref === "net") return pos.net;
    if (ref.startsWith("host:")) return pos[ref.slice(5)] || null;
    if (ref.startsWith("obj:")) { const o = objOf(ref.slice(4)); return o && o.kind !== "arrow" ? objCentre(o) : null; }
    return null;
  }
  // the half size of what an arrow ends at, so it stops at the border
  function refHalf(ref) {
    if (!ref) return [0, 0];
    if (ref === "net") return [78, 18];
    if (ref.startsWith("host:")) return [TOPO_W / 2, TOPO_H / 2];
    const o = objOf(ref.slice(4));
    if (!o) return [0, 0];
    const b = objBox(o);
    return [(b[2] - b[0]) / 2, (b[3] - b[1]) / 2];
  }
  function trim(p, half, toward) {
    const dx = toward[0] - p[0], dy = toward[1] - p[1];
    if (!half[0] || (!dx && !dy)) return p.slice();
    const s = Math.min(half[0] / Math.abs(dx || 1e-9), half[1] / Math.abs(dy || 1e-9));
    return s >= 1 ? p.slice() : [p[0] + dx * s, p[1] + dy * s];
  }
  function arrowEnds(o) {
    const a = refPoint(o.from) || [o.x, o.y], b = refPoint(o.to) || [o.x2, o.y2];
    return [trim(a, refHalf(o.from), b), trim(b, refHalf(o.to), a)];
  }

  // ---------- what to draw on the links
  function flowsShown() {
    let fl = d.flows;
    const tl = live.timeline;
    if (topo.time && tl && tl.snaps.length && topo.timeIdx >= 0 && topo.timeIdx < tl.snaps.length - 1) {
      fl = tl.snaps[topo.timeIdx].flows.map((f) => ({ from: f.f, to: f.t, port: f.p, n: f.n }));
    }
    return fl.filter((f) => byId[f.from] && byId[f.to] && (topo.showVigil || f.port !== agentPort));
  }
  function isNew(f) {
    const tl = live.timeline;
    if (!topo.newSince || !tl) return false;
    const since = Date.now() / 1000 - (topo.newSince === "7d" ? 7 * 86400 : 86400);
    const first = tl.first_seen[f.from + "|" + f.to + "|" + f.port];
    return first && first >= since && first > tl.from + 600;
  }
  // the plan shown, compared with the links seen
  function compare(fl) {
    const out = { unplanned: new Set(), missing: new Set(), n: 0, m: 0 };
    if (!topo.layer || !topo.compare) return out;
    const covered = new Set(), allow = [], block = [];
    for (const o of Object.values(doc().objects)) {
      if (o.layer !== topo.layer || o.kind !== "arrow" || !/^(allow|block)$/.test(o.style) || !/^host:/.test(o.from || "") || !/^host:/.test(o.to || "")) continue;
      const a = o.from.slice(5), b = o.to.slice(5), ports = String((o.meta || {}).port || "").split(",").map((x) => Number(x.trim())).filter(Boolean);
      covered.add(a); covered.add(b);
      (o.style === "allow" ? allow : block).push({ id: o.id, a, b, ports });
    }
    const hit = (r, f) => r.a === f.from && r.b === f.to && (!r.ports.length || r.ports.includes(f.port));
    for (const f of fl) {
      if (f.port === agentPort || !covered.has(f.from) || !covered.has(f.to)) continue;
      if (block.some((r) => hit(r, f)) || !allow.some((r) => hit(r, f))) { out.unplanned.add([f.from, f.to].sort().join("|")); out.n++; }
    }
    for (const r of allow) if (!fl.some((f) => hit(r, f))) { out.missing.add(r.id); out.m++; }
    return out;
  }

  // ---------- drawing
  const nodeEls = {}, objEls = {};
  let cmp = { unplanned: new Set(), missing: new Set(), n: 0, m: 0 };
  const flowText = (f) => (byId[f.from] || {}).name + " → " + (byId[f.to] || {}).name + "  " + portName(f.port, agentPort) + " (" + f.port + ")  ×" + f.n +
    ([f.client_proc, f.server_proc].some(Boolean) ? "  " + [f.client_proc || "?", f.server_proc || "?"].join(" → ") : "");

  function drawHulls() {
    L.hull.replaceChildren();
    const by = new Map();
    for (const x of hosts) { const g = primaryGroup(x); if (g && pos[x.id]) { if (!by.has(g)) by.set(g, []); by.get(g).push(pos[x.id]); } }
    for (const [g, ps] of by) {
      const x0 = Math.min(...ps.map((p) => p[0])) - TOPO_W / 2 - 18, y0 = Math.min(...ps.map((p) => p[1])) - TOPO_H / 2 - 38;
      const x1 = Math.max(...ps.map((p) => p[0])) + TOPO_W / 2 + 18, y1 = Math.max(...ps.map((p) => p[1])) + TOPO_H / 2 + 30;
      L.hull.append(sv("g", { class: "hull " + groupClass(g) },
        sv("rect", { x: x0, y: y0, width: x1 - x0, height: y1 - y0, rx: 18 }),
        sv("text", { x: x0 + 16, y: y0 + 22 }, g)));
    }
  }

  function drawEdges() {
    L.edge.replaceChildren(); L.label.replaceChildren();
    const fl = flowsShown();
    cmp = compare(fl);
    if (topo.showNet && pos.net) {
      const [nx, ny] = pos.net;
      for (const x of hosts) {
        const n = (x.ext_in || 0) + (x.ext_out || 0);
        if (!x.metrics || !pos[x.id]) continue;
        const [x1, y1] = pos[x.id];
        L.edge.append(hoverTip(sv("line", { x1, y1: y1 - TOPO_H / 2, x2: nx, y2: ny + 16, class: "edge ext", "data-a": x.id, "data-b": "net", "stroke-width": n ? 1 + Math.log10(1 + n) : 1 }),
          x.name + "  ·  " + t("internet") + ": " + (x.ext_in || 0) + " " + t("connIn") + ", " + (x.ext_out || 0) + " " + t("connOut")));
      }
    }
    const pairs = {};
    for (const f of fl) { const k = [f.from, f.to].sort().join("|"); (pairs[k] = pairs[k] || []).push(f); }
    let pid = 0;
    for (const [k, list] of Object.entries(pairs)) {
      const [a, b] = k.split("|");
      if (!pos[a] || !pos[b]) continue;
      const [x1, y1] = pos[a], [x2, y2] = pos[b];
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2, len = Math.hypot(x2 - x1, y2 - y1) || 1;
      const bend = Math.min(60, len * 0.18);
      const qx = mx - (y2 - y1) / len * bend, qy = my + (x2 - x1) / len * bend;
      const id = "tp" + (pid++);
      const n = list.reduce((s, f) => s + f.n, 0);
      const kinds = list.map((f) => linkKind(f.port, agentPort));
      const kind = ["db", "tcp", "ssh", "vigil"].find((x) => kinds.includes(x));
      const fresh = list.some(isNew), unpl = cmp.unplanned.has(k);
      const detail = list.map(flowText).join("\n");
      const dpath = "M" + x1 + "," + y1 + " Q" + qx + "," + qy + " " + x2 + "," + y2;
      L.edge.append(sv("path", { id, d: dpath, class: "edge " + kind + (fresh ? " fresh" : "") + (unpl ? " unplanned" : ""), "data-a": a, "data-b": b,
        "stroke-width": (kind === "vigil" ? 1.2 : 1.5 + Math.log2(1 + n)).toFixed(1) }));
      // a wide invisible twin makes thin links easy to hit
      L.edge.append(hoverTip(sv("path", { d: dpath, class: "ehit", "data-a": a, "data-b": b, "data-ref": "link:" + k }), detail));
      if (!still) {
        for (const f of list) {
          const forward = f.from === a;
          const dots = Math.min(3, 1 + Math.floor(Math.log2(f.n)));
          for (let i = 0; i < dots; i++) {
            const dur = 3.2;
            L.edge.append(sv("circle", { r: 3, class: "particle " + linkKind(f.port, agentPort), "data-a": a, "data-b": b },
              sv("animateMotion", { dur: dur + "s", repeatCount: "indefinite", begin: (-dur * i / dots).toFixed(2) + "s",
                keyPoints: forward ? "0;1" : "1;0", keyTimes: "0;1", calcMode: "linear" }, sv("mpath", { href: "#" + id }))));
          }
        }
      }
      const text = list.map((f) => portName(f.port, agentPort) + " ×" + f.n).join("  ·  ") + (fresh ? "  · " + t("tmNew") : "") + (unpl ? "  · " + t("plnUnplanned") : "");
      const lx = (x1 + 2 * qx + x2) / 4, ly = (y1 + 2 * qy + y2) / 4;
      linkMid[k] = [lx, ly];
      const tw = Math.min(260, text.length * 6.4 + 16);
      const shown = text.length * 6.4 + 16 > tw ? text.slice(0, Math.floor((tw - 22) / 6.4)) + "…" : text;
      const covers = Object.entries(pos).some(([nid, [nx, ny]]) => nid !== "net" && Math.abs(nx - lx) < TOPO_W / 2 + tw / 2 && Math.abs(ny - ly) < TOPO_H / 2 + 10);
      L.label.append(hoverTip(sv("g", { class: "elabel " + kind + (covers || (kind === "vigil" && !fresh && !unpl) ? " minor" : "") + (fresh ? " fresh" : "") + (unpl ? " unplanned" : ""),
        "data-a": a, "data-b": b, "data-ref": "link:" + k },
        sv("rect", { x: lx - tw / 2, y: ly - 10, width: tw, height: 20, rx: 10 }),
        sv("text", { x: lx, y: ly + 4, "text-anchor": "middle" }, shown)), detail));
    }
  }

  function drawArrows() {
    L.arrow.replaceChildren();
    for (const o0 of visObjects()) {
      if (o0.kind !== "arrow") continue;
      const o = objOf(o0.id);
      const [a, b] = arrowEnds(o);
      const st = o.style || "flow", missing = cmp.missing.has(o.id);
      const g = sv("g", { class: "arrow " + st + (o.layer ? " plan" : "") + (missing ? " missing" : "") + (selected("obj:" + o.id) ? " sel" : ""), "data-ref": "obj:" + o.id,
        "data-a": (o.from || "").replace(/^host:/, ""), "data-b": (o.to || "").replace(/^host:/, "") });
      const dpath = "M" + a[0] + "," + a[1] + " L" + b[0] + "," + b[1];
      g.append(sv("path", { d: dpath, class: "aline" }), sv("path", { d: dpath, class: "ahit" }));
      const ang = Math.atan2(b[1] - a[1], b[0] - a[0]), hl = 12;
      if (st !== "block") g.append(sv("path", { class: "ahead", d: "M" + b[0] + "," + b[1] + " L" + (b[0] - hl * Math.cos(ang - 0.4)) + "," + (b[1] - hl * Math.sin(ang - 0.4)) +
        " L" + (b[0] - hl * Math.cos(ang + 0.4)) + "," + (b[1] - hl * Math.sin(ang + 0.4)) + " Z" }));
      const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
      if (st === "block") g.append(sv("g", { class: "ablock" }, sv("circle", { cx: mx, cy: my, r: 9 }), sv("path", { d: "M" + (mx - 4) + "," + (my - 4) + " l8,8 M" + (mx + 4) + "," + (my - 4) + " l-8,8" })));
      const ports = (o.meta || {}).port ? ":" + o.meta.port : "";
      const label = [o.text, ports, missing ? t("plnMissing") : ""].filter(Boolean).join("  ");
      if (label) {
        const tw = Math.min(260, label.length * 6.4 + 16), ly = st === "block" ? my + 22 : my;
        g.append(sv("rect", { x: mx - tw / 2, y: ly - 10, width: tw, height: 20, rx: 10, class: "alabel" }), sv("text", { x: mx, y: ly + 4, "text-anchor": "middle", class: "alabel" }, label.length * 6.4 + 16 > tw ? label.slice(0, 36) + "…" : label));
      }
      hoverTip(g, () => t("arrow" + st[0].toUpperCase() + st.slice(1)) + (o.text ? ": " + o.text : "") + (ports ? "  " + ports : ""));
      L.arrow.append(g);
    }
  }

  function badges(g, ref, x0, y0) {
    // comments, open tasks, a host note: small marks above the box's right corner
    const cms = Object.values(doc().comments).filter((c) => c.target === ref && !c.parent && !c.resolved && inLayer(c.layer)).length;
    const tks = Object.values(doc().tasks).filter((k) => k.target === ref && k.status !== "done" && inLayer(k.layer)).length;
    const marks = [];
    if (cms) marks.push(["comment", cms]);
    if (tks) marks.push(["task", tks]);
    if (ref.startsWith("host:") && doc().notes[ref.slice(5)]) marks.push(["info", ""]);
    let x = x0;
    for (const [ic, n] of marks.reverse()) {
      const w = n === "" ? 20 : 20 + String(n).length * 7;
      x -= w + 4;
      g.append(sv("g", { class: "nmark " + ic }, sv("rect", { x, y: y0 - 22, width: w, height: 18, rx: 9 }), mapIcon(ic, x + 4, y0 - 19, 12),
        n === "" ? null : sv("text", { x: x + 18, y: y0 - 9 }, String(n))));
    }
  }

  function overlayLevel(x) {
    const m = x.metrics, ov = topo.overlay;
    if (!ov) return "";
    if (ov === "cpu") return m ? level(m.cpu) : "";
    if (ov === "mem") return m ? level(pctOf(m.mem_used, m.mem_total)) : "";
    if (ov === "disk") return m ? level(m.disk_pct) : "";
    if (ov === "alerts") { const s = x.open_by_severity || {}; return s.critical || s.high ? "critical" : s.medium ? "medium" : "ok"; }
    if (ov === "updates") { const u = x.updates || {}; return u.security ? "critical" : u.pending ? "medium" : "ok"; }
    if (ov === "vulns") { const v = x.vulns || {}; const f = v.fixable || {}; return (v.exploited || []).length ? "critical" : f.critical || f.high ? "medium" : "ok"; }
    return "";
  }

  function hostNode(x) {
    const m = x.metrics, W2 = TOPO_W / 2, H2 = TOPO_H / 2;
    const ov = overlayLevel(x), maint = x.maintenance_until && Date.parse(x.maintenance_until) > Date.now();
    const g = sv("g", { class: "node" + (x.server ? " server" : "") + (x.status !== "online" || x.stale ? " off" : "") + (d.focus && !d.focus.has(x.id) ? " dim" : "") + (ov ? " ov ov-" + ov : ""),
      tabindex: 0, role: "button", "aria-label": x.name, "data-id": x.id, "data-ref": "host:" + x.id });
    g.append(sv("rect", { x: -W2, y: -H2, width: TOPO_W, height: TOPO_H, rx: 12, class: "nbox" }));
    if (primaryGroup(x)) g.append(sv("rect", { x: -W2 + 1, y: -H2 + 10, width: 3, height: TOPO_H - 20, rx: 1.5, class: "ngroup " + groupClass(primaryGroup(x)) }));
    g.append(sv("circle", { cx: -W2 + 16, cy: -H2 + 19, r: 4, class: "ndot " + x.status }));
    const sevs = x.open_by_severity || {}, worst = SEVS.find((s) => sevs[s]);
    const badgeW = worst ? 14 + String(sevs[worst]).length * 7 : 0;
    g.append(sv("text", { x: -W2 + 26, y: -H2 + 24, class: "nname" }, midCut(names[x.id], worst ? 19 : 22)));
    if (worst) g.append(sv("g", { class: "nalert " + worst },
      sv("rect", { x: W2 - 12 - badgeW, y: -H2 + 11, width: badgeW, height: 17, rx: 8.5 }),
      sv("text", { x: W2 - 12 - badgeW / 2, y: -H2 + 23.5, "text-anchor": "middle" }, sevs[worst])));
    const sub = [x.hostname, x.last_ip].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join("  ·  ");
    g.append(sv("text", { x: -W2 + 14, y: -H2 + 42, class: "nhost" }, midCut(sub, 32) + (x.updates && x.updates.reboot_required ? "  ↻" : "")));
    if (m) {
      const bw = TOPO_W - 28;
      [[t("cpu"), m.cpu], ["RAM", pctOf(m.mem_used, m.mem_total)], [t("disk"), m.disk_pct]].forEach(([lab, v], i) => {
        const y = -H2 + 62 + i * 19;
        g.append(sv("text", { x: -W2 + 14, y, class: "nsub" }, lab));
        g.append(sv("text", { x: W2 - 14, y, class: "nsub strong", "text-anchor": "end" }, Math.round(v) + " %"));
        g.append(sv("rect", { x: -W2 + 14, y: y + 4, width: bw, height: 3, rx: 1.5, class: "ntrack" }));
        g.append(sv("rect", { x: -W2 + 14, y: y + 4, width: Math.max(2, bw * Math.min(100, v) / 100), height: 3, rx: 1.5, class: "nfill " + level(v) }));
      });
      g.append(sv("text", { x: -W2 + 14, y: H2 - 10, class: "nfoot" }, "↓ " + fmtRate(m.rx) + "  ↑ " + fmtRate(m.tx)));
      g.append(sv("text", { x: W2 - 14, y: H2 - 10, class: "nfoot", "text-anchor": "end" }, "⇅ " + (x.ext_in || 0) + " / " + (x.ext_out || 0)));
    } else {
      g.append(sv("text", { x: -W2 + 14, y: 8, class: "nsub" }, x.status === "online" ? "·" : t(x.status)));
    }
    const under = [x.server ? t("vigilServer") : "", maint ? t("mtTitle") : ""].filter(Boolean).join("  ·  ");
    if (under) g.append(sv("text", { x: 0, y: H2 + 17, "text-anchor": "middle", class: "nbadge" + (maint ? " maint" : "") }, under));
    badges(g, "host:" + x.id, W2, -H2);
    hoverTip(g, () => topo.drag ? null : x.name + (maint ? "\n" + tf("mtUntil", { t: abs(x.maintenance_until) }) : "") + (live.pulses[x.id] ? "\n" + live.pulses[x.id].title : ""));
    return g;
  }
  function netNode() {
    const extIn = hosts.reduce((s, x) => s + (x.ext_in || 0), 0), extOut = hosts.reduce((s, x) => s + (x.ext_out || 0), 0);
    return sv("g", { class: "node netnode", tabindex: 0, role: "button", "aria-label": t("internet"), "data-id": "net", "data-ref": "net" },
      sv("rect", { x: -78, y: -18, width: 156, height: 36, rx: 18 }),
      sv("text", { x: 0, y: -1, "text-anchor": "middle" }, t("internet")),
      sv("text", { x: 0, y: 12, "text-anchor": "middle", class: "nsub" }, "⇅ " + extIn + " / " + extOut));
  }

  // objects are drawn at their own origin and moved by a transform
  function objNode(o) {
    const ref = "obj:" + o.id;
    const g = sv("g", { class: "mobj " + o.kind + (o.color ? " c-" + o.color : "") + (o.layer ? " plan" : ""), "data-ref": ref, tabindex: 0, role: "button",
      "aria-label": o.text || t("tool" + o.kind[0].toUpperCase() + o.kind.slice(1)) });
    const w = o.w || 200, hh = o.h || 100;
    if (o.kind === "zone") {
      g.append(sv("rect", { x: 0, y: 0, width: w, height: hh, rx: 16, class: "zbox" }));
      g.append(sv("text", { x: 14, y: 22, class: "zlabel" }, midCut(o.text || "", Math.max(6, Math.floor(w / 8)))));
    } else if (o.kind === "note") {
      g.append(sv("rect", { x: 0, y: 0, width: w, height: hh, rx: 6, class: "notebox" }));
      g.append(foText(10, 8, w - 20, hh - 16, o.text, "mnote"));
    } else if (o.kind === "text") {
      g.append(sv("rect", { x: 0, y: 0, width: w, height: hh, class: "textbox" }));
      g.append(foText(0, 0, w, hh, o.text, "mtext"));
    } else if (o.kind === "stamp") {
      g.append(sv("circle", { cx: 0, cy: 0, r: 24, class: "stampbox" }), mapIcon(o.style, -13, -13, 26, "stampic"));
      if (o.text) g.append(sv("text", { x: 0, y: 40, "text-anchor": "middle", class: "stamplabel" }, midCut(o.text, 24)));
    } else if (o.kind === "ext") {
      const m = o.meta || {};
      g.append(sv("rect", { x: -80, y: -20, width: 160, height: 40, rx: 20, class: "extbox" }));
      g.append(sv("text", { x: 0, y: m.org ? -2 : 4, "text-anchor": "middle", class: "extname" }, midCut(o.text || "?", 20)));
      if (m.org) g.append(sv("text", { x: 0, y: 12, "text-anchor": "middle", class: "nsub" }, midCut(m.org, 24)));
    } else if (o.kind === "planned") {
      const m = o.meta || {}, W2 = TOPO_W / 2, H2 = TOPO_H / 2;
      g.append(sv("rect", { x: -W2, y: -H2, width: TOPO_W, height: TOPO_H, rx: 12, class: "nbox planbox" }));
      g.append(sv("text", { x: -W2 + 14, y: -H2 + 24, class: "nname" }, midCut(o.text || "?", 22)));
      g.append(sv("text", { x: -W2 + 14, y: -H2 + 42, class: "nhost" }, midCut(m.match || "", 32)));
      [[t("plProvider"), m.provider], [t("plSize"), m.size], [t("plOwner"), m.owner]].forEach(([k, v], i) => {
        g.append(sv("text", { x: -W2 + 14, y: -H2 + 66 + i * 18, class: "nsub" }, k));
        g.append(sv("text", { x: W2 - 14, y: -H2 + 66 + i * 18, class: "nsub strong", "text-anchor": "end" }, midCut(v || "·", 20)));
      });
      g.append(sv("text", { x: 0, y: H2 + 17, "text-anchor": "middle", class: "nbadge" }, t({ planned: "plPlanned", ordered: "plOrdered", setup: "plSetup" }[m.status || "planned"])));
    }
    const b = objBox(o);
    badges(g, ref, b[2] - o.x, b[1] - o.y);
    // a handle to resize notes, zones and text
    if (BOXED[o.kind] && canEdit() && selected(ref) && topo.sel.length === 1) g.append(sv("rect", { x: w - 7, y: hh - 7, width: 14, height: 14, rx: 3, class: "rhandle", "data-handle": "1" }));
    return g;
  }
  const place = (id) => { const p = pos[id]; if (nodeEls[id] && p) nodeEls[id].setAttribute("transform", "translate(" + p[0] + "," + p[1] + ")"); };
  const placeObj = (id) => { const o = objOf(id); if (objEls[id] && o) objEls[id].setAttribute("transform", "translate(" + o.x + "," + o.y + ")"); };

  function drawNodes() {
    L.node.replaceChildren(); L.obj.replaceChildren(); L.zone.replaceChildren();
    for (const k in nodeEls) delete nodeEls[k];
    for (const k in objEls) delete objEls[k];
    for (const x of hosts) { if (!pos[x.id]) continue; L.node.append(nodeEls[x.id] = hostNode(x)); place(x.id); }
    if (topo.showNet) { L.node.append(nodeEls.net = netNode()); place("net"); }
    const objs = visObjects().filter((o) => o.kind !== "arrow");
    objs.sort((a, b) => (a.kind === "zone" ? 0 : 1) - (b.kind === "zone" ? 0 : 1) || (b.w || 0) * (b.h || 0) - (a.w || 0) * (a.h || 0));
    for (const o of objs) {
      const el = objNode(objOf(o.id));
      objEls[o.id] = el;
      (o.kind === "zone" ? L.zone : L.obj).append(el);
      placeObj(o.id);
    }
    drawPulses();
  }

  function drawPins() {
    L.pin.replaceChildren();
    const roots = Object.values(doc().comments).filter((c) => !c.parent && inLayer(c.layer) && (topo.showDone || !c.resolved));
    const count = (id) => 1 + Object.values(doc().comments).filter((c) => c.parent === id).length;
    const at = {};
    for (const c of roots) {
      let p = null;
      if (c.target === "pos") p = [c.x, c.y];
      else if (c.target.startsWith("link:")) { const m = linkMid[c.target.slice(5)]; p = m ? [m[0] + 14, m[1] - 22] : null; }
      else if (c.target === "net") p = pos.net ? [pos.net[0] + 84, pos.net[1] - 16] : null;
      else continue; // hosts and objects show a count mark instead
      if (!p) continue;
      const k = Math.round(p[0]) + "," + Math.round(p[1]);
      const off = (at[k] = (at[k] || 0) + 1) - 1;
      const x = p[0] + off * 18, y = p[1];
      const g = sv("g", { class: "pin" + (c.resolved ? " done" : "") + (selected("cmt:" + c.id) ? " sel" : ""), "data-ref": "cmt:" + c.id, transform: "translate(" + x + "," + y + ")", tabindex: 0, role: "button" },
        withUC(sv("path", { d: "M0,0 C-11,-11 -13,-16 -13,-22 A13,13 0 1 1 13,-22 C13,-16 11,-11 0,0 Z" }), c.author),
        sv("text", { x: 0, y: -18, "text-anchor": "middle" }, String(count(c.id))));
      hoverTip(g, () => c.author + ": " + c.text.slice(0, 120));
      L.pin.append(g);
    }
  }

  // other people's pointers, drawn at a size that does not zoom
  function drawCursors() {
    L.cursor.replaceChildren();
    const k = topo.view ? topo.view.k : 1, now = Date.now();
    for (const c of Object.values(live.cursors)) {
      if (now - c.at > 15000 || (c.layer || "") !== topo.layer || !topo.cursors) continue;
      L.cursor.append(withUC(sv("g", { class: "cursor", transform: "translate(" + c.x + "," + c.y + ") scale(" + (1 / k) + ")" },
        sv("path", { d: "M0,0 L0,17 L4.5,13 L8,20.5 L11,19 L7.5,12 L13,12 Z" }),
        sv("rect", { x: 12, y: 18, width: c.user.length * 7 + 12, height: 18, rx: 9 }),
        sv("text", { x: 18, y: 31 }, c.user)), c.user));
    }
  }
  const lockedBy = () => {
    const out = {}, now = Date.now();
    for (const c of Object.values(live.cursors)) if (c.drag && now - c.at < 5000) out[c.drag] = c.user;
    return out;
  };
  function drawLocks() {
    const lk = lockedBy();
    for (const [id, el] of Object.entries(nodeEls)) { const u = lk["host:" + id]; el.classList.toggle("locked", !!u); if (u) el.style.setProperty("--uc", userColor(u)); }
    for (const [id, el] of Object.entries(objEls)) { const u = lk["obj:" + id] || lk[id]; el.classList.toggle("locked", !!u); if (u) el.style.setProperty("--uc", userColor(u)); }
  }

  function drawPulses() {
    const now = Date.now();
    for (const [id, p] of Object.entries(live.pulses)) {
      if (p.until < now) { delete live.pulses[id]; continue; }
      const el = nodeEls[id];
      if (el) { el.classList.add("pulse", "p-" + p.sev); setTimeout(() => el.classList.remove("pulse", "p-" + p.sev), Math.max(0, p.until - now)); }
    }
  }

  // attacks of the last seconds as arcs from the internet to their host
  let atkCursor = null, atkT = null;
  async function pollAttacks() {
    clearTimeout(atkT);
    if (stopped || !topo.attacks) return;
    try {
      const r = await api("/api/ui/attacks/live" + (atkCursor == null ? "" : "?after=" + atkCursor));
      atkCursor = r.cursor;
      const byName = Object.fromEntries(hosts.map((x) => [x.name, x.id]));
      for (const a of (r.attacks || []).slice(-25)) {
        const id = byName[a.host];
        if (!id || !pos[id] || !pos.net || !topo.showNet) continue;
        const [x1, y1] = pos.net, [x2, y2] = pos[id];
        const arc = sv("path", { class: "atk " + a.kind, d: "M" + x1 + "," + y1 + " Q" + ((x1 + x2) / 2 + (Math.random() - 0.5) * 200) + "," + (Math.min(y1, y2) - 60) + " " + x2 + "," + (y2 - TOPO_H / 2) });
        hoverTip(arc, a.ip + (a.country ? " (" + countryName(a.country) + ")" : "") + " → " + a.host + "  ×" + a.count);
        L.atk.append(arc);
        setTimeout(() => arc.remove(), 4500);
      }
    } catch { /* the next poll tries again */ }
    atkT = setTimeout(pollAttacks, 8000);
  }

  function drawMini() {
    if (!topo.view) return;
    const W = 180, H = 120;
    const [x0, y0, x1, y1] = bbox();
    const v = topo.view, vw = svg.clientWidth / v.k, vh = svg.clientHeight / v.k, vx = -v.x / v.k, vy = -v.y / v.k;
    const X0 = Math.min(x0, vx), Y0 = Math.min(y0, vy), X1 = Math.max(x1, vx + vw), Y1 = Math.max(y1, vy + vh);
    const s = Math.min(W / (X1 - X0), H / (Y1 - Y0));
    const ox = (W - (X1 - X0) * s) / 2, oy = (H - (Y1 - Y0) * s) / 2;
    const tx = (x) => ox + (x - X0) * s, ty = (y) => oy + (y - Y0) * s;
    mini.setAttribute("viewBox", "0 0 " + W + " " + H);
    mini.replaceChildren();
    for (const o of visObjects()) { if (o.kind === "arrow") continue; const b = objBox(o); mini.append(sv("rect", { x: tx(b[0]), y: ty(b[1]), width: Math.max(1, (b[2] - b[0]) * s), height: Math.max(1, (b[3] - b[1]) * s), class: "mm-obj " + o.kind })); }
    for (const [id, p] of Object.entries(pos)) {
      if (id === "net" && !topo.showNet) continue;
      mini.append(sv("rect", { x: tx(p[0] - TOPO_W / 2), y: ty(p[1] - TOPO_H / 2), width: TOPO_W * s, height: TOPO_H * s, rx: 1.5, class: "mm-host" + (selected("host:" + id) ? " sel" : "") }));
    }
    mini.append(sv("rect", { x: tx(vx), y: ty(vy), width: vw * s, height: vh * s, class: "mm-view" }));
    mini._map = { X0, Y0, s, ox, oy };
  }
  const miniGo = (e) => {
    const m = mini._map; if (!m) return;
    const r = mini.getBoundingClientRect(), sc = 180 / r.width;
    centreOn(((e.clientX - r.left) * sc - m.ox) / m.s + m.X0, ((e.clientY - r.top) * sc - m.oy) / m.s + m.Y0);
  };
  mini.addEventListener("pointerdown", (e) => { e.stopPropagation(); mini.setPointerCapture(e.pointerId); miniGo(e); });
  mini.addEventListener("pointermove", (e) => { if (e.buttons) miniGo(e); });

  // ---------- highlight: a box, its links and neighbours; search; impact
  function impactSet(root) {
    // who depends on root: whoever connects to it, and so on, plus the arrows of the plan shown
    const edges = flowsShown().filter((f) => f.port !== agentPort).map((f) => [f.from, f.to]);
    for (const o of visObjects()) if (o.kind === "arrow" && /^host:/.test(o.from || "") && /^host:/.test(o.to || "") && o.style !== "block") edges.push([o.from.slice(5), o.to.slice(5)]);
    const out = new Set([root]), todo = [root];
    while (todo.length) { const s = todo.pop(); for (const [a, b] of edges) if (b === s && !out.has(a)) { out.add(a); todo.push(a); } }
    return out;
  }
  function mark() {
    const hRef = hover;
    const sel = topo.sel[0] || null;
    const refHost = (r) => r && r.startsWith("host:") ? r.slice(5) : r === "net" ? "net" : null;
    const id = refHost(hRef) || (topo.sel.length === 1 ? refHost(sel) : null);
    const pair = !hRef && sel && sel.startsWith("link:") ? sel.slice(5).split("|") : null;
    const q = topo.find.trim().toLowerCase();
    const found = q ? new Set(hosts.filter((x) => [x.name, x.hostname, x.last_ip, ...(x.tags || [])].some((v) => (v || "").toLowerCase().includes(q))).map((x) => x.id)) : null;
    let near = null;
    if (topo.impact) near = impactSet(topo.impact);
    else if (id === "net") near = new Set(["net", ...hosts.filter((x) => x.metrics).map((x) => x.id)]);
    else if (id) { near = new Set([id]); for (const f of flowsShown()) { if (f.from === id) near.add(f.to); if (f.to === id) near.add(f.from); } }
    else if (pair) near = new Set(pair);
    else if (found) near = found;
    if (near) for (const s of topo.sel) { const hId = refHost(s); if (hId) near.add(hId); }
    svg.classList.toggle("focus", !!near);
    for (const [nid, el] of Object.entries(nodeEls)) {
      el.classList.toggle("on", !!near && near.has(nid));
      el.classList.toggle("sel", selected(nid === "net" ? "net" : "host:" + nid));
      el.classList.toggle("root", topo.impact === nid);
    }
    for (const [oid, el] of Object.entries(objEls)) el.classList.toggle("sel", selected("obj:" + oid));
    svg.querySelectorAll(".edge[data-a], .particle[data-a], .elabel[data-a]").forEach((el) => {
      const a = el.dataset.a, b = el.dataset.b;
      const on = topo.impact ? near.has(a) && near.has(b) : id ? a === id || b === id : pair ? a === pair[0] && b === pair[1] : !!found && (found.has(a) || found.has(b));
      el.classList.toggle("on", on);
    });
    drawLocks();
  }
  const selected = (ref) => topo.sel.includes(ref);

  // ---------- moving things: hosts (shared or own layout), objects, pins
  const movable = (ref) => {
    const lk = lockedBy();
    if (lk[ref]) return false;
    if (ref === "net" || ref.startsWith("host:")) return canMoveHosts();
    if (ref.startsWith("obj:")) return canEdit() && !!doc().objects[ref.slice(4)];
    if (ref.startsWith("cmt:")) { const c = doc().comments[ref.slice(4)]; return !!c && c.target === "pos" && (canEdit() || c.author === live.me); }
    return false;
  };
  function startOf(ref) {
    if (ref === "net") return pos.net.slice();
    if (ref.startsWith("host:")) return pos[ref.slice(5)].slice();
    if (ref.startsWith("obj:")) { const o = objOf(ref.slice(4)); return [o.x, o.y, o.x2 || 0, o.y2 || 0]; }
    if (ref.startsWith("cmt:")) { const c = doc().comments[ref.slice(4)]; return [c.x, c.y]; }
    return [0, 0];
  }
  // what a zone carries when it moves: everything whose middle lies in it
  function inZone(z) {
    const out = [], x0 = z.x, y0 = z.y, x1 = z.x + (z.w || 200), y1 = z.y + (z.h || 100), inside = (p) => p && p[0] > x0 && p[0] < x1 && p[1] > y0 && p[1] < y1;
    for (const x of hosts) if (inside(pos[x.id])) out.push("host:" + x.id);
    for (const o of visObjects()) if (o.id !== z.id && o.kind !== "arrow" && inside(objCentre(o)) && (o.kind !== "zone" || (o.w || 0) * (o.h || 0) < (z.w || 0) * (z.h || 0))) out.push("obj:" + o.id);
    for (const c of Object.values(doc().comments)) if (!c.parent && c.target === "pos" && inLayer(c.layer) && inside([c.x, c.y])) out.push("cmt:" + c.id);
    return out;
  }
  function moveTo(ref, start, dx, dy) {
    const sx = snap(start[0] + dx), sy = snap(start[1] + dy);
    if (ref === "net" || ref.startsWith("host:")) { const id = ref === "net" ? "net" : ref.slice(5); pos[id] = [sx, sy]; place(id); }
    else if (ref.startsWith("obj:")) {
      const id = ref.slice(4), o = doc().objects[id];
      tmp[id] = { ...(tmp[id] || {}), x: sx, y: sy };
      if (o && o.kind === "arrow") { tmp[id].x2 = snap(start[2] + dx); tmp[id].y2 = snap(start[3] + dy); }
      placeObj(id);
    } else if (ref.startsWith("cmt:")) { const c = doc().comments[ref.slice(4)]; if (c) { c.x = sx; c.y = sy; } }
  }
  // commit sends where the given things are now, as one change
  function commit(refs) {
    const ops = [];
    let mine = false;
    for (const ref of refs) {
      if (ref === "net" || ref.startsWith("host:")) {
        const id = ref === "net" ? "net" : ref.slice(5);
        if (topo.mine) mine = true; else ops.push(putOp("layout", id, pos[id].slice()));
      } else if (ref.startsWith("obj:")) {
        const id = ref.slice(4), o = objOf(id);
        if (o) ops.push(putOp("objects", id, cleanObj(o)));
      } else if (ref.startsWith("cmt:")) {
        const c = doc().comments[ref.slice(4)];
        if (c) ops.push(putOp("comments", c.id, { ...c }));
      }
    }
    if (mine) { topo.pos = Object.fromEntries(Object.entries(pos).map(([k, p]) => [k, p.slice()])); saveTopo(); }
    for (const k in tmp) delete tmp[k];
    if (ops.length) mapSend(ops); else redraw();
  }
  const cleanObj = (o) => { const x = { ...o }; delete x.author; delete x.created; delete x.updated; return x; };

  function createObj(kind, at, extra) {
    if (!canEdit()) { toast(t("mapReadonly")); return; }
    const [x, y] = at.map(snap);
    const base = { note: { w: 200, h: 120, color: "yellow", text: "" }, text: { w: 240, h: 40, text: t("mapText") }, zone: { w: 400, h: 260, color: "blue", text: t("toolZone") },
      stamp: { style: topo.stamp, text: "" }, ext: { text: t("toolExt"), meta: { org: "" } },
      planned: { text: t("toolPlanned"), meta: { status: "planned", provider: "", size: "", owner: "", match: "" } } }[kind] || {};
    const id = newMapID();
    const o = { kind, layer: topo.layer, x: BOXED[kind] ? x - (base.w || 0) / 2 : x, y: BOXED[kind] ? y - (base.h || 0) / 2 : y, ...base, ...(extra || {}) };
    mapSend([putOp("objects", id, o)]);
    topo.tool = "select";
    select(["obj:" + id], true);
    tools.replaceChildren(...toolButtons());
  }

  // ---------- pointers
  const pts = new Map();
  let act = null, lastTap = {}, lastCursor = 0, pressT = null;
  const refAt = (e) => { const el = e.target.closest && e.target.closest("[data-ref]"); return el ? el.dataset.ref : null; };
  const refUnder = (cx, cy) => { const el = document.elementFromPoint(cx, cy); const r = el && el.closest && el.closest("[data-ref]"); return r && svg.contains(r) ? r.dataset.ref : null; };

  svg.addEventListener("pointerdown", (e) => {
    hideCtx();
    if (e.button !== 0 && e.pointerType === "mouse") return;
    pts.set(e.pointerId, local(e));
    if (pts.size === 2) { clearTimeout(pressT); const [p, q] = [...pts.values()]; act = { kind: "pinch", d: Math.hypot(p[0] - q[0], p[1] - q[1]) }; return; }
    const [sx, sy] = local(e), w = toWorld([sx, sy]);
    const ref = refAt(e), handle = e.target.dataset && e.target.dataset.handle;
    svg.setPointerCapture(e.pointerId);
    svg.focus({ preventScroll: true });
    // long press opens the menu on touch screens
    if (e.pointerType !== "mouse") { clearTimeout(pressT); pressT = setTimeout(() => { if (act && !act.moved) { const a = act; act = null; pts.clear(); openCtx(a.ref, e.clientX, e.clientY, w); } }, 550); }
    const tool = topo.tool;
    if (tool === "hand") { act = { kind: "pan", sx, sy, v0: { ...topo.view } }; return; }
    if (tool === "zone" && canEdit()) { act = { kind: "zone", w0: w, sx, sy }; return; }
    if (tool === "arrow" && canEdit()) { act = { kind: "arrow", from: ref && !/^(link|cmt):/.test(ref) ? ref : "", w0: w, sx, sy }; return; }
    if (tool !== "select") { act = { kind: "place", tool, ref, w, sx, sy }; return; }
    if (handle && ref && ref.startsWith("obj:")) { const o = objOf(ref.slice(4)); act = { kind: "resize", id: o.id, w0: o.w || 200, h0: o.h || 100, sx, sy }; return; }
    if (!ref) { act = e.shiftKey ? { kind: "lasso", w0: w, sx, sy, add: true } : { kind: "pan", sx, sy, v0: { ...topo.view } }; return; }
    let items = selected(ref) && topo.sel.length > 1 ? topo.sel.filter(movable) : movable(ref) ? [ref] : [];
    if (ref.startsWith("obj:") && (doc().objects[ref.slice(4)] || {}).kind === "zone" && items.length === 1) items = items.concat(inZone(objOf(ref.slice(4))).filter(movable));
    act = { kind: "move", ref, items, starts: Object.fromEntries(items.map((r) => [r, startOf(r)])), sx, sy, shift: e.shiftKey };
  });

  svg.addEventListener("pointermove", (e) => {
    const [sx, sy] = local(e);
    if (live.conn && Date.now() - lastCursor > 150) {
      lastCursor = Date.now();
      const w = topo.view ? toWorld([sx, sy]) : [0, 0];
      presencePost({ conn: live.conn, x: w[0], y: w[1], layer: topo.layer, sel: topo.sel.slice(0, 10), drag: act && act.kind === "move" && act.moved && /^(host|obj):/.test(act.ref) ? act.ref : "" });
    }
    if (!pts.has(e.pointerId) || !act) return;
    pts.set(e.pointerId, [sx, sy]);
    if (act.kind === "pinch" && pts.size === 2) {
      const [p, q] = [...pts.values()], dd = Math.hypot(p[0] - q[0], p[1] - q[1]);
      zoomAt(dd / (act.d || dd), (p[0] + q[0]) / 2, (p[1] + q[1]) / 2);
      act.d = dd;
      return;
    }
    if (!act.moved && Math.hypot(sx - act.sx, sy - act.sy) < 4) return;
    act.moved = true;
    clearTimeout(pressT);
    const k = topo.view.k, dx = (sx - act.sx) / k, dy = (sy - act.sy) / k, w = toWorld([sx, sy]);
    if (act.kind === "pan") { topo.view = { ...act.v0, x: act.v0.x + sx - act.sx, y: act.v0.y + sy - act.sy }; applyView(); }
    else if (act.kind === "move" && act.items.length) {
      topo.drag = true; tip(null, null);
      act.hosts = act.items.filter((r) => r.startsWith("host:")).map((r) => r.slice(5)).concat(act.items.includes("net") ? ["net"] : []);
      for (const r of act.items) moveTo(r, act.starts[r], dx, dy);
      drawHulls(); drawEdges(); drawArrows(); drawPins(); mark();
    } else if (act.kind === "resize") {
      topo.drag = true;
      tmp[act.id] = { ...(tmp[act.id] || {}), w: Math.max(60, snap(act.w0 + dx)), h: Math.max(40, snap(act.h0 + dy)) };
      drawNodes(); drawArrows(); mark();
    } else if (act.kind === "lasso" || act.kind === "zone") {
      const [x0, y0] = act.w0;
      L.temp.replaceChildren(sv("rect", { x: Math.min(x0, w[0]), y: Math.min(y0, w[1]), width: Math.abs(w[0] - x0), height: Math.abs(w[1] - y0), class: act.kind === "zone" ? "tzone" : "tlasso" }));
    } else if (act.kind === "arrow") {
      const a = refPoint(act.from) || act.w0;
      L.temp.replaceChildren(sv("path", { d: "M" + a[0] + "," + a[1] + " L" + w[0] + "," + w[1], class: "tarrow " + topo.arrow }));
    }
  });

  const up = (e) => {
    if (!pts.has(e.pointerId)) return;
    pts.delete(e.pointerId);
    clearTimeout(pressT);
    if (!act || pts.size) { if (!pts.size) act = null; return; }
    const a = act; act = null;
    L.temp.replaceChildren();
    const [sx, sy] = local(e), w = toWorld([sx, sy]);
    if (a.kind === "move" && a.moved) { topo.drag = false; commit(a.items); return; }
    if (a.kind === "resize") { topo.drag = false; if (a.moved) commit(["obj:" + a.id]); return; }
    if (a.kind === "lasso") {
      if (!a.moved) return;
      const x0 = Math.min(a.w0[0], w[0]), x1 = Math.max(a.w0[0], w[0]), y0 = Math.min(a.w0[1], w[1]), y1 = Math.max(a.w0[1], w[1]);
      const inside = (p) => p[0] >= x0 && p[0] <= x1 && p[1] >= y0 && p[1] <= y1;
      const got = hosts.filter((x) => pos[x.id] && inside(pos[x.id])).map((x) => "host:" + x.id)
        .concat(visObjects().filter((o) => inside(objCentre(o))).map((o) => "obj:" + o.id));
      select([...new Set(topo.sel.concat(got))]);
      return;
    }
    if (a.kind === "zone") {
      if (!a.moved) return;
      const x0 = snap(Math.min(a.w0[0], w[0])), y0 = snap(Math.min(a.w0[1], w[1]));
      const ww = Math.max(120, snap(Math.abs(w[0] - a.w0[0]))), hh = Math.max(80, snap(Math.abs(w[1] - a.w0[1])));
      createObj("zone", [x0 + ww / 2, y0 + hh / 2], { x: x0, y: y0, w: ww, h: hh });
      return;
    }
    if (a.kind === "arrow") {
      const to = refUnder(e.clientX, e.clientY);
      const end = to && !/^(link|cmt):/.test(to) && to !== a.from ? to : "";
      const from = a.from;
      if (!a.moved && !end) return;
      const id = newMapID();
      const o = { kind: "arrow", layer: topo.layer, style: topo.arrow, from, to: end, x: from ? 0 : snap(a.w0[0]), y: from ? 0 : snap(a.w0[1]), x2: end ? 0 : snap(w[0]), y2: end ? 0 : snap(w[1]) };
      mapSend([putOp("objects", id, o)]);
      select(["obj:" + id], true);
      return;
    }
    if (a.kind === "place") {
      if (a.tool === "comment") { newComment(a.ref && !/^cmt:/.test(a.ref) ? a.ref : "pos", a.w); return; }
      createObj(a.tool, a.w);
      return;
    }
    if (a.kind === "move" || a.kind === "pan") {
      if (a.moved) return;
      if (!a.ref) { if (!e.shiftKey) select([]); return; }
      const now = Date.now();
      if (lastTap.ref === a.ref && now - lastTap.t < 400) {
        lastTap = {};
        if (a.ref.startsWith("host:")) { location.hash = "#/hosts/" + a.ref.slice(5); return; }
        const ta = side.querySelector("textarea, input[type=text]");
        if (ta) ta.focus();
        return;
      }
      lastTap = { ref: a.ref, t: now };
      if (e.shiftKey || a.shift) select(selected(a.ref) ? topo.sel.filter((r) => r !== a.ref) : topo.sel.concat(a.ref));
      else select([a.ref]);
    }
  };
  svg.addEventListener("pointerup", up);
  svg.addEventListener("pointercancel", (e) => { if (act && (act.kind === "move" || act.kind === "resize")) { topo.drag = false; for (const k in tmp) delete tmp[k]; redraw(); } act = null; pts.delete(e.pointerId); L.temp.replaceChildren(); });
  svg.addEventListener("pointerleave", () => { if (hover) { hover = null; mark(); } if (live.conn && topo.cursors) presencePost({ conn: live.conn, x: 0, y: 0, off: true }); });
  svg.addEventListener("pointerover", (e) => {
    if (topo.drag) return;
    const r = refAt(e);
    const hr = r && (r.startsWith("host:") || r === "net") ? r : null;
    if (hr !== hover) { hover = hr; mark(); }
  });
  // the wheel scrolls the page; with Ctrl (or a pinch on a touchpad), or
  // in full screen, it zooms the map
  svg.addEventListener("wheel", (e) => {
    if (!(e.ctrlKey || e.metaKey || topo.full)) return;
    e.preventDefault();
    const [sx, sy] = local(e);
    zoomAt(Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.0018)), sx, sy);
  }, { passive: false });
  svg.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    act = null; pts.clear();
    openCtx(refAt(e), e.clientX, e.clientY, toWorld(local(e)));
  });

  // ---------- context menu
  function hideCtx() { ctx.hidden = true; }
  function openCtx(ref, cx, cy, w) {
    const items = [];
    const add = (label, fn, on = true) => { if (on) items.push(h("button", { type: "button", onclick: () => { hideCtx(); fn(); } }, label)); };
    const ed = canEdit();
    if (ref && ref.startsWith("host:")) {
      const id = ref.slice(5);
      add(t("ctxDetails"), () => select([ref]));
      add(t("ctxOpen"), () => { location.hash = "#/hosts/" + id; });
      add(t("impShow"), () => { topo.impact = id; select([ref]); });
      add(t("toolComment"), () => newComment(ref));
      add(t("tkNew"), () => { select([ref]); openTab("tasks"); }, ed);
      add(t("ctxArrow"), () => { topo.tool = "arrow"; tools.replaceChildren(...toolButtons()); toast(t("toolArrow")); }, ed);
      add(t("mtFor") + " 1 h", () => maintenance([id], 60), ed);
      add(t("mtFor") + " 4 h", () => maintenance([id], 240), ed);
    } else if (ref && ref.startsWith("obj:")) {
      add(t("ctxDetails"), () => select([ref]));
      add(t("toolComment"), () => newComment(ref));
      add(t("ctxCopy"), () => { topo.clip = [cloneObj(doc().objects[ref.slice(4)])]; }, ed);
      add(t("mapDelete"), () => removeSel([ref]), ed);
    } else if (ref && ref.startsWith("link:")) {
      add(t("ctxDetails"), () => select([ref]));
      add(t("toolComment"), () => newComment(ref));
    } else if (ref === "net") {
      add(t("ctxDetails"), () => select(["net"]));
      add(t("toolComment"), () => newComment("net"));
    } else {
      add(t("toolComment"), () => newComment("pos", w));
      for (const k of ["note", "text", "stamp", "ext", "planned"]) add(t("tool" + k[0].toUpperCase() + k.slice(1)), () => createObj(k, w), ed);
      add(t("ctxPaste"), () => paste(w), ed && topo.clip.length > 0);
      add(t("topoFit"), fit);
    }
    if (!items.length) return;
    ctx.replaceChildren(...items);
    const r = stage.getBoundingClientRect();
    ctx.hidden = false;
    ctx.style.left = Math.min(cx - r.left, r.width - ctx.offsetWidth - 8) + "px";
    ctx.style.top = Math.min(cy - r.top, r.height - ctx.offsetHeight - 8) + "px";
    ctx.querySelector("button").focus();
  }
  document.addEventListener("pointerdown", (e) => { if (!ctx.hidden && !ctx.contains(e.target)) hideCtx(); });

  async function maintenance(ids, minutes) {
    try { for (const id of ids) await post("/api/ui/agents/" + id + "/maintenance", { minutes }); toast(t("mtTitle") + " · " + minutes + " min"); }
    catch (x) { toast(x.message); }
  }
  function removeSel(refs) {
    const ops = [];
    for (const r of refs) {
      if (r.startsWith("obj:") && canEdit() && doc().objects[r.slice(4)]) ops.push(delOp("objects", r.slice(4)));
      if (r.startsWith("cmt:")) { const c = doc().comments[r.slice(4)]; if (c && (canEdit() || c.author === live.me)) ops.push(delOp("comments", c.id)); }
    }
    if (!ops.length) return;
    select(topo.sel.filter((r) => !refs.includes(r)));
    mapSend(ops);
  }
  function paste(at) {
    if (!canEdit() || !topo.clip.length) return;
    const cs = topo.clip.map((o) => objCentre(o));
    const cx = cs.reduce((s, p) => s + p[0], 0) / cs.length, cy = cs.reduce((s, p) => s + p[1], 0) / cs.length;
    const [dx, dy] = at ? [snap(at[0] - cx), snap(at[1] - cy)] : [40, 40];
    const ops = [], refs = [];
    for (const o of topo.clip) {
      const id = newMapID(), c = cleanObj(o);
      c.id = id; c.layer = topo.layer; c.x += dx; c.y += dy;
      if (c.kind === "arrow") { if (!c.from) { c.x += 0; } if (!c.to) { c.x2 += dx; c.y2 += dy; } }
      ops.push(putOp("objects", id, c)); refs.push("obj:" + id);
    }
    mapSend(ops);
    select(refs, true);
  }
  // align or spread the selected things by their boxes
  function arrange(how) {
    const refs = topo.sel.filter(movable);
    if (refs.length < 2) return;
    const box = (r) => {
      if (r === "net" || r.startsWith("host:")) { const p = pos[r === "net" ? "net" : r.slice(5)]; return [p[0] - TOPO_W / 2, p[1] - TOPO_H / 2, p[0] + TOPO_W / 2, p[1] + TOPO_H / 2]; }
      if (r.startsWith("obj:")) return objBox(objOf(r.slice(4)));
      const c = doc().comments[r.slice(4)]; return [c.x, c.y, c.x, c.y];
    };
    const bs = Object.fromEntries(refs.map((r) => [r, box(r)]));
    const all = Object.values(bs);
    const moves = {};
    const X0 = Math.min(...all.map((b) => b[0])), X1 = Math.max(...all.map((b) => b[2])), Y0 = Math.min(...all.map((b) => b[1])), Y1 = Math.max(...all.map((b) => b[3]));
    for (const r of refs) {
      const b = bs[r];
      if (how === "left") moves[r] = [X0 - b[0], 0];
      if (how === "right") moves[r] = [X1 - b[2], 0];
      if (how === "hcentre") moves[r] = [(X0 + X1) / 2 - (b[0] + b[2]) / 2, 0];
      if (how === "top") moves[r] = [0, Y0 - b[1]];
      if (how === "bottom") moves[r] = [0, Y1 - b[3]];
      if (how === "vcentre") moves[r] = [0, (Y0 + Y1) / 2 - (b[1] + b[3]) / 2];
    }
    if (how === "hspread" || how === "vspread") {
      const i = how === "hspread" ? 0 : 1;
      const sorted = refs.slice().sort((a, b) => bs[a][i] - bs[b][i]);
      const first = (bs[sorted[0]][i] + bs[sorted[0]][i + 2]) / 2, last = (bs[sorted[sorted.length - 1]][i] + bs[sorted[sorted.length - 1]][i + 2]) / 2;
      sorted.forEach((r, n) => { const c = (bs[r][i] + bs[r][i + 2]) / 2, want = first + (last - first) * n / (sorted.length - 1); moves[r] = i ? [0, want - c] : [want - c, 0]; });
    }
    for (const r of refs) if (moves[r]) moveTo(r, startOf(r), moves[r][0], moves[r][1]);
    commit(refs);
  }

  // ---------- keys
  wrap.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
    if (e.key === "Escape") {
      if (!ctx.hidden) hideCtx();
      else if (topo.tool !== "select") { topo.tool = "select"; tools.replaceChildren(...toolButtons()); }
      else if (topo.impact) { topo.impact = null; mark(); panel(); }
      else if (topo.sel.length) select([]);
      else if (topo.full) toggleFull();
      return;
    }
    if (typing) return;
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "z") { e.preventDefault(); mapUndo(e.shiftKey); return; }
    if (mod && e.key.toLowerCase() === "y") { e.preventDefault(); mapUndo(true); return; }
    if (mod && e.key.toLowerCase() === "c") { const objs = topo.sel.filter((r) => r.startsWith("obj:")).map((r) => doc().objects[r.slice(4)]).filter(Boolean); if (objs.length) { topo.clip = objs.map(cloneObj); e.preventDefault(); } return; }
    if (mod && e.key.toLowerCase() === "v") { if (topo.clip.length) { e.preventDefault(); paste(null); } return; }
    if (mod && e.key.toLowerCase() === "a") { e.preventDefault(); select(visObjects().map((o) => "obj:" + o.id).concat(hosts.map((x) => "host:" + x.id))); return; }
    if (mod) return;
    if (e.key === "Delete" || e.key === "Backspace") { e.preventDefault(); removeSel(topo.sel); return; }
    if (e.key === "?") { help(); return; }
    if (e.key === "f" || e.key === "F") { fit(); return; }
    if (e.key === "+" || e.key === "=") { zoomAt(1.25, svg.clientWidth / 2, svg.clientHeight / 2); return; }
    if (e.key === "-") { zoomAt(0.8, svg.clientWidth / 2, svg.clientHeight / 2); return; }
    const toolKey = { v: "select", h: "hand", c: "comment", n: "note", z: "zone", a: "arrow", t: "text", s: "stamp", e: "ext", p: "planned" }[e.key.toLowerCase()];
    if (toolKey && (canEdit() || ["select", "hand", "comment"].includes(toolKey))) { topo.tool = toolKey; tools.replaceChildren(...toolButtons()); return; }
    const focusRef = e.target.closest && e.target.closest("[data-ref]") ? e.target.closest("[data-ref]").dataset.ref : null;
    if (e.key === "Enter" && focusRef) { select([focusRef]); return; }
    const step = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[e.key];
    if (!step) return;
    const refs = (topo.sel.length ? topo.sel : focusRef ? [focusRef] : []).filter(movable);
    if (!refs.length) return;
    e.preventDefault();
    for (const r of refs) moveTo(r, startOf(r), step[0] * TOPO_GRID, step[1] * TOPO_GRID);
    commit(refs);
  });

  // ---------- selection and the side panel
  function select(refs, focusEditor) {
    topo.sel = refs;
    if (refs.length) topo.panel = "sel";
    else if (topo.panel === "sel") topo.panel = "";
    drawNodes(); drawArrows(); drawPins(); mark(); drawMini();
    panel(true);
    if (focusEditor) requestAnimationFrame(() => { const ta = side.querySelector("textarea, input[type=text]"); if (ta) ta.focus(); });
  }
  function openTab(tab) { topo.panel = topo.panel === tab && tab !== "sel" ? "" : tab; panel(true); }

  const refName = (ref) => {
    if (!ref || ref === "pos") return "·";
    if (ref === "net") return t("internet");
    if (ref.startsWith("host:")) return names[ref.slice(5)] || ref.slice(5);
    if (ref.startsWith("obj:")) { const o = doc().objects[ref.slice(4)]; return o ? (o.text || t("tool" + o.kind[0].toUpperCase() + o.kind.slice(1))).split("\n")[0].slice(0, 40) : "?"; }
    if (ref.startsWith("link:")) { const [a, b] = ref.slice(5).split("|"); return (names[a] || a) + " ⇄ " + (names[b] || b); }
    return ref;
  };
  const row = (k, v) => h("div", { class: "ts-row" }, h("span", { class: "muted" }, k), h("span", null, v));
  const sec = (title, ...kids) => [h("h5", null, title), ...kids];
  const userDot = (u) => withUC(h("span", { class: "udot", title: u }, (u || "?").slice(0, 2).toUpperCase()), u);

  let panelDirty = false;
  side.addEventListener("focusout", () => setTimeout(() => { if (panelDirty && !side.contains(document.activeElement)) panel(true); }, 0));
  function panel(force) {
    // never pull a field away from someone typing in it
    if (!force && side.contains(document.activeElement) && document.activeElement.matches("textarea, input:not([type=checkbox]):not([type=range])")) { panelDirty = true; return; }
    panelDirty = false;
    if (!topo.panel) { side.hidden = true; wrap.classList.remove("side-open"); return; }
    const mine = mineItems();
    const tabs = h("div", { class: "tabs ts-tabs" }, [["sel", t("mapTabSel")], ["tasks", t("mapTabTasks")], ["plans", t("mapTabPlans")], ["history", t("mapTabHistory")], ["mine", t("mapTabMine") + (mine.n ? " · " + mine.n : "")]]
      .map(([k, l]) => h("button", { type: "button", class: topo.panel === k ? "on" : null, onclick: () => { topo.panel = k; panel(true); } }, l)));
    const close = h("button", { type: "button", class: "linkbtn ts-x", "aria-label": t("close"), onclick: () => { topo.panel = ""; panel(true); } }, "×");
    let body;
    try {
      body = { sel: selPanel, tasks: tasksPanel, plans: plansPanel, history: historyPanel, mine: () => minePanel(mine) }[topo.panel]();
    } catch (x) { console.error(x); body = h("div", { class: "err" }, x.message); }
    side.replaceChildren(close, tabs, ...[body].flat(4).filter(Boolean));
    side.hidden = false;
    wrap.classList.add("side-open");
  }

  function selPanel() {
    const s = topo.sel;
    if (!s.length) return h("div", { class: "muted small" }, t("mapNothingSel"));
    if (s.length > 1) {
      const can = s.some(movable);
      const ab = (lab, how) => h("button", { type: "button", class: "btn ghost small", onclick: () => arrange(how) }, lab);
      return [h("h4", null, tf("mapSelected", { n: s.length })),
        can ? sec(t("mapAlign"), h("div", { class: "flex wrap" }, ab("⇤", "left"), ab("↔", "hcentre"), ab("⇥", "right"), ab("⤒", "top"), ab("↕", "vcentre"), ab("⤓", "bottom"))) : null,
        can ? sec(t("mapDistribute"), h("div", { class: "flex wrap" }, ab("⇿", "hspread"), ab("⇳", "vspread"))) : null,
        canEdit() && s.some((r) => r.startsWith("obj:")) ? h("button", { type: "button", class: "btn ghost small danger mt", onclick: () => removeSel(s) }, t("mapDelete")) : null];
    }
    const ref = s[0];
    if (ref.startsWith("host:")) return byId[ref.slice(5)] ? hostPanel(byId[ref.slice(5)]) : h("div", { class: "muted" }, "·");
    if (ref === "net") return netPanel();
    if (ref.startsWith("link:")) return linkPanel(ref);
    if (ref.startsWith("obj:")) return doc().objects[ref.slice(4)] ? objPanel(doc().objects[ref.slice(4)]) : h("div", { class: "muted" }, "·");
    if (ref.startsWith("cmt:")) { const c = doc().comments[ref.slice(4)]; return c ? [h("h4", null, t("cmTitle")), thread(c)] : h("div", { class: "muted" }, "·"); }
    return null;
  }

  const links = (id) => d.flows.filter((f) => f.from === id || f.to === id).sort((f, g) => (f.port === agentPort) - (g.port === agentPort) || g.n - f.n);
  function hostPanel(x) {
    const m = x.metrics, mine = links(x.id), maint = x.maintenance_until && Date.parse(x.maintenance_until) > Date.now();
    const imp = topo.impact === x.id ? impactSet(x.id) : null;
    return [h("h4", null, x.name),
      h("div", { class: "flex wrap" }, statusChip(x.status), primaryGroup(x) ? h("span", { class: "chip" }, h("span", { class: "gmark " + groupClass(primaryGroup(x)) }), primaryGroup(x)) : null,
        Object.keys(x.open_by_severity || {}).length ? sevCounts(x.open_by_severity) : null, maint ? h("span", { class: "pill warn" }, tf("mtUntil", { t: abs(x.maintenance_until) })) : null),
      h("div", { class: "flex wrap ts-actions" },
        h("a", { class: "btn ghost small", href: "#/hosts/" + x.id }, t("topoOpen")),
        h("button", { type: "button", class: "btn ghost small" + (imp ? " on" : ""), onclick: () => { topo.impact = imp ? null : x.id; mark(); panel(true); } }, imp ? t("impEnd") : t("impShow")),
        canEdit() ? h("button", { type: "button", class: "btn ghost small", onclick: () => maintenance([x.id], 60) }, t("mtFor") + " 1 h") : null),
      imp ? sec(tf("impTitle", { name: names[x.id] }), imp.size > 1 ? [...imp].filter((i) => i !== x.id).map((i) => h("div", { class: "ts-flow click", onclick: () => select(["host:" + i]) }, h("span", { class: "strong" }, names[i] || i))) : h("div", { class: "muted small" }, t("impNone"))) : null,
      row(t("topoHostname"), x.hostname || "·"), row("IP", x.last_ip || "·"),
      m ? [row(t("cpu"), fmtPct(m.cpu) + "  ·  " + t("load") + " " + m.load.map((v) => v.toFixed(2)).join(" ")),
        row(t("memory"), fmtPct(pctOf(m.mem_used, m.mem_total)) + "  ·  " + fmtBytes(m.mem_used) + " " + t("ofTotal") + " " + fmtBytes(m.mem_total)),
        row(t("disk"), fmtPct(m.disk_pct)), row(t("traffic"), "↓ " + fmtRate(m.rx) + "  ↑ " + fmtRate(m.tx)),
        row(t("connections"), m.conn_in + " " + t("netIn") + "  ·  " + m.conn_out + " " + t("netOut")), row(t("upFor"), fmtUptime(m.uptime)),
        x.stale ? row(t("asOf"), ago(m.ts)) : null] : null,
      hostNote(x),
      sec(t("topoLinks"), mine.length ? mine.map((f) => {
        const other = f.from === x.id ? f.to : f.from;
        return h("div", { class: "ts-flow click", onclick: () => select(["host:" + other]) },
          h("div", null, h("span", { class: "strong" }, (f.from === x.id ? "→ " : "← ") + (names[other] || other)), h("span", { class: "muted" }, "  " + portName(f.port, agentPort) + " :" + f.port + "  ×" + f.n)),
          f.client_proc || f.server_proc ? h("div", { class: "mono small" }, (f.client_proc || "?") + " → " + (f.server_proc || "?")) : null);
      }) : h("div", { class: "muted small" }, "·")),
      sec(t("internet") + "  ·  ↓ " + (x.ext_in || 0) + "  ↑ " + (x.ext_out || 0),
        (x.ext_top || []).map((e) => h("div", { class: "ts-flow" },
          h("div", null, h("span", { class: "strong" }, (e.out ? "→ " : "← ") + portName(e.port) + (PORT_NAMES[e.port] ? " :" + e.port : "")), h("span", { class: "muted" }, "  ×" + e.n + "  ·  " + e.addrs + " " + t("topoAddrs"))),
          h("div", { class: "muted small" }, [e.proc ? h("span", { class: "mono" }, e.proc) : null, e.proc && (e.countries || []).length ? "  ·  " : null, (e.countries || []).map(countryName).join(", ")])))),
      tasksFor("host:" + x.id), threads("host:" + x.id)];
  }
  function netPanel() {
    const list = hosts.filter((x) => (x.ext_in || 0) + (x.ext_out || 0)).sort((a, b) => (b.ext_in + b.ext_out) - (a.ext_in + a.ext_out));
    return [h("h4", null, t("internet")),
      list.map((x) => h("div", { class: "ts-flow click", onclick: () => select(["host:" + x.id]) },
        h("span", { class: "strong" }, names[x.id]), h("span", { class: "muted" }, "  ↓ " + (x.ext_in || 0) + "  ↑ " + (x.ext_out || 0)))),
      threads("net")];
  }
  function linkPanel(ref) {
    const [a, b] = ref.slice(5).split("|");
    const fl = flowsShown().filter((f) => (f.from === a && f.to === b) || (f.from === b && f.to === a));
    return [h("h4", null, (names[a] || a) + " ⇄ " + (names[b] || b)),
      cmp.unplanned.has(ref.slice(5)) ? h("div", { class: "pill bad" }, t("plnUnplanned")) : null,
      fl.map((f) => h("div", { class: "ts-flow" },
        h("div", null, h("span", { class: "strong" }, portName(f.port, agentPort)), h("span", { class: "muted" }, "  :" + f.port + "  ×" + f.n), isNew(f) ? h("span", { class: "pill" }, t("tmNew")) : null),
        h("div", { class: "muted small" }, (names[f.from] || f.from) + " → " + (names[f.to] || f.to)),
        f.client_proc || f.server_proc ? h("div", { class: "mono small" }, (f.client_proc || "?") + " → " + (f.server_proc || "?")) : null)),
      threads(ref)];
  }

  // a host's note: what it is for, who looks after it
  function hostNote(x) {
    const n = doc().notes[x.id];
    if (!n && !canEdit()) return null;
    const view = n ? [n.purpose ? row(t("hnPurpose"), n.purpose) : null, n.owners ? row(t("hnOwners"), n.owners) : null, n.services ? row(t("hnServices"), n.services) : null,
      n.links ? h("div", { class: "ts-row" }, h("span", { class: "muted" }, t("hnLinks")), foLinks(n.links)) : null] : [];
    if (!canEdit()) return sec(t("hnTitle"), view);
    const f = {};
    const field = (k, lab, ml) => h("label", null, lab, f[k] = h("textarea", { rows: k === "purpose" || k === "services" ? 2 : 1, maxlength: ml }, (n || {})[k] || ""));
    const form = h("form", { class: "ts-form", hidden: true, onsubmit: (e) => {
      e.preventDefault();
      const v = { purpose: f.purpose.value.trim(), owners: f.owners.value.trim(), services: f.services.value.trim(), links: f.links.value.trim() };
      mapSend([Object.values(v).some(Boolean) ? putOp("notes", x.id, v) : delOp("notes", x.id)]);
    } }, field("purpose", t("hnPurpose"), 1000), field("owners", t("hnOwners"), 300), field("services", t("hnServices"), 1000), field("links", t("hnLinks"), 1000),
      h("div", { class: "flex" }, h("button", { class: "btn small", type: "submit" }, t("mapSave")), h("button", { class: "btn ghost small", type: "button", onclick: () => { form.hidden = true; } }, t("mapCancel"))));
    return sec(t("hnTitle"), view, h("button", { type: "button", class: "linkbtn small", onclick: () => { form.hidden = !form.hidden; } }, t("hnEdit")), form);
  }
  const foLinks = (s) => h("span", { class: "ts-links" }, s.split(/[\s,]+/).filter(Boolean).map((u) => /^https?:\/\//.test(u) ? h("a", { href: u, target: "_blank", rel: "noopener noreferrer" }, u.replace(/^https?:\/\//, "")) : h("span", null, u + " ")));

  // ---------- drawn objects: editor or view
  function objPanel(o) {
    const ref = "obj:" + o.id, ed = canEdit();
    const save = (patch) => mapSend([putOp("objects", o.id, { ...cleanObj(doc().objects[o.id]), ...patch })]);
    const meta = (k, v) => save({ meta: { ...((doc().objects[o.id] || o).meta || {}), [k]: v } });
    // one timer per field, so typing in the next field does not drop the last
    const debs = {};
    const later = (key, fn) => { clearTimeout(debs[key]); debs[key] = setTimeout(fn, 700); };
    let fieldN = 0;
    const txt = (lab, val, onv, area) => { const key = fieldN++; return h("label", null, lab, area ? h("textarea", { rows: 4, maxlength: 4000, disabled: !ed || null, oninput: (e) => later(key, () => onv(e.target.value)) }, val || "")
      : h("input", { type: "text", value: val || "", maxlength: 200, disabled: !ed || null, oninput: (e) => later(key, () => onv(e.target.value)) })); };
    const sel = (lab, val, opts, onv) => h("label", null, lab, h("select", { disabled: !ed || null, onchange: (e) => onv(e.target.value) }, opts.map(([v, l]) => h("option", { value: v, selected: v === val || null }, l))));
    const colours = () => h("div", { class: "swatches" }, MAP_COLORS.map((c) => h("button", { type: "button", class: "sw c-" + c + (o.color === c ? " on" : ""), title: c, disabled: !ed || null, onclick: () => save({ color: c }) })));
    const kindName = t("tool" + o.kind[0].toUpperCase() + o.kind.slice(1));
    const out = [h("h4", null, kindName + (o.layer ? "  ·  " + ((doc().layers[o.layer] || {}).name || "") : "")),
      h("div", { class: "muted small" }, o.author + "  ·  " + ago(o.updated || o.created))];
    if (o.kind === "note") out.push(txt(t("mapText"), o.text, (v) => save({ text: v }), true), sec(t("mapColor"), colours()));
    if (o.kind === "text") out.push(txt(t("mapText"), o.text, (v) => save({ text: v }), true));
    if (o.kind === "zone") out.push(txt(t("plnName"), o.text, (v) => save({ text: v })), sec(t("mapColor"), colours()));
    if (o.kind === "stamp") out.push(sel(t("toolStamp"), o.style, MAP_STAMPS.map((s) => [s, t("st" + s[0].toUpperCase() + s.slice(1))]), (v) => save({ style: v })), txt(t("mapLabel"), o.text, (v) => save({ text: v })));
    if (o.kind === "ext") out.push(txt(t("plnName"), o.text, (v) => save({ text: v })), txt(t("extOrg"), (o.meta || {}).org, (v) => meta("org", v)), txt(t("extUrl"), (o.meta || {}).url, (v) => meta("url", v)),
      (o.meta || {}).url && /^https?:\/\//.test(o.meta.url) ? foLinks(o.meta.url) : null);
    if (o.kind === "arrow") {
      out.push(sel(t("mapStyle"), o.style || "flow", MAP_ARROWS.map((s) => [s, t("arrow" + s[0].toUpperCase() + s.slice(1))]), (v) => save({ style: v })),
        txt(t("mapLabel"), o.text, (v) => save({ text: v })), txt(t("mapPorts"), (o.meta || {}).port, (v) => meta("port", v.replace(/[^0-9,]/g, ""))),
        row("", (o.from ? refName(o.from) : "·") + "  →  " + (o.to ? refName(o.to) : "·")));
    }
    if (o.kind === "planned") {
      const m = o.meta || {};
      out.push(txt(t("plnName"), o.text, (v) => save({ text: v })), txt(t("plMatch"), m.match, (v) => meta("match", v)), txt(t("plProvider"), m.provider, (v) => meta("provider", v)),
        txt(t("plSize"), m.size, (v) => meta("size", v)), txt(t("plOwner"), m.owner, (v) => meta("owner", v)),
        sel(t("plStatus"), m.status || "planned", [["planned", t("plPlanned")], ["ordered", t("plOrdered")], ["setup", t("plSetup")]], (v) => meta("status", v)));
      const want = (m.match || "").trim().toLowerCase();
      const found = want ? hosts.find((x) => (x.hostname || "").toLowerCase() === want || x.name.toLowerCase().includes(want)) : null;
      if (found) out.push(h("div", { class: "ts-found" }, h("div", null, tf("plFound", { name: found.name })),
        ed ? h("button", { type: "button", class: "btn small", onclick: () => replacePlanned(o, found) }, t("plReplace")) : null));
    }
    if (ed && Object.keys(doc().layers).length) out.push(sel(t("mapLayer"), o.layer || "", [["", t("mapLive")], ...Object.values(doc().layers).map((l) => [l.id, l.name])], (v) => save({ layer: v })));
    if (ed) out.push(h("button", { type: "button", class: "btn ghost small danger", onclick: () => removeSel([ref]) }, t("mapDelete")));
    out.push(tasksFor(ref), threads(ref));
    return out;
  }
  // a planned host that now exists: the host takes its place, its comments,
  // tasks and arrows
  function replacePlanned(o, x) {
    const ops = [], ref = "obj:" + o.id, to = "host:" + x.id;
    if (!topo.mine) ops.push(putOp("layout", x.id, [snap(o.x), snap(o.y)]));
    for (const c of Object.values(doc().comments)) if (c.target === ref) ops.push(putOp("comments", c.id, { ...c, target: to }));
    for (const k of Object.values(doc().tasks)) if (k.target === ref) ops.push(putOp("tasks", k.id, { ...k, target: to }));
    for (const a of Object.values(doc().objects)) if (a.kind === "arrow" && (a.from === ref || a.to === ref)) ops.push(putOp("objects", a.id, { ...cleanObj(a), from: a.from === ref ? to : a.from, to: a.to === ref ? to : a.to }));
    ops.push(delOp("objects", o.id));
    mapSend(ops);
    select([to]);
  }

  // ---------- comments
  function newComment(target, at) {
    topo.panel = "sel";
    if (target === "pos") {
      const id = newMapID();
      pending = { id, target: "pos", x: snap(at[0]), y: snap(at[1]), layer: topo.layer };
      topo.sel = [];
      side.replaceChildren(h("h4", null, t("cmNew")), commentBox(pending, null));
      side.hidden = false; wrap.classList.add("side-open");
      L.temp.replaceChildren(sv("g", { class: "pin new", transform: "translate(" + pending.x + "," + pending.y + ")" }, sv("path", { d: "M0,0 C-11,-11 -13,-16 -13,-22 A13,13 0 1 1 13,-22 C13,-16 11,-11 0,0 Z" })));
      requestAnimationFrame(() => { const ta = side.querySelector("textarea"); if (ta) ta.focus(); });
      return;
    }
    select([target]);
    requestAnimationFrame(() => { const ta = side.querySelector(".cm-new textarea"); if (ta) { ta.scrollIntoView({ block: "nearest" }); ta.focus(); } });
  }
  let pending = null;
  function commentBox(base, parent) {
    const ta = h("textarea", { rows: parent ? 2 : 3, maxlength: 4000, placeholder: parent ? t("cmReply") : t("cmNew") });
    const send = () => {
      const text = ta.value.trim();
      if (!text) return;
      const id = base && base.id ? base.id : newMapID();
      const v = parent ? { target: parent.target, layer: parent.layer || "", parent: parent.id, text } : { target: base.target, layer: base.layer || topo.layer, x: base.x || 0, y: base.y || 0, text };
      mapSend([putOp("comments", parent ? newMapID() : id, v)]).then((ok) => { if (ok && !parent && v.target === "pos") { L.temp.replaceChildren(); select(["cmt:" + id]); } });
      ta.value = ""; pending = null;
    };
    ta.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); send(); } });
    const at = h("div", { class: "cm-at" }, live.users.filter((u) => u !== live.me).slice(0, 12).map((u) => h("button", { type: "button", class: "linkbtn small", onclick: () => { ta.value += (ta.value && !/\s$/.test(ta.value) ? " " : "") + "@" + u + " "; ta.focus(); } }, "@" + u)));
    return h("div", { class: "cm-new" }, ta, at, h("button", { type: "button", class: "btn small", onclick: send }, t("cmSend")));
  }
  function commentItem(c, root) {
    const mayEdit = canEdit() || c.author === live.me;
    const text = h("div", { class: "cm-text" }, c.text.split(/(@[A-Za-z0-9._-]+)/g).map((p) => /^@/.test(p) && (c.mentions || []).includes(p.slice(1)) ? h("span", { class: "cm-mention" }, p) : p));
    return h("div", { class: "cm" + (c.resolved ? " done" : "") },
      h("div", { class: "cm-head" }, userDot(c.author), h("span", { class: "strong" }, c.author), h("span", { class: "muted small" }, ago(c.updated || c.created)),
        root ? h("button", { type: "button", class: "linkbtn small", onclick: () => mapSend([putOp("comments", c.id, { ...c, resolved: !c.resolved })]) }, c.resolved ? t("cmReopen") : t("cmResolve")) : null,
        mayEdit ? h("button", { type: "button", class: "linkbtn small", "aria-label": t("mapDelete"), onclick: () => removeSel(["cmt:" + c.id]) }, "×") : null),
      text);
  }
  function thread(root) {
    const replies = Object.values(doc().comments).filter((c) => c.parent === root.id).sort((a, b) => Date.parse(a.created) - Date.parse(b.created));
    return h("div", { class: "cm-thread" + (selected("cmt:" + root.id) ? " sel" : "") }, commentItem(root, true), replies.map((c) => commentItem(c, false)), commentBox(null, root));
  }
  function threads(target) {
    const roots = Object.values(doc().comments).filter((c) => c.target === target && !c.parent && inLayer(c.layer) && (topo.showDone || !c.resolved))
      .sort((a, b) => Date.parse(a.created) - Date.parse(b.created));
    const done = Object.values(doc().comments).filter((c) => c.target === target && !c.parent && c.resolved && inLayer(c.layer)).length;
    return sec(t("cmTitle") + (roots.length ? " · " + roots.length : ""), roots.map(thread),
      done && !topo.showDone ? h("button", { type: "button", class: "linkbtn small", onclick: () => { topo.showDone = true; drawPins(); panel(true); } }, t("cmShowDone") + " (" + done + ")") : null,
      commentBox({ target, layer: topo.layer }, null));
  }

  // ---------- tasks
  const taskRow = (k) => {
    const ed = canEdit(), late = k.due && k.status !== "done" && k.due < new Date().toISOString().slice(0, 10);
    return h("div", { class: "tk" + (k.status === "done" ? " done" : "") },
      h("input", { type: "checkbox", checked: k.status === "done" || null, disabled: !ed || null, "aria-label": t("tkDone"), onchange: (e) => mapSend([putOp("tasks", k.id, { ...k, status: e.target.checked ? "done" : "open" })]) }),
      h("div", { class: "tk-main" },
        h("div", null, h("span", { class: "strong" }, k.title), k.status === "doing" ? h("span", { class: "pill" }, t("tkDoing")) : null),
        h("div", { class: "muted small" }, [k.assignee ? "@" + k.assignee : t("tkNobody"), k.due ? (late ? t("tkOverdue") + " " : "") + k.due : null,
          k.target ? h("button", { type: "button", class: "linkbtn small", onclick: () => select([k.target]) }, refName(k.target)) : null, k.layer ? (doc().layers[k.layer] || {}).name : null].filter(Boolean).flatMap((x, i) => i ? ["  ·  ", x] : [x]))),
      ed ? h("select", { class: "tk-st", "aria-label": t("plStatus"), onchange: (e) => mapSend([putOp("tasks", k.id, { ...k, status: e.target.value })]) },
        [["open", t("tkOpen")], ["doing", t("tkDoing")], ["done", t("tkDone")]].map(([v, l]) => h("option", { value: v, selected: v === k.status || null }, l))) : null,
      ed ? h("button", { type: "button", class: "linkbtn small", "aria-label": t("mapDelete"), onclick: () => mapSend([delOp("tasks", k.id)]) }, "×") : null);
  };
  function taskForm(target) {
    if (!canEdit()) return null;
    const title = h("input", { type: "text", maxlength: 200, placeholder: t("tkNew") });
    const who = h("select", { "aria-label": t("tkAssignee") }, h("option", { value: "" }, t("tkNobody")), live.users.map((u) => h("option", { value: u }, u)));
    const due = h("input", { type: "date", "aria-label": t("tkDue") });
    return h("form", { class: "tk-form", onsubmit: (e) => {
      e.preventDefault();
      if (!title.value.trim()) return;
      mapSend([putOp("tasks", newMapID(), { title: title.value.trim(), assignee: who.value, due: due.value, status: "open", target: target || "", layer: topo.layer })]);
      title.value = "";
    } }, title, h("div", { class: "flex" }, who, due, h("button", { class: "btn small", type: "submit" }, "+")));
  }
  function tasksFor(target) {
    const list = Object.values(doc().tasks).filter((k) => k.target === target && inLayer(k.layer)).sort((a, b) => (a.status === "done") - (b.status === "done") || (a.due || "9").localeCompare(b.due || "9"));
    if (!list.length && !canEdit()) return null;
    return sec(t("tkTitle") + (list.length ? " · " + list.filter((k) => k.status !== "done").length : ""), list.map(taskRow), taskForm(target));
  }
  function tasksPanel() {
    let list = Object.values(doc().tasks);
    if (topo.tkStatus !== "all") list = list.filter((k) => topo.tkStatus === "open" ? k.status !== "done" : k.status === topo.tkStatus);
    if (topo.tkWho) list = list.filter((k) => k.assignee === topo.tkWho);
    if (topo.tkLayer === "here") list = list.filter((k) => inLayer(k.layer));
    list.sort((a, b) => (a.status === "done") - (b.status === "done") || (a.due || "9").localeCompare(b.due || "9") || a.title.localeCompare(b.title, lang));
    const f = (key, opts) => h("select", { onchange: (e) => { topo[key] = e.target.value; panel(true); } }, opts.map(([v, l]) => h("option", { value: v, selected: topo[key] === v || null }, l)));
    return [h("div", { class: "flex wrap ts-filters" },
      f("tkStatus", [["open", t("tkOpen")], ["doing", t("tkDoing")], ["done", t("tkDone")], ["all", t("tkAll")]]),
      f("tkWho", [["", t("tkAll")], ...live.users.map((u) => [u, "@" + u])]),
      f("tkLayer", [["here", t("tkLayerHere")], ["all", t("tkLayerAll")]])),
      list.length ? list.map(taskRow) : h("div", { class: "muted small" }, "·"),
      taskForm(topo.sel.length === 1 && !/^cmt:/.test(topo.sel[0]) ? topo.sel[0] : "")];
  }

  // ---------- plans
  function plansPanel() {
    const ed = canEdit(), layers = Object.values(doc().layers).sort((a, b) => Date.parse(a.created) - Date.parse(b.created));
    const st = [["draft", t("plnDraft")], ["active", t("plnActive")], ["done", t("plnDone")], ["dropped", t("plnDropped")]];
    const name = h("input", { type: "text", maxlength: 80, placeholder: t("plnName") });
    return [
      h("div", { class: "pl" + (!topo.layer ? " on" : "") }, h("button", { type: "button", class: "linkbtn strong", onclick: () => setLayer("") }, t("mapLive"))),
      layers.map((l) => {
        const n = Object.values(doc().objects).filter((o) => o.layer === l.id).length;
        return h("div", { class: "pl" + (topo.layer === l.id ? " on" : "") },
          h("div", { class: "flex" }, h("button", { type: "button", class: "linkbtn strong", onclick: () => setLayer(l.id) }, l.name), h("span", { class: "muted small" }, n + "  ·  " + l.author),
            ed ? h("button", { type: "button", class: "linkbtn small right", "aria-label": t("mapDelete"), onclick: () => { if (confirm(tf("plnDelAsk", { name: l.name }))) { if (topo.layer === l.id) setLayer(""); mapSend([delOp("layers", l.id)]); } } }, "×") : null),
          h("div", { class: "flex wrap" },
            ed ? h("select", { onchange: (e) => mapSend([putOp("layers", l.id, { ...l, status: e.target.value })]) }, st.map(([v, lb]) => h("option", { value: v, selected: v === l.status || null }, lb)))
              : h("span", { class: "pill" }, t("pln" + l.status[0].toUpperCase() + l.status.slice(1))),
            h("label", { class: "check small" }, h("input", { type: "checkbox", checked: l.alert || null, disabled: !ed || null, onchange: (e) => mapSend([putOp("layers", l.id, { ...l, alert: e.target.checked })]) }), t("plnAlert"))),
          topo.layer === l.id && topo.compare ? h("div", { class: "small" }, h("span", { class: "pill bad" }, cmp.n + " " + t("plnUnplanned")), " ", h("span", { class: "pill warn" }, cmp.m + " " + t("plnMissing"))) : null);
      }),
      topo.layer ? h("label", { class: "check" }, h("input", { type: "checkbox", checked: topo.compare || null, onchange: (e) => { topo.compare = e.target.checked; redraw(); } }), t("plnCompare")) : null,
      ed ? h("form", { class: "flex mt", onsubmit: (e) => {
        e.preventDefault();
        if (!name.value.trim()) return;
        const id = newMapID();
        mapSend([putOp("layers", id, { name: name.value.trim(), status: "draft" })]).then((ok) => { if (ok) setLayer(id); });
      } }, name, h("button", { class: "btn small", type: "submit" }, t("plnNew"))) : null];
  }
  function setLayer(id) {
    topo.layer = id; store("vigil.mapLayer", id);
    topo.sel = topo.sel.filter((r) => !r.startsWith("obj:") && !r.startsWith("cmt:"));
    buildBar(); redraw();
    if (live.conn) presencePost({ conn: live.conn, x: 0, y: 0, layer: id, off: true });
  }

  // ---------- history
  let hist = null, histBusy = false;
  async function loadHistory(before) {
    if (histBusy) return;
    histBusy = true;
    try {
      const r = await api("/api/ui/map/history" + (before ? "?before=" + before : ""));
      hist = before && hist ? { batches: hist.batches.concat(r.batches), oldest: r.oldest } : r;
    } catch (x) { toast(x.message); }
    histBusy = false;
    if (topo.panel === "history") panel(true);
  }
  const CNAME = { layout: "topoHostname", objects: "", comments: "cmTitle", tasks: "tkTitle", layers: "mapTabPlans", notes: "hnTitle" };
  function entryName(e) {
    if (e.c === "layout") return refName(e.id === "net" ? "net" : "host:" + e.id);
    if (e.c === "objects") { const o = e.after || e.before || {}; return t("tool" + (o.kind || "note")[0].toUpperCase() + (o.kind || "note").slice(1)) + (o.text ? ": " + o.text.split("\n")[0].slice(0, 30) : ""); }
    if (e.c === "notes") return t("hnTitle") + ": " + refName("host:" + e.id);
    const o = e.after || e.before || {};
    return t(CNAME[e.c]) + (o.title || o.name || o.text ? ": " + String(o.title || o.name || o.text).split("\n")[0].slice(0, 30) : "");
  }
  function historyPanel() {
    if (!hist) { loadHistory(); return h("div", { class: "muted small" }, "…"); }
    return [hist.batches.map((b) => h("div", { class: "hi" },
      h("div", { class: "cm-head" }, userDot(b.user), h("span", { class: "strong" }, b.user), h("span", { class: "muted small", title: abs(b.ts) }, ago(b.ts)), b.undo ? h("span", { class: "pill" }, t("hiUndo")) : null,
        canEdit() ? h("button", { type: "button", class: "linkbtn small right", onclick: async () => {
          if (!confirm(t("hiRestoreAsk"))) return;
          try { await post("/api/ui/map/restore", { rev: b.rev }); hist = null; loadHistory(); } catch (x) { toast(x.message); }
        } }, t("hiRestore")) : null),
      b.entries.slice(0, 4).map((e) => h("div", { class: "small hi-e" + (e.after ? "" : " gone"), onclick: () => {
        const ref = e.c === "layout" ? (e.id === "net" ? "net" : "host:" + e.id) : e.c === "objects" && doc().objects[e.id] ? "obj:" + e.id : e.c === "comments" && doc().comments[e.id] ? "cmt:" + e.id : null;
        if (ref) { select([ref]); const p = ref.startsWith("host:") ? pos[ref.slice(5)] : ref.startsWith("obj:") ? objCentre(objOf(e.id)) : null; if (p) centreOn(p[0], p[1]); }
      } }, (e.after ? (e.before ? "~ " : "+ ") : "− ") + entryName(e))),
      b.entries.length > 4 ? h("div", { class: "muted small" }, tf("hiChanges", { n: b.entries.length })) : null)),
      hist.batches.length && hist.batches[hist.batches.length - 1].rev > hist.oldest ? h("button", { type: "button", class: "linkbtn small", onclick: () => loadHistory(hist.batches[hist.batches.length - 1].rev) }, t("hiMore")) : null];
  }

  // ---------- for me: mentions and my tasks
  function mineItems() {
    const ment = Object.values(doc().comments).filter((c) => (c.mentions || []).includes(live.me) && !(c.parent ? (doc().comments[c.parent] || {}).resolved : c.resolved));
    const tasks = Object.values(doc().tasks).filter((k) => k.assignee === live.me && k.status !== "done");
    return { ment, tasks, n: ment.length + tasks.length };
  }
  function minePanel(m) {
    if (!m.n) return h("div", { class: "muted small" }, t("miNone"));
    return [m.ment.length ? sec(t("miMentions"), m.ment.map((c) => {
      const root = c.parent ? doc().comments[c.parent] || c : c;
      return h("div", { class: "ts-flow click", onclick: () => { if (root.target === "pos") select(["cmt:" + root.id]); else select([root.target]); if (root.layer !== topo.layer) setLayer(root.layer || ""); } },
        h("div", null, h("span", { class: "strong" }, c.author), h("span", { class: "muted small" }, "  " + ago(c.created) + "  ·  " + refName(root.target === "pos" ? null : root.target))),
        h("div", { class: "small" }, c.text.slice(0, 140)));
    })) : null, m.tasks.length ? sec(t("miTasks"), m.tasks.map(taskRow)) : null];
  }

  // ---------- toolbars
  const btn = (label, title, onclick, cls) => h("button", { type: "button", class: "btn ghost small" + (cls ? " " + cls : ""), title, "aria-label": title, onclick }, label);
  const check = (key, label, storeKey, after) => h("label", { class: "check" }, h("input", { type: "checkbox", checked: topo[key] || null,
    onchange: (e) => { topo[key] = e.target.checked; store(storeKey, topo[key] ? "1" : "0"); (after || redraw)(); } }), label);
  const find = h("input", { type: "search", class: "topo-find", placeholder: t("topoFind"), value: topo.find,
    oninput: () => { topo.find = find.value; mark(); },
    onkeydown: (e) => {
      if (e.key !== "Enter") return;
      const id = [...svg.querySelectorAll(".node.on")].map((n) => n.dataset.id).find((nid) => nid !== "net");
      if (id) { centreOn(pos[id][0], pos[id][1]); select(["host:" + id]); }
    } });
  const people = h("span", { class: "topo-people" });
  let fullBtn = null;
  function buildBar() {
    const layerSel = h("select", { "aria-label": t("mapLayer"), onchange: (e) => setLayer(e.target.value) },
      h("option", { value: "" }, t("mapLive")), Object.values(doc().layers).sort((a, b) => Date.parse(a.created) - Date.parse(b.created)).map((l) => h("option", { value: l.id, selected: l.id === topo.layer || null }, l.name)));
    const ovSel = h("select", { "aria-label": t("mapOverlay"), onchange: (e) => { topo.overlay = e.target.value; store("vigil.mapOverlay", topo.overlay); redraw(); } },
      [["", t("mapOverlay") + ": " + t("mapOverlayOff")], ["cpu", t("cpu")], ["mem", t("memory")], ["disk", t("disk")], ["alerts", t("mapAlerts")], ["updates", t("mapUpdates")], ["vulns", t("mapVulns")]]
        .map(([v, l]) => h("option", { value: v, selected: v === topo.overlay || null }, l)));
    const mode = h("div", { class: "tabs" }, [[false, t("mapShared")], [true, t("mapMine")]].map(([v, l]) =>
      h("button", { type: "button", class: topo.mine === v ? "on" : null, onclick: () => { topo.mine = v; store("vigil.mapMine", v ? "1" : "0"); buildBar(); redraw(); } }, l)));
    fullBtn = btn(topo.full ? t("topoFullEnd") : t("topoFull"), t("topoFull"), toggleFull);
    // on a phone the bars fold away behind one button
    const fold = h("button", { type: "button", class: "btn ghost small topo-narrow-btn" + (wrap.classList.contains("tools-open") ? " on" : ""),
      onclick: (e) => { wrap.classList.toggle("tools-open"); e.currentTarget.classList.toggle("on"); } }, t("mapTools"));
    const fullSmall = h("button", { type: "button", class: "btn ghost small topo-narrow-btn", onclick: toggleFull }, t("topoFull"));
    bar.replaceChildren(...[find, fold, fullSmall, h("label", { class: "inline-l" }, t("mapLayer"), layerSel), ovSel, mode,
      check("showVigil", t("topoVigil"), "vigil.topoVigil"), check("showNet", t("internet"), "vigil.topoNet"),
      check("cursors", t("mapCursors"), "vigil.mapCursors", drawCursors), check("attacks", t("mapAttacks"), "vigil.mapAttacks", () => { atkCursor = null; pollAttacks(); }),
      topo.mine && canEdit() && topo.pos ? btn(t("mapAdoptMine"), t("mapAdoptMine"), adoptMine) : null,
      people,
      h("span", { class: "topo-tools" },
        btn("−", t("topoZoomOut"), () => zoomAt(1 / 1.25, svg.clientWidth / 2, svg.clientHeight / 2)),
        btn("+", t("topoZoomIn"), () => zoomAt(1.25, svg.clientWidth / 2, svg.clientHeight / 2)),
        btn(t("topoFit"), t("topoFit"), fit),
        topo.mine && topo.pos ? btn(t("topoReset"), t("topoReset"), async () => {
          if (!confirm(t("topoResetAsk"))) return;
          clearTimeout(topo.saveT);
          await post("/api/ui/account/topology", { pos: {} }).catch(() => null);
          topo.pos = null; buildBar(); redraw();
        }) : null,
        btn(t("mapShare"), t("mapShare"), share),
        exportMenu(),
        fullBtn)].filter(Boolean));
    showPeople();
  }
  function toolButtons() {
    const ed = canEdit();
    const tb = (k, key) => h("button", { type: "button", class: "btn ghost small tool" + (topo.tool === k ? " on" : ""), title: t("tool" + k[0].toUpperCase() + k.slice(1)) + " (" + key + ")",
      onclick: () => { topo.tool = topo.tool === k ? "select" : k; tools.replaceChildren(...toolButtons()); svg.focus({ preventScroll: true }); } }, t("tool" + k[0].toUpperCase() + k.slice(1)));
    const out = [tb("select", "V"), tb("hand", "H"), tb("comment", "C")];
    if (ed) {
      out.push(h("span", { class: "tsep" }), tb("note", "N"), tb("zone", "Z"), tb("arrow", "A"), tb("text", "T"), tb("stamp", "S"), tb("ext", "E"), tb("planned", "P"));
      if (topo.tool === "arrow") out.push(h("select", { "aria-label": t("mapStyle"), onchange: (e) => { topo.arrow = e.target.value; } }, MAP_ARROWS.map((s) => h("option", { value: s, selected: s === topo.arrow || null }, t("arrow" + s[0].toUpperCase() + s.slice(1))))));
      if (topo.tool === "stamp") out.push(h("select", { "aria-label": t("toolStamp"), onchange: (e) => { topo.stamp = e.target.value; } }, MAP_STAMPS.map((s) => h("option", { value: s, selected: s === topo.stamp || null }, t("st" + s[0].toUpperCase() + s.slice(1))))));
    }
    out.push(h("span", { class: "tsep" }), btn("↶", t("mapUndo") + " (Ctrl+Z)", () => mapUndo(false)), btn("↷", t("mapRedo") + " (Ctrl+Y)", () => mapUndo(true)),
      h("span", { class: "tsep" }), btn(t("mapTime"), t("mapTime"), () => { topo.time = !topo.time; timeBar(); if (topo.time) loadTimeline(); else { topo.timeIdx = -1; redraw(); } }, topo.time ? "on" : ""),
      btn(t("mapPanel"), t("mapPanel"), () => openTab(topo.panel ? topo.panel : "sel"), topo.panel ? "on" : ""),
      btn("?", t("mapHelp"), help));
    wrap.classList.toggle("tool-place", !["select", "hand"].includes(topo.tool));
    wrap.classList.toggle("tool-hand", topo.tool === "hand");
    return out;
  }
  function showPeople() {
    const seen = new Map();
    for (const p of live.presence) if (!seen.has(p.user)) seen.set(p.user, p);
    people.replaceChildren(...[live.lost ? h("span", { class: "muted small" }, t("mapReconnect")) : null].filter(Boolean),
      ...[...seen.keys()].map((u) => withUC(h("span", { class: "udot" + (u === live.me ? " me" : ""), title: u + "  ·  " + t("mapHere") }, u.slice(0, 2).toUpperCase()), u)));
  }
  async function adoptMine() {
    if (!confirm(t("mapAdoptAsk"))) return;
    const ops = Object.entries(topo.pos || {}).filter(([id]) => id === "net" || byId[id]).map(([id, p]) => putOp("layout", id, p.slice()));
    if (await mapSend(ops)) { topo.mine = false; store("vigil.mapMine", "0"); buildBar(); redraw(); }
  }

  // ---------- time travel and "new since"
  async function loadTimeline() {
    const now = Math.floor(Date.now() / 1000);
    try { live.timeline = await api("/api/ui/map/timeline?from=" + (now - 7 * 86400) + "&to=" + now); }
    catch (x) { toast(x.message); return; }
    topo.timeIdx = live.timeline.snaps.length - 1;
    timeBar(); redraw();
  }
  let playT = null;
  function timeBar() {
    clearInterval(playT); playT = null;
    timebar.hidden = !topo.time;
    tools.replaceChildren(...toolButtons());
    if (!topo.time) return;
    const tl = live.timeline, n = tl ? tl.snaps.length : 0;
    const label = h("span", { class: "tm-label" });
    const setLabel = () => { label.textContent = !n ? t("tmNoData") : topo.timeIdx >= n - 1 ? t("tmNow") : new Date(tl.snaps[topo.timeIdx].t * 1000).toLocaleString(lang, { weekday: "short", hour: "2-digit", minute: "2-digit", day: "2-digit", month: "2-digit" }); };
    const range = h("input", { type: "range", min: 0, max: Math.max(0, n - 1), value: Math.max(0, topo.timeIdx), disabled: n < 2 || null, "aria-label": t("mapTime"),
      oninput: (e) => { topo.timeIdx = Number(e.target.value); setLabel(); drawEdges(); drawPins(); mark(); } });
    const play = btn(t("tmPlay"), t("tmPlay"), () => {
      if (playT) { clearInterval(playT); playT = null; play.textContent = t("tmPlay"); return; }
      if (topo.timeIdx >= n - 1) topo.timeIdx = 0;
      play.textContent = t("tmPause");
      playT = setInterval(() => {
        topo.timeIdx = Math.min(n - 1, topo.timeIdx + 1); range.value = topo.timeIdx; setLabel(); drawEdges(); mark();
        if (topo.timeIdx >= n - 1) { clearInterval(playT); playT = null; play.textContent = t("tmPlay"); }
      }, 350);
    });
    const ns = h("select", { "aria-label": t("tmNewSince"), onchange: (e) => { topo.newSince = e.target.value; store("vigil.mapNewSince", topo.newSince); redraw(); } },
      [["", t("tmOff")], ["24h", t("tm24h")], ["7d", t("tm7d")]].map(([v, l]) => h("option", { value: v, selected: v === topo.newSince || null }, l)));
    setLabel();
    timebar.replaceChildren(play, range, label, h("label", { class: "inline-l" }, t("tmNewSince"), ns), btn("×", t("close"), () => { topo.time = false; topo.timeIdx = -1; timeBar(); redraw(); }));
  }

  // ---------- export, import, share, help, full screen
  function exportMenu() {
    const menu = h("div", { class: "topo-menu", hidden: true });
    const item = (l, fn) => h("button", { type: "button", onclick: () => { menu.hidden = true; fn(); } }, l);
    const file = h("input", { type: "file", accept: "application/json,.json", hidden: true, onchange: (e) => importJSON(e.target.files[0]) });
    menu.append(item(t("mapPng"), () => exportImage(true)), item(t("mapSvg"), () => exportImage(false)), item(t("mapJson"), exportJSON));
    if (canEdit()) menu.append(item(t("mapImport"), () => file.click()));
    const b = btn(t("mapExport"), t("mapExport"), () => { menu.hidden = !menu.hidden; });
    return h("span", { class: "topo-menu-wrap" }, b, menu, file);
  }
  const download = (blob, name) => { const a = h("a", { href: URL.createObjectURL(blob), download: name }); document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000); };
  const STYLE_PROPS = ["fill", "fill-opacity", "stroke", "stroke-width", "stroke-dasharray", "stroke-opacity", "opacity", "font-size", "font-family", "font-weight", "display", "color", "background-color", "padding", "line-height", "white-space", "overflow-wrap", "text-transform", "letter-spacing"];
  function exportImage(png) {
    const W = svg.clientWidth, H = svg.clientHeight;
    // the page's CSP refuses style attributes even on a copy, so each
    // element gets a number and the styles go into the text afterwards
    const copy = svg.cloneNode(true);
    const a = [svg, ...svg.querySelectorAll("*")], b = [copy, ...copy.querySelectorAll("*")];
    const styles = a.map((el) => { const cs = getComputedStyle(el); return STYLE_PROPS.map((p) => p + ":" + cs.getPropertyValue(p)).join(";"); });
    b.forEach((el, i) => { el.removeAttribute("style"); el.setAttribute("data-xs", i); });
    copy.querySelectorAll(".ehit, .ahit, .particle, .cursor, .rhandle").forEach((el) => el.remove());
    copy.setAttribute("xmlns", SVG); copy.setAttribute("width", W); copy.setAttribute("height", H); copy.setAttribute("viewBox", "0 0 " + W + " " + H);
    copy.insertBefore(sv("rect", { width: W, height: H, fill: getComputedStyle(wrap).backgroundColor }), copy.firstChild);
    const esc = (v) => v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
    const text = new XMLSerializer().serializeToString(copy).replace(/data-xs="(\d+)"/g, (_, i) => 'style="' + esc(styles[Number(i)] || "") + '"');
    const name = "vigil-map-" + new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
    if (!png) { download(new Blob([text], { type: "image/svg+xml" }), name + ".svg"); return; }
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas"); c.width = W * 2; c.height = H * 2;
      const g = c.getContext("2d"); g.scale(2, 2); g.drawImage(img, 0, 0);
      try { c.toBlob((bl) => bl ? download(bl, name + ".png") : toast("PNG"), "image/png"); } catch (x) { toast(x.message); }
    };
    img.onerror = () => toast("PNG");
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(text);
  }
  function exportJSON() {
    const dd = doc();
    download(new Blob([JSON.stringify({ vigil_map: 1, layers: dd.layers, objects: dd.objects, layout: dd.layout, notes: dd.notes, tasks: dd.tasks, comments: dd.comments }, null, 1)], { type: "application/json" }), "vigil-map.json");
  }
  async function importJSON(f) {
    if (!f) return;
    let j;
    try { j = JSON.parse(await f.text()); } catch (x) { toast(x.message); return; }
    if (!j || j.vigil_map !== 1) { toast("JSON"); return; }
    const ops = [];
    for (const c of ["layers", "objects", "layout", "notes", "tasks", "comments"]) for (const [id, v] of Object.entries(j[c] || {})) ops.push(putOp(c, id, c === "objects" ? cleanObj(v) : v));
    // replies after their threads, plans before what is drawn in them
    ops.sort((x, y) => ["layers", "objects", "layout", "notes", "tasks", "comments"].indexOf(x.c) - ["layers", "objects", "layout", "notes", "tasks", "comments"].indexOf(y.c) || (x.v && x.v.parent ? 1 : 0) - (y.v && y.v.parent ? 1 : 0));
    if (!ops.length || !confirm(tf("mapImportAsk", { n: ops.length }))) return;
    mapSend(ops);
  }
  function share() {
    const v = topo.view || { x: 0, y: 0, k: 1 };
    const W = svg.clientWidth, H = svg.clientHeight;
    const cx = Math.round((W / 2 - v.x) / v.k), cy = Math.round((H / 2 - v.y) / v.k);
    const q = new URLSearchParams({ map: [cx, cy, v.k.toFixed(2)].join(",") });
    if (topo.layer) q.set("layer", topo.layer);
    if (topo.sel[0]) q.set("sel", topo.sel[0]);
    const url = location.origin + location.pathname + "#/hosts?" + q.toString();
    (navigator.clipboard ? navigator.clipboard.writeText(url) : Promise.reject()).then(() => toast(t("mapCopied")), () => prompt(t("mapShare"), url));
  }
  // a shared link: where to look, which plan, what to select
  function fromLink() {
    const q = new URLSearchParams(location.hash.split("?")[1] || "");
    if (!q.has("map") && !q.has("sel") && !q.has("layer")) return false;
    if (q.has("layer") && doc().layers[q.get("layer")]) { topo.layer = q.get("layer"); buildBar(); }
    const m = (q.get("map") || "").split(",").map(Number);
    if (m.length === 3 && m.every(Number.isFinite)) { const k = Math.max(0.15, Math.min(2.5, m[2])); topo.view = { k, x: svg.clientWidth / 2 - m[0] * k, y: svg.clientHeight / 2 - m[1] * k }; }
    if (q.get("sel")) select([q.get("sel")]);
    history.replaceState(null, "", "#/hosts");
    return !!topo.view;
  }
  function help() {
    const box = h("div", { class: "topo-help", role: "dialog" }, h("h4", null, t("mapHelp")), h("pre", null, t("helpKeys")),
      h("button", { type: "button", class: "btn small", onclick: () => box.remove() }, t("close")));
    stage.append(box);
    box.querySelector("button").focus();
  }
  function toggleFull() {
    topo.full = !topo.full;
    wrap.classList.toggle("full", topo.full);
    document.body.classList.toggle("topo-noscroll", topo.full);
    if (fullBtn) fullBtn.textContent = topo.full ? t("topoFullEnd") : t("topoFull");
    requestAnimationFrame(fit);
  }

  // ---------- redraw
  function drawAll() {
    layoutNow();
    drawNodes(); drawHulls(); drawEdges(); drawArrows(); drawPins(); drawCursors(); mark(); drawMini();
    panel();
  }
  let lastLayers = "";
  function redraw() {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(() => {
      rafPending = false;
      if (stopped) return;
      if (topo.drag) { dirty = true; return; }
      // plans and the right to edit show in the toolbars
      const sig = live.edit + "|" + Object.values(doc().layers).map((l) => l.id + l.name).join("|");
      if (sig !== lastLayers) { lastLayers = sig; buildBar(); tools.replaceChildren(...toolButtons()); }
      drawAll();
    });
  }
  // a redraw that waited for a drag runs once the drag ends
  const dirtyT = setInterval(() => {
    if (dirty && !topo.drag) { dirty = false; redraw(); }
    const now = Date.now();
    if (Object.values(live.cursors).some((c) => now - c.at > 15000)) { for (const [k, c] of Object.entries(live.cursors)) if (now - c.at > 15000) delete live.cursors[k]; drawCursors(); }
  }, 1000);

  buildBar();
  tools.replaceChildren(...toolButtons());
  layoutNow();
  drawAll();
  timeBar();
  if (topo.full) document.body.classList.add("topo-noscroll");
  requestAnimationFrame(() => {
    if (!fromLink()) { if (topo.view) applyView(); else fit(); } else applyView();
    if ((wrap.clientWidth || 800) < 620) wrap.classList.add("narrow");
  });
  if (topo.attacks) pollAttacks();
  if (topo.newSince || topo.time) loadTimeline();

  return {
    el: wrap,
    update(nd) { setData(nd); redraw(); },
    redraw,
    toast,
    people: showPeople,
    cursors() { drawCursors(); drawLocks(); },
    pulse: drawPulses,
    stop() { stopped = true; clearTimeout(atkT); clearInterval(playT); clearInterval(dirtyT); },
  };
}
