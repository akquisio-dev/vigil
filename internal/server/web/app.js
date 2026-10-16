"use strict";

// Everything that comes from agents (host names, paths, command lines) is
// attacker-controlled. It only ever reaches the page through textContent.

const T = {
  en: {
    overview: "Overview", alerts: "Alerts", events: "Events", canaries: "Canaries", settings: "Settings",
    logout: "Log out", user: "User", password: "Password", code: "Code", login: "Log in",
    hosts: "Hosts", online: "online", silent: "silent", stopped: "stopped", pending: "waiting",
    open: "Open", acked: "Acknowledged", resolved: "Resolved", all: "All",
    critical: "critical", high: "high", medium: "medium", low: "low", info: "info",
    lastSeen: "Last seen", lastIP: "Address", version: "Version", enrolled: "Enrolled",
    ports: "Ports", logins24: "SSH logins (24 h)", eventsHour: "Events per hour", failedHour: "Failed SSH logins per hour",
    chain: "Event chain", chainOK: "intact", chainBroken: "broken", verify: "Verify now", records: "Records", head: "Head",
    noAlerts: "No alerts", noEvents: "No events", noCanaries: "No canaries", noHosts: "No hosts",
    ack: "Acknowledge", resolve: "Resolve", reopen: "Reopen", count: "Count", technique: "ATT&CK", host: "Host",
    created: "Created", updated: "Updated", by: "By", status: "Status", type: "Type", path: "Path",
    triggers: "Opened", lastTriggered: "Last opened", place: "Place canary", remove: "Remove",
    domain: "Domain (optional)", email: "Tracking e-mail (optional)", comment: "Key comment (optional)",
    canaryRoots: "Canary roots", none: "none", expected: "expected", unexpected: "new",
    accept: "Accept", acceptAll: "Accept all", process: "Process", scope: "Scope", via: "Via",
    rename: "Rename", deleteHost: "Remove host", confirmDelete: "Remove this host and its canaries?",
    confirmCanary: "Remove this canary? The agent deletes the file.",
    enroll: "Enroll a host", newToken: "Create token", validUntil: "valid until", notifyTest: "Send test notification",
    sent: "sent", loadMore: "Load more", filterType: "Type prefix", allHosts: "All hosts", time: "Time", details: "Details",
    params: "Parameters", logins: "SSH logins", ip: "IP", key: "Key", method: "Method", configSync: "Config",
    synced: "applied", waiting: "pending", alertsOpen: "open alerts", canariesOpened: "opened",
    active: "active", tampered: "tampered", error: "error", loginSub: "Access to your security operations center",
    maintenance: "Maintenance", maintenanceUntil: "Maintenance until", start: "Start", end: "End", minutes: "min",
    acceptProcess: "Allow process", welcome: "Welcome", placed: "placed", noneOpened: "none opened",
    alertsTile: "Open alerts", language: "Language", sectionOverview: "Overview", sectionDetect: "Detection", sectionSystem: "System",
    admin: "Administrator", failedTile: "Failed logins", addresses: "addresses", mtta: "Time to acknowledge",
    mttaSub: "median, 30 days", noneYet: "nothing acknowledged yet", hoursShort: "h", daysShort: "d",
    alertsWeek: "Alerts, last 7 days", openBySev: "Open by severity", tactics: "ATT&CK tactics", topRules: "Top rules",
    attackers: "Attacking addresses", days7: "7 days", theme: "Appearance", light: "Light", dark: "Dark", system: "System",
    suppressions: "Suppressions", suppress: "Suppress similar", suppressHint: "Matching findings stay in the event log but raise no alert.",
    onlyHost: "Only this host", reason: "Reason", duration: "Duration", days: "days", hits: "Hits", expires: "Expires",
    expired: "Expired", renew: "Renew", allHostsLbl: "all hosts", noSuppressions: "No suppressions", confirmSuppressionDelete: "Delete this suppression?",
    activeCount: "active", match: "Match", severity: "Severity",
    incidents: "Incidents", incident: "Incident", noIncidents: "No incidents", owner: "Owner", assignMe: "Take over",
    investigating: "investigating", contained: "contained", closed: "closed", openInc: "open", activeInc: "Active",
    notes: "Notes", addNote: "Add note", timeline: "Timeline", startedBy: "Session started by", newIncident: "Open incident",
    mttc: "Median time to close", alertsN: "alerts", unowned: "nobody", setStatus: "Status",
    rules: "Rules", customRules: "Custom rules", builtinRules: "Built-in rules", ruleErrors: "Not loaded", noCustom: "No custom rules (rules_dir in server.json)",
    rule: "Rule", file: "File", title: "Title", builtin: "built-in", customShort: "custom",
  },
  de: {
    overview: "Lage", alerts: "Alarme", events: "Ereignisse", canaries: "Köder", settings: "Einstellungen",
    logout: "Abmelden", user: "Benutzer", password: "Passwort", code: "Code", login: "Anmelden",
    hosts: "Hosts", online: "online", silent: "stumm", stopped: "beendet", pending: "wartet",
    open: "Offen", acked: "Gesehen", resolved: "Erledigt", all: "Alle",
    critical: "kritisch", high: "hoch", medium: "mittel", low: "niedrig", info: "Info",
    lastSeen: "Zuletzt gesehen", lastIP: "Adresse", version: "Version", enrolled: "Eingeschrieben",
    ports: "Ports", logins24: "SSH-Anmeldungen (24 h)", eventsHour: "Ereignisse pro Stunde", failedHour: "Fehlgeschlagene SSH-Anmeldungen pro Stunde",
    chain: "Ereigniskette", chainOK: "intakt", chainBroken: "gebrochen", verify: "Jetzt prüfen", records: "Einträge", head: "Kopf",
    noAlerts: "Keine Alarme", noEvents: "Keine Ereignisse", noCanaries: "Keine Köder", noHosts: "Keine Hosts",
    ack: "Gesehen", resolve: "Erledigt", reopen: "Wieder öffnen", count: "Anzahl", technique: "ATT&CK", host: "Host",
    created: "Erstellt", updated: "Aktualisiert", by: "Von", status: "Status", type: "Typ", path: "Pfad",
    triggers: "Geöffnet", lastTriggered: "Zuletzt geöffnet", place: "Köder auslegen", remove: "Entfernen",
    domain: "Domain (optional)", email: "Tracking-Mail (optional)", comment: "Schlüssel-Kommentar (optional)",
    canaryRoots: "Köder-Wurzeln", none: "keine", expected: "erwartet", unexpected: "neu",
    accept: "Erlauben", acceptAll: "Alle erlauben", process: "Prozess", scope: "Bereich", via: "Über",
    rename: "Umbenennen", deleteHost: "Host entfernen", confirmDelete: "Diesen Host und seine Köder entfernen?",
    confirmCanary: "Köder entfernen? Der Agent löscht die Datei.",
    enroll: "Host einschreiben", newToken: "Token erzeugen", validUntil: "gültig bis", notifyTest: "Testnachricht senden",
    sent: "gesendet", loadMore: "Mehr laden", filterType: "Typ-Präfix", allHosts: "Alle Hosts", time: "Zeit", details: "Details",
    params: "Parameter", logins: "SSH-Anmeldungen", ip: "IP", key: "Schlüssel", method: "Methode", configSync: "Konfiguration",
    synced: "übernommen", waiting: "ausstehend", alertsOpen: "offene Alarme", canariesOpened: "geöffnet",
    active: "aktiv", tampered: "manipuliert", error: "Fehler", loginSub: "Zugang zu deiner Sicherheitszentrale",
    maintenance: "Wartung", maintenanceUntil: "Wartung bis", start: "Starten", end: "Beenden", minutes: "Min.",
    acceptProcess: "Prozess erlauben", welcome: "Willkommen", placed: "ausgelegt", noneOpened: "keiner geöffnet",
    alertsTile: "Offene Alarme", language: "Sprache", sectionOverview: "Übersicht", sectionDetect: "Erkennung", sectionSystem: "System",
    admin: "Administrator", failedTile: "Fehlversuche", addresses: "Adressen", mtta: "Reaktionszeit",
    mttaSub: "Median, 30 Tage", noneYet: "noch nichts gesehen", hoursShort: "Std.", daysShort: "Tg.",
    alertsWeek: "Alarme, letzte 7 Tage", openBySev: "Offen nach Schwere", tactics: "ATT&CK-Taktiken", topRules: "Häufigste Regeln",
    attackers: "Angreifende Adressen", days7: "7 Tage", theme: "Darstellung", light: "Hell", dark: "Dunkel", system: "System",
    suppressions: "Ausnahmen", suppress: "Ähnliche stummschalten", suppressHint: "Passende Funde bleiben im Ereignisprotokoll, lösen aber keinen Alarm aus.",
    onlyHost: "Nur dieser Host", reason: "Begründung", duration: "Dauer", days: "Tage", hits: "Treffer", expires: "Läuft ab",
    expired: "Abgelaufen", renew: "Verlängern", allHostsLbl: "alle Hosts", noSuppressions: "Keine Ausnahmen", confirmSuppressionDelete: "Diese Ausnahme löschen?",
    activeCount: "aktiv", match: "Bedingung", severity: "Schwere",
    incidents: "Vorfälle", incident: "Vorfall", noIncidents: "Keine Vorfälle", owner: "Zuständig", assignMe: "Übernehmen",
    investigating: "in Arbeit", contained: "eingedämmt", closed: "geschlossen", openInc: "offen", activeInc: "Aktiv",
    notes: "Notizen", addNote: "Notiz hinzufügen", timeline: "Zeitstrahl", startedBy: "Sitzung begonnen von", newIncident: "Vorfall anlegen",
    mttc: "Median bis geschlossen", alertsN: "Alarme", unowned: "niemand", setStatus: "Status",
    rules: "Regeln", customRules: "Eigene Regeln", builtinRules: "Eingebaute Regeln", ruleErrors: "Nicht geladen", noCustom: "Keine eigenen Regeln (rules_dir in server.json)",
    rule: "Regel", file: "Datei", title: "Titel", builtin: "eingebaut", customShort: "eigene",
  },
};

const SEVS = ["critical", "high", "medium", "low"];
const store = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { return null; } };
let lang = store("vigil.lang") || ((navigator.language || "").startsWith("de") ? "de" : "en");
const t = (k) => (T[lang] && T[lang][k]) || T.en[k] || k;
let me = null;

// h builds DOM nodes. Strings become text nodes, never markup.
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {}, credentials: "same-origin" };
  if (opts.body !== undefined) {
    init.body = JSON.stringify(opts.body);
    init.headers["Content-Type"] = "application/json";
  }
  if (init.method !== "GET" && me) init.headers["X-CSRF"] = me.csrf;
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(path + sep + "lang=" + lang, init);
  if (res.status === 401 && !path.endsWith("/login")) {
    // Only a session that just expired re-renders; a missing one is handled by render() itself.
    if (me) { me = null; render(); }
    throw new Error("unauthorized");
  }
  if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
  return res.json();
}

const post = (path, body = {}) => api(path, { method: "POST", body });

function ago(ts) {
  if (!ts || ts.startsWith("0001")) return "·";
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto", style: "short" });
  if (s < 60) return rtf.format(-Math.round(s), "second");
  if (s < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (s < 86400) return rtf.format(-Math.round(s / 3600), "hour");
  return rtf.format(-Math.round(s / 86400), "day");
}
const abs = (ts) => (ts && !ts.startsWith("0001") ? new Date(ts).toLocaleString(lang) : "");
const timeEl = (ts) => h("time", { datetime: ts, title: abs(ts) }, ago(ts));

const sevChip = (sev) => h("span", { class: "sev " + sev }, t(sev));
const incChip = (st) => h("span", { class: "chip" }, h("span", { class: "dot " + ({ open: "critical", investigating: "medium", contained: "low", closed: "ok" }[st] || "") }),
  t(st === "open" ? "openInc" : st));
const statusChip = (st) => h("span", { class: "chip" }, h("span", { class: "dot " + st }), t(st) || st);

function summary(data) {
  if (!data) return "";
  return Object.entries(data)
    .filter(([k]) => k !== "ports")
    .map(([k, v]) => k + "=" + (typeof v === "object" ? JSON.stringify(v) : v))
    .join("  ");
}

// Tabler Icons (MIT, https://tabler.io/icons), outline paths.
const ICONS = {"book": ["M3 19a9 9 0 0 1 9 0a9 9 0 0 1 9 0", "M3 6a9 9 0 0 1 9 0a9 9 0 0 1 9 0", "M3 6l0 13", "M12 6l0 13", "M21 6l0 13"], "stack-2": ["M12 4l-8 4l8 4l8 -4l-8 -4", "M4 12l8 4l8 -4", "M4 16l8 4l8 -4"], "bell-off": ["M9.346 5.353c.21 -.129 .428 -.246 .654 -.353a2 2 0 1 1 4 0a7 7 0 0 1 4 6v3m-1 3h-13a4 4 0 0 0 2 -3v-3a6.996 6.996 0 0 1 1.273 -3.707", "M9 17v1a3 3 0 0 0 6 0v-1", "M3 3l18 18"], "clock": ["M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0", "M12 7v5l3 3"], "user-x": ["M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0", "M6 21v-2a4 4 0 0 1 4 -4h3.5", "M22 22l-5 -5", "M17 22l5 -5"], "plus": ["M12 5l0 14", "M5 12l14 0"], "alert-triangle": ["M12 9v4", "M10.363 3.591l-8.106 13.534a1.914 1.914 0 0 0 1.636 2.871h16.214a1.914 1.914 0 0 0 1.636 -2.87l-8.106 -13.536a1.914 1.914 0 0 0 -3.274 0z", "M12 16h.01"], "fish-hook": ["M16 9v6a5 5 0 0 1 -10 0v-4l3 3", "M16 7m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M16 5v-2"], "layout-dashboard": ["M5 4h4a1 1 0 0 1 1 1v6a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-6a1 1 0 0 1 1 -1", "M5 16h4a1 1 0 0 1 1 1v2a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-2a1 1 0 0 1 1 -1", "M15 12h4a1 1 0 0 1 1 1v6a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-6a1 1 0 0 1 1 -1", "M15 4h4a1 1 0 0 1 1 1v2a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-2a1 1 0 0 1 1 -1"], "list-details": ["M13 5h8", "M13 9h5", "M13 15h8", "M13 19h5", "M3 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z", "M3 14m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"], "logout": ["M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2", "M9 12h12l-3 -3", "M18 15l3 -3"], "server": ["M3 4m0 3a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z", "M3 12m0 3a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z", "M7 8l0 .01", "M7 16l0 .01"], "settings": ["M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065z", "M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"], "shield-check": ["M11.46 20.846a12 12 0 0 1 -7.96 -14.846a12 12 0 0 0 8.5 -3a12 12 0 0 0 8.5 3a12 12 0 0 1 -.09 7.06", "M15 19l2 2l4 -4"]};

const SVG = "http://www.w3.org/2000/svg";
function icon(name, viewBox = "0 0 24 24", paths = ICONS[name]) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", viewBox);
  svg.setAttribute("class", "ic");
  svg.setAttribute("aria-hidden", "true");
  for (const d of paths || []) {
    const p = document.createElementNS(SVG, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}
function logoMark() {
  const svg = icon(null, "0 0 32 32", ["M7 10c2.6 6.4 5.4 10.2 9 12 3.6-1.8 6.4-5.6 9-12"]);
  svg.setAttribute("class", "ic logo-mark");
  const eye = document.createElementNS(SVG, "circle");
  eye.setAttribute("cx", "16"); eye.setAttribute("cy", "8.5"); eye.setAttribute("r", "2.4");
  svg.append(eye);
  return svg;
}
// A brand set in the server config replaces the vigil mark and name.
const brandTpl = document.getElementById("brand-logo");
const brandName = (document.querySelector('meta[name="vigil-brand"]') || {}).content || "vigil";
function logo() {
  if (brandTpl) return h("a", { class: "sidebar-logo branded", href: "#/", "aria-label": brandName }, brandTpl.content.cloneNode(true));
  return h("a", { class: "sidebar-logo", href: "#/" }, logoMark(), h("span", { class: "logo-text" }, "VIGIL"));
}

// ---------- shell ----------

const sections = [
  ["sectionOverview", [["overview", "#/", "layout-dashboard"]]],
  ["sectionDetect", [["incidents", "#/incidents", "stack-2"], ["alerts", "#/alerts", "alert-triangle"], ["events", "#/events", "list-details"], ["canaries", "#/canaries", "fish-hook"],
    ["suppressions", "#/suppressions", "bell-off"]]],
  ["sectionSystem", [["rules", "#/rules", "book"], ["settings", "#/settings", "settings"]]],
];
let openAlerts = 0;

const logout = async () => { await post("/api/ui/logout").catch(() => {}); me = null; render(); };
const setLang = (l) => { lang = l; store("vigil.lang", lang); render(); };
const theme = () => store("vigil.theme") || "system";
function setTheme(v) {
  store("vigil.theme", v);
  if (v === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = v;
  render();
}

// shell lays out a page like the Akquisio app: sidebar, topbar, content.
// The page's h1 becomes the topbar title, .crumbs the line below it and
// .page-actions the buttons on the right.
function shell(active, ...content) {
  const flat = content.flat().filter(Boolean);
  const has = (n, c) => n.classList && n.classList.contains(c);
  const title = flat.find((n) => n.tagName === "H1");
  const crumbs = flat.find((n) => has(n, "crumbs"));
  const actions = flat.find((n) => has(n, "page-actions"));
  const body = flat.filter((n) => n !== title && n !== crumbs && n !== actions);
  const initials = (me.user || "?").slice(0, 1);

  const sidebar = h("aside", { class: "sidebar" },
    logo(),
    h("nav", { class: "nav" }, sections.map(([sec, items]) => [
      h("div", { class: "nav-section" }, t(sec)),
      items.map(([k, href, ic]) => h("a", { href, class: "nav-item" + (k === active ? " active" : ""), title: t(k) },
        h("span", { class: "nav-icon" }, icon(ic), k === "alerts" && openAlerts > 0 ? h("span", { class: "nav-dot" }) : null),
        h("span", { class: "nav-label" }, t(k)),
        k === "alerts" && openAlerts > 0 ? h("span", { class: "nav-count" }, openAlerts) : null))])),
    h("div", { class: "sidebar-footer" },
      h("div", { class: "user-chip" }, h("span", { class: "avatar" }, initials),
        h("div", { class: "user-info" }, h("div", { class: "user-name" }, me.user), h("div", { class: "user-role" }, t("admin"))),
        h("button", { class: "logout-btn", title: t("logout"), onclick: logout }, icon("logout")))));

  if (crumbs) crumbs.className = "page-sub";
  const topbar = h("header", { class: "topbar" },
    h("div", { class: "page-head" }, h("div", { class: "page-title" }, title ? title.textContent : ""), crumbs),
    actions);

  if (title) document.title = title.textContent + " | " + brandName;
  return h("div", { class: "app" }, sidebar, h("div", { class: "main" }, topbar, h("main", { class: "content" }, body)));
}

function mount(nodes) {
  const app = document.getElementById("app");
  app.replaceChildren(...[nodes].flat());
  document.documentElement.lang = lang;
}

function loginView() {
  const err = h("div", { class: "err" });
  const form = h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault();
    const f = new FormData(form);
    err.textContent = "";
    try {
      me = await post("/api/ui/login", { user: f.get("user"), password: f.get("password"), code: f.get("code") });
      render();
    } catch (x) { err.textContent = x.message; }
  } },
    h("label", null, t("user"), h("input", { name: "user", autocomplete: "username", required: true })),
    h("label", null, t("password"), h("input", { name: "password", type: "password", autocomplete: "current-password", required: true })),
    h("label", null, t("code"), h("input", { name: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: 6, required: true, placeholder: "000000" })),
    err,
    h("button", { class: "btn", type: "submit" }, t("login")));
  document.title = brandName;
  mount(h("div", { class: "login-wrap" }, h("div", { class: "login" },
    logo(), h("div", { class: "login-title" }, t("login")), h("div", { class: "login-sub" }, t("loginSub")), form)));
}

// ---------- charts ----------

let tipEl = null;
function tip(e, text) {
  if (!tipEl) { tipEl = h("div", { class: "tip" }); document.body.append(tipEl); }
  if (!text) { tipEl.hidden = true; return; }
  tipEl.hidden = false;
  tipEl.textContent = text;
  const x = Math.min(e.clientX + 12, window.innerWidth - tipEl.offsetWidth - 8);
  tipEl.style.left = x + "px";
  tipEl.style.top = (e.clientY - 34) + "px";
}

function barChart(title, values, startISO, alt) {
  const max = Math.max(1, ...values);
  const start = new Date(startISO);
  const total = values.reduce((a, b) => a + b, 0);
  const label = (i) => {
    const d = new Date(start.getTime() + i * 3600e3);
    return d.toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit" });
  };
  const chart = h("div", { class: "chart" + (alt ? " alt" : ""), role: "img", "aria-label": title });
  values.forEach((v, i) => {
    const bar = h("div", { class: "bar" });
    bar.style.height = (v / max * 100) + "%";
    chart.append(h("div", { class: "slot", onmousemove: (e) => tip(e, label(i) + "  ·  " + v.toLocaleString(lang)), onmouseleave: (e) => tip(e, null) }, bar));
  });
  return h("div", { class: "card" },
    h("div", { class: "chart-head" }, h("h3", null, title), h("span", { class: "total" }, total.toLocaleString(lang))),
    chart,
    h("div", { class: "axis" }, h("span", null, label(0)), h("span", null, label(12)), h("span", null, label(23))));
}

// ---------- views ----------

function alertRow(a) {
  return h("a", { class: "row", href: "#/alerts/" + a.id },
    sevChip(a.severity),
    h("div", null, h("div", { class: "title" }, a.title),
      h("div", { class: "sub" }, [a.host, a.technique, a.count > 1 ? "×" + a.count : null].filter(Boolean).join("  ·  "))),
    h("div", { class: "meta" }, timeEl(a.updated)));
}

const TACTICS = {
  "initial-access": "Initial Access", persistence: "Persistence", "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion", "credential-access": "Credential Access", impact: "Impact",
};

function duration(sec) {
  if (sec === null || sec === undefined) return "·";
  if (sec < 60) return sec + " s";
  if (sec < 3600) return Math.round(sec / 60) + " " + t("minutes");
  if (sec < 86400) return (sec / 3600).toLocaleString(lang, { maximumFractionDigits: 1 }) + " " + t("hoursShort");
  return (sec / 86400).toLocaleString(lang, { maximumFractionDigits: 1 }) + " " + t("daysShort");
}

// metric cards like the Akquisio dashboard: icon and label, value, one line of context
const metric = (href, ic, label, value, tone, sub) => h(href ? "a" : "div", { class: "card metric", href },
  h("div", { class: "metric-label" }, icon(ic), label),
  h("div", { class: "metric-value" + (tone ? " " + tone : "") }, value),
  sub ? h("div", { class: "metric-sub" }, sub) : null);

const panel = (title, extra, ...body) => h("div", { class: "card panel" },
  h("div", { class: "panel-head" }, h("h3", null, title), extra ? h("span", { class: "panel-extra" }, extra) : null), body);

// stacked columns, one per day, segments by severity
function severityChart(days, start) {
  const totals = days.map((d) => SEVS.reduce((a, s) => a + (d[s] || 0), 0));
  const max = Math.max(1, ...totals);
  const day = (i) => new Date(new Date(start).getTime() + i * 864e5);
  const chart = h("div", { class: "chart stacked" });
  days.forEach((d, i) => {
    const col = h("div", { class: "stack" });
    for (const s of [...SEVS].reverse()) {
      if (!d[s]) continue;
      const seg = h("div", { class: "seg " + s });
      seg.style.height = (d[s] / max * 100) + "%";
      col.append(seg);
    }
    const text = day(i).toLocaleDateString(lang, { weekday: "short", day: "numeric", month: "numeric" }) + "  ·  " +
      (SEVS.filter((s) => d[s]).map((s) => d[s] + " " + t(s)).join(", ") || t("noAlerts"));
    chart.append(h("div", { class: "slot", onmousemove: (e) => tip(e, text), onmouseleave: (e) => tip(e, null) }, col));
  });
  return h("div", null, chart,
    h("div", { class: "axis days" }, days.map((_, i) => h("span", null, day(i).toLocaleDateString(lang, { weekday: "short" })))),
    h("div", { class: "legend" }, SEVS.map((s) => h("span", null, h("span", { class: "dot " + s }), t(s)))));
}

// donut of open alerts by severity
function severityDonut(bySev) {
  const total = SEVS.reduce((a, s) => a + (bySev[s] || 0), 0);
  const ring = h("div", { class: "donut" + (total ? "" : " empty-ring") });
  if (total) {
    let at = 0;
    const stops = SEVS.filter((s) => bySev[s]).map((s) => {
      const from = at; at += bySev[s] / total * 360;
      return "var(--sev-" + s + ") " + from + "deg " + at + "deg";
    });
    ring.style.background = "conic-gradient(" + stops.join(", ") + ")";
  }
  ring.append(h("div", { class: "donut-hole" }, h("div", { class: "donut-num" }, total), h("div", { class: "donut-lbl" }, t("open"))));
  return h("div", { class: "donut-wrap" }, ring,
    h("div", { class: "donut-legend" }, SEVS.map((s) => h("a", { href: "#/alerts", class: "legend-row" },
      h("span", { class: "dot " + s }), h("span", null, t(s)), h("span", { class: "right num-sm" }, bySev[s] || 0)))));
}

// horizontal bars for ranked lists
function rankList(items, opts = {}) {
  if (!items.length) return h("div", { class: "empty small" }, opts.empty || t("none"));
  const max = Math.max(1, ...items.map((i) => i.count));
  return h("div", { class: "rank" }, items.map((it) => {
    const fill = h("div", { class: "rank-fill" + (opts.tone ? " " + opts.tone : "") });
    fill.style.width = (it.count / max * 100) + "%";
    return h(opts.href ? "a" : "div", { class: "rank-row" + (it.count ? "" : " zero"), href: opts.href ? opts.href(it) : null },
      h("div", { class: "rank-top" },
        h("span", { class: "rank-key" + (opts.mono ? " mono" : "") }, opts.label ? opts.label(it) : it.key),
        h("span", { class: "rank-count" }, it.count.toLocaleString(lang))),
      h("div", { class: "rank-bar" }, fill),
      it.extra ? h("div", { class: "rank-extra" }, it.extra) : null);
  }));
}

const sevCounts = (m) => h("span", { class: "sevcounts" }, SEVS.filter((s) => m && m[s]).map((s) => h("span", { class: "sev " + s }, m[s])));

async function overview() {
  const [o, inc] = await Promise.all([api("/api/ui/overview"), api("/api/ui/incidents?status=active")]);
  openAlerts = Object.values(o.open_by_severity).reduce((a, b) => a + b, 0);
  const online = o.agents.filter((a) => a.status === "online").length;
  const bySev = SEVS.filter((s) => o.open_by_severity[s]).map((s) => o.open_by_severity[s] + " " + t(s));
  const urgent = (o.open_by_severity.critical || 0) + (o.open_by_severity.high || 0);

  const tiles = h("div", { class: "grid metrics six" },
    metric(null, "server", t("hosts"), online + " / " + o.agents.length, online === o.agents.length ? null : "bad", t("online")),
    metric("#/alerts", "alert-triangle", t("alertsTile"), openAlerts, urgent ? "bad" : null, bySev.join(", ") || t("noAlerts")),
    metric("#/events?type=ssh.failed", "user-x", t("failedTile"), o.ssh_failed_24h.toLocaleString(lang), null,
      o.ssh_failed_ips + " " + t("addresses")),
    metric(null, "clock", t("mtta"), duration(o.mtta_seconds), null, o.acked_30d ? t("mttaSub") : t("noneYet")),
    metric("#/canaries", "fish-hook", t("canaries"), o.canaries, o.canaries_triggered ? "bad" : null,
      o.canaries_triggered ? o.canaries_triggered + " " + t("canariesOpened") : o.canaries ? t("noneOpened") : t("none")),
    metric("#/settings", "shield-check", t("chain"), t(o.chain.ok ? "chainOK" : "chainBroken"), o.chain.ok ? "good" : "bad",
      o.chain.seq.toLocaleString(lang) + " " + t("records")));

  const hostTable = o.agents.length ? h("div", { class: "tablewrap" }, h("table", { class: "hosts" },
    h("thead", null, h("tr", null, [t("host"), t("status"), t("lastSeen"), t("alertsOpen"), t("ports"), t("canaries"), t("configSync"), t("version")]
      .map((x) => h("th", null, x)))),
    h("tbody", null, o.agents.map((a) => h("tr", { class: "click", onclick: () => { location.hash = "#/hosts/" + a.id; } },
      h("td", null, h("a", { href: "#/hosts/" + a.id, class: "strong" }, a.name)),
      h("td", null, statusChip(a.status)),
      h("td", { class: "nowrap" }, timeEl(a.last_seen)),
      h("td", null, a.open_alerts ? sevCounts(a.open_by_severity) : h("span", { class: "muted" }, "0")),
      h("td", null, a.ports),
      h("td", null, a.canaries),
      h("td", null, h("span", { class: "chip" }, h("span", { class: "dot " + (a.config_sync ? "ok" : "pending") }), t(a.config_sync ? "synced" : "waiting"))),
      h("td", { class: "muted nowrap" }, a.version || "·")))))) : h("div", { class: "card empty" }, t("noHosts"));

  const loginRows = o.logins.length ? h("div", { class: "feed" }, o.logins.map((l) => h("div", { class: "feed-row" },
    h("div", null, h("span", { class: "strong" }, l.user), " ", h("span", { class: "muted" }, "@ " + l.host)),
    h("div", { class: "feed-sub mono" }, [l.ip, l.method, l.key].filter(Boolean).join("  ·  ")),
    h("div", { class: "feed-time" }, timeEl(l.ts))))) : h("div", { class: "empty small" }, t("noEvents"));

  mount(shell("overview",
    h("h1", null, t("overview")),
    h("div", { class: "crumbs" }, t("welcome") + ", " + me.user),
    tiles,
    h("div", { class: "grid dash-a" },
      panel(t("alertsWeek"), null, severityChart(o.alerts_per_day, o.day_start)),
      panel(t("openBySev"), null, severityDonut(o.open_by_severity))),
    h("div", { class: "grid dash-b" },
      panel(t("tactics"), t("days7"), rankList(o.tactics, { label: (i) => TACTICS[i.key] || i.key, href: () => "#/alerts" })),
      panel(t("topRules"), t("days7"), rankList(o.top_rules, { mono: true, empty: t("noAlerts"), href: () => "#/alerts" })),
      panel(t("attackers"), "24 h", rankList(o.top_attackers, { mono: true, tone: "red", empty: t("noEvents"),
        href: (i) => "#/events?type=ssh.failed" }))),
    h("h2", null, t("hosts")), hostTable,
    h("div", { class: "grid dash-b mt" },
      panel(t("incidents"), h("a", { href: "#/incidents" }, inc.incidents.length + " " + t("activeInc").toLowerCase()),
        h("div", { class: "feed" }, inc.incidents.length ? inc.incidents.slice(0, 5).map((c) => h("a", { class: "feed-row", href: "#/incidents/" + c.id },
          h("div", { class: "flex nowrap-flex" }, sevChip(c.severity), h("span", { class: "feed-title" }, c.title)),
          h("div", { class: "feed-sub" }, [c.host, c.count + " " + t("alertsN"), t(c.status === "open" ? "openInc" : c.status)].join("  ·  ")),
          h("div", { class: "feed-time" }, timeEl(c.last)))) : h("div", { class: "empty small" }, t("noIncidents")))),
      panel(t("alerts"), h("a", { href: "#/alerts" }, t("all")),
        h("div", { class: "feed" }, o.recent_alerts.length ? o.recent_alerts.slice(0, 6).map((a) => h("a", { class: "feed-row", href: "#/alerts/" + a.id },
          h("div", { class: "flex nowrap-flex" }, sevChip(a.severity), h("span", { class: "feed-title" }, a.title)),
          h("div", { class: "feed-sub" }, [a.host, a.technique].filter(Boolean).join("  ·  ")),
          h("div", { class: "feed-time" }, timeEl(a.updated)))) : h("div", { class: "empty small" }, t("noAlerts")))),
      panel(t("logins"), o.logins_24h + " · 24 h", loginRows)),
    h("div", { class: "grid two mt" },
      barChart(t("eventsHour"), o.events_per_hour, o.hour_start),
      barChart(t("failedHour"), o.ssh_failed_per_hour, o.hour_start, true))));
}

let alertTab = "open";
async function alertsView() {
  const list = await api("/api/ui/alerts?status=" + (alertTab === "all" ? "" : alertTab));
  const tabs = h("div", { class: "tabs" }, ["open", "acked", "resolved", "all"].map((k) =>
    h("button", { class: k === alertTab ? "on" : null, onclick: () => { alertTab = k; render(); } }, t(k))));
  const n = list.length + " " + (alertTab === "all" ? t("alerts") : t(alertTab).toLowerCase());
  mount(shell("alerts", h("h1", null, t("alerts")), h("div", { class: "crumbs" }, n), tabs,
    h("div", { class: "list" }, list.length ? list.map(alertRow) : h("div", { class: "empty" }, t("noAlerts")))));
}

async function alertDetail(id) {
  const all = await api("/api/ui/alerts");
  const a = all.find((x) => x.id === id);
  if (!a) { location.hash = "#/alerts"; return; }
  const params = (a.detail || "").split("\n").filter(Boolean).map((l) => l.split(/=(.*)/s));
  const act = (action) => async () => { await post("/api/ui/alerts/" + a.id + "/" + action); render(); };
  // suppression form, prefilled from the alert; volatile parameters start unchecked
  const volatile = new Set(["count", "pid", "gap", "fingerprint"]);
  const onlyHost = h("input", { type: "checkbox", checked: Boolean(a.agent) });
  const checks = params.filter(([k]) => k && k !== "host").map(([k, v]) => ({ k, v, box: h("input", { type: "checkbox", checked: !volatile.has(k) }) }));
  const reason = h("input", { maxlength: 500, required: true });
  const daysSel = h("select", null, [7, 30, 90].map((d) => h("option", { value: d, selected: d === 30 }, d + " " + t("days"))));
  const err = h("div", { class: "err" });
  const box = h("form", { class: "card stack mt", hidden: true, onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    const match = {};
    for (const c of checks) if (c.box.checked) match[c.k] = c.v;
    try {
      await post("/api/ui/suppressions", { rule: a.rule, agent: onlyHost.checked ? a.agent : "", match, reason: reason.value, days: Number(daysSel.value) });
      if (a.status !== "resolved") await post("/api/ui/alerts/" + a.id + "/resolve");
      location.hash = "#/suppressions";
    } catch (x) { err.textContent = x.message; }
  } },
    h("h3", null, t("suppress")),
    h("div", { class: "muted" }, t("suppressHint")),
    a.agent ? h("label", { class: "check" }, onlyHost, t("onlyHost") + " (" + (a.host || a.agent) + ")") : null,
    checks.map((c) => h("label", { class: "check" }, c.box, h("span", { class: "mono" }, c.k + " = " + (c.v || "·")))),
    h("div", { class: "grid two" }, h("label", null, t("reason"), reason), h("label", null, t("duration"), daysSel)),
    err, h("div", null, h("button", { class: "btn", type: "submit" }, t("suppress"))));
  mount(shell("alerts",
    h("div", { class: "crumbs" }, h("a", { href: "#/alerts" }, t("alerts")), " / ", a.rule),
    h("h1", null, a.title),
    h("div", { class: "card" },
      h("dl", { class: "kv" },
        h("dt", null, t("status")), h("dd", null, t(a.status) + (a.by ? " · " + a.by : "")),
        h("dt", null, t("severity")), h("dd", null, sevChip(a.severity)),
        h("dt", null, t("host")), h("dd", null, a.agent ? h("a", { href: "#/hosts/" + a.agent }, a.host || a.agent) : "·"),
        h("dt", null, t("technique")), h("dd", null, a.technique ? h("a", { href: "https://attack.mitre.org/techniques/" + a.technique.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer" }, a.technique) : "·"),
        h("dt", null, t("count")), h("dd", null, a.count),
        h("dt", null, t("created")), h("dd", null, abs(a.created)),
        h("dt", null, t("updated")), h("dd", null, abs(a.updated)),
        params.map(([k, v]) => [h("dt", null, k), h("dd", { class: "mono" }, v || "·")])),
      h("div", { class: "actions" },
        a.status === "open" ? h("button", { class: "btn", onclick: act("ack") }, t("ack")) : null,
        a.status !== "resolved" ? h("button", { class: "btn ghost", onclick: act("resolve") }, t("resolve")) : null,
        a.status !== "open" ? h("button", { class: "btn ghost", onclick: act("reopen") }, t("reopen")) : null,
        a.suppressible ? h("button", { class: "btn ghost", onclick: () => { box.hidden = false; reason.focus(); } }, icon("bell-off"), t("suppress")) : null,
        a.incident ? h("a", { class: "btn ghost", href: "#/incidents/" + a.incident }, icon("stack-2"), t("incident"))
          : a.agent ? h("button", { class: "btn ghost", onclick: async () => {
            const r = await post("/api/ui/incidents/new/create", { alert: a.id }); location.hash = "#/incidents/" + r.id;
          } }, icon("stack-2"), t("newIncident")) : null)),
    box));
}

async function hostView(id) {
  const d = await api("/api/ui/agents/" + encodeURIComponent(id));
  const a = d.agent;
  const action = (name, body) => async () => { await post("/api/ui/agents/" + a.id + "/" + name, body || {}); render(); };
  const portRows = d.ports.map((p) => h("tr", null,
    h("td", { class: "mono" }, p.proto + "/" + p.port),
    h("td", { class: "mono" }, p.addr),
    h("td", null, p.scope),
    h("td", null, p.via),
    h("td", { class: "mono" }, p.process || p.target || ""),
    h("td", null, p.expected ? h("span", { class: "pill" }, t("expected"))
      : h("div", { class: "flex" },
        h("button", { class: "btn small", onclick: action("accept-port", { key: p.key }) }, t("accept")),
        p.proc_key ? h("button", { class: "btn small ghost", title: p.proc_key, onclick: action("accept-port", { key: p.proc_key }) }, t("acceptProcess")) : null))));
  const loginRows = d.logins.map((r) => h("tr", null,
    h("td", { class: "nowrap" }, timeEl(r.event.ts)),
    h("td", null, r.event.data.user),
    h("td", { class: "mono" }, r.event.data.ip),
    h("td", null, r.event.data.method),
    h("td", { class: "mono" }, r.event.data.key_comment || r.event.data.fingerprint || "")));
  const renameInput = h("input", { value: a.name, maxlength: 100 });
  const minutesSel = h("select", null, [30, 60, 120, 240].map((m) => h("option", { value: m }, m + " " + t("minutes"))));

  mount(shell("overview",
    h("div", { class: "crumbs" }, h("a", { href: "#/" }, t("overview")), " / ", t("hosts")),
    h("h1", null, a.name),
    h("div", { class: "grid two" },
      h("div", { class: "card" },
        h("div", { class: "flex" }, statusChip(a.status)),
        h("dl", { class: "kv" },
          h("dt", null, "Hostname"), h("dd", null, a.hostname),
          h("dt", null, t("lastSeen")), h("dd", null, timeEl(a.last_seen)),
          h("dt", null, t("lastIP")), h("dd", { class: "mono" }, a.last_ip),
          h("dt", null, t("version")), h("dd", null, a.version || "·"),
          h("dt", null, t("enrolled")), h("dd", null, abs(a.enrolled)),
          h("dt", null, t("canaryRoots")), h("dd", { class: "mono" }, (a.canary_roots || []).join("  ") || t("none")),
          h("dt", null, t("configSync")), h("dd", null, t(a.config_sync ? "synced" : "waiting")))),
      h("div", { class: "card" },
        h("form", { class: "inline", onsubmit: async (e) => { e.preventDefault(); await post("/api/ui/agents/" + a.id + "/rename", { name: renameInput.value }); render(); } },
          h("label", null, t("rename"), renameInput), h("button", { class: "btn ghost", type: "submit" }, t("rename"))),
        a.maintenance_until
          ? h("div", { class: "flex mt" }, h("span", { class: "chip" }, h("span", { class: "dot stopped" }), t("maintenanceUntil") + " " + abs(a.maintenance_until)),
            h("button", { class: "btn small ghost", onclick: action("maintenance", { minutes: 0 }) }, t("end")))
          : h("form", { class: "inline mt", onsubmit: async (e) => { e.preventDefault(); await post("/api/ui/agents/" + a.id + "/maintenance", { minutes: Number(minutesSel.value) }); render(); } },
            h("label", null, t("maintenance"), minutesSel), h("button", { class: "btn ghost", type: "submit" }, t("start"))),
        h("div", { class: "actions" },
          h("a", { class: "btn ghost", href: "#/events?agent=" + a.id }, t("events")),
          h("a", { class: "btn ghost", href: "#/alerts" }, t("alerts")),
          h("button", { class: "btn danger", onclick: async () => { if (confirm(t("confirmDelete"))) { await post("/api/ui/agents/" + a.id + "/delete"); location.hash = "#/"; } } }, t("deleteHost"))))),
    h("div", { class: "flex" }, h("h2", null, t("ports")),
      d.ports.some((p) => !p.expected) ? h("button", { class: "btn small right", onclick: action("accept-port", { key: "*" }) }, t("acceptAll")) : null),
    h("div", { class: "tablewrap" }, h("table", { class: "nowrap" },
      h("thead", null, h("tr", null, ["Port", "Addr", t("scope"), t("via"), t("process"), ""].map((x) => h("th", null, x)))),
      h("tbody", null, portRows))),
    h("h2", null, t("logins")),
    d.logins.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, [t("time"), t("user"), t("ip"), t("method"), t("key")].map((x) => h("th", null, x)))),
      h("tbody", null, loginRows))) : h("div", { class: "card empty" }, t("noEvents"))));
}

async function eventsView(params) {
  const agents = (await api("/api/ui/overview")).agents;
  const agent = params.get("agent") || "";
  const type = params.get("type") || "";
  const tbody = h("tbody");
  let before = 0;
  const more = h("button", { class: "btn ghost mt" }, t("loadMore"));
  async function load() {
    const q = new URLSearchParams({ agent, type, limit: "200" });
    if (before) q.set("before", before);
    const rows = await api("/api/ui/events?" + q);
    for (const r of rows) {
      tbody.append(h("tr", null,
        h("td", { class: "nowrap" }, h("span", { title: abs(r.event.ts) }, new Date(r.event.ts).toLocaleString(lang))),
        h("td", null, r.host || r.source + (r.actor ? ":" + r.actor : "")),
        h("td", { class: "mono" }, r.event.type),
        h("td", { class: "mono" }, summary(r.event.data))));
      before = r.seq;
    }
    more.hidden = rows.length < 200;
  }
  more.addEventListener("click", load);
  const hostSel = h("select", { name: "agent" }, h("option", { value: "" }, t("allHosts")),
    agents.map((a) => h("option", { value: a.id, selected: a.id === agent }, a.name)));
  const typeIn = h("input", { name: "type", value: type, placeholder: "ssh. / file. / canary." });
  const form = h("form", { class: "inline", onsubmit: (e) => {
    e.preventDefault();
    location.hash = "#/events?" + new URLSearchParams({ agent: hostSel.value, type: typeIn.value.trim() });
  } }, h("label", null, t("host"), hostSel), h("label", null, t("filterType"), typeIn), h("button", { class: "btn", type: "submit" }, "OK"));
  const scopeLine = [(agents.find((a) => a.id === agent) || {}).name || t("allHosts"), type].filter(Boolean).join(", ");
  mount(shell("events", h("h1", null, t("events")), h("div", { class: "crumbs" }, scopeLine), h("div", { class: "card" }, form), h("div", { class: "tablewrap mt" },
    h("table", null, h("thead", null, h("tr", null, [t("time"), t("host"), t("type"), t("details")].map((x) => h("th", null, x)))), tbody)), more));
  await load();
}

async function canariesView() {
  const [{ canaries, types }, o] = await Promise.all([api("/api/ui/canaries"), api("/api/ui/overview")]);
  const err = h("div", { class: "err" });
  const agentSel = h("select", { name: "agent_id", required: true }, o.agents.map((a) => h("option", { value: a.id }, a.name)));
  const typeSel = h("select", { name: "type" }, types.map((x) => h("option", { value: x }, x)));
  const pathIn = h("input", { name: "path", required: true, placeholder: "/…", class: "mono" });
  const roots = h("div", { class: "muted mono" });
  const showRoots = () => {
    const a = o.agents.find((x) => x.id === agentSel.value);
    roots.textContent = t("canaryRoots") + ": " + ((a && a.canary_roots && a.canary_roots.join("  ")) || t("none"));
  };
  agentSel.addEventListener("change", showRoots);
  showRoots();
  const form = h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault();
    const f = new FormData(form);
    err.textContent = "";
    try {
      await post("/api/ui/canaries", { agent_id: f.get("agent_id"), type: f.get("type"), path: f.get("path").trim(),
        params: { domain: f.get("domain"), email: f.get("email"), comment: f.get("comment") } });
      render();
    } catch (x) { err.textContent = x.message; }
  } },
    h("div", { class: "grid two" }, h("label", null, t("host"), agentSel), h("label", null, t("type"), typeSel)),
    h("label", null, t("path"), pathIn), roots,
    h("div", { class: "grid tiles" },
      h("label", null, t("domain"), h("input", { name: "domain" })),
      h("label", null, t("email"), h("input", { name: "email", type: "email" })),
      h("label", null, t("comment"), h("input", { name: "comment" }))),
    err, h("div", null, h("button", { class: "btn", type: "submit", disabled: !o.agents.length }, t("place"))));

  const rows = canaries.map((c) => h("div", { class: "row" },
    statusChip(c.status),
    h("div", null,
      h("div", { class: "title mono" }, c.path),
      h("div", { class: "sub" }, [c.host, c.type].join("  ·  ")),
      c.error ? h("div", { class: "sub warn" }, c.error) : null),
    h("div", { class: "meta" },
      c.triggers ? h("span", { class: "chip" }, h("span", { class: "dot critical" }), t("triggers") + " " + c.triggers + " · ", timeEl(c.last_triggered)) : null,
      h("button", { class: "btn small ghost", onclick: async () => {
        if (!confirm(t("confirmCanary"))) return;
        await post("/api/ui/canaries/" + c.id + "/delete"); render();
      } }, t("remove")))));

  mount(shell("canaries", h("h1", null, t("canaries")), h("div", { class: "crumbs" }, canaries.length + " " + t("placed")),
    h("div", { class: "page-actions" }, h("button", { class: "btn", onclick: () => pathIn.focus() }, icon("plus"), t("place"))),
    h("div", { class: "card" }, form),
    h("h2", null, t("canaries")),
    h("div", { class: "list" }, rows.length ? rows : h("div", { class: "empty" }, t("noCanaries")))));
}

let incTab = "active";
const incRow = (c) => h("a", { class: "row", href: "#/incidents/" + c.id },
  sevChip(c.severity),
  h("div", null, h("div", { class: "title" }, c.title || c.id),
    h("div", { class: "sub" }, [c.host, c.count + " " + t("alertsN"), t("owner") + ": " + (c.owner || t("unowned"))].join("  ·  "))),
  h("div", { class: "meta" }, incChip(c.status), timeEl(c.last)));

async function incidentsView() {
  const r = await api("/api/ui/incidents?status=" + (incTab === "all" ? "" : incTab));
  const tabs = h("div", { class: "tabs" }, [["active", t("activeInc")], ["closed", t("closed")], ["all", t("all")]].map(([k, l]) =>
    h("button", { class: k === incTab ? "on" : null, onclick: () => { incTab = k; render(); } }, l)));
  mount(shell("incidents", h("h1", null, t("incidents")),
    h("div", { class: "crumbs" }, r.incidents.length + " " + (incTab === "all" ? t("incidents") : (incTab === "active" ? t("activeInc") : t("closed")).toLowerCase())
      + (r.mttc_seconds != null ? "  ·  " + t("mttc") + " " + duration(r.mttc_seconds) : "")),
    tabs, h("div", { class: "list" }, r.incidents.length ? r.incidents.map(incRow) : h("div", { class: "empty" }, t("noIncidents")))));
}

async function incidentDetail(id) {
  const d = await api("/api/ui/incidents/" + encodeURIComponent(id));
  const c = d.incident;
  const act = (action, body) => async () => { await post("/api/ui/incidents/" + c.id + "/" + action, body || {}); render(); };
  const note = h("textarea", { rows: 3, maxlength: 4000, required: true });
  // timeline: alerts and raw events in time order, the session's login first
  const items = [
    ...d.alerts.map((a) => ({ ts: a.created, kind: "alert", a })),
    ...d.events.map((e) => ({ ts: e.event.ts, kind: "event", e })),
  ].sort((x, y) => new Date(x.ts) - new Date(y.ts));
  const tl = h("div", { class: "timeline" },
    d.login ? h("div", { class: "tl-item tl-login" }, h("span", { class: "tl-time" }, abs(d.login.event.ts)),
      h("div", null, h("div", { class: "strong" }, t("startedBy") + " " + d.login.event.data.user),
        h("div", { class: "mono muted" }, summary(d.login.event.data)))) : null,
    items.map((it) => it.kind === "alert"
      ? h("a", { class: "tl-item alert " + it.a.severity, href: "#/alerts/" + it.a.id }, h("span", { class: "tl-time" }, abs(it.ts)),
        h("div", null, h("div", { class: "flex nowrap-flex" }, sevChip(it.a.severity), h("span", { class: "feed-title" }, it.a.title)),
          h("div", { class: "mono muted" }, it.a.rule + (it.a.technique ? "  ·  " + it.a.technique : ""))))
      : h("div", { class: "tl-item" }, h("span", { class: "tl-time" }, abs(it.ts)),
        h("div", null, h("span", { class: "mono" }, it.e.event.type), " ", h("span", { class: "mono muted" }, summary(it.e.event.data))))));
  mount(shell("incidents",
    h("div", { class: "crumbs" }, h("a", { href: "#/incidents" }, t("incidents")), " / " + c.id),
    h("h1", null, c.title || c.id),
    h("div", { class: "page-actions" }, c.owner !== me.user ? h("button", { class: "btn", onclick: act("assign") }, t("assignMe")) : null),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("dl", { class: "kv" },
        h("dt", null, t("status")), h("dd", null, incChip(c.status)),
        h("dt", null, t("severity")), h("dd", null, sevChip(c.severity)),
        h("dt", null, t("host")), h("dd", null, h("a", { href: "#/hosts/" + c.agent }, c.host || c.agent)),
        h("dt", null, t("owner")), h("dd", null, c.owner || t("unowned")),
        h("dt", null, t("created")), h("dd", null, abs(c.created)),
        h("dt", null, t("updated")), h("dd", null, abs(c.last)),
        h("dt", null, t("alerts")), h("dd", null, c.count + (c.open_alerts ? " (" + c.open_alerts + " " + t("open").toLowerCase() + ")" : ""))),
        h("div", { class: "actions" }, h("span", { class: "muted" }, t("setStatus")),
          h("div", { class: "tabs" }, ["open", "investigating", "contained", "closed"].map((st) =>
            h("button", { class: st === c.status ? "on" : null, onclick: act("status", { status: st }) }, t(st === "open" ? "openInc" : st)))))),
      h("div", { class: "card" }, h("h3", null, t("notes")),
        h("div", { class: "notes" }, (c.notes || []).map((n) => h("div", { class: "note" },
          h("div", { class: "note-head" }, h("span", { class: "strong" }, n.by), " ", h("span", { class: "muted" }, abs(n.at))),
          h("div", { class: "note-text" }, n.text)))),
        h("form", { class: "stack mt", onsubmit: async (e) => { e.preventDefault(); await act("note", { note: note.value })(); } },
          note, h("div", null, h("button", { class: "btn ghost", type: "submit" }, t("addNote")))))),
    h("h2", null, t("timeline")), h("div", { class: "card" }, tl)));
}

async function rulesView() {
  const r = await api("/api/ui/rules");
  const technique = (x) => x ? h("a", { href: "https://attack.mitre.org/techniques/" + x.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", class: "mono" }, x) : "·";
  const table = (list, custom) => h("div", { class: "tablewrap" }, h("table", { class: "rules" },
    h("thead", null, h("tr", null, [t("severity"), t("rule"), "ATT&CK", t("title"), custom ? t("file") : ""].map((x) => h("th", null, x)))),
    h("tbody", null, list.map((x) => h("tr", null,
      h("td", null, sevChip(x.Severity)), h("td", { class: "mono nowrap" }, x.ID), h("td", { class: "nowrap" }, technique(x.Technique)),
      h("td", null, h("div", null, x.Title), x.Trigger ? h("div", { class: "muted small-text" }, x.Trigger) : null),
      h("td", { class: "muted mono" }, custom ? x.File : (r.suppressible[x.ID] ? "" : h("span", { class: "pill", title: t("suppress") }, icon("bell-off"))) ))))));
  mount(shell("rules", h("h1", null, t("rules")),
    h("div", { class: "crumbs" }, r.builtin.length + " " + t("builtin") + ", " + (r.custom || []).length + " " + t("customShort")),
    h("h2", null, t("customRules")),
    r.errors && r.errors.length ? h("div", { class: "card err-box" }, h("h3", null, t("ruleErrors")), r.errors.map((e) => h("div", { class: "mono" }, e))) : null,
    (r.custom || []).length ? table(r.custom, true) : h("div", { class: "card empty" }, t("noCustom")),
    h("h2", null, t("builtinRules")), table(r.builtin, false)));
}

async function suppressionsView() {
  const list = await api("/api/ui/suppressions");
  const act = (sp, action, ask) => async () => {
    if (ask && !confirm(ask)) return;
    await post("/api/ui/suppressions/" + sp.id + "/" + action, { days: 30 }); render();
  };
  const row = (sp) => h("div", { class: "row" + (sp.active ? "" : " faded") },
    h("span", { class: "chip" }, h("span", { class: "dot " + (sp.active ? "ok" : "pending") }), sp.active ? t("active") : t("expired")),
    h("div", null,
      h("div", { class: "title" }, h("span", { class: "mono" }, sp.rule), "  ", h("span", { class: "muted" }, sp.host || t("allHostsLbl"))),
      Object.keys(sp.match || {}).length ? h("div", { class: "sub mono" }, Object.entries(sp.match).map(([k, v]) => k + " = " + v).join("  ·  ")) : null,
      h("div", { class: "sub" }, sp.reason + "  ·  " + sp.by)),
    h("div", { class: "meta" },
      h("span", null, t("hits") + " " + sp.hits),
      h("span", { title: abs(sp.expires) }, (sp.active ? t("expires") + " " : t("expired") + " ") + abs(sp.expires).split(",")[0]),
      h("button", { class: "btn small ghost", onclick: act(sp, "renew") }, t("renew")),
      h("button", { class: "btn small ghost", onclick: act(sp, "delete", t("confirmSuppressionDelete")) }, t("remove"))));
  const active = list.filter((x) => x.active).length;
  mount(shell("suppressions", h("h1", null, t("suppressions")), h("div", { class: "crumbs" }, active + " " + t("activeCount")),
    h("div", { class: "list" }, list.length ? list.map(row) : h("div", { class: "empty" }, t("noSuppressions")))));
}

async function settingsView() {
  const chain = await api("/api/ui/chain");
  const tokenBox = h("div");
  const notifyOut = h("span", { class: "muted" });
  const chainBox = h("div");
  const drawChain = (c) => chainBox.replaceChildren(h("dl", { class: "kv" },
    h("dt", null, t("status")), h("dd", null, h("span", { class: "chip" }, h("span", { class: "dot " + (c.ok ? "ok" : "broken") }), t(c.ok ? "chainOK" : "chainBroken"))),
    c.error ? [h("dt", null, "Error"), h("dd", { class: "mono" }, c.error)] : null,
    h("dt", null, t("records")), h("dd", null, c.seq.toLocaleString(lang)),
    h("dt", null, t("head")), h("dd", { class: "mono" }, c.head || "·"),
    h("dt", null, t("verify")), h("dd", null, abs(c.verified_at))));
  drawChain(chain);

  const langTabs = h("div", { class: "tabs" }, [["de", "Deutsch"], ["en", "English"]].map(([k, name]) =>
    h("button", { class: k === lang ? "on" : null, onclick: () => setLang(k) }, name)));
  mount(shell("settings", h("h1", null, t("settings")), h("div", { class: "crumbs" }, "vigil " + me.version),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("h3", null, t("enroll")),
        h("button", { class: "btn", onclick: async () => {
          const r = await post("/api/ui/tokens");
          tokenBox.replaceChildren(
            h("div", { class: "secret mt" }, "vigil-agent enroll -server " + (me.agent_url || location.origin) + " -token " + r.token),
            h("div", { class: "muted mt" }, t("validUntil") + " " + abs(r.expires)));
        } }, t("newToken")), tokenBox),
      h("div", { class: "card" }, h("h3", null, t("chain")), chainBox,
        h("div", { class: "actions" },
          h("button", { class: "btn ghost", onclick: async () => drawChain(await post("/api/ui/chain/verify")) }, t("verify"))))),
    h("div", { class: "card mt" }, h("div", { class: "flex" },
      h("button", { class: "btn ghost", onclick: async () => { const r = await post("/api/ui/notify/test"); notifyOut.textContent = t("sent") + " (" + r.notifiers + ")"; } }, t("notifyTest")),
      notifyOut)),
    h("div", { class: "card mt" }, h("h3", null, t("theme")), h("div", { class: "tabs" }, ["light", "dark", "system"].map((k) =>
      h("button", { class: k === theme() ? "on" : null, onclick: () => setTheme(k) }, t(k))))),
    h("div", { class: "card mt" }, h("h3", null, t("language")), h("div", { class: "flex" }, langTabs,
      h("button", { class: "btn ghost right", onclick: logout }, icon("logout"), t("logout"))))));
}

// ---------- router ----------

let refreshTimer = null;
async function render() {
  clearTimeout(refreshTimer);
  if (!me) {
    try { me = await api("/api/ui/me"); } catch { me = null; }
    if (!me) return loginView();
  }
  const [path, query] = (location.hash.slice(1) || "/").split("?");
  const params = new URLSearchParams(query || "");
  const parts = path.split("/").filter(Boolean);
  try {
    if (parts[0] === "alerts" && parts[1]) await alertDetail(parts[1]);
    else if (parts[0] === "alerts") await alertsView();
    else if (parts[0] === "hosts" && parts[1]) await hostView(parts[1]);
    else if (parts[0] === "events") await eventsView(params);
    else if (parts[0] === "canaries") await canariesView();
    else if (parts[0] === "suppressions") await suppressionsView();
    else if (parts[0] === "rules") await rulesView();
    else if (parts[0] === "incidents" && parts[1]) await incidentDetail(parts[1]);
    else if (parts[0] === "incidents") await incidentsView();
    else if (parts[0] === "settings") await settingsView();
    else await overview();
  } catch (x) {
    if (x.message !== "unauthorized") mount(shell("", h("div", { class: "card err" }, x.message)));
  }
  // The overview and alert list refresh themselves; forms are left alone.
  if (!parts.length || (parts[0] === "alerts" && !parts[1])) refreshTimer = setTimeout(render, 30000);
}

window.addEventListener("hashchange", render);
render();
