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
    active: "active", tampered: "tampered", error: "error",
    maintenance: "Maintenance", maintenanceUntil: "Maintenance until", start: "Start", end: "End", minutes: "min",
    acceptProcess: "Allow process",
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
    active: "aktiv", tampered: "manipuliert", error: "Fehler",
    maintenance: "Wartung", maintenanceUntil: "Wartung bis", start: "Starten", end: "Beenden", minutes: "Min.",
    acceptProcess: "Prozess erlauben",
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
  for (const kid of kids.flat()) {
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

const sevChip = (sev) => h("span", { class: "chip" }, h("span", { class: "dot " + sev }), t(sev));
const statusChip = (st) => h("span", { class: "chip" }, h("span", { class: "dot " + st }), t(st) || st);

function summary(data) {
  if (!data) return "";
  return Object.entries(data)
    .filter(([k]) => k !== "ports")
    .map(([k, v]) => k + "=" + (typeof v === "object" ? JSON.stringify(v) : v))
    .join("  ");
}

// ---------- shell ----------

const routes = [
  ["overview", "#/"], ["alerts", "#/alerts"], ["events", "#/events"], ["canaries", "#/canaries"], ["settings", "#/settings"],
];

function shell(active, ...content) {
  const nav = h("nav", { class: "main" },
    routes.map(([k, href]) => h("a", { href, class: k === active ? "on" : null }, t(k))),
    h("button", { class: "linkbtn", onclick: () => { lang = lang === "de" ? "en" : "de"; store("vigil.lang", lang); render(); } }, lang === "de" ? "EN" : "DE"),
    h("button", { class: "linkbtn", onclick: async () => { await post("/api/ui/logout").catch(() => {}); me = null; render(); } }, t("logout")));
  return [
    h("header", { class: "top" }, h("div", { class: "wrap" },
      h("a", { class: "brand", href: "#/" }, h("img", { src: "favicon.svg", alt: "" }), "vigil"), nav)),
    h("main", null, h("div", { class: "wrap" }, ...content)),
  ];
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
    h("label", null, t("code"), h("input", { name: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: 6, required: true })),
    err,
    h("button", { class: "btn", type: "submit" }, t("login")));
  mount(h("div", { class: "login" }, h("h1", null, "vigil"), form));
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

async function overview() {
  const o = await api("/api/ui/overview");
  const online = o.agents.filter((a) => a.status === "online").length;
  const tiles = h("div", { class: "grid tiles" },
    h("div", { class: "card tile" }, h("div", { class: "num" }, online + " / " + o.agents.length),
      h("div", { class: "lbl" }, h("span", { class: "dot " + (online === o.agents.length ? "online" : "silent") }), t("hosts"))),
    SEVS.map((s) => h("a", { class: "card tile", href: "#/alerts" }, h("div", { class: "num" }, o.open_by_severity[s] || 0),
      h("div", { class: "lbl" }, h("span", { class: "dot " + s }), t(s)))),
    h("a", { class: "card tile", href: "#/canaries" }, h("div", { class: "num" }, o.canaries),
      h("div", { class: "lbl" }, h("span", { class: "dot " + (o.canaries_triggered ? "critical" : "online") }), t("canaries"),
        o.canaries_triggered ? " · " + o.canaries_triggered + " " + t("canariesOpened") : null)),
    h("a", { class: "card tile", href: "#/settings" }, h("div", { class: "num" }, o.chain.seq.toLocaleString(lang)),
      h("div", { class: "lbl" }, h("span", { class: "dot " + (o.chain.ok ? "ok" : "broken") }), t("chain") + " " + t(o.chain.ok ? "chainOK" : "chainBroken"))));

  const hosts = o.agents.length ? h("div", { class: "grid cards" }, o.agents.map((a) =>
    h("a", { class: "card", href: "#/hosts/" + a.id },
      h("div", { class: "flex" }, h("div", { class: "host-name" }, a.name), h("span", { class: "right" }, statusChip(a.status))),
      h("dl", { class: "kv" },
        h("dt", null, t("lastSeen")), h("dd", null, timeEl(a.last_seen)),
        h("dt", null, t("alertsOpen")), h("dd", null, a.open_alerts),
        h("dt", null, t("ports")), h("dd", null, a.ports),
        h("dt", null, t("canaries")), h("dd", null, a.canaries))))) : h("div", { class: "card empty" }, t("noHosts"));

  mount(shell("overview",
    h("h1", null, t("overview")),
    tiles,
    h("h2", null, t("hosts")), hosts,
    h("div", { class: "grid two mt" },
      barChart(t("eventsHour"), o.events_per_hour, o.hour_start),
      barChart(t("failedHour"), o.ssh_failed_per_hour, o.hour_start, true)),
    h("h2", null, t("alerts")),
    h("div", { class: "list" }, o.recent_alerts.length ? o.recent_alerts.map(alertRow) : h("div", { class: "empty" }, t("noAlerts")))));
}

let alertTab = "open";
async function alertsView() {
  const list = await api("/api/ui/alerts?status=" + (alertTab === "all" ? "" : alertTab));
  const tabs = h("div", { class: "tabs" }, ["open", "acked", "resolved", "all"].map((k) =>
    h("button", { class: k === alertTab ? "on" : null, onclick: () => { alertTab = k; render(); } }, t(k))));
  mount(shell("alerts", h("h1", null, t("alerts")), tabs,
    h("div", { class: "list" }, list.length ? list.map(alertRow) : h("div", { class: "empty" }, t("noAlerts")))));
}

async function alertDetail(id) {
  const all = await api("/api/ui/alerts");
  const a = all.find((x) => x.id === id);
  if (!a) { location.hash = "#/alerts"; return; }
  const params = (a.detail || "").split("\n").filter(Boolean).map((l) => l.split(/=(.*)/s));
  const act = (action) => async () => { await post("/api/ui/alerts/" + a.id + "/" + action); render(); };
  mount(shell("alerts",
    h("div", { class: "crumbs" }, h("a", { href: "#/alerts" }, t("alerts")), " / ", a.rule),
    h("h1", null, a.title),
    h("div", { class: "card" },
      h("dl", { class: "kv" },
        h("dt", null, t("status")), h("dd", null, t(a.status) + (a.by ? " · " + a.by : "")),
        h("dt", null, "Severity"), h("dd", null, sevChip(a.severity)),
        h("dt", null, t("host")), h("dd", null, a.agent ? h("a", { href: "#/hosts/" + a.agent }, a.host || a.agent) : "·"),
        h("dt", null, t("technique")), h("dd", null, a.technique ? h("a", { href: "https://attack.mitre.org/techniques/" + a.technique.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer" }, a.technique) : "·"),
        h("dt", null, t("count")), h("dd", null, a.count),
        h("dt", null, t("created")), h("dd", null, abs(a.created)),
        h("dt", null, t("updated")), h("dd", null, abs(a.updated)),
        params.map(([k, v]) => [h("dt", null, k), h("dd", { class: "mono" }, v || "·")])),
      h("div", { class: "actions" },
        a.status === "open" ? h("button", { class: "btn", onclick: act("ack") }, t("ack")) : null,
        a.status !== "resolved" ? h("button", { class: "btn ghost", onclick: act("resolve") }, t("resolve")) : null,
        a.status !== "open" ? h("button", { class: "btn ghost", onclick: act("reopen") }, t("reopen")) : null))));
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
  mount(shell("events", h("h1", null, t("events")), h("div", { class: "card" }, form), h("div", { class: "tablewrap mt" },
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

  mount(shell("canaries", h("h1", null, t("canaries")), h("div", { class: "card" }, form),
    h("h2", null, t("canaries")),
    h("div", { class: "list" }, rows.length ? rows : h("div", { class: "empty" }, t("noCanaries")))));
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

  mount(shell("settings", h("h1", null, t("settings")),
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
      notifyOut, h("span", { class: "right muted" }, me.user + " · vigil " + me.version)))));
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
