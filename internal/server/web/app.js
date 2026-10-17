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
    selftest: "Self test", runSelftest: "Run self test", noSelftests: "No self test yet.", selftestOff: "This agent does not offer self tests (older version, or selftest off in agent.json).",
    st_pending: "waiting for the agent", st_running: "running", st_passed: "passed", st_warning: "passed with warnings", st_failed: "failed",
    st_waiting: "waiting", st_ok: "detected", st_suppressed: "suppressed", st_skipped: "skipped", st_missing: "not detected", notifiedTo: "Sent to",
    notifiers: "Notifications", noNotifiers: "No notifier configured. Alerts only show up here.", delivered: "last delivered",
    neverDelivered: "nothing sent yet", failing: "failing", heartbeat: "Outside heartbeat", configured: "configured", notConfigured: "not configured",
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
    passkeyLogin: "Log in with a passkey", or: "or", passkeyCancelled: "Passkey cancelled", account: "Account", role: "Role",
    passkeys: "Passkeys", noPasskeys: "No passkey yet", addPasskey: "Add passkey", passkeyName: "Name (e.g. laptop)",
    totpCode: "Current code from your app", changePassword: "Change password", currentPassword: "Current password",
    newPassword: "New password (at least 12 characters)", repeatPassword: "Repeat new password", passwordsDiffer: "The passwords differ",
    saved: "saved", users: "Users", addUser: "Add user", name: "Name", created2: "Created", lastLogin: "Last login",
    codePrompt: "Current code from your authenticator app", newUserInfo: "Hand these over once, they are not shown again.",
    viewer: "viewer", analyst: "analyst", admin: "admin", noPasskeySupport: "This browser does not support passkeys",
    updates: "Updates", securityShort: "security", rebootShort: "reboot", upToDate: "up to date", pendingShort: "pending",
    kernel: "Kernel", unattended: "Automatic updates", listsAge: "Package lists", daysAgo: "days old", on: "on", off: "off",
    securityPackages: "Security updates", newestInstalled: "newest installed",
    response: "Response", notEnabled: "not enabled on this host (response in agent.json)", actBlock: "Block {ip} for 24 h",
    actSession: "End SSH session of {user}", actProcess: "Stop process {pid}", actKey: "Remove key {fingerprint}",
    requested: "requested, waiting for the agent", done: "done", failed: "failed", expiredAct: "expired", pendingAct: "pending",
    confirmAction: "Run this on the host?",
    actIsolate: "Isolate the host for {dur}", actRelease: "End isolation", actLock: "Lock account {user} for {dur}", actUnlock: "Unlock account {user}",
    awaitingApproval: "needs approval", rejectedAct: "rejected", approvedBy: "approved by", approve: "Approve", reject: "Reject",
    withdraw: "Withdraw", needsSecond: "a second admin has to approve", confirmApprove: "Approve and run this on the host?", confirmReject: "Reject this action?",
    containment: "Containment", isolatedUntil: "Isolated until", lockedUntil: "locked until", unlock: "Unlock", lockAccount: "Lock an account",
    pendingApprovals: "Actions waiting for approval",
    posture: "Hardening", checksOk: "{n} of {m} checks passed", checked: "checked",
    chk_ssh_root_login: "SSH root login with password", chk_ssh_password: "SSH password login", chk_ssh_empty_password: "SSH empty passwords",
    chk_empty_password: "Accounts without password", chk_aslr: "Address space randomization", chk_sysctl: "Kernel setting",
    chk_permissions: "Permissions", chk_firewall: "Firewall", chk_mac: "AppArmor / SELinux",
    certs: "Certificates", expiresIn: "expires in", days: "days", expiredAgo: "expired {n} days ago", selfSigned: "self-signed",
    backups: "Backups", hoursOld: "h old", limit: "limit", bkMissing: "missing", bkOld: "too old", bkSmall: "too small",
    vulns: "Vulnerabilities", fixable: "fixable", unfixed: "no fix yet", exploitedNow: "Exploited in the wild", cve: "CVE",
    pkg: "Package", installed: "Installed", fixedIn: "Fixed in", noVulns: "No fixable vulnerability",
    vulnPending: "No data yet", proOnly: "Ubuntu Pro",
    timeline: "Timeline", window: "Window", earlier: "Earlier", later: "Later", anchor: "moment of the alert",
    allKinds: "All", kAuth: "Logins", kProc: "Processes", kFile: "Files", kNet: "Network", kKernel: "Kernel", kOther: "Other", kAlert: "Alerts",
    receivedLate: "received", truncatedRows: "Only the first {n} events are shown.", noTimeline: "Nothing recorded in this window",
    pivot: "Investigate", firstSeen: "First seen", lastSeenShort: "Last seen", seenOn: "Hosts", eventTypes: "Event types", total: "Events",
    publicAddr: "public address", privateAddr: "private address", onList: "on list", days30: "last {n} days",
    snapshots: "Evidence", takeSnapshot: "Secure evidence", snapshotAsked: "requested, the agent answers within a minute",
    noSnapshots: "No snapshot yet", trigger: "Trigger", suspect: "Suspect process", parents: "Parents", children: "Children",
    openFiles: "Open files", libraries: "Mapped files", envNames: "Environment (names only)", sockets: "Sockets",
    sessions: "Logged in", connections: "Connections", processes: "Processes", modules: "Kernel modules", journal: "Last journal lines",
    quarantined: "Quarantined copy", programHash: "Program SHA-256", gone: "Process had already exited",
    snapshotHash: "Snapshot SHA-256", requestStatus: "Request", changeLines: "Changed lines", prevUnknown: "Previous content unknown (first change since the upgrade)",
    causingEvents: "Events behind this alert", truncatedDiff: "shortened",
    sessions: "Sessions", hunt: "Hunt", search: "Search", query: "Query", searchHint: "type:process.* uid:0 exe:/tmp/*  -user:root  count:>10  \"two words\"",
    saveSearch: "Save", savedSearches: "Saved searches", searchName: "Name", exportCSV: "CSV", exportJSONL: "JSON lines", found: "{n} found, {ms} ms",
    huntHint: "Addresses, user names or SHA-256 hashes, one per line or separated by spaces. Searches the stored events of all hosts.",
    huntRun: "Search", notFound: "not seen", invalidValues: "Not an address, user or hash",
    started: "Start", ended: "End", duration: "Duration", commands: "Commands", sudoShort: "sudo", filesShort: "Files", stillOpen: "open",
    noSessions: "No SSH sessions in this period", sessionOf: "Session of {user}", dropped: "{n} more commands not recorded (limit per hour)",
    reportMD: "Report (Markdown)", reportPrint: "Report to print / PDF",
    activeRules: "rules active", otherSources: "for log sources without vigil events", notConfigured: "not set up", hashLists: "Malware hashes",
    forwarding: "Forwarding", sentShort: "sent", droppedShort: "dropped", queuedShort: "waiting",
    filesDuring: "changed while the session was open", partialScan: "stopped after 20 s, shorten the period",
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
    selftest: "Selbsttest", runSelftest: "Selbsttest starten", noSelftests: "Noch kein Selbsttest.", selftestOff: "Dieser Agent bietet keinen Selbsttest an (ältere Version oder selftest in agent.json aus).",
    st_pending: "wartet auf den Agenten", st_running: "läuft", st_passed: "bestanden", st_warning: "bestanden mit Hinweisen", st_failed: "fehlgeschlagen",
    st_waiting: "ausstehend", st_ok: "erkannt", st_suppressed: "unterdrückt", st_skipped: "übersprungen", st_missing: "nicht erkannt", notifiedTo: "Gesendet an",
    notifiers: "Benachrichtigungen", noNotifiers: "Keine Benachrichtigung eingerichtet. Alarme erscheinen nur hier.", delivered: "zuletzt zugestellt",
    neverDelivered: "noch nichts gesendet", failing: "fehlerhaft", heartbeat: "Herzschlag nach außen", configured: "eingerichtet", notConfigured: "nicht eingerichtet",
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
    passkeyLogin: "Mit Passkey anmelden", or: "oder", passkeyCancelled: "Passkey abgebrochen", account: "Konto", role: "Rolle",
    passkeys: "Passkeys", noPasskeys: "Noch kein Passkey", addPasskey: "Passkey hinzufügen", passkeyName: "Name (z. B. Laptop)",
    totpCode: "Aktueller Code aus der App", changePassword: "Passwort ändern", currentPassword: "Aktuelles Passwort",
    newPassword: "Neues Passwort (mindestens 12 Zeichen)", repeatPassword: "Neues Passwort wiederholen", passwordsDiffer: "Die Passwörter sind verschieden",
    saved: "gespeichert", users: "Benutzer", addUser: "Benutzer anlegen", name: "Name", created2: "Angelegt", lastLogin: "Letzte Anmeldung",
    codePrompt: "Aktueller Code aus deiner Authenticator-App", newUserInfo: "Einmal weitergeben, das wird nicht noch einmal angezeigt.",
    viewer: "Lesen", analyst: "Analyst", admin: "Admin", noPasskeySupport: "Dieser Browser kann keine Passkeys",
    updates: "Updates", securityShort: "Sicherheit", rebootShort: "Neustart", upToDate: "aktuell", pendingShort: "offen",
    kernel: "Kernel", unattended: "Automatische Updates", listsAge: "Paketlisten", daysAgo: "Tage alt", on: "an", off: "aus",
    securityPackages: "Sicherheitsupdates", newestInstalled: "neuester installiert",
    response: "Gegenmaßnahmen", notEnabled: "auf diesem Host nicht freigeschaltet (response in agent.json)", actBlock: "{ip} für 24 Std. sperren",
    actSession: "SSH-Sitzung von {user} beenden", actProcess: "Prozess {pid} beenden", actKey: "Schlüssel {fingerprint} entfernen",
    requested: "angefordert, wartet auf den Agent", done: "erledigt", failed: "fehlgeschlagen", expiredAct: "abgelaufen", pendingAct: "wartet",
    confirmAction: "Das auf dem Host ausführen?",
    actIsolate: "Host für {dur} isolieren", actRelease: "Isolation beenden", actLock: "Konto {user} für {dur} sperren", actUnlock: "Konto {user} entsperren",
    awaitingApproval: "Freigabe offen", rejectedAct: "abgelehnt", approvedBy: "freigegeben von", approve: "Freigeben", reject: "Ablehnen",
    withdraw: "Zurückziehen", needsSecond: "ein zweiter Admin muss freigeben", confirmApprove: "Freigeben und auf dem Host ausführen?", confirmReject: "Diese Maßnahme ablehnen?",
    containment: "Eindämmung", isolatedUntil: "Isoliert bis", lockedUntil: "gesperrt bis", unlock: "Entsperren", lockAccount: "Konto sperren",
    pendingApprovals: "Maßnahmen warten auf Freigabe",
    posture: "Härtung", checksOk: "{n} von {m} Prüfungen bestanden", checked: "geprüft",
    chk_ssh_root_login: "SSH-Root-Login mit Passwort", chk_ssh_password: "SSH-Passwort-Login", chk_ssh_empty_password: "SSH mit leeren Passwörtern",
    chk_empty_password: "Konten ohne Passwort", chk_aslr: "Adressraum-Randomisierung", chk_sysctl: "Kernel-Einstellung",
    chk_permissions: "Dateirechte", chk_firewall: "Firewall", chk_mac: "AppArmor / SELinux",
    certs: "Zertifikate", expiresIn: "läuft ab in", days: "Tagen", expiredAgo: "seit {n} Tagen abgelaufen", selfSigned: "selbst signiert",
    backups: "Backups", hoursOld: "Std. alt", limit: "Grenze", bkMissing: "fehlt", bkOld: "zu alt", bkSmall: "zu klein",
    vulns: "Schwachstellen", fixable: "behebbar", unfixed: "noch ohne Fix", exploitedNow: "Aktiv ausgenutzt", cve: "CVE",
    pkg: "Paket", installed: "Installiert", fixedIn: "Behoben in", noVulns: "Keine behebbare Schwachstelle",
    vulnPending: "Noch keine Daten", proOnly: "Ubuntu Pro",
    timeline: "Zeitachse", window: "Zeitraum", earlier: "Früher", later: "Später", anchor: "Zeitpunkt des Alarms",
    allKinds: "Alle", kAuth: "Anmeldungen", kProc: "Prozesse", kFile: "Dateien", kNet: "Netzwerk", kKernel: "Kernel", kOther: "Sonstiges", kAlert: "Alarme",
    receivedLate: "empfangen", truncatedRows: "Nur die ersten {n} Ereignisse werden gezeigt.", noTimeline: "In diesem Zeitraum wurde nichts aufgezeichnet",
    pivot: "Untersuchen", firstSeen: "Zuerst gesehen", lastSeenShort: "Zuletzt gesehen", seenOn: "Hosts", eventTypes: "Ereignistypen", total: "Ereignisse",
    publicAddr: "öffentliche Adresse", privateAddr: "private Adresse", onList: "auf Liste", days30: "letzte {n} Tage",
    snapshots: "Spuren", takeSnapshot: "Spuren sichern", snapshotAsked: "angefordert, der Agent antwortet innerhalb einer Minute",
    noSnapshots: "Noch keine Sicherung", trigger: "Auslöser", suspect: "Verdächtiger Prozess", parents: "Eltern", children: "Kinder",
    openFiles: "Offene Dateien", libraries: "Eingeblendete Dateien", envNames: "Umgebung (nur Namen)", sockets: "Sockets",
    sessions: "Angemeldet", connections: "Verbindungen", processes: "Prozesse", modules: "Kernelmodule", journal: "Letzte Journal-Zeilen",
    quarantined: "Kopie in Quarantäne", programHash: "Programm-SHA-256", gone: "Prozess war schon beendet",
    snapshotHash: "SHA-256 der Sicherung", requestStatus: "Anforderung", changeLines: "Geänderte Zeilen", prevUnknown: "Vorheriger Inhalt unbekannt (erste Änderung seit dem Update)",
    causingEvents: "Ereignisse hinter diesem Alarm", truncatedDiff: "gekürzt",
    sessions: "Sitzungen", hunt: "Fahndung", search: "Suche", query: "Abfrage", searchHint: "type:process.* uid:0 exe:/tmp/*  -user:root  count:>10  \"zwei Wörter\"",
    saveSearch: "Speichern", savedSearches: "Gespeicherte Suchen", searchName: "Name", exportCSV: "CSV", exportJSONL: "JSON-Zeilen", found: "{n} gefunden, {ms} ms",
    huntHint: "Adressen, Benutzernamen oder SHA-256-Hashes, je Zeile oder mit Leerzeichen getrennt. Durchsucht die gespeicherten Ereignisse aller Hosts.",
    huntRun: "Suchen", notFound: "nicht gesehen", invalidValues: "Keine Adresse, kein Benutzer, kein Hash",
    started: "Beginn", ended: "Ende", duration: "Dauer", commands: "Befehle", sudoShort: "sudo", filesShort: "Dateien", stillOpen: "offen",
    noSessions: "Keine SSH-Sitzungen in diesem Zeitraum", sessionOf: "Sitzung von {user}", dropped: "{n} weitere Befehle nicht aufgezeichnet (Grenze pro Stunde)",
    reportMD: "Bericht (Markdown)", reportPrint: "Bericht drucken / PDF",
    activeRules: "Regeln aktiv", otherSources: "für Quellen ohne vigil-Ereignisse", notConfigured: "nicht eingerichtet", hashLists: "Schadsoftware-Hashes",
    forwarding: "Weiterleitung", sentShort: "gesendet", droppedShort: "verworfen", queuedShort: "wartend",
    filesDuring: "geändert, während die Sitzung offen war", partialScan: "nach 20 s abgebrochen, Zeitraum verkürzen",
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
const RANK = { viewer: 1, analyst: 2, admin: 3 };
const can = (role) => me && (RANK[me.role] || 3) >= RANK[role];
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const toB64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// QR code from the server's module rows, always dark on light so phones scan it
function qrSVG(rows) {
  const n = rows.length, q = 4;
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", `0 0 ${n + 2 * q} ${n + 2 * q}`);
  svg.setAttribute("class", "qr");
  const bg = document.createElementNS(SVG, "rect");
  bg.setAttribute("width", n + 2 * q); bg.setAttribute("height", n + 2 * q); bg.setAttribute("fill", "#fff");
  let d = "";
  rows.forEach((row, y) => { for (let x = 0; x < row.length; x++) if (row[x] === "1") d += `M${x + q} ${y + q}h1v1h-1z`; });
  const p = document.createElementNS(SVG, "path");
  p.setAttribute("d", d); p.setAttribute("fill", "#000");
  svg.append(bg, p);
  return svg;
}

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
const ICONS = {"terminal-2": ["M8 9l3 3l-3 3", "M13 15l3 0", "M3 4m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z"], "radar": ["M21 12h-8a1 1 0 1 0 -1 1v8a9 9 0 0 0 9 -9", "M16 9a5 5 0 1 0 -7 7", "M20.486 9a9 9 0 1 0 -11.482 11.495"], "key": ["M16.555 3.843l3.602 3.602a2.877 2.877 0 0 1 0 4.069l-2.643 2.643a2.877 2.877 0 0 1 -4.069 0l-.301 -.301l-6.558 6.558a2 2 0 0 1 -1.239 .578l-.175 .008h-1.172a1 1 0 0 1 -.993 -.883l-.007 -.117v-1.172a2 2 0 0 1 .467 -1.284l.119 -.13l.414 -.414h2v-2h2v-2l2.144 -2.144l-.301 -.301a2.877 2.877 0 0 1 0 -4.069l2.643 -2.643a2.877 2.877 0 0 1 4.069 0z", "M15 9h.01"], "book": ["M3 19a9 9 0 0 1 9 0a9 9 0 0 1 9 0", "M3 6a9 9 0 0 1 9 0a9 9 0 0 1 9 0", "M3 6l0 13", "M12 6l0 13", "M21 6l0 13"], "stack-2": ["M12 4l-8 4l8 4l8 -4l-8 -4", "M4 12l8 4l8 -4", "M4 16l8 4l8 -4"], "bell-off": ["M9.346 5.353c.21 -.129 .428 -.246 .654 -.353a2 2 0 1 1 4 0a7 7 0 0 1 4 6v3m-1 3h-13a4 4 0 0 0 2 -3v-3a6.996 6.996 0 0 1 1.273 -3.707", "M9 17v1a3 3 0 0 0 6 0v-1", "M3 3l18 18"], "clock": ["M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0", "M12 7v5l3 3"], "user-x": ["M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0", "M6 21v-2a4 4 0 0 1 4 -4h3.5", "M22 22l-5 -5", "M17 22l5 -5"], "plus": ["M12 5l0 14", "M5 12l14 0"], "alert-triangle": ["M12 9v4", "M10.363 3.591l-8.106 13.534a1.914 1.914 0 0 0 1.636 2.871h16.214a1.914 1.914 0 0 0 1.636 -2.87l-8.106 -13.536a1.914 1.914 0 0 0 -3.274 0z", "M12 16h.01"], "fish-hook": ["M16 9v6a5 5 0 0 1 -10 0v-4l3 3", "M16 7m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M16 5v-2"], "layout-dashboard": ["M5 4h4a1 1 0 0 1 1 1v6a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-6a1 1 0 0 1 1 -1", "M5 16h4a1 1 0 0 1 1 1v2a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-2a1 1 0 0 1 1 -1", "M15 12h4a1 1 0 0 1 1 1v6a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-6a1 1 0 0 1 1 -1", "M15 4h4a1 1 0 0 1 1 1v2a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-2a1 1 0 0 1 1 -1"], "list-details": ["M13 5h8", "M13 9h5", "M13 15h8", "M13 19h5", "M3 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z", "M3 14m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"], "logout": ["M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2", "M9 12h12l-3 -3", "M18 15l3 -3"], "server": ["M3 4m0 3a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z", "M3 12m0 3a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z", "M7 8l0 .01", "M7 16l0 .01"], "settings": ["M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065z", "M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"], "shield-check": ["M11.46 20.846a12 12 0 0 1 -7.96 -14.846a12 12 0 0 0 8.5 -3a12 12 0 0 0 8.5 3a12 12 0 0 1 -.09 7.06", "M15 19l2 2l4 -4"]};

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
  ["sectionDetect", [["incidents", "#/incidents", "stack-2"], ["alerts", "#/alerts", "alert-triangle"], ["events", "#/events", "list-details"], ["sessions", "#/sessions", "terminal-2"], ["hunt", "#/hunt", "radar"], ["canaries", "#/canaries", "fish-hook"],
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
  const passkey = window.PublicKeyCredential ? [h("div", { class: "divider" }, h("span", null, t("or"))),
    h("button", { class: "btn ghost wide", type: "button", onclick: async () => {
      err.textContent = "";
      try {
        const b = await post("/api/ui/passkey/begin");
        const cred = await navigator.credentials.get({ publicKey: { challenge: fromB64u(b.challenge), rpId: b.rp_id, userVerification: "required", timeout: 60000 } });
        me = await post("/api/ui/passkey/finish", { token: b.token, id: cred.id, clientData: toB64u(cred.response.clientDataJSON),
          authenticatorData: toB64u(cred.response.authenticatorData), signature: toB64u(cred.response.signature) });
        render();
      } catch (x) { err.textContent = x.name === "NotAllowedError" ? t("passkeyCancelled") : x.message; }
    } }, icon("key"), t("passkeyLogin"))] : null;
  document.title = brandName;
  mount(h("div", { class: "login-wrap" }, h("div", { class: "login" },
    logo(), h("div", { class: "login-title" }, t("login")), h("div", { class: "login-sub" }, t("loginSub")), form, passkey)));
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
  execution: "Execution", "command-and-control": "Command and Control", reconnaissance: "Reconnaissance",
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

function updatesCell(u) {
  if (!u) return h("span", { class: "muted" }, "·");
  const parts = [];
  if (u.security) parts.push(h("span", { class: "sev high" }, u.security + " " + t("securityShort")));
  if (u.reboot_required) parts.push(h("span", { class: "sev medium" }, t("rebootShort")));
  if (!parts.length) parts.push(u.pending ? h("span", { class: "muted" }, u.pending + " " + t("pendingShort"))
    : h("span", { class: "chip" }, h("span", { class: "dot ok" }), t("upToDate")));
  return h("span", { class: "sevcounts" }, parts);
}

function postureSection(a) {
  const p = a.posture, v = a.vulns;
  if (!p && !v) return null;
  const out = [];
  if (p) {
    const checks = p.checks || [];
    const bad = checks.filter((c) => !c.ok);
    const names = [...new Set(checks.map((c) => c.check))];
    const failedNames = new Set(bad.map((c) => c.check));
    out.push(h("div", { class: "card mt" },
      h("div", { class: "flex" }, h("h3", null, t("posture")),
        h("span", { class: "chip right" }, h("span", { class: "dot " + (bad.length ? "high" : "ok") }),
          t("checksOk").replace("{n}", names.length - failedNames.size).replace("{m}", names.length))),
      h("dl", { class: "kv" }, names.map((n) => {
        const fails = bad.filter((c) => c.check === n);
        return [h("dt", null, t("chk_" + n)),
          h("dd", null, fails.length
            ? fails.map((c) => h("div", { class: "chip" }, h("span", { class: "dot high" }),
              h("span", { class: "mono" }, [c.key, c.value].filter(Boolean).join(": ") + (c.want ? " (" + c.want + ")" : ""))))
            : h("span", { class: "chip" }, h("span", { class: "dot ok" }), "ok"))];
      }))));
    const certs = p.certs || [];
    if (certs.length) out.push(h("div", { class: "card mt" }, h("h3", null, t("certs")),
      h("div", { class: "tablewrap" }, h("table", null, h("tbody", null, certs.map((c) => h("tr", null,
        h("td", null, h("span", { class: "dot " + (c.error || c.days < 0 ? "high" : c.days < 14 ? "medium" : "ok") })),
        h("td", null, c.subject || "·", c.self_signed ? h("span", { class: "muted" }, " · " + t("selfSigned")) : null),
        h("td", { class: "nowrap" }, c.error ? c.error : c.days < 0 ? t("expiredAgo").replace("{n}", -c.days) : t("expiresIn") + " " + c.days + " " + t("days")),
        h("td", { class: "mono muted" }, c.path))))))));
    const bks = p.backups || [];
    if (bks.length) out.push(h("div", { class: "card mt" }, h("h3", null, t("backups")),
      h("div", { class: "tablewrap" }, h("table", null, h("tbody", null, bks.map((b) => h("tr", null,
        h("td", null, h("span", { class: "dot " + (b.ok ? "ok" : "high") })),
        h("td", null, b.name),
        h("td", { class: "nowrap" }, b.problem === "missing" ? t("bkMissing")
          : b.age_hours + " " + t("hoursOld") + (b.max_age_hours ? " (" + t("limit") + " " + b.max_age_hours + ")" : "") + (b.problem === "small" ? ", " + t("bkSmall") : "")),
        h("td", { class: "mono muted" }, b.newest || b.path))))))));
  }
  if (v) {
    const rows = (list) => h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["", t("cve"), t("pkg"), t("installed"), t("fixedIn")].map((x) => h("th", null, x)))),
      h("tbody", null, list.map((x) => h("tr", null,
        h("td", null, h("span", { class: "sev " + (x.severity in { critical: 1, high: 1, medium: 1, low: 1 } ? x.severity : "low") }, x.severity)),
        h("td", { class: "mono" }, h("a", { href: "https://www.cve.org/CVERecord?id=" + encodeURIComponent(x.cve), target: "_blank", rel: "noopener noreferrer" }, x.cve)),
        h("td", { class: "mono" }, x.package),
        h("td", { class: "mono" }, x.installed),
        h("td", { class: "mono" }, x.fixed ? x.fixed + (x.pro ? " (" + t("proOnly") + ")" : "") : "·"))))));
    const fixable = (v.top || []).filter((x) => !x.kev);
    out.push(h("div", { class: "card mt" },
      h("div", { class: "flex" }, h("h3", null, t("vulns")), h("span", { class: "muted right" }, v.release || "", v.checked ? "  ·  " + t("checked") + " " : "", v.checked ? timeEl(v.checked) : null)),
      v.error ? h("div", { class: "muted mt" }, v.error) : h("dl", { class: "kv" },
        h("dt", null, t("fixable")), h("dd", null, SEVS.some((s) => (v.fixable || {})[s]) ? sevCounts(v.fixable) : h("span", { class: "chip" }, h("span", { class: "dot ok" }), t("noVulns"))),
        h("dt", null, t("unfixed")), h("dd", null, sevCounts(v.unfixed))),
      (v.exploited || []).length ? [h("h3", { class: "mt" }, t("exploitedNow")), rows(v.exploited)] : null,
      fixable.length ? [h("h3", { class: "mt" }, t("fixable")), rows(fixable.slice(0, 25))] : null));
  }
  return out;
}

const sevCounts = (m) => h("span", { class: "sevcounts" }, SEVS.filter((s) => m && m[s]).map((s) => h("span", { class: "sev " + s }, m[s])));

async function overview() {
  const [o, inc, acts] = await Promise.all([api("/api/ui/overview"), api("/api/ui/incidents?status=active"), api("/api/ui/actions").catch(() => [])]);
  const waiting = acts.filter((x) => x.status === "approval");
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
    h("thead", null, h("tr", null, [t("host"), t("status"), t("lastSeen"), t("alertsOpen"), t("updates"), t("ports"), t("canaries"), t("configSync"), t("version")]
      .map((x) => h("th", null, x)))),
    h("tbody", null, o.agents.map((a) => h("tr", { class: "click", onclick: () => { location.hash = "#/hosts/" + a.id; } },
      h("td", null, h("a", { href: "#/hosts/" + a.id, class: "strong" }, a.name)),
      h("td", null, statusChip(a.status)),
      h("td", { class: "nowrap" }, timeEl(a.last_seen)),
      h("td", null, a.open_alerts ? sevCounts(a.open_by_severity) : h("span", { class: "muted" }, "0")),
      h("td", null, updatesCell(a.updates)),
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
    waiting.length ? [h("h2", null, t("pendingApprovals")), actionRows(waiting)] : null,
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

const actLabel = (a) => t({ block_ip: "actBlock", kill_session: "actSession", kill_process: "actProcess", remove_key: "actKey",
  isolate_host: "actIsolate", release_host: "actRelease", lock_user: "actLock", unlock_user: "actUnlock" }[a.type])
  .replace(/\{(\w+)\}/g, (_, k) => k === "dur" ? fmtMinutes(a.params.minutes) : (a.params[k] || "").slice(0, 24));
const fmtMinutes = (m) => { m = Number(m) || 0; return !m ? "" : m % 1440 === 0 ? m / 1440 + " d" : m % 60 === 0 ? m / 60 + " h" : m + " min"; };
const actStatus = (st) => h("span", { class: "chip" }, h("span", { class: "dot " + ({ done: "ok", failed: "critical", expired: "low", pending: "medium", approval: "high", rejected: "low" }[st] || "") }),
  t({ done: "done", failed: "failed", expired: "expiredAct", pending: "pendingAct", approval: "awaitingApproval", rejected: "rejectedAct" }[st] || st));

// actionRows lists actions with approve and reject for those waiting.
function actionRows(list) {
  return h("div", { class: "list" }, list.map((x) => h("div", { class: "row" },
    actStatus(x.status),
    h("div", null, h("div", { class: "title" }, actLabel(x)),
      h("div", { class: "sub" }, [x.by, x.approved_by ? t("approvedBy") + " " + x.approved_by : "", x.result].filter(Boolean).join("  ·  ")),
      x.status === "approval" && can("admin") ? h("div", { class: "actions" },
        x.by !== me.user ? h("button", { class: "btn small", onclick: decide(x, "approve") }, t("approve")) : h("span", { class: "muted" }, t("needsSecond")),
        h("button", { class: "btn small ghost", onclick: decide(x, "reject") }, x.by === me.user ? t("withdraw") : t("reject"))) : null),
    h("div", { class: "meta" }, timeEl(x.created)))));
}

const decide = (x, d) => async () => {
  if (!confirm(actLabel(x) + "\n\n" + t(d === "approve" ? "confirmApprove" : "confirmReject"))) return;
  const code = prompt(t("codePrompt")); if (!code) return;
  try { await post("/api/ui/actions/" + x.id + "/" + d, { code: code.trim() }); render(); } catch (e) { alert(e.message); }
};

// respondNow starts an action from a host page (release, unlock, isolate, lock).
const respondNow = (agent, type, params) => async () => {
  const label = actLabel({ type, params });
  if (!confirm(label + "\n\n" + t("confirmAction"))) return;
  const code = prompt(t("codePrompt")); if (!code) return;
  try { await post("/api/ui/agents/" + agent + "/respond", { type, params, code: code.trim() }); render(); } catch (e) { alert(e.message); }
};

function containCard(a) {
  const c = a.contain || {};
  const allowed = new Set(a.response_types || []);
  const locked = Object.entries(c.locked || {});
  const isolated = c.isolated_until && new Date(c.isolated_until) > new Date();
  if (!isolated && !locked.length && !(can("admin") && (allowed.has("isolate_host") || allowed.has("lock_user")))) return null;
  const userIn = h("input", { placeholder: t("user"), maxlength: 32, class: "mono" });
  return h("div", { class: "card mt" + (isolated ? " danger-card" : "") },
    h("h3", null, t("containment")),
    isolated ? h("div", { class: "flex" }, h("span", { class: "chip" }, h("span", { class: "dot critical" }), t("isolatedUntil") + " " + abs(c.isolated_until)),
      can("admin") && allowed.has("release_host") ? h("button", { class: "btn small right", onclick: respondNow(a.id, "release_host", {}) }, t("actRelease")) : null) : null,
    locked.map(([u, until]) => h("div", { class: "flex mt" }, h("span", { class: "chip" }, h("span", { class: "dot high" }), u + ": " + t("lockedUntil") + " " + abs(until)),
      can("admin") && allowed.has("unlock_user") ? h("button", { class: "btn small right", onclick: respondNow(a.id, "unlock_user", { user: u }) }, t("unlock")) : null)),
    can("admin") && !isolated && allowed.has("isolate_host") ? h("div", { class: "actions" },
      h("button", { class: "btn danger", onclick: respondNow(a.id, "isolate_host", { minutes: "60" }) }, t("actIsolate").replace("{dur}", "1 h"))) : null,
    can("admin") && allowed.has("lock_user") ? h("form", { class: "inline mt", onsubmit: (e) => { e.preventDefault(); if (userIn.value.trim()) respondNow(a.id, "lock_user", { user: userIn.value.trim(), minutes: "1440" })(); } },
      h("label", null, t("lockAccount"), userIn), h("button", { class: "btn ghost", type: "submit" }, t("actLock").replace("{user}", "").replace("{dur}", "24 h").trim())) : null);
}

async function responseCard(a) {
  if (!can("admin") || !a.agent) return null;
  const r = await api("/api/ui/alerts/" + a.id + "/actions");
  if (!(r.suggested || []).length) return null;
  const out = h("div", { class: "muted" });
  return h("div", { class: "card mt" }, h("h3", null, t("response")),
    h("div", { class: "actions" }, r.suggested.map((s) => {
      const ok = (r.allowed || []).includes(s.type);
      return h("button", { class: "btn " + (s.type === "block_ip" ? "" : "ghost"), disabled: !ok, title: ok ? "" : t("notEnabled"), onclick: async () => {
        if (!confirm(actLabel(s) + "\n\n" + t("confirmAction"))) return;
        const code = prompt(t("codePrompt")); if (!code) return;
        try {
          const act = await post("/api/ui/agents/" + a.agent + "/respond", { type: s.type, params: s.params, alert: a.id, code: code.trim() });
          out.textContent = actLabel(s) + ": " + t(act.status === "approval" ? "awaitingApproval" : "requested");
        } catch (x) { out.textContent = x.message; }
      } }, actLabel(s));
    })),
    (r.allowed || []).length ? null : h("div", { class: "muted mt" }, t("notEnabled")), out);
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
        a.agent ? [h("dt", null, t("timeline")), h("dd", null, h("a", { href: tlHref(a.agent, a.created, { alert: a.id }) }, "± 30 min"))] : null,
        h("dt", null, t("count")), h("dd", null, a.count),
        h("dt", null, t("created")), h("dd", null, abs(a.created)),
        h("dt", null, t("updated")), h("dd", null, abs(a.updated)),
        params.map(([k, v]) => [h("dt", null, k), h("dd", { class: "mono" }, entityLink(k, v) || v || "·")])),
      !can("analyst") ? null : h("div", { class: "actions" },
        a.status === "open" ? h("button", { class: "btn", onclick: act("ack") }, t("ack")) : null,
        a.status !== "resolved" ? h("button", { class: "btn ghost", onclick: act("resolve") }, t("resolve")) : null,
        a.status !== "open" ? h("button", { class: "btn ghost", onclick: act("reopen") }, t("reopen")) : null,
        a.suppressible ? h("button", { class: "btn ghost", onclick: () => { box.hidden = false; reason.focus(); } }, icon("bell-off"), t("suppress")) : null,
        a.incident ? h("a", { class: "btn ghost", href: "#/incidents/" + a.incident }, icon("stack-2"), t("incident"))
          : a.agent ? h("button", { class: "btn ghost", onclick: async () => {
            const r = await post("/api/ui/incidents/new/create", { alert: a.id }); location.hash = "#/incidents/" + r.id;
          } }, icon("stack-2"), t("newIncident")) : null)),
    box, await causingEvents(a), a.agent ? await snapshotsCard(a.agent, a.id) : null, await responseCard(a)));
}

async function hostView(id) {
  const [d, actions, tests] = await Promise.all([api("/api/ui/agents/" + encodeURIComponent(id)), api("/api/ui/actions?agent=" + encodeURIComponent(id)),
    api("/api/ui/selftests?agent=" + encodeURIComponent(id))]);
  const a = d.agent;
  selftestOpen = tests.some((x) => x.status === "pending" || x.status === "running");
  const stErr = h("div", { class: "err" });
  const stDot = { passed: "ok", warning: "medium", failed: "critical", pending: "stopped", running: "stopped", ok: "ok", suppressed: "medium", skipped: "medium", missing: "critical", waiting: "stopped" };
  const testRow = (x) => h("div", { class: "row" },
    h("span", { class: "chip" }, h("span", { class: "dot " + (stDot[x.status] || "") }), t("st_" + x.status)),
    h("div", null,
      h("div", { class: "title steps" }, x.steps.map((st) => h("span", { class: "chip", title: st.detail || "" }, h("span", { class: "dot " + (stDot[st.status] || "") }), st.rule + ": " + t("st_" + st.status)))),
      h("div", { class: "sub" }, [x.by, x.error, x.notified ? t("notifiedTo") + " " + Object.entries(x.notified).map(([k, v]) => k + (v === "ok" ? "" : " (" + v + ")")).join(", ") : ""].filter(Boolean).join("  ·  "))),
    h("div", { class: "meta" }, timeEl(x.created)));
  const selftestCard = h("div", null, h("div", { class: "flex" }, h("h2", null, t("selftest")),
      can("admin") && a.selftest ? h("button", { class: "btn small right", onclick: async () => {
        stErr.textContent = "";
        try { await post("/api/ui/agents/" + a.id + "/selftest"); render(); } catch (x) { stErr.textContent = x.message; }
      } }, t("runSelftest")) : null),
    stErr,
    !a.selftest ? h("div", { class: "card empty" }, t("selftestOff"))
      : tests.length ? h("div", { class: "list" }, tests.slice(0, 5).map(testRow)) : h("div", { class: "card empty" }, t("noSelftests")));
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
      !can("admin") ? null : h("div", { class: "card" },
        h("form", { class: "inline", onsubmit: async (e) => { e.preventDefault(); await post("/api/ui/agents/" + a.id + "/rename", { name: renameInput.value }); render(); } },
          h("label", null, t("rename"), renameInput), h("button", { class: "btn ghost", type: "submit" }, t("rename"))),
        a.maintenance_until
          ? h("div", { class: "flex mt" }, h("span", { class: "chip" }, h("span", { class: "dot stopped" }), t("maintenanceUntil") + " " + abs(a.maintenance_until)),
            h("button", { class: "btn small ghost", onclick: action("maintenance", { minutes: 0 }) }, t("end")))
          : h("form", { class: "inline mt", onsubmit: async (e) => { e.preventDefault(); await post("/api/ui/agents/" + a.id + "/maintenance", { minutes: Number(minutesSel.value) }); render(); } },
            h("label", null, t("maintenance"), minutesSel), h("button", { class: "btn ghost", type: "submit" }, t("start"))),
        h("div", { class: "actions" },
          h("a", { class: "btn ghost", href: "#/events?agent=" + a.id }, t("events")),
          h("a", { class: "btn ghost", href: tlHref(a.id, new Date().toISOString(), { minutes: 60 }) }, t("timeline")),
          h("a", { class: "btn ghost", href: "#/sessions?agent=" + a.id }, t("sessions")),
          h("a", { class: "btn ghost", href: "#/alerts" }, t("alerts")),
          h("button", { class: "btn danger", onclick: async () => { if (confirm(t("confirmDelete"))) { await post("/api/ui/agents/" + a.id + "/delete"); location.hash = "#/"; } } }, t("deleteHost"))))),
    a.updates ? h("div", { class: "card mt" }, h("h3", null, t("updates")), h("dl", { class: "kv" },
      h("dt", null, t("updates")), h("dd", null, updatesCell(a.updates)),
      h("dt", null, t("securityPackages")), h("dd", { class: "mono" }, (a.updates.security_packages || []).join("  ") || "·"),
      h("dt", null, t("kernel")), h("dd", { class: "mono" }, a.updates.kernel_running + (a.updates.kernel_newest && a.updates.kernel_newest !== a.updates.kernel_running ? "  (" + t("newestInstalled") + " " + a.updates.kernel_newest + ")" : "")),
      h("dt", null, t("unattended")), h("dd", null, t(a.updates.unattended_upgrades ? "on" : "off")),
      h("dt", null, t("listsAge")), h("dd", null, a.updates.lists_age_days >= 0 ? a.updates.lists_age_days + " " + t("daysAgo") : "·"))) : null,
    postureSection(a),
    h("div", { class: "flex" }, h("h2", null, t("ports")),
      d.ports.some((p) => !p.expected) ? h("button", { class: "btn small right", onclick: action("accept-port", { key: "*" }) }, t("acceptAll")) : null),
    h("div", { class: "tablewrap" }, h("table", { class: "nowrap" },
      h("thead", null, h("tr", null, ["Port", "Addr", t("scope"), t("via"), t("process"), ""].map((x) => h("th", null, x)))),
      h("tbody", null, portRows))),
    containCard(a),
    actions.length ? [h("h2", null, t("response")), actionRows(actions)] : null,
    await snapshotsCard(a.id),
    selftestCard,
    h("h2", null, t("logins")),
    d.logins.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, [t("time"), t("user"), t("ip"), t("method"), t("key")].map((x) => h("th", null, x)))),
      h("tbody", null, loginRows))) : h("div", { class: "card empty" }, t("noEvents"))));
}

async function eventsView(params) {
  const q = params.get("q") || "";
  if (q) return searchView(params);
  const agents = (await api("/api/ui/overview")).agents;
  const agent = params.get("agent") || "";
  const type = params.get("type") || "";
  const tbody = h("tbody");
  let before = 0;
  const more = h("button", { class: "btn ghost mt" }, t("loadMore"));
  async function load() {
    const qs = new URLSearchParams({ agent, type, limit: "200" });
    if (before) qs.set("before", before);
    const rows = await api("/api/ui/events?" + qs);
    for (const r of rows) {
      tbody.append(eventRow(r));
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
  mount(shell("events", h("h1", null, t("events")), h("div", { class: "crumbs" }, scopeLine),
    await searchCard(""),
    h("div", { class: "card mt" }, form), h("div", { class: "tablewrap mt" },
    h("table", { class: "evtable" }, h("thead", null, h("tr", null, [t("time"), t("host"), t("type"), t("details")].map((x) => h("th", null, x)))), tbody)), more));
  await load();
}

function eventRow(r) {
  return h("tr", null,
    h("td", { class: "nowrap" }, r.agent ? h("a", { href: tlHref(r.agent, r.event.ts || r.time), title: t("timeline") }, new Date(r.event.ts || r.time).toLocaleString(lang))
      : h("span", { title: abs(r.event.ts) }, new Date(r.event.ts || r.time).toLocaleString(lang))),
    h("td", null, r.host || r.source + (r.actor ? ":" + r.actor : "")),
    h("td", { class: "mono" }, r.event.type),
    h("td", { class: "mono" }, dataLine(r.event.data), diffBlock(r.event.data)));
}

// searchCard: the query box with saved searches, used on the events page.
async function searchCard(q, days = "7") {
  const saved = await api("/api/ui/searches").catch(() => []);
  const qIn = h("input", { value: q, placeholder: t("searchHint"), class: "mono grow", spellcheck: false });
  const daysSel = h("select", null, [1, 7, 30, 90].map((n) => h("option", { value: n, selected: String(n) === String(days) }, t("days30").replace("{n}", n))));
  const nameIn = h("input", { placeholder: t("searchName"), maxlength: 100 });
  const err = h("div", { class: "err" });
  const go = (e) => { e.preventDefault(); if (qIn.value.trim()) location.hash = "#/events?" + new URLSearchParams({ q: qIn.value.trim(), days: daysSel.value }); };
  return h("div", { class: "card" },
    h("form", { class: "inline", onsubmit: go },
      h("label", { class: "grow" }, t("query"), qIn), h("label", null, t("window"), daysSel), h("button", { class: "btn", type: "submit" }, t("search"))),
    saved.length ? h("div", { class: "flex mt" }, h("span", { class: "muted" }, t("savedSearches") + ":"),
      saved.map((x) => h("span", { class: "chip" },
        h("a", { href: "#/events?" + new URLSearchParams({ q: x.query, days }), title: x.query }, x.name),
        can("analyst") ? h("button", { class: "linkbtn", title: "×", onclick: async () => { await post("/api/ui/searches/" + x.id + "/delete"); render(); } }, "×") : null))) : null,
    q && can("analyst") ? h("form", { class: "inline mt", onsubmit: async (e) => {
      e.preventDefault();
      try { await post("/api/ui/searches", { name: nameIn.value, query: q }); render(); } catch (x) { err.textContent = x.message; }
    } }, h("label", null, t("saveSearch"), nameIn), h("button", { class: "btn ghost", type: "submit" }, t("saveSearch"))) : null,
    err);
}

async function searchView(params) {
  const q = params.get("q"), days = params.get("days") || "7";
  const res = await api("/api/ui/search?" + new URLSearchParams({ q, days, limit: "500" }));
  const exp = (fmt) => "/api/ui/search?" + new URLSearchParams({ q, days, limit: "5000", format: fmt });
  mount(shell("events", h("h1", null, t("search")), h("div", { class: "crumbs mono" }, q),
    await searchCard(q, days),
    h("div", { class: "flex mt" }, h("span", { class: "muted" }, t("found").replace("{n}", res.total).replace("{ms}", res.ms) + (res.partial ? " · " + t("partialScan") : "")),
      h("span", { class: "right flex" }, h("a", { class: "btn small ghost", href: exp("csv") }, t("exportCSV")), h("a", { class: "btn small ghost", href: exp("jsonl") }, t("exportJSONL")))),
    res.records.length ? h("div", { class: "tablewrap mt" }, h("table", { class: "evtable" },
      h("thead", null, h("tr", null, [t("time"), t("host"), t("type"), t("details")].map((x) => h("th", null, x)))),
      h("tbody", null, res.records.map(eventRow)))) : h("div", { class: "card empty mt" }, t("noEvents"))));
}

async function huntView() {
  const ta = h("textarea", { rows: 6, class: "mono", placeholder: "203.0.113.7\nroot\n" + "e3b0c442…" });
  const daysSel = h("select", null, [7, 30, 90, 365].map((n) => h("option", { value: n, selected: n === 30 }, t("days30").replace("{n}", n))));
  const out = h("div", { class: "mt" });
  const err = h("div", { class: "err" });
  const form = h("form", { class: "card stack", onsubmit: async (e) => {
    e.preventDefault(); err.textContent = ""; out.replaceChildren(h("div", { class: "muted" }, "…"));
    try {
      const r = await post("/api/ui/hunt", { values: ta.value.split(/[\s,;]+/).filter(Boolean), days: Number(daysSel.value) });
      out.replaceChildren(...[
        r.invalid && r.invalid.length ? h("div", { class: "card muted" }, t("invalidValues") + ": ", h("span", { class: "mono" }, r.invalid.join("  "))) : null,
        h("div", { class: "tablewrap mt" }, h("table", null,
          h("thead", null, h("tr", null, ["", t("total"), t("seenOn"), t("firstSeen"), t("lastSeenShort")].map((x) => h("th", null, x)))),
          h("tbody", null, r.results.map((x) => h("tr", null,
            h("td", { class: "mono" }, h("a", { href: pivotHref(x.kind, x.value) }, x.value), x.intel ? [" ", h("span", { class: "pill warn" }, x.intel)] : null),
            h("td", null, x.count ? h("strong", null, x.count) : h("span", { class: "muted" }, t("notFound"))),
            h("td", null, h("div", { class: "flex" }, Object.entries(x.hosts).map(([k, n]) => h("span", { class: "chip" }, k + " " + n)))),
            h("td", null, x.count ? abs(x.first) : ""), h("td", null, x.count ? abs(x.last) : ""))))))].filter(Boolean));
    } catch (x) { out.replaceChildren(); err.textContent = x.message; }
  } }, h("div", { class: "muted" }, t("huntHint")), ta, h("div", { class: "inline" }, h("label", null, t("window"), daysSel), h("button", { class: "btn", type: "submit" }, t("huntRun"))), err);
  mount(shell("hunt", h("h1", null, t("hunt")), can("analyst") ? form : h("div", { class: "card muted" }, "analyst"), out));
}

const fmtDur = (a, b) => { const s = Math.max(0, Math.round((new Date(b) - new Date(a)) / 1000)); return s < 3600 ? Math.floor(s / 60) + " min" : Math.floor(s / 3600) + " h " + Math.floor((s % 3600) / 60) + " min"; };
const sessionHref = (x) => "#/session?" + new URLSearchParams({ agent: x.agent, pid: x.sshd_pid, start: x.start });

async function sessionsView(params) {
  const days = params.get("days") || "7";
  const agent = params.get("agent") || "";
  const r = await api("/api/ui/sessions?" + new URLSearchParams({ days, agent }));
  const daysSel = h("select", { onchange: () => { location.hash = "#/sessions?" + new URLSearchParams({ days: daysSel.value, agent }); } },
    [1, 7, 30, 90].map((n) => h("option", { value: n, selected: String(n) === days }, t("days30").replace("{n}", n))));
  mount(shell("sessions", h("h1", null, t("sessions")),
    h("div", { class: "card" }, h("div", { class: "inline" }, h("label", null, t("window"), daysSel))),
    r.sessions.length ? h("div", { class: "tablewrap mt" }, h("table", null,
      h("thead", null, h("tr", null, [t("started"), t("host"), t("user"), "IP", t("duration"), t("commands"), t("sudoShort"), t("filesShort"), t("alerts")].map((x) => h("th", null, x)))),
      h("tbody", null, r.sessions.map((x) => h("tr", { class: "click", onclick: () => { location.hash = sessionHref(x); } },
        h("td", { class: "nowrap" }, h("a", { href: sessionHref(x) }, abs(x.start))),
        h("td", null, x.host),
        h("td", null, h("a", { href: pivotHref("user", x.user) }, x.user), x.key ? h("div", { class: "muted small" }, x.key) : null),
        h("td", { class: "mono" }, h("a", { href: pivotHref("ip", x.ip) }, x.ip)),
        h("td", { class: "nowrap" }, x.end ? fmtDur(x.start, x.end) : h("span", { class: "chip" }, h("span", { class: "dot online" }), t("stillOpen"))),
        h("td", null, x.commands + (x.dropped ? "+" : "")), h("td", null, x.sudo || ""), h("td", null, x.files || ""),
        h("td", null, x.alerts ? h("span", { class: "sev high" }, x.alerts) : "")))))) : h("div", { class: "card empty mt" }, t("noSessions"))));
}

async function sessionView(params) {
  const r = await api("/api/ui/session?" + new URLSearchParams({ agent: params.get("agent"), pid: params.get("pid"), start: params.get("start") }));
  const x = r.session;
  const items = [
    ...r.events.map((e) => ({ ts: e.event.ts || e.time, e })),
    ...r.alerts.map((a) => ({ ts: a.created, a })),
  ].sort((a, b) => new Date(a.ts) - new Date(b.ts));
  const line = (it) => {
    if (it.a) return h("a", { class: "row tl-row", href: "#/alerts/" + it.a.id }, h("span", { class: "tl-time mono" }, hhmmss(it.ts)),
      h("div", null, h("div", { class: "title" }, sevChip(it.a.severity), " ", it.a.title)), h("span", null));
    const e = it.e.event, d = e.data || {};
    let title, sub;
    if (e.type === "session.exec") { title = h("span", { class: "mono cmd" }, (d.uid === 0 ? "# " : "$ ") + (d.cmdline || d.exe)); sub = d.cwd || ""; }
    else if (e.type === "sudo.command") { title = h("span", { class: "mono cmd" }, "sudo " + (d.as && d.as !== "root" ? "-u " + d.as + " " : "") + d.command); sub = d.cwd || ""; }
    else { title = h("span", { class: "mono" }, e.type + " " + (d.path || "")); sub = t("filesDuring"); }
    return h("div", { class: "row tl-row" }, h("span", { class: "tl-time mono" }, hhmmss(it.ts)),
      h("div", null, h("div", { class: "title" }, title), sub ? h("div", { class: "sub mono" }, sub) : null, diffBlock(d)), h("span", null));
  };
  mount(shell("sessions",
    h("div", { class: "crumbs" }, h("a", { href: "#/sessions" }, t("sessions")), " / ", x.user),
    h("h1", null, t("sessionOf").replace("{user}", x.user) + " · " + x.host),
    h("div", { class: "card" }, h("dl", { class: "kv" },
      h("dt", null, t("user")), h("dd", null, h("a", { href: pivotHref("user", x.user) }, x.user)),
      h("dt", null, "IP"), h("dd", { class: "mono" }, h("a", { href: pivotHref("ip", x.ip) }, x.ip)),
      h("dt", null, t("method")), h("dd", null, x.method + (x.key ? " · " + x.key : "")),
      h("dt", null, t("started")), h("dd", null, abs(x.start)),
      h("dt", null, t("ended")), h("dd", null, x.end ? abs(x.end) + " (" + fmtDur(x.start, x.end) + ")" : t("stillOpen")),
      h("dt", null, t("timeline")), h("dd", null, h("a", { href: tlHref(x.agent, x.start, { minutes: 60 }) }, "± 60 min")))),
    x.dropped ? h("div", { class: "card muted mt" }, t("dropped").replace("{n}", x.dropped)) : null,
    h("div", { class: "list timeline mt" }, items.length ? items.map(line) : h("div", { class: "card empty" }, t("noEvents")))));
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
    can("admin") ? h("div", { class: "page-actions" }, h("button", { class: "btn", onclick: () => pathIn.focus() }, icon("plus"), t("place"))) : null,
    can("admin") ? h("div", { class: "card" }, form) : null,
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
    h("div", { class: "page-actions" }, c.owner !== me.user && can("analyst") ? h("button", { class: "btn", onclick: act("assign") }, t("assignMe")) : null,
      can("analyst") ? h("a", { class: "btn ghost", href: "/api/ui/incidents/" + c.id + "/report?format=md" }, t("reportMD")) : null,
      can("analyst") ? h("a", { class: "btn ghost", href: "/api/ui/incidents/" + c.id + "/report?format=html", target: "_blank", rel: "noopener" }, t("reportPrint")) : null),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("dl", { class: "kv" },
        h("dt", null, t("status")), h("dd", null, incChip(c.status)),
        h("dt", null, t("severity")), h("dd", null, sevChip(c.severity)),
        h("dt", null, t("host")), h("dd", null, h("a", { href: "#/hosts/" + c.agent }, c.host || c.agent)),
        h("dt", null, t("owner")), h("dd", null, c.owner || t("unowned")),
        h("dt", null, t("created")), h("dd", null, abs(c.created)),
        h("dt", null, t("updated")), h("dd", null, abs(c.last)),
        h("dt", null, t("alerts")), h("dd", null, c.count + (c.open_alerts ? " (" + c.open_alerts + " " + t("open").toLowerCase() + ")" : ""))),
        !can("analyst") ? null : h("div", { class: "actions" }, h("span", { class: "muted" }, t("setStatus")),
          h("div", { class: "tabs" }, ["open", "investigating", "contained", "closed"].map((st) =>
            h("button", { class: st === c.status ? "on" : null, onclick: act("status", { status: st }) }, t(st === "open" ? "openInc" : st)))))),
      h("div", { class: "card" }, h("h3", null, t("notes")),
        h("div", { class: "notes" }, (c.notes || []).map((n) => h("div", { class: "note" },
          h("div", { class: "note-head" }, h("span", { class: "strong" }, n.by), " ", h("span", { class: "muted" }, abs(n.at))),
          h("div", { class: "note-text" }, n.text)))),
        !can("analyst") ? null : h("form", { class: "stack mt", onsubmit: async (e) => { e.preventDefault(); await act("note", { note: note.value })(); } },
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
  const st = (ok, text) => h("span", { class: "chip" }, h("span", { class: "dot " + (ok ? "ok" : "high") }), text);
  const m = r.malware || {}, hi = m.hash_intel || {}, ya = m.yara || {}, sg = r.sigma || {};
  const engines = h("div", { class: "card" }, h("dl", { class: "kv" },
    h("dt", null, "Sigma"), h("dd", null, st(!(sg.errors || []).length, sg.rules + " " + t("activeRules") + (sg.other_sources ? ", " + sg.other_sources + " " + t("otherSources") : "")),
      (sg.errors || []).slice(0, 20).map((e) => h("div", { class: "mono muted small" }, e))),
    h("dt", null, "YARA"), h("dd", null, ya.dir ? st(!(ya.errors || []).length, ya.rules + " " + t("activeRules")) : h("span", { class: "muted" }, t("notConfigured") + " (yara_dir)"),
      (ya.errors || []).slice(0, 20).map((e) => h("div", { class: "mono muted small" }, e))),
    h("dt", null, t("hashLists")), h("dd", null, hi.enabled ? st(!hi.error, (hi.hashes || 0).toLocaleString(lang) + " SHA-256" + (hi.recent && !hi.recent.startsWith("0001") ? ", " + t("updated") + " " + abs(hi.recent) : "")) : h("span", { class: "muted" }, t("notConfigured") + " (hash_intel)"),
      hi.error ? h("div", { class: "mono muted small" }, hi.error) : null),
    h("dt", null, t("forwarding")), h("dd", null, (r.forward || []).length ? (r.forward || []).map((f) => h("div", null,
      st(!f.error, f.name + " (" + f.type + "): " + f.sent + " " + t("sentShort") + (f.dropped ? ", " + f.dropped + " " + t("droppedShort") : "") + (f.queued ? ", " + f.queued + " " + t("queuedShort") : "")),
      f.error ? h("div", { class: "mono muted small" }, f.error) : null)) : h("span", { class: "muted" }, t("notConfigured") + " (forward)"))));
  mount(shell("rules", h("h1", null, t("rules")),
    h("div", { class: "crumbs" }, r.builtin.length + " " + t("builtin") + ", " + (r.custom || []).length + " " + t("customShort")),
    engines,
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
  const notifyErr = h("div", { class: "err" });
  const notifyBox = h("div");
  const drawNotifiers = (list) => notifyBox.replaceChildren(list.length ? h("div", { class: "feed" }, list.map((n) => h("div", { class: "feed-row" },
    h("div", null, h("span", { class: "chip" }, h("span", { class: "dot " + (n.failures ? "broken" : n.last_ok && !n.last_ok.startsWith("0001") ? "ok" : "") }), h("span", { class: "strong" }, n.name)),
      " ", h("span", { class: "muted" }, n.type + ", " + t(n.min_severity) + "+")),
    h("div", { class: "feed-sub" }, n.failures ? t("failing") + ": " + n.last_error
      : n.last_ok && !n.last_ok.startsWith("0001") ? t("delivered") + " " + abs(n.last_ok) : t("neverDelivered")))))
    : h("div", { class: "muted" }, t("noNotifiers")));
  const notif = await api("/api/ui/notifiers");
  drawNotifiers(notif.notifiers);
  const chainBox = h("div");
  const drawChain = (c) => chainBox.replaceChildren(h("dl", { class: "kv" },
    h("dt", null, t("status")), h("dd", null, h("span", { class: "chip" }, h("span", { class: "dot " + (c.ok ? "ok" : "broken") }), t(c.ok ? "chainOK" : "chainBroken"))),
    c.error ? [h("dt", null, "Error"), h("dd", { class: "mono" }, c.error)] : null,
    h("dt", null, t("records")), h("dd", null, c.seq.toLocaleString(lang)),
    h("dt", null, t("head")), h("dd", { class: "mono" }, c.head || "·"),
    h("dt", null, t("verify")), h("dd", null, abs(c.verified_at))));
  drawChain(chain);

  const acc = await api("/api/ui/account");
  const users = can("admin") ? await api("/api/ui/users") : null;
  const askCode = () => { const c = prompt(t("codePrompt")); return c && c.trim(); };
  const fail = (box) => (x) => { box.textContent = x.message; };

  // passkeys
  const pkErr = h("div", { class: "err" });
  const pkName = h("input", { maxlength: 60, placeholder: t("passkeyName") });
  const pkCode = h("input", { inputmode: "numeric", maxlength: 6, pattern: "[0-9]{6}", required: true, placeholder: "000000", autocomplete: "one-time-code" });
  const addPasskey = async (e) => {
    e.preventDefault(); pkErr.textContent = "";
    try {
      const b = await post("/api/ui/account/passkeys/begin", { code: pkCode.value });
      const cred = await navigator.credentials.create({ publicKey: {
        challenge: fromB64u(b.challenge), rp: { id: b.rp_id, name: b.rp_name },
        user: { id: fromB64u(b.user_id), name: b.user_name, displayName: b.user_name },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
        authenticatorSelection: { residentKey: "required", userVerification: "required" }, attestation: "none",
        excludeCredentials: b.exclude.map((id) => ({ type: "public-key", id: fromB64u(id) })), timeout: 60000 } });
      await post("/api/ui/account/passkeys/finish", { token: b.token, name: pkName.value, clientData: toB64u(cred.response.clientDataJSON),
        attestationObject: toB64u(cred.response.attestationObject) });
      render();
    } catch (x) { pkErr.textContent = x.name === "NotAllowedError" ? t("passkeyCancelled") : x.message; }
  };
  const pkList = acc.passkeys.length ? h("div", { class: "feed" }, acc.passkeys.map((k) => h("div", { class: "feed-row" },
    h("div", null, icon("key"), " ", h("span", { class: "strong" }, k.name)),
    h("div", { class: "feed-sub" }, t("created2") + " " + abs(k.created).split(",")[0] + (k.last_used && !k.last_used.startsWith("0001") ? "  ·  " + t("lastLogin") + " " + abs(k.last_used) : "")),
    h("div", { class: "feed-time" }, h("button", { class: "btn small ghost", onclick: async () => {
      const code = askCode(); if (!code) return;
      try { await post("/api/ui/account/passkeys/" + encodeURIComponent(k.id) + "/delete", { code }); render(); } catch (x) { pkErr.textContent = x.message; }
    } }, t("remove")))))) : h("div", { class: "muted" }, t("noPasskeys"));

  // password
  const pwErr = h("div", { class: "err" });
  const pwForm = h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault(); pwErr.textContent = "";
    const f = new FormData(pwForm);
    if (f.get("new") !== f.get("new2")) { pwErr.textContent = t("passwordsDiffer"); return; }
    try { await post("/api/ui/account/password", { current: f.get("current"), new: f.get("new"), code: f.get("code") }); pwForm.reset(); pwErr.textContent = t("saved"); }
    catch (x) { pwErr.textContent = x.message; }
  } },
    h("label", null, t("currentPassword"), h("input", { name: "current", type: "password", autocomplete: "current-password", required: true })),
    h("div", { class: "grid two" },
      h("label", null, t("newPassword"), h("input", { name: "new", type: "password", autocomplete: "new-password", minlength: 12, required: true })),
      h("label", null, t("repeatPassword"), h("input", { name: "new2", type: "password", autocomplete: "new-password", minlength: 12, required: true }))),
    h("label", null, t("totpCode"), h("input", { name: "code", inputmode: "numeric", maxlength: 6, pattern: "[0-9]{6}", required: true, placeholder: "000000", autocomplete: "one-time-code" })),
    pwErr, h("div", null, h("button", { class: "btn ghost", type: "submit" }, t("changePassword"))));

  // users (admins)
  let usersCard = null;
  if (users) {
    const uErr = h("div", { class: "err" });
    const result = h("div");
    const roleSel = (value, onchange) => h("select", { onchange }, ["viewer", "analyst", "admin"].map((r) => h("option", { value: r, selected: r === value }, t(r))));
    const newRole = roleSel("analyst");
    const uForm = h("form", { class: "inline", onsubmit: async (e) => {
      e.preventDefault(); uErr.textContent = ""; result.replaceChildren();
      const f = new FormData(uForm);
      try {
        const r = await post("/api/ui/users", { name: f.get("name"), role: newRole.value, code: f.get("code") });
        uForm.reset();
        result.replaceChildren(h("div", { class: "newuser mt" }, qrSVG(r.qr), h("dl", { class: "kv" },
          h("dt", null, t("user")), h("dd", { class: "mono" }, r.name),
          h("dt", null, t("password")), h("dd", { class: "mono secret-inline" }, r.password),
          h("dt", null, "TOTP"), h("dd", { class: "mono secret-inline" }, r.totp_secret),
          h("dt", null, ""), h("dd", { class: "muted" }, t("newUserInfo")))));
        const list = await api("/api/ui/users"); tbody.replaceChildren(...list.map(userRow));
      } catch (x) { uErr.textContent = x.message; }
    } },
      h("label", null, t("name"), h("input", { name: "name", required: true, maxlength: 32, pattern: "[a-z0-9][a-z0-9._-]*", autocomplete: "off" })),
      h("label", null, t("role"), newRole),
      h("label", null, t("totpCode"), h("input", { name: "code", inputmode: "numeric", maxlength: 6, pattern: "[0-9]{6}", required: true, placeholder: "000000", autocomplete: "one-time-code" })),
      h("button", { class: "btn", type: "submit" }, icon("plus"), t("addUser")));
    const userRow = (u) => h("tr", null,
      h("td", { class: "strong" }, u.name),
      h("td", null, u.name === me.user ? t(u.role) : roleSel(u.role, async (e) => {
        const code = askCode(); if (!code) { render(); return; }
        try { await post("/api/ui/users/" + encodeURIComponent(u.name) + "/role", { role: e.target.value, code }); } catch (x) { uErr.textContent = x.message; }
        render();
      })),
      h("td", { class: "nowrap" }, u.last_login && !u.last_login.startsWith("0001") ? timeEl(u.last_login) : "·"),
      h("td", null, u.passkeys),
      h("td", null, u.name === me.user ? null : h("button", { class: "btn small ghost", onclick: async () => {
        if (!confirm(u.name + ": " + t("remove") + "?")) return;
        const code = askCode(); if (!code) return;
        try { await post("/api/ui/users/" + encodeURIComponent(u.name) + "/delete", { code }); render(); } catch (x) { uErr.textContent = x.message; }
      } }, t("remove"))));
    const tbody = h("tbody", null, users.map(userRow));
    usersCard = h("div", { class: "card mt" }, h("h3", null, t("users")),
      h("div", { class: "tablewrap flat" }, h("table", null, h("thead", null, h("tr", null, [t("name"), t("role"), t("lastLogin"), t("passkeys"), ""].map((x) => h("th", null, x)))), tbody)),
      h("div", { class: "mt" }, uForm), uErr, result);
  }

  const accountCards = h("div", { class: "grid two mt" },
    h("div", { class: "card" }, h("h3", null, t("account")),
      h("dl", { class: "kv" }, h("dt", null, t("user")), h("dd", null, acc.name), h("dt", null, t("role")), h("dd", null, t(acc.role)),
        h("dt", null, t("lastLogin")), h("dd", null, abs(acc.last_login))),
      h("h3", { class: "mt" }, t("passkeys")), pkList,
      window.PublicKeyCredential ? h("form", { class: "inline mt", onsubmit: addPasskey },
        h("label", null, t("passkeyName"), pkName), h("label", null, t("totpCode"), pkCode),
        h("button", { class: "btn", type: "submit" }, icon("key"), t("addPasskey"))) : h("div", { class: "muted mt" }, t("noPasskeySupport")),
      pkErr),
    h("div", { class: "card" }, h("h3", null, t("changePassword")), pwForm));

  const langTabs = h("div", { class: "tabs" }, [["de", "Deutsch"], ["en", "English"]].map(([k, name]) =>
    h("button", { class: k === lang ? "on" : null, onclick: () => setLang(k) }, name)));
  mount(shell("settings", h("h1", null, t("settings")), h("div", { class: "crumbs" }, "vigil " + me.version),
    accountCards, usersCard,
    h("div", { class: "grid two mt" },
      can("admin") ? h("div", { class: "card" }, h("h3", null, t("enroll")),
        h("button", { class: "btn", onclick: async () => {
          const r = await post("/api/ui/tokens");
          tokenBox.replaceChildren(
            h("div", { class: "secret mt" }, "vigil-agent enroll -server " + (me.agent_url || location.origin) + " -token " + r.token),
            h("div", { class: "muted mt" }, t("validUntil") + " " + abs(r.expires)));
        } }, t("newToken")), tokenBox) : null,
      h("div", { class: "card" }, h("h3", null, t("chain")), chainBox,
        h("div", { class: "actions" },
          can("analyst") ? h("button", { class: "btn ghost", onclick: async () => drawChain(await post("/api/ui/chain/verify")) }, t("verify")) : null))),
    h("div", { class: "card mt" }, h("h3", null, t("notifiers")), notifyBox,
      h("dl", { class: "kv mt" }, h("dt", null, t("heartbeat")), h("dd", null, t(notif.heartbeat ? "configured" : "notConfigured"))),
      can("admin") && notif.notifiers.length ? h("div", { class: "actions" }, h("button", { class: "btn ghost", onclick: async () => {
        notifyErr.textContent = "";
        try { drawNotifiers((await post("/api/ui/notify/test")).notifiers); } catch (x) { notifyErr.textContent = x.message; }
      } }, t("notifyTest"))) : null, notifyErr),
    h("div", { class: "card mt" }, h("h3", null, t("theme")), h("div", { class: "tabs" }, ["light", "dark", "system"].map((k) =>
      h("button", { class: k === theme() ? "on" : null, onclick: () => setTheme(k) }, t(k))))),
    h("div", { class: "card mt" }, h("h3", null, t("language")), h("div", { class: "flex" }, langTabs,
      h("button", { class: "btn ghost right", onclick: logout }, icon("logout"), t("logout"))))));
}

// ---------- investigation ----------

const pivotHref = (kind, value) => "#/pivot/" + kind + "/" + encodeURIComponent(value);
const tlHref = (agent, at, extra = {}) => "#/timeline?" + new URLSearchParams({ agent, at, ...extra });
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]*:[0-9a-f:.]+$/i;

// entityLink makes a parameter value clickable when it is something to pivot on.
function entityLink(k, v) {
  if (!v) return null;
  if (["ip", "remote_ip", "addr", "source_ip"].includes(k) && IP_RE.test(v)) return h("a", { href: pivotHref("ip", v) }, v);
  if (["sha256", "old_sha256", "exe_sha256", "hash"].includes(k) && /^[0-9a-f]{64}$/.test(v)) return h("a", { href: pivotHref("hash", v) }, v);
  if (k === "user" && /^[A-Za-z0-9._@$-]{1,64}$/.test(v)) return h("a", { href: pivotHref("user", v) }, v);
  return null;
}

// dataLine renders an event's data with pivotable values as links. Bulky
// fields (diffs, snapshots) are left to their own views.
function dataLine(data) {
  if (!data) return "";
  const skip = new Set(["ports", "diff", "processes", "connections", "journal", "target", "sessions", "modules", "checks", "certs", "backups", "packages"]);
  const out = [];
  for (const [k, v] of Object.entries(data)) {
    if (skip.has(k)) continue;
    const text = typeof v === "object" ? JSON.stringify(v) : String(v);
    out.push(h("span", { class: "kvp" }, k + "=", entityLink(k, text) || text));
  }
  return out;
}

function diffBlock(data) {
  if (!data) return null;
  if (data.diff_note) return h("div", { class: "muted mt" }, t("prevUnknown"));
  if (typeof data.diff !== "string") return null;
  return h("details", { class: "diff", open: true }, h("summary", null, t("changeLines") + (data.diff_truncated ? " (" + t("truncatedDiff") + ")" : "")),
    h("pre", null, data.diff.split("\n").filter((l) => l !== "").map((l) =>
      h("span", { class: l[0] === "+" ? "add" : l[0] === "-" ? "del" : l.startsWith("@@") ? "hunk" : "" }, l + "\n"))));
}

function kindOf(type) {
  const p = type.split(".")[0];
  if (["ssh", "sudo", "user"].includes(p)) return "kAuth";
  if (["process", "canary", "forensics"].includes(p)) return "kProc";
  if (["file", "integrity", "secret"].includes(p)) return "kFile";
  if (["net", "port", "web"].includes(p)) return "kNet";
  if (p === "kernel") return "kKernel";
  return "kOther";
}

const hhmmss = (ts) => new Date(ts).toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" });

async function timelineView(params) {
  const q = new URLSearchParams();
  for (const k of ["agent", "at", "minutes", "alert"]) if (params.get(k)) q.set(k, params.get(k));
  const d = await api("/api/ui/timeline?" + q);
  const kinds = ["kAuth", "kProc", "kFile", "kNet", "kKernel", "kOther", "kAlert"];
  const anchor = new Date(d.at).getTime();
  const anchorSeqs = new Set(d.anchor_seqs || []);
  const items = [
    ...d.records.map((r) => ({ ts: r.event.ts || r.time, kind: kindOf(r.event.type), rec: r })),
    ...d.alerts.map((a) => ({ ts: a.created, kind: "kAlert", alert: a })),
  ].sort((a, b) => new Date(a.ts) - new Date(b.ts));
  let active = "";
  const list = h("div", { class: "list timeline" });
  let markerDone = false;
  const draw = () => {
    list.replaceChildren();
    markerDone = false;
    const shown = items.filter((it) => !active || it.kind === active);
    if (!shown.length) list.append(h("div", { class: "card empty" }, t("noTimeline")));
    for (const it of shown) {
      if (!markerDone && new Date(it.ts).getTime() >= anchor) {
        list.append(h("div", { class: "tl-marker" }, hhmmss(d.at) + "  " + (params.get("alert") ? t("anchor") : "")));
        markerDone = true;
      }
      if (it.alert) {
        const a = it.alert;
        list.append(h("a", { class: "row tl-row", href: "#/alerts/" + a.id },
          h("span", { class: "tl-time mono" }, hhmmss(it.ts)),
          h("div", null, h("div", { class: "title" }, sevChip(a.severity), " ", a.title), h("div", { class: "sub mono" }, a.rule)),
          h("span", { class: "dot " + a.severity })));
        continue;
      }
      const r = it.rec;
      const late = r.time && r.event.ts && Math.abs(new Date(r.time) - new Date(r.event.ts)) > 60000;
      list.append(h("div", { class: "row tl-row" + (anchorSeqs.has(r.seq) ? " tl-anchor" : "") },
        h("span", { class: "tl-time mono" }, hhmmss(it.ts)),
        h("div", null,
          h("div", { class: "title mono" }, r.event.type,
            r.event.type === "forensics.snapshot" ? [" ", h("a", { href: "#/snapshot/" + r.seq + "?at=" + encodeURIComponent(r.time) }, t("snapshots"))] : null),
          h("div", { class: "sub mono" }, dataLine(r.event.data)),
          late ? h("div", { class: "sub warn" }, t("receivedLate") + " " + abs(r.time)) : null,
          diffBlock(r.event.data)),
        h("span", { class: "tl-kind muted" }, t(it.kind))));
    }
    if (!markerDone) list.append(h("div", { class: "tl-marker" }, hhmmss(d.at) + "  " + (params.get("alert") ? t("anchor") : "")));
  };
  const chips = h("div", { class: "flex" }, ["", ...kinds].map((k) => {
    const n = k ? items.filter((it) => it.kind === k).length : items.length;
    if (k && !n) return null;
    const b = h("button", { class: "btn small ghost" + (k === active ? " on" : ""), onclick: () => { active = k; chips.querySelectorAll("button").forEach((x) => x.classList.remove("on")); b.classList.add("on"); draw(); } },
      (k ? t(k) : t("allKinds")) + " " + n);
    return b;
  }));
  const shift = (mins) => tlHref(d.agent, new Date(anchor + mins * 60000).toISOString(), { minutes: d.minutes });
  const minutesSel = h("select", { onchange: () => { location.hash = tlHref(d.agent, d.at, { minutes: minutesSel.value, ...(params.get("alert") ? { alert: params.get("alert") } : {}) }); } },
    [15, 30, 60, 240, 720].map((m) => h("option", { value: m, selected: m === d.minutes }, "± " + (m < 60 ? m + " min" : m / 60 + " h"))));
  mount(shell("events",
    h("div", { class: "crumbs" }, h("a", { href: "#/hosts/" + d.agent }, d.host || d.agent), " / ", t("timeline")),
    h("h1", null, t("timeline") + ": " + (d.host || d.agent)),
    h("div", { class: "card" },
      h("div", { class: "flex" },
        h("span", { class: "muted" }, abs(d.from) + "  ·  " + abs(d.to)),
        h("label", { class: "right" }, t("window"), " ", minutesSel),
        h("a", { class: "btn small ghost", href: shift(-d.minutes) }, t("earlier")),
        h("a", { class: "btn small ghost", href: shift(d.minutes) }, t("later"))),
      h("div", { class: "mt" }, chips),
      d.truncated ? h("div", { class: "muted mt" }, t("truncatedRows").replace("{n}", d.records.length)) : null),
    h("div", { class: "mt" }, list)));
  draw();
}

async function pivotView(kind, value, params) {
  const days = params.get("days") || "30";
  const d = await api("/api/ui/pivot?" + new URLSearchParams({ kind, value, days }));
  const daysSel = h("select", { onchange: () => { location.hash = pivotHref(kind, value) + "?days=" + daysSel.value; } },
    [1, 7, 30, 90, 365].map((n) => h("option", { value: n, selected: String(n) === String(d.days) }, t("days30").replace("{n}", n))));
  const counts = (m) => Object.entries(m || {}).sort((a, b) => b[1] - a[1]).map(([k, n]) => h("span", { class: "chip" }, h("span", { class: "mono" }, k || "·"), " " + n));
  const label = { ip: "IP", user: t("user"), hash: "SHA-256" }[kind] || kind;
  mount(shell("events",
    h("div", { class: "crumbs" }, t("pivot"), " / ", label),
    h("h1", { class: "mono break" }, value),
    h("div", { class: "card" },
      h("div", { class: "flex" }, h("span", { class: "pill" }, label),
        kind === "ip" ? h("span", { class: "chip" }, t(d.public ? "publicAddr" : "privateAddr")) : null,
        d.intel ? h("span", { class: "pill warn" }, t("onList") + ": " + d.intel) : null,
        h("label", { class: "right" }, daysSel)),
      h("dl", { class: "kv" },
        h("dt", null, t("total")), h("dd", null, d.total),
        h("dt", null, t("firstSeen")), h("dd", null, d.first ? abs(d.first) : "·"),
        h("dt", null, t("lastSeenShort")), h("dd", null, d.last ? abs(d.last) : "·"),
        h("dt", null, t("seenOn")), h("dd", { class: "flex" }, counts(d.hosts)),
        h("dt", null, t("eventTypes")), h("dd", { class: "flex" }, counts(d.types)))),
    d.alerts.length ? [h("h2", null, t("alerts")), h("div", { class: "list" }, d.alerts.map(alertRow))] : null,
    h("h2", null, t("events")),
    d.records.length ? h("div", { class: "tablewrap" }, h("table", { class: "evtable" },
      h("thead", null, h("tr", null, [t("time"), t("host"), t("type"), t("details")].map((x) => h("th", null, x)))),
      h("tbody", null, d.records.map((r) => h("tr", null,
        h("td", { class: "nowrap" }, h("a", { href: tlHref(r.agent, r.event.ts || r.time), title: t("timeline") }, new Date(r.event.ts || r.time).toLocaleString(lang))),
        h("td", null, r.host || r.source),
        h("td", { class: "mono" }, r.event.type),
        h("td", { class: "mono" }, dataLine(r.event.data))))))) : h("div", { class: "card empty" }, t("noEvents"))));
}

// snapshotsCard lists the evidence of a host or an alert and asks for more.
async function snapshotsCard(agent, alertID) {
  const q = new URLSearchParams(alertID ? { alert: alertID } : { agent });
  const d = await api("/api/ui/snapshots?" + q);
  const note = h("span", { class: "muted" });
  const ask = can("analyst") && agent ? h("button", { class: "btn small ghost", onclick: async () => {
    try { await post("/api/ui/agents/" + agent + "/snapshot", { alert: alertID || "" }); note.textContent = t("snapshotAsked"); setTimeout(render, 45000); }
    catch (x) { note.textContent = x.message; }
  } }, t("takeSnapshot")) : null;
  const pending = d.requests.filter((r) => r.status === "pending" || r.status === "failed" || r.status === "expired").slice(0, 3);
  return h("div", { class: "card mt" },
    h("div", { class: "flex" }, h("h3", null, t("snapshots")), h("span", { class: "right flex" }, note, ask)),
    pending.map((r) => h("div", { class: "chip mt" }, h("span", { class: "dot " + (r.status === "pending" ? "pending" : "error") }),
      t("requestStatus") + " " + abs(r.created) + ": " + r.status + (r.error ? " (" + r.error + ")" : ""))),
    d.snapshots.length ? h("div", { class: "tablewrap flat mt" }, h("table", null, h("tbody", null, d.snapshots.slice(0, 20).map((x) => h("tr", null,
      h("td", { class: "nowrap" }, x.error ? abs(x.time) : h("a", { href: "#/snapshot/" + x.seq + "?at=" + encodeURIComponent(x.time) }, abs(x.time))),
      h("td", { class: "mono" }, x.trigger),
      h("td", { class: "mono" }, x.error ? h("span", { class: "muted" }, x.error) : [x.comm, x.pid ? " (" + x.pid + ")" : ""]),
      h("td", { class: "mono muted" }, x.exe || "")))))) : h("div", { class: "muted mt" }, t("noSnapshots")));
}

async function snapshotView(seq, params) {
  const recs = await api("/api/ui/records?" + new URLSearchParams({ seq, at: params.get("at") || "" }));
  const r = recs[0];
  if (!r) { mount(shell("events", h("div", { class: "card err" }, "not found"))); return; }
  const d = r.event.data;
  const tg = d.target && typeof d.target === "object" ? d.target : null;
  const table = (cols, rows) => h("div", { class: "tablewrap" }, h("table", null,
    h("thead", null, h("tr", null, cols.map((c) => h("th", null, c)))), h("tbody", null, rows)));
  const remoteLink = (addr) => {
    if (!addr) return "";
    const ip = addr.replace(/^\[/, "").replace(/\]?:\d+$/, "");
    return IP_RE.test(ip) ? h("a", { href: pivotHref("ip", ip) }, addr) : addr;
  };
  // the process list as a tree, children under their parent
  const procs = Array.isArray(d.processes) ? d.processes : [];
  const kids = new Map();
  for (const p of procs) { if (!kids.has(p.ppid)) kids.set(p.ppid, []); kids.get(p.ppid).push(p); }
  const pids = new Set(procs.map((p) => p.pid));
  const procRows = [];
  const walk = (p, depth) => {
    if (procRows.length > 1000) return;
    procRows.push(h("tr", { class: p.pid === d.pid ? "hl" : "" },
      h("td", { class: "mono" }, p.pid), h("td", { class: "mono" }, p.uid),
      h("td", { class: "mono" }, "  ".repeat(Math.min(depth, 12)) + (depth ? "└ " : "") + p.comm),
      h("td", { class: "mono muted" }, p.cmdline || p.exe || "")));
    for (const c of kids.get(p.pid) || []) walk(c, depth + 1);
  };
  for (const p of procs) if (!pids.has(p.ppid) || p.ppid === p.pid) walk(p, 0);
  mount(shell("events",
    h("div", { class: "crumbs" }, h("a", { href: "#/hosts/" + r.agent }, r.host || r.agent), " / ", t("snapshots")),
    h("h1", null, t("snapshots") + ": " + (r.host || r.agent) + ", " + abs(r.event.ts)),
    h("div", { class: "card" }, h("dl", { class: "kv" },
      h("dt", null, t("trigger")), h("dd", { class: "mono" }, d.trigger || "·"),
      d.alert ? [h("dt", null, t("alerts")), h("dd", null, h("a", { href: "#/alerts/" + d.alert }, d.alert))] : null,
      h("dt", null, t("timeline")), h("dd", null, h("a", { href: tlHref(r.agent, r.event.ts) }, "± 30 min")),
      h("dt", null, t("snapshotHash")), h("dd", { class: "mono break" }, d.sha256 || "·"),
      h("dt", null, "Seq"), h("dd", { class: "mono" }, r.seq))),
    tg ? h("div", { class: "card mt" }, h("h3", null, t("suspect")),
      tg.gone ? h("div", { class: "muted" }, t("gone") + " (pid " + tg.pid + ")") : h("dl", { class: "kv" },
        h("dt", null, "PID / UID"), h("dd", { class: "mono" }, tg.pid + " / " + tg.uid),
        h("dt", null, "exe"), h("dd", { class: "mono break" }, tg.exe),
        h("dt", null, t("programHash")), h("dd", { class: "mono break" }, tg.exe_sha256 ? h("a", { href: pivotHref("hash", tg.exe_sha256) }, tg.exe_sha256) : "·"),
        h("dt", null, "cmdline"), h("dd", { class: "mono break" }, tg.cmdline || "·"),
        h("dt", null, "cwd"), h("dd", { class: "mono" }, tg.cwd || "·"),
        tg.ld_preload ? [h("dt", null, "LD_PRELOAD"), h("dd", { class: "mono" }, tg.ld_preload)] : null,
        tg.quarantined ? [h("dt", null, t("quarantined")), h("dd", { class: "mono" }, tg.quarantined)] : null,
        tg.quarantine_error ? [h("dt", null, t("quarantined")), h("dd", { class: "muted" }, tg.quarantine_error)] : null,
        h("dt", null, t("parents")), h("dd", { class: "mono" }, (tg.ancestry || []).map((x) => h("div", null, x.pid + " " + x.comm + "  " + (x.cmdline || x.exe || "")))),
        h("dt", null, t("children")), h("dd", { class: "mono" }, (tg.children || []).map((x) => h("div", null, x.pid + " " + x.comm)), (tg.children || []).length ? null : "·"),
        h("dt", null, t("sockets")), h("dd", { class: "mono" }, (tg.sockets || []).map((c) => h("div", null, c.proto + " " + c.state + " " + c.local + " ", remoteLink(c.remote)))), 
        h("dt", null, t("openFiles")), h("dd", { class: "mono small" }, (tg.fds || []).map((x) => h("div", null, x))),
        h("dt", null, t("libraries")), h("dd", { class: "mono small" }, (tg.maps || []).map((x) => h("div", null, x))),
        h("dt", null, t("envNames")), h("dd", { class: "mono small" }, (tg.env_names || []).join(" ")))) : null,
    Array.isArray(d.sessions) && d.sessions.length ? [h("h2", null, t("sessions")), table([t("user"), "TTY", "Host", t("time")],
      d.sessions.map((x) => h("tr", null, h("td", null, entityLink("user", x.user) || x.user), h("td", { class: "mono" }, x.tty),
        h("td", { class: "mono" }, entityLink("ip", x.host) || x.host), h("td", null, abs(x.since)))))] : null,
    Array.isArray(d.connections) ? [h("h2", null, t("connections")), table(["Proto", "State", "Local", "Remote", t("process")],
      d.connections.map((c) => h("tr", null, h("td", null, c.proto), h("td", null, c.state), h("td", { class: "mono" }, c.local),
        h("td", { class: "mono" }, remoteLink(c.remote)), h("td", { class: "mono" }, c.comm ? c.comm + " (" + c.pid + ")" : "·"))))] : null,
    procs.length ? [h("h2", null, t("processes") + " (" + procs.length + ")"), table(["PID", "UID", t("process"), "cmdline"], procRows)] : null,
    Array.isArray(d.journal) ? [h("h2", null, t("journal")), h("pre", { class: "card logpre" }, d.journal.join("\n"))] : null,
    Array.isArray(d.modules) ? [h("h2", null, t("modules")), h("div", { class: "card mono small" }, d.modules.join("  "))] : null));
}

// causingEvents shows the events an alert was raised for, with diffs.
async function causingEvents(a) {
  if (!a.seqs || !a.seqs.length) return null;
  const recs = await api("/api/ui/records?" + new URLSearchParams({ seq: a.seqs.slice(0, 10).join(","), at: a.created }));
  if (!recs.length) return null;
  return [h("h2", null, t("causingEvents")), h("div", { class: "list" }, recs.map((r) => h("div", { class: "row" },
    h("span", { class: "mono muted" }, hhmmss(r.event.ts || r.time)),
    h("div", null, h("div", { class: "title mono" }, r.event.type), h("div", { class: "sub mono" }, dataLine(r.event.data)), diffBlock(r.event.data)),
    h("a", { class: "meta", href: tlHref(r.agent, r.event.ts || r.time) }, t("timeline")))))];
}

// ---------- router ----------

let refreshTimer = null;
let selftestOpen = false;
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
    else if (parts[0] === "timeline") await timelineView(params);
    else if (parts[0] === "sessions") await sessionsView(params);
    else if (parts[0] === "session") await sessionView(params);
    else if (parts[0] === "hunt") await huntView();
    else if (parts[0] === "pivot" && parts[2]) await pivotView(parts[1], decodeURIComponent(parts.slice(2).join("/")), params);
    else if (parts[0] === "snapshot" && parts[1]) await snapshotView(parts[1], params);
    else if (parts[0] === "canaries") await canariesView();
    else if (parts[0] === "suppressions") await suppressionsView();
    else if (parts[0] === "rules") await rulesView();
    else if (parts[0] === "incidents" && parts[1]) await incidentDetail(parts[1]);
    else if (parts[0] === "incidents") await incidentsView();
    else if (parts[0] === "settings") await settingsView();
    else await overview();
  } catch (x) {
    if (x.message !== "unauthorized") { console.error(x); mount(shell("", h("div", { class: "card err" }, x.message))); }
  }
  // The overview and alert list refresh themselves; forms are left alone.
  if (!parts.length || (parts[0] === "alerts" && !parts[1])) refreshTimer = setTimeout(render, 30000);
  // A running self test finishes within minutes; follow it on the host page.
  if (parts[0] === "hosts" && selftestOpen) refreshTimer = setTimeout(render, 10000);
}

window.addEventListener("hashchange", render);
render();
