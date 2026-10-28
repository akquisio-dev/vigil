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
    readable: "Readable by every user (0644), so a broken service account trips it too", readableTag: "readable",
    canaryRoots: "Canary roots", none: "none", expected: "expected", unexpected: "new",
    accept: "Accept", acceptAll: "Accept all", process: "Process", scope: "Scope", via: "Via",
    rename: "Rename", deleteHost: "Remove host", confirmDelete: "Remove this host and its canaries?",
    confirmCanary: "Remove this canary? The agent deletes the file.",
    enroll: "Enroll a host", newToken: "Create token", validUntil: "valid until", notifyTest: "Send test notification",
    updateAgent: "Update agent", upToDate: "Up to date", confirmUpdate: "Update this agent to {v}? It downloads the release, checks its signature and restarts.",
    upd_asked: "update to {v} asked", upd_staged: "{v} downloaded, installing", upd_done: "updated from {f}", upd_failed: "update to {v} failed",
    selfUpdateOff: "self_update was off at the agent's last start.",
    selftest: "Self test", runSelftest: "Run self test", noSelftests: "No self test yet.", selftestOff: "This agent does not offer self tests (older version, or selftest off in agent.json).",
    st_pending: "waiting for the agent", st_running: "running", st_passed: "passed", st_warning: "passed with warnings", st_failed: "failed",
    st_waiting: "waiting", st_ok: "detected", st_suppressed: "suppressed", st_skipped: "skipped", st_missing: "not detected", notifiedTo: "Sent to",
    notifiers: "Notifications", noNotifiers: "No notifier configured. Alerts only show up here.", delivered: "last delivered",
    neverDelivered: "nothing sent yet", failing: "failing", heartbeat: "Outside heartbeat", configured: "configured", notConfigured: "not configured",
    summary: "Daily summary", summaryAt: "daily at", summaryPreview: "Preview summary", summarySend: "Send summary now", summarySent: "Summary sent",
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
    patExact: "exactly", pat_name: "program, any pid", pat_glob: "path pattern", pat_range: "range", pat_cidr: "network",
    covers: "Open alerts that match: {n}. They are resolved when you save.",
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
    appVulns: "Application dependencies", appFiles: "{n} lock files, {m} packages", appMalicious: "Known malicious packages",
    appMissing: "No data yet for", appTruncated: "list cut short", unknownSev: "no rating", maliciousPkg: "malicious",
    containers: "Containers", ctrImage: "Image", ctrRisks: "Host access", dockerGroupLbl: "docker group (root equivalent)", vulnId: "Advisory", lockFile: "Lock file",
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
    incCopyRef: "Copy number", incCopyText: "Copy for Claude", incCopied: "Copied", incCopyTextHint: "The incident as short text with its alerts and notes, to paste into a chat with Claude or a ticket",
    incGoto: "INC-0042", incGotoHint: "Open an incident by its number", incNotFound: "No incident {r}",
    activeRules: "rules active", otherSources: "for log sources without vigil events", notConfigured: "not set up", hashLists: "Malware hashes",
    forwarding: "Forwarding", sentShort: "sent", droppedShort: "dropped", queuedShort: "waiting",
    filesDuring: "changed while the session was open", partialScan: "stopped after 20 s, shorten the period",
    attacks: "Attackers", attacksSub: "Who attacks the hosts, from where and with what", day1: "24 hours",
    attemptsN: "attempts", countries: "Countries", networks: "Networks", successTile: "Successful", targetedTile: "Aimed at us",
    campaigns: "Campaigns", worldMap: "Origin of the attacks", byCountry: "Countries", byNetwork: "Networks", netKind: "Type of network",
    net_hosting: "data centre or cloud (estimate)", net_tor: "Tor", net_other: "other networks", triedUsers: "Most tried user names",
    accountMissing: "no such account", accountShort: "exists", otherUsers: "other names", otherCountries: "other countries", otherNetworks: "other networks",
    userName: "User name", trendDays: "per day", trend24: "per hour", userRanking: "Ranking", cloudTitle: "Word cloud", heatTitle: "User names by hour",
    matrixTitle: "User names by country", sankeyTitle: "Country, user name, account", treemapTitle: "Origin by network", treemapSub: "area = attempts",
    noUserData: "No attempts per user name yet. Agents from v0.26.0 count them.", usersEstimated: "Some days come from older agents that report one total for several names; those are shared out evenly.",
    existingTried: "Tried names that exist", webAttack: "web attack", liveSeen: "{n} since opened", liveHint: "Agents report every 30 seconds, so attacks appear up to that late.",
    accountExists: "account exists", webAttacks: "Web attacks", attackPaths: "Most requested attack paths", hourOfDay: "Time of day",
    perDay: "Per day", addressesTitle: "Addresses", cls_all: "All", cls_success: "Successful", cls_targeted: "Aimed",
    cls_persistent: "Persistent", cls_noise: "Noise", r_login: "logged in after failing", r_web_ok: "attack answered with 2xx",
    r_own_account: "tried an account that exists here", r_own_name: "tried a name of these hosts", r_persistent: "came back on several days",
    r_listed: "on a threat list", r_tor: "Tor exit", r_campaign: "part of a campaign", r_wordlist: "only word list names", r_standard_user: "tried a standard user (root, ubuntu, debian, linux)",
    campaignN: "Campaign {n}", addressesN: "{n} addresses", signature: "Tries", geoOff: "Origin data is off. Set \"geoip\": true in server.json to see countries and networks.",
    geoAttr: "IP Geolocation by DB-IP", noAttacks: "No attacks in this period", building: "The statistics are being built from the log",
    origin: "Origin", network: "Network", classLabel: "Class", country: "Country", activity30: "Activity, 30 days",
    attackReport: "Report (Markdown)", attackPrint: "Report to print / PDF", loggedInAs: "logged in as", unknown: "unknown", timezoneLocal: "local time",
    sources: "Sources", sourcesSub: "Threat data from allied networks and other software, and what we share with them", sourcesTile: "Sources active", withProblems: "with problems", reported: "Reported", inTop: "in the ranking", overlapUs: "Also attacked us", ofOurs: "of our {n} attackers", firstShare: "Seen first by a source", earlyWarn: "early warnings among the shared attackers", medianLead: "Median lead", leadSub: "how much earlier a source saw our attackers", categories: "Categories", leadSame: "same hour", leadAhead: "{d} ahead", leadBehind: "{d} behind", overlapTitle: "Overlap", leadTitle: "Who saw them first", leadHint: "attackers we share", lb0: "we, over a day ahead", lb1: "we, up to a day ahead", lb2: "within an hour", lb3: "source, up to 6 h ahead", lb4: "source, 6 to 24 h ahead", lb5: "source, 1 to 3 days ahead", lb6: "source, over 3 days ahead", weFirst: "we saw them first", theyFirst: "the source saw them first", noOverlap: "No attacker seen by us and a source yet", srcTableTitle: "Sources compared", source: "Source", newPerDay: "New per day", fetchFailed: "fetch failed", staleShort: "no fetch for a day", srcHeatTitle: "When sources see attackers first", srcSankeyTitle: "Source, kind of attack, country", topReported: "Attackers reported by the most sources", seenBy: "Seen by", firstSeenBy: "First seen by", ourAttempts: "Our attempts", usLabel: "Our hosts", noSources: "No sources yet", noSourceData: "No reports from sources in this period", cat_ssh: "SSH logins", cat_web: "Web attacks", cat_web_login: "Web login attempts", cat_shell: "Web shell requests", trust_low: "trust low", trust_medium: "trust medium", trust_high: "trust high", trust: "Trust", trustHint: "Low: analytics only. Medium and high: a login from or a connection to a reported address raises an alert. Reports never start a response action.", fedConnections: "Partner connections", connectionsSub: "Partners fetch over the VPN with their own token. Nothing is ever sent on its own, and a partner cannot change anything here.", networkName: "This network", fingerprint: "Fingerprint", feedAddress: "Feed address", noListen: "No feed served: set federation.listen in server.json (a VPN address).", copy: "Copy", sharesTitle: "What we share", noShares: "Nothing shared yet", newShare: "Share with a partner", editShare: "Change share {name}", partnerName: "Partner", period: "Period", daysN: "{n} days", detail: "Detail", withCountsLong: "Attempts and first/last seen (otherwise addresses only)", withUsersLong: "Tried SSH user names (names that exist on our hosts are never shared)", minHits: "Minimum attempts per address", partnerNets: "The partner's own networks (never sent to them)", shareEnabled: "Partner may fetch", previewN: "The partner would get {n} addresses from {network}, these first:", neverShared: "Never shared, whatever is chosen: host names, our own and internal addresses, addresses that logged in, paths, processes and alert texts.", createShare: "Create share and token", save: "Save", cancel: "Cancel", edit: "Edit", rotateToken: "New token", tokenOnce: "Token for {name}. It is shown only now; pass it to the partner over a private channel.", confirmRotate: "Make a new token? The partner's current token stops working at once.", confirmShareDelete: "Stop sharing with this partner?", withCounts: "with counts", addressesOnly: "addresses only", withUsers: "with user names", minHitsN: "from {n} attempts", lastFetch: "last fetch", neverFetched: "not fetched yet", sourcesTitle: "What we fetch", newSource: "Add a source", editSource: "Change source {name}", sourceName: "Name", partnerToken: "Token from the partner", partnerFingerprint: "Fingerprint of the partner", tokenUnchanged: "unchanged", keepDaysLabel: "Keep reports (days)", keepDays: "kept {n} days", sourceEnabled: "Fetch every 15 minutes", addSource: "Add source", fetchNow: "Fetch now", confirmSourceDelete: "Remove this source and everything it reported?",
    hostsSub: "Load, memory, disks and the connections between the hosts", topology: "Connections", topologySub: "TCP between the hosts right now, the dots run from client to server. UDP (games, WireGuard) only counts as interface traffic.",
    internet: "Internet", cpu: "CPU", memory: "Memory", swap: "Swap", disk: "Disk", disks: "Disks", load: "Load", traffic: "Network", diskIO: "Disk I/O",
    netIn: "in", netOut: "out", readL: "read", writeL: "write", connections: "Connections", connIn: "incoming", connOut: "outgoing", upFor: "up for", cores: "cores",
    topProcs: "Busiest processes", interfaces: "Interfaces", peers: "Connections by remote", noMetrics: "No load data yet. Agents from v0.29.0 send it once a minute.",
    performance: "Performance", lastHour: "last hour", avgCpu: "CPU average", memUsed: "Memory used", throughput: "Throughput", hostLinks: "Between hosts",
    vigilServer: "vigil server", iowait: "waiting for disk", steal: "taken by the hypervisor", fullest: "fullest file system", used: "used", mount: "Mount", size: "Size",
    remote: "Remote", program: "Program", direction: "Direction", outgoing: "outgoing", incoming: "incoming", legendTcp: "TCP connection, line width by count",
    legendDb: "database", legendVigil: "agent to the vigil server", topoVigil: "vigil links", topoFind: "Find a host", topoFit: "Fit", topoZoomIn: "Zoom in", topoZoomOut: "Zoom out",
    topoReset: "Reset layout", topoResetAsk: "Drop your own layout of the map?", topoFull: "Full screen", topoFullEnd: "Close full screen", topoOpen: "Open host",
    topoLinks: "Links to hosts", topoAddrs: "addresses", topoHostname: "Hostname",
    legendNet: "connections to the internet", asOf: "data from", noData: "No data in this period", loadPerCore: "per core", processes: "processes", ofTotal: "of",
    hostScope: "Hosts shown", group: "Group", groups: "Groups", searchL: "Search", allRules: "All rules", anyTime: "Any time", noGrouping: "No grouping",
    byRule: "By rule", byHost: "By host", grouping: "Grouping", searchAlerts: "Title, rule or host", bulkAck: "Acknowledge all shown", bulkResolve: "Resolve all shown",
    confirmBulkAck: "Acknowledge {n} alerts?", confirmBulkResolve: "Resolve {n} alerts?", resetFilters: "Reset filters", cards: "Cards", table: "Table", rows: "List", pagePrev: "Previous page", pageNext: "Next page", hostOpen: "Open host", moreDetails: "Show details",
    allStates: "Any state", notOnline: "not online", onlyCritical: "critical or high alerts", onlyReboot: "reboot pending", noHostsFilter: "No host matches the filter",
    onlyScope: "Only {s}", attacksOnHost: "Addresses that tried {h}", attacksNoGroup: "Attacks can be narrowed to one host, not to a group. Shown for all hosts.",
    attacksHostNote: "Counts per address cover every host it tried. Hours of day and tried user names are kept for all hosts together and are left out here.",
    noGroup: "No group", onlyThisGroup: "Only this group", securityShortL: "Security updates", renameGroup: "New name of the group", confirmDeleteGroup: "Remove the group {g} from all its hosts? The hosts stay.",
    saveMembers: "Save members", newGroup: "New group", createGroup: "Create group", noGroups: "No groups yet", groupRoles: "Roles per group", baseRoleOnly: "base role only",
    ht_tabs: "Host sections", ht_overview: "Overview", ht_perf: "Performance", ht_security: "Security", ht_network: "Network", ht_software: "Software", ht_access: "Access", ht_changes: "Changes",
    close: "Close", pf_normal: "normal", pf_clickProcs: "click for programs", pf_reboot: "Reboot", pf_unzoom: "Whole range", pf_hours: "hourly values", pf_minutes: "minute values",
    pf_mark_alert: "Alerts", pf_mark_login: "Logins", pf_mark_agent: "Agent starts", pf_mark_pkg: "Packages", pf_mark_boot: "Reboots",
    pf_noProcs: "No programs recorded at this moment.", pf_procsAt: "Programs at {t}", pf_procsHour: "Programs in the hour from {t}", pf_cpuCore: "CPU (one core)",
    pf_cpuHost: "CPU (host)", pf_peak: "peak", pf_perIface: "Traffic per interface", pf_pointsDay: "points a day", pf_topCpu: "Busiest programs",
    pf_topMem: "Largest programs", pf_span: "span", pf_avgCore: "average {v} of one core", pf_ofHost: "of the host", pf_seenN: "in {n} samples",
    pf_forecast: "Outlook", pf_diskNow: "Fullest disk", pf_diskTrend: "Disk trend", pf_diskFull: "Full", pf_inDays: "in about {n} days", pf_notFilling: "not filling up",
    pf_tooShort: "needs two days of data", pf_memTrend: "Memory trend", pf_bandWeek: "per hour of the week", pf_bandDay: "per hour of the day, until three weeks are known",
    ht_openInc: "Open incidents", ht_allHostsCount: "attempts on all hosts", ht_inSessions: "in {n} sessions", ht_new: "new", ht_noReport: "no report yet", ht_secUpdates: "Security updates", ht_oldestDays: "oldest open for {n} days", ht_oldestOpen: "Oldest open",
    ht_exploitedN: "exploited", ht_allSev: "all severities", ht_publicPorts: "Public ports", ht_unexpected: "unexpected", ht_unexpectedOne: "unexpected", ht_allExpected: "all expected",
    ht_diskMem: "Disk and memory", ht_openAlerts: "Open alerts", ht_alerts30: "Alerts", ht_mttaHost: "median, this host, 30 days", ht_alertsMonth: "Alerts per day, 30 days",
    ht_latestEvents: "Latest events", ht_olderThan: "open for longer than {n} days", ht_openSince: "Open since", ht_destinations: "Outbound destinations",
    ht_partial: "The scan of the log ran out of time; the result is incomplete.", ht_newDest: "Destinations by first contact", ht_public: "public", ht_private: "private",
    ht_firstSeen: "First seen", ht_origin: "Country and network", ht_noDest: "No outbound connections in this period.", ht_destByProg: "Destinations per program",
    ht_portHistory: "Port history", ht_opened: "Opened", ht_closed: "Closed", ht_times: "Times opened", ht_volume: "Data sent and received per hour, 14 days",
    ht_sent: "sent", ht_received: "received", ht_sevLabel: "Severity", ht_ecosystem: "Ecosystem", ht_allEco: "all ecosystems", ht_onlyExploited: "only exploited or malicious",
    ht_vulnList: "Weaknesses", ht_exploited: "exploited", ht_noMatch: "Nothing matches the filter.", ht_lockfiles: "Lock files",
    ht_loginHeat: "Logins by user and hour", ht_loginsN: "logins", ht_usersN: "Users", ht_keysN: "keys or methods", ht_sources: "Source addresses", ht_newSources: "new in 7 days",
    ht_countriesN: "countries", ht_rollupWait: "being counted", ht_commandsN: "Commands", ht_failedDay: "Failed logins per day", ht_keys: "Keys and methods", ht_lastUse: "Last used",
    ht_attackersHost: "Attackers of this host", ht_topAttackers: "Most attempts", ht_duration: "Duration",
    ht_changesTitle: "What changed on this host", ht_truncated: "Only the newest 1000 changes are shown.", ht_noChanges: "No changes in this period.",
    ht_diffOnTimeline: "lines on the timeline", ht_pkgSummary: "Packages: {a} added, {r} removed, {c} updated",
    ck_file: "File", ck_systemd: "Systemd", ck_cron: "Cron", ck_keys: "Key", ck_users: "Account", ck_ports: "Port", ck_programs: "Program", ck_packages: "Packages",
    ck_kernel: "Kernel", ck_containers: "Container", ck_agent: "Agent",
    ch_file_added: "Added", ch_file_changed: "Changed", ch_file_removed: "Removed", ch_file_suid: "New SUID file", ch_file_suid_removed: "SUID file gone",
    ch_ssh_key_added: "Key added", ch_ssh_key_removed: "Key removed", ch_user_added: "Account added", ch_user_removed: "Account removed", ch_user_uid_changed: "Account ID changed",
    ch_port_opened: "Port opened", ch_port_closed: "Port closed", ch_process_rare: "New program", ch_process_rare_child: "New program start",
    ch_kernel_module_loaded: "Module loaded", ch_kernel_module_unloaded: "Module unloaded", ch_agent_started: "Agent started", ch_agent_stopping: "Agent stopped", ch_agent_update: "Agent update",
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
    readable: "Für alle Benutzer lesbar (0644), dann löst auch ein geknackter Dienst ihn aus", readableTag: "lesbar",
    canaryRoots: "Köder-Wurzeln", none: "keine", expected: "erwartet", unexpected: "neu",
    accept: "Erlauben", acceptAll: "Alle erlauben", process: "Prozess", scope: "Bereich", via: "Über",
    rename: "Umbenennen", deleteHost: "Host entfernen", confirmDelete: "Diesen Host und seine Köder entfernen?",
    confirmCanary: "Köder entfernen? Der Agent löscht die Datei.",
    enroll: "Host einschreiben", newToken: "Token erzeugen", validUntil: "gültig bis", notifyTest: "Testnachricht senden",
    updateAgent: "Agent aktualisieren", upToDate: "Aktuell", confirmUpdate: "Diesen Agent auf {v} aktualisieren? Er lädt das Release, prüft die Signatur und startet neu.",
    upd_asked: "Update auf {v} angefragt", upd_staged: "{v} geladen, wird installiert", upd_done: "aktualisiert von {f}", upd_failed: "Update auf {v} fehlgeschlagen",
    selfUpdateOff: "self_update war beim letzten Start des Agents aus.",
    selftest: "Selbsttest", runSelftest: "Selbsttest starten", noSelftests: "Noch kein Selbsttest.", selftestOff: "Dieser Agent bietet keinen Selbsttest an (ältere Version oder selftest in agent.json aus).",
    st_pending: "wartet auf den Agenten", st_running: "läuft", st_passed: "bestanden", st_warning: "bestanden mit Hinweisen", st_failed: "fehlgeschlagen",
    st_waiting: "ausstehend", st_ok: "erkannt", st_suppressed: "unterdrückt", st_skipped: "übersprungen", st_missing: "nicht erkannt", notifiedTo: "Gesendet an",
    notifiers: "Benachrichtigungen", noNotifiers: "Keine Benachrichtigung eingerichtet. Alarme erscheinen nur hier.", delivered: "zuletzt zugestellt",
    neverDelivered: "noch nichts gesendet", failing: "fehlerhaft", heartbeat: "Herzschlag nach außen", configured: "eingerichtet", notConfigured: "nicht eingerichtet",
    summary: "Tagesbericht", summaryAt: "täglich um", summaryPreview: "Tagesbericht ansehen", summarySend: "Tagesbericht jetzt senden", summarySent: "Tagesbericht gesendet",
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
    patExact: "genau", pat_name: "Programm, jede PID", pat_glob: "Pfadmuster", pat_range: "Bereich", pat_cidr: "Netz",
    covers: "Passende offene Alarme: {n}. Sie werden beim Speichern geschlossen.",
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
    appVulns: "Abhängigkeiten von Anwendungen", appFiles: "{n} Lock-Dateien, {m} Pakete", appMalicious: "Bekannte Schadpakete",
    appMissing: "Noch keine Daten für", appTruncated: "Liste gekürzt", unknownSev: "ohne Einstufung", maliciousPkg: "Schadpaket",
    containers: "Container", ctrImage: "Image", ctrRisks: "Zugriff auf den Host", dockerGroupLbl: "Gruppe docker (wie root)", vulnId: "Meldung", lockFile: "Lock-Datei",
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
    incCopyRef: "Nummer kopieren", incCopied: "Kopiert", incCopyText: "Für Claude kopieren", incCopyTextHint: "Der Vorfall als kurzer Text mit Alarmen und Notizen, zum Einfügen in einen Chat mit Claude oder ein Ticket",
    incGoto: "INC-0042", incGotoHint: "Vorfall über seine Nummer öffnen", incNotFound: "Kein Vorfall {r}",
    activeRules: "Regeln aktiv", otherSources: "für Quellen ohne vigil-Ereignisse", notConfigured: "nicht eingerichtet", hashLists: "Schadsoftware-Hashes",
    forwarding: "Weiterleitung", sentShort: "gesendet", droppedShort: "verworfen", queuedShort: "wartend",
    filesDuring: "geändert, während die Sitzung offen war", partialScan: "nach 20 s abgebrochen, Zeitraum verkürzen",
    attacks: "Angreifer", attacksSub: "Wer die Hosts angreift, von wo und womit", day1: "24 Stunden",
    attemptsN: "Versuche", countries: "Länder", networks: "Netze", successTile: "Erfolgreich", targetedTile: "Gezielt auf uns",
    campaigns: "Kampagnen", worldMap: "Herkunft der Angriffe", byCountry: "Länder", byNetwork: "Netze", netKind: "Art des Netzes",
    net_hosting: "Rechenzentrum oder Cloud (geschätzt)", net_tor: "Tor", net_other: "sonstige Netze", triedUsers: "Meistversuchte Benutzernamen",
    accountMissing: "kein solches Konto", accountShort: "existiert", otherUsers: "andere Namen", otherCountries: "andere Länder", otherNetworks: "andere Netze",
    userName: "Benutzername", trendDays: "pro Tag", trend24: "pro Stunde", userRanking: "Rangliste", cloudTitle: "Wortwolke", heatTitle: "Benutzernamen nach Uhrzeit",
    matrixTitle: "Benutzernamen nach Land", sankeyTitle: "Land, Benutzername, Konto", treemapTitle: "Herkunft nach Netz", treemapSub: "Fläche = Versuche",
    noUserData: "Noch keine Versuche pro Benutzername. Agents ab v0.26.0 zählen sie.", usersEstimated: "Einige Tage stammen von älteren Agents, die eine Summe für mehrere Namen melden; die ist gleichmäßig aufgeteilt.",
    existingTried: "Versuchte Namen, die existieren", webAttack: "Web-Angriff", liveSeen: "{n} seit geöffnet", liveHint: "Agents melden alle 30 Sekunden, Angriffe erscheinen also bis zu so spät.",
    accountExists: "Konto existiert", webAttacks: "Web-Angriffe", attackPaths: "Meistabgefragte Angriffspfade", hourOfDay: "Tageszeit",
    perDay: "Pro Tag", addressesTitle: "Adressen", cls_all: "Alle", cls_success: "Erfolgreich", cls_targeted: "Gezielt",
    cls_persistent: "Hartnäckig", cls_noise: "Rauschen", r_login: "nach Fehlversuchen angemeldet", r_web_ok: "Angriff mit 2xx beantwortet",
    r_own_account: "hat ein hier existierendes Konto versucht", r_own_name: "hat einen Namen dieser Hosts versucht", r_persistent: "an mehreren Tagen wiedergekommen",
    r_listed: "auf einer Bedrohungsliste", r_tor: "Tor-Ausgang", r_campaign: "Teil einer Kampagne", r_wordlist: "nur Namen aus Wortlisten", r_standard_user: "hat einen Standardnutzer versucht (root, ubuntu, debian, linux)",
    campaignN: "Kampagne {n}", addressesN: "{n} Adressen", signature: "Versucht", geoOff: "Herkunftsdaten sind aus. Mit \"geoip\": true in server.json erscheinen Länder und Netze.",
    geoAttr: "IP Geolocation by DB-IP", noAttacks: "Keine Angriffe in diesem Zeitraum", building: "Die Statistik wird gerade aus dem Log aufgebaut",
    origin: "Herkunft", network: "Netz", classLabel: "Einstufung", country: "Land", activity30: "Aktivität, 30 Tage",
    attackReport: "Bericht (Markdown)", attackPrint: "Bericht drucken / PDF", loggedInAs: "angemeldet als", unknown: "unbekannt", timezoneLocal: "Ortszeit",
    sources: "Quellen", sourcesSub: "Bedrohungsdaten von verbündeten Netzen und anderer Software, und was wir mit ihnen teilen", sourcesTile: "Aktive Quellen", withProblems: "mit Problemen", reported: "Gemeldet", inTop: "in der Rangliste", overlapUs: "Griffen auch uns an", ofOurs: "unserer {n} Angreifer", firstShare: "Zuerst von einer Quelle gesehen", earlyWarn: "Frühwarnungen unter den gemeinsamen Angreifern", medianLead: "Vorlauf (Median)", leadSub: "wie viel früher eine Quelle unsere Angreifer sah", categories: "Kategorien", leadSame: "gleiche Stunde", leadAhead: "{d} früher", leadBehind: "{d} später", overlapTitle: "Überschneidung", leadTitle: "Wer sah sie zuerst", leadHint: "gemeinsame Angreifer", lb0: "wir, über einen Tag früher", lb1: "wir, bis einen Tag früher", lb2: "innerhalb einer Stunde", lb3: "Quelle, bis 6 h früher", lb4: "Quelle, 6 bis 24 h früher", lb5: "Quelle, 1 bis 3 Tage früher", lb6: "Quelle, über 3 Tage früher", weFirst: "wir sahen sie zuerst", theyFirst: "die Quelle sah sie zuerst", noOverlap: "Noch kein Angreifer, den wir und eine Quelle gesehen haben", srcTableTitle: "Quellen im Vergleich", source: "Quelle", newPerDay: "Neu pro Tag", fetchFailed: "Abruf fehlgeschlagen", staleShort: "seit einem Tag kein Abruf", srcHeatTitle: "Wann Quellen Angreifer zuerst sehen", srcSankeyTitle: "Quelle, Angriffsart, Land", topReported: "Angreifer, die die meisten Quellen melden", seenBy: "Gesehen von", firstSeenBy: "Zuerst gesehen von", ourAttempts: "Unsere Versuche", usLabel: "Unsere Hosts", noSources: "Noch keine Quellen", noSourceData: "Keine Meldungen von Quellen in diesem Zeitraum", cat_ssh: "SSH-Anmeldungen", cat_web: "Web-Angriffe", cat_web_login: "Web-Anmeldeversuche", cat_shell: "Webshell-Aufrufe", trust_low: "Vertrauen niedrig", trust_medium: "Vertrauen mittel", trust_high: "Vertrauen hoch", trust: "Vertrauen", trustHint: "Niedrig: nur Analyse. Mittel und hoch: eine Anmeldung von oder eine Verbindung zu einer gemeldeten Adresse löst einen Alarm aus. Meldungen starten nie eine Gegenmaßnahme.", fedConnections: "Partnerverbindungen", connectionsSub: "Partner holen über das VPN mit eigenem Token ab. Von selbst wird nie etwas verschickt, und ein Partner kann hier nichts ändern.", networkName: "Dieses Netz", fingerprint: "Fingerabdruck", feedAddress: "Feed-Adresse", noListen: "Kein Feed: federation.listen in server.json setzen (eine VPN-Adresse).", copy: "Kopieren", sharesTitle: "Was wir teilen", noShares: "Noch nichts geteilt", newShare: "Mit einem Partner teilen", editShare: "Freigabe {name} ändern", partnerName: "Partner", period: "Zeitraum", daysN: "{n} Tage", detail: "Detail", withCountsLong: "Versuche und erstes/letztes Auftreten (sonst nur Adressen)", withUsersLong: "Versuchte SSH-Nutzernamen (Namen, die es auf unseren Hosts gibt, werden nie geteilt)", minHits: "Mindestzahl Versuche pro Adresse", partnerNets: "Eigene Netze des Partners (gehen nie an ihn)", shareEnabled: "Partner darf abholen", previewN: "Der Partner bekäme {n} Adressen von {network}, als Erstes diese:", neverShared: "Nie geteilt, egal was gewählt ist: Hostnamen, eigene und interne Adressen, Adressen mit erfolgreicher Anmeldung, Pfade, Prozesse und Alarmtexte.", createShare: "Freigabe und Token erstellen", save: "Speichern", cancel: "Abbrechen", edit: "Bearbeiten", rotateToken: "Neuer Token", tokenOnce: "Token für {name}. Er wird nur jetzt angezeigt; gib ihn dem Partner über einen privaten Weg.", confirmRotate: "Neuen Token erstellen? Der bisherige Token des Partners funktioniert sofort nicht mehr.", confirmShareDelete: "Teilen mit diesem Partner beenden?", withCounts: "mit Zahlen", addressesOnly: "nur Adressen", withUsers: "mit Nutzernamen", minHitsN: "ab {n} Versuchen", lastFetch: "letzter Abruf", neverFetched: "noch nicht abgeholt", sourcesTitle: "Was wir abholen", newSource: "Quelle hinzufügen", editSource: "Quelle {name} ändern", sourceName: "Name", partnerToken: "Token vom Partner", partnerFingerprint: "Fingerabdruck des Partners", tokenUnchanged: "unverändert", keepDaysLabel: "Meldungen behalten (Tage)", keepDays: "{n} Tage behalten", sourceEnabled: "Alle 15 Minuten abholen", addSource: "Quelle hinzufügen", fetchNow: "Jetzt abholen", confirmSourceDelete: "Diese Quelle und alles, was sie gemeldet hat, entfernen?",
    hostsSub: "Last, Speicher, Platten und die Verbindungen zwischen den Hosts", topology: "Verbindungen", topologySub: "TCP zwischen den Hosts in diesem Moment, die Punkte laufen vom Client zum Server. UDP (Spiele, WireGuard) zählt nur im Schnittstellenverkehr.",
    internet: "Internet", cpu: "CPU", memory: "Arbeitsspeicher", swap: "Swap", disk: "Platte", disks: "Platten", load: "Last", traffic: "Netzwerk", diskIO: "Platten-E/A",
    netIn: "ein", netOut: "aus", readL: "lesen", writeL: "schreiben", connections: "Verbindungen", connIn: "eingehend", connOut: "ausgehend", upFor: "läuft seit", cores: "Kerne",
    topProcs: "Aktivste Prozesse", interfaces: "Schnittstellen", peers: "Verbindungen nach Gegenstelle", noMetrics: "Noch keine Lastdaten. Agents ab v0.29.0 senden sie einmal pro Minute.",
    performance: "Leistung", lastHour: "letzte Stunde", avgCpu: "CPU im Schnitt", memUsed: "Speicher belegt", throughput: "Durchsatz", hostLinks: "Zwischen Hosts",
    vigilServer: "vigil-Server", iowait: "wartet auf Platte", steal: "vom Hypervisor belegt", fullest: "vollstes Dateisystem", used: "belegt", mount: "Einhängepunkt", size: "Größe",
    remote: "Gegenstelle", program: "Programm", direction: "Richtung", outgoing: "ausgehend", incoming: "eingehend", legendTcp: "TCP-Verbindung, Linienstärke nach Anzahl",
    legendDb: "Datenbank", legendVigil: "Agent zum vigil-Server", topoVigil: "vigil-Verbindungen", topoFind: "Host suchen", topoFit: "Einpassen", topoZoomIn: "Vergrößern", topoZoomOut: "Verkleinern",
    topoReset: "Anordnung zurücksetzen", topoResetAsk: "Eigene Anordnung der Karte verwerfen?", topoFull: "Vollbild", topoFullEnd: "Vollbild beenden", topoOpen: "Host öffnen",
    topoLinks: "Verbindungen zu Hosts", topoAddrs: "Adressen", topoHostname: "Rechnername",
    legendNet: "Verbindungen ins Internet", asOf: "Stand", noData: "Keine Daten in diesem Zeitraum", loadPerCore: "pro Kern", processes: "Prozesse", ofTotal: "von",
    hostScope: "Angezeigte Hosts", group: "Gruppe", groups: "Gruppen", searchL: "Suche", allRules: "Alle Regeln", anyTime: "Gesamter Zeitraum", noGrouping: "Nicht gruppiert",
    byRule: "Nach Regel", byHost: "Nach Host", grouping: "Gruppierung", searchAlerts: "Titel, Regel oder Host", bulkAck: "Alle angezeigten bestätigen", bulkResolve: "Alle angezeigten erledigen",
    confirmBulkAck: "{n} Alarme bestätigen?", confirmBulkResolve: "{n} Alarme als erledigt markieren?", resetFilters: "Filter zurücksetzen", cards: "Karten", table: "Tabelle", rows: "Liste", pagePrev: "Vorherige Seite", pageNext: "Nächste Seite", hostOpen: "Host öffnen", moreDetails: "Details zeigen",
    allStates: "Jeder Zustand", notOnline: "nicht online", onlyCritical: "kritische oder hohe Alarme", onlyReboot: "Neustart nötig", noHostsFilter: "Kein Host passt zum Filter",
    onlyScope: "Nur {s}", attacksOnHost: "Adressen, die {h} angegriffen haben", attacksNoGroup: "Angriffe lassen sich auf einen Host eingrenzen, nicht auf eine Gruppe. Angezeigt für alle Hosts.",
    attacksHostNote: "Die Zahlen je Adresse umfassen alle Hosts, die sie angegriffen hat. Tageszeiten und versuchte Benutzernamen gibt es nur für alle Hosts zusammen, sie fehlen hier.",
    noGroup: "Ohne Gruppe", onlyThisGroup: "Nur diese Gruppe", securityShortL: "Sicherheitsupdates", renameGroup: "Neuer Name der Gruppe", confirmDeleteGroup: "Die Gruppe {g} bei allen Hosts entfernen? Die Hosts bleiben.",
    saveMembers: "Mitglieder speichern", newGroup: "Neue Gruppe", createGroup: "Gruppe anlegen", noGroups: "Noch keine Gruppen", groupRoles: "Rollen je Gruppe", baseRoleOnly: "nur Grundrolle",
    ht_tabs: "Bereiche des Hosts", ht_overview: "Überblick", ht_perf: "Leistung", ht_security: "Sicherheit", ht_network: "Netzwerk", ht_software: "Software", ht_access: "Zugänge", ht_changes: "Änderungen",
    close: "Schließen", pf_normal: "normal", pf_clickProcs: "Klick zeigt Programme", pf_reboot: "Neustart", pf_unzoom: "Ganzer Zeitraum", pf_hours: "Stundenwerte", pf_minutes: "Minutenwerte",
    pf_mark_alert: "Alarme", pf_mark_login: "Anmeldungen", pf_mark_agent: "Agent-Starts", pf_mark_pkg: "Pakete", pf_mark_boot: "Neustarts",
    pf_noProcs: "Zu diesem Zeitpunkt sind keine Programme erfasst.", pf_procsAt: "Programme um {t}", pf_procsHour: "Programme in der Stunde ab {t}", pf_cpuCore: "CPU (ein Kern)",
    pf_cpuHost: "CPU (Host)", pf_peak: "Spitze", pf_perIface: "Verkehr je Schnittstelle", pf_pointsDay: "Punkte pro Tag", pf_topCpu: "Fleißigste Programme",
    pf_topMem: "Größte Programme", pf_span: "Ausschnitt", pf_avgCore: "im Mittel {v} eines Kerns", pf_ofHost: "des Hosts", pf_seenN: "in {n} Messungen",
    pf_forecast: "Ausblick", pf_diskNow: "Vollste Platte", pf_diskTrend: "Trend Platte", pf_diskFull: "Voll", pf_inDays: "in etwa {n} Tagen", pf_notFilling: "füllt sich nicht",
    pf_tooShort: "braucht zwei Tage Daten", pf_memTrend: "Trend Speicher", pf_bandWeek: "je Stunde der Woche", pf_bandDay: "je Stunde des Tages, bis drei Wochen bekannt sind",
    ht_openInc: "Offene Vorfälle", ht_allHostsCount: "Versuche auf allen Hosts", ht_inSessions: "in {n} Sitzungen", ht_new: "neu", ht_noReport: "noch kein Bericht", ht_secUpdates: "Sicherheitsupdates", ht_oldestDays: "ältestes seit {n} Tagen offen", ht_oldestOpen: "Ältestes offen",
    ht_exploitedN: "ausgenutzt", ht_allSev: "alle Schweregrade", ht_publicPorts: "Öffentliche Ports", ht_unexpected: "unerwartet", ht_unexpectedOne: "unerwartet", ht_allExpected: "alle erwartet",
    ht_diskMem: "Platte und Speicher", ht_openAlerts: "Offene Alarme", ht_alerts30: "Alarme", ht_mttaHost: "Median, dieser Host, 30 Tage", ht_alertsMonth: "Alarme pro Tag, 30 Tage",
    ht_latestEvents: "Letzte Ereignisse", ht_olderThan: "länger als {n} Tage offen", ht_openSince: "Offen seit", ht_destinations: "Ausgehende Ziele",
    ht_partial: "Die Suche im Protokoll hat die Zeit überschritten, das Ergebnis ist unvollständig.", ht_newDest: "Ziele nach erstem Kontakt", ht_public: "öffentlich", ht_private: "privat",
    ht_firstSeen: "Zuerst gesehen", ht_origin: "Land und Netz", ht_noDest: "Keine ausgehenden Verbindungen in diesem Zeitraum.", ht_destByProg: "Ziele je Programm",
    ht_portHistory: "Verlauf der Ports", ht_opened: "Geöffnet", ht_closed: "Geschlossen", ht_times: "Mal geöffnet", ht_volume: "Gesendet und empfangen pro Stunde, 14 Tage",
    ht_sent: "gesendet", ht_received: "empfangen", ht_sevLabel: "Schweregrad", ht_ecosystem: "Ökosystem", ht_allEco: "alle Ökosysteme", ht_onlyExploited: "nur ausgenutzt oder bösartig",
    ht_vulnList: "Schwachstellen", ht_exploited: "ausgenutzt", ht_noMatch: "Nichts passt zum Filter.", ht_lockfiles: "Lockfiles",
    ht_loginHeat: "Anmeldungen nach Benutzer und Stunde", ht_loginsN: "Anmeldungen", ht_usersN: "Benutzer", ht_keysN: "Schlüssel oder Verfahren", ht_sources: "Herkunftsadressen", ht_newSources: "neu in 7 Tagen",
    ht_countriesN: "Länder", ht_rollupWait: "wird gezählt", ht_commandsN: "Befehle", ht_failedDay: "Fehlversuche pro Tag", ht_keys: "Schlüssel und Verfahren", ht_lastUse: "Zuletzt",
    ht_attackersHost: "Angreifer dieses Hosts", ht_topAttackers: "Meiste Versuche", ht_duration: "Dauer",
    ht_changesTitle: "Was sich auf diesem Host geändert hat", ht_truncated: "Nur die neuesten 1000 Änderungen werden gezeigt.", ht_noChanges: "Keine Änderungen in diesem Zeitraum.",
    ht_diffOnTimeline: "Zeilen in der Zeitachse", ht_pkgSummary: "Pakete: {a} neu, {r} entfernt, {c} aktualisiert",
    ck_file: "Datei", ck_systemd: "Systemd", ck_cron: "Cron", ck_keys: "Schlüssel", ck_users: "Konto", ck_ports: "Port", ck_programs: "Programm", ck_packages: "Pakete",
    ck_kernel: "Kernel", ck_containers: "Container", ck_agent: "Agent",
    ch_file_added: "Neu", ch_file_changed: "Geändert", ch_file_removed: "Entfernt", ch_file_suid: "Neue SUID-Datei", ch_file_suid_removed: "SUID-Datei weg",
    ch_ssh_key_added: "Schlüssel hinzugefügt", ch_ssh_key_removed: "Schlüssel entfernt", ch_user_added: "Konto angelegt", ch_user_removed: "Konto entfernt", ch_user_uid_changed: "Konto-ID geändert",
    ch_port_opened: "Port geöffnet", ch_port_closed: "Port geschlossen", ch_process_rare: "Neues Programm", ch_process_rare_child: "Neuer Programmstart",
    ch_kernel_module_loaded: "Modul geladen", ch_kernel_module_unloaded: "Modul entladen", ch_agent_started: "Agent gestartet", ch_agent_stopping: "Agent beendet", ch_agent_update: "Agent-Update",
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
    if (me) { me = null; topo.pos = null; live.doc = null; render(); }
    throw new Error("unauthorized");
  }
  if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
  return res.json();
}

const post = (path, body = {}) => api(path, { method: "POST", body });

// newerVersion compares release tags like v0.19.0; anything else is never newer.
function newerVersion(a, b) {
  const p = (v) => /^v(\d+)\.(\d+)\.(\d+)$/.exec(v || "");
  const x = p(a), y = p(b);
  if (!x || !y) return false;
  for (let i = 1; i <= 3; i++) if (Number(x[i]) !== Number(y[i])) return Number(x[i]) > Number(y[i]);
  return false;
}
const RANK = { viewer: 1, analyst: 2, admin: 3 };
// can(role, agent): the base role, raised by the account's role for the
// groups of that host (as the server decides it, see roles.go). agent ""
// asks for the base role only.
const can = (role, agent) => {
  if (!me) return false;
  let r = RANK[me.role] || 3;
  const gr = me.group_roles || {};
  if (agent && Object.keys(gr).length) {
    const host = (scopeHosts || []).find((x) => x.id === agent);
    for (const g of (host && host.tags) || []) for (const [k, v] of Object.entries(gr)) if (k.toLowerCase() === g.toLowerCase()) r = Math.max(r, RANK[v] || 0);
  }
  return r >= RANK[role];
};
// anyGroupRole: the account is at least role for some group
const anyGroupRole = (role) => Object.values((me && me.group_roles) || {}).some((v) => (RANK[v] || 0) >= RANK[role]);
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
const ICONS = {"affiliate": ["M5.931 6.936l1.275 4.249m5.607 5.609l4.251 1.275", "M11.683 12.317l5.759 -5.759", "M5.5 5.5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0 -3 0", "M18.5 5.5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0 -3 0", "M18.5 18.5m-1.5 0a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0 -3 0", "M8.5 15.5m-4.5 0a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0 -9 0"], "world": ["M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0", "M3.6 9h16.8", "M3.6 15h16.8", "M11.5 3a17 17 0 0 0 0 18", "M12.5 3a17 17 0 0 1 0 18"], "terminal-2": ["M8 9l3 3l-3 3", "M13 15l3 0", "M3 4m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z"], "radar": ["M21 12h-8a1 1 0 1 0 -1 1v8a9 9 0 0 0 9 -9", "M16 9a5 5 0 1 0 -7 7", "M20.486 9a9 9 0 1 0 -11.482 11.495"], "key": ["M16.555 3.843l3.602 3.602a2.877 2.877 0 0 1 0 4.069l-2.643 2.643a2.877 2.877 0 0 1 -4.069 0l-.301 -.301l-6.558 6.558a2 2 0 0 1 -1.239 .578l-.175 .008h-1.172a1 1 0 0 1 -.993 -.883l-.007 -.117v-1.172a2 2 0 0 1 .467 -1.284l.119 -.13l.414 -.414h2v-2h2v-2l2.144 -2.144l-.301 -.301a2.877 2.877 0 0 1 0 -4.069l2.643 -2.643a2.877 2.877 0 0 1 4.069 0z", "M15 9h.01"], "book": ["M3 19a9 9 0 0 1 9 0a9 9 0 0 1 9 0", "M3 6a9 9 0 0 1 9 0a9 9 0 0 1 9 0", "M3 6l0 13", "M12 6l0 13", "M21 6l0 13"], "stack-2": ["M12 4l-8 4l8 4l8 -4l-8 -4", "M4 12l8 4l8 -4", "M4 16l8 4l8 -4"], "bell-off": ["M9.346 5.353c.21 -.129 .428 -.246 .654 -.353a2 2 0 1 1 4 0a7 7 0 0 1 4 6v3m-1 3h-13a4 4 0 0 0 2 -3v-3a6.996 6.996 0 0 1 1.273 -3.707", "M9 17v1a3 3 0 0 0 6 0v-1", "M3 3l18 18"], "clock": ["M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0", "M12 7v5l3 3"], "user-x": ["M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0", "M6 21v-2a4 4 0 0 1 4 -4h3.5", "M22 22l-5 -5", "M17 22l5 -5"], "plus": ["M12 5l0 14", "M5 12l14 0"], "alert-triangle": ["M12 9v4", "M10.363 3.591l-8.106 13.534a1.914 1.914 0 0 0 1.636 2.871h16.214a1.914 1.914 0 0 0 1.636 -2.87l-8.106 -13.536a1.914 1.914 0 0 0 -3.274 0z", "M12 16h.01"], "fish-hook": ["M16 9v6a5 5 0 0 1 -10 0v-4l3 3", "M16 7m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M16 5v-2"], "layout-dashboard": ["M5 4h4a1 1 0 0 1 1 1v6a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-6a1 1 0 0 1 1 -1", "M5 16h4a1 1 0 0 1 1 1v2a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-2a1 1 0 0 1 1 -1", "M15 12h4a1 1 0 0 1 1 1v6a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-6a1 1 0 0 1 1 -1", "M15 4h4a1 1 0 0 1 1 1v2a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1v-2a1 1 0 0 1 1 -1"], "list-details": ["M13 5h8", "M13 9h5", "M13 15h8", "M13 19h5", "M3 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z", "M3 14m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"], "logout": ["M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2", "M9 12h12l-3 -3", "M18 15l3 -3"], "server": ["M3 4m0 3a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z", "M3 12m0 3a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v2a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z", "M7 8l0 .01", "M7 16l0 .01"], "settings": ["M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065z", "M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0"], "shield-check": ["M11.46 20.846a12 12 0 0 1 -7.96 -14.846a12 12 0 0 0 8.5 -3a12 12 0 0 0 8.5 3a12 12 0 0 1 -.09 7.06", "M15 19l2 2l4 -4"], "brand-debian": ["M12 17c-2.397 -.943 -4 -3.153 -4 -5.635c0 -2.19 1.039 -3.14 1.604 -3.595c2.646 -2.133 6.396 -.27 6.396 3.23c0 2.5 -2.905 2.121 -3.5 1.5c-.595 -.621 -1 -1.5 -.5 -2.5", "M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0"], "brand-ubuntu": ["M12 5m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M17.723 7.41a7.992 7.992 0 0 0 -3.74 -2.162m-3.971 0a7.993 7.993 0 0 0 -3.789 2.216m-1.881 3.215a8 8 0 0 0 -.342 2.32c0 .738 .1 1.453 .287 2.132m1.96 3.428a7.993 7.993 0 0 0 3.759 2.19m4 0a7.993 7.993 0 0 0 3.747 -2.186m1.962 -3.43a8.008 8.008 0 0 0 .287 -2.131c0 -.764 -.107 -1.503 -.307 -2.203", "M5 17m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M19 17m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0"], "brand-redhat": ["M6 10.5l1.436 -4c.318 -.876 .728 -1.302 1.359 -1.302c.219 0 1.054 .365 1.88 .583c.825 .219 .733 -.329 .908 -.487c.176 -.158 .355 -.294 .61 -.294c.242 0 .553 .048 1.692 .448c.759 .267 1.493 .574 2.204 .922c1.175 .582 1.426 .913 1.595 1.507l.816 4.623c2.086 .898 3.5 2.357 3.5 3.682c0 1.685 -1.2 3.818 -5.957 3.818c-6.206 0 -14.043 -4.042 -14.043 -7.32c0 -1.044 1.333 -1.77 4 -2.18z", "M6 10.5c0 .969 4.39 3.5 9.5 3.5c1.314 0 3 .063 3 -1.5"], "cpu": ["M5 5m0 1a1 1 0 0 1 1 -1h12a1 1 0 0 1 1 1v12a1 1 0 0 1 -1 1h-12a1 1 0 0 1 -1 -1z", "M9 9h6v6h-6z", "M3 10h2", "M3 14h2", "M10 3v2", "M14 3v2", "M21 10h-2", "M21 14h-2", "M14 21v-2", "M10 21v-2"], "adjustments-horizontal": ["M14 6m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M4 6l8 0", "M16 6l4 0", "M8 12m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M4 12l2 0", "M10 12l10 0", "M17 18m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M4 18l11 0", "M19 18l1 0"], "chevron-down": ["M6 9l6 6l6 -6"], "chevron-left": ["M15 6l-6 6l6 6"], "chevron-right": ["M9 6l6 6l-6 6"], "layout-grid": ["M4 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z", "M14 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z", "M4 14m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z", "M14 14m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z"]};

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
  ["sectionOverview", [["overview", "#/", "layout-dashboard"], ["hosts", "#/hosts", "server"]]],
  ["sectionDetect", [["incidents", "#/incidents", "stack-2"], ["alerts", "#/alerts", "alert-triangle"], ["events", "#/events", "list-details"], ["sessions", "#/sessions", "terminal-2"], ["hunt", "#/hunt", "radar"], ["attacks", "#/attacks", "world"], ["sources", "#/sources", "affiliate"], ["canaries", "#/canaries", "fish-hook"],
    ["suppressions", "#/suppressions", "bell-off"]]],
  ["sectionSystem", [["rules", "#/rules", "book"], ["settings", "#/settings", "settings"]]],
];
let openAlerts = 0;

const logout = async () => { await post("/api/ui/logout").catch(() => {}); me = null; topo.pos = null; live.doc = null; render(); };
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
    SCOPED.has(active) && scopeHosts && scopeHosts.length > 1 && !/^#\/hosts\/./.test(location.hash) ? scopePicker() : null,
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
    days.length > 10
      ? h("div", { class: "axis" }, [0, Math.floor(days.length / 2), days.length - 1].map((i) => h("span", null, day(i).toLocaleDateString(lang, { day: "numeric", month: "numeric" }))))
      : h("div", { class: "axis days" }, days.map((_, i) => h("span", null, day(i).toLocaleDateString(lang, { weekday: "short" })))),
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
        h("span", { class: "rank-count" }, opts.fmt ? opts.fmt(it.count) : it.count.toLocaleString(lang))),
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
  const p = a.posture;
  if (!p) return null;
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
  return out;
}

function containersCard(a) {
  const cs = a.containers || [];
  const out = [];
  if (cs.length) {
    const socket = (c) => (c.mounts || []).some((m) => /^\/(var\/)?run\/docker(\.sock)?$/.test(m.source));
    out.push(h("div", { class: "card mt" },
      h("div", { class: "flex" }, h("h3", null, t("containers")), h("span", { class: "muted right" }, cs.length)),
      (a.docker_group || []).length ? h("dl", { class: "kv" }, h("dt", null, t("dockerGroupLbl")),
        h("dd", null, h("span", { class: "chip" }, h("span", { class: "dot medium" }), a.docker_group.join(", ")))) : null,
      h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, ["", "Name", t("ctrImage"), t("ctrRisks")].map((x) => h("th", null, x)))),
        h("tbody", null, cs.map((c) => {
          const risks = (c.risks || []).concat(socket(c) ? ["docker.sock"] : []);
          return h("tr", null,
            h("td", null, h("span", { class: "dot " + (risks.length ? "high" : "ok") })),
            h("td", { class: "mono nowrap" }, c.name, c.project ? h("span", { class: "muted" }, " " + c.project) : null),
            h("td", { class: "mono nowrap" }, c.image),
            h("td", null, risks.length ? risks.join(", ") : h("span", { class: "muted" }, "·")));
        }))))));
  }
  return out;
}

const sevCounts = (m) => h("span", { class: "sevcounts" }, SEVS.filter((s) => m && m[s]).map((s) => h("span", { class: "sev " + s }, m[s])));

async function overview() {
  const [o, inc, acts] = await Promise.all([api("/api/ui/overview?" + scopeQ()), api("/api/ui/incidents?" + scopeQ({ status: "active" })), api("/api/ui/actions").catch(() => [])]);
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
    h("div", { class: "crumbs" }, scopeName() ? t("onlyScope").replace("{s}", scopeName()) : t("welcome") + ", " + me.user),
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
    scopeName() ? null : await groupsPanel(),
    h("h2", null, t("hosts")), hostTable,
    h("div", { class: "grid dash-b mt" },
      panel(t("incidents"), h("a", { href: "#/incidents" }, inc.incidents.length + " " + t("activeInc").toLowerCase()),
        h("div", { class: "feed" }, inc.incidents.length ? inc.incidents.slice(0, 5).map((c) => h("a", { class: "feed-row", href: "#/incidents/" + (c.ref || c.id) },
          h("div", { class: "flex nowrap-flex" }, sevChip(c.severity), incRef(c), h("span", { class: "feed-title" }, c.title)),
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
      x.status === "approval" && can("admin", x.agent) ? h("div", { class: "actions" },
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
  if (!isolated && !locked.length && !(can("admin", a.id) && (allowed.has("isolate_host") || allowed.has("lock_user")))) return null;
  const userIn = h("input", { placeholder: t("user"), maxlength: 32, class: "mono" });
  return h("div", { class: "card mt" + (isolated ? " danger-card" : "") },
    h("h3", null, t("containment")),
    isolated ? h("div", { class: "flex" }, h("span", { class: "chip" }, h("span", { class: "dot critical" }), t("isolatedUntil") + " " + abs(c.isolated_until)),
      can("admin", a.id) && allowed.has("release_host") ? h("button", { class: "btn small right", onclick: respondNow(a.id, "release_host", {}) }, t("actRelease")) : null) : null,
    locked.map(([u, until]) => h("div", { class: "flex mt" }, h("span", { class: "chip" }, h("span", { class: "dot high" }), u + ": " + t("lockedUntil") + " " + abs(until)),
      can("admin", a.id) && allowed.has("unlock_user") ? h("button", { class: "btn small right", onclick: respondNow(a.id, "unlock_user", { user: u }) }, t("unlock")) : null)),
    can("admin", a.id) && !isolated && allowed.has("isolate_host") ? h("div", { class: "actions" },
      h("button", { class: "btn danger", onclick: respondNow(a.id, "isolate_host", { minutes: "60" }) }, t("actIsolate").replace("{dur}", "1 h"))) : null,
    can("admin", a.id) && allowed.has("lock_user") ? h("form", { class: "inline mt", onsubmit: (e) => { e.preventDefault(); if (userIn.value.trim()) respondNow(a.id, "lock_user", { user: userIn.value.trim(), minutes: "1440" })(); } },
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

// patternFor offers the one pattern that fits a parameter (see parsePattern
// in suppress.go), prefilled from the alert's value. Free text such as a
// command line only ever matches exactly.
function patternFor(k, v) {
  if (k === "process" && v) return { op: "name", arg: v.split("/")[0] };
  if ((k === "port" || k === "uid") && /^\d+$/.test(v)) return { op: "range", arg: v + "-" + v };
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return { op: "cidr", arg: v.replace(/\.\d+$/, ".0") + "/24" };
  if (/^[0-9a-f:]+:[0-9a-f:]*$/i.test(v) && v.includes("::")) return { op: "cidr", arg: v + "/64" };
  if (v.startsWith("/") && !["cmdline", "sample", "user_agent", "title"].includes(k)) {
    // numbered directories (go-build1247739926) and the file name vary
    const parts = v.split("/").map((p, i, all) => i === all.length - 1 ? "*" : p.replace(/^(.*\D)\d{3,}$/, "$1*"));
    return { op: "glob", arg: parts.join("/") };
  }
  return null;
}

async function alertDetail(id) {
  const all = await api("/api/ui/alerts");
  const a = all.find((x) => x.id === id);
  if (!a) { location.hash = "#/alerts"; return; }
  const params = (a.detail || "").split("\n").filter(Boolean).map((l) => l.split(/=(.*)/s));
  const act = (action) => async () => { await post("/api/ui/alerts/" + a.id + "/" + action); render(); };
  // suppression form, prefilled from the alert; volatile parameters start
  // unchecked, and a process matches by name because its pid always differs
  const volatile = new Set(["count", "pid", "gap", "fingerprint"]);
  const onlyHost = h("input", { type: "checkbox", checked: Boolean(a.agent) });
  const checks = params.filter(([k]) => k && k !== "host").map(([k, v]) => {
    const op = patternFor(k, v || "");
    const box = h("input", { type: "checkbox", checked: !volatile.has(k) });
    const mode = h("select", { class: "small", hidden: !op }, h("option", { value: "" }, t("patExact")),
      op ? h("option", { value: op.op, selected: k === "process" }, t("pat_" + op.op)) : null);
    const arg = h("input", { class: "mono small", value: op ? op.arg : "", hidden: !(op && k === "process") });
    mode.onchange = () => { arg.hidden = !mode.value; preview(); };
    box.onchange = arg.oninput = () => preview();
    return { k, v, box, mode, arg };
  });
  const reason = h("input", { maxlength: 500, required: true });
  const daysSel = h("select", null, [7, 30, 90].map((d) => h("option", { value: d, selected: d === 30 }, d + " " + t("days"))));
  const err = h("div", { class: "err" });
  const covers = h("div", { class: "muted" });
  const body = () => {
    const match = {}, patterns = {};
    for (const c of checks) {
      if (!c.box.checked) continue;
      if (c.mode.value) patterns[c.k] = c.mode.value + ":" + c.arg.value; else match[c.k] = c.v;
    }
    return { rule: a.rule, agent: onlyHost.checked ? a.agent : "", match, patterns, reason: reason.value, days: Number(daysSel.value) };
  };
  let timer = 0;
  const preview = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      err.textContent = "";
      try {
        const r = await post("/api/ui/suppressions", { ...body(), dry_run: true });
        covers.textContent = t("covers").replace("{n}", r.alerts) +
          (r.alerts ? " (" + Object.entries(r.hosts).map(([n, c]) => n + " " + c).join(", ") + ")" : "");
      } catch (x) { covers.textContent = ""; err.textContent = x.message; }
    }, 300);
  };
  onlyHost.onchange = preview;
  const box = h("form", { class: "card stack mt", hidden: true, onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    try {
      await post("/api/ui/suppressions", { ...body(), resolve: true });
      if (a.status !== "resolved") await post("/api/ui/alerts/" + a.id + "/resolve");
      location.hash = "#/suppressions";
    } catch (x) { err.textContent = x.message; }
  } },
    h("h3", null, t("suppress")),
    h("div", { class: "muted" }, t("suppressHint")),
    a.agent ? h("label", { class: "check" }, onlyHost, t("onlyHost") + " (" + (a.host || a.agent) + ")") : null,
    checks.map((c) => h("div", { class: "check pattern" }, h("label", { class: "check" }, c.box, h("span", { class: "mono" }, c.k + " = " + (c.v || "·"))), c.mode, c.arg)),
    covers,
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
      !can("analyst", a.agent) ? null : h("div", { class: "actions" },
        a.status === "open" ? h("button", { class: "btn", onclick: act("ack") }, t("ack")) : null,
        a.status !== "resolved" ? h("button", { class: "btn ghost", onclick: act("resolve") }, t("resolve")) : null,
        a.status !== "open" ? h("button", { class: "btn ghost", onclick: act("reopen") }, t("reopen")) : null,
        a.suppressible && can("analyst", "") ? h("button", { class: "btn ghost", onclick: () => { box.hidden = false; preview(); reason.focus(); } }, icon("bell-off"), t("suppress")) : null,
        a.proc_key && a.agent && can("admin", a.agent) ? h("button", { class: "btn ghost", title: a.proc_key, onclick: async () => {
          await post("/api/ui/agents/" + a.agent + "/accept-port", { key: a.proc_key }); render();
        } }, t("acceptProcess")) : null,
        a.incident ? h("a", { class: "btn ghost", href: "#/incidents/" + (a.incident_ref || a.incident) }, icon("stack-2"), t("incident") + (a.incident_ref ? " " + a.incident_ref : ""))
          : a.agent ? h("button", { class: "btn ghost", onclick: async () => {
            const r = await post("/api/ui/incidents/new/create", { alert: a.id }); location.hash = "#/incidents/" + (r.ref || r.id);
          } }, icon("stack-2"), t("newIncident")) : null)),
    box, await causingEvents(a), a.agent ? await snapshotsCard(a.agent, a.id) : null, await responseCard(a)));
}

// ---------- host page: one host in tabs ----------
// The tab and its options live in the hash (#/hosts/ID?tab=network&days=7),
// so links, the back button and a refresh keep them. A tab loads only its
// own data. The parameter is never called host: that sets the scope.
const HOST_TABS = ["overview", "perf", "security", "network", "software", "access", "changes"];
const hostHref = (id, tab, extra = {}) => "#/hosts/" + id + (tab && tab !== "overview" ? "?" + new URLSearchParams({ tab, ...extra }) : "");
const DAY_CHOICES = [["1", "day1"], ["7", "days7"], ["30", "days30"]];
const dayLabel = (k, l) => k === "30" ? t(l).replace("{n}", 30) : t(l);
function hostDays(params, def) {
  const d = params.get("days") || def;
  return DAY_CHOICES.some(([k]) => k === d) ? d : def;
}
function daysPick(id, tab, cur, params) {
  return h("div", { class: "tabs" }, DAY_CHOICES.map(([k, l]) => h("a", { class: "tab" + (k === cur ? " on" : ""),
    href: hostHref(id, tab, { ...Object.fromEntries(params), tab, days: k }) }, dayLabel(k, l))));
}
const newSince = (ts, hours) => ts && Date.now() - new Date(ts).getTime() < hours * 3600e3;
const newPill = () => h("span", { class: "pill new" }, t("ht_new"));
const geoCell = (g) => g.country || g.asn ? [g.country ? countryName(g.country) : "", g.asn ? h("span", { class: "muted" }, (g.country ? "  ·  " : "") + "AS" + g.asn + " " + (g.org || "")) : null] : h("span", { class: "muted" }, "·");

async function hostView(id, params) {
  const tab = HOST_TABS.includes(params.get("tab")) ? params.get("tab") : "overview";
  selftestOpen = false;
  const d = await api("/api/ui/agents/" + encodeURIComponent(id));
  const a = d.agent;
  const body = await ({ overview: hostOverviewTab, perf: hostPerfTab, security: hostSecurityTab, network: hostNetworkTab,
    software: hostSoftwareTab, access: hostAccessTab, changes: hostChangesTab }[tab])(a, d, params);
  mount(shell("hosts",
    h("div", { class: "crumbs" }, h("a", { href: "#/hosts" }, t("hosts")), " / ", a.name),
    h("h1", null, a.name),
    h("div", { class: "flex" }, statusChip(a.status), tagChips(a.tags)),
    h("nav", { class: "hosttabs", "aria-label": t("ht_tabs") }, HOST_TABS.map((k) =>
      h("a", { class: "tab" + (k === tab ? " on" : ""), href: hostHref(a.id, k), "aria-current": k === tab ? "page" : null }, t("ht_" + k)))),
    body));
  // on a phone the strip scrolls; keep the open tab in sight
  const on = document.querySelector(".hosttabs .on");
  if (on) on.scrollIntoView({ inline: "center", block: "nearest" });
}

// The state card: one light per area, each with its number; a click opens
// the tab with the detail.
function hostStatus(a, d, tests, hostsData) {
  const tiles = [];
  const urgent = (a.open_by_severity.critical || 0) + (a.open_by_severity.high || 0);
  tiles.push(metric(hostHref(a.id, "security"), "alert-triangle", t("alertsTile"), a.open_alerts, urgent ? "bad" : a.open_alerts ? null : "good",
    SEVS.filter((s) => a.open_by_severity[s]).map((s) => a.open_by_severity[s] + " " + t(s)).join(", ") || t("noAlerts")));
  const checks = (a.posture && a.posture.checks) || [];
  const failed = new Set(checks.filter((c) => !c.ok).map((c) => c.check));
  const names = new Set(checks.map((c) => c.check));
  tiles.push(metric(hostHref(a.id, "security"), "settings", t("posture"), a.posture ? failed.size : "·", failed.size ? "bad" : a.posture ? "good" : null,
    a.posture ? t("checksOk").replace("{n}", names.size - failed.size).replace("{m}", names.size) : t("ht_noReport")));
  const u = a.updates;
  tiles.push(metric(hostHref(a.id, "software"), "stack-2", t("ht_secUpdates"), u ? u.security || 0 : "·",
    u && u.security ? (u.security_oldest_days >= 7 ? "bad" : null) : u ? "good" : null,
    !u ? t("ht_noReport") : u.security ? t("ht_oldestDays").replace("{n}", u.security_oldest_days || 0) : u.reboot_required ? t("rebootShort") : t("upToDate")));
  const v = a.vulns, av = a.app_vulns;
  const sum = (m) => SEVS.reduce((x, s) => x + ((m || {})[s] || 0), 0);
  const vulnN = (v ? sum(v.fixable) + sum(v.unfixed) : 0) + (av ? sum(av.counts) : 0);
  const exploited = (v ? (v.exploited || []).length : 0) + (av ? (av.top || []).filter((x) => x.kev).length + (av.malicious || []).length : 0);
  const critical = ((v && v.fixable) || {}).critical || ((av && av.counts) || {}).critical;
  tiles.push(metric(hostHref(a.id, "software"), "radar", t("vulns"), v || av ? vulnN : "·", exploited || critical ? "bad" : v || av ? (vulnN ? null : "good") : null,
    !v && !av ? t("ht_noReport") : exploited ? exploited + " " + t("ht_exploitedN") : critical ? critical + " " + t("critical") : t("ht_allSev")));
  const pub = d.ports.filter((p) => p.scope !== "loopback");
  const unexpected = pub.filter((p) => !p.expected).length;
  tiles.push(metric(hostHref(a.id, "network"), "world", t("ht_publicPorts"), pub.length, unexpected ? "bad" : null,
    unexpected ? unexpected + " " + t("ht_unexpected") : t("ht_allExpected")));
  const last = tests[0];
  const stTone = { passed: "good", warning: null, failed: "bad" };
  tiles.push(metric(hostHref(a.id, "security"), "shield-check", t("selftest"), last ? t("st_" + last.status) : "·",
    last ? stTone[last.status] : null, last ? ago(last.created) : a.selftest ? t("noSelftests") : t("selftestOff")));
  const hx = ((hostsData && hostsData.hosts) || []).find((x) => x.id === a.id);
  const m = hx && hx.metrics;
  const mem = m ? pctOf(m.mem_used, m.mem_total) : 0;
  const worst = m ? Math.max(m.disk_pct || 0, mem) : 0;
  tiles.push(metric(hostHref(a.id, "perf"), "server", t("ht_diskMem"), m ? fmtPct(m.disk_pct || 0) : "·", m ? (worst >= 90 ? "bad" : worst < 70 ? "good" : null) : null,
    m ? t("memory") + " " + fmtPct(mem) : t("noMetrics")));
  return h("div", { class: "grid metrics seven" }, tiles);
}

async function hostOverviewTab(a, d) {
  const [tests, hostsData, open] = await Promise.all([api("/api/ui/selftests?agent=" + encodeURIComponent(a.id)), api("/api/ui/hosts").catch(() => null),
    api("/api/ui/alerts?" + new URLSearchParams({ agent: a.id, status: "open" }))]);
  if (hostsData) { scopeHosts = hostsData.hosts; scopeHostsAt = Date.now(); }
  const action = (name, body) => async () => { await post("/api/ui/agents/" + a.id + "/" + name, body || {}); render(); };
  const renameInput = h("input", { value: a.name, maxlength: 100 });
  const updErr = h("div", { class: "err" });
  const u = a.update;
  const updText = u ? t("upd_" + u.status).replace("{v}", u.version).replace("{f}", u.from || "?") + (u.error ? ": " + u.error : "") : "";
  // Agents before v0.19.0 cannot update themselves. A newer one decides by
  // its own agent.json; self_update is what it said on its last start.
  const updButton = !can("admin", a.id) ? null : newerVersion("v0.19.0", a.version) ? null
    : h("div", { class: "actions" }, !a.self_update ? h("div", { class: "muted" }, t("selfUpdateOff")) : null, h("button", { class: "btn ghost", onclick: async () => {
      updErr.textContent = "";
      try {
        const r = await api("/api/ui/release/latest");
        if (r.error) throw new Error(r.error);
        if (!newerVersion(r.version, a.version)) { updErr.textContent = t("upToDate") + ": " + r.version; return; }
        if (!confirm(t("confirmUpdate").replace("{v}", r.version))) return;
        await post("/api/ui/agents/" + a.id + "/update", { version: r.version });
        render();
      } catch (x) { updErr.textContent = x.message; }
    } }, t("updateAgent")), updErr);
  const minutesSel = h("select", null, [30, 60, 120, 240].map((m) => h("option", { value: m }, m + " " + t("minutes"))));
  return [
    hostStatus(a, d, tests, hostsData),
    h("div", { class: "grid two mt" },
      h("div", { class: "card" },
        h("dl", { class: "kv" },
          h("dt", null, "Hostname"), h("dd", null, a.hostname),
          h("dt", null, t("groups")), h("dd", null, tagChips(a.tags) || h("span", { class: "muted" }, t("none"))),
          h("dt", null, t("lastSeen")), h("dd", null, timeEl(a.last_seen)),
          h("dt", null, t("lastIP")), h("dd", { class: "mono" }, a.last_ip),
          h("dt", null, t("version")), h("dd", null, (a.version || "·") + (updText ? "  ·  " + updText : "")),
          h("dt", null, t("enrolled")), h("dd", null, abs(a.enrolled)),
          h("dt", null, t("canaryRoots")), h("dd", { class: "mono" }, (a.canary_roots || []).join("  ") || t("none")),
          h("dt", null, t("configSync")), h("dd", null, t(a.config_sync ? "synced" : "waiting")))),
      !can("admin", a.id) ? null : h("div", { class: "card" },
        h("form", { class: "inline", onsubmit: async (e) => { e.preventDefault(); await post("/api/ui/agents/" + a.id + "/rename", { name: renameInput.value }); render(); } },
          h("label", null, t("rename"), renameInput), h("button", { class: "btn ghost", type: "submit" }, t("rename"))),
        can("admin", "") ? tagEditor(a) : null,
        a.maintenance_until
          ? h("div", { class: "flex mt" }, h("span", { class: "chip" }, h("span", { class: "dot stopped" }), t("maintenanceUntil") + " " + abs(a.maintenance_until)),
            h("button", { class: "btn small ghost", onclick: action("maintenance", { minutes: 0 }) }, t("end")))
          : h("form", { class: "inline mt", onsubmit: async (e) => { e.preventDefault(); await post("/api/ui/agents/" + a.id + "/maintenance", { minutes: Number(minutesSel.value) }); render(); } },
            h("label", null, t("maintenance"), minutesSel), h("button", { class: "btn ghost", type: "submit" }, t("start"))),
        updButton,
        h("div", { class: "actions" },
          h("a", { class: "btn ghost", href: "#/events?agent=" + a.id }, t("events")),
          h("a", { class: "btn ghost", href: tlHref(a.id, new Date().toISOString(), { minutes: 60 }) }, t("timeline")),
          h("a", { class: "btn ghost", href: "#/alerts?host=" + a.id }, t("alerts")),
          h("a", { class: "btn ghost", href: "#/attacks?host=" + a.id }, t("attacks")),
          can("admin", "") ? h("button", { class: "btn danger", onclick: async () => { if (confirm(t("confirmDelete"))) { await post("/api/ui/agents/" + a.id + "/delete"); location.hash = "#/"; } } }, t("deleteHost")) : null))),
    h("div", { class: "flex mt" }, h("h2", null, t("ht_openAlerts")), open.length > 8 ? h("a", { class: "right", href: hostHref(a.id, "security") }, t("all")) : null),
    open.length ? h("div", { class: "list" }, open.slice(0, 8).map(alertRow)) : h("div", { class: "card empty" }, t("noAlerts")),
  ];
}

async function hostPerfTab(a, d, params) {
  const hostsData = await api("/api/ui/hosts").catch(() => null);
  if (hostsData) { scopeHosts = hostsData.hosts; scopeHostsAt = Date.now(); }
  return performanceSection(a, hostsData, params);
}

function selftestSection(a, tests) {
  selftestOpen = tests.some((x) => x.status === "pending" || x.status === "running");
  const stErr = h("div", { class: "err" });
  const stDot = { passed: "ok", warning: "medium", failed: "critical", pending: "stopped", running: "stopped", ok: "ok", suppressed: "medium", skipped: "medium", missing: "critical", waiting: "stopped" };
  const testRow = (x) => h("div", { class: "row" },
    h("span", { class: "chip" }, h("span", { class: "dot " + (stDot[x.status] || "") }), t("st_" + x.status)),
    h("div", null,
      h("div", { class: "title steps" }, x.steps.map((st) => h("span", { class: "chip", title: st.detail || "" }, h("span", { class: "dot " + (stDot[st.status] || "") }), st.rule + ": " + t("st_" + st.status)))),
      h("div", { class: "sub" }, [x.by, x.error, x.notified ? t("notifiedTo") + " " + Object.entries(x.notified).map(([k, v]) => k + (v === "ok" ? "" : " (" + v + ")")).join(", ") : ""].filter(Boolean).join("  ·  "))),
    h("div", { class: "meta" }, timeEl(x.created)));
  return h("div", null, h("div", { class: "flex" }, h("h2", null, t("selftest")),
      can("admin", a.id) && a.selftest ? h("button", { class: "btn small right", onclick: async () => {
        stErr.textContent = "";
        try { await post("/api/ui/agents/" + a.id + "/selftest"); render(); } catch (x) { stErr.textContent = x.message; }
      } }, t("runSelftest")) : null),
    stErr,
    !a.selftest ? h("div", { class: "card empty" }, t("selftestOff"))
      : tests.length ? h("div", { class: "list" }, tests.slice(0, 5).map(testRow)) : h("div", { class: "card empty" }, t("noSelftests")));
}

async function hostSecurityTab(a) {
  const q = encodeURIComponent(a.id);
  const [o, inc, open, tests, actions, recent] = await Promise.all([api("/api/ui/overview?agent=" + q + "&days=30"),
    api("/api/ui/incidents?agent=" + q + "&status=active"), api("/api/ui/alerts?agent=" + q + "&status=open"),
    api("/api/ui/selftests?agent=" + q), api("/api/ui/actions?agent=" + q), api("/api/ui/events?agent=" + q + "&limit=12")]);
  const total30 = o.alerts_per_day.reduce((x, d) => x + SEVS.reduce((y, s) => y + (d[s] || 0), 0), 0);
  return [
    h("div", { class: "grid metrics" },
      metric(null, "alert-triangle", t("alertsTile"), a.open_alerts, (a.open_by_severity.critical || a.open_by_severity.high) ? "bad" : null, sevText(a.open_by_severity)),
      metric(null, "list-details", t("ht_alerts30"), total30, null, t("days30").replace("{n}", 30)),
      metric(null, "clock", t("mtta"), duration(o.mtta_seconds), null, o.acked_30d ? t("ht_mttaHost") : t("noneYet")),
      metric(null, "radar", t("ht_openInc"), inc.incidents.length, inc.incidents.length ? "bad" : null, inc.incidents.length ? t("openInc") : t("noIncidents"))),
    h("div", { class: "grid dash-a" },
      panel(t("ht_alertsMonth"), null, severityChart(o.alerts_per_day, o.day_start)),
      panel(t("topRules"), t("days30").replace("{n}", 30), rankList(o.top_rules, { mono: true, empty: t("noAlerts"), href: () => "#/alerts?host=" + a.id }))),
    inc.incidents.length ? [h("h2", null, t("incidents")), h("div", { class: "list" }, inc.incidents.map(incRow))] : null,
    h("div", { class: "flex mt" }, h("h2", null, t("ht_openAlerts")), h("a", { class: "right", href: "#/alerts?host=" + a.id }, t("all"))),
    open.length ? h("div", { class: "list" }, open.slice(0, 25).map(alertRow)) : h("div", { class: "card empty" }, t("noAlerts")),
    postureSection(a),
    containCard(a),
    actions.length ? [h("h2", null, t("response")), actionRows(actions)] : null,
    await snapshotsCard(a.id),
    selftestSection(a, tests),
    h("div", { class: "flex mt" }, h("h2", null, t("ht_latestEvents")),
      h("a", { class: "right", href: tlHref(a.id, new Date().toISOString(), { minutes: 60 }) }, t("timeline"))),
    recent.length ? h("div", { class: "tablewrap" }, h("table", null, h("tbody", null, recent.map(eventRow)))) : h("div", { class: "card empty" }, t("noEvents")),
  ];
}
const sevText = (m) => SEVS.filter((s) => m[s]).map((s) => m[s] + " " + t(s)).join(", ") || t("noAlerts");

async function hostNetworkTab(a, d, params) {
  const days = hostDays(params, "7");
  const act = await api("/api/ui/agents/" + encodeURIComponent(a.id) + "/activity?days=" + days);
  const action = (name, body) => async () => { await post("/api/ui/agents/" + a.id + "/" + name, body || {}); render(); };
  const opened = {};
  for (const p of act.ports) if (p.opened && !p.closed) opened[p.key] = p.opened;
  const portRows = d.ports.map((p) => h("tr", null,
    h("td", { class: "mono" }, p.proto + "/" + p.port),
    h("td", { class: "mono" }, p.addr),
    h("td", null, p.scope),
    h("td", null, p.via),
    h("td", { class: "mono" }, p.process || p.target || ""),
    h("td", { class: "nowrap" }, opened[p.key] ? [timeEl(opened[p.key]), newSince(opened[p.key], 24) ? [" ", newPill()] : null] : h("span", { class: "muted", title: t("ht_olderThan").replace("{n}", act.days) }, "·")),
    h("td", null, p.expected ? h("span", { class: "pill" }, t("expected"))
      : !can("admin", a.id) ? h("span", { class: "pill warn" }, t("ht_unexpectedOne"))
      : h("div", { class: "flex" },
        h("button", { class: "btn small", onclick: action("accept-port", { key: p.key }) }, t("accept")),
        p.proc_key ? h("button", { class: "btn small ghost", title: p.proc_key, onclick: action("accept-port", { key: p.proc_key }) }, t("acceptProcess")) : null))));
  const hist = act.ports.filter((p) => p.closed || p.times > 1 || opened[p.key]);
  const pub = act.destinations.filter((x) => !x.private);
  const byProg = {};
  for (const x of act.destinations) {
    const k = x.process || "?";
    byProg[k] = byProg[k] || { key: k, count: 0, set: new Set() };
    byProg[k].count++;
    if (x.country) byProg[k].set.add(x.country);
  }
  const progs = Object.values(byProg).sort((x, y) => y.count - x.count).slice(0, 10)
    .map((x) => ({ key: x.key, count: x.count, extra: [...x.set].slice(0, 6).map(countryName).join(", ") }));
  const vol = (d.volume || []).map((x) => ({ t: Date.parse(x.at) / 1000, tx: x.tx, rx: x.rx }));
  return [
    h("div", { class: "flex" }, h("h2", null, t("ports")),
      can("admin", a.id) && d.ports.some((p) => !p.expected) ? h("button", { class: "btn small right", onclick: action("accept-port", { key: "*" }) }, t("acceptAll")) : null),
    h("div", { class: "tablewrap" }, h("table", { class: "nowrap" },
      h("thead", null, h("tr", null, ["Port", "Addr", t("scope"), t("via"), t("process"), t("ht_openSince"), ""].map((x) => h("th", null, x)))),
      h("tbody", null, portRows))),
    h("div", { class: "flex mt" }, h("h2", null, t("ht_destinations")), h("div", { class: "right" }, daysPick(a.id, "network", days, params))),
    act.partial ? scopeNote(t("ht_partial")) : null,
    h("div", { class: "grid dash-a" },
      h("div", { class: "card panel" }, h("div", { class: "panel-head" }, h("h3", null, t("ht_newDest")),
        h("span", { class: "panel-extra" }, pub.length + " " + t("ht_public") + "  ·  " + (act.destinations.length - pub.length) + " " + t("ht_private"))),
        act.destinations.length ? h("div", { class: "tablewrap" }, h("table", null,
          h("thead", null, h("tr", null, [t("ht_firstSeen"), t("remote"), "Port", t("program"), t("ht_origin"), "n"].map((x) => h("th", null, x)))),
          h("tbody", null, act.destinations.slice(0, 60).map((x) => h("tr", null,
            h("td", { class: "nowrap" }, timeEl(x.first), newSince(x.first, 24) ? [" ", newPill()] : null),
            h("td", { class: "mono nowrap" }, entityLink("ip", x.ip) || x.ip, x.private ? h("span", { class: "muted" }, " " + t("ht_private")) : null,
              x.net === "tor" ? [" ", h("span", { class: "pill warn" }, "Tor")] : null),
            h("td", { class: "nowrap" }, portName(x.port) + (PORT_NAMES[x.port] ? " (" + x.port + ")" : "")),
            h("td", { class: "mono", title: x.exe || "" }, x.process || "·"),
            h("td", null, x.private ? h("span", { class: "muted" }, "·") : geoCell(x)),
            h("td", null, x.n)))))) : h("div", { class: "empty small" }, t("ht_noDest"))),
      panel(t("ht_destByProg"), null, rankList(progs, { mono: true, empty: t("ht_noDest") }))),
    hist.length ? [h("h3", { class: "mt" }, t("ht_portHistory")), h("div", { class: "tablewrap" }, h("table", { class: "nowrap" },
      h("thead", null, h("tr", null, ["Port", "Addr", t("process"), t("ht_opened"), t("ht_closed"), t("ht_times")].map((x) => h("th", null, x)))),
      h("tbody", null, hist.map((p) => h("tr", null,
        h("td", { class: "mono" }, p.proto + "/" + p.port), h("td", { class: "mono" }, p.addr), h("td", { class: "mono" }, p.process || "·"),
        h("td", null, p.opened ? timeEl(p.opened) : "·"), h("td", null, p.closed ? timeEl(p.closed) : h("span", { class: "chip" }, h("span", { class: "dot ok" }), t("open"))),
        h("td", null, p.times))))))] : null,
    h("div", { class: "mt" }, lineChart({ title: t("ht_volume"), points: vol, step: 3600, fmt: fmtBytes,
      series: [{ label: t("ht_sent"), get: (p) => p.tx }, { label: t("ht_received"), get: (p) => p.rx }] })),
  ];
}

// downloadCSV saves the points shown, one row each.
function downloadCSV(a, d) {
  const ifs = [...new Set(d.points.flatMap((p) => Object.keys(p.if || {})))].sort();
  const cols = ["cpu", "iow", "st", "mem", "swap", "l1", "rx", "tx", "dr", "dw", "disk", "ci", "co"];
  const rows = [["time", ...cols, ...ifs.flatMap((n) => [n + "_rx", n + "_tx"])].join(",")];
  for (const p of d.points) rows.push([new Date(p.t * 1000).toISOString(), ...cols.map((c) => p[c] ?? ""), ...ifs.flatMap((n) => p.if && p.if[n] ? p.if[n] : ["", ""])].join(","));
  const url = URL.createObjectURL(new Blob([rows.join("\n") + "\n"], { type: "text/csv" }));
  const link = h("a", { href: url, download: (a.name || a.id).replace(/[^A-Za-z0-9._-]+/g, "_") + "-" + new Date(d.from * 1000).toISOString().slice(0, 16).replace(/[:T]/g, "") + ".csv" });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// one list of the operating system's and the applications' weaknesses,
// filtered by severity, "exploited" and ecosystem
function vulnTable(a, params) {
  const v = a.vulns, av = a.app_vulns;
  const list = [];
  const sevOf = (s) => s in { critical: 1, high: 1, medium: 1, low: 1 } ? s : "";
  if (v) {
    const seen = new Set();
    for (const x of [...(v.exploited || []), ...(v.top || [])]) {
      if (seen.has(x.cve + x.package)) continue;
      seen.add(x.cve + x.package);
      list.push({ sev: sevOf(x.severity), id: x.cve, url: "https://www.cve.org/CVERecord?id=" + encodeURIComponent(x.cve), pkg: x.package, eco: v.release || "OS",
        installed: x.installed, fixed: x.fixed ? x.fixed + (x.pro ? " (" + t("proOnly") + ")" : "") : "", kev: x.kev, path: "" });
    }
  }
  if (av) {
    for (const x of [...(av.malicious || []), ...(av.top || [])]) list.push({ sev: sevOf(x.severity), id: (x.cves || [])[0] || x.id,
      url: "https://osv.dev/vulnerability/" + encodeURIComponent(x.id), pkg: x.package, eco: x.ecosystem, installed: x.installed, fixed: x.fixed || "",
      kev: x.kev, malicious: x.malicious, path: x.path, summary: x.summary });
  }
  if (!list.length) return null;
  const f = { sev: params.get("sev") || "", eco: params.get("eco") || "", kev: params.get("kev") === "1" };
  const go = (ch) => { const p = new URLSearchParams(params); p.set("tab", "software"); for (const [k, x] of Object.entries(ch)) { if (x) p.set(k, x); else p.delete(k); } location.hash = "#/hosts/" + a.id + "?" + p; };
  const ecos = [...new Set(list.map((x) => x.eco))].sort();
  const rank = { critical: 0, high: 1, medium: 2, low: 3, "": 4 };
  const shown = list.filter((x) => (!f.sev || x.sev === f.sev) && (!f.eco || x.eco === f.eco) && (!f.kev || x.kev || x.malicious))
    .sort((x, y) => (y.malicious ? 1 : 0) - (x.malicious ? 1 : 0) || (y.kev ? 1 : 0) - (x.kev ? 1 : 0) || rank[x.sev] - rank[y.sev]);
  const sevSel = h("select", { onchange: (e) => go({ sev: e.target.value }), "aria-label": t("ht_sevLabel") },
    h("option", { value: "" }, t("ht_allSev")), SEVS.map((s) => h("option", { value: s, selected: f.sev === s }, t(s))));
  const ecoSel = h("select", { onchange: (e) => go({ eco: e.target.value }), "aria-label": t("ht_ecosystem") },
    h("option", { value: "" }, t("ht_allEco")), ecos.map((e) => h("option", { value: e, selected: f.eco === e }, e)));
  const kevBox = h("label", { class: "check" }, h("input", { type: "checkbox", checked: f.kev, onchange: (e) => go({ kev: e.target.checked ? "1" : "" }) }), t("ht_onlyExploited"));
  return h("div", { class: "card mt" },
    h("div", { class: "flex" }, h("h3", null, t("ht_vulnList")), h("span", { class: "muted right" }, shown.length + " / " + list.length)),
    h("div", { class: "flex vfilters" }, sevSel, ecoSel, kevBox),
    shown.length ? h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["", t("vulnId"), t("pkg"), t("ht_ecosystem"), t("installed"), t("fixedIn"), t("lockFile")].map((x) => h("th", null, x)))),
      h("tbody", null, shown.slice(0, 200).map((x) => h("tr", null,
        h("td", { class: "nowrap" }, h("span", { class: "sev " + (x.sev || "low") }, x.malicious ? t("maliciousPkg") : x.sev ? t(x.sev) : t("unknownSev")),
          x.kev ? [" ", h("span", { class: "pill warn" }, t("ht_exploited"))] : null),
        h("td", { class: "mono nowrap" }, h("a", { href: x.url, target: "_blank", rel: "noopener noreferrer", title: x.summary || "" }, x.id)),
        h("td", { class: "mono nowrap" }, x.pkg),
        h("td", { class: "nowrap" }, x.eco),
        h("td", { class: "mono nowrap" }, x.installed),
        h("td", { class: "mono nowrap" }, x.fixed || "·"),
        h("td", { class: "mono muted nowrap" }, x.path || "·")))))) : h("div", { class: "empty small" }, t("ht_noMatch")));
}

async function hostSoftwareTab(a, d, params) {
  const u = a.updates, v = a.vulns, av = a.app_vulns;
  const locks = {};
  for (const x of [...((av && av.top) || []), ...((av && av.malicious) || [])]) locks[x.path] = (locks[x.path] || 0) + 1;
  const counts = Object.assign({}, (av && av.counts) || {});
  const unknown = counts.unknown || 0;
  delete counts.unknown;
  return [
    u ? h("div", { class: "card" }, h("h3", null, t("updates")), h("dl", { class: "kv" },
      h("dt", null, t("updates")), h("dd", null, updatesCell(u)),
      u.security ? [h("dt", null, t("ht_oldestOpen")), h("dd", { class: u.security_oldest_days >= 7 ? "bad-text" : "" }, t("ht_oldestDays").replace("{n}", u.security_oldest_days || 0))] : null,
      h("dt", null, t("securityPackages")), h("dd", { class: "mono" }, (u.security_packages || []).join("  ") || "·"),
      h("dt", null, t("kernel")), h("dd", { class: "mono" }, u.kernel_running + (u.kernel_newest && u.kernel_newest !== u.kernel_running ? "  (" + t("newestInstalled") + " " + u.kernel_newest + ")" : "")),
      u.reboot_required ? [h("dt", null, t("rebootShort")), h("dd", null, (u.reboot_days || 0) + " " + t("days"))] : null,
      h("dt", null, t("unattended")), h("dd", null, t(u.unattended_upgrades ? "on" : "off")),
      h("dt", null, t("listsAge")), h("dd", null, u.lists_age_days >= 0 ? u.lists_age_days + " " + t("daysAgo") : "·"))) : h("div", { class: "card empty" }, t("ht_noReport")),
    v || av ? h("div", { class: "grid two mt" },
      v ? h("div", { class: "card" }, h("div", { class: "flex" }, h("h3", null, t("vulns")), h("span", { class: "muted right" }, v.release || "", v.checked ? "  ·  " : "", v.checked ? timeEl(v.checked) : null)),
        v.error ? h("div", { class: "muted mt" }, v.error) : h("dl", { class: "kv" },
          h("dt", null, t("fixable")), h("dd", null, SEVS.some((s) => (v.fixable || {})[s]) ? sevCounts(v.fixable) : h("span", { class: "chip" }, h("span", { class: "dot ok" }), t("noVulns"))),
          h("dt", null, t("unfixed")), h("dd", null, sevCounts(v.unfixed)),
          h("dt", null, t("exploitedNow")), h("dd", null, (v.exploited || []).length))) : null,
      av ? h("div", { class: "card" }, h("div", { class: "flex" }, h("h3", null, t("appVulns")), h("span", { class: "muted right" }, av.checked ? timeEl(av.checked) : null)),
        h("dl", { class: "kv" },
          h("dt", null, t("vulns")), h("dd", null, SEVS.some((s) => counts[s]) || unknown
            ? [sevCounts(counts), unknown ? h("span", { class: "muted" }, " " + unknown + " " + t("unknownSev")) : null]
            : h("span", { class: "chip" }, h("span", { class: "dot ok" }), t("noVulns"))),
          h("dt", null, t("appMalicious")), h("dd", null, (av.malicious || []).length),
          h("dt", null, t("ht_lockfiles")), h("dd", null, t("appFiles").replace("{n}", av.manifests).replace("{m}", av.packages) + (av.truncated ? ", " + t("appTruncated") : ""))),
        (av.missing || []).length ? h("div", { class: "muted mt" }, t("appMissing") + " " + av.missing.join(", ")) : null) : null) : null,
    vulnTable(a, params),
    Object.keys(locks).length ? h("div", { class: "card mt" }, h("h3", null, t("ht_lockfiles")), h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, [t("lockFile"), t("vulns")].map((x) => h("th", null, x)))),
      h("tbody", null, Object.entries(locks).sort((x, y) => y[1] - x[1]).map(([p, n]) => h("tr", null, h("td", { class: "mono" }, p), h("td", null, n))))))) : null,
    containersCard(a),
  ];
}

async function hostAccessTab(a, d, params) {
  const q = encodeURIComponent(a.id);
  const [ses, act, atk] = await Promise.all([api("/api/ui/sessions?agent=" + q + "&days=30"), api("/api/ui/agents/" + q + "/activity?days=30"),
    api("/api/ui/attacks?agent=" + q + "&days=30").catch(() => null)]);
  // counts come from the log on disk; the session list is cut at 500
  const list = ses.sessions;
  const users = Object.entries(act.login_hours).map(([user, utc]) => ({ user, hours: localHours(utc), n: utc.reduce((x, y) => x + y, 0) }));
  const keys = act.keys, ipList = act.sources;
  const rows = users.sort((x, y) => y.n - x.n).slice(0, 12);
  const max = Math.max(1, ...rows.flatMap((r) => r.hours));
  const grid = h("div", { class: "heatgrid", role: "table", "aria-label": t("ht_loginHeat") });
  grid.append(h("div", { class: "hlabel" }), ...Array.from({ length: 24 }, (_, i) => h("div", { class: "hhead" }, i % 3 === 0 ? String(i) : "")));
  for (const r of rows) {
    grid.append(h("div", { class: "hlabel mono", title: r.user }, r.user));
    r.hours.forEach((n, i) => grid.append(hoverTip(heatCell(heatLevel(n, max)), r.user + "  ·  " + String(i).padStart(2, "0") + ":00  ·  " + num(n) + " " + t("ht_loginsN"))));
  }
  const failedTotal = act.failed_per_day.reduce((x, y) => x + y, 0);
  const failedDays = act.failed_per_day.map((n, i) => ({ day: new Date(Date.parse(act.day_start + "T00:00:00Z") + i * 864e5).toISOString().slice(0, 10), ssh: n, web: 0, ips: act.failed_ips_per_day[i] }));
  // new: first login from it in the last 7 days, none in the 23 days before
  const isNew = (x) => newSince(x.first, 7 * 24);
  return [
    h("div", { class: "grid metrics six" },
      metric(null, "key", t("logins"), num(act.logins), null, t("days30").replace("{n}", 30)),
      metric(null, "user-x", t("ht_usersN"), users.length, null, keys.length + " " + t("ht_keysN")),
      metric(null, "world", t("ht_sources"), ipList.length, ipList.some(isNew) ? "bad" : null, ipList.filter(isNew).length + " " + t("ht_newSources")),
      metric(null, "user-x", t("failedTile"), num(failedTotal), null, t("days30").replace("{n}", 30)),
      metric(atk ? "#/attacks?host=" + a.id : null, "radar", t("attackers"), atk ? (atk.ready ? num(atk.totals.ips) : "·") : "·", null, atk && atk.ready ? atk.totals.countries + " " + t("ht_countriesN") : t("ht_rollupWait")),
      metric("#/sessions?agent=" + a.id, "terminal-2", t("ht_commandsN"), num(list.reduce((x, s) => x + s.commands, 0)), null,
        t("ht_inSessions").replace("{n}", list.length >= 500 ? "500+" : list.length))),
    h("div", { class: "grid dash-a" },
      panel(t("ht_loginHeat"), t("days30").replace("{n}", 30), rows.length ? h("div", { class: "scrollx" }, grid) : h("div", { class: "empty small" }, t("noEvents"))),
      panel(t("ht_failedDay"), num(failedTotal), sshDays(failedDays))),
    h("div", { class: "grid two mt" },
      panel(t("ht_keys"), null, keys.length ? h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, [t("key"), t("user"), "n", t("ht_lastUse")].map((x) => h("th", null, x)))),
        h("tbody", null, keys.map((k) => h("tr", null,
          h("td", { class: "mono" }, k.key, k.method === "password" ? [" ", h("span", { class: "pill warn" }, t("password"))] : null),
          h("td", { class: "mono" }, k.users.join(", ")), h("td", null, k.n), h("td", { class: "nowrap" }, timeEl(k.last))))))) : h("div", { class: "empty small" }, t("noEvents"))),
      panel(t("ht_sources"), null, ipList.length ? h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, [t("ip"), t("user"), "n", t("ht_firstSeen"), t("ht_lastUse")].map((x) => h("th", null, x)))),
        h("tbody", null, ipList.map((x) => h("tr", null,
          h("td", { class: "mono nowrap" }, entityLink("ip", x.key) || x.key, isNew(x) ? [" ", newPill()] : null),
          h("td", { class: "mono" }, x.users.join(", ")), h("td", null, x.n),
          h("td", { class: "nowrap" }, timeEl(x.first)), h("td", { class: "nowrap" }, timeEl(x.last))))))) : h("div", { class: "empty small" }, t("noEvents")))),
    atk && atk.ready && atk.countries.length ? h("div", { class: "grid dash-a mt" },
      h("div", { class: "card panel" }, h("div", { class: "panel-head" }, h("h3", null, t("ht_attackersHost")), h("span", { class: "panel-extra" }, t("days30").replace("{n}", 30))),
        worldMap(atk.countries, (k) => { location.hash = "#/attacks?" + new URLSearchParams({ host: a.id, country: k }); }), geoAttr(atk.geo)),
      panel(t("ht_topAttackers"), t("ht_allHostsCount"), rankList(atk.addresses.slice(0, 8).map((x) => ({ key: x.ip, count: x.ssh + x.web,
        extra: [x.country ? countryName(x.country) : "", x.org || "", x.class ? t("cls_" + x.class) : ""].filter(Boolean).join("  ·  ") })),
        { mono: true, tone: "red", href: (i) => pivotHref("ip", i.key) }))) : null,
    h("div", { class: "flex mt" }, h("h2", null, t("sessions")), h("a", { class: "right", href: "#/sessions?agent=" + a.id }, t("all"))),
    list.length ? h("div", { class: "tablewrap" }, h("table", { class: "nowrap" },
      h("thead", null, h("tr", null, [t("time"), t("user"), t("ip"), t("key"), t("ht_duration"), t("ht_commandsN"), "sudo", t("alerts")].map((x) => h("th", null, x)))),
      h("tbody", null, list.slice(0, 30).map((x) => h("tr", { class: "click", onclick: () => { location.hash = sessionHref(x); } },
        h("td", { class: "nowrap" }, h("a", { href: sessionHref(x) }, new Date(x.start).toLocaleString(lang))),
        h("td", { class: "mono" }, x.user), h("td", { class: "mono" }, x.ip), h("td", { class: "mono" }, x.key || x.method),
        h("td", { class: "nowrap" }, x.end ? fmtDur(x.start, x.end) : h("span", { class: "chip" }, h("span", { class: "dot ok" }), t("open"))),
        h("td", null, x.commands), h("td", null, x.sudo), h("td", null, x.alerts ? h("span", { class: "sev high" }, x.alerts) : "0")))))) : h("div", { class: "card empty" }, t("noEvents")),
  ];
}

// failed logins per day: the attack chart's columns without the web part
function sshDays(days) {
  const c = dayChart(days);
  c.lastChild.remove();
  return c;
}

// The host's changelog: what changed on it, newest first, by day.
const CHANGE_KINDS = ["file", "systemd", "cron", "keys", "users", "ports", "programs", "packages", "kernel", "containers", "agent"];
function changeKind(r) {
  const ty = r.event.type, d = r.event.data || {};
  if (ty.startsWith("file.")) return d.category === "systemd" ? "systemd" : d.category === "cron" ? "cron" : "file";
  if (ty.startsWith("ssh.key_")) return "keys";
  if (ty.startsWith("user.")) return "users";
  if (ty.startsWith("port.")) return "ports";
  if (ty.startsWith("process.")) return "programs";
  if (ty === "packages.changed") return "packages";
  if (ty.startsWith("kernel.")) return "kernel";
  if (ty.startsWith("container.")) return "containers";
  return "agent";
}
function changeText(r) {
  const ty = r.event.type, d = r.event.data || {};
  const key = "ch_" + ty.replace(".", "_");
  const verb = t(key) === key ? ty : t(key);
  const mono = (x) => h("span", { class: "mono" }, x);
  if (ty.startsWith("file.")) return [verb, " ", mono(d.path || ""), d.has_diff ? h("span", { class: "muted" }, "  ·  " + t("ht_diffOnTimeline")) : null];
  if (ty.startsWith("ssh.key_")) return [verb, " ", mono(d.comment || d.fingerprint || ""), h("span", { class: "muted" }, " " + (d.file || ""))];
  if (ty.startsWith("port.")) return [verb, " ", mono((d.proto || "") + "/" + (d.port || "") + " " + (d.addr || "")), d.process ? h("span", { class: "muted" }, "  ·  " + d.process) : null];
  if (ty === "packages.changed") {
    const part = (k, sign) => (d[k] || []).map((p) => h("div", { class: "mono" }, sign + " " + p[0] + " " + (p.length > 2 ? p[1] + " → " + p[2] : p[1])));
    return h("details", null, h("summary", null, t("ht_pkgSummary").replace("{a}", d.added_n).replace("{r}", d.removed_n).replace("{c}", d.changed_n)),
      h("div", { class: "pkgdiff" }, part("added", "+"), part("removed", "−"), part("changed", "~")));
  }
  if (ty.startsWith("user.")) return [verb, " ", mono(d.user || d.name || ""), d.uid != null ? h("span", { class: "muted" }, "  ·  uid " + d.uid) : null];
  if (ty === "agent.stopping") return [verb, d.reason ? h("span", { class: "muted" }, "  ·  " + d.reason) : null];
  if (ty.startsWith("process.")) return [verb, " ", mono(d.exe || d.comm || ""), d.parent_comm ? h("span", { class: "muted" }, "  ·  " + d.parent_comm) : null];
  if (ty === "agent.started" || ty === "agent.update") return [verb, " ", mono(d.version || d.to || "")];
  return [verb, " ", dataLine(d)];
}
async function hostChangesTab(a, d, params) {
  const days = hostDays(params, "7");
  const kind = CHANGE_KINDS.includes(params.get("kind")) ? params.get("kind") : "";
  const act = await api("/api/ui/agents/" + encodeURIComponent(a.id) + "/activity?days=" + days);
  const counts = {};
  for (const r of act.changes) counts[changeKind(r)] = (counts[changeKind(r)] || 0) + 1;
  const shown = kind ? act.changes.filter((r) => changeKind(r) === kind) : act.changes;
  const byDay = [];
  for (const r of shown) {
    const day = new Date(r.event.ts || r.time).toLocaleDateString(lang, { weekday: "long", day: "numeric", month: "long" });
    if (!byDay.length || byDay[byDay.length - 1][0] !== day) byDay.push([day, []]);
    byDay[byDay.length - 1][1].push(r);
  }
  const kindHref = (k) => hostHref(a.id, "changes", { days, ...(k ? { kind: k } : {}) });
  return [
    h("div", { class: "flex" }, h("h2", null, t("ht_changesTitle")), h("div", { class: "right" }, daysPick(a.id, "changes", days, params))),
    h("div", { class: "tabs mt" }, h("a", { class: "tab" + (kind ? "" : " on"), href: kindHref("") }, t("all") + " " + act.changes.length),
      CHANGE_KINDS.filter((k) => counts[k]).map((k) => h("a", { class: "tab" + (k === kind ? " on" : ""), href: kindHref(k) }, t("ck_" + k) + " " + counts[k]))),
    act.partial ? scopeNote(t("ht_partial")) : null,
    act.truncated ? scopeNote(t("ht_truncated")) : null,
    shown.length ? byDay.map(([day, list]) => [h("h3", { class: "mt" }, day), h("div", { class: "list changes" }, list.map((r) => h("div", { class: "row" },
      h("span", { class: "chip" }, t("ck_" + changeKind(r))),
      h("div", null, h("div", { class: "title" }, changeText(r))),
      h("div", { class: "meta" }, h("a", { href: tlHref(a.id, r.event.ts || r.time, { minutes: 30 }), title: t("timeline") }, hhmmss(r.event.ts || r.time))))))])
      : h("div", { class: "card empty" }, t("ht_noChanges")),
  ];
}

async function eventsView(params) {
  const q = params.get("q") || "";
  if (q) return searchView(params);
  const agents = scopeHosts || (await api("/api/ui/overview")).agents;
  const agent = params.get("agent") || scopeSel.agent || "";
  const group = params.get("agent") ? "" : scopeSel.group || "";
  const type = params.get("type") || "";
  const tbody = h("tbody");
  let before = 0;
  const more = h("button", { class: "btn ghost mt" }, t("loadMore"));
  async function load() {
    const qs = new URLSearchParams({ agent, group, type, limit: "200" });
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
  const scopeLine = [(agents.find((a) => a.id === agent) || {}).name || (group ? t("group") + " " + group : t("allHosts")), type].filter(Boolean).join(", ");
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
  const agent = params.get("agent") || scopeSel.agent || "";
  const r = await api("/api/ui/sessions?" + new URLSearchParams({ days, agent }));
  if (!agent && scopeSel.group && r.sessions) r.sessions = r.sessions.filter((x) => inScopeHost(x.agent));
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
  const readableBox = h("input", { type: "checkbox", name: "readable" });
  const showRoots = () => {
    const a = o.agents.find((x) => x.id === agentSel.value);
    roots.textContent = t("canaryRoots") + ": " + ((a && a.canary_roots && a.canary_roots.join("  ")) || t("none"));
    readableBox.disabled = !(a && a.canary_readable);
    if (readableBox.disabled) readableBox.checked = false;
  };
  agentSel.addEventListener("change", showRoots);
  showRoots();
  const form = h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault();
    const f = new FormData(form);
    err.textContent = "";
    try {
      await post("/api/ui/canaries", { agent_id: f.get("agent_id"), type: f.get("type"), path: f.get("path").trim(),
        params: { domain: f.get("domain"), email: f.get("email"), comment: f.get("comment") }, readable: readableBox.checked });
      render();
    } catch (x) { err.textContent = x.message; }
  } },
    h("div", { class: "grid two" }, h("label", null, t("host"), agentSel), h("label", null, t("type"), typeSel)),
    h("label", null, t("path"), pathIn), roots,
    h("label", { class: "check" }, readableBox, t("readable")),
    h("div", { class: "grid tiles" },
      h("label", null, t("domain"), h("input", { name: "domain" })),
      h("label", null, t("email"), h("input", { name: "email", type: "email" })),
      h("label", null, t("comment"), h("input", { name: "comment" }))),
    err, h("div", null, h("button", { class: "btn", type: "submit", disabled: !o.agents.length }, t("place"))));

  const rows = canaries.map((c) => h("div", { class: "row" },
    statusChip(c.status),
    h("div", null,
      h("div", { class: "title mono" }, c.path),
      h("div", { class: "sub" }, [c.host, c.type, c.readable ? t("readableTag") : null].filter(Boolean).join("  ·  ")),
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
// the running number of an incident, INC-0042: to say, search and paste
const incRef = (c) => c.ref ? h("span", { class: "incref mono" }, c.ref) : null;
async function copyText(text, btn) {
  try { await navigator.clipboard.writeText(text); } catch { prompt("", text); return; }
  if (!btn) return;
  const was = btn.textContent;
  btn.textContent = t("incCopied");
  setTimeout(() => { btn.textContent = was; }, 1500);
}
const incRow = (c) => h("a", { class: "row", href: "#/incidents/" + (c.ref || c.id) },
  sevChip(c.severity),
  h("div", null, h("div", { class: "title" }, incRef(c), c.title || c.id),
    h("div", { class: "sub" }, [c.host, c.count + " " + t("alertsN"), t("owner") + ": " + (c.owner || t("unowned"))].join("  ·  "))),
  h("div", { class: "meta" }, incChip(c.status), timeEl(c.last)));

async function incidentsView() {
  const r = await api("/api/ui/incidents?" + scopeQ({ status: incTab === "all" ? "" : incTab }));
  const tabs = h("div", { class: "tabs" }, [["active", t("activeInc")], ["closed", t("closed")], ["all", t("all")]].map(([k, l]) =>
    h("button", { class: k === incTab ? "on" : null, onclick: () => { incTab = k; render(); } }, l)));
  const go = h("form", { class: "incgo", onsubmit: (e) => {
    e.preventDefault();
    const v = find.value.trim();
    if (v) location.hash = "#/incidents/" + encodeURIComponent(/^\d+$/.test(v) ? "INC-" + v.padStart(4, "0") : v.toUpperCase());
  } });
  const find = h("input", { type: "search", class: "mono", placeholder: t("incGoto"), title: t("incGotoHint"), "aria-label": t("incGotoHint"), maxlength: 20 });
  go.append(find);
  mount(shell("incidents", h("h1", null, t("incidents")),
    h("div", { class: "crumbs" }, r.incidents.length + " " + (incTab === "all" ? t("incidents") : (incTab === "active" ? t("activeInc") : t("closed")).toLowerCase())
      + (r.mttc_seconds != null ? "  ·  " + t("mttc") + " " + duration(r.mttc_seconds) : "")),
    h("div", { class: "flex toolbar" }, tabs, h("span", { class: "right" }, go)), h("div", { class: "list" }, r.incidents.length ? r.incidents.map(incRow) : h("div", { class: "empty" }, t("noIncidents")))));
}

async function incidentDetail(id) {
  let d;
  try { d = await api("/api/ui/incidents/" + encodeURIComponent(id)); } catch (x) {
    if (x.message === "unauthorized") throw x;
    mount(shell("incidents", h("div", { class: "crumbs" }, h("a", { href: "#/incidents" }, t("incidents"))),
      h("div", { class: "card empty" }, t("incNotFound").replace("{r}", decodeURIComponent(id)))));
    return;
  }
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
    h("div", { class: "crumbs" }, h("a", { href: "#/incidents" }, t("incidents")), " / " + (c.ref || c.id)),
    // the topbar shows the h1 as text, the browser tab too
    h("h1", null, (c.ref ? c.ref + "  ·  " : "") + (c.title || c.id)),
    h("div", { class: "page-actions" }, c.owner !== me.user && can("analyst", c.agent) ? h("button", { class: "btn", onclick: act("assign") }, t("assignMe")) : null,
      c.ref ? h("button", { class: "btn ghost", onclick: (e) => copyText(c.ref, e.currentTarget) }, t("incCopyRef")) : null,
      can("analyst", c.agent) ? h("button", { class: "btn ghost", title: t("incCopyTextHint"), onclick: async (e) => {
        const b = e.currentTarget;
        const res = await fetch("/api/ui/incidents/" + c.id + "/text?lang=" + lang, { credentials: "same-origin" });
        if (res.ok) copyText(await res.text(), b);
      } }, t("incCopyText")) : null,
      can("analyst", c.agent) ? h("a", { class: "btn ghost", href: "/api/ui/incidents/" + c.id + "/report?format=md" }, t("reportMD")) : null,
      can("analyst", c.agent) ? h("a", { class: "btn ghost", href: "/api/ui/incidents/" + c.id + "/report?format=html", target: "_blank", rel: "noopener" }, t("reportPrint")) : null),
    h("div", { class: "grid two" },
      h("div", { class: "card" }, h("dl", { class: "kv" },
        h("dt", null, t("status")), h("dd", null, incChip(c.status)),
        h("dt", null, t("severity")), h("dd", null, sevChip(c.severity)),
        h("dt", null, t("host")), h("dd", null, h("a", { href: "#/hosts/" + c.agent }, c.host || c.agent)),
        h("dt", null, t("owner")), h("dd", null, c.owner || t("unowned")),
        h("dt", null, t("created")), h("dd", null, abs(c.created)),
        h("dt", null, t("updated")), h("dd", null, abs(c.last)),
        h("dt", null, t("alerts")), h("dd", null, c.count + (c.open_alerts ? " (" + c.open_alerts + " " + t("open").toLowerCase() + ")" : ""))),
        !can("analyst", c.agent) ? null : h("div", { class: "actions" }, h("span", { class: "muted" }, t("setStatus")),
          h("div", { class: "tabs" }, ["open", "investigating", "contained", "closed"].map((st) =>
            h("button", { class: st === c.status ? "on" : null, onclick: act("status", { status: st }) }, t(st === "open" ? "openInc" : st)))))),
      h("div", { class: "card" }, h("h3", null, t("notes")),
        h("div", { class: "notes" }, (c.notes || []).map((n) => h("div", { class: "note" },
          h("div", { class: "note-head" }, h("span", { class: "strong" }, n.by), " ", h("span", { class: "muted" }, abs(n.at))),
          h("div", { class: "note-text" }, n.text)))),
        !can("analyst", c.agent) ? null : h("form", { class: "stack mt", onsubmit: async (e) => { e.preventDefault(); await act("note", { note: note.value })(); } },
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
      Object.keys(sp.match || {}).length || Object.keys(sp.patterns || {}).length ? h("div", { class: "sub mono" },
        [...Object.entries(sp.match || {}).map(([k, v]) => k + " = " + v), ...Object.entries(sp.patterns || {}).map(([k, v]) => k + " ~ " + v)].join("  ·  ")) : null,
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
  const summaryBox = h("div");
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
      h("td", null, groupRolesCell(u, askCode, (m) => { uErr.textContent = m; })),
      h("td", { class: "nowrap" }, u.last_login && !u.last_login.startsWith("0001") ? timeEl(u.last_login) : "·"),
      h("td", null, u.passkeys),
      h("td", null, u.name === me.user ? null : h("button", { class: "btn small ghost", onclick: async () => {
        if (!confirm(u.name + ": " + t("remove") + "?")) return;
        const code = askCode(); if (!code) return;
        try { await post("/api/ui/users/" + encodeURIComponent(u.name) + "/delete", { code }); render(); } catch (x) { uErr.textContent = x.message; }
      } }, t("remove"))));
    const tbody = h("tbody", null, users.map(userRow));
    usersCard = h("div", { class: "card mt" }, h("h3", null, t("users")),
      h("div", { class: "tablewrap flat" }, h("table", null, h("thead", null, h("tr", null, [t("name"), t("role"), t("groupRoles"), t("lastLogin"), t("passkeys"), ""].map((x) => h("th", null, x)))), tbody)),
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
    can("admin", "") && scopeHosts && scopeHosts.length ? groupsAdmin(scopeHosts) : null,
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
      h("dl", { class: "kv mt" }, h("dt", null, t("heartbeat")), h("dd", null, t(notif.heartbeat ? "configured" : "notConfigured")),
        h("dt", null, t("summary")), h("dd", null, notif.summary_time ? t("summaryAt") + " " + notif.summary_time : t("notConfigured") + " (summary_time)")),
      can("admin") && notif.notifiers.length ? h("div", { class: "actions" }, h("button", { class: "btn ghost", onclick: async () => {
        notifyErr.textContent = "";
        try { drawNotifiers((await post("/api/ui/notify/test")).notifiers); } catch (x) { notifyErr.textContent = x.message; }
      } }, t("notifyTest")),
      h("button", { class: "btn ghost", onclick: async () => {
        notifyErr.textContent = "";
        try { summaryBox.replaceChildren(h("div", { class: "secret summary mt" }, (await api("/api/ui/summary")).text)); } catch (x) { notifyErr.textContent = x.message; }
      } }, t("summaryPreview")),
      h("button", { class: "btn ghost", onclick: async () => {
        notifyErr.textContent = "";
        try { await post("/api/ui/summary/send"); summaryBox.replaceChildren(h("div", { class: "muted mt" }, t("summarySent"))); } catch (x) { notifyErr.textContent = x.message; }
      } }, t("summarySend"))) : null, summaryBox, notifyErr),
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

// ---------- attackers ----------

let worldLoad = null;
// The country outlines (about 100 KB) load with the first map.
function loadWorld() {
  if (window.VIGIL_WORLD) return Promise.resolve(window.VIGIL_WORLD);
  if (!worldLoad) {
    const own = document.querySelector('script[src^="app.js"]');
    const v = own ? (own.getAttribute("src").split("?v=")[1] || "") : "";
    worldLoad = new Promise((ok, fail) => {
      const el = document.createElement("script");
      el.src = "world.js" + (v ? "?v=" + v : "");
      el.onload = () => ok(window.VIGIL_WORLD);
      el.onerror = () => { worldLoad = null; fail(new Error("world.js")); };
      document.head.append(el);
    });
  }
  return worldLoad;
}

let regionNames = null;
function countryName(cc) {
  if (!cc || cc === "??") return t("unknown");
  try {
    if (!regionNames || regionNames.lang !== lang) regionNames = { lang, dn: new Intl.DisplayNames([lang], { type: "region" }) };
    return regionNames.dn.of(cc) || cc;
  } catch { return cc; }
}

// worldMap colours each country by its attempts (log scale) and puts a dot
// on countries too small to see.
function worldMap(countries, onPick) {
  const box = h("div", { class: "worldmap" }, h("div", { class: "empty small" }, "…"));
  loadWorld().then((w) => {
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 " + w.w + " " + w.h);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", t("worldMap"));
    const by = {};
    countries.forEach((c) => { by[c.key] = c; });
    const max = Math.max(1, ...countries.map((c) => c.count));
    const level = (n) => n ? 0.18 + 0.82 * Math.log(1 + n) / Math.log(1 + max) : 0;
    const label = (cc) => { const c = by[cc]; return countryName(cc) + (c ? "  ·  " + c.ips + " " + t("addresses") + ", " + c.count.toLocaleString(lang) + " " + t("attemptsN") : ""); };
    const hook = (el, cc) => {
      el.addEventListener("mousemove", (e) => tip(e, label(cc)));
      el.addEventListener("mouseleave", (e) => tip(e, null));
      if (by[cc] && onPick) { el.addEventListener("click", () => onPick(cc)); el.setAttribute("class", el.getAttribute("class") + " pick"); }
    };
    for (const [cc, d] of Object.entries(w.paths)) {
      const p = document.createElementNS(SVG, "path");
      p.setAttribute("d", d);
      p.setAttribute("class", "land" + (by[cc] ? " hit" : ""));
      if (by[cc]) p.style.fillOpacity = level(by[cc].count);
      hook(p, cc);
      svg.append(p);
    }
    for (const c of countries) {
      const at = w.dots[c.key];
      if (!at || w.paths[c.key] && w.paths[c.key].length > 160) continue;
      const dot = document.createElementNS(SVG, "circle");
      dot.setAttribute("cx", at[0]);
      dot.setAttribute("cy", at[1]);
      dot.setAttribute("r", 3 + 5 * level(c.count));
      dot.setAttribute("class", "dot-hit");
      hook(dot, c.key);
      svg.append(dot);
    }
    box.replaceChildren(svg);
  }).catch(() => box.replaceChildren(h("div", { class: "empty small" }, t("worldMap"))));
  return box;
}

// ---- attack analytics -------------------------------------------------
// Every chart uses one red scale (the world map's), so "darker means more"
// reads the same everywhere. User names are attacker-controlled: they only
// ever become text nodes.

function sv(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) el.setAttribute(k, v);
  for (const c of kids.flat()) if (c != null) el.append(typeof c === "string" ? document.createTextNode(c) : c);
  return el;
}
function hoverTip(el, text) {
  el.addEventListener("mousemove", (e) => tip(e, typeof text === "function" ? text() : text));
  el.addEventListener("mouseleave", (e) => tip(e, null));
  return el;
}
const heatLevel = (n, max) => n ? 0.12 + 0.88 * Math.log(1 + n) / Math.log(1 + Math.max(1, max)) : 0;
function localHours(utc) {
  const off = Math.round(-new Date().getTimezoneOffset() / 60);
  return Array.from({ length: 24 }, (_, i) => utc[((i - off) % 24 + 24) % 24]);
}
const userLabel = (u) => u === "*" ? t("otherUsers") : u;
const ccLabel = (cc) => cc === "*" ? t("otherCountries") : countryName(cc);
const num = (n) => n.toLocaleString(lang);

function heatCell(level, text, cls) {
  const fill = h("span", { class: "hfill" });
  fill.style.opacity = level;
  return h("div", { class: "hcell" + (cls ? " " + cls : "") + (level > 0.62 ? " hot" : "") }, fill, text != null ? h("span", { class: "hnum" }, text) : null);
}

function sparkline(values, label) {
  const W = 84, H = 22, max = Math.max(1, ...values);
  const pts = values.map((v, i) => [values.length > 1 ? i * (W - 4) / (values.length - 1) + 2 : W / 2, H - 3 - (v / max) * (H - 6)]);
  const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "spark", role: "img", "aria-label": label + ": " + values.join(", ") },
    sv("polyline", { points: pts.map((p) => p.map((x) => x.toFixed(1)).join(",")).join(" ") }),
    sv("circle", { cx: pts[pts.length - 1][0].toFixed(1), cy: pts[pts.length - 1][1].toFixed(1), r: 2.5 }));
  return hoverTip(svg, label + ": " + values.join(" · "));
}

// ranked table: attempts as inline bars, spread, and the trend per day (or
// per hour for a one-day window)
function userTable(stats, days) {
  const top = stats.slice(0, 15);
  if (!top.length) return h("div", { class: "empty small" }, t("noUserData"));
  const max = Math.max(...top.map((s) => s.attempts));
  return h("div", { class: "scrollx" }, h("table", { class: "usertable" },
    h("thead", null, h("tr", null, [t("userName"), t("attemptsN"), t("addresses"), t("countries"), days === 1 ? t("trend24") : t("trendDays")].map((x) => h("th", null, x)))),
    h("tbody", null, top.map((s) => {
      const bar = h("span", { class: "inbar-fill" });
      bar.style.width = (100 * s.attempts / max).toFixed(1) + "%";
      return h("tr", null,
        h("td", { class: "mono ucell" }, h("a", { href: pivotHref("user", s.user) }, s.user), s.existing ? h("span", { class: "acct", title: t("accountExists") }, t("accountShort")) : null),
        h("td", { class: "barcell" }, h("span", { class: "inbar" }, bar), h("span", { class: "num-sm" }, num(s.attempts))),
        h("td", { class: "num-sm" }, num(s.ips)),
        h("td", { class: "num-sm" }, num(s.countries)),
        h("td", null, sparkline(days === 1 ? localHours(s.hours) : s.days, s.user)));
    }))));
}

// heatmap user name x local hour of day
function userHeatmap(stats) {
  const top = stats.slice(0, 12);
  if (!top.length) return h("div", { class: "empty small" }, t("noUserData"));
  const rows = top.map((s) => ({ user: s.user, hours: localHours(s.hours) }));
  const max = Math.max(1, ...rows.flatMap((r) => r.hours));
  const grid = h("div", { class: "heatgrid", role: "table", "aria-label": t("heatTitle") });
  grid.append(h("div", { class: "hlabel" }), ...Array.from({ length: 24 }, (_, i) => h("div", { class: "hhead" }, i % 3 === 0 ? String(i) : "")));
  for (const r of rows) {
    grid.append(h("div", { class: "hlabel mono", title: r.user }, r.user));
    r.hours.forEach((n, i) => grid.append(hoverTip(heatCell(heatLevel(n, max)), r.user + "  ·  " + String(i).padStart(2, "0") + ":00  ·  " + num(n) + " " + t("attemptsN"))));
  }
  return h("div", { class: "scrollx" }, grid);
}

// matrix user name x country with the count in each cell
function userCountryMatrix(m) {
  if (!m.users.length || !m.countries.length) return h("div", { class: "empty small" }, t("noUserData"));
  const max = Math.max(1, ...m.cells.flat());
  const grid = h("div", { class: "matrix", role: "table", "aria-label": t("matrixTitle") });
  grid.style.gridTemplateColumns = "minmax(64px, 120px) repeat(" + m.countries.length + ", minmax(34px, 1fr))";
  grid.append(h("div", { class: "hlabel" }), ...m.countries.map((cc) => h("div", { class: "mhead", title: countryName(cc) }, cc === "??" ? "?" : cc)));
  m.users.forEach((u, i) => {
    grid.append(h("div", { class: "hlabel mono", title: u }, u));
    m.cells[i].forEach((n, j) => grid.append(hoverTip(heatCell(heatLevel(n, max), n ? num(n) : "", "mcell"),
      u + "  ·  " + countryName(m.countries[j]) + "  ·  " + num(n) + " " + t("attemptsN"))));
  });
  return h("div", { class: "scrollx" }, grid);
}

// three-column Sankey of rows [a, b, c, count]. opts: labels (one per
// column), mono (column shown in monospace), hot (third-column key drawn
// strong), unit, empty, title
function sankey3(rows, opts) {
  if (!rows.length) return h("div", { class: "empty small" }, opts.empty);
  const W = 680, H = 340, NW = 10, GAP = 6, X = [140, 340, 520];
  const cols = [new Map(), new Map(), new Map()];
  const bump = (col, key, n) => cols[col].set(key, (cols[col].get(key) || 0) + n);
  const l1 = new Map(), l2 = new Map();
  for (const [a, b, c, n] of rows) {
    bump(0, a, n); bump(1, b, n); bump(2, c, n);
    l1.set(a + "\n" + b, (l1.get(a + "\n" + b) || 0) + n);
    l2.set(b + "\n" + c, (l2.get(b + "\n" + c) || 0) + n);
  }
  const total = rows.reduce((s, r) => s + r[3], 0);
  const hot = opts.hot || (() => false);
  const nodes = cols.map((m) => {
    const keys = [...m.keys()].sort((a, b) => (a === "*") - (b === "*") || m.get(b) - m.get(a));
    const scale = (H - GAP * (keys.length - 1)) / total;
    let y = 0;
    const out = new Map();
    for (const k of keys) { const hgt = Math.max(1, m.get(k) * scale); out.set(k, { y, h: hgt, n: m.get(k), inY: y, outY: y }); y += hgt + GAP; }
    return { out, scale };
  });
  const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "sankey", role: "img", "aria-label": opts.title });
  const band = (x0, y0, x1, y1, w) => {
    const mx = (x0 + x1) / 2;
    return "M" + x0 + "," + y0 + "C" + mx + "," + y0 + " " + mx + "," + y1 + " " + x1 + "," + y1 +
      "L" + x1 + "," + (y1 + w) + "C" + mx + "," + (y1 + w) + " " + mx + "," + (y0 + w) + " " + x0 + "," + (y0 + w) + "Z";
  };
  const links = (map, a, b) => {
    const order = [...map.entries()].sort((p, q) => {
      const [pa, pb] = p[0].split("\n"), [qa, qb] = q[0].split("\n");
      return nodes[a].out.get(pa).y - nodes[a].out.get(qa).y || nodes[b].out.get(pb).y - nodes[b].out.get(qb).y;
    });
    for (const [key, n] of order) {
      const [ka, kb] = key.split("\n");
      const na = nodes[a].out.get(ka), nb = nodes[b].out.get(kb);
      const w = n * nodes[a].scale;
      const p = sv("path", { d: band(X[a] + NW, na.outY, X[b], nb.inY, w), class: "link" + (b === 2 && hot(kb) ? " exist" : "") });
      hoverTip(p, opts.labels[a](ka) + "  →  " + opts.labels[b](kb) + "  ·  " + num(n) + " " + opts.unit);
      svg.append(p);
      na.outY += w; nb.inY += n * nodes[b].scale;
    }
  };
  links(l1, 0, 1);
  links(l2, 1, 2);
  nodes.forEach((col, ci) => {
    for (const [k, nd] of col.out) {
      svg.append(hoverTip(sv("rect", { x: X[ci], y: nd.y.toFixed(1), width: NW, height: nd.h.toFixed(1), rx: 2, class: "node" + (ci === 2 && hot(k) ? " exist" : "") }),
        opts.labels[ci](k) + "  ·  " + num(nd.n)));
      const left = ci === 0;
      if (nd.h >= 12) {
        svg.append(sv("text", { x: left ? X[ci] - 6 : X[ci] + NW + 6, y: (nd.y + nd.h / 2).toFixed(1), "text-anchor": left ? "end" : "start", class: "nlabel" + (ci === opts.mono && k !== "*" ? " mono" : "") },
          opts.labels[ci](k)));
      }
    }
  });
  return h("div", { class: "scrollx" }, svg);
}

// Sankey: country -> user name -> account exists on the host or not
function userSankey(flows) {
  const acct = (k) => k === "yes" ? t("accountExists") : t("accountMissing");
  return sankey3(flows.map((f) => [f.country, f.user, f.existing ? "yes" : "no", f.count]),
    { labels: [ccLabel, userLabel, acct], mono: 1, hot: (k) => k === "yes", unit: t("attemptsN"), empty: t("noUserData"), title: t("sankeyTitle") });
}

// squarified treemap (Bruls, Huizing, van Wijk) of items {v} in a rectangle
function squarify(items, x, y, w, hgt) {
  const total = items.reduce((a, b) => a + b.v, 0);
  if (!total) return [];
  const scale = w * hgt / total;
  const queue = items.filter((i) => i.v > 0).map((i) => ({ ...i, a: i.v * scale }));
  const out = [];
  let row = [];
  const worst = (r, side) => {
    const s = r.reduce((a, b) => a + b.a, 0), mx = Math.max(...r.map((q) => q.a)), mn = Math.min(...r.map((q) => q.a));
    return Math.max(side * side * mx / (s * s), s * s / (side * side * mn));
  };
  const flush = () => {
    const s = row.reduce((a, b) => a + b.a, 0);
    if (w >= hgt) {
      const rw = s / hgt; let yy = y;
      for (const r of row) { const rh = r.a / rw; out.push({ ...r, x, y: yy, w: rw, h: rh }); yy += rh; }
      x += rw; w -= rw;
    } else {
      const rh = s / w; let xx = x;
      for (const r of row) { const rw = r.a / rh; out.push({ ...r, x: xx, y, w: rw, h: rh }); xx += rw; }
      y += rh; hgt -= rh;
    }
    row = [];
  };
  while (queue.length) {
    const side = Math.min(w, hgt);
    if (!row.length || worst([...row, queue[0]], side) <= worst(row, side)) row.push(queue.shift());
    else flush();
  }
  if (row.length) flush();
  return out;
}

// treemap: area = attempts, countries holding their networks
function originTreemap(countries, networks) {
  const top = countries.filter((c) => c.count > 0).slice(0, 10);
  if (!top.length) return h("div", { class: "empty small" }, t("noAttacks"));
  const restN = countries.slice(10).reduce((a, c) => a + c.count, 0);
  const items = top.map((c) => ({ key: c.key, v: c.count }));
  if (restN) items.push({ key: "*", v: restN });
  const W = 1000, H = 360;
  const max = Math.max(...items.map((i) => i.v));
  const fit = (text, width, px) => { const n = Math.floor((width - 16) / px); return text.length <= n ? text : n > 3 ? text.slice(0, n - 1) + "…" : ""; };
  const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, class: "treemap", role: "img", "aria-label": t("treemapTitle") });
  for (const c of squarify(items, 0, 0, W, H)) {
    const nets = networks.filter((n) => n.country === c.key && n.count > 0).map((n) => ({ key: "AS" + n.asn + " " + n.org, v: n.count }));
    const known = nets.reduce((a, n) => a + n.v, 0);
    if (c.v - known > 0) nets.push({ key: t("otherNetworks"), v: c.v - known, rest: true });
    const level = heatLevel(c.v, max);
    for (const n of squarify(nets.length ? nets : [{ key: "", v: c.v }], c.x, c.y, c.w, c.h)) {
      const r = sv("rect", { x: n.x.toFixed(1), y: n.y.toFixed(1), width: Math.max(0, n.w).toFixed(1), height: Math.max(0, n.h).toFixed(1), class: "tcell" + (n.rest ? " rest" : "") });
      r.style.fillOpacity = n.rest ? level * 0.55 : level;
      svg.append(hoverTip(r, ccLabel(c.key) + (n.key ? "  ·  " + n.key : "") + "  ·  " + num(n.v) + " " + t("attemptsN")));
    }
    svg.append(sv("rect", { x: c.x.toFixed(1), y: c.y.toFixed(1), width: c.w.toFixed(1), height: c.h.toFixed(1), class: "tframe" }));
    if (c.w > 50 && c.h > 34) {
      svg.append(sv("text", { x: (c.x + 8).toFixed(1), y: (c.y + 18).toFixed(1), class: "tlabel" + (level > 0.62 ? " hot" : "") }, fit(ccLabel(c.key), c.w, 7.2)));
      svg.append(sv("text", { x: (c.x + 8).toFixed(1), y: (c.y + 32).toFixed(1), class: "tsub" + (level > 0.62 ? " hot" : "") }, num(c.v)));
    }
  }
  return h("div", { class: "scrollx" }, svg);
}

// word cloud: the biggest names in the middle, existing accounts in red
function userCloud(stats) {
  const list = stats.slice(0, 60);
  if (!list.length) return h("div", { class: "empty small" }, t("noUserData"));
  const max = Math.max(...list.map((s) => s.attempts)), min = Math.min(...list.map((s) => s.attempts));
  const size = (n) => 12 + 26 * (max === min ? 1 : Math.sqrt((n - min) / (max - min)));
  const ordered = [];
  list.forEach((s, i) => { if (i % 2) ordered.push(s); else ordered.unshift(s); });
  return h("div", { class: "cloud" }, ordered.map((s) => {
    const a = h("a", { class: "word mono" + (s.existing ? " exist" : ""), href: pivotHref("user", s.user) }, s.user);
    a.style.fontSize = size(s.attempts).toFixed(1) + "px";
    return hoverTip(a, s.user + "  ·  " + num(s.attempts) + " " + t("attemptsN") + ", " + num(s.ips) + " " + t("addresses") + (s.existing ? "  ·  " + t("accountExists") : ""));
  }));
}

// columns per hour of the local day (the server counts in UTC)
function hourChart(utc) {
  const off = -new Date().getTimezoneOffset() / 60;
  const local = Array.from({ length: 24 }, (_, i) => utc[((i - Math.round(off)) % 24 + 24) % 24]);
  const max = Math.max(1, ...local);
  const chart = h("div", { class: "chart alt" });
  local.forEach((v, i) => {
    const bar = h("div", { class: "bar" });
    bar.style.height = (v / max * 100) + "%";
    chart.append(h("div", { class: "slot", onmousemove: (e) => tip(e, String(i).padStart(2, "0") + ":00  ·  " + v.toLocaleString(lang)), onmouseleave: (e) => tip(e, null) }, bar));
  });
  return h("div", null, chart, h("div", { class: "axis" }, ["00", "06", "12", "18", "23"].map((x) => h("span", null, x))));
}

function dayChart(days) {
  const max = Math.max(1, ...days.map((d) => d.ssh + d.web));
  const chart = h("div", { class: "chart stacked" });
  days.forEach((d) => {
    const col = h("div", { class: "stack" });
    for (const [k, cls] of [["web", "high"], ["ssh", "critical"]]) {
      if (!d[k]) continue;
      const seg = h("div", { class: "seg " + cls });
      seg.style.height = (d[k] / max * 100) + "%";
      col.append(seg);
    }
    const day = new Date(d.day + "T12:00:00Z").toLocaleDateString(lang, { weekday: "short", day: "numeric", month: "numeric" });
    chart.append(h("div", { class: "slot", onmousemove: (e) => tip(e, day + "  ·  SSH " + d.ssh.toLocaleString(lang) + ", Web " + d.web.toLocaleString(lang) + ", " + d.ips + " " + t("addresses")), onmouseleave: (e) => tip(e, null) }, col));
  });
  const fmt = (d) => new Date(d.day + "T12:00:00Z").toLocaleDateString(lang, { day: "numeric", month: "numeric" });
  return h("div", null, chart,
    h("div", { class: "axis" }, h("span", null, fmt(days[0])), h("span", null, fmt(days[days.length - 1]))),
    h("div", { class: "legend" }, h("span", null, h("span", { class: "dot critical" }), "SSH"), h("span", null, h("span", { class: "dot high" }), "Web")));
}

const CLASS_DOT = { success: "critical", targeted: "high", persistent: "medium", noise: "low" };
const classChip = (c) => h("span", { class: "chip" }, h("span", { class: "dot " + CLASS_DOT[c] }), t("cls_" + c));
const netLabel = (a) => a.asn ? "AS" + a.asn + " " + (a.org || "") : "";
const geoAttr = (geo) => geo && geo.enabled ? h("div", { class: "attr" }, h("a", { href: geo.attribution_url, target: "_blank", rel: "noopener" }, t("geoAttr"))) : null;

let attackClass = "all";
// ---- sources: allied networks and other software ------------------------
// Everything a source reports is attacker-controlled text: names, users
// and addresses only ever become text nodes.

const catLabel = (c) => t("cat_" + c);
const leadText = (hrs) => hrs == null ? "·" : Math.abs(hrs) < 1 ? t("leadSame")
  : (hrs > 0 ? t("leadAhead") : t("leadBehind")).replace("{d}", Math.abs(hrs) >= 48 ? Math.round(Math.abs(hrs) / 24) + " d" : Math.round(Math.abs(hrs)) + " h");

function sourceMatrix(st, name) {
  const n = st.labels.length;
  if (n < 2) return h("div", { class: "empty small" }, t("noSources"));
  const max = Math.max(1, ...st.matrix.flat());
  const grid = h("div", { class: "matrix", role: "table", "aria-label": t("overlapTitle") });
  grid.style.gridTemplateColumns = "minmax(80px, 150px) repeat(" + n + ", minmax(44px, 1fr))";
  grid.append(h("div", { class: "hlabel" }), ...st.labels.map((l) => h("div", { class: "mhead", title: name(l) }, name(l))));
  st.labels.forEach((a, i) => {
    grid.append(h("div", { class: "hlabel", title: name(a) }, name(a)));
    st.matrix[i].forEach((v, j) => grid.append(hoverTip(heatCell(heatLevel(v, max), v ? num(v) : "", "mcell" + (i === j ? " diag" : "")),
      i === j ? name(a) + "  ·  " + num(v) + " " + t("addresses") : name(a) + "  ∩  " + name(st.labels[j]) + "  ·  " + num(v) + " " + t("addresses"))));
  });
  return h("div", { class: "scrollx" }, grid);
}

// who saw the shared attackers first: from "we, a day ahead" on the left to
// "the source, days ahead" on the right
function leadStrip(st) {
  const total = st.lead.reduce((a, b) => a + b, 0);
  if (!total) return h("div", { class: "empty small" }, t("noOverlap"));
  const max = Math.max(1, ...st.lead);
  return h("div", null,
    h("div", { class: "leadstrip" }, st.lead.map((v, i) => hoverTip(h("div", { class: "leadcell" + (i < 2 ? " ours" : i === 2 ? " same" : "") },
      heatCell(heatLevel(v, max), v ? num(v) : ""), h("div", { class: "leadlabel" }, t("lb" + i))), t("lb" + i) + "  ·  " + num(v) + " " + t("addresses")))),
    h("div", { class: "leadaxis muted small" }, h("span", null, "← " + t("weFirst")), h("span", null, t("theyFirst") + " →")));
}

function sourceHeatmap(st) {
  const rows = st.sources.filter((s) => s.active).map((s) => ({ name: s.name, hours: localHours(s.hours) }));
  if (!rows.length) return h("div", { class: "empty small" }, t("noSourceData"));
  const max = Math.max(1, ...rows.flatMap((r) => r.hours));
  const grid = h("div", { class: "heatgrid", role: "table", "aria-label": t("srcHeatTitle") });
  grid.append(h("div", { class: "hlabel" }), ...Array.from({ length: 24 }, (_, i) => h("div", { class: "hhead" }, i % 3 === 0 ? String(i) : "")));
  for (const r of rows) {
    grid.append(h("div", { class: "hlabel", title: r.name }, r.name));
    r.hours.forEach((n, i) => grid.append(hoverTip(heatCell(heatLevel(n, max)), r.name + "  ·  " + String(i).padStart(2, "0") + ":00  ·  " + num(n) + " " + t("addresses"))));
  }
  return h("div", { class: "scrollx" }, grid);
}

function sourceTable(st, days) {
  if (!st.sources.length) return h("div", { class: "empty small" }, t("noSources"));
  const max = Math.max(1, ...st.sources.map((s) => s.active));
  return h("div", { class: "scrollx" }, h("table", { class: "usertable" },
    h("thead", null, h("tr", null, [t("source"), t("reported"), t("overlapUs"), t("firstShare"), t("medianLead"), t("newPerDay"), t("status")].map((x) => h("th", null, x)))),
    h("tbody", null, st.sources.map((s) => {
      const bar = h("span", { class: "inbar-fill" });
      bar.style.width = (100 * s.active / max).toFixed(1) + "%";
      const share = s.overlap ? Math.round(100 * s.earlier / s.overlap) + " %" : "·";
      return h("tr", null,
        h("td", { class: "ucell" }, h("div", { class: "strong" }, s.name), h("div", { class: "muted small" }, [s.network, t("trust_" + s.trust)].filter(Boolean).join("  ·  "))),
        h("td", { class: "barcell" }, h("span", { class: "inbar" }, bar), h("span", { class: "num-sm" }, num(s.active))),
        h("td", { class: "num-sm" }, num(s.overlap)),
        h("td", { class: "num-sm" }, share),
        h("td", { class: "num-sm nowrap" }, leadText(s.lead_h)),
        h("td", null, sparkline(s.new, s.name)),
        h("td", { class: "small" }, !s.enabled ? h("span", { class: "muted" }, t("disabled"))
          : s.last_err ? h("span", { class: "warn", title: s.last_err }, t("fetchFailed"))
          : s.stale ? h("span", { class: "warn" }, t("staleShort"))
          : h("span", { class: "chip" }, h("span", { class: "dot ok" }), timeEl(s.last_ok))));
    }))));
}

function sourceTop(st, name) {
  if (!st.top.length) return h("div", { class: "empty small" }, t("noSourceData"));
  return h("div", { class: "tablewrap" }, h("table", { class: "evtable" },
    h("thead", null, h("tr", null, [t("ip"), t("seenBy"), t("firstSeenBy"), t("country"), t("categories"), t("ourAttempts"), t("reported")].map((x) => h("th", null, x)))),
    h("tbody", null, st.top.map((r) => h("tr", null,
      h("td", { class: "mono nowrap" }, h("a", { href: pivotHref("ip", r.ip) }, r.ip)),
      h("td", null, h("span", { class: "flex wrap" }, r.sources.map((id) => h("span", { class: "chip" + (id === "us" ? " us" : "") }, name(id))))),
      h("td", { class: "nowrap" }, name(r.first_by), h("div", { class: "muted small" }, abs(r.first))),
      h("td", null, r.country === "?" ? "·" : countryName(r.country)),
      h("td", { class: "small" }, r.cats.map(catLabel).join(", ")),
      h("td", { class: "num-sm" }, r.ours ? num(r.ours) : "·"),
      h("td", { class: "num-sm" }, r.reported ? num(r.reported) : "·"))))));
}

async function sourcesView(params) {
  const days = params.get("days") || "7";
  const [st, cfg] = await Promise.all([api("/api/ui/sources/stats?days=" + encodeURIComponent(days)),
    can("admin") ? api("/api/ui/sources") : Promise.resolve(null)]);
  const names = { us: t("usLabel") };
  st.sources.forEach((s) => { names[s.id] = s.name; });
  const name = (id) => names[id] || id;
  const daySel = h("div", { class: "tabs" }, [["1", t("day1")], ["7", t("days7")], ["30", t("days30").replace("{n}", 30)]].map(([k, l]) =>
    h("button", { class: k === String(st.days) ? "on" : null, onclick: () => { location.hash = "#/sources?days=" + k; } }, l)));
  const active = st.sources.filter((s) => s.enabled).length;
  const reported = new Set(st.top.map((r) => r.ip)).size;
  const sumActive = st.sources.reduce((a, s) => a + s.active, 0);
  const tiles = h("div", { class: "grid metrics six" },
    metric(null, "affiliate", t("sourcesTile"), active + " / " + st.sources.length, st.sources.some((s) => s.enabled && (s.last_err || s.stale)) ? "bad" : null,
      st.sources.filter((s) => s.enabled && (s.last_err || s.stale)).length + " " + t("withProblems")),
    metric(null, "world", t("reported"), num(sumActive), null, t("addressesN").replace("{n}", num(reported || 0)) + " " + t("inTop")),
    metric(null, "radar", t("overlapUs"), num(st.shared), st.shared ? "bad" : null, st.us ? Math.round(100 * st.shared / st.us) + " % " + t("ofOurs").replace("{n}", num(st.us)) : t("noAttacks")),
    metric(null, "clock", t("firstShare"), st.shared ? Math.round(100 * st.earlier / st.shared) + " %" : "·", null, t("earlyWarn")),
    metric(null, "clock", t("medianLead"), leadText(st.lead_h), null, t("leadSub")),
    metric(null, "stack-2", t("categories"), String(new Set(st.sources.flatMap((s) => Object.keys(s.cats))).size), null, Object.keys(st.sources.reduce((a, s) => Object.assign(a, s.cats), {})).map(catLabel).join(", ") || "·"));

  mount(shell("sources",
    h("h1", null, t("sources")),
    h("div", { class: "crumbs" }, t("sourcesSub")),
    h("div", { class: "flex toolbar" }, daySel),
    tiles,
    h("div", { class: "grid two mt" },
      panel(t("overlapTitle"), t("addresses"), sourceMatrix(st, name)),
      panel(t("leadTitle"), t("leadHint"), leadStrip(st))),
    h("div", { class: "mt" }, panel(t("srcTableTitle"), null, sourceTable(st, st.days))),
    h("div", { class: "grid two mt" },
      panel(t("srcHeatTitle"), t("timezoneLocal"), sourceHeatmap(st)),
      panel(t("srcSankeyTitle"), null, sankey3(st.flows.map((f) => [f.from, f.cat, f.to, f.n]),
        { labels: [name, catLabel, ccLabel], unit: t("addresses"), empty: t("noSourceData"), title: t("srcSankeyTitle") }))),
    h("h2", null, t("topReported")),
    sourceTop(st, name),
    cfg ? sourceAdmin(cfg) : null));
}

// ---- admin: what we share, what we fetch ----

function copyField(value) {
  const inp = h("input", { class: "mono", readonly: true, value });
  return h("div", { class: "flex copyfield" }, inp,
    h("button", { class: "btn small ghost", type: "button", onclick: () => { inp.select(); navigator.clipboard && navigator.clipboard.writeText(value); } }, t("copy")));
}

function sourceAdmin(cfg) {
  const feedURL = cfg.listen ? "http://" + cfg.listen + cfg.path : "";
  const ident = h("div", { class: "card" },
    h("dl", { class: "kv" },
      h("dt", null, t("networkName")), h("dd", null, cfg.network),
      h("dt", null, t("fingerprint")), h("dd", null, copyField(cfg.fingerprint)),
      h("dt", null, t("feedAddress")), h("dd", null, feedURL ? copyField(feedURL) : h("span", { class: "muted" }, t("noListen")))));
  return h("div", null,
    h("h2", null, t("fedConnections")),
    h("div", { class: "muted small" }, t("connectionsSub")),
    ident,
    h("h2", null, t("sharesTitle")),
    shareEditor(cfg),
    h("div", { class: "list" }, cfg.shares.length ? cfg.shares.map((s) => shareRow(s)) : h("div", { class: "empty" }, t("noShares"))),
    h("h2", null, t("sourcesTitle")),
    sourceEditor(cfg),
    h("div", { class: "list" }, cfg.sources.length ? cfg.sources.map((s) => sourceRow(s)) : h("div", { class: "empty" }, t("noSources"))));
}

let shareEdit = null; // the share being edited, or null for a new one
let sourceEdit = null;
let newToken = null; // {name, token} right after creating or rotating

function shareRow(s) {
  return h("div", { class: "row" },
    h("span", { class: "chip" }, h("span", { class: "dot " + (s.enabled ? "ok" : "") }), s.enabled ? t("on") : t("off")),
    h("div", null,
      h("div", { class: "title" }, s.name),
      h("div", { class: "sub" }, [s.cats.map(catLabel).join(", "), t("daysN").replace("{n}", s.days), s.counts ? t("withCounts") : t("addressesOnly"),
        s.users ? t("withUsers") : null, s.min_hits ? t("minHitsN").replace("{n}", s.min_hits) : null].filter(Boolean).join("  ·  ")),
      h("div", { class: "sub" }, s.pulls ? [t("lastFetch"), " ", timeEl(s.pulled), "  ·  " + (s.pulled_ip || "") + "  ·  " + t("addressesN").replace("{n}", num(s.sent))] : t("neverFetched"))),
    h("div", { class: "meta" },
      h("button", { class: "btn small ghost", onclick: () => { shareEdit = s; render(); } }, t("edit")),
      h("button", { class: "btn small ghost", onclick: async () => {
        if (!confirm(t("confirmRotate"))) return;
        const r = await post("/api/ui/shares/" + s.id + "/rotate"); newToken = { name: s.name, token: r.token }; render();
      } }, t("rotateToken")),
      h("button", { class: "btn small ghost", onclick: async () => {
        if (!confirm(t("confirmShareDelete"))) return;
        await post("/api/ui/shares/" + s.id + "/delete"); render();
      } }, t("remove"))));
}

function shareEditor(cfg) {
  const s = shareEdit || { name: "", cats: ["ssh"], users: false, counts: true, days: 7, min_hits: 3, exclude: [], enabled: true };
  const err = h("div", { class: "err" });
  const nameIn = h("input", { value: s.name, maxlength: 64, required: true });
  const cats = cfg.cats.map((c) => h("input", { type: "checkbox", value: c, checked: s.cats.includes(c) || null }));
  const counts = h("input", { type: "checkbox", checked: s.counts || null });
  const users = h("input", { type: "checkbox", checked: s.users || null });
  const enabled = h("input", { type: "checkbox", checked: s.enabled || null });
  const daysSel = h("select", null, [1, 3, 7, 14, 30].map((d) => h("option", { value: d, selected: d === s.days || null }, t("daysN").replace("{n}", d))));
  const minHits = h("input", { type: "number", min: 0, value: s.min_hits });
  const excl = h("textarea", { rows: 3, class: "mono", placeholder: "192.0.2.0/24" }, (s.exclude || []).join("\n"));
  const preview = h("div", { class: "preview" });
  const body = () => ({ id: shareEdit ? shareEdit.id : "", name: nameIn.value.trim() || "preview", cats: cats.filter((c) => c.checked).map((c) => c.value),
    counts: counts.checked, users: users.checked, enabled: enabled.checked, days: +daysSel.value, min_hits: +minHits.value || 0,
    exclude: excl.value.split(/\s+/).filter(Boolean) });
  let timer = null, seq = 0;
  const refresh = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const my = ++seq;
      try {
        const r = await post("/api/ui/shares", { ...body(), preview: true });
        if (my !== seq) return;
        preview.replaceChildren(
          h("div", { class: "strong" }, t("previewN").replace("{n}", num(r.count)).replace("{network}", r.network)),
          r.sample.length ? h("div", { class: "scrollx" }, h("table", { class: "usertable" },
            h("thead", null, h("tr", null, [t("ip"), t("categories"), t("attemptsN"), t("triedUsers")].map((x) => h("th", null, x)))),
            h("tbody", null, r.sample.map((e) => h("tr", null, h("td", { class: "mono" }, e.ip), h("td", { class: "small" }, e.c.map(catLabel).join(", ")),
              h("td", { class: "num-sm" }, e.n != null ? num(e.n) : "·"), h("td", { class: "mono small" }, (e.u || []).join(", "))))))) : null,
          h("div", { class: "muted small" }, t("neverShared")));
      } catch (x) { if (my === seq) preview.replaceChildren(h("div", { class: "err" }, x.message)); }
    }, 300);
  };
  const form = h("form", { class: "stack", oninput: refresh, onchange: refresh, onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    try {
      const r = await post("/api/ui/shares", body());
      if (r.token) newToken = { name: r.share.name, token: r.token };
      shareEdit = null; render();
    } catch (x) { err.textContent = x.message; }
  } },
    h("div", { class: "grid two" }, h("label", null, t("partnerName"), nameIn), h("label", null, t("period"), daysSel)),
    h("fieldset", { class: "checks" }, h("legend", null, t("categories")), cats.map((c) => h("label", { class: "check" }, c, catLabel(c.value)))),
    h("fieldset", { class: "checks" }, h("legend", null, t("detail")),
      h("label", { class: "check" }, counts, t("withCountsLong")),
      h("label", { class: "check" }, users, t("withUsersLong"))),
    h("div", { class: "grid two" }, h("label", null, t("minHits"), minHits), h("label", null, t("partnerNets"), excl)),
    h("label", { class: "check" }, enabled, t("shareEnabled")),
    preview, err,
    h("div", { class: "flex" }, h("button", { class: "btn", type: "submit" }, shareEdit ? t("save") : t("createShare")),
      shareEdit ? h("button", { class: "btn ghost", type: "button", onclick: () => { shareEdit = null; render(); } }, t("cancel")) : null));
  refresh();
  const tok = newToken;
  newToken = null;
  return h("div", null,
    tok ? h("div", { class: "card note" }, h("div", { class: "strong" }, t("tokenOnce").replace("{name}", tok.name)), copyField(tok.token)) : null,
    h("div", { class: "card" }, h("h3", null, shareEdit ? t("editShare").replace("{name}", shareEdit.name) : t("newShare")), form));
}

function sourceRow(s) {
  return h("div", { class: "row" },
    h("span", { class: "chip" }, h("span", { class: "dot " + (!s.enabled ? "" : s.last_err ? "critical" : "ok") }), s.enabled ? t("on") : t("off")),
    h("div", null,
      h("div", { class: "title" }, s.name, s.network ? h("span", { class: "muted" }, "  ·  " + s.network) : null),
      h("div", { class: "sub mono" }, s.url),
      h("div", { class: "sub" }, [t("trust_" + s.trust), t("keepDays").replace("{n}", s.ttl_days), t("addressesN").replace("{n}", num(s.entries))].join("  ·  "),
        s.last_ok && !s.last_ok.startsWith("0001") ? ["  ·  " + t("lastFetch") + " ", timeEl(s.last_ok)] : null),
      s.last_err ? h("div", { class: "sub warn" }, s.last_err) : null),
    h("div", { class: "meta" },
      h("button", { class: "btn small ghost", onclick: async (e) => {
        e.target.disabled = true;
        await post("/api/ui/sources/" + s.id + "/pull").catch(() => {}); render();
      } }, t("fetchNow")),
      h("button", { class: "btn small ghost", onclick: () => { sourceEdit = s; render(); } }, t("edit")),
      h("button", { class: "btn small ghost", onclick: async () => {
        if (!confirm(t("confirmSourceDelete"))) return;
        await post("/api/ui/sources/" + s.id + "/delete"); render();
      } }, t("remove"))));
}

function sourceEditor() {
  const s = sourceEdit || { name: "", url: "", fingerprint: "", trust: "medium", ttl_days: 30, enabled: true };
  const err = h("div", { class: "err" });
  const f = {
    name: h("input", { value: s.name, maxlength: 64, required: true }),
    url: h("input", { value: s.url, class: "mono", required: true, placeholder: "http://10.90.0.5:8472/api/federation/v1/feed" }),
    token: h("input", { type: "password", class: "mono", autocomplete: "off", required: !sourceEdit || null, placeholder: sourceEdit ? t("tokenUnchanged") : "vfs_…" }),
    fingerprint: h("input", { value: s.fingerprint, class: "mono", required: true, placeholder: "xxxx:xxxx:…" }),
    trust: h("select", null, ["low", "medium", "high"].map((k) => h("option", { value: k, selected: k === s.trust || null }, t("trust_" + k)))),
    ttl: h("input", { type: "number", min: 1, max: 90, value: s.ttl_days }),
    enabled: h("input", { type: "checkbox", checked: s.enabled || null }),
  };
  const form = h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    try {
      await post("/api/ui/sources", { id: sourceEdit ? sourceEdit.id : "", name: f.name.value.trim(), url: f.url.value.trim(), token: f.token.value.trim(),
        fingerprint: f.fingerprint.value.trim(), trust: f.trust.value, ttl_days: +f.ttl.value, enabled: f.enabled.checked });
      sourceEdit = null; render();
    } catch (x) { err.textContent = x.message; }
  } },
    h("div", { class: "grid two" }, h("label", null, t("sourceName"), f.name), h("label", null, t("feedAddress"), f.url)),
    h("div", { class: "grid two" }, h("label", null, t("partnerToken"), f.token), h("label", null, t("partnerFingerprint"), f.fingerprint)),
    h("div", { class: "grid two" }, h("label", null, t("trust"), f.trust), h("label", null, t("keepDaysLabel"), f.ttl)),
    h("div", { class: "muted small" }, t("trustHint")),
    h("label", { class: "check" }, f.enabled, t("sourceEnabled")),
    err,
    h("div", { class: "flex" }, h("button", { class: "btn", type: "submit" }, sourceEdit ? t("save") : t("addSource")),
      sourceEdit ? h("button", { class: "btn ghost", type: "button", onclick: () => { sourceEdit = null; render(); } }, t("cancel")) : null));
  return h("div", { class: "card" }, h("h3", null, sourceEdit ? t("editSource").replace("{name}", sourceEdit.name) : t("newSource")), form);
}

async function attacksView(params) {
  const days = params.get("days") || "7";
  const cc = params.get("country") || "";
  const v = await api("/api/ui/attacks?" + new URLSearchParams({ days, ...(scopeSel.agent ? { agent: scopeSel.agent } : {}) }));
  const href = (extra) => "#/attacks?" + new URLSearchParams({ days, ...extra });
  const T_ = v.totals;
  const tiles = h("div", { class: "grid metrics six" },
    metric(null, "world", t("addressesTitle"), T_.ips.toLocaleString(lang), null, (T_.ssh + T_.web).toLocaleString(lang) + " " + t("attemptsN")),
    metric(null, "user-x", "SSH", T_.ssh.toLocaleString(lang), null, "Web " + T_.web.toLocaleString(lang)),
    metric(null, "world", t("countries"), v.geo.enabled ? T_.countries : "·", null, v.geo.enabled ? T_.networks + " " + t("networks") : t("notConfigured")),
    metric(null, "alert-triangle", t("successTile"), T_.success, T_.success ? "bad" : "good", t("r_login") + ", " + t("r_web_ok")),
    metric(null, "radar", t("targetedTile"), T_.targeted, T_.targeted ? "bad" : null, T_.persistent + " " + t("cls_persistent").toLowerCase()),
    metric(null, "stack-2", t("campaigns"), T_.campaigns, null, T_.noise + " " + t("cls_noise").toLowerCase()));
  const daySel = h("div", { class: "tabs" }, [["1", t("day1")], ["7", t("days7")], ["30", t("days30").replace("{n}", 30)]].map(([k, l]) =>
    h("button", { class: k === String(v.days) ? "on" : null, onclick: () => { location.hash = "#/attacks?" + new URLSearchParams(cc ? { days: k, country: cc } : { days: k }); } }, l)));
  const reports = can("analyst") ? h("div", { class: "flex" },
    h("a", { class: "btn ghost", href: "/api/ui/attacks/report?" + new URLSearchParams({ days: v.days, lang, format: "md" }) }, t("attackReport")),
    h("a", { class: "btn ghost", href: "/api/ui/attacks/report?" + new URLSearchParams({ days: v.days, lang, format: "html" }), target: "_blank", rel: "noopener" }, t("attackPrint"))) : null;

  let list = v.addresses;
  if (cc) list = list.filter((a) => (a.country || "??") === cc);
  if (attackClass !== "all") list = list.filter((a) => a.class === attackClass);
  const counts = { all: v.addresses.length };
  v.addresses.forEach((a) => { counts[a.class] = (counts[a.class] || 0) + 1; });
  const clsTabs = h("div", { class: "tabs" }, ["all", "success", "targeted", "persistent", "noise"].map((k) =>
    h("button", { class: k === attackClass ? "on" : null, onclick: () => { attackClass = k; render(); } }, t("cls_" + k) + " " + (counts[k] || 0))));
  const table = list.length ? h("div", { class: "tablewrap" }, h("table", { class: "evtable attackers" },
    h("thead", null, h("tr", null, [t("ip"), t("origin"), t("classLabel"), "SSH", "Web", t("details"), t("lastSeenShort")].map((x) => h("th", null, x)))),
    h("tbody", null, list.slice(0, 150).map((a) => h("tr", null,
      h("td", { class: "mono nowrap" }, h("a", { href: pivotHref("ip", a.ip) }, a.ip)),
      h("td", null, h("div", null, a.country ? countryName(a.country) : "·"), h("div", { class: "muted small" }, [netLabel(a), a.net ? t("net_" + a.net).split(" (")[0] : ""].filter(Boolean).join("  ·  "))),
      h("td", null, classChip(a.class), h("div", { class: "muted small" }, (a.reasons || []).filter((r) => r !== "wordlist" || a.class === "noise").map((r) => t("r_" + r)).join(", "))),
      h("td", { class: "num-sm" }, a.ssh ? a.ssh.toLocaleString(lang) : "·"),
      h("td", { class: "num-sm" }, a.web ? a.web.toLocaleString(lang) : "·"),
      h("td", { class: "mono small" }, [...(a.users || []).slice(0, 5), ...(a.paths || []).slice(0, 3)].join(", ") + (a.campaign >= 0 ? "  ·  " + t("campaignN").replace("{n}", a.campaign + 1) : "")),
      h("td", { class: "nowrap" }, timeEl(a.last))))))) : h("div", { class: "card empty" }, t("noAttacks"));

  const campaigns = v.campaigns.length ? h("div", { class: "grid cards" }, v.campaigns.slice(0, 8).map((c) => h("div", { class: "card" },
    h("div", { class: "chart-head" }, h("h3", null, t("campaignN").replace("{n}", c.id + 1)), h("span", { class: "chip" }, c.kind.toUpperCase())),
    h("div", { class: "metric-sub" }, t("addressesN").replace("{n}", c.size) + ", " + c.attempts.toLocaleString(lang) + " " + t("attemptsN") + ", " + c.networks + " " + t("networks")),
    h("dl", { class: "kv" },
      h("dt", null, t("signature")), h("dd", { class: "mono" }, c.signature.map((x) => x.slice(2)).join(", ")),
      h("dt", null, t("countries")), h("dd", null, c.countries.map((x) => (x.key === "??" ? "?" : x.key) + " " + x.ips).join(", ")),
      h("dt", null, t("firstSeen")), h("dd", null, abs(c.first)),
      h("dt", null, t("lastSeenShort")), h("dd", null, abs(c.last)),
      h("dt", null, t("addressesTitle")), h("dd", { class: "mono" }, c.members.slice(0, 6).map((ip) => h("a", { href: pivotHref("ip", ip) }, ip + " ")), c.members.length > 6 ? "…" : ""))))) : h("div", { class: "card empty small" }, t("none"));

  const kinds = ["hosting", "tor", "other"].map((k) => ({ key: k, count: v.net_kinds[k] || 0 }));
  mount(shell("attacks",
    h("h1", null, t("attacks")),
    h("div", { class: "crumbs" }, scopeSel.agent ? t("attacksOnHost").replace("{h}", scopeName()) : t("attacksSub")),
    h("div", { class: "flex toolbar" }, daySel, h("span", { class: "right" }, reports)),
    v.ready ? null : h("div", { class: "card note" }, t("building")),
    scopeSel.group ? scopeNote(t("attacksNoGroup")) : v.agent ? scopeNote(t("attacksHostNote")) : null,
    tiles,
    v.geo.enabled ? h("div", { class: "card amap-card" },
      h("div", { class: "panel-head" }, h("h3", null, t("worldMap")), cc ? h("a", { class: "panel-extra", href: href({}) }, countryName(cc) + "  ×") : null),
      attackMap(v.days, scopeSel.agent, params.get("sel") || cc, params), geoAttr(v.geo))
      : h("div", { class: "card note" }, t("geoOff")),
    h("div", { class: "grid dash-b mt" },
      panel(t("byNetwork"), null, rankList(v.networks.slice(0, 8).map((n) => ({ key: "AS" + n.asn + " " + n.org, count: n.ips,
        extra: [countryName(n.country), n.net ? t("net_" + n.net) : "", n.count.toLocaleString(lang) + " " + t("attemptsN")].filter(Boolean).join("  ·  ") })),
        { empty: v.geo.enabled ? t("noAttacks") : t("notConfigured") })),
      panel(t("netKind"), null, rankList(kinds.map((k) => ({ key: t("net_" + k.key), count: k.count })), { empty: t("noAttacks") })),
      panel(t("perDay"), null, dayChart(v.per_day))),
    v.geo.enabled ? h("div", { class: "mt" }, panel(t("treemapTitle"), t("treemapSub"), originTreemap(v.countries, v.networks))) : null,
    // per user and per hour is kept for all hosts together only
    v.agent ? null : [h("h2", null, t("triedUsers")),
      v.estimated ? h("div", { class: "muted small" }, t("usersEstimated")) : null,
      h("div", { class: "grid dash-a" },
        panel(t("userRanking"), null, userTable(v.user_stats || [], v.days)),
        panel(t("cloudTitle"), null, userCloud(v.user_stats || []))),
      h("div", { class: "mt" }, panel(t("heatTitle"), t("timezoneLocal"), userHeatmap(v.user_stats || []))),
      h("div", { class: "grid two mt" },
        panel(t("matrixTitle"), null, userCountryMatrix(v.matrix || { users: [], countries: [], cells: [] })),
        panel(t("sankeyTitle"), null, userSankey(v.flows || [])))],
    h("div", { class: "grid dash-b mt" },
      v.agent ? null : panel(t("hourOfDay"), t("timezoneLocal"), hourChart(v.hours)),
      panel(t("webAttacks"), null, v.web_kinds.length || v.paths.length ? [
        rankList(v.web_kinds.map((k) => ({ key: k.key, count: k.ips })), { mono: true }),
        h("div", { class: "rank-gap" }), rankList(v.paths.slice(0, 6).map((k) => ({ key: k.key, count: k.ips })), { mono: true })] : h("div", { class: "empty small" }, t("noAttacks"))),
      panel(t("existingTried"), t("addresses"), rankList(v.users.filter((u) => u.existing).slice(0, 8).map((u) => ({ key: u.user, count: u.ips })),
        { mono: true, tone: "red", empty: t("none") }))),
    h("h2", null, t("campaigns")), campaigns,
    h("h2", null, t("addressesTitle") + (cc ? ": " + countryName(cc) : "")), clsTabs, table));
}

// originCard: what the attack statistics know about an address.
function originCard(o) {
  if (!o) return null;
  const g = o.geo || {};
  const a = o.attack;
  const rows = [];
  if (g.country) rows.push(h("dt", null, t("country")), h("dd", null, countryName(g.country)));
  if (g.asn) rows.push(h("dt", null, t("network")), h("dd", null, netLabel(g) + (g.net ? "  ·  " + t("net_" + g.net) : "")));
  if (a) {
    rows.push(h("dt", null, t("classLabel")), h("dd", { class: "flex" }, classChip(a.class), (a.reasons || []).map((r) => t("r_" + r)).join(", ")));
    if (a.users && a.users.length) rows.push(h("dt", null, t("triedUsers")), h("dd", { class: "mono" }, a.users.map((u) => (a.existing || []).includes(u) ? u + " (" + t("accountExists") + ")" : u).join(", ")));
    if (a.paths && a.paths.length) rows.push(h("dt", null, t("attackPaths")), h("dd", { class: "mono" }, a.paths.join(", ")));
    if (a.logins) rows.push(h("dt", null, t("loggedInAs")), h("dd", { class: "mono" }, (a.login_as || []).join(", ")));
    if (a.user_agent) rows.push(h("dt", null, "User-Agent"), h("dd", { class: "mono small" }, a.user_agent));
  }
  if (o.campaign) rows.push(h("dt", null, t("campaigns")), h("dd", null, h("a", { href: "#/attacks?days=30" }, t("campaignN").replace("{n}", o.campaign.id + 1)),
    "  ·  " + t("addressesN").replace("{n}", o.campaign.size) + ", " + o.campaign.signature.map((x) => x.slice(2)).join(", ")));
  if (!rows.length && !a) return null;
  return h("div", { class: "card mt" },
    h("div", { class: "chart-head" }, h("h3", null, t("origin")), a ? h("span", { class: "total" }, (a.ssh + a.web).toLocaleString(lang)) : null),
    h("dl", { class: "kv" }, rows),
    a ? h("div", { class: "mini" }, h("div", { class: "metric-sub mt" }, t("activity30")), dayChart(o.per_day)) : null,
    o.geoip ? h("div", { class: "attr" }, h("a", { href: o.attribution_url, target: "_blank", rel: "noopener" }, t("geoAttr"))) : null);
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
    kind === "ip" ? originCard(d.origin) : null,
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
  const ask = can("analyst", agent) && agent ? h("button", { class: "btn small ghost", onclick: async () => {
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

// ---------- hosts: load, memory, disks, connections ----------
const fmtBytes = (b) => {
  b = Number(b) || 0;
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (b >= 100 || i === 0 ? Math.round(b) : b.toFixed(1)).toLocaleString(lang) + " " + u[i];
};
const fmtRate = (b) => fmtBytes(b) + "/s";
const fmtPct = (v) => (Math.round((Number(v) || 0) * 10) / 10).toLocaleString(lang) + " %";
const pctOf = (used, total) => total ? used / total * 100 : 0;
function fmtUptime(sec) {
  sec = Number(sec) || 0;
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), mm = Math.floor((sec % 3600) / 60);
  return d ? d + " d " + hh + " h" : hh ? hh + " h " + mm + " min" : mm + " min";
}
// level names the state of a share; it is always shown with its number
const level = (p) => p >= 90 ? "critical" : p >= 70 ? "medium" : "ok";
const PORT_NAMES = { 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
  27017: "MongoDB", 9200: "Elasticsearch", 5672: "AMQP", 11211: "memcached", 2049: "NFS", 873: "rsync", 9090: "Prometheus", 3001: "Uptime Kuma" };
const portName = (p, agentPort) => p === agentPort ? "vigil" : PORT_NAMES[p] || String(p);

function meter(label, p, sub) {
  const fill = h("span", { class: "meter-fill " + level(p) });
  fill.style.width = Math.min(100, Math.max(0, p)) + "%";
  return h("div", { class: "meter" },
    h("div", { class: "meter-head" }, h("span", { class: "meter-label" }, label), h("span", { class: "meter-value" }, fmtPct(p))),
    h("div", { class: "meter-bar", role: "meter", "aria-valuemin": 0, "aria-valuemax": 100, "aria-valuenow": Math.round(p), "aria-label": label }, fill),
    sub ? h("div", { class: "meter-sub" }, sub) : null);
}

// lineChart draws up to three series over time in one scale. The plot is
// stretched to the card's width, so its lines keep their width with
// non-scaling-stroke and the labels live in HTML around it. A gap of more
// than a few steps (the host was off) breaks the line.
// Optional: band(p) gives the normal [low, high] of the first series and
// marks its points above it; marks [{t, kind, text}] sit in a strip under
// the plot; onPick(t) gets a click, onZoom(from, to) a range dragged with
// the mouse (a touch only picks, so the page still scrolls).
function lineChart(opts) {
  const { title, points, series, fmt = (v) => String(v), max: fixedMax, step = 60, compact, ref, band, marks, onPick, onZoom, extra } = opts;
  const W = 600, H = compact ? 44 : 150;
  const wrap = h("div", { class: "lc" + (compact ? " compact" : "") });
  if (!compact) {
    wrap.append(h("div", { class: "chart-head" }, h("h3", null, title),
      series.length > 1 || band ? h("div", { class: "lc-legend" }, series.length > 1 ? series.map((s, i) => h("span", { class: "chip" }, h("span", { class: "lc-key s" + (i + 1) }), s.label)) : null,
        band ? h("span", { class: "chip" }, h("span", { class: "lc-key band" }), t("pf_normal")) : null) : null, extra || null));
  }
  if (!points.length) {
    wrap.append(h("div", { class: "empty small" }, t("noData")));
    return compact ? wrap : h("div", { class: "card" }, wrap);
  }
  const t0 = points[0].t, t1 = Math.max(points[points.length - 1].t, t0 + step);
  const vals = series.flatMap((s) => points.map((p) => Number(s.get(p)) || 0));
  const max = fixedMax || Math.max(ref || 0, ...vals) * 1.1 || 1;
  const X = (tt) => (tt - t0) / (t1 - t0) * W, Y = (v) => H - 2 - Math.min(1, v / max) * (H - 4);
  const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none", class: "lc-plot", role: "img",
    "aria-label": title + ": " + series.map((s) => s.label + " " + fmt(s.get(points[points.length - 1]))).join(", ") });
  if (!compact) for (const f of [0.25, 0.5, 0.75]) svg.append(sv("line", { x1: 0, x2: W, y1: H * f, y2: H * f, class: "lc-grid" }));
  if (ref) svg.append(sv("line", { x1: 0, x2: W, y1: Y(ref), y2: Y(ref), class: "lc-ref" }));
  if (band) {
    // one polygon per run of points that have a band
    let run = [];
    const flush = () => {
      if (run.length > 1) svg.append(sv("path", { class: "lc-band", d: "M" + run.map(([x, , hi]) => x + "," + Y(hi).toFixed(1)).join("L") +
        "L" + run.slice().reverse().map(([x, lo]) => x + "," + Y(lo).toFixed(1)).join("L") + "Z" }));
      run = [];
    };
    for (const p of points) { const b = band(p); if (b) run.push([X(p.t).toFixed(1), b[0], b[1]]); else flush(); }
    flush();
  }
  series.forEach((s, i) => {
    let d = "", prev = null, area = "", runStart = null;
    for (const p of points) {
      const x = X(p.t).toFixed(1), y = Y(Number(s.get(p)) || 0).toFixed(1);
      const brk = prev && p.t - prev.t > step * 3;
      if (!prev || brk) {
        if (runStart !== null && i === 0) area += "L" + X(prev.t).toFixed(1) + "," + H + "L" + runStart + "," + H + "Z";
        d += "M" + x + "," + y; runStart = x;
        if (i === 0) area += "M" + x + "," + H + "L" + x + "," + y;
      } else {
        d += "L" + x + "," + y;
        if (i === 0) area += "L" + x + "," + y;
      }
      prev = p;
    }
    if (i === 0 && series.length === 1) {
      area += "L" + X(prev.t).toFixed(1) + "," + H + "L" + runStart + "," + H + "Z";
      svg.append(sv("path", { d: area, class: "lc-area s1" }));
    }
    svg.append(sv("path", { d, class: "lc-line s" + (i + 1), "vector-effect": "non-scaling-stroke" }));
  });
  if (band) for (const p of points) {
    const b = band(p), v = Number(series[0].get(p)) || 0;
    // clearly above: by half the band's width, at least 5 points
    if (b && v > b[1] + Math.max(5, (b[1] - b[0]) / 2)) svg.append(sv("line", { x1: X(p.t), x2: X(p.t), y1: Y(v), y2: Y(v), class: "lc-out", "vector-effect": "non-scaling-stroke" }));
  }
  const cross = sv("line", { x1: 0, x2: 0, y1: 0, y2: H, class: "lc-cross", "vector-effect": "non-scaling-stroke", visibility: "hidden" });
  svg.append(cross);
  const sel = sv("rect", { x: 0, y: 0, width: 0, height: H, class: "lc-sel", visibility: "hidden" });
  svg.append(sel);
  const when = (tt) => new Date(tt * 1000).toLocaleString(lang, step >= 3600 ? { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" } : { hour: "2-digit", minute: "2-digit" });
  const tAt = (clientX) => { const r = svg.getBoundingClientRect(); return t0 + Math.max(0, Math.min(1, (clientX - r.left) / r.width)) * (t1 - t0); };
  const nearest = (tt) => { let best = points[0]; for (const p of points) if (Math.abs(p.t - tt) < Math.abs(best.t - tt)) best = p; return best; };
  let drag = null;
  svg.addEventListener("mousemove", (e) => {
    const best = nearest(tAt(e.clientX));
    cross.setAttribute("x1", X(best.t)); cross.setAttribute("x2", X(best.t)); cross.setAttribute("visibility", "visible");
    if (drag !== null) {
      const a = X(Math.min(drag, tAt(e.clientX))), b = X(Math.max(drag, tAt(e.clientX)));
      sel.setAttribute("x", a); sel.setAttribute("width", Math.max(0, b - a)); sel.setAttribute("visibility", "visible");
    }
    const bb = band && band(best);
    tip(e, when(best.t) + "  ·  " + series.map((s) => (series.length > 1 || compact ? s.label + " " : "") + fmt(s.get(best))).join("  ·  ") +
      (bb ? "  ·  " + t("pf_normal") + " " + fmt(bb[0]) + " … " + fmt(bb[1]) : "") + (onPick ? "  ·  " + t("pf_clickProcs") : ""));
  });
  if (onPick || onZoom) {
    svg.addEventListener("mousedown", (e) => { if (e.button === 0 && onZoom) { drag = tAt(e.clientX); e.preventDefault(); } });
    svg.addEventListener("mouseup", (e) => {
      const a = drag, b = tAt(e.clientX);
      drag = null; sel.setAttribute("visibility", "hidden");
      if (a !== null && onZoom && Math.abs(X(b) - X(a)) / W * svg.getBoundingClientRect().width > 8) onZoom(Math.floor(Math.min(a, b)), Math.ceil(Math.max(a, b)));
      else if (onPick) onPick(nearest(b).t);
    });
    // a touch: pick only
    svg.addEventListener("touchend", (e) => { if (onPick && e.changedTouches[0]) onPick(nearest(tAt(e.changedTouches[0].clientX)).t); });
  }
  svg.addEventListener("mouseleave", (e) => { cross.setAttribute("visibility", "hidden"); sel.setAttribute("visibility", "hidden"); drag = null; tip(e, null); });
  const plot = h("div", { class: "lc-frame" }, svg);
  if (marks && marks.length) {
    // marks close together share one dot; its tip lists them
    const cols = {};
    for (const m of marks) {
      if (m.t < t0 || m.t > t1) continue;
      const c = Math.round(X(m.t) / W * 100);
      (cols[c] = cols[c] || []).push(m);
    }
    const strip = h("div", { class: "lc-marks" });
    for (const [c, list] of Object.entries(cols)) {
      const kinds = [...new Set(list.map((m) => m.kind))];
      const dot = h("span", { class: "lc-mark k-" + (kinds.length > 1 ? "many" : kinds[0]) });
      dot.style.left = c + "%";
      const text = list.slice(0, 8).map((m) => when(m.t) + "  " + m.text).join("\n") + (list.length > 8 ? "\n+" + (list.length - 8) : "");
      dot.addEventListener("mousemove", (e) => tip(e, text));
      dot.addEventListener("mouseleave", (e) => tip(e, null));
      strip.append(dot);
    }
    plot.append(strip);
  }
  if (!compact) plot.append(h("span", { class: "lc-max" }, fmt(max)));
  wrap.append(plot);
  if (!compact) wrap.append(h("div", { class: "axis" }, h("span", null, when(t0)), h("span", null, when((t0 + t1) / 2)), h("span", null, when(t1))));
  return compact ? wrap : h("div", { class: "card" }, wrap);
}

function hostCard(x, agentPort) {
  const m = x.metrics;
  const head = h("div", { class: "hc-head" },
    h("a", { href: "#/hosts/" + x.id, class: "strong" }, x.name), statusChip(x.status),
    x.server ? h("span", { class: "pill" }, t("vigilServer")) : null,
    tagChips(x.tags),
    h("span", { class: "muted right" }, x.version || "·"));
  if (!m) return h("div", { class: "card hostcard" }, head, h("div", { class: "empty small" }, t("noMetrics")));
  const mem = pctOf(m.mem_used, m.mem_total);
  const sp = x.spark;
  const top = (m.top || []).slice(0, 3);
  return h("div", { class: "card hostcard" + (x.stale ? " stale" : "") },
    head,
    x.stale ? h("div", { class: "pill warn" }, t("asOf") + " " + ago(m.ts)) : null,
    h("div", { class: "hc-sub" }, [x.hostname, m.cores + " " + t("cores"), t("upFor") + " " + fmtUptime(m.uptime), m.procs + " " + t("processes")].join("  ·  ")),
    h("div", { class: "hc-meters" },
      meter(t("cpu"), m.cpu, t("load") + " " + m.load.map((v) => v.toFixed(2)).join(" ")),
      meter(t("memory"), mem, fmtBytes(m.mem_used) + " " + t("ofTotal") + " " + fmtBytes(m.mem_total)),
      meter(t("disk"), m.disk_pct, t("fullest")),
      m.swap_total ? meter(t("swap"), pctOf(m.swap_used, m.swap_total), fmtBytes(m.swap_used) + " " + t("ofTotal") + " " + fmtBytes(m.swap_total)) : null),
    h("div", { class: "hc-sparks" },
      h("div", null, h("div", { class: "hc-label" }, t("cpu") + ", " + t("lastHour")), lineChart({ title: t("cpu"), points: sp, compact: true, max: 100, series: [{ label: t("cpu"), get: (p) => p.cpu }], fmt: fmtPct })),
      h("div", null, h("div", { class: "hc-label" }, t("memory")), lineChart({ title: t("memory"), points: sp, compact: true, max: 100, series: [{ label: t("memory"), get: (p) => p.mem }], fmt: fmtPct })),
      h("div", null, h("div", { class: "hc-label" }, t("traffic")), lineChart({ title: t("traffic"), points: sp, compact: true, series: [{ label: "↓", get: (p) => p.rx }, { label: "↑", get: (p) => p.tx }], fmt: fmtRate }))),
    h("div", { class: "hc-facts" },
      h("span", null, h("span", { class: "muted" }, t("traffic") + " "), "↓ " + fmtRate(m.rx) + "  ↑ " + fmtRate(m.tx)),
      h("span", null, h("span", { class: "muted" }, t("connections") + " "), m.conn_in + " " + t("netIn") + "  ·  " + m.conn_out + " " + t("netOut"))),
    top.length ? h("div", { class: "hc-procs" }, top.map((p) => h("div", { class: "hc-proc", title: p.exe || "" },
      h("span", { class: "mono" }, p.comm), h("span", { class: "muted" }, fmtPct(p.cpu) + "  ·  " + fmtBytes(p.rss))))) : null);
}

async function hostsView() {
  const [d, lay] = await Promise.all([api("/api/ui/hosts"), topo.pos ? null : api("/api/ui/account/topology").catch(() => null)]);
  if (lay && Object.keys(lay.pos || {}).length) topo.pos = lay.pos;
  scopeHosts = d.hosts; scopeHostsAt = Date.now();
  const everyHost = d.hosts;
  const hosts = d.hosts.filter(hostFilterMatch);
  const withM = hosts.filter((x) => x.metrics);
  const online = hosts.filter((x) => x.status === "online").length;
  const sum = (f) => withM.reduce((s, x) => s + f(x.metrics), 0);
  const cores = sum((m) => m.cores);
  const cpuAvg = cores ? sum((m) => m.cpu * m.cores) / cores : 0;
  const memUsed = sum((m) => m.mem_used), memTotal = sum((m) => m.mem_total);
  const conns = sum((m) => m.conn_in + m.conn_out);
  const tiles = h("div", { class: "grid metrics six" },
    metric(null, "server", t("hosts"), online + " / " + hosts.length, online === hosts.length ? null : "bad", scopeName() || t("online")),
    metric(null, "layout-dashboard", t("avgCpu"), withM.length ? fmtPct(cpuAvg) : "·", cpuAvg >= 90 ? "bad" : null, cores + " " + t("cores")),
    metric(null, "stack-2", t("memUsed"), withM.length ? fmtPct(pctOf(memUsed, memTotal)) : "·", pctOf(memUsed, memTotal) >= 90 ? "bad" : null, fmtBytes(memUsed) + " " + t("ofTotal") + " " + fmtBytes(memTotal)),
    metric(null, "world", t("throughput"), withM.length ? fmtRate(sum((m) => m.rx + m.tx)) : "·", null, "↓ " + fmtRate(sum((m) => m.rx)) + "  ↑ " + fmtRate(sum((m) => m.tx))),
    metric(null, "affiliate", t("hostLinks"), d.flows.length, null, d.flows.reduce((s, f) => s + f.n, 0) + " " + t("connections").toLowerCase()),
    metric(null, "terminal-2", t("connections"), withM.length ? conns.toLocaleString(lang) : "·", null, sum((m) => m.conn_in) + " " + t("netIn") + "  ·  " + sum((m) => m.conn_out) + " " + t("netOut")));
  mount(shell("hosts",
    h("h1", null, t("hosts")),
    h("div", { class: "crumbs" }, t("hostsSub")),
    tiles,
    everyHost.length ? hostFilterBar(hosts, everyHost) : null,
    hosts.length ? null : h("div", { class: "card empty mt" }, everyHost.length ? t("noHostsFilter") : t("noHosts"))));
  if (!hosts.length) return;
  // the graph needs the content's real width, known once the page is mounted
  const content = document.querySelector("main.content");
  if (hostsMode === "table") { content.append(h("div", { class: "mt" }, hostTable(hosts))); return; }
  if (hostsMode === "rows") { content.append(hostRows(hosts)); return; }
  content.append(
    h("div", { class: "card mt topo-card" },
      h("div", { class: "panel-head" }, h("h3", null, t("topology")), h("span", { class: "panel-extra" }, t("topologySub"))),
      topology({ ...d, focus: hosts.length < everyHost.length ? new Set(hosts.map((x) => x.id)) : null }),
      h("div", { class: "topo-legend" },
        h("span", { class: "chip" }, h("span", { class: "lg-line" }), t("legendTcp")),
        h("span", { class: "chip" }, h("span", { class: "lg-line db" }), t("legendDb")),
        h("span", { class: "chip" }, h("span", { class: "lg-line ssh" }), "SSH"),
        h("span", { class: "chip" }, h("span", { class: "lg-line vigil" }), t("legendVigil")),
        h("span", { class: "chip" }, h("span", { class: "lg-line ext" }), t("legendNet")),
        mainGroups().map((g) => h("span", { class: "chip" }, h("span", { class: "gmark " + groupClass(g) }), g)))),
    ...[groupedCards(hosts, d.agent_port)].flat());
}

const RANGES = ["1h", "6h", "24h", "7d", "30d"];
let hostRange = store("vigil.hostRange") || "6h";
// The tab takes a range (1h to 30d) or a span dragged on a graph (from, to
// in the hash). Marks: alerts, logins, agent starts, package changes and
// reboots. A click on a graph shows the programs of that minute.
async function performanceSection(a, hostsData, params) {
  const q = encodeURIComponent(a.id);
  const r = RANGES.includes(hostRange) ? hostRange : "6h";
  const zf = Number(params.get("from")) || 0, zt = Number(params.get("to")) || 0;
  const zoomed = zf > 0 && zt > zf;
  const d = await api("/api/ui/agents/" + q + "/metrics?" + (zoomed ? "from=" + zf + "&to=" + zt : "range=" + r));
  const pts = d.points, step = d.step, m = d.latest;
  const days = Math.min(30, Math.max(1, Math.ceil((Date.now() / 1000 - d.from) / 86400)));
  const [act, alerts] = await Promise.all([api("/api/ui/agents/" + q + "/activity?days=" + days).catch(() => null),
    api("/api/ui/alerts?" + new URLSearchParams({ agent: a.id, status: "", days: String(days) })).catch(() => [])]);
  const sec = (ts) => Math.floor(Date.parse(ts) / 1000);
  const marks = [];
  for (const al of alerts) marks.push({ t: sec(al.created), kind: "alert", text: t(al.severity) + ": " + al.title });
  if (act) {
    for (const [hr, n] of Object.entries(act.login_hourly || {})) marks.push({ t: Number(hr) + 1800, kind: "login", text: n + " " + t("ht_loginsN") });
    for (const c of act.changes) {
      const ty = c.event.type, ts = sec(c.event.ts || c.time);
      if (ty === "agent.started") marks.push({ t: ts, kind: "agent", text: t("ch_agent_started") + " " + (c.event.data.version || "") });
      if (ty === "packages.changed") marks.push({ t: ts, kind: "pkg", text: t("ht_pkgSummary").replace("{a}", c.event.data.added_n).replace("{r}", c.event.data.removed_n).replace("{c}", c.event.data.changed_n) });
    }
  }
  for (const b of d.boots || []) marks.push({ t: b, kind: "boot", text: t("pf_reboot") });
  for (let i = marks.length - 1; i >= 0; i--) if (marks[i].t < d.from || marks[i].t > d.to) marks.splice(i, 1);
  const MARK_KINDS = ["alert", "login", "agent", "pkg", "boot"];
  const shownKinds = new Set((params.get("marks") || MARK_KINDS.join(",")).split(",").filter((k) => MARK_KINDS.includes(k)));
  const shownMarks = marks.filter((x) => shownKinds.has(x.kind));
  const go = (ch) => { const p = new URLSearchParams(params); p.set("tab", "perf"); for (const [k, v] of Object.entries(ch)) { if (v) p.set(k, v); else p.delete(k); } location.hash = "#/hosts/" + a.id + "?" + p; };
  const pick = h("div", { class: "rangepick" }, RANGES.map((x) => h("button", { class: "btn small" + (x === r && !zoomed ? "" : " ghost"),
    onclick: () => { hostRange = x; store("vigil.hostRange", x); if (zoomed) go({ from: "", to: "" }); else render(); } }, x)),
    zoomed ? h("button", { class: "btn small", onclick: () => go({ from: "", to: "" }) }, t("pf_unzoom")) : null,
    pts.length ? h("button", { class: "btn small ghost", onclick: () => downloadCSV(a, d) }, "CSV") : null);
  const markPick = h("div", { class: "tabs" }, MARK_KINDS.map((k) => h("a", { class: "tab" + (shownKinds.has(k) ? " on" : ""), href: "#",
    onclick: (e) => { e.preventDefault(); const n = new Set(shownKinds); if (n.has(k)) n.delete(k); else n.add(k); go({ marks: [...n].join(",") || "none" }); } },
    h("span", { class: "lc-mark inline k-" + k }), t("pf_mark_" + k) + " " + marks.filter((x) => x.kind === k).length)));
  const cores = m ? m.cores : d.cores || 0;
  const owner = {};
  for (const x of (hostsData && hostsData.hosts) || []) for (const f of (x.metrics && x.metrics.ifaces) || []) for (const ip of f.addrs || []) owner[ip] = x.name;
  const out = [h("div", { class: "flex mt" }, h("h2", null, t("performance")), h("div", { class: "right" }, pick)),
    zoomed ? h("div", { class: "muted" }, new Date(zf * 1000).toLocaleString(lang) + " … " + new Date(zt * 1000).toLocaleString(lang) + "  ·  " + t(step >= 3600 ? "pf_hours" : "pf_minutes")) : null];
  if (!pts.length && !m) return [...out, h("div", { class: "card empty" }, t("noMetrics"))];
  // the band is per hour of the week (UTC, Monday first) or of the day
  const bd = d.band;
  const bucket = (tt) => { const x = new Date(tt * 1000); return bd.kind === "week" ? ((x.getUTCDay() + 6) % 7) * 24 + x.getUTCHours() : x.getUTCHours(); };
  const bandOf = (key) => bd ? (p) => { const k = bucket(p.t); return bd.n[k] >= 3 ? bd[key][k] : null; } : null;
  const procBox = h("div", { class: "procbox" });
  const showProcs = async (tt) => {
    procBox.replaceChildren(h("div", { class: "card empty small" }, "…"));
    const x = await api("/api/ui/agents/" + q + "/procs?at=" + tt).catch(() => null);
    if (!x || !x.found) { procBox.replaceChildren(h("div", { class: "card empty" }, t("pf_noProcs"))); return; }
    const c = x.cores || cores || 1;
    procBox.replaceChildren(h("div", { class: "card" },
      h("div", { class: "flex" }, h("h3", null, t(x.step >= 3600 ? "pf_procsHour" : "pf_procsAt").replace("{t}", new Date(x.t * 1000).toLocaleString(lang, { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }))),
        h("button", { class: "btn small ghost right", onclick: () => procBox.replaceChildren() }, t("close"))),
      h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, [t("program"), t("pf_cpuCore"), t("pf_cpuHost"), x.step >= 3600 ? t("pf_peak") : null, t("memory")].filter(Boolean).map((y) => h("th", null, y)))),
        h("tbody", null, x.procs.map((p) => h("tr", null, h("td", { class: "mono" }, p.name), h("td", { class: "nowrap" }, fmtPct(p.cpu)),
          h("td", { class: "nowrap" }, fmtPct(p.cpu / c)), x.step >= 3600 ? h("td", { class: "nowrap" }, fmtPct(p.peak || 0)) : null, h("td", { class: "nowrap" }, fmtBytes(p.rss)))))))));
    procBox.scrollIntoView({ block: "nearest", behavior: "smooth" });
  };
  const zoom = (f, tt) => go({ from: String(f), to: String(tt) });
  const common = { points: pts, step, marks: shownMarks, onPick: showProcs, onZoom: zoom };
  const ifNames = [...new Set(pts.flatMap((p) => Object.keys(p.if || {})))].sort().slice(0, 3);
  out.push(markPick);
  out.push(h("div", { class: "grid perfgrid" },
    lineChart({ ...common, title: t("cpu"), max: 100, fmt: fmtPct, band: bandOf("cpu"), series: [{ label: t("cpu"), get: (p) => p.cpu }, { label: t("iowait"), get: (p) => p.iow }, { label: t("steal"), get: (p) => p.st }] }),
    lineChart({ ...common, title: t("memory"), max: 100, fmt: fmtPct, band: bandOf("mem"), series: [{ label: t("memory"), get: (p) => p.mem }, { label: t("swap"), get: (p) => p.swap }] }),
    lineChart({ ...common, title: t("load") + (cores ? "  (" + cores + " " + t("cores") + ")" : ""), ref: cores, fmt: (v) => (Number(v) || 0).toFixed(2), series: [{ label: t("load"), get: (p) => p.l1 }] }),
    lineChart({ ...common, title: t("traffic"), fmt: fmtRate, series: [{ label: t("netIn"), get: (p) => p.rx }, { label: t("netOut"), get: (p) => p.tx }] }),
    ifNames.length > 1 ? lineChart({ ...common, title: t("pf_perIface"), fmt: fmtRate,
      series: ifNames.map((n) => ({ label: n, get: (p) => p.if && p.if[n] ? p.if[n][0] + p.if[n][1] : 0 })) }) : null,
    lineChart({ ...common, title: t("diskIO"), fmt: fmtRate, series: [{ label: t("readL"), get: (p) => p.dr }, { label: t("writeL"), get: (p) => p.dw }] }),
    lineChart({ ...common, title: t("connections"), fmt: (v) => Math.round(Number(v) || 0).toLocaleString(lang), series: [{ label: t("connIn"), get: (p) => p.ci }, { label: t("connOut"), get: (p) => p.co }] })));
  out.push(procBox);
  const f = d.forecast || {};
  const perDay = (v) => v == null ? "·" : (v > 0 ? "+" : "") + v.toLocaleString(lang, { maximumFractionDigits: 2 }) + " " + t("pf_pointsDay");
  const loads = (list, val, fmt) => list && list.length ? rankList(list.map((x) => ({ key: x.name, count: val(x).n, extra: val(x).extra })), { mono: true, fmt })
    : h("div", { class: "empty small" }, t("noData"));
  out.push(h("div", { class: "grid dash-b mt" },
    panel(t("pf_topCpu"), zoomed ? t("pf_span") : r, loads(d.top_cpu, (x) => ({ n: Math.round(x.cpu * 10) / 10,
      extra: t("pf_avgCore").replace("{v}", fmtPct(x.cpu)) + (cores ? "  ·  " + fmtPct(x.cpu / cores) + " " + t("pf_ofHost") : "") + (x.peak ? "  ·  " + t("pf_peak") + " " + fmtPct(x.peak) : "") }), fmtPct)),
    panel(t("pf_topMem"), zoomed ? t("pf_span") : r, loads(d.top_mem, (x) => ({ n: x.rss, extra: x.seen ? t("pf_seenN").replace("{n}", x.seen) : "" }), fmtBytes)),
    panel(t("pf_forecast"), t("days7"), h("dl", { class: "kv" },
      h("dt", null, t("pf_diskNow")), h("dd", null, fmtPct(f.disk || 0)),
      h("dt", null, t("pf_diskTrend")), h("dd", null, perDay(f.disk_per_day)),
      h("dt", null, t("pf_diskFull")), h("dd", { class: f.disk_full_days != null && f.disk_full_days < 14 ? "bad-text" : "" },
        f.disk_full_days != null ? t("pf_inDays").replace("{n}", Math.round(f.disk_full_days).toLocaleString(lang)) : f.disk_per_day != null ? t("pf_notFilling") : t("pf_tooShort")),
      h("dt", null, t("pf_memTrend")), h("dd", null, perDay(f.mem_per_day)),
      h("dt", null, t("pf_normal")), h("dd", null, bd ? t(bd.kind === "week" ? "pf_bandWeek" : "pf_bandDay") : t("pf_tooShort"))))));
  if (!m) return out;
  const usage = (used, total) => {
    const fill = h("span", { class: "meter-fill " + level(pctOf(used, total)) });
    fill.style.width = Math.min(100, pctOf(used, total)) + "%";
    return h("div", { class: "usage" }, h("div", { class: "meter-bar" }, fill), h("span", { class: "muted nowrap" }, fmtPct(pctOf(used, total))));
  };
  out.push(h("div", { class: "grid two mt" },
    h("div", null, h("h3", null, t("disks")), h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, [t("mount"), "FS", t("size"), t("used")].map((x) => h("th", null, x)))),
      h("tbody", null, (m.disks || []).map((x) => h("tr", null, h("td", { class: "mono" }, x.mount), h("td", null, x.fs), h("td", { class: "nowrap" }, fmtBytes(x.total)), h("td", null, usage(x.used, x.total)))))))),
    h("div", null, h("h3", null, t("interfaces")), h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["", t("ip"), "↓", "↑"].map((x) => h("th", null, x)))),
      h("tbody", null, (m.ifaces || []).map((x) => h("tr", null, h("td", { class: "mono" }, x.name), h("td", { class: "mono" }, (x.addrs || []).join("  ")),
        h("td", { class: "nowrap" }, fmtRate(x.rx)), h("td", { class: "nowrap" }, fmtRate(x.tx))))))))));
  out.push(h("h3", { class: "mt" }, t("topProcs")), h("div", { class: "tablewrap" }, h("table", null,
    h("thead", null, h("tr", null, [t("program"), "PID", t("cpu"), t("memory")].map((x) => h("th", null, x)))),
    h("tbody", null, (m.top || []).map((p) => h("tr", null, h("td", null, h("span", { class: "strong" }, p.comm), " ", h("span", { class: "muted mono" }, p.exe || "")),
      h("td", { class: "mono" }, p.pid), h("td", { class: "nowrap" }, fmtPct(p.cpu)), h("td", { class: "nowrap" }, fmtBytes(p.rss))))))));
  const peers = (m.peers || []).slice().sort((x, y) => (owner[y.ip] ? 1 : 0) - (owner[x.ip] ? 1 : 0) || y.n - x.n);
  if (peers.length) out.push(h("h3", { class: "mt" }, t("peers")), h("div", { class: "tablewrap" }, h("table", null,
    h("thead", null, h("tr", null, [t("remote"), "Port", t("direction"), "n", t("program")].map((x) => h("th", null, x)))),
    h("tbody", null, peers.map((p) => h("tr", null,
      h("td", null, owner[p.ip] ? h("span", { class: "strong" }, owner[p.ip] + " ") : null, h("span", { class: "mono" }, entityLink("ip", p.ip) || p.ip)),
      h("td", { class: "nowrap" }, portName(p.port, hostsData && hostsData.agent_port) + (PORT_NAMES[p.port] || p.port === (hostsData && hostsData.agent_port) ? " (" + p.port + ")" : "")),
      h("td", null, t(p.out ? "outgoing" : "incoming")), h("td", null, p.n), h("td", { class: "mono" }, p.process || "")))))));
  return out;
}

// ---------- scope: one host or one group of hosts ----------
// The choice holds across pages (and reloads); the API takes it as
// ?agent= or ?group=. Pages that cannot narrow by a group say so.
const SCOPED = new Set(["overview", "hosts", "alerts", "incidents", "events", "sessions", "attacks"]);
let scopeSel = (() => { try { return JSON.parse(store("vigil.scope") || "{}") || {}; } catch { return {}; } })();
let scopeHosts = null, scopeHostsAt = 0;
async function loadScopeHosts(force) {
  if (!force && scopeHosts && Date.now() - scopeHostsAt < 60000) return;
  try { scopeHosts = (await api("/api/ui/hosts")).hosts; scopeHostsAt = Date.now(); } catch { scopeHosts = scopeHosts || []; }
  // a host or group that no longer exists does not stay selected
  if (scopeSel.agent && !scopeHosts.some((x) => x.id === scopeSel.agent)) scopeSel = {};
  if (scopeSel.group && !scopeHosts.some((x) => (x.tags || []).some((g) => g.toLowerCase() === scopeSel.group.toLowerCase()))) scopeSel = {};
}
const scopeParams = () => scopeSel.agent ? { agent: scopeSel.agent } : scopeSel.group ? { group: scopeSel.group } : {};
const scopeQ = (extra = {}) => new URLSearchParams({ ...extra, ...scopeParams() }).toString();
const allTags = () => [...new Set((scopeHosts || []).flatMap((x) => x.tags || []))].sort((a, b) => a.localeCompare(b, lang));
const inScopeHost = (id) => scopeSel.agent ? id === scopeSel.agent
  : scopeSel.group ? ((scopeHosts || []).find((x) => x.id === id) || { tags: [] }).tags.some((g) => g.toLowerCase() === scopeSel.group.toLowerCase()) : true;
function scopeName() {
  if (scopeSel.agent) return ((scopeHosts || []).find((x) => x.id === scopeSel.agent) || {}).name || scopeSel.agent;
  if (scopeSel.group) return t("group") + " " + scopeSel.group;
  return "";
}
function setScope(v, quiet) {
  scopeSel = v && (v.agent || v.group) ? v : {};
  store("vigil.scope", JSON.stringify(scopeSel));
  if (!quiet) render();
}
function scopePicker() {
  const hosts = (scopeHosts || []).slice().sort((a, b) => a.name.localeCompare(b.name, lang));
  const cur = scopeSel.agent ? "a:" + scopeSel.agent : scopeSel.group ? "g:" + scopeSel.group : "";
  const tags = allTags();
  const sel = h("select", { class: "scope-select" + (cur ? " on" : ""), "aria-label": t("hostScope"), onchange: () => {
    const v = sel.value;
    setScope(v.startsWith("a:") ? { agent: v.slice(2) } : v.startsWith("g:") ? { group: v.slice(2) } : {});
  } },
    h("option", { value: "" }, t("allHosts")),
    tags.length ? h("optgroup", { label: t("groups") }, tags.map((g) => h("option", { value: "g:" + g, selected: cur === "g:" + g },
      g + " (" + hosts.filter((x) => (x.tags || []).includes(g)).length + ")"))) : null,
    h("optgroup", { label: t("hosts") }, hosts.map((x) => h("option", { value: "a:" + x.id, selected: cur === "a:" + x.id }, x.name))));
  return h("div", { class: "scope" }, icon("server"), sel,
    cur ? h("button", { class: "scope-clear", title: t("allHosts"), "aria-label": t("allHosts"), onclick: () => setScope({}) }, "×") : null);
}
const tagChips = (tags) => (tags || []).length ? h("span", { class: "tags" }, tags.map((g) => h("a", { class: "tag", href: "#/hosts", onclick: (e) => { e.preventDefault(); setScope({ group: g }); location.hash = "#/hosts"; } }, g))) : null;
const scopeNote = (text) => h("div", { class: "card note" }, text);

// ---------- alerts: filters, groups, bulk actions ----------
let alertFilt = { sev: [], rule: "", q: "", days: "", by: "" };
function alertGroups(list, by) {
  const m = new Map();
  for (const a of list) {
    const k = by === "host" ? a.host || "·" : a.rule;
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(a);
  }
  const rank = (l) => Math.min(...l.map((a) => SEVS.indexOf(a.severity)));
  return [...m.entries()].sort((x, y) => rank(x[1]) - rank(y[1]) || y[1].length - x[1].length);
}
function alertMatches(a, f) {
  if (f.sev.length && !f.sev.includes(a.severity)) return false;
  if (f.rule && !a.rule.startsWith(f.rule)) return false;
  if (f.days && Date.now() - new Date(a.updated).getTime() > Number(f.days) * 86400e3) return false;
  if (f.q && !(a.title + " " + a.rule + " " + (a.host || "")).toLowerCase().includes(f.q.toLowerCase())) return false;
  return true;
}

async function alertsView() {
  const all = await api("/api/ui/alerts?" + scopeQ({ status: alertTab === "all" ? "" : alertTab }));
  const tabs = h("div", { class: "tabs" }, ["open", "acked", "resolved", "all"].map((k) =>
    h("button", { class: k === alertTab ? "on" : null, onclick: () => { alertTab = k; render(); } }, t(k))));
  const listBox = h("div");
  const countLine = h("div", { class: "filter-sum" });
  const bulkErr = h("div", { class: "err" });
  const rules = [...new Set(all.map((a) => a.rule))].sort();
  const sevBox = h("div", { class: "chips" }, SEVS.map((sv) => {
    const n = all.filter((a) => a.severity === sv).length;
    return h("button", { class: "fchip sev-" + sv + (alertFilt.sev.includes(sv) ? " on" : ""), "aria-pressed": alertFilt.sev.includes(sv) ? "true" : "false", onclick: (e) => {
      alertFilt.sev = alertFilt.sev.includes(sv) ? alertFilt.sev.filter((x) => x !== sv) : [...alertFilt.sev, sv];
      e.currentTarget.classList.toggle("on"); e.currentTarget.setAttribute("aria-pressed", alertFilt.sev.includes(sv) ? "true" : "false");
      draw();
    } }, h("span", { class: "dot " + sv }), t(sv), h("span", { class: "fcount" }, n));
  }));
  const ruleSel = h("select", { onchange: () => { alertFilt.rule = ruleSel.value; draw(); } },
    h("option", { value: "" }, t("allRules")), rules.map((r) => h("option", { value: r, selected: r === alertFilt.rule }, r)));
  const qIn = h("input", { type: "search", value: alertFilt.q, placeholder: t("searchAlerts"), oninput: () => { alertFilt.q = qIn.value.trim(); draw(); } });
  const daysSel = h("select", { onchange: () => { alertFilt.days = daysSel.value; draw(); } },
    [["", t("anyTime")], ["1", "24 h"], ["7", t("days7")], ["30", t("days30").replace("{n}", 30)]].map(([v, l]) => h("option", { value: v, selected: v === alertFilt.days }, l)));
  const bySel = h("select", { onchange: () => { alertFilt.by = bySel.value; draw(); } },
    [["", t("noGrouping")], ["rule", t("byRule")], ["host", t("byHost")]].map(([v, l]) => h("option", { value: v, selected: v === alertFilt.by }, l)));
  let shown = [];
  const bulk = (action) => async () => {
    if (!shown.length || !confirm(t(action === "ack" ? "confirmBulkAck" : "confirmBulkResolve").replace("{n}", shown.length))) return;
    bulkErr.textContent = "";
    try { await post("/api/ui/alerts/bulk", { ids: shown.map((a) => a.id), action }); render(); } catch (x) { bulkErr.textContent = x.message; }
  };
  const bulkBox = (can("analyst") || anyGroupRole("analyst")) && alertTab !== "resolved" ? h("div", { class: "flex wrap" },
    alertTab !== "acked" ? h("button", { class: "btn small ghost", onclick: bulk("ack") }, t("bulkAck")) : null,
    h("button", { class: "btn small ghost", onclick: bulk("resolve") }, t("bulkResolve"))) : null;
  function draw() {
    shown = all.filter((a) => alertMatches(a, alertFilt));
    const active = alertFilt.sev.length || alertFilt.rule || alertFilt.q || alertFilt.days;
    countLine.replaceChildren(...[h("span", { class: "strong" }, shown.length.toLocaleString(lang)), " ",
      active ? t("ofTotal") + " " + all.length.toLocaleString(lang) + " " : "", alertTab === "all" ? t("alerts") : t(alertTab).toLowerCase(),
      active ? h("button", { class: "linkbtn", onclick: () => { alertFilt = { sev: [], rule: "", q: "", days: "", by: alertFilt.by }; render(); } }, t("resetFilters")) : null].filter((x) => x != null));
    if (bulkBox) bulkBox.hidden = !shown.length;
    if (!shown.length) { listBox.replaceChildren(h("div", { class: "list" }, h("div", { class: "empty" }, t("noAlerts")))); return; }
    if (!alertFilt.by) { listBox.replaceChildren(h("div", { class: "list" }, shown.slice(0, 500).map(alertRow))); return; }
    const groups = alertGroups(shown, alertFilt.by);
    listBox.replaceChildren(...groups.map(([k, l], i) => {
      const bySev = {};
      l.forEach((a) => { bySev[a.severity] = (bySev[a.severity] || 0) + 1; });
      return h("details", { class: "agroup", open: groups.length <= 4 || i < 2 ? true : null },
        h("summary", null, h("span", { class: alertFilt.by === "rule" ? "mono strong" : "strong" }, k), h("span", { class: "muted" }, "×" + l.length), sevCounts(bySev),
          alertFilt.by === "rule" ? h("span", { class: "muted right" }, [...new Set(l.map((a) => a.host))].join(", ")) : null),
        h("div", { class: "list" }, l.slice(0, 200).map(alertRow)));
    }));
  }
  draw();
  mount(shell("alerts", h("h1", null, t("alerts")), h("div", { class: "crumbs" }, scopeName() || t("allHosts")),
    tabs,
    h("div", { class: "card filters mt" },
      sevBox,
      h("div", { class: "filter-row" }, h("label", null, t("searchL"), qIn), h("label", null, t("rule"), ruleSel), h("label", null, t("period"), daysSel), h("label", null, t("grouping"), bySel))),
    h("div", { class: "flex mt" }, countLine, h("div", { class: "right" }, bulkBox)), bulkErr,
    listBox));
}

// ---------- hosts tab: table with sorting and filters ----------
let hostsMode = store("vigil.hostsMode") || "cards";
let hostSort = { key: "name", dir: 1 };
let hostFilt = { status: "", crit: false, reboot: false };
const sevWeight = (o) => ((o || {}).critical || 0) * 1e6 + ((o || {}).high || 0) * 1e3 + ((o || {}).medium || 0);
const HOST_COLS = [
  ["name", "host", (x) => x.name.toLowerCase()],
  ["status", "status", (x) => x.status],
  ["cpu", "cpu", (x) => x.metrics ? x.metrics.cpu : -1],
  ["mem", "memory", (x) => x.metrics ? pctOf(x.metrics.mem_used, x.metrics.mem_total) : -1],
  ["disk", "disk", (x) => x.metrics ? x.metrics.disk_pct : -1],
  ["load", "load", (x) => x.metrics && x.metrics.cores ? x.metrics.load[0] / x.metrics.cores : -1],
  ["net", "traffic", (x) => x.metrics ? x.metrics.rx + x.metrics.tx : -1],
  ["alerts", "alertsOpen", (x) => sevWeight(x.open_by_severity)],
  ["updates", "updates", (x) => x.updates ? (x.updates.security || 0) * 1000 + (x.updates.pending || 0) : -1],
  ["version", "version", (x) => x.version || ""],
];
function hostFilterMatch(x) {
  if (!inScopeHost(x.id)) return false;
  if (hostFilt.status && (hostFilt.status === "online") !== (x.status === "online")) return false;
  if (hostFilt.crit && !((x.open_by_severity || {}).critical || (x.open_by_severity || {}).high)) return false;
  if (hostFilt.reboot && !(x.updates && x.updates.reboot_required)) return false;
  return true;
}
function hostTable(hosts) {
  const col = HOST_COLS.find((c) => c[0] === hostSort.key) || HOST_COLS[0];
  const rows = hosts.slice().sort((a, b) => { const x = col[2](a), y = col[2](b); return (x < y ? -1 : x > y ? 1 : 0) * hostSort.dir; });
  const cell = (v, cls) => h("td", { class: cls || "" }, v);
  const pctCell = (p) => {
    const fill = h("span", { class: "meter-fill " + level(p) });
    fill.style.width = Math.min(100, p) + "%";
    return h("div", { class: "usage" }, h("div", { class: "meter-bar" }, fill), h("span", { class: "nowrap" }, fmtPct(p)));
  };
  return h("div", { class: "tablewrap" }, h("table", { class: "hosts sortable" },
    h("thead", null, h("tr", null, HOST_COLS.map(([k, label]) => h("th", { class: "sort" + (hostSort.key === k ? " on" : ""), "aria-sort": hostSort.key === k ? (hostSort.dir > 0 ? "ascending" : "descending") : null },
      h("button", { onclick: () => { hostSort = { key: k, dir: hostSort.key === k ? -hostSort.dir : k === "name" ? 1 : -1 }; render(); } },
        t(label), hostSort.key === k ? (hostSort.dir > 0 ? " ↑" : " ↓") : ""))))),
    h("tbody", null, rows.map((x) => {
      const m = x.metrics;
      return h("tr", { class: "click" + (x.stale ? " stale" : ""), onclick: (e) => { if (!e.target.closest("a")) location.hash = "#/hosts/" + x.id; } },
        cell(h("div", null, h("a", { href: "#/hosts/" + x.id, class: "strong" }, x.name), x.server ? h("span", { class: "pill ml" }, "vigil") : null, h("div", null, tagChips(x.tags)))),
        cell(statusChip(x.status)),
        cell(m ? pctCell(m.cpu) : "·"),
        cell(m ? pctCell(pctOf(m.mem_used, m.mem_total)) : "·"),
        cell(m ? pctCell(m.disk_pct) : "·"),
        cell(m ? m.load[0].toFixed(2) + " / " + m.cores : "·", "nowrap"),
        cell(m ? "↓ " + fmtRate(m.rx) + "  ↑ " + fmtRate(m.tx) : "·", "nowrap"),
        cell(x.open_alerts ? h("a", { href: "#/alerts", onclick: (e) => { e.preventDefault(); e.stopPropagation(); setScope({ agent: x.id }, true); location.hash = "#/alerts"; } }, sevCounts(x.open_by_severity)) : h("span", { class: "muted" }, "0")),
        cell(updatesCell(x.updates)),
        cell(x.version || "·", "muted nowrap"));
    }))));
}
// ---------- hosts tab: list with rings, one host per row ----------
const HOST_PAGE = 10;
let hostPage = 0;
const hostOpen = new Set();
// osOf reads the release the vulnerability check found ("debian:bookworm").
function osOf(x) {
  const rel = (x.vulns && x.vulns.release) || "";
  const id = rel.split(":")[0];
  const ic = { debian: "brand-debian", raspbian: "brand-debian", ubuntu: "brand-ubuntu", rhel: "brand-redhat", redhat: "brand-redhat" }[id] || "server";
  return { ic, label: rel || "·" };
}
// ring draws one value as a circle, starting at twelve o'clock.
function ring(value, label, cls, title) {
  const r = 26, c = 2 * Math.PI * r, p = Math.max(0, Math.min(100, value));
  const svg = sv("svg", { viewBox: "0 0 60 60", class: "hr-ring " + cls, "aria-hidden": "true" },
    sv("circle", { cx: 30, cy: 30, r, class: "hr-track" }),
    sv("circle", { cx: 30, cy: 30, r, class: "hr-arc", "stroke-dasharray": (c * p / 100).toFixed(1) + " " + c.toFixed(1), transform: "rotate(-90 30 30)" }));
  return hoverTip(h("div", { class: "hr-gauge", role: "img", "aria-label": label + " " + title },
    svg, h("div", { class: "hr-mid" }, h("span", { class: "hr-val" }, title), h("span", { class: "hr-lab" }, label))), label + ": " + title);
}
function hostRow(x) {
  const m = x.metrics, os = osOf(x), open = hostOpen.has(x.id);
  const sevs = x.open_by_severity || {};
  const bars = h("a", { class: "hr-sev", href: "#/alerts", "aria-label": t("alertsOpen") + ": " + (x.open_alerts || 0),
    onclick: (e) => { e.preventDefault(); setScope({ agent: x.id }, true); location.hash = "#/alerts"; } },
    ["critical", "high", "medium"].map((s) => h("span", { class: sevs[s] ? s : null })));
  hoverTip(bars, x.open_alerts ? ["critical", "high", "medium", "low"].filter((s) => sevs[s]).map((s) => sevs[s] + " " + t(s)).join("  ·  ") : "0 " + t("alertsOpen"));
  const act = (ic, label, onclick, href) => hoverTip(h(href ? "a" : "button", { class: "hr-act", href, onclick, "aria-label": label }, icon(ic)), label);
  const toggle = act("chevron-down", t("moreDetails"), () => { open ? hostOpen.delete(x.id) : hostOpen.add(x.id); render(); });
  toggle.setAttribute("aria-expanded", open);
  const row = h("div", { class: "hr" + (x.stale ? " stale" : "") + (open ? " open" : "") },
    hoverTip(h("span", { class: "hr-os" }, icon(os.ic)), os.label),
    h("div", { class: "hr-name" },
      h("a", { href: "#/hosts/" + x.id, class: "strong" }, x.name),
      h("div", { class: "muted mono small" }, [x.hostname !== x.name ? x.hostname : null, x.last_ip].filter(Boolean).join("  ·  ") || "·")),
    h("div", { class: "hr-state" }, statusChip(x.status), x.server ? h("span", { class: "pill" }, "vigil") : null,
      x.stale && m ? h("span", { class: "pill warn" }, t("asOf") + " " + ago(m.ts)) : null),
    h("div", { class: "hr-hw" },
      h("span", null, icon("cpu"), m ? m.cores + " " + t("cores") : "·"),
      h("span", null, icon("stack-2"), m ? fmtBytes(m.mem_total) : "·")),
    h("div", { class: "hr-rings" },
      m ? ring(m.cpu, t("cpu"), level(m.cpu), Math.round(m.cpu) + " %") : ring(0, t("cpu"), "none", "·"),
      m ? ring(pctOf(m.mem_used, m.mem_total), "RAM", level(pctOf(m.mem_used, m.mem_total)), Math.round(pctOf(m.mem_used, m.mem_total)) + " %") : ring(0, "RAM", "none", "·"),
      ring(x.ports ? 100 : 0, t("ports"), "count", String(x.ports || 0))),
    bars,
    h("div", { class: "hr-acts" },
      act("layout-grid", t("hostOpen"), null, "#/hosts/" + x.id),
      act("adjustments-horizontal", t("performance"), null, "#/hosts/" + x.id + "?tab=perf"),
      toggle));
  if (!open) return row;
  const fact = (k, v) => h("div", null, h("div", { class: "hc-label" }, k), h("div", null, v));
  return h("div", null, row, h("div", { class: "hr-more" },
    m ? [fact(t("disk"), fmtPct(m.disk_pct)),
      fact(t("load"), m.load.map((v) => v.toFixed(2)).join(" ")),
      fact(t("traffic"), "↓ " + fmtRate(m.rx) + "  ↑ " + fmtRate(m.tx)),
      fact(t("connections"), m.conn_in + " " + t("netIn") + "  ·  " + m.conn_out + " " + t("netOut")),
      fact(t("upFor"), fmtUptime(m.uptime))] : fact(t("cpu"), t("noMetrics")),
    fact(t("updates"), updatesCell(x.updates)),
    fact(t("version"), x.version || "·"),
    (x.tags || []).length ? fact(t("groups"), tagChips(x.tags)) : null));
}
function hostRows(hosts) {
  const pages = Math.ceil(hosts.length / HOST_PAGE);
  hostPage = Math.min(hostPage, pages - 1);
  const go = (n) => () => { hostPage = n; render(); };
  const pager = pages > 1 ? h("nav", { class: "hr-pager", "aria-label": t("hosts") },
    hoverTip(h("button", { class: "hr-act", disabled: hostPage === 0 ? true : null, onclick: go(hostPage - 1), "aria-label": t("pagePrev") }, icon("chevron-left")), t("pagePrev")),
    Array.from({ length: pages }, (_, i) => h("button", { class: "hr-page" + (i === hostPage ? " on" : ""), "aria-current": i === hostPage ? "page" : null, onclick: go(i) }, String(i + 1))),
    hoverTip(h("button", { class: "hr-act", disabled: hostPage === pages - 1 ? true : null, onclick: go(hostPage + 1), "aria-label": t("pageNext") }, icon("chevron-right")), t("pageNext"))) : null;
  return h("div", { class: "card mt hostrows" },
    h("div", { class: "panel-head" }, h("h3", null, t("hosts")), h("span", { class: "panel-extra" }, hosts.length + " " + t("hosts").toLowerCase())),
    hosts.slice(hostPage * HOST_PAGE, (hostPage + 1) * HOST_PAGE).map(hostRow),
    pager);
}

function hostFilterBar(hosts, all) {
  const statusSel = h("select", { onchange: () => { hostFilt.status = statusSel.value; render(); } },
    [["", t("allStates")], ["online", t("online")], ["offline", t("notOnline")]].map(([v, l]) => h("option", { value: v, selected: v === hostFilt.status }, l)));
  const check = (k, label) => h("label", { class: "check" }, h("input", { type: "checkbox", checked: hostFilt[k] ? true : null, onchange: (e) => { hostFilt[k] = e.target.checked; render(); } }), t(label));
  const mode = h("div", { class: "tabs" }, [["cards", t("cards")], ["table", t("table")], ["rows", t("rows")]].map(([k, l]) =>
    h("button", { class: hostsMode === k ? "on" : null, onclick: () => { hostsMode = k; store("vigil.hostsMode", k); render(); } }, l)));
  return h("div", { class: "flex wrap mt hostbar" }, mode, h("label", { class: "inline-l" }, t("status"), statusSel), check("crit", "onlyCritical"), check("reboot", "onlyReboot"),
    h("span", { class: "muted right" }, hosts.length + " " + t("ofTotal") + " " + all.length));
}

// tags editor for the host page (admins)
function tagEditor(a) {
  const input = h("input", { value: (a.tags || []).join(", "), maxlength: 220, list: "tag-list", placeholder: "E, M, game, web" });
  const err = h("div", { class: "err" });
  return h("form", { class: "inline mt", onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    try {
      await post("/api/ui/agents/" + a.id + "/tags", { tags: input.value.split(",").map((x) => x.trim()).filter(Boolean) });
      await loadScopeHosts(true);
      render();
    } catch (x) { err.textContent = x.message; }
  } }, h("datalist", { id: "tag-list" }, allTags().map((g) => h("option", { value: g }))),
    h("label", null, t("groups"), input), h("button", { class: "btn ghost", type: "submit" }, t("save")), err);
}

// ---------- groups ----------
// The first three groups (alphabetical) get the validated series colours,
// further ones stay grey; colour is never the only hint, names come along.
const groupNames = () => allTags();
// A host's main group is the one most hosts share (owner groups like
// "Moritz" rather than a role tag only it carries); ties go by name.
const groupSize = (g) => (scopeHosts || []).filter((x) => (x.tags || []).includes(g)).length;
const primaryGroup = (x) => ((x.tags || []).slice().sort((a, b) => groupSize(b) - groupSize(a) || a.localeCompare(b, lang))[0]) || "";
const mainGroups = () => [...new Set((scopeHosts || []).map(primaryGroup).filter(Boolean))].sort((a, b) => a.localeCompare(b, lang));
const groupClass = (g) => { const i = mainGroups().indexOf(g); return i >= 0 && i < 3 ? "g" + (i + 1) : "g0"; };

function groupHead(name, list) {
  const withM = list.filter((x) => x.metrics);
  const online = list.filter((x) => x.status === "online").length;
  const avg = (f) => withM.length ? withM.reduce((s, x) => s + f(x.metrics), 0) / withM.length : 0;
  const bySev = {};
  list.forEach((x) => Object.entries(x.open_by_severity || {}).forEach(([k, n]) => { bySev[k] = (bySev[k] || 0) + n; }));
  return h("div", { class: "ghead" },
    h("span", { class: "gmark " + (name ? groupClass(name) : "g0") }),
    h("h2", null, name || t("noGroup")),
    h("span", { class: "chip" }, h("span", { class: "dot " + (online === list.length ? "online" : "silent") }), online + " / " + list.length + " " + t("online")),
    withM.length ? h("span", { class: "muted" }, t("cpu") + " " + fmtPct(avg((m) => m.cpu)) + "  ·  " + t("memory") + " " + fmtPct(avg((m) => pctOf(m.mem_used, m.mem_total)))) : null,
    Object.keys(bySev).length ? sevCounts(bySev) : null,
    name ? h("button", { class: "linkbtn right", onclick: () => setScope({ group: name }) }, t("onlyThisGroup")) : null);
}

function groupedCards(hosts, agentPort) {
  const by = new Map();
  for (const x of hosts) {
    const g = primaryGroup(x);
    if (!by.has(g)) by.set(g, []);
    by.get(g).push(x);
  }
  const names = [...by.keys()].sort((a, b) => (a === "") - (b === "") || a.localeCompare(b, lang));
  if (names.length === 1 && names[0] === "") return h("div", { class: "hostgrid mt" }, hosts.map((x) => hostCard(x, agentPort)));
  return names.map((g) => h("section", { class: "gsection mt" }, groupHead(g, by.get(g)), h("div", { class: "hostgrid" }, by.get(g).map((x) => hostCard(x, agentPort)))));
}

async function groupsPanel() {
  const gs = await api("/api/ui/groups").catch(() => []);
  if (!gs.length) return null;
  return h("div", { class: "mt" }, h("h2", null, t("groups")), h("div", { class: "tablewrap" }, h("table", { class: "groups" },
    h("thead", null, h("tr", null, [t("group"), t("hosts"), t("alertsOpen"), t("securityShortL"), t("rebootShort"), t("attackers") + " 24 h"].map((x) => h("th", null, x)))),
    h("tbody", null, gs.map((g) => h("tr", { class: "click", onclick: () => setScope({ group: g.name }) },
      h("td", null, h("span", { class: "gmark " + groupClass(g.name) }), h("span", { class: "strong" }, g.name)),
      h("td", null, h("span", { class: "chip" }, h("span", { class: "dot " + (g.online === g.hosts.length ? "online" : "silent") }), g.online + " / " + g.hosts.length)),
      h("td", null, Object.values(g.open_by_severity).some(Boolean) ? sevCounts(g.open_by_severity) : h("span", { class: "muted" }, "0")),
      h("td", null, g.security_updates ? h("span", { class: "sev high" }, g.security_updates) : h("span", { class: "muted" }, "0")),
      h("td", null, g.reboot_pending ? h("span", { class: "sev medium" }, g.reboot_pending) : h("span", { class: "muted" }, "0")),
      h("td", null, g.attackers_24h == null ? h("span", { class: "muted", title: t("ht_rollupWait") }, "·") : g.attackers_24h.toLocaleString(lang))))))));
}

// settings: groups and their members (admins with the base role)
function groupsAdmin(hosts) {
  const err = h("div", { class: "err" });
  const names = groupNames();
  const send = async (body) => {
    err.textContent = "";
    try { await post("/api/ui/groups", body); await loadScopeHosts(true); render(); } catch (x) { err.textContent = x.message; }
  };
  const sorted = hosts.slice().sort((a, b) => a.name.localeCompare(b.name, lang));
  const memberForm = (g) => {
    const boxes = sorted.map((x) => h("label", { class: "check" }, h("input", { type: "checkbox", value: x.id, checked: (x.tags || []).some((t_) => t_.toLowerCase() === g.toLowerCase()) ? true : null }), x.name));
    return h("div", { class: "gadmin" },
      h("div", { class: "flex wrap" }, h("span", { class: "gmark " + groupClass(g) }), h("span", { class: "strong" }, g),
        h("button", { class: "btn small ghost right", onclick: () => { const to = prompt(t("renameGroup"), g); if (to && to.trim() !== g) send({ action: "rename", group: g, to: to.trim() }); } }, t("rename")),
        h("button", { class: "btn small ghost", onclick: () => { if (confirm(t("confirmDeleteGroup").replace("{g}", g))) send({ action: "delete", group: g }); } }, t("remove"))),
      h("div", { class: "flex wrap mt" }, boxes),
      h("button", { class: "btn small mt", onclick: () => send({ action: "members", group: g, hosts: boxes.map((b) => b.querySelector("input")).filter((i) => i.checked).map((i) => i.value) }) }, t("saveMembers")));
  };
  const newName = h("input", { maxlength: 24, placeholder: t("newGroup") });
  const newBoxes = sorted.map((x) => h("label", { class: "check" }, h("input", { type: "checkbox", value: x.id }), x.name));
  return h("div", { class: "card mt" }, h("h3", null, t("groups")),
    names.length ? names.map(memberForm) : h("div", { class: "muted" }, t("noGroups")),
    h("div", { class: "gadmin" }, h("label", null, t("newGroup"), newName), h("div", { class: "flex wrap mt" }, newBoxes),
      h("button", { class: "btn small mt", onclick: () => {
        const g = newName.value.trim();
        const ids = newBoxes.map((b) => b.querySelector("input")).filter((i) => i.checked).map((i) => i.value);
        if (g && ids.length) send({ action: "members", group: g, hosts: ids });
      } }, icon("plus"), t("createGroup"))),
    err);
}

// settings: one account's roles per group
function groupRolesCell(u, askCode, onErr) {
  const gr = u.group_roles || {};
  const chips = Object.entries(gr).map(([g, r]) => h("span", { class: "tag" }, g + ": " + t(r)));
  const edit = h("button", { class: "btn small ghost", onclick: () => {
    const box = h("div", { class: "grolesedit" }, groupNames().map((g) => {
      const cur = Object.entries(gr).find(([k]) => k.toLowerCase() === g.toLowerCase());
      return h("label", null, g, h("select", { "data-group": g },
        [["", t("baseRoleOnly")], ["viewer", t("viewer")], ["analyst", t("analyst")], ["admin", t("admin")]].map(([v, l]) => h("option", { value: v, selected: (cur ? cur[1] : "") === v }, l))));
    }), h("button", { class: "btn small", onclick: async () => {
      const roles = {};
      box.querySelectorAll("select").forEach((s_) => { if (s_.value) roles[s_.dataset.group] = s_.value; });
      const code = askCode(); if (!code) return;
      try { await post("/api/ui/users/" + encodeURIComponent(u.name) + "/group_roles", { group_roles: roles, code }); render(); } catch (x) { onErr(x.message); }
    } }, t("save")));
    edit.replaceWith(box);
  } }, t("edit"));
  return h("div", { class: "flex wrap" }, chips.length ? chips : h("span", { class: "muted" }, t("none")), groupNames().length ? edit : null);
}

let refreshTimer = null;
let selftestOpen = false;
let lastHash = null;
async function render() {
  clearTimeout(refreshTimer);
  // a page refreshing itself keeps where the reader was
  const box = document.querySelector("main.content");
  const keep = lastHash === location.hash && box ? box.scrollTop : 0;
  lastHash = location.hash;
  tip(null, null);
  if (!me) {
    try { me = await api("/api/ui/me"); } catch { me = null; }
    if (!me) return loginView();
  }
  const [path, query] = (location.hash.slice(1) || "/").split("?");
  const params = new URLSearchParams(query || "");
  const parts = path.split("/").filter(Boolean);
  if (parts[0] !== "hosts" || parts[1]) topo.full = false;
  // the map's live stream runs while the map is shown
  if (parts[0] !== "hosts" || parts[1] || hostsMode !== "cards") mapClose();
  document.body.classList.remove("topo-noscroll");
  // links may carry a scope: #/alerts?host=ID or ?group=TAG
  if (params.get("host")) setScope({ agent: params.get("host") }, true);
  else if (params.get("group")) setScope({ group: params.get("group") }, true);
  try {
    await loadScopeHosts();
    if (parts[0] === "alerts" && parts[1]) await alertDetail(parts[1]);
    else if (parts[0] === "alerts") await alertsView();
    else if (parts[0] === "hosts" && parts[1]) await hostView(parts[1], params);
    else if (parts[0] === "hosts") await hostsView();
    else if (parts[0] === "events") await eventsView(params);
    else if (parts[0] === "timeline") await timelineView(params);
    else if (parts[0] === "sessions") await sessionsView(params);
    else if (parts[0] === "session") await sessionView(params);
    else if (parts[0] === "hunt") await huntView();
    else if (parts[0] === "attacks") await attacksView(params);
    else if (parts[0] === "sources") await sourcesView(params);
    else if (parts[0] === "pivot" && parts[2]) await pivotView(parts[1], decodeURIComponent(parts.slice(2).join("/")), params);
    else if (parts[0] === "snapshot" && parts[1]) await snapshotView(parts[1], params);
    else if (parts[0] === "canaries") await canariesView();
    else if (parts[0] === "suppressions") await suppressionsView();
    else if (parts[0] === "rules") await rulesView();
    else if (parts[0] === "incidents" && parts[1]) await incidentDetail(parts[1]);
    else if (parts[0] === "incidents") await incidentsView();
    else if (parts[0] === "settings") await settingsView();
    else await overview();
    if (keep) { const b = document.querySelector("main.content"); if (b) b.scrollTop = keep; }
  } catch (x) {
    if (x.message !== "unauthorized") { console.error(x); mount(shell("", h("div", { class: "card err" }, x.message))); }
  }
  // The overview and alert list refresh themselves; forms are left alone.
  // not while someone types into a filter
  const later = () => { const el = document.activeElement; if (topoBusy() || el && /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName)) refreshTimer = setTimeout(later, 10000); else render(); };
  if (!parts.length || (parts[0] === "alerts" && !parts[1]) || (parts[0] === "hosts" && !parts[1])) refreshTimer = setTimeout(later, 30000);
  // A running self test finishes within minutes; follow it on the host page.
  if (parts[0] === "hosts" && selftestOpen) refreshTimer = setTimeout(render, 10000);
}

window.addEventListener("hashchange", render);
// map.js and attackmap.js load after this file and add the host map and
// the attackers map
document.addEventListener("DOMContentLoaded", render);
