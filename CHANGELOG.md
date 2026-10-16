# Changelog

## v0.11.0

- Self test: on request and every `selftest_days` (default 7) each agent leaves three harmless marked traces (crontab spool file, `sleep` from `/tmp`, an sshd-tagged log line) that `file.cron`, `process.tmp_exec` and `log.spoofed` must catch; the result goes to every notifier, failures raise `selftest.failed` with the reason a sensor is down. Agent option `selftest` (default on).
- Notifications: new types `ntfy`, `slack` (also Mattermost, Rocket.Chat) and `telegram`; Discord `mention` for critical alerts; `vigil-server notify test`; delivery status per notifier in the dashboard; a lost message raises `notify.failed` through the other notifiers; HTTP 429 waits for Retry-After; notifiers are validated at start.
- `heartbeat_url` is only pinged while the event chain verifies, the log and data directory are writable and the server is not hung.
- Fix: notifier errors in the log no longer contain the webhook URL with its secret.

## v0.10.0

- Response actions from an alert: block an address (nftables, table `inet vigil`), end an SSH session, stop a process, remove an SSH key. Off unless `response` in agent.json enables them; fresh TOTP code, ten minute validity, at most once, audited.

## v0.9.0

- Reproducible, signed releases (Sigstore keyless) with binaries and Debian packages for amd64 and arm64; `install.sh` checks signature and checksum; `version -verify` compares a running binary with the release.

## v0.8.0

- Agent: suspicious program starts (process events connector), new outbound destinations, web server access logs, pending updates and reboots.
- Server: `threat_intel` matches outbound connections against abuse.ch Feodo Tracker and ThreatFox, Spamhaus DROP and Tor exits. New rules `process.*`, `net.*`, `web.*`, `updates.*`.

## v0.7.0

- Passkeys (WebAuthn, standard library only), roles viewer, analyst and admin, password change, user management with TOTP QR codes; `user add -role`.

## v0.6.0

- Custom rules as JSON in `rules_dir`, with `vigil-server rules check` and `rules test`; rules page in the dashboard; event type reference in the docs.

## v0.5.0

- Incidents: related alerts grouped per host, with timeline, owner, status and notes.

## v0.4.0

- Suppressions with reason and expiry (at most 90 days); critical and self-protection rules cannot be suppressed.

## v0.3.0

- SOC overview (alerts per day, open by severity, ATT&CK tactics, top rules, attacking addresses, host table, logins), light and dark switch, configurable brand.

## v0.2.x

- Dashboard layout following the Akquisio app; content-hashed assets.

## v0.1.0

- First release: agent, server, dashboard, canaries, hash-chained event log.
