# Changelog

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
