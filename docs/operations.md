# Operations

## Working with alerts

An alert is `open` until someone acknowledges or resolves it. The same finding
on the same host within 24 hours raises the counter of the open alert instead
of a new one.

| Status | Meaning |
|---|---|
| open | nobody has looked at it yet |
| acknowledged | someone looked and is on it |
| resolved | closed, by a person or by vigil (for example when a silent agent is back) |

Every alert names its rule. The [rule catalogue](rules.md) explains each one.

## Accounts and roles

| Role | May |
|---|---|
| viewer | read everything |
| analyst | also acknowledge and resolve alerts, work on incidents, manage suppressions, verify the chain |
| admin | also place canaries, manage hosts, create enrollment tokens, send test notifications, manage users |

Accounts created before roles existed are admins. Under **Settings** every
user can add passkeys and change the password; admins add users (the page
shows the new password and a QR code for the authenticator app once), change
roles and remove users. These changes need a fresh code from the
authenticator app and are written to the event chain. The last admin can
neither be removed nor lowered.

Passkeys need `public_url` to be set to the address in the browser, because
it is the relying party they are bound to. Changing the domain later makes
existing passkeys unusable; password and TOTP keep working.

## Incidents

Alerts that belong together are grouped into incidents, so an intrusion is
handled as one case:

- An alert joins the newest incident on its host that is not closed, if the
  incident had an alert within two hours before or after it.
- Otherwise a high or critical alert opens a new incident. It takes along the
  host's alerts from the two hours before that are in no incident yet, for
  example the login from a new address that came first.
- Alerts about the agent itself (stopped, restarted, silent) never open an
  incident, but they join one.

An incident page shows its alerts and the host's raw events from 30 minutes
before the first to 30 minutes after the last alert, with the SSH login that
most likely started the session at the top. Take it over, set the status
(open, investigating, contained, closed) and write notes; every change is in
the event chain. **Open incident** on an alert starts one by hand.

Notifications are still sent per alert.

## Suppressions

When a finding is expected (a backup job that rewrites a cron file every night,
a deploy runner that logs in from a fixed address), open the alert and use
**Suppress similar**. Choose which of the alert's parameters must match, whether
it applies to this host only, a reason and a duration (at most 90 days).

- Matching findings raise no alert and no notification. The events that caused
  them stay in the event log, and each suppression counts its hits.
- Creating, renewing, deleting and expiring a suppression are written to the
  event chain with the user's name.
- Expired suppressions stay listed under **Suppressions** for 30 days, so they
  can be renewed.
- Rules an attacker would want silenced cannot be suppressed: every critical
  rule, and all rules about agents, canaries, the event chain and log spoofing.
  Use a maintenance window for planned agent restarts instead.

## Planned work on a host

Every agent stop and restart raises a high alert, because an attacker would do
exactly that before touching a canary. Before planned work, open the host in the
dashboard and start a **maintenance window** (30 to 240 minutes). While it
runs, agent stop, restart and silence alerts for that host are not raised. The
events themselves stay in the log, and the window is recorded with the name of
the person who set it.

The agent cannot announce its own maintenance. Anything the host says about
itself may come from the attacker.

## Ports

The first port snapshot of a host is its baseline. Afterwards:

- **Accept** allows one exact socket (protocol, address, port).
- **Allow process** allows every port of that program with the same protocol
  and scope. Use it for programs with random ports.

## Upgrading

Replace the binary and restart the service. Start a maintenance window for the
host first, or the restart raises an alert.

```sh
install -m 0755 dist/vigil-agent /usr/local/bin/
systemctl restart vigil-agent
```

The server keeps all state across restarts. Dashboard sessions do not survive a
restart; everyone logs in again.

## Verifying the event log

```sh
vigil-server verify -config /etc/vigil/server.json
```

The server also verifies the chain on start, once a day and when you press
**Verify now** in the settings. A break raises `chain.broken` with the file and
line.

## Backups

Back up `/var/lib/vigil` on the server. It holds the event log, the state,
dashboard users and the server key. Agents pinned that key at enrollment; if it
is lost, every agent has to be enrolled again.

On hosts, `/var/lib/vigil-agent` holds the agent key and its last known state.
After restoring an old copy, the agent reports every change since that copy as
new, which is correct but noisy. Keep the host's clock synchronized: sequence
numbers come from it, and a clock that jumps backwards makes the server reject
batches as replays.

## Removing a host

Remove the host's canaries in the dashboard first and wait until the host page
shows the configuration as applied; the agent has then deleted the files. Then use **Remove host**, which
deletes the agent record from the server. On the host, stop and disable the
service and delete `/var/lib/vigil-agent`. The event log keeps everything the
host reported.

## Resource limits

The systemd units cap the agent at 96 MB of memory and 15 % CPU with idle I/O
priority, and the server at 256 MB and 50 % CPU. Adjust them in a drop-in if a
host needs more.
