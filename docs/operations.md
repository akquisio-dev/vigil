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

## Response actions

On an alert, admins can contain an attack on the host directly, if the host's
`agent.json` allows it ([configuration](configuration.md#response-actions)):

| Action | What the agent does | Refuses |
|---|---|---|
| Block address | adds it for 24 hours to an nftables set in its own table `inet vigil`, dropping traffic from and to it (input, forward, output) | loopback, local, the vigil server, `never_block` |
| End SSH session | stops the sshd process of the login (`SIGTERM`, then `SIGKILL`) | anything that is not an sshd session, the SSH daemon itself |
| Stop process | stops the process | a pid that now runs another program, pid 1, the agent |
| Remove key | removes the key from `authorized_keys`, after a backup in the agent's state directory | the last key of a file, files that are not `authorized_keys` |

Every action needs a fresh code from the authenticator app, reaches the
agent in the next signed configuration, is valid for ten minutes and runs at
most once. The request and the agent's result are in the event chain, and
the host page lists them. There is no way to run arbitrary commands.

To lift a block early: `nft delete element inet vigil blocked4 { 203.0.113.9 }`,
or remove the whole table with `nft delete table inet vigil`.

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
  rule, and all rules about agents, canaries, the event chain, log spoofing,
  notifiers and self tests.
  Use a maintenance window for planned agent restarts instead.

## Self test

A detection that never fires looks exactly like a quiet host. The self test
proves that each host's sensors, the server's rules and your notifiers still
work, end to end.

On request, the agent leaves three harmless traces, each named after a random
test id:

| Step | Trace | Must raise |
|---|---|---|
| file | a comment-only file in `/var/spool/cron/crontabs` (or `/etc/cron.d`), removed right after the scan | `file.cron` |
| process | a copy of `sleep` started from `/tmp` for one second | `process.tmp_exec` |
| journal | a log line tagged `sshd`, written by the agent | `log.spoofed` |

The server matches findings to the test by that id, never by time, so an
attack during a test still raises its normal alert. Findings of the test raise
no alert; they stay in the event log like everything else. The result goes to
**every** notifier, whatever its `min_severity`, so each channel is tested too.

- **passed**: every trace was detected.
- **passed with warnings**: a step was skipped (for example `/tmp` is mounted
  `noexec`, or a collector is turned off in `agent.json`) or its rule is
  suppressed.
- **failed**: a trace was not detected, a collector stopped, or the agent did
  not run the test within ten minutes. This raises `selftest.failed` (high,
  cannot be suppressed) with the missing steps and, where the agent knows it,
  why the sensor is down.

Every host is tested right after it first connects and then every
`selftest_days` days (default 7). Admins start a test on the host page at any
time. Hosts in a maintenance window, stopped or silent are skipped by the
schedule. An agent with `"selftest": false` in `agent.json` refuses tests.

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

Start a maintenance window for the host first, or the restart raises an
alert. Then install the new release (`sh install.sh agent -version vX.Y.Z`,
the `.deb`, or the binary by hand) and restart the service. Agents do not
update themselves; a compromised server must not be able to push code to
every host.

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
