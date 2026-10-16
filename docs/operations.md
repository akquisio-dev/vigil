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
