# Custom rules

Custom rules add detections without changing vigil's code. They are JSON
files in the directory set as `rules_dir` in `server.json`, loaded when the
server starts.

```json
"rules_dir": "/etc/vigil/rules.d"
```

They cannot replace or switch off a built-in rule: their ids must start with
`custom.`. A file that fails to load is skipped and reported, the other files
and all built-in rules keep working. The dashboard lists loaded rules and load
errors under **Rules**.

## A rule

```json
{
  "id": "custom.sudo_shell",
  "severity": "medium",
  "technique": "T1548.003",
  "description": "Someone used sudo to start an interactive shell.",
  "title": {
    "en": "{user} started a root shell with sudo: {command}",
    "de": "{user} hat mit sudo eine Root-Shell gestartet: {command}"
  },
  "event": "sudo.command",
  "where": [ { "field": "command", "op": "regex", "value": "(^|/)(ba|z|da)?sh$" } ],
  "key": ["user"]
}
```

A file holds one rule or a list of rules.
[`deploy/examples/rules/examples.json`](https://github.com/akquisio-dev/vigil/blob/main/deploy/examples/rules/examples.json)
has three to start from.

| Field | |
|---|---|
| `id` | `custom.` followed by lower case letters, digits, `_`, `.` or `-` |
| `severity` | `info`, `low`, `medium`, `high` or `critical` |
| `technique` | optional ATT&CK technique, shown with a link |
| `title` | `en` is required, `de` optional. `{field}` is replaced by the event's field, `{host}` by the host name |
| `event` | an event type such as `ssh.login`, or a prefix ending in `*` such as `file.*` |
| `where` | conditions that must all hold |
| `threshold` | optional: `count` matches within `window_minutes`, counted per value of `group_by` |
| `key` | fields that make two findings the same alert (default: every match is the same alert per host) |

## Conditions

`field` is a field of the event's data, or `type` or `host`. If the field is
a list (the `users` of `ssh.failed`), the condition holds when any element
matches.

| `op` | `value` |
|---|---|
| `equals`, `not_equals` | text or number |
| `contains`, `prefix`, `suffix` | text |
| `regex` | a [Go regular expression](https://pkg.go.dev/regexp/syntax) |
| `in` | a list |
| `gt`, `lt` | a number |
| `exists` | none |

The event types and their fields are listed in the [architecture](architecture.md#event-types)
and visible on the **Events** page of the dashboard.

## Trying a rule

```sh
vigil-server rules check /etc/vigil/rules.d
vigil-server rules test my-rule.json /var/lib/vigil/events/2026-10-16.jsonl
```

`rules test` runs one file against recorded events: lines of the event log,
records, or bare events (`{"type": "...", "ts": "...", "data": {...}}`), and
prints every finding.

Custom rules raise alerts, join incidents and can be suppressed like built-in
rules (unless they are critical). Sigma import is planned once process events
exist.
