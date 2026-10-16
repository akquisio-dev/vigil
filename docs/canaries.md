# Canaries

A canary is a file that looks valuable and that no legitimate workflow ever
opens. Because nothing should touch it, every touch is worth an alert, and
there is no baseline of normal behaviour to tune.

## Types

| Type | Content | Typical name |
|---|---|---|
| `credentials` | a plain text list of hosts, users and passwords | `access-old.txt`, `passwords.txt` |
| `env` | an application `.env` with database, SMTP, JWT and storage secrets | `.env.bak`, `.env.production.old` |
| `ssh-key` | a real, unencrypted OpenSSH ed25519 private key that is authorized nowhere | `id_ed25519_backup`, `deploy_key` |
| `sql-dump` | a mysqldump of a user table with 40 made-up users | `users-2025-11.sql`, `db-backup.sql` |

All values are generated randomly on the host when the canary is placed. The
optional parameters:

| Parameter | Types | Effect |
|---|---|---|
| `domain` | all | domain used in host names and addresses inside the file |
| `email` | `sql-dump` | the admin row gets this address |
| `comment` | `ssh-key` | comment of the key |

### Tracking e-mail addresses

Give a `sql-dump` canary an address on a mail domain you control, used nowhere
else. If mail ever arrives there, the dump left the server, even when nobody
was logged in to trip the file alert. This works across leaks, backups and
copies.

## Placing a canary

Open **Canaries** in the dashboard, pick the host, type and path. The agent
creates the file with the next batch (within 30 seconds by default). The status
changes from `pending` to `active`, or to `error` with the reason.

The agent only accepts paths below the `canary_roots` of its local
configuration and refuses anything that could turn a canary into a backdoor:

- names such as `authorized_keys`, `.bashrc`, `.profile`, `crontab`
- suffixes such as `.service`, `.timer`, `.sh`, `.py`, `.so`
- directories such as `cron.d`, `systemd`, `sudoers.d`, `profile.d`, `bin`
- any symlink on the path
- an existing file at the path (canaries never overwrite)

Files are created with mode 0600 and owned by root.

## Where to put them

Good places are where an intruder looks first:

- the home directory of root and of admin users
- next to real application directories in `/opt` or `/srv`
- backup directories

Use names that fit the host. A file called `passwords.txt` on a game server
with no other text files stands out; `.env.bak` next to a real `.env` does not.

## What will trip them by accident

| Source | What to do |
|---|---|
| backup jobs that archive the directory | place canaries outside the backed-up paths, or add the backup program to `canary_ignore_exe` |
| `updatedb`/`locate`, file indexers | they only read names, not contents, and do not trigger; full-content indexers do |
| antivirus or secret scanners | add them to `canary_ignore_exe` |
| admins running `grep -r` over a directory | expected; acknowledge the alert, or keep canaries out of directories you search often |

`canary_ignore_exe` matches the full executable path, for example
`/usr/bin/restic`. Keep the list in your private configuration: it tells a
reader which program can open canaries unseen.

## What an alert tells you

`canary.opened` reports the process ID, executable or process name, user,
login UID, session ID and the chain of parent processes. Short-lived readers
such as `cat` are often gone before the executable path can be read; the name,
user and parent chain usually remain. Compare the login UID and the time with
the SSH logins of the host.

If a canary is deleted, replaced or edited, `canary.tampered` fires: someone
found it.

## Removing a canary

Remove it in the dashboard. The agent deletes the file only if it is still
exactly the file it created (same inode and content). Otherwise it leaves the
file alone and reports `canary.remove_failed`.
