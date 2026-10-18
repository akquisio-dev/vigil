# Installation

This guide sets up one server and enrolls hosts. It assumes Linux with
systemd. Commands run as root.

## Plan the network

vigil has two listeners on the server:

| Listener | Purpose | Recommended address |
|---|---|---|
| `listen` | dashboard | `127.0.0.1:8470`, behind a TLS reverse proxy |
| `agent_listen` | agent API | an address on a private network or VPN, for example WireGuard |

Agents sign everything they send, so the agent API does not need TLS for
integrity. It should still not be reachable from the internet: keep it on a VPN
address and allow it in the firewall only from your hosts.

## Get the binaries

### From a release (recommended)

Every release on GitHub has static binaries for amd64 and arm64, Debian
packages, `SHA256SUMS` and a Sigstore signature of `SHA256SUMS`, made by the
release workflow without any long-lived key. `install.sh` downloads, checks
both and installs the binary and its systemd unit:

```sh
curl -fsSLO https://github.com/akquisio-dev/vigil/releases/latest/download/install.sh
less install.sh
sh install.sh server
sh install.sh agent -server http://10.0.0.1:8471 -token vgl_...   # on each host
```

It needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
for the signature check. To check a download by hand:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/akquisio-dev/vigil/.github/workflows/release.yml@refs/tags/v0.9.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

Builds are reproducible: `git checkout v0.9.0 && deploy/release/build.sh
v0.9.0` with the Go toolchain named in `go.mod` produces the same checksums.
On a running host, `vigil-agent version -verify` and `vigil-server version
-verify` compare the installed binary with the published one.

The Debian packages install to `/usr/bin` and do not enable the service; add
the configuration first.

### With apt (Debian and Ubuntu)

```sh
curl -fsSL https://akquisio-dev.github.io/vigil/apt/vigil-archive-keyring.gpg -o /usr/share/keyrings/vigil-archive-keyring.gpg
gpg --show-keys /usr/share/keyrings/vigil-archive-keyring.gpg   # fingerprint below
echo "deb [signed-by=/usr/share/keyrings/vigil-archive-keyring.gpg] https://akquisio-dev.github.io/vigil/apt stable main" > /etc/apt/sources.list.d/vigil.list
apt update
apt install vigil-agent   # or vigil-server
```

The repository key has the fingerprint

```
9296 F127 C574 D1B1 9F16  F529 D493 FE1D DD6B 70D8
```

and is also in the source tree as `deploy/apt/vigil-archive-keyring.asc`;
compare the two before trusting it. It expires on 2029-10-17. The repository
holds the packages of the newest five releases, each taken only after the
release's Sigstore signature was checked. The packages do not start or
restart the service: after `apt upgrade`, run `systemctl restart vigil-agent`
(with a maintenance window, see [Operations](operations.md#upgrading)).
Agents installed this way are updated with apt, not from the dashboard.

### From source

vigil needs Go 1.25 or newer.

```sh
git clone https://github.com/akquisio-dev/vigil
cd vigil
make build     # dist/vigil-agent and dist/vigil-server, static binaries
make test
```

## Install the server

```sh
useradd --system --home-dir /var/lib/vigil --shell /usr/sbin/nologin vigil
install -m 0755 dist/vigil-server /usr/local/bin/
install -d -m 0750 -o root -g vigil /etc/vigil
install -m 0640 -o root -g vigil deploy/examples/server.json /etc/vigil/server.json
```

Edit `/etc/vigil/server.json`. At least set `agent_listen`, `agent_url`
(how agents reach `agent_listen`) and `public_url`. See
[Configuration](configuration.md).

```sh
cp deploy/systemd/vigil-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vigil-server
```

If `agent_listen` is a VPN address, start the server after the VPN with a
drop-in, for example for WireGuard:

```ini
# /etc/systemd/system/vigil-server.service.d/vpn.conf
[Unit]
After=wg-quick@wg0.service
Wants=wg-quick@wg0.service
```

Allow the agent API only from your hosts, for example with ufw:

```sh
ufw allow in on wg0 from 10.0.0.0/24 to any port 8471 proto tcp
```

## Create a dashboard user

```sh
vigil-server user add -config /etc/vigil/server.json alice
```

The command asks for a password (at least 12 characters) and prints the TOTP
secret as a QR code to scan with an authenticator app; every login needs the
code. `-role viewer|analyst|admin` sets the role (default admin). After the
first login, add a passkey under **Settings** and further users from there. Run the
command in your own terminal so the password never lands in a log or a chat.

## Put the dashboard behind TLS

`deploy/examples/nginx.conf` is a starting point. Important details:

- Return 404 for `/api/agent/` on the public site; agents use `agent_listen`.
- Set `X-Forwarded-For` to the client address and enable `trust_proxy` in the
  server config.
- Behind a CDN such as Cloudflare, restore the client address first
  (`set_real_ip_from` for the CDN ranges and `real_ip_header CF-Connecting-IP`).
  Otherwise rate limits and the audit log show the CDN.
- Rate limit `/api/ui/login` in addition to vigil's own limit.

## Enroll a host

In the dashboard, open **Settings** and create an enrollment token. It is valid
for one hour and one use. On the host:

```sh
install -m 0755 dist/vigil-agent /usr/local/bin/
install -d -m 0700 /etc/vigil
cp deploy/examples/agent.json /etc/vigil/agent.json   # set server and canary_roots
vigil-agent enroll -config /etc/vigil/agent.json -server http://10.0.0.1:8471 -token vgl_...
cp deploy/systemd/vigil-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vigil-agent
```

The host appears in the overview within one interval (30 seconds by default).
Rename it in the dashboard; hostnames like `ubuntu` are not helpful.

## What happens first

- The first scan becomes the **baseline**. Files, accounts and ports that exist
  already raise nothing.
- Every SSH user raises `ssh.new_source` once per source address. Acknowledge
  these after checking them.
- Programs that pick random ports on each start (game servers, Wine) raise
  port alerts after their next restart. Use **Allow process** on the host page
  once per program.

## Add notifications

Until a notifier is configured, alerts only appear in the dashboard, and an
attack at night waits until someone looks. Add at least two channels, for
example a chat and a phone push, see
[Configuration](configuration.md#notifiers) for Discord, Slack, Mattermost,
ntfy, Telegram, webhooks and mail. Then check them:

```
sudo vigil-server notify test -config /etc/vigil/server.json
```

Finally set `heartbeat_url` to an outside check, so you also hear about it
when the server itself goes down. See
[Watching the server from outside](configuration.md#watching-the-server-from-outside).
