# SSH VPN GUI

SSH VPN GUI is an Ubuntu desktop application that creates an OpenSSH TUN
tunnel (`ssh -w`) to a remote Linux server. Traffic can be sent through the
tunnel selectively using `routing.cfg`, nftables and a local DNS-over-TLS
classifier.

## Features

- GTK 4/Libadwaita interface.
- Password-based root login to the remote server.
- Automatic remote-server bootstrap before the tunnel starts.
- Full-tunnel and rule-based routing modes.
- Optional cascaded VPN through a user-supplied `.ovpn` file running on the
  remote server.
- GeoIP and Geosite routing data updates from the GUI.
- Automatic rollback when a connection attempt fails.
- Detects a dead tunnel after suspend/resume or SSH drop, updates the
  window, removes leftover routes, and reconnects automatically.

## Requirements

### Local computer

- Ubuntu 22.04 or newer.
- A graphical desktop session.
- Network access to the remote server's SSH port.

The Debian package installs all local runtime dependencies automatically.

### Remote server

- A Linux VPS with OpenSSH server running.
- Working root SSH login and password.
- Kernel/provider support for `/dev/net/tun`.

On the first connection the application uses the supplied root credentials to
load the TUN module when available, enable IPv4 forwarding, configure
`PermitTunnel point-to-point`, reload SSH safely, and configure tunnel
addresses and NAT. Users do not need to prepare `PermitTunnel` manually.

The application cannot enable TUN when the VPS provider or container host has
disabled that capability. In that case, enable TUN in the provider control
panel first.

## Install from GitHub Releases

1. Open this repository's **Releases** page.
2. Download the latest `ssh-vpn-gui_<version>_all.deb` asset.
3. Install it from the download directory:

```bash
sudo apt install ./ssh-vpn-gui_*_all.deb
```

Launch **SSH VPN GUI** from the application menu or run:

```bash
ssh-vpn-gui
```

Enter the remote server IP address, `root` as the login, and its SSH password.
Click **Update Routing Data** once before using GeoIP or Geosite rules, then
click **Connect**.

To update, download the newer `.deb` and run the same `apt install` command.
Your saved credentials and `/etc/ssh-vpn-gui/routing.cfg` are preserved.

To uninstall:

```bash
sudo apt remove ssh-vpn-gui
```

Use `sudo apt purge ssh-vpn-gui` instead if you also want apt to remove package
configuration files.

## Build the Debian Package

Clone or download the repository, open a terminal in its root directory, and
install the build dependencies:

```bash
sudo apt update
sudo apt install -y build-essential debhelper devscripts dh-python \
  pybuild-plugin-pyproject python3-all python3-pytest python3-setuptools \
  python3-wheel
```

Build and install:

```bash
dpkg-buildpackage -us -uc
sudo apt install ./../ssh-vpn-gui_*_all.deb
```

The package installs:

- GUI launcher: `/usr/bin/ssh-vpn-gui`
- Privileged helper: `/usr/bin/ssh-vpn-helper`
- Routing configuration: `/etc/ssh-vpn-gui/routing.cfg`
- Desktop entry, icon and Polkit policy under `/usr/share`

## Routing Rules

After installing the Debian package, edit the system configuration:

```bash
sudoedit /etc/ssh-vpn-gui/routing.cfg
```

You can also click **Edit Routing Rules** next to **Update Routing Data**. The
built-in editor validates rules before saving and applies them immediately
when rule-based routing is active.

Supported forms include:

```text
default: proxy
domain(domain:mail.qq.com)->direct
domain(regexp: '(^|[.])yandex[.]com$')->direct
domain(geosite:ru)->direct
ip(203.0.113.0/24)->direct
ip(geoip:private, geoip:ru)->direct
```

`proxy` sends matching traffic through `tun3`; `direct` uses the normal local
network. Domain and Geosite rules require applications to use normal system
DNS. After changing the file, disconnect and reconnect.

DNS is sent over TLS to Cloudflare or Quad9 using the same domain action:
queries classified as `proxy` go through `tun3`, while `direct` queries use
the local connection. IP/GeoIP rules are evaluated after the DNS response, so
the DNS path itself is selected from domain/Geosite rules and `default`.

`geosite:ru` expands the maintained v2fly `category-ru` hierarchy, including
its nested lists for VK (`vk-portal.net`, VK media CDNs), Mail.ru, OK, Yandex,
Russian banks, telecom operators, government and other domestic services.
Click **Update Routing Data** periodically to receive list updates.

**Update Routing Data** downloads:

- IP66 GeoIP MMDB to `/var/lib/ssh-vpn-gui/ip66.mmdb`
- v2fly domain-list-community data to `/var/lib/ssh-vpn-gui/geosite`

## Cascaded VPN with an .ovpn File

Enable **Use .ovpn file on remote server** and choose an OpenVPN client
configuration to chain a second VPN behind the SSH tunnel:

```text
your computer -> SSH TUN -> remote server -> OpenVPN provider -> Internet
```

During connect the application, using the root credentials:

1. Installs OpenVPN on the remote server when it is missing (apt, dnf or
   yum).
2. Uploads the selected file to `/etc/ssh-vpn-gui/client.ovpn` (mode `0600`).
3. Starts the OpenVPN client with the interface `ovpn0` and waits for it to
   come up. The client log is written to `/var/log/ssh-vpn-gui-ovpn.log` on
   the server.
4. Adds a policy-routing rule on the server so that only traffic arriving
   from the SSH tunnel is sent through `ovpn0`. The server's own default
   route and the SSH connection are not affected.

Traffic that your routing rules classify as `proxy` therefore exits through
the OpenVPN provider, while `direct` traffic keeps using your local network.
Disconnecting stops the remote OpenVPN client and removes the extra routing.

Both routing checkboxes are live while connected:

- Clearing **Use .ovpn file on remote server** immediately removes the remote
  policy route and stops the managed OpenVPN client. Selecting it starts the
  cascade without rebuilding the SSH tunnel.
- Changing **Routing rules** immediately switches between `routing.cfg` and
  full-tunnel mode.
- While disconnected, checkbox changes are saved as preferences for the next
  connection. If a live change fails, the checkbox returns to its previous
  state instead of showing a state that was not applied.
- Choosing another `.ovpn` file while the cascade is active restarts the
  remote client with that file.

Changing the cascade changes the public exit IP. Existing TCP, browser and
WebSocket sessions must reconnect. The application clears stale remote
connection-tracking entries during the switch so browsers establish fresh
sessions immediately instead of reusing the old OpenVPN NAT mapping. It also
checks connectivity after enabling the cascade and shows the new public IP.
If the check fails, it stops OpenVPN automatically and restores the SSH-only
route.

Notes:

- The `.ovpn` file must be self-contained (inline certificates and keys).
  Configurations that require an interactive username and password
  (`auth-user-pass` without a credentials file) will fail to start; embed
  `auth-user-pass` credentials in the file if your provider needs them.
- The first cascaded connect can take a minute while OpenVPN is installed.

## Local Privilege Prompt

The GUI uses Polkit (`pkexec`) because local TUN, routing and firewall changes
require root privileges. This local administrator prompt is separate from the
remote server password entered in the application.

For a single-user machine, an optional repository script can allow the current
user to run only `/usr/bin/ssh-vpn-helper` through passwordless sudo:

```bash
./scripts/install-sudoers-rule.sh
```

The GUI detects that rule and uses `sudo -n`. Remove it with:

```bash
./scripts/uninstall-sudoers-rule.sh
```

These scripts are available in the source repository, not in the Debian
package.

## Troubleshooting

Run the built-in **Diagnose** action while disconnected or connected. For
terminal diagnostics:

```bash
sudo ssh-vpn-helper diagnose --server SERVER_IP
```

Common failures:

- **Authentication failed:** verify the server IP, root login and password.
- **Connection timed out:** verify the SSH port is reachable.
- **Tunnel device open failed:** confirm that the VPS provider allows TUN.
- **Routing data missing:** click **Update Routing Data**.
- **After sleep the window still said Connected:** older versions did not
  notice the SSH session dying during suspend. Current versions probe the
  tunnel on wake (and every few seconds while connected), drop leftover
  `tun3` routes, and reconnect. If reconnect fails, click **Connect**.

Inspect tunnel liveness without changing the system:

```bash
ssh-vpn-helper status
```

Inspect generated commands without making changes:

```bash
printf '%s\n' 'test' |
  sudo ssh-vpn-helper connect --dry-run --server 203.0.113.10 \
  --password-stdin
```

## Development

Install local system dependencies:

```bash
sudo apt update
sudo apt install -y python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 python3-venv \
  openssh-client nftables policykit-1
```

Create an environment and run the tests:

```bash
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
```

PyGObject is normally provided by Ubuntu's `python3-gi` package rather than
installed from PyPI.

## Security

- The remote server is modified using root privileges. Test on a disposable
  server before using the application in production.
- Server, login and password are stored in
  `~/.config/ssh-vpn-gui/config.json` with mode `0600`; the password is not
  encrypted at rest.
- The first SSH host key is accepted automatically and stored in
  `/var/lib/ssh-vpn-gui/known_hosts`. A changed key is rejected.
- DNS uses TLS to `1.1.1.1:853`, with `9.9.9.9:853` as fallback.
- IPv6 traffic is not routed through the tunnel.

## License

SSH VPN GUI is licensed under the
[GNU General Public License version 3](LICENSE).
