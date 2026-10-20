"""The optional second hop on the server.

Without it, tunnel traffic leaves the server through the server's own
address. With it, the traffic leaves through an OpenVPN client, Tor or a
SOCKS5 proxy, and whatever the hop cannot carry is blocked on the server
instead of going around it.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import quote

from .system import (
    CASCADE_TABLE,
    OVPN_CONFIG_PATH,
    OVPN_PID_PATH,
    REDSOCKS_CONFIG_PATH,
    SOCKS5_CHECK_CONFIG_PATH,
    TOR_CONFIG_PATH,
    TunnelBinding,
    remote_cascade_block_snippet,
    remote_cascade_prologue,
    remote_cascade_redirect_snippet,
    remote_install_snippet,
    remote_rp_filter_snippet,
)

CASCADE_KINDS = ("none", "ovpn", "tor", "socks5")
CASCADE_LABELS = {"ovpn": "OpenVPN", "tor": "Tor", "socks5": "SOCKS5 proxy"}

OVPN_LOG_PATH = "/var/log/ssh-vpn-gui-ovpn.log"
OVPN_INTERFACE_WAIT_SECONDS = 90
OVPN_CONNECT_TIMEOUT_SECONDS = 8
OVPN_CONNECT_FAIL_PATTERN = (
    r"AUTH_FAILED|TLS Error|TLS handshake failed|Cannot resolve host address|"
    r"RESOLVE:|Name or service not known|Connection refused|Options error|"
    r"Exiting due to fatal error|TCP: connect to .* failed"
)

TOR_DEFAULTS_PATH = "/etc/ssh-vpn-gui/torrc-defaults"
TOR_DATA_DIR = "/var/lib/ssh-vpn-gui/tor"
TOR_LOG_PATH = "/var/log/ssh-vpn-gui-tor.log"
TOR_TRANS_PORT = 9140
TOR_DNS_PORT = 9153
TOR_BOOTSTRAP_WAIT_SECONDS = 180

REDSOCKS_LOG_PATH = "/var/log/ssh-vpn-gui-redsocks.log"
REDSOCKS_PORT = 12380
# redsocks answers every UDP DNS query with "truncated", so resolvers ask
# again over TCP, which the proxy can carry.
REDSOCKS_DNS_PORT = 5380
SOCKS5_CHECK_URLS = ("https://api.ipify.org", "https://ifconfig.me/ip")

_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"{_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?")


@dataclass(frozen=True)
class Socks5Proxy:
    host: str
    port: int
    user: str = ""
    password: str = ""

    @property
    def label(self) -> str:
        endpoint = f"{self.host}:{self.port}"
        return f"{self.user}@{endpoint}" if self.user else endpoint


@dataclass(frozen=True)
class Cascade:
    kind: str
    ovpn_b64: str = ""
    socks5: Socks5Proxy | None = None

    @property
    def label(self) -> str:
        return CASCADE_LABELS[self.kind]


def socks5_proxy(host: str, port: int | str, user: str = "", password: str = "") -> Socks5Proxy:
    """Validate SOCKS5 settings. The ValueError message is shown to the user."""
    host = host.strip()
    if not host:
        raise ValueError("Enter the SOCKS5 proxy address.")
    try:
        address = ipaddress.ip_address(host[1:-1] if host.startswith("[") and host.endswith("]") else host)
    except ValueError:
        if len(host) > 253 or not _HOSTNAME.fullmatch(host):
            raise ValueError(f"{host} is not a valid SOCKS5 proxy address.") from None
    else:
        if address.version != 4:
            raise ValueError("Use an IPv4 address or a host name for the SOCKS5 proxy.")
    try:
        number = int(str(port).strip())
    except ValueError:
        raise ValueError("The SOCKS5 port must be a number.") from None
    if not 1 <= number <= 65535:
        raise ValueError("The SOCKS5 port must be between 1 and 65535.")
    user = user.strip()
    if password and not user:
        raise ValueError("Enter the SOCKS5 login for this password.")
    for name, value in (("login", user), ("password", password)):
        # RFC 1929 sends each in at most 255 bytes.
        if len(value.encode("utf-8")) > 255:
            raise ValueError(f"The SOCKS5 {name} is longer than 255 bytes.")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(f"The SOCKS5 {name} contains control characters.")
    return Socks5Proxy(host=host, port=number, user=user, password=password)


def split_endpoint(value: str) -> tuple[str, str]:
    host, separator, port = value.strip().rpartition(":")
    if not separator or not host:
        raise ValueError("The SOCKS5 server must look like HOST:PORT.")
    return host, port


def remote_cascade_script(cascade: Cascade, binding: TunnelBinding) -> str:
    if cascade.kind == "ovpn":
        return remote_ovpn_bootstrap_script(cascade.ovpn_b64, binding)
    if cascade.kind == "tor":
        return remote_tor_bootstrap_script(binding)
    if cascade.kind == "socks5" and cascade.socks5 is not None:
        return remote_socks5_bootstrap_script(cascade.socks5, binding)
    raise ValueError(f"unsupported second hop {cascade.kind!r}")


def remote_ovpn_bootstrap_script(ovpn_b64: str, binding: TunnelBinding) -> str:
    install = remote_install_snippet(
        "OpenVPN",
        present="command -v openvpn >/dev/null 2>&1 && command -v conntrack >/dev/null 2>&1",
        apt="openvpn conntrack",
        dnf="openvpn conntrack-tools",
    )
    return f"""
set -eu
{remote_cascade_prologue(binding)}
{install}

echo 'SSH_VPN_PROGRESS Clearing the previous second hop on the server'
_ssh_vpn_gui_stop_cascade
{remote_cascade_block_snippet()}

mkdir -p /etc/ssh-vpn-gui
base64 -d > {OVPN_CONFIG_PATH} <<'SSH_VPN_OVPN_B64'
{ovpn_b64}
SSH_VPN_OVPN_B64
chmod 600 {OVPN_CONFIG_PATH}

ovpn_dev=""
for i in $(seq 0 255); do
  if [ ! -e /sys/class/net/ovpn$i ]; then
    ovpn_dev=ovpn$i
    break
  fi
done
[ -n "$ovpn_dev" ] || {{
  echo 'no free ovpn device on the remote server' >&2
  exit 1
}}
echo SSH_VPN_REMOTE_OVPN $ovpn_dev

{remote_rp_filter_snippet()}

# Timeouts belong to OpenVPN on this server. resolv-retry defaults to
# infinite and is applied before --daemon returns, so a bad hostname
# blocks this SSH script for minutes. One short resolve + one connect
# attempt; the wait loop only watches that process.
printf '\\n# ssh-vpn-gui timeouts\\nresolv-retry 3\\nconnect-retry-max 1\\nconnect-timeout {OVPN_CONNECT_TIMEOUT_SECONDS}\\nserver-poll-timeout {OVPN_CONNECT_TIMEOUT_SECONDS}\\nignore-unknown-option disable-dco\\ndisable-dco\\n' >> {OVPN_CONFIG_PATH}
echo 'SSH_VPN_PROGRESS Starting OpenVPN on the server'
# OpenVPN 2.7 DCO ignores --dev ovpnN and opens tun0, clobbering the SSH tun.
# --persist-tun keeps ovpnN, and the default route on it, across reconnects.
openvpn \
  --config {OVPN_CONFIG_PATH} \
  --ignore-unknown-option disable-dco \
  --disable-dco \
  --dev-type tun \
  --dev "$ovpn_dev" \
  --route-noexec \
  --persist-tun \
  --resolv-retry 3 \
  --connect-timeout {OVPN_CONNECT_TIMEOUT_SECONDS} \
  --server-poll-timeout {OVPN_CONNECT_TIMEOUT_SECONDS} \
  --connect-retry-max 1 \
  --daemon ssh-vpn-gui-ovpn \
  --writepid {OVPN_PID_PATH} \
  --log {OVPN_LOG_PATH}

up=0
for _ in $(seq 1 {OVPN_INTERFACE_WAIT_SECONDS}); do
  if ip -4 addr show "$ovpn_dev" 2>/dev/null | grep -q 'inet '; then
    up=1
    break
  fi
  if ! {{ [ -f {OVPN_PID_PATH} ] && kill -0 "$(cat {OVPN_PID_PATH})" 2>/dev/null; }}; then
    echo 'openvpn exited during startup' >&2
    tail -n 25 {OVPN_LOG_PATH} 2>/dev/null >&2 || true
    exit 1
  fi
  if [ -f {OVPN_LOG_PATH} ] && grep -Eiq '{OVPN_CONNECT_FAIL_PATTERN}' {OVPN_LOG_PATH}; then
    echo 'openvpn failed to connect to the VPN server' >&2
    tail -n 25 {OVPN_LOG_PATH} 2>/dev/null >&2 || true
    exit 1
  fi
  sleep 1
done
if [ "$up" -ne 1 ]; then
  echo 'openvpn interface did not come up in time' >&2
  tail -n 25 {OVPN_LOG_PATH} 2>/dev/null >&2 || true
  exit 1
fi

sysctl -w "net.ipv4.conf.$ovpn_dev.rp_filter=0" >/dev/null 2>&1 || true
ip route replace default dev "$ovpn_dev" table {CASCADE_TABLE}
cascade_ready=1
echo SSH_VPN_CASCADE_READY
""".strip()


def remote_tor_bootstrap_script(binding: TunnelBinding) -> str:
    torrc = "\n".join(
        (
            "RunAsDaemon 1",
            "ClientOnly 1",
            f"DataDirectory {TOR_DATA_DIR}",
            f"Log notice file {TOR_LOG_PATH}",
            "SocksPort 0",
            f"TransPort 127.0.0.1:{TOR_TRANS_PORT}",
            f"DNSPort 127.0.0.1:{TOR_DNS_PORT}",
        )
    )
    install = remote_install_snippet(
        "Tor",
        present="command -v tor >/dev/null 2>&1 && command -v nft >/dev/null 2>&1",
        apt="tor nftables conntrack",
        dnf="tor nftables conntrack-tools",
    )
    return f"""
set -eu
{remote_cascade_prologue(binding)}
tor_preinstalled=0
if command -v tor >/dev/null 2>&1; then
  tor_preinstalled=1
fi
{install}
if [ "$tor_preinstalled" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  # The distro unit would keep a second Tor running that nothing uses.
  systemctl disable --now tor.service tor@default.service >/dev/null 2>&1 || true
fi

echo 'SSH_VPN_PROGRESS Clearing the previous second hop on the server'
_ssh_vpn_gui_stop_cascade
{remote_cascade_block_snippet()}

tor_user=""
for candidate in debian-tor toranon _tor tor; do
  if id -u "$candidate" >/dev/null 2>&1; then
    tor_user=$candidate
    break
  fi
done
mkdir -p /etc/ssh-vpn-gui {TOR_DATA_DIR}
chmod 755 /var/lib/ssh-vpn-gui
chmod 700 {TOR_DATA_DIR}
: > {TOR_LOG_PATH}
: > {TOR_DEFAULTS_PATH}
cat > {TOR_CONFIG_PATH} <<'SSH_VPN_TORRC'
{torrc}
SSH_VPN_TORRC
if [ -n "$tor_user" ]; then
  # Tor drops root after opening its ports and must own its data.
  echo "User $tor_user" >> {TOR_CONFIG_PATH}
  chown -R "$tor_user:" {TOR_DATA_DIR} {TOR_LOG_PATH}
fi

echo 'SSH_VPN_PROGRESS Starting Tor on the server'
if ! tor_output=$(tor -f {TOR_CONFIG_PATH} --defaults-torrc {TOR_DEFAULTS_PATH} 2>&1); then
  echo 'tor exited during startup' >&2
  printf '%s\\n' "$tor_output" | tail -n 15 >&2
  exit 1
fi
tor_pid=$(_ssh_vpn_gui_daemon_pids tor {TOR_CONFIG_PATH} | head -n 1)
bootstrapped=0
last_percent=""
for _ in $(seq 1 {TOR_BOOTSTRAP_WAIT_SECONDS}); do
  if [ -z "$tor_pid" ] || ! kill -0 "$tor_pid" 2>/dev/null; then
    echo 'tor exited while connecting to the Tor network' >&2
    tail -n 15 {TOR_LOG_PATH} 2>/dev/null >&2 || true
    exit 1
  fi
  percent=$(sed -n 's/.*Bootstrapped \\([0-9][0-9]*\\)%.*/\\1/p' {TOR_LOG_PATH} 2>/dev/null | tail -n 1)
  if [ "$percent" = 100 ]; then
    bootstrapped=1
    break
  fi
  if [ -n "$percent" ] && [ "$percent" != "$last_percent" ]; then
    echo "SSH_VPN_PROGRESS Connecting to the Tor network: $percent%"
    last_percent=$percent
  fi
  sleep 1
done
if [ "$bootstrapped" -ne 1 ]; then
  echo 'Tor did not connect to the Tor network in time' >&2
  tail -n 15 {TOR_LOG_PATH} 2>/dev/null >&2 || true
  exit 1
fi

{remote_cascade_redirect_snippet(tcp_port=TOR_TRANS_PORT, dns_port=TOR_DNS_PORT)}
cascade_ready=1
echo SSH_VPN_CASCADE_READY
""".strip()


def remote_socks5_bootstrap_script(proxy: Socks5Proxy, binding: TunnelBinding) -> str:
    # Both files carry the proxy password, so they travel base64-encoded
    # rather than as shell text.
    config_b64 = _b64(redsocks_config(proxy))
    check_b64 = _b64(_curl_proxy_config(proxy))
    check_urls = " ".join(SOCKS5_CHECK_URLS)
    install = remote_install_snippet(
        "redsocks",
        present=(
            "command -v redsocks >/dev/null 2>&1 && command -v curl >/dev/null 2>&1"
            " && command -v nft >/dev/null 2>&1"
        ),
        apt="redsocks curl nftables conntrack",
    )
    return f"""
set -eu
{remote_cascade_prologue(binding)}
redsocks_preinstalled=0
if command -v redsocks >/dev/null 2>&1; then
  redsocks_preinstalled=1
fi
{install}
if [ "$redsocks_preinstalled" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  # The distro unit would run a second redsocks for a proxy that does not exist.
  systemctl disable --now redsocks.service >/dev/null 2>&1 || true
fi

mkdir -p /etc/ssh-vpn-gui
umask 077
base64 -d > {SOCKS5_CHECK_CONFIG_PATH} <<'SSH_VPN_SOCKS5_CHECK_B64'
{check_b64}
SSH_VPN_SOCKS5_CHECK_B64
echo 'SSH_VPN_PROGRESS Checking the SOCKS5 proxy from the server'
exit_ip=""
check_error="no answer"
for url in {check_urls}; do
  if answer=$(curl -4 -sS --max-time 20 -K {SOCKS5_CHECK_CONFIG_PATH} "$url" 2>&1); then
    exit_ip=$(printf '%s\\n' "$answer" | head -n 1 | cut -c 1-64)
    break
  fi
  check_error=$answer
done
rm -f {SOCKS5_CHECK_CONFIG_PATH}
if [ -z "$exit_ip" ]; then
  echo "the SOCKS5 proxy does not work from the server: $check_error" >&2
  exit 1
fi
echo "SSH_VPN_PROGRESS The SOCKS5 proxy works, its exit IP is $exit_ip"

echo 'SSH_VPN_PROGRESS Clearing the previous second hop on the server'
_ssh_vpn_gui_stop_cascade
{remote_cascade_block_snippet()}

base64 -d > {REDSOCKS_CONFIG_PATH} <<'SSH_VPN_REDSOCKS_B64'
{config_b64}
SSH_VPN_REDSOCKS_B64
if ! id -u redsocks >/dev/null 2>&1; then
  sed -i '/^  user = /d; /^  group = /d' {REDSOCKS_CONFIG_PATH}
fi
: > {REDSOCKS_LOG_PATH}
echo 'SSH_VPN_PROGRESS Starting redsocks on the server'
if ! redsocks_output=$(redsocks -c {REDSOCKS_CONFIG_PATH} 2>&1); then
  echo 'redsocks exited during startup' >&2
  printf '%s\\n' "$redsocks_output" | tail -n 15 >&2
  exit 1
fi
# The DNS listener is opened after redsocks forks, so a busy port shows up
# only as a daemon that is gone.
listening=0
for _ in $(seq 1 40); do
  if ss -lun 2>/dev/null | grep -q '127.0.0.1:{REDSOCKS_DNS_PORT} ' \\
    && ss -ltn 2>/dev/null | grep -q '127.0.0.1:{REDSOCKS_PORT} '; then
    listening=1
    break
  fi
  sleep 0.25
done
if [ "$listening" -ne 1 ] || [ -z "$(_ssh_vpn_gui_daemon_pids redsocks {REDSOCKS_CONFIG_PATH})" ]; then
  echo 'redsocks did not start' >&2
  tail -n 15 {REDSOCKS_LOG_PATH} 2>/dev/null >&2 || true
  exit 1
fi

{remote_cascade_redirect_snippet(tcp_port=REDSOCKS_PORT, dns_port=REDSOCKS_DNS_PORT)}
cascade_ready=1
echo SSH_VPN_CASCADE_READY
""".strip()


def redsocks_config(proxy: Socks5Proxy) -> str:
    auth = ""
    if proxy.user:
        auth = (
            f'  login = "{_redsocks_string(proxy.user)}";\n'
            f'  password = "{_redsocks_string(proxy.password)}";\n'
        )
    return f"""base {{
  log_debug = off;
  log_info = off;
  log = "file:{REDSOCKS_LOG_PATH}";
  daemon = on;
  redirector = iptables;
  user = redsocks;
  group = redsocks;
}}

redsocks {{
  local_ip = 127.0.0.1;
  local_port = {REDSOCKS_PORT};
  ip = "{_redsocks_string(proxy.host)}";
  port = {proxy.port};
  type = socks5;
{auth}}}

dnstc {{
  local_ip = 127.0.0.1;
  local_port = {REDSOCKS_DNS_PORT};
}}
"""


def _redsocks_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _curl_proxy_config(proxy: Socks5Proxy) -> str:
    credentials = ""
    if proxy.user:
        credentials = f"{quote(proxy.user, safe='')}:{quote(proxy.password, safe='')}@"
    return f'proxy = "socks5h://{credentials}{proxy.host}:{proxy.port}"\n'


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")
