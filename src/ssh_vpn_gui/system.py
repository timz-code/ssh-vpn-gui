from __future__ import annotations

from dataclasses import dataclass, field, replace
import os
from pathlib import Path
import re
import shlex
import subprocess

STATE_DIR = Path("/run/ssh-vpn-gui")
DATA_DIR = Path("/var/lib/ssh-vpn-gui")
KNOWN_HOSTS = DATA_DIR / "known_hosts"
LOCAL_TUN = "tun3"
LOCAL_TUN_ADDRESS = "10.255.3.1"
REMOTE_TUN_ADDRESS = "10.255.3.2"
TUN_CIDR = "10.255.3.0/30"
PROXY_MARK = "2023"
PROXY_TABLE = "2023"
OLD_FORCED_ROUTES = ("0.0.0.0/1", "128.0.0.0/1")
# Every tun route gets a blackhole twin at this metric. When ssh exits the
# kernel deletes the tun with its routes, and the twin is what remains, so
# tunneled destinations never fall through to the WAN default route.
KILL_SWITCH_METRIC = "4095"
IPV6_GUARD_TABLE = "ssh_vpn_gui_v6"
IPV6_GUARD_CONFIG = STATE_DIR / "ipv6-guard.nft"
SINGBOX_PID = STATE_DIR / "sing-box.pid"

OVPN_DEV = "ovpn0"
# Traffic from the SSH /30 looks up this table on the server when a second
# hop (OpenVPN, Tor or a SOCKS5 proxy) is on.
CASCADE_TABLE = "2124"
# Looked up before CASCADE_TABLE so replies to the SSH tun peer do not
# follow the second hop and vanish inside it.
CASCADE_KEEP_TUN_PRIORITY = "2123"
CASCADE_NFT_TABLE = "ssh_vpn_gui_cascade"
CASCADE_INPUT_COMMENT = "ssh-vpn-gui-cascade"
TUNNEL_STATE = STATE_DIR / "tunnel.env"
FAIL_CLOSED_FLAG = STATE_DIR / "fail-closed"
OVPN_CONFIG_PATH = "/etc/ssh-vpn-gui/client.ovpn"
OVPN_PID_PATH = "/run/ssh-vpn-gui-ovpn.pid"
TOR_CONFIG_PATH = "/etc/ssh-vpn-gui/torrc"
REDSOCKS_CONFIG_PATH = "/etc/ssh-vpn-gui/redsocks.conf"
SOCKS5_CHECK_CONFIG_PATH = "/etc/ssh-vpn-gui/socks5-check.conf"
# A first install of the second hop's packages can sit on an apt lock or a
# slow mirror for minutes. This is the laptop wait for that SSH script, not
# a connect timeout of the hop. Cutting SSH first leaves a half-installed
# package manager and leftover daemons.
CASCADE_BOOTSTRAP_TIMEOUT_SECONDS = 600
CASCADE_HELPER_TIMEOUT_SECONDS = 660
APT_LOCK_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class TunnelBinding:
    local_tun: str
    remote_tun: str
    local_address: str
    remote_address: str
    cidr: str
    ovpn_dev: str = ""
    server: str = ""
    underlay_via: str = ""
    underlay_dev: str = ""

    @property
    def local_index(self) -> int:
        return _tun_index(self.local_tun)

    @property
    def remote_index(self) -> int:
        return _tun_index(self.remote_tun)


def _tun_index(name: str) -> int:
    match = re.fullmatch(r"tun(\d+)", name)
    if match is None:
        raise ValueError(f"invalid tun name {name!r}")
    return int(match.group(1))


def iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def next_free_tun(*, exclude: set[str] | None = None) -> str:
    taken = exclude or set()
    for index in range(256):
        name = f"tun{index}"
        if name not in taken and not iface_exists(name):
            return name
    raise RuntimeError("no free tun device (tun0-tun255 are all present)")


def local_ipv4_addresses() -> set[str]:
    try:
        completed = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return set()
    addresses: set[str] = set()
    for line in completed.stdout.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        inet = parts[parts.index("inet") + 1]
        addresses.add(inet.split("/")[0])
    return addresses


def next_free_p2p_net(*, exclude: set[str] | None = None) -> tuple[str, str, str]:
    used = local_ipv4_addresses()
    if exclude:
        used |= exclude
    for octet in range(3, 64):
        local = f"10.255.{octet}.1"
        remote = f"10.255.{octet}.2"
        if local not in used and remote not in used:
            return local, remote, f"10.255.{octet}.0/30"
    raise RuntimeError("no free 10.255.N.0/30 pair for the SSH tunnel")


def load_tunnel_state() -> TunnelBinding | None:
    if not TUNNEL_STATE.exists():
        return None
    try:
        values = dict(
            line.split("=", 1)
            for line in TUNNEL_STATE.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.startswith("#")
        )
        return TunnelBinding(
            local_tun=values["local_tun"],
            remote_tun=values["remote_tun"],
            local_address=values["local_address"],
            remote_address=values["remote_address"],
            cidr=values["cidr"],
            ovpn_dev=values.get("ovpn_dev", ""),
            server=values.get("server", ""),
            underlay_via=values.get("underlay_via", ""),
            underlay_dev=values.get("underlay_dev", ""),
        )
    except (OSError, KeyError, ValueError):
        return None


def save_tunnel_state(binding: TunnelBinding) -> None:
    ensure_state_dir()
    TUNNEL_STATE.write_text(
        (
            f"local_tun={binding.local_tun}\n"
            f"remote_tun={binding.remote_tun}\n"
            f"local_address={binding.local_address}\n"
            f"remote_address={binding.remote_address}\n"
            f"cidr={binding.cidr}\n"
            f"ovpn_dev={binding.ovpn_dev}\n"
            f"server={binding.server}\n"
            f"underlay_via={binding.underlay_via}\n"
            f"underlay_dev={binding.underlay_dev}\n"
        ),
        encoding="utf-8",
    )
    # The unprivileged GUI watchdog must be able to read this. The file
    # names the claimed tun, the 10.255.N.0/30 pair, and the SSH server
    # underlay pin — no secrets.
    TUNNEL_STATE.chmod(0o644)


def clear_tunnel_state() -> None:
    TUNNEL_STATE.unlink(missing_ok=True)


def is_fail_closed() -> bool:
    return FAIL_CLOSED_FLAG.exists()


def mark_fail_closed() -> None:
    ensure_state_dir()
    FAIL_CLOSED_FLAG.write_text("1\n", encoding="utf-8")
    try:
        FAIL_CLOSED_FLAG.chmod(0o644)
    except OSError:
        pass


def clear_fail_closed() -> None:
    FAIL_CLOSED_FLAG.unlink(missing_ok=True)


def routing_binding() -> TunnelBinding:
    return load_tunnel_state() or TunnelBinding(
        local_tun=LOCAL_TUN,
        remote_tun=LOCAL_TUN,
        local_address=LOCAL_TUN_ADDRESS,
        remote_address=REMOTE_TUN_ADDRESS,
        cidr=TUN_CIDR,
        ovpn_dev=OVPN_DEV,
    )


def parse_remote_allocation(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    used: list[str] = []
    for line in output.splitlines():
        if line.startswith("SSH_VPN_REMOTE_TUN "):
            result["remote_tun"] = line.split()[1]
        elif line.startswith("SSH_VPN_REMOTE_OVPN "):
            result["ovpn_dev"] = line.split()[1]
        elif line.startswith("SSH_VPN_USED"):
            used.extend(line.split()[1:])
        elif line.startswith("SSH_VPN_ADDR "):
            parts = line.split()
            if len(parts) >= 4:
                result["local_address"] = parts[1]
                result["remote_address"] = parts[2]
                result["cidr"] = parts[3]
    if used:
        result["used"] = " ".join(used)
    return result


def allocate_tunnel_binding(output: str, *, local_tun: str | None = None) -> TunnelBinding:
    parsed = parse_remote_allocation(output)
    remote_tun = parsed.get("remote_tun")
    if not remote_tun:
        raise RuntimeError("remote bootstrap did not allocate a tun device")
    used = set((parsed.get("used") or "").split())
    used |= local_ipv4_addresses()
    suggested_local = parsed.get("local_address")
    suggested_remote = parsed.get("remote_address")
    suggested_cidr = parsed.get("cidr")
    if (
        suggested_local
        and suggested_remote
        and suggested_cidr
        and suggested_local not in used
        and suggested_remote not in used
    ):
        local_address, remote_address, cidr = suggested_local, suggested_remote, suggested_cidr
    else:
        local_address, remote_address, cidr = next_free_p2p_net(exclude=used)
    return TunnelBinding(
        local_tun=local_tun or next_free_tun(),
        remote_tun=remote_tun,
        local_address=local_address,
        remote_address=remote_address,
        cidr=cidr,
        ovpn_dev=parsed.get("ovpn_dev", ""),
    )


def placeholder_tunnel_binding() -> TunnelBinding:
    local_tun = next_free_tun()
    local_address, remote_address, cidr = next_free_p2p_net()
    return TunnelBinding(
        local_tun=local_tun,
        remote_tun=local_tun,
        local_address=local_address,
        remote_address=remote_address,
        cidr=cidr,
    )


def update_tunnel_ovpn(ovpn_dev: str) -> None:
    binding = load_tunnel_state()
    if binding is None:
        return
    save_tunnel_state(replace(binding, ovpn_dev=ovpn_dev))


@dataclass
class CommandRunner:
    dry_run: bool = False
    commands: list[str] = field(default_factory=list)

    def run(
        self, command: list[str], *, check: bool = True, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str] | None:
        self.commands.append(" ".join(command))
        if input_text:
            self.commands.extend(input_text.splitlines())
        if self.dry_run:
            return None
        completed = subprocess.run(command, check=False, text=True, capture_output=True, input=input_text)
        if check and completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"{' '.join(command)} failed: {detail or completed.returncode}")
        return completed

    def run_shell(self, command: str, *, check: bool = True) -> subprocess.CompletedProcess[str] | None:
        self.commands.append(command)
        if self.dry_run:
            return None
        completed = subprocess.run(["sh", "-c", command], check=False, text=True, capture_output=True)
        if check and completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"{command} failed: {detail or completed.returncode}")
        return completed

    def write_file(self, path: Path, content: str) -> None:
        self.commands.append(f"write {path}")
        if self.dry_run:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("This command must run as root. Start it through pkexec or sudo.")


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        STATE_DIR.chmod(0o755)
    except OSError:
        pass


def discover_local_binding() -> TunnelBinding | None:
    """Recover the claimed local tun if tunnel.env is missing or unreadable."""
    try:
        completed = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or "inet" not in parts:
            continue
        iface = parts[1].rstrip(":")
        if not re.fullmatch(r"tun\d+", iface):
            continue
        inet = parts[parts.index("inet") + 1].split("/")[0]
        match = re.fullmatch(r"10\.255\.(\d+)\.1", inet)
        if match is None:
            continue
        octet = match.group(1)
        return TunnelBinding(
            local_tun=iface,
            remote_tun="",
            local_address=inet,
            remote_address=f"10.255.{octet}.2",
            cidr=f"10.255.{octet}.0/30",
        )
    return None


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def setup_local_tun(runner: CommandRunner) -> None:
    binding = routing_binding()
    if not runner.dry_run:
        ensure_state_dir()
    runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    runner.run(["ip", "addr", "flush", "dev", binding.local_tun], check=False)
    runner.run(
        [
            "ip",
            "addr",
            "add",
            binding.local_address,
            "peer",
            binding.remote_address,
            "dev",
            binding.local_tun,
        ],
        check=False,
    )
    runner.run(["ip", "link", "set", binding.local_tun, "up"])


def ensure_proxy_rule(runner: CommandRunner) -> None:
    add = ["ip", "rule", "add", "fwmark", PROXY_MARK, "table", PROXY_TABLE, "priority", PROXY_TABLE]
    if runner.dry_run:
        runner.run(add, check=False)
        return
    count = _proxy_rule_count(runner)
    if count == 0:
        runner.run(add, check=False)
    for _ in range(count - 1):
        runner.run(["ip", "rule", "del", "fwmark", PROXY_MARK, "table", PROXY_TABLE], check=False)


def delete_proxy_rules(runner: CommandRunner) -> None:
    delete = ["ip", "rule", "del", "fwmark", PROXY_MARK, "table", PROXY_TABLE]
    if runner.dry_run:
        runner.run(delete, check=False)
        return
    for _ in range(max(1, _proxy_rule_count(runner))):
        runner.run(delete, check=False)


def _proxy_rule_count(runner: CommandRunner) -> int:
    listing = runner.run(["ip", "-4", "rule", "show"], check=False)
    if listing is None or listing.returncode != 0:
        return 0
    mark = f"fwmark {int(PROXY_MARK):#x}"
    lookup = f"lookup {PROXY_TABLE}"
    return sum(1 for line in listing.stdout.splitlines() if mark in line and lookup in line)


def setup_full_tunnel_routes(runner: CommandRunner) -> None:
    binding = routing_binding()
    ipv6_guard_up(runner)
    for route in OLD_FORCED_ROUTES:
        runner.run(
            ["ip", "route", "replace", route, "dev", binding.local_tun, "src", binding.local_address]
        )
        runner.run(["ip", "route", "replace", "blackhole", route, "metric", KILL_SWITCH_METRIC])


def remove_full_tunnel_routes(runner: CommandRunner) -> None:
    for route in OLD_FORCED_ROUTES:
        runner.run(["ip", "route", "del", "blackhole", route, "metric", KILL_SWITCH_METRIC], check=False)
        runner.run(["ip", "route", "del", route], check=False)


def ipv6_guard_up(runner: CommandRunner, *, check: bool = True) -> None:
    runner.write_file(IPV6_GUARD_CONFIG, _ipv6_guard_config())
    runner.run(["nft", "-f", str(IPV6_GUARD_CONFIG)], check=check)


def ipv6_guard_down(runner: CommandRunner) -> None:
    runner.run(["nft", "delete", "table", "inet", IPV6_GUARD_TABLE], check=False)


def _ipv6_guard_config() -> str:
    # The tunnel is IPv4-only: any IPv6 that leaves goes around it.
    return f"""
add table inet {IPV6_GUARD_TABLE}
delete table inet {IPV6_GUARD_TABLE}
table inet {IPV6_GUARD_TABLE} {{
  chain reject6_output {{
    type filter hook output priority filter; policy accept;
    meta l4proto icmpv6 accept;
    ip6 daddr ::1 accept;
    meta nfproto ipv6 reject;
  }}
}}
""".strip() + "\n"


def underlay_ips(*extra: str) -> set[str]:
    ips: set[str] = set()
    state = load_tunnel_state()
    if state and state.server:
        ips.add(state.server)
    for item in extra:
        if item:
            ips.add(item)
    return ips


def _route_via_dev(stdout: str) -> tuple[str, str]:
    words = stdout.split()
    via = words[words.index("via") + 1] if "via" in words else ""
    dev = words[words.index("dev") + 1] if "dev" in words else ""
    return via, dev


def _lookup_underlay(
    runner: CommandRunner, server: str, avoid_dev: str, *, route_get: bool = True
) -> tuple[str, str]:
    if route_get:
        # Fails with EINVAL when only a kill-switch blackhole matches.
        route = runner.run(["ip", "route", "get", server], check=False)
        if route is not None and route.returncode == 0:
            via, dev = _route_via_dev(route.stdout)
            if dev and dev != avoid_dev:
                return via, dev
    default = runner.run(["ip", "-4", "route", "show", "default"], check=False)
    if default is None or default.returncode != 0:
        return "", ""
    via, dev = _route_via_dev(default.stdout)
    if dev == avoid_dev:
        return "", ""
    return via, dev


def preserve_server_route(runner: CommandRunner, server: str, *, refresh: bool = False) -> None:
    """Pin the SSH server to the WAN.

    refresh=True re-reads the main default route instead of trusting the
    saved pin, so a reconnect after a network change does not dial out
    through a dead gateway. It never raises: it runs while traffic is
    blocked and must not abort the block.
    """
    if not server:
        return
    state = load_tunnel_state()
    avoid_dev = state.local_tun if state else ""
    via = state.underlay_via if state and not refresh else ""
    dev = state.underlay_dev if state and not refresh else ""
    if dev == avoid_dev:
        via, dev = "", ""
    if runner.dry_run:
        runner.commands.append("ip -4 route show default" if refresh else f"ip route get {server}")
        runner.commands.append(
            f"ip route replace {server}/32 via {via or '<gw>'} dev {dev or '<underlay>'}"
        )
        return

    if not via and not dev:
        via, dev = _lookup_underlay(runner, server, avoid_dev, route_get=not refresh)
        if state and (via or dev):
            save_tunnel_state(replace(state, server=server, underlay_via=via, underlay_dev=dev))
    command = ["ip", "route", "replace", f"{server}/32"]
    if via:
        command.extend(["via", via])
    if dev:
        command.extend(["dev", dev])
    if len(command) == 4:
        return
    runner.run(command, check=not refresh)


def cleanup_local_tun(runner: CommandRunner, server: str | None = None) -> None:
    if server:
        runner.run(["ip", "route", "del", f"{server}/32"], check=False)
    for name in _local_tuns_to_reap():
        cleanup_tun_routes(runner, name)
        runner.run(["ip", "addr", "flush", "dev", name], check=False)
        runner.run(["ip", "link", "set", name, "down"], check=False)
    if not runner.dry_run:
        clear_tunnel_state()


def _local_tuns_to_reap() -> list[str]:
    names: list[str] = []
    state = load_tunnel_state()
    if state:
        names.append(state.local_tun)
    names.extend(_tuns_holding_app_p2p())
    seen: set[str] = set()
    unique: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


def _tuns_holding_app_p2p() -> list[str]:
    try:
        completed = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return []
    found: list[str] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or "inet" not in parts:
            continue
        iface = parts[1].rstrip(":")
        if not re.fullmatch(r"tun\d+", iface):
            continue
        inet = parts[parts.index("inet") + 1].split("/")[0]
        if re.fullmatch(r"10\.255\.\d+\.1", inet):
            found.append(iface)
    return found


def cleanup_tun_routes(runner: CommandRunner, tun: str | None = None) -> None:
    name = tun
    if name is None:
        state = load_tunnel_state()
        name = state.local_tun if state else None
    if name is None:
        if runner.dry_run:
            runner.commands.append("delete routes using claimed tuns")
        return
    if runner.dry_run:
        runner.commands.append(f"delete routes using {name}")
        return
    routes = runner.run(["ip", "-4", "route", "show", "dev", name], check=False)
    if routes is None:
        return
    for line in routes.stdout.splitlines():
        words = line.split()
        if words:
            runner.run(["ip", "route", "del", words[0]], check=False)


def cleanup_legacy_singbox(runner: CommandRunner) -> None:
    if SINGBOX_PID.exists() and not runner.dry_run:
        pid = SINGBOX_PID.read_text(encoding="utf-8").strip()
        runner.run(["kill", "-TERM", pid], check=False)
        SINGBOX_PID.unlink(missing_ok=True)
    runner.run(["pkill", "-f", "sing-box run -c /run/ssh-vpn-gui/sing-box.json"], check=False)


def remote_bootstrap_script() -> str:
    return """
set -eu
changed=0

__SSH_VPN_CASCADE_STOP__

if command -v modprobe >/dev/null 2>&1; then
  modprobe tun 2>/dev/null || true
fi
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200 2>/dev/null || true
  chmod 666 /dev/net/tun 2>/dev/null || true
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null
if [ -w /etc/sysctl.conf ] && ! grep -Eq '^net[.]ipv4[.]ip_forward[[:space:]]*=[[:space:]]*1' /etc/sysctl.conf; then
  printf '\\n# Managed by ssh-vpn-gui\\nnet.ipv4.ip_forward=1\\n' >> /etc/sysctl.conf
fi

sshd_config_dir=/etc/ssh/sshd_config.d
sshd_config_file=$sshd_config_dir/99-ssh-vpn-gui.conf
if [ -d "$sshd_config_dir" ]; then
  desired='PermitTunnel point-to-point
PermitRootLogin yes
PasswordAuthentication yes
'
  if ! printf '%s' "$desired" | cmp -s "$sshd_config_file" -; then
    printf '%s' "$desired" > "$sshd_config_file"
    changed=1
  fi
elif ! grep -Eq '^[[:space:]]*PermitTunnel[[:space:]]+(yes|point-to-point)' /etc/ssh/sshd_config; then
  printf '\\n# Managed by ssh-vpn-gui\\nPermitTunnel point-to-point\\nPermitRootLogin yes\\nPasswordAuthentication yes\\n' >> /etc/ssh/sshd_config
  changed=1
fi

if [ "$changed" -eq 1 ]; then
  sshd -t
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh
  else
    service ssh reload 2>/dev/null || service sshd reload
  fi
fi

sshd -T 2>/dev/null | grep -qi '^permittunnel \\(yes\\|point-to-point\\)' || {
  echo 'PermitTunnel is still disabled after bootstrap' >&2
  exit 1
}
remote_tun=""
for i in $(seq 0 255); do
  if [ ! -e /sys/class/net/tun$i ]; then
    remote_tun=tun$i
    break
  fi
done
[ -n "$remote_tun" ] || {
  echo 'no free tun device on the remote server' >&2
  exit 1
}
echo SSH_VPN_REMOTE_TUN $remote_tun
used=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\\n' ' ')
echo SSH_VPN_USED $used
addr_set=0
for n in $(seq 3 63); do
  a=10.255.$n.1
  b=10.255.$n.2
  case " $used " in
    *" $a "*|*" $b "*) continue ;;
  esac
  echo SSH_VPN_ADDR $a $b 10.255.$n.0/30
  addr_set=1
  break
done
[ "$addr_set" -eq 1 ] || {
  echo 'no free 10.255.N.0/30 pair on the remote server' >&2
  exit 1
}
echo SSH_VPN_BOOTSTRAP_READY
""".replace("__SSH_VPN_CASCADE_STOP__", _remote_cascade_stop_snippet()).strip()


def remote_rp_filter_snippet() -> str:
    return """
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# IPv4 forward is AND(all, ingress-iface) on current kernels.
# systemd-networkd / cloud-init set enp*.forwarding=0 after boot, so
# tun->WAN is forwarded and WAN->tun is dropped. That is exactly
# outbound FORWARD hits and zero -o tun.
sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.forwarding=1 >/dev/null 2>&1 || true
for fw in /proc/sys/net/ipv4/conf/*/forwarding; do
  printf '1\\n' > "$fw" 2>/dev/null || true
done
# Linux applies max(all, iface). Clearing only 'all' leaves eth0=1 and
# drops masqueraded replies on cloud images that ship strict rp_filter.
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
for rp in /proc/sys/net/ipv4/conf/*/rp_filter; do
  printf '0\\n' > "$rp" 2>/dev/null || true
done
""".strip()


def _remote_forward_accept_snippet(tun: str, cidr: str) -> str:
    return f"""
# ufw and many VPS images DROP FORWARD. NAT never sees the packets.
if command -v nft >/dev/null 2>&1; then
  nft add table ip ssh_vpn_gui 2>/dev/null || true
  nft 'add chain ip ssh_vpn_gui forward {{ type filter hook forward priority -5; policy accept; }}' 2>/dev/null || true
  nft add rule ip ssh_vpn_gui forward iifname "{tun}" accept 2>/dev/null || true
  nft add rule ip ssh_vpn_gui forward oifname "{tun}" accept 2>/dev/null || true
fi
if command -v iptables >/dev/null 2>&1; then
  iptables -C FORWARD -i {tun} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i {tun} -j ACCEPT
  iptables -C FORWARD -o {tun} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o {tun} -j ACCEPT
  iptables -C FORWARD -s {cidr} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s {cidr} -j ACCEPT
fi
""".strip()


def _remote_nat_snippet(tun: str, cidr: str) -> str:
    return f"""
modprobe nf_conntrack 2>/dev/null || true
modprobe nf_nat 2>/dev/null || true
modprobe xt_MASQUERADE 2>/dev/null || true
modprobe iptable_nat 2>/dev/null || true
{_remote_nat_cleanup_snippet(tun, cidr)}
# MASQUERADE follows the egress iface. Frozen SNAT to the VPS WAN IP
# breaks cascade: policy-routed packets leave ovpn with src=public.
nat_ok=0
if command -v nft >/dev/null 2>&1; then
  nft add table ip ssh_vpn_gui 2>/dev/null || true
  nft 'add chain ip ssh_vpn_gui postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}' 2>/dev/null || true
  nft add rule ip ssh_vpn_gui postrouting ip saddr {cidr} oifname != "{tun}" masquerade 2>/dev/null || true
  if nft list chain ip ssh_vpn_gui postrouting 2>/dev/null | grep -q masquerade; then
    nat_ok=1
  fi
fi
if command -v iptables >/dev/null 2>&1; then
  iptables -t nat -C POSTROUTING -s {cidr} ! -o {tun} -j MASQUERADE 2>/dev/null || \\
    iptables -t nat -A POSTROUTING -s {cidr} ! -o {tun} -j MASQUERADE
  if iptables -t nat -C POSTROUTING -s {cidr} ! -o {tun} -j MASQUERADE 2>/dev/null; then
    nat_ok=1
  fi
fi
if [ "$nat_ok" -ne 1 ]; then
  echo 'failed to install MASQUERADE for the SSH tun' >&2
  exit 1
fi
wan_if=$(ip -4 route show default | awk '{{print $5; exit}}')
echo SSH_VPN_NAT masquerade "$wan_if"
""".strip()


def _remote_nat_cleanup_snippet(tun: str, cidr: str) -> str:
    _ = tun
    return f"""
if command -v iptables >/dev/null 2>&1; then
  iptables -t nat -S POSTROUTING 2>/dev/null | sed -n 's/^-A POSTROUTING //p' | while read -r spec; do
    case "$spec" in
      *"-s {cidr}"*) iptables -t nat -D POSTROUTING $spec 2>/dev/null || true ;;
    esac
  done
fi
""".strip()


def _remote_forward_cleanup_snippet(binding: TunnelBinding | None) -> str:
    if binding is None:
        return "iptables -D FORWARD -s 10.255.0.0/16 -j ACCEPT 2>/dev/null || true"
    return (
        f"iptables -D FORWARD -i {binding.remote_tun} -j ACCEPT 2>/dev/null || true; "
        f"iptables -D FORWARD -o {binding.remote_tun} -j ACCEPT 2>/dev/null || true; "
        f"iptables -D FORWARD -s {binding.cidr} -j ACCEPT 2>/dev/null || true"
    )


def remote_setup_script(binding: TunnelBinding | None = None) -> str:
    chosen = binding or routing_binding()
    return f"""
set -eu
ip addr flush dev {chosen.remote_tun} || true
ip addr add {chosen.remote_address} peer {chosen.local_address} dev {chosen.remote_tun} || true
ip link set {chosen.remote_tun} up
{remote_rp_filter_snippet()}
sysctl -w net.ipv4.conf.{chosen.remote_tun}.rp_filter=0 >/dev/null 2>&1 || true
# A Tor or SOCKS5 second hop, set up before this tun existed, redirects
# its traffic to 127.0.0.1.
if nft list table ip {CASCADE_NFT_TABLE} >/dev/null 2>&1; then
  sysctl -w net.ipv4.conf.{chosen.remote_tun}.route_localnet=1 >/dev/null 2>&1 || true
fi
{_remote_nat_snippet(chosen.remote_tun, chosen.cidr)}
{_remote_forward_accept_snippet(chosen.remote_tun, chosen.cidr)}
ip rule add from {chosen.cidr} to {chosen.cidr} table main priority {CASCADE_KEEP_TUN_PRIORITY} 2>/dev/null || true
ip route replace {chosen.cidr} dev {chosen.remote_tun} table {CASCADE_TABLE} 2>/dev/null || true
echo SSH_VPN_READY
trap '{_remote_nat_cleanup_snippet(chosen.remote_tun, chosen.cidr)}; {_remote_forward_cleanup_snippet(chosen)}; nft delete table ip ssh_vpn_gui 2>/dev/null || true; ip addr flush dev {chosen.remote_tun} 2>/dev/null || true' EXIT
while true; do sleep 3600; done
""".strip()


def _remote_tun_cleanup_snippet(binding: TunnelBinding | None) -> str:
    known = ""
    if binding is not None:
        known = (
            f"ip addr flush dev {binding.remote_tun} 2>/dev/null || true\n"
            f"ip link set {binding.remote_tun} down 2>/dev/null || true\n"
        )
    return f"""
{known}
for iface in /sys/class/net/tun*; do
  [ -e "$iface" ] || continue
  name=${{iface##*/}}
  if ip -4 addr show dev "$name" 2>/dev/null | grep -qE 'inet 10\\.255\\.[0-9]+\\.2[ /]'; then
    ip addr flush dev "$name" 2>/dev/null || true
    ip link set "$name" down 2>/dev/null || true
  fi
done
""".strip()


def remote_cleanup_command(binding: TunnelBinding | None = None) -> str:
    chosen = binding or load_tunnel_state()
    if chosen:
        nat_cleanup = _remote_nat_cleanup_snippet(chosen.remote_tun, chosen.cidr)
    else:
        nat_cleanup = _remote_nat_cleanup_snippet("tun+", "10.255.")
    return f"""
set -eu
nft delete table ip ssh_vpn_gui 2>/dev/null || true
{nat_cleanup}
{_remote_forward_cleanup_snippet(chosen)}
{_remote_tun_cleanup_snippet(chosen)}
{_remote_cascade_stop_snippet(cidr=chosen.cidr if chosen else None, tun=chosen.remote_tun if chosen else None)}
""".strip()


def _remote_cascade_stop_snippet(*, cidr: str | None = None, tun: str | None = None) -> str:
    return f"{_remote_cascade_pid_helpers()}\n{_remote_cascade_stop_commands(cidr=cidr, tun=tun)}"


def _remote_cascade_pid_helpers() -> str:
    return f"""
# Ours only: match the process name and our config path in its command
# line. Do not pgrep -f the path — the SSH bash -lc script text contains
# it and would die.
_ssh_vpn_gui_ovpn_pids() {{
  for proc in /proc/[0-9]*; do
    [ -r "$proc/comm" ] && [ -r "$proc/cmdline" ] || continue
    comm=$(cat "$proc/comm" 2>/dev/null || true)
    case "$comm" in
      openvpn|ssh-vpn-gui-ovpn) ;;
      *) continue ;;
    esac
    cmd=$(tr '\\0' ' ' < "$proc/cmdline" 2>/dev/null || true)
    case "$cmd" in
      *"{OVPN_CONFIG_PATH}"*)
        printf '%s\\n' "${{proc#/proc/}}"
        ;;
    esac
  done | sort -u
}}
_ssh_vpn_gui_daemon_pids() {{
  for proc in /proc/[0-9]*; do
    read -r comm 2>/dev/null < "$proc/comm" || continue
    [ "$comm" = "$1" ] || continue
    cmd=$(tr '\\0' ' ' < "$proc/cmdline" 2>/dev/null || true)
    case "$cmd" in
      *"$2"*) printf '%s\\n' "${{proc#/proc/}}" ;;
    esac
  done
}}
""".strip()


def _remote_cascade_stop_commands(*, cidr: str | None = None, tun: str | None = None) -> str:
    """Stop every second hop on the server, whichever kind is running."""
    tracked = cidr or "10.255.0.0/16"
    localnet = f"sysctl -w net.ipv4.conf.{tun}.route_localnet=0 >/dev/null 2>&1 || true\n" if tun else ""
    return f"""
while ip rule del priority {CASCADE_KEEP_TUN_PRIORITY} 2>/dev/null; do :; done
while ip rule del table {CASCADE_TABLE} 2>/dev/null; do :; done
ip route flush table {CASCADE_TABLE} 2>/dev/null || true
nft delete table ip {CASCADE_NFT_TABLE} 2>/dev/null || true
if command -v iptables >/dev/null 2>&1; then
  iptables -S INPUT 2>/dev/null | sed -n 's/^-A INPUT //p' | while read -r spec; do
    case "$spec" in
      *"--comment {CASCADE_INPUT_COMMENT}"*) iptables -D INPUT $spec 2>/dev/null || true ;;
    esac
  done
fi
{localnet}if command -v conntrack >/dev/null 2>&1; then
  conntrack -D -s {tracked} >/dev/null 2>&1 || true
fi
leftovers=$(_ssh_vpn_gui_ovpn_pids)
n=0
if [ -n "$leftovers" ]; then
  n=$(printf '%s\\n' "$leftovers" | wc -l)
fi
echo "SSH_VPN_OVPN_LEFTOVERS $n"
ovpn_ifaces=""
for ovpn_pid in $leftovers; do
  cmd=$(tr '\\0' ' ' < "/proc/$ovpn_pid/cmdline" 2>/dev/null || true)
  set -- $cmd
  while [ $# -gt 1 ]; do
    if [ "$1" = --dev ]; then
      ovpn_ifaces="$ovpn_ifaces $2"
    fi
    shift
  done
done
for _sig in TERM KILL; do
  for _ in $(seq 1 30); do
    left=$(_ssh_vpn_gui_ovpn_pids)
    [ -z "$left" ] && break 2
    for ovpn_pid in $left; do
      kill -"$_sig" "$ovpn_pid" 2>/dev/null || true
    done
    sleep 0.1
  done
done
rm -f {OVPN_PID_PATH}
for ovpn_dev in $ovpn_ifaces; do
  ip addr flush dev "$ovpn_dev" 2>/dev/null || true
  ip link set "$ovpn_dev" down 2>/dev/null || true
  ip link del "$ovpn_dev" 2>/dev/null || true
done
for daemon in tor:{TOR_CONFIG_PATH} redsocks:{REDSOCKS_CONFIG_PATH}; do
  for _sig in TERM KILL; do
    for _ in $(seq 1 30); do
      left=$(_ssh_vpn_gui_daemon_pids "${{daemon%%:*}}" "${{daemon#*:}}")
      [ -z "$left" ] && break 2
      for daemon_pid in $left; do
        kill -"$_sig" "$daemon_pid" 2>/dev/null || true
      done
      sleep 0.1
    done
  done
done
rm -f {REDSOCKS_CONFIG_PATH} {SOCKS5_CHECK_CONFIG_PATH}
""".strip()


def remote_cascade_cleanup_command(binding: TunnelBinding | None = None) -> str:
    chosen = binding or load_tunnel_state()
    return f"""
set -eu
{_remote_cascade_stop_snippet(cidr=chosen.cidr if chosen else None, tun=chosen.remote_tun if chosen else None)}
echo SSH_VPN_CASCADE_STOPPED
""".strip()


def remote_cascade_prologue(binding: TunnelBinding) -> str:
    """Header of a second-hop bootstrap script.

    From here on any failure stops every second hop, so the server ends up
    with none rather than with a half-started one or the previous one.
    """
    return f"""
cidr='{binding.cidr}'
ssh_tun='{binding.remote_tun}'
{_remote_cascade_pid_helpers()}
_ssh_vpn_gui_stop_cascade() {{
{_remote_cascade_stop_commands(cidr=binding.cidr, tun=binding.remote_tun)}
}}
cascade_ready=0
trap '[ "$cascade_ready" -eq 1 ] || _ssh_vpn_gui_stop_cascade >/dev/null 2>&1' EXIT
""".strip()


def remote_install_snippet(label: str, *, present: str, apt: str, dnf: str | None = None) -> str:
    if dnf:
        other_managers = f"""  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y {dnf}
  elif command -v yum >/dev/null 2>&1; then
    yum install -y {dnf}
"""
        unsupported = f"no supported package manager found to install {label}"
    else:
        other_managers = ""
        unsupported = f"{label} can only be installed automatically on Debian or Ubuntu"
    return f"""
if ! {{ {present}; }}; then
  echo 'SSH_VPN_INSTALLING {label}'
  echo 'SSH_VPN_PROGRESS Installing {label} on the server'
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    (
      apt-get -o DPkg::Lock::Timeout={APT_LOCK_TIMEOUT_SECONDS} update || true
      apt-get -o DPkg::Lock::Timeout={APT_LOCK_TIMEOUT_SECONDS} install -y {apt}
    ) &
    _apt_pid=$!
    while kill -0 "$_apt_pid" 2>/dev/null; do
      echo 'SSH_VPN_PROGRESS Installing {label} on the server'
      sleep 8
    done
    wait "$_apt_pid"
{other_managers}  else
    echo '{unsupported}' >&2
    exit 1
  fi
fi
""".strip()


def remote_cascade_block_snippet() -> str:
    return f"""
# While the second hop starts, and after it dies, traffic from the SSH /30
# that the hop does not carry is unreachable instead of leaving through the
# server's own address.
ip route replace unreachable default table {CASCADE_TABLE} metric {KILL_SWITCH_METRIC}
ip rule add from "$cidr" to "$cidr" table main priority {CASCADE_KEEP_TUN_PRIORITY} 2>/dev/null || true
ip route replace "$cidr" dev "$ssh_tun" table {CASCADE_TABLE} 2>/dev/null || true
ip rule add from "$cidr" table {CASCADE_TABLE} priority {CASCADE_TABLE} 2>/dev/null || true
""".strip()


def remote_cascade_redirect_snippet(*, tcp_port: int, dns_port: int) -> str:
    return f"""
nft -f - <<SSH_VPN_CASCADE_NFT
table ip {CASCADE_NFT_TABLE} {{
  chain prerouting {{
    type nat hook prerouting priority -100; policy accept;
    iifname "$ssh_tun" ip daddr $cidr return
    iifname "$ssh_tun" udp dport 53 dnat to 127.0.0.1:{dns_port}
    iifname "$ssh_tun" ip protocol tcp dnat to 127.0.0.1:{tcp_port}
  }}
}}
SSH_VPN_CASCADE_NFT
# The kernel drops packets for 127.0.0.1 that arrive on another interface
# unless route_localnet is on there. Before connect, the tun does not exist
# yet; the SSH session sets this when it creates it.
sysctl -w "net.ipv4.conf.$ssh_tun.route_localnet=1" >/dev/null 2>&1 || true
# ufw and many VPS images DROP INPUT, and redirected connections are local.
if command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -i "$ssh_tun" -m conntrack --ctstate DNAT -m comment --comment {CASCADE_INPUT_COMMENT} -j ACCEPT 2>/dev/null || \\
    iptables -I INPUT 1 -i "$ssh_tun" -m conntrack --ctstate DNAT -m comment --comment {CASCADE_INPUT_COMMENT} -j ACCEPT 2>/dev/null || true
fi
""".strip()
