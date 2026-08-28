from __future__ import annotations

from dataclasses import dataclass, field
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
SINGBOX_PID = STATE_DIR / "sing-box.pid"

OVPN_DEV = "ovpn0"
OVPN_TABLE = "2124"
TUNNEL_STATE = STATE_DIR / "tunnel.env"
OVPN_CONFIG_PATH = "/etc/ssh-vpn-gui/client.ovpn"
OVPN_PID_PATH = "/run/ssh-vpn-gui-ovpn.pid"
OVPN_LOG_PATH = "/var/log/ssh-vpn-gui-ovpn.log"
OVPN_INTERFACE_WAIT_SECONDS = 90
OVPN_CONNECT_TIMEOUT_SECONDS = 8
# First apt/dnf/yum of openvpn+conntrack can sit on a lock or a slow
# mirror for minutes. This is the laptop wait for that SSH script — not
# an OpenVPN connect timeout. Cutting SSH first leaves a half-installed
# package manager and leftover clients.
OVPN_BOOTSTRAP_TIMEOUT_SECONDS = 600
OVPN_HELPER_TIMEOUT_SECONDS = 660
OVPN_APT_LOCK_TIMEOUT_SECONDS = 300
OVPN_CONNECT_FAIL_PATTERN = (
    r"AUTH_FAILED|TLS Error|TLS handshake failed|Cannot resolve host address|"
    r"RESOLVE:|Name or service not known|Connection refused|Options error|"
    r"Exiting due to fatal error|TCP: connect to .* failed"
)


@dataclass(frozen=True)
class TunnelBinding:
    local_tun: str
    remote_tun: str
    local_address: str
    remote_address: str
    cidr: str
    ovpn_dev: str = ""

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
        ),
        encoding="utf-8",
    )
    # The unprivileged GUI watchdog must be able to read this. The file
    # only names the claimed tun and the 10.255.N.0/30 pair — no secrets.
    TUNNEL_STATE.chmod(0o644)


def clear_tunnel_state() -> None:
    TUNNEL_STATE.unlink(missing_ok=True)


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
    save_tunnel_state(
        TunnelBinding(
            local_tun=binding.local_tun,
            remote_tun=binding.remote_tun,
            local_address=binding.local_address,
            remote_address=binding.remote_address,
            cidr=binding.cidr,
            ovpn_dev=ovpn_dev,
        )
    )


@dataclass
class CommandRunner:
    dry_run: bool = False
    commands: list[str] = field(default_factory=list)

    def run(self, command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str] | None:
        self.commands.append(" ".join(command))
        if self.dry_run:
            return None
        completed = subprocess.run(command, check=False, text=True, capture_output=True)
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


def setup_proxy_routes(runner: CommandRunner) -> None:
    cleanup_proxy_routes(runner)
    binding = routing_binding()
    runner.run(
        [
            "ip",
            "route",
            "replace",
            "default",
            "dev",
            binding.local_tun,
            "src",
            binding.local_address,
            "table",
            PROXY_TABLE,
        ]
    )
    runner.run(["ip", "rule", "add", "fwmark", PROXY_MARK, "table", PROXY_TABLE, "priority", PROXY_TABLE])


def cleanup_proxy_routes(runner: CommandRunner) -> None:
    runner.run(["ip", "rule", "del", "fwmark", PROXY_MARK, "table", PROXY_TABLE], check=False)
    runner.run(["ip", "route", "flush", "table", PROXY_TABLE], check=False)
    for route in OLD_FORCED_ROUTES:
        runner.run(["ip", "route", "del", route], check=False)
    cleanup_tun_routes(runner)


def setup_full_tunnel_routes(runner: CommandRunner, *, cleanup_first: bool = True) -> None:
    if cleanup_first:
        cleanup_proxy_routes(runner)
    for route in OLD_FORCED_ROUTES:
        binding = routing_binding()
        runner.run(
            ["ip", "route", "replace", route, "dev", binding.local_tun, "src", binding.local_address]
        )


def preserve_server_route(runner: CommandRunner, server: str) -> None:
    if runner.dry_run:
        runner.commands.append(f"ip route get {server}")
        runner.commands.append(f"ip route replace {server}/32 dev <current-default-interface>")
        return

    route = runner.run(["ip", "route", "get", server])
    if route is None:
        return
    route_words = route.stdout.split()
    command = ["ip", "route", "replace", f"{server}/32"]
    if "via" in route_words:
        command.extend(["via", route_words[route_words.index("via") + 1]])
    if "dev" in route_words:
        command.extend(["dev", route_words[route_words.index("dev") + 1]])
    runner.run(command)


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

__SSH_VPN_OVPN_STOP__

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
""".replace("__SSH_VPN_OVPN_STOP__", _remote_ovpn_stop_snippet()).strip()


def remote_setup_script(binding: TunnelBinding | None = None) -> str:
    chosen = binding or routing_binding()
    return f"""
set -eu
ip addr flush dev {chosen.remote_tun} || true
ip addr add {chosen.remote_address} peer {chosen.local_address} dev {chosen.remote_tun} || true
ip link set {chosen.remote_tun} up
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.{chosen.remote_tun}.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
if command -v nft >/dev/null 2>&1; then
  nft add table ip ssh_vpn_gui 2>/dev/null || true
  nft 'add chain ip ssh_vpn_gui postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}' 2>/dev/null || true
  nft add rule ip ssh_vpn_gui postrouting ip saddr {chosen.cidr} oifname != "{chosen.remote_tun}" masquerade 2>/dev/null || true
fi
if command -v iptables >/dev/null 2>&1; then
  iptables -t nat -C POSTROUTING -s {chosen.cidr} ! -o {chosen.remote_tun} -j MASQUERADE 2>/dev/null || \\
    iptables -t nat -A POSTROUTING -s {chosen.cidr} ! -o {chosen.remote_tun} -j MASQUERADE
fi
echo SSH_VPN_READY
trap 'nft delete table ip ssh_vpn_gui 2>/dev/null || true; iptables -t nat -D POSTROUTING -s {chosen.cidr} ! -o {chosen.remote_tun} -j MASQUERADE 2>/dev/null || true; ip addr flush dev {chosen.remote_tun} 2>/dev/null || true' EXIT
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
    return f"""
set -eu
nft delete table ip ssh_vpn_gui 2>/dev/null || true
{_remote_tun_cleanup_snippet(chosen)}
{_remote_ovpn_stop_snippet(cidr=chosen.cidr if chosen else None)}
""".strip()


def _remote_ovpn_stop_snippet(*, cidr: str | None = None) -> str:
    tracked = cidr or "10.255.0.0/16"
    return f"""
while ip rule del table {OVPN_TABLE} 2>/dev/null; do :; done
ip route flush table {OVPN_TABLE} 2>/dev/null || true
if command -v conntrack >/dev/null 2>&1; then
  conntrack -D -s {tracked} >/dev/null 2>&1 || true
fi
# Ours only: comm is openvpn or the --daemon name. Do not pgrep -f the
# config path — the SSH bash -lc script text contains it and would die.
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
""".strip()


def remote_ovpn_cleanup_command(binding: TunnelBinding | None = None) -> str:
    chosen = binding or load_tunnel_state()
    return f"""
set -eu
{_remote_ovpn_stop_snippet(cidr=chosen.cidr if chosen else None)}
echo SSH_VPN_OVPN_STOPPED
""".strip()


def remote_ovpn_bootstrap_script(ovpn_b64: str, *, cidr: str | None = None) -> str:
    chosen = cidr
    if chosen is None:
        state = load_tunnel_state()
        chosen = state.cidr if state else ""
    return f"""
set -eu
if ! command -v openvpn >/dev/null 2>&1 || ! command -v conntrack >/dev/null 2>&1; then
  echo SSH_VPN_OVPN_INSTALLING
  echo 'SSH_VPN_OVPN_PROGRESS Installing OpenVPN packages on the server'
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    (
      apt-get -o DPkg::Lock::Timeout={OVPN_APT_LOCK_TIMEOUT_SECONDS} update
      apt-get -o DPkg::Lock::Timeout={OVPN_APT_LOCK_TIMEOUT_SECONDS} install -y openvpn conntrack
    ) &
    _apt_pid=$!
    while kill -0 "$_apt_pid" 2>/dev/null; do
      echo 'SSH_VPN_OVPN_PROGRESS Installing OpenVPN packages on the server'
      sleep 8
    done
    wait "$_apt_pid"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y openvpn conntrack-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y openvpn conntrack-tools
  else
    echo 'no supported package manager found to install openvpn and conntrack tools' >&2
    exit 1
  fi
fi

mkdir -p /etc/ssh-vpn-gui
base64 -d > {OVPN_CONFIG_PATH} <<'SSH_VPN_OVPN_B64'
{ovpn_b64}
SSH_VPN_OVPN_B64
chmod 600 {OVPN_CONFIG_PATH}

# Reap our leftover clients by config path, then take the first free ovpnN.
echo 'SSH_VPN_OVPN_REAP_BEFORE_START'
echo 'SSH_VPN_OVPN_PROGRESS Clearing leftover OpenVPN on the server'
{_remote_ovpn_stop_snippet(cidr=chosen or None)}

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

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true

# Timeouts belong to OpenVPN on this server. resolv-retry defaults to
# infinite and is applied before --daemon returns, so a bad hostname
# blocks this SSH script for minutes. One short resolve + one connect
# attempt; the wait loop only watches that process.
printf '\\n# ssh-vpn-gui timeouts\\nresolv-retry 3\\nconnect-retry-max 1\\nconnect-timeout {OVPN_CONNECT_TIMEOUT_SECONDS}\\nserver-poll-timeout {OVPN_CONNECT_TIMEOUT_SECONDS}\\n' >> {OVPN_CONFIG_PATH}
echo 'SSH_VPN_OVPN_PROGRESS Starting OpenVPN cascade'
openvpn \
  --config {OVPN_CONFIG_PATH} \
  --dev-type tun \
  --dev "$ovpn_dev" \
  --route-noexec \
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
    {_remote_ovpn_stop_snippet(cidr=chosen or None)}
    exit 1
  fi
  if [ -f {OVPN_LOG_PATH} ] && grep -Eiq '{OVPN_CONNECT_FAIL_PATTERN}' {OVPN_LOG_PATH}; then
    echo 'openvpn failed to connect to the VPN server' >&2
    tail -n 25 {OVPN_LOG_PATH} 2>/dev/null >&2 || true
    {_remote_ovpn_stop_snippet(cidr=chosen or None)}
    exit 1
  fi
  sleep 1
done

if [ "$up" -ne 1 ]; then
  echo 'openvpn interface did not come up in time' >&2
  tail -n 25 {OVPN_LOG_PATH} 2>/dev/null >&2 || true
  {_remote_ovpn_stop_snippet(cidr=chosen or None)}
  exit 1
fi

cidr='{chosen}'
if [ -z "$cidr" ]; then
  cidr=$(ip -4 -o addr show 2>/dev/null | sed -n 's/.* inet 10\\.255\\.\\([0-9][0-9]*\\)\\.[12]\\/.*/10.255.\\1.0\\/30/p' | head -n 1)
fi
sysctl -w "net.ipv4.conf.$ovpn_dev.rp_filter=0" >/dev/null 2>&1 || true
ip route replace default dev "$ovpn_dev" table {OVPN_TABLE}
if [ -n "$cidr" ]; then
  ip rule add from "$cidr" table {OVPN_TABLE} priority {OVPN_TABLE}
fi
echo SSH_VPN_OVPN_READY
""".strip()
