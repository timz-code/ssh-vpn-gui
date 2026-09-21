from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from .routing_config import RoutingConfig
from .system import (
    CommandRunner,
    OLD_FORCED_ROUTES,
    PROXY_MARK,
    PROXY_TABLE,
    STATE_DIR,
    cleanup_tun_routes,
    clear_fail_closed,
    is_fail_closed,
    mark_fail_closed,
    preserve_server_route,
    routing_binding,
    underlay_ips,
)

NFT_TABLE = "ssh_vpn_gui"
DNS_PORT = "53535"
NFT_CONFIG = STATE_DIR / "nftables.conf"
DOT_UPSTREAMS = ("1.1.1.1", "9.9.9.9")
PROXY_ROUTES_FILE = STATE_DIR / "proxy-routes.txt"


@dataclass(frozen=True)
class RoutingEngine:
    config: RoutingConfig
    server: str

    def start(self, runner: CommandRunner) -> None:
        self._reset_policy_routing(runner)
        runner.write_file(NFT_CONFIG, self._nft_config())
        runner.write_file(PROXY_ROUTES_FILE, "")
        runner.run(["nft", "-f", str(NFT_CONFIG)])
        binding = routing_binding()
        runner.run(["ip", "route", "replace", "default", "dev", binding.local_tun, "src", binding.local_address, "table", PROXY_TABLE])
        runner.run(["ip", "rule", "add", "fwmark", PROXY_MARK, "table", PROXY_TABLE, "priority", PROXY_TABLE], check=False)
        if not runner.dry_run:
            clear_fail_closed()
        if self.server:
            runner.run(
                ["nft", "add", "element", "inet", NFT_TABLE, "direct4", "{", self.server, "}"],
                check=False,
            )
            preserve_server_route(runner, self.server)

    def stop(self, runner: CommandRunner) -> None:
        reset_local_routing(runner)

    def _reset_policy_routing(self, runner: CommandRunner) -> None:
        _reset_policy_routing(runner)

    def add_static_ip_rules(self, runner: CommandRunner) -> None:
        protected = underlay_ips(self.server)
        for rule in self.config.rules:
            for matcher in rule.matchers:
                if matcher.name != "ip_cidr":
                    continue
                if _cidr_covers(matcher.value, protected):
                    runner.run(
                        ["nft", "add", "element", "inet", NFT_TABLE, "direct4", "{", matcher.value, "}"],
                        check=False,
                    )
                    preserve_server_route(runner, self.server)
                    continue
                set_name = "direct4" if rule.action == "direct" else "proxy4"
                runner.run(["nft", "add", "element", "inet", NFT_TABLE, set_name, "{", matcher.value, "}"], check=False)

    def _setup_commands(self) -> list[list[str]]:
        return [["nft", "-f", str(NFT_CONFIG)]]

    def _nft_config(self) -> str:
        networks = [str(network) for network in _direct_networks()]
        try:
            ipaddress.ip_address(self.server)
        except ValueError:
            pass
        else:
            networks.append(self.server)
        direct_elements = ", ".join(networks)
        mark_rules = "\n".join(f"    {rule}" for rule in self._mark_rules())
        binding = routing_binding()
        return f"""
table inet {NFT_TABLE} {{
  set direct4 {{
    type ipv4_addr;
    flags interval,timeout;
    elements = {{ {direct_elements} }};
  }}

  set proxy4 {{
    type ipv4_addr;
    flags interval,timeout;
  }}

  chain mark_output {{
    type route hook output priority mangle; policy accept;
{mark_rules}
  }}

  chain dns_output {{
    type nat hook output priority -100; policy accept;
    udp dport 53 redirect to :{DNS_PORT};
    tcp dport 53 redirect to :{DNS_PORT};
  }}

  chain snat_tun {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname "{binding.local_tun}" ip saddr != {binding.local_address} snat ip to {binding.local_address};
  }}

  chain reject6_output {{
    type filter hook output priority filter; policy accept;
    meta l4proto icmpv6 accept;
    ip6 daddr ::1 accept;
    meta nfproto ipv6 reject;
  }}
}}
""".strip() + "\n"

    def _mark_rules(self) -> list[str]:
        rules = [
            "udp dport 53 return;",
            "tcp dport 53 return;",
            f"ip daddr {self.server} return;",
            *[f"ip daddr {upstream} return;" for upstream in DOT_UPSTREAMS],
            "ip daddr @direct4 return;",
        ]
        if self.config.default == "proxy":
            rules.append(f"meta mark set {PROXY_MARK};")
        else:
            rules.append(f"ip daddr @proxy4 meta mark set {PROXY_MARK};")
        return rules


def add_resolved_ips(runner: CommandRunner, action: str, addresses: list[str], ttl: int) -> None:
    set_name = "direct4" if action == "direct" else "proxy4"
    timeout = f"{max(30, min(ttl, 86400))}s"
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.version == 4:
            if str(ip) in underlay_ips():
                runner.run(
                    ["nft", "add", "element", "inet", NFT_TABLE, "direct4", "{", str(ip), "}"],
                    check=False,
                )
                preserve_server_route(runner, str(ip))
                continue
            runner.run(["nft", "add", "element", "inet", NFT_TABLE, set_name, "{", str(ip), "timeout", timeout, "}"], check=False)
            if action == "proxy":
                if is_fail_closed():
                    continue
                binding = routing_binding()
                runner.run(["ip", "route", "replace", f"{ip}/32", "dev", binding.local_tun, "src", binding.local_address], check=False)
                _record_proxy_route(runner, str(ip))
            else:
                runner.run(["ip", "route", "del", f"{ip}/32"], check=False)


def reset_local_routing(runner: CommandRunner) -> None:
    """Remove every local policy-routing artifact this app installs.

    Does not depend on routing.cfg or the remote server. The main default
    route is never rewritten on connect, so deleting our overlays returns
    traffic to the system default path.
    """
    _reset_policy_routing(runner)
    cleanup_tun_routes(runner)
    if not runner.dry_run:
        clear_fail_closed()


def apply_fail_closed(runner: CommandRunner, *, full_tunnel: bool = False, server: str | None = None) -> None:
    """Keep direct traffic on the WAN. Send everything else into a hole.

    Used when the SSH tunnel is dead: proxy/full-tunnel destinations must
    not fall back to the clearnet. Exit and Restore (or a clean
    disconnect) calls reset_local_routing() to undo this.
    """
    if runner.dry_run:
        runner.commands.append("write fail-closed")
    else:
        mark_fail_closed()
    if full_tunnel:
        for route in OLD_FORCED_ROUTES:
            runner.run(["ip", "route", "replace", "blackhole", route], check=False)
    else:
        runner.run(
            ["ip", "route", "replace", "blackhole", "default", "table", PROXY_TABLE],
            check=False,
        )
        runner.run(
            ["ip", "rule", "add", "fwmark", PROXY_MARK, "table", PROXY_TABLE, "priority", PROXY_TABLE],
            check=False,
        )
    if server:
        preserve_server_route(runner, server)


def _reset_policy_routing(runner: CommandRunner) -> None:
    runner.run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)
    runner.run(["ip", "rule", "del", "fwmark", PROXY_MARK, "table", PROXY_TABLE], check=False)
    runner.run(["ip", "route", "flush", "table", PROXY_TABLE], check=False)
    cleanup_dynamic_proxy_routes(runner)
    for route in OLD_FORCED_ROUTES:
        runner.run(["ip", "route", "del", route], check=False)


def cleanup_dynamic_proxy_routes(runner: CommandRunner) -> None:
    if runner.dry_run:
        runner.commands.append(f"cleanup routes from {PROXY_ROUTES_FILE}")
        return
    if not PROXY_ROUTES_FILE.exists():
        return
    protected = underlay_ips()
    for address in PROXY_ROUTES_FILE.read_text(encoding="utf-8").splitlines():
        if address and address not in protected:
            runner.run(["ip", "route", "del", f"{address}/32"], check=False)
    PROXY_ROUTES_FILE.unlink(missing_ok=True)


def _record_proxy_route(runner: CommandRunner, address: str) -> None:
    if runner.dry_run:
        runner.commands.append(f"record proxy route {address}")
        return
    PROXY_ROUTES_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = set(PROXY_ROUTES_FILE.read_text(encoding="utf-8").splitlines()) if PROXY_ROUTES_FILE.exists() else set()
    if address not in existing:
        with PROXY_ROUTES_FILE.open("a", encoding="utf-8") as file:
            file.write(address + "\n")


def _cidr_covers(value: str, addresses: set[str]) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    for address in addresses:
        try:
            if ipaddress.ip_address(address) in network:
                return True
        except ValueError:
            continue
    return False


def _direct_networks() -> tuple[ipaddress.IPv4Network, ...]:
    return tuple(
        ipaddress.ip_network(network)
        for network in (
            "0.0.0.0/8",
            "10.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
        )
    )
