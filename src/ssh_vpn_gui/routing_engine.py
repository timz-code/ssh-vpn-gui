from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from .routing_config import RoutingConfig
from .system import (
    CommandRunner,
    KILL_SWITCH_METRIC,
    OLD_FORCED_ROUTES,
    PROXY_MARK,
    PROXY_TABLE,
    STATE_DIR,
    cleanup_tun_routes,
    clear_fail_closed,
    delete_proxy_rules,
    ensure_proxy_rule,
    ipv6_guard_down,
    ipv6_guard_up,
    is_fail_closed,
    mark_fail_closed,
    preserve_server_route,
    remove_full_tunnel_routes,
    routing_binding,
    underlay_ips,
)

NFT_TABLE = "ssh_vpn_gui"
DNS_PORT = "53535"
NFT_CONFIG = STATE_DIR / "nftables.conf"
DOT_UPSTREAMS = ("1.1.1.1", "9.9.9.9")
PROXY_ROUTES_FILE = STATE_DIR / "proxy-routes.txt"
ROUTE_BATCH_FILE = STATE_DIR / "routes.batch"


@dataclass(frozen=True)
class RoutingEngine:
    config: RoutingConfig
    server: str

    def start(self, runner: CommandRunner) -> None:
        """Route by rules through the current tun.

        New state goes in over the old one — nft swaps the table in one
        transaction, routes are replaced in place, full-tunnel routes are
        removed last — so a mode switch or a reconnect from the blocked
        state has no moment where tunneled traffic can reach the WAN.
        Per-IP proxy routes learned from DNS move to the new tun.
        """
        runner.write_file(NFT_CONFIG, self._nft_config())
        runner.run(["nft", "-f", str(NFT_CONFIG)])
        binding = routing_binding()
        runner.run(["ip", "route", "replace", "default", "dev", binding.local_tun, "src", binding.local_address, "table", PROXY_TABLE])
        runner.run(["ip", "route", "replace", "blackhole", "default", "table", PROXY_TABLE, "metric", KILL_SWITCH_METRIC])
        ensure_proxy_rule(runner)
        ipv6_guard_up(runner)
        restore_dynamic_proxy_routes(runner)
        remove_full_tunnel_routes(runner)
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
add table inet {NFT_TABLE}
delete table inet {NFT_TABLE}
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
                # The set entry expires with the DNS TTL; the /32 pair keeps
                # an app that caches the address longer off the WAN.
                if not is_fail_closed():
                    binding = routing_binding()
                    runner.run(["ip", "route", "replace", f"{ip}/32", "dev", binding.local_tun, "src", binding.local_address], check=False)
                runner.run(["ip", "route", "replace", "blackhole", f"{ip}/32", "metric", KILL_SWITCH_METRIC], check=False)
                _record_proxy_route(runner, str(ip))
            else:
                runner.run(["ip", "route", "del", "blackhole", f"{ip}/32", "metric", KILL_SWITCH_METRIC], check=False)
                runner.run(["ip", "route", "del", f"{ip}/32"], check=False)


def reset_local_routing(runner: CommandRunner) -> None:
    """Remove every local policy-routing artifact this app installs.

    Does not depend on routing.cfg or the remote server. The main default
    route is never rewritten on connect, so deleting our overlays returns
    traffic to the system default path.
    """
    _reset_policy_routing(runner)
    ipv6_guard_down(runner)
    cleanup_tun_routes(runner)
    if not runner.dry_run:
        clear_fail_closed()


def stop_rule_mode(runner: CommandRunner) -> None:
    """Remove rule-based routing. A caller that keeps the tunnel up must
    install the full-tunnel routes before calling this."""
    runner.run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)
    delete_proxy_rules(runner)
    runner.run(["ip", "route", "flush", "table", PROXY_TABLE], check=False)
    cleanup_dynamic_proxy_routes(runner)


def apply_fail_closed(runner: CommandRunner, *, full_tunnel: bool = False, server: str | None = None) -> None:
    """Keep direct traffic on the WAN. Send everything else into a hole.

    The blackholes are already installed next to every tun route, so when
    ssh dies nothing leaks even before this runs; here they are re-asserted
    and the state is flagged for the GUI. Exit and Restore (or a clean
    disconnect) calls reset_local_routing() to undo this.
    """
    if runner.dry_run:
        runner.commands.append("write fail-closed")
    else:
        mark_fail_closed()
    if full_tunnel:
        for route in OLD_FORCED_ROUTES:
            runner.run(["ip", "route", "replace", "blackhole", route, "metric", KILL_SWITCH_METRIC], check=False)
    else:
        runner.run(
            ["ip", "route", "replace", "blackhole", "default", "table", PROXY_TABLE, "metric", KILL_SWITCH_METRIC],
            check=False,
        )
        ensure_proxy_rule(runner)
    ipv6_guard_up(runner, check=False)
    if server:
        preserve_server_route(runner, server, refresh=True)


def let_server_through(runner: CommandRunner, server: str) -> None:
    """Let ssh reach the server, possibly a different one, while blocked."""
    runner.run(["nft", "add", "element", "inet", NFT_TABLE, "direct4", "{", server, "}"], check=False)
    preserve_server_route(runner, server, refresh=True)


def _reset_policy_routing(runner: CommandRunner) -> None:
    stop_rule_mode(runner)
    remove_full_tunnel_routes(runner)


def cleanup_dynamic_proxy_routes(runner: CommandRunner) -> None:
    if runner.dry_run:
        runner.commands.append(f"cleanup routes from {PROXY_ROUTES_FILE}")
        return
    _route_batch(
        runner,
        [
            line
            for address in _recorded_proxy_routes()
            for line in (
                f"route del blackhole {address}/32 metric {KILL_SWITCH_METRIC}",
                f"route del {address}/32",
            )
        ],
    )
    PROXY_ROUTES_FILE.unlink(missing_ok=True)


def restore_dynamic_proxy_routes(runner: CommandRunner) -> None:
    if runner.dry_run:
        runner.commands.append(f"restore routes from {PROXY_ROUTES_FILE}")
        return
    binding = routing_binding()
    _route_batch(
        runner,
        [
            line
            for address in _recorded_proxy_routes()
            for line in (
                f"route replace {address}/32 dev {binding.local_tun} src {binding.local_address}",
                f"route replace blackhole {address}/32 metric {KILL_SWITCH_METRIC}",
            )
        ],
    )


def _recorded_proxy_routes() -> list[str]:
    if not PROXY_ROUTES_FILE.exists():
        return []
    protected = underlay_ips()
    addresses: list[str] = []
    for line in PROXY_ROUTES_FILE.read_text(encoding="utf-8").splitlines():
        try:
            address = str(ipaddress.IPv4Address(line.strip()))
        except ValueError:
            continue
        if address not in protected:
            addresses.append(address)
    return addresses


def _route_batch(runner: CommandRunner, lines: list[str]) -> None:
    if not lines:
        return
    runner.write_file(ROUTE_BATCH_FILE, "\n".join(lines) + "\n")
    runner.run(["ip", "-force", "-batch", str(ROUTE_BATCH_FILE)], check=False)


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
