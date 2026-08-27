from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from .routing_config import RoutingConfig
from .system import (
    CommandRunner,
    LOCAL_TUN,
    LOCAL_TUN_ADDRESS,
    OLD_FORCED_ROUTES,
    PROXY_MARK,
    PROXY_TABLE,
    STATE_DIR,
    cleanup_tun_routes,
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
        runner.run(["ip", "route", "replace", "default", "dev", LOCAL_TUN, "src", LOCAL_TUN_ADDRESS, "table", PROXY_TABLE])
        runner.run(["ip", "rule", "add", "fwmark", PROXY_MARK, "table", PROXY_TABLE, "priority", PROXY_TABLE], check=False)

    def stop(self, runner: CommandRunner) -> None:
        reset_local_routing(runner)

    def _reset_policy_routing(self, runner: CommandRunner) -> None:
        _reset_policy_routing(runner)

    def add_static_ip_rules(self, runner: CommandRunner) -> None:
        for rule in self.config.rules:
            for matcher in rule.matchers:
                if matcher.name != "ip_cidr":
                    continue
                set_name = "direct4" if rule.action == "direct" else "proxy4"
                runner.run(["nft", "add", "element", "inet", NFT_TABLE, set_name, "{", matcher.value, "}"], check=False)

    def _setup_commands(self) -> list[list[str]]:
        return [["nft", "-f", str(NFT_CONFIG)]]

    def _nft_config(self) -> str:
        direct_elements = ", ".join(str(network) for network in _direct_networks())
        mark_rules = "\n".join(f"    {rule}" for rule in self._mark_rules())
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
    oifname "{LOCAL_TUN}" ip saddr != {LOCAL_TUN_ADDRESS} snat ip to {LOCAL_TUN_ADDRESS};
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
            runner.run(["nft", "add", "element", "inet", NFT_TABLE, set_name, "{", str(ip), "timeout", timeout, "}"], check=False)
            if action == "proxy":
                runner.run(["ip", "route", "replace", f"{ip}/32", "dev", LOCAL_TUN, "src", LOCAL_TUN_ADDRESS], check=False)
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
    for address in PROXY_ROUTES_FILE.read_text(encoding="utf-8").splitlines():
        if address:
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
