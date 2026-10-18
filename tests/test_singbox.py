from dataclasses import dataclass, field
import ipaddress
import subprocess

import pytest

from ssh_vpn_gui.geoip import PRIVATE_NETWORKS
from ssh_vpn_gui.routing_config import parse_routing_text
from ssh_vpn_gui.routing_engine import (
    RoutingEngine,
    add_resolved_ips,
    apply_fail_closed,
    cleanup_dynamic_proxy_routes,
    let_server_through,
    reset_local_routing,
    restore_dynamic_proxy_routes,
    _static_ip_action,
)
from ssh_vpn_gui.system import CommandRunner, TunnelBinding


TUN4_BINDING = TunnelBinding(
    local_tun="tun4",
    remote_tun="tun7",
    local_address="10.255.8.1",
    remote_address="10.255.8.2",
    cidr="10.255.8.0/30",
    server="192.168.50.2",
)


@pytest.fixture
def country_networks(monkeypatch):
    available = {
        "private": PRIVATE_NETWORKS,
        "ru": (ipaddress.ip_network("5.255.255.0/24"),),
    }
    monkeypatch.setattr(
        "ssh_vpn_gui.routing_engine.GeoIpStore.ipv4_networks",
        lambda _self, tags: {tag.lower(): available[tag.lower()] for tag in tags},
    )


@dataclass
class RecordingRunner(CommandRunner):
    files: dict = field(default_factory=dict)

    def run(self, command, *, check=True):
        self.commands.append(" ".join(command))
        return subprocess.CompletedProcess(command, 0, "", "")

    def write_file(self, path, content):
        self.commands.append(f"write {path}")
        self.files[path] = content


def test_routing_engine_uses_marked_table_without_forced_default_routes(monkeypatch, country_networks) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    routing = parse_routing_text(
        """
        default: proxy
        domain(domain:mail.qq.com)->direct
        domain(geosite:google)->proxy
        ip(217.174.105.72)->direct
        ip(geoip:ru)->direct
        """
    )

    engine = RoutingEngine(config=routing, server="203.0.113.10")
    commands = [" ".join(command) for command in engine._setup_commands()]
    nft_config = engine._nft_config()

    assert "nft -f /run/ssh-vpn-gui/nftables.conf" in commands
    assert "table inet ssh_vpn_gui" in nft_config
    assert "chain mark_output" in nft_config
    assert "ip daddr 203.0.113.10 return;" in nft_config
    assert "203.0.113.10" in nft_config
    assert "ip daddr 1.1.1.1 return;" in nft_config
    assert "ip daddr 9.9.9.9 return;" in nft_config
    assert "ip daddr @direct4 return;" in nft_config
    assert "meta mark set 2023;" in nft_config
    assert "chain dns_output" in nft_config
    assert "chain snat_tun" in nft_config
    assert "chain reject6_output" not in nft_config
    assert 'oifname "tun3" ip saddr != 10.255.3.1 snat ip to 10.255.3.1;' in nft_config
    assert not any("0.0.0.0/1 dev tun3" in command for command in commands)


def test_nft_config_swaps_the_table_in_one_transaction(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    routing = parse_routing_text("default: proxy\n")

    nft_config = RoutingEngine(config=routing, server="203.0.113.10")._nft_config()

    assert nft_config.startswith(
        "add table inet ssh_vpn_gui\ndelete table inet ssh_vpn_gui\ntable inet ssh_vpn_gui {\n"
    )


def test_routing_engine_sets_policy_route_for_marked_proxy_traffic(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    routing = parse_routing_text("default: proxy\ndomain(geosite:ru)->direct")
    runner = CommandRunner(dry_run=True)

    RoutingEngine(config=routing, server="203.0.113.10").start(runner)

    assert "ip route replace default dev tun3 src 10.255.3.1 table 2023" in runner.commands
    assert "ip route replace blackhole default table 2023 metric 4095" in runner.commands
    assert "ip rule add fwmark 2023 table 2023 priority 2023" in runner.commands
    assert "nft -f /run/ssh-vpn-gui/ipv6-guard.nft" in runner.commands
    assert "delete routes using claimed tuns" not in runner.commands
    assert not any(command.startswith("delete routes using tun") for command in runner.commands)


def test_routing_engine_start_never_opens_a_gap(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    routing = parse_routing_text("default: direct\ndomain(domain:example.com)->proxy")
    runner = CommandRunner(dry_run=True)

    RoutingEngine(config=routing, server="203.0.113.10").start(runner)

    commands = runner.commands
    assert "nft delete table inet ssh_vpn_gui" not in commands
    assert "ip route flush table 2023" not in commands
    assert "ip rule del fwmark 2023 table 2023" not in commands
    assert "cleanup routes from /run/ssh-vpn-gui/proxy-routes.txt" not in commands
    assert "restore routes from /run/ssh-vpn-gui/proxy-routes.txt" in commands
    rule_mode_ready = max(
        commands.index("nft -f /run/ssh-vpn-gui/nftables.conf"),
        commands.index("ip route replace default dev tun3 src 10.255.3.1 table 2023"),
        commands.index("ip route replace blackhole default table 2023 metric 4095"),
        commands.index("ip rule add fwmark 2023 table 2023 priority 2023"),
    )
    assert commands.index("ip route del 0.0.0.0/1") > rule_mode_ready
    assert commands.index("ip route del blackhole 128.0.0.0/1 metric 4095") > rule_mode_ready


def test_reset_local_routing_removes_overlays_without_touching_main_default(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    runner = CommandRunner(dry_run=True)

    reset_local_routing(runner)

    assert "nft delete table inet ssh_vpn_gui" in runner.commands
    assert "ip rule del fwmark 2023 table 2023" in runner.commands
    assert "ip route flush table 2023" in runner.commands
    assert "ip route del blackhole 0.0.0.0/1 metric 4095" in runner.commands
    assert "ip route del blackhole 128.0.0.0/1 metric 4095" in runner.commands
    assert "ip route del 0.0.0.0/1" in runner.commands
    assert "ip route del 128.0.0.0/1" in runner.commands
    assert "cleanup routes from /run/ssh-vpn-gui/proxy-routes.txt" in runner.commands
    assert "nft delete table inet ssh_vpn_gui_v6" in runner.commands
    assert "delete routes using claimed tuns" in runner.commands
    assert not any("ip route replace default" in command for command in runner.commands)
    assert not any(command.startswith("ip route add") for command in runner.commands)


def test_add_resolved_ips_never_tunnels_the_ssh_server(monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_vpn_gui.system.load_tunnel_state",
        lambda: TunnelBinding(
            local_tun="tun4",
            remote_tun="tun7",
            local_address="10.255.8.1",
            remote_address="10.255.8.2",
            cidr="10.255.8.0/30",
            server="192.168.50.2",
            underlay_via="192.168.1.1",
            underlay_dev="wlp2s0",
        ),
    )
    runner = CommandRunner(dry_run=True)

    add_resolved_ips(runner, "proxy", ["192.168.50.2", "1.2.3.4"], 60)
    add_resolved_ips(runner, "direct", ["192.168.50.2"], 60)

    joined = "\n".join(runner.commands)
    assert "ip route replace 192.168.50.2/32 dev tun4" not in joined
    assert "ip route del 192.168.50.2/32" not in joined
    assert "blackhole 192.168.50.2" not in joined
    assert "nft add element inet ssh_vpn_gui direct4 { 192.168.50.2 }" in joined
    assert "ip route replace 1.2.3.4/32 dev tun4 src 10.255.8.1" in joined
    assert "ip route replace blackhole 1.2.3.4/32 metric 4095" in joined
    assert "ip route replace 192.168.50.2/32 via 192.168.1.1 dev wlp2s0" in joined


def test_add_resolved_ips_direct_drops_the_proxy_route_pair(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: TUN4_BINDING)
    runner = CommandRunner(dry_run=True)

    add_resolved_ips(runner, "direct", ["5.6.7.8"], 60)

    assert "ip route del blackhole 5.6.7.8/32 metric 4095" in runner.commands
    assert "ip route del 5.6.7.8/32" in runner.commands


def test_fail_closed_blackholes_proxy_table_and_keeps_underlay(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    runner = CommandRunner(dry_run=True)

    apply_fail_closed(runner, full_tunnel=False, server="203.0.113.10")

    assert "write fail-closed" in runner.commands
    assert "ip route replace blackhole default table 2023 metric 4095" in runner.commands
    assert "ip rule add fwmark 2023 table 2023 priority 2023" in runner.commands
    assert "nft -f /run/ssh-vpn-gui/ipv6-guard.nft" in runner.commands
    assert "nft delete table inet ssh_vpn_gui" not in runner.commands
    assert "ip -4 route show default" in runner.commands
    assert "ip route replace 203.0.113.10/32 via <gw> dev <underlay>" in runner.commands
    assert not any(command.startswith("ip route get") for command in runner.commands)


def test_fail_closed_full_tunnel_blackholes_split_defaults(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    runner = CommandRunner(dry_run=True)

    apply_fail_closed(runner, full_tunnel=True, server=None)

    assert "ip route replace blackhole 0.0.0.0/1 metric 4095" in runner.commands
    assert "ip route replace blackhole 128.0.0.0/1 metric 4095" in runner.commands
    assert "nft -f /run/ssh-vpn-gui/ipv6-guard.nft" in runner.commands
    assert not any("table 2023" in command for command in runner.commands)


def test_let_server_through_opens_only_the_new_server(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    runner = CommandRunner(dry_run=True)

    let_server_through(runner, "198.51.100.7")

    assert runner.commands == [
        "nft add element inet ssh_vpn_gui direct4 { 198.51.100.7 }",
        "ip -4 route show default",
        "ip route replace 198.51.100.7/32 via <gw> dev <underlay>",
    ]


def test_restore_moves_learned_proxy_routes_to_the_new_tun(monkeypatch, tmp_path) -> None:
    recorded = tmp_path / "proxy-routes.txt"
    recorded.write_text("1.2.3.4\n192.168.50.2\nnot an address\n\n", encoding="utf-8")
    batch = tmp_path / "routes.batch"
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.PROXY_ROUTES_FILE", recorded)
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.ROUTE_BATCH_FILE", batch)
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: TUN4_BINDING)
    runner = RecordingRunner()

    restore_dynamic_proxy_routes(runner)

    assert runner.files[batch] == (
        "route replace 1.2.3.4/32 dev tun4 src 10.255.8.1\n"
        "route replace blackhole 1.2.3.4/32 metric 4095\n"
    )
    assert runner.commands[-1] == f"ip -force -batch {batch}"
    assert recorded.exists()


def test_cleanup_drops_learned_proxy_routes_with_their_blackholes(monkeypatch, tmp_path) -> None:
    recorded = tmp_path / "proxy-routes.txt"
    recorded.write_text("1.2.3.4\n192.168.50.2\n", encoding="utf-8")
    batch = tmp_path / "routes.batch"
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.PROXY_ROUTES_FILE", recorded)
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.ROUTE_BATCH_FILE", batch)
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: TUN4_BINDING)
    runner = RecordingRunner()

    cleanup_dynamic_proxy_routes(runner)

    assert runner.files[batch] == (
        "route del blackhole 1.2.3.4/32 metric 4095\n"
        "route del 1.2.3.4/32\n"
    )
    assert not recorded.exists()


def test_cleanup_without_learned_routes_runs_nothing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.PROXY_ROUTES_FILE", tmp_path / "missing.txt")
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    runner = RecordingRunner()

    cleanup_dynamic_proxy_routes(runner)
    restore_dynamic_proxy_routes(runner)

    assert runner.commands == []


def test_add_resolved_ips_skips_tun_routes_when_fail_closed(monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_vpn_gui.system.load_tunnel_state",
        lambda: TunnelBinding(
            local_tun="tun4",
            remote_tun="tun7",
            local_address="10.255.8.1",
            remote_address="10.255.8.2",
            cidr="10.255.8.0/30",
            server="192.168.50.2",
        ),
    )
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.is_fail_closed", lambda: True)
    runner = CommandRunner(dry_run=True)

    add_resolved_ips(runner, "proxy", ["1.2.3.4"], 60)

    joined = "\n".join(runner.commands)
    assert "nft add element inet ssh_vpn_gui proxy4 { 1.2.3.4" in joined
    assert "ip route replace 1.2.3.4/32" not in joined
    assert "ip route replace blackhole 1.2.3.4/32 metric 4095" in joined


def test_static_proxy_rule_cannot_steal_the_ssh_server(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    routing = parse_routing_text("default: proxy\nip(192.168.50.2)->proxy\n")
    nft = RoutingEngine(config=routing, server="192.168.50.2")._nft_config()

    assert nft.index("ip daddr 192.168.50.2 return;") < nft.index("ip daddr @ip_rule_2 meta mark set 2023 return;")


def test_geoip_private_and_ru_install_permanent_ip_rules_without_dns(country_networks) -> None:
    engine = RoutingEngine(
        parse_routing_text("default: proxy\nip(geoip:private, geoip:ru)->direct\n"),
        server="203.0.113.10",
    )
    rules = engine._static_ip_rules()
    nft = engine._nft_config(rules)

    assert _static_ip_action("5.255.255.77", rules) == "direct"
    assert _static_ip_action("100.64.0.1", rules) == "direct"
    assert _static_ip_action("8.8.8.8", rules) is None
    static_set = nft.split("set ip_rule_2 {", 1)[1].split("\n  }", 1)[0]
    assert "5.255.255.0/24" in static_set
    assert "100.64.0.0/10" in static_set
    assert "flags interval;" in static_set
    assert "timeout" not in static_set
    assert nft.index("ip daddr @ip_rule_2 return;") < nft.index("ip daddr @direct4 return;")


def test_static_ip_rules_keep_first_match_precedence(country_networks) -> None:
    engine = RoutingEngine(
        parse_routing_text("default: proxy\nip(5.255.255.0/28)->proxy\nip(geoip:ru)->direct\n"),
        server="203.0.113.10",
    )
    rules = engine._static_ip_rules()
    nft = engine._nft_config(rules)

    assert _static_ip_action("5.255.255.1", rules) == "proxy"
    assert _static_ip_action("5.255.255.40", rules) == "direct"
    assert nft.index("ip daddr @ip_rule_2 meta mark set 2023 return;") < nft.index("ip daddr @ip_rule_3 return;")


def test_rule_reload_removes_old_proxy_routes_for_geoip_direct(monkeypatch, tmp_path, country_networks) -> None:
    recorded = tmp_path / "proxy-routes.txt"
    recorded.write_text("5.255.255.77\n1.2.3.4\n", encoding="utf-8")
    batch = tmp_path / "routes.batch"
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.PROXY_ROUTES_FILE", recorded)
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.ROUTE_BATCH_FILE", batch)
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: TUN4_BINDING)
    runner = RecordingRunner()
    rules = RoutingEngine(
        parse_routing_text("ip(geoip:private, geoip:ru)->direct"), server="192.168.50.2"
    )._static_ip_rules()

    restore_dynamic_proxy_routes(runner, rules)

    assert "route del blackhole 5.255.255.77/32 metric 4095\nroute del 5.255.255.77/32\n" in runner.files[batch]
    assert "route replace 5.255.255.77/32" not in runner.files[batch]
    assert "route replace 1.2.3.4/32 dev tun4" in runner.files[batch]
    assert runner.files[recorded] == "1.2.3.4\n"


def test_direct_dns_answer_is_not_restored_as_proxy_later(monkeypatch, tmp_path) -> None:
    recorded = tmp_path / "proxy-routes.txt"
    recorded.write_text("5.255.255.77\n1.2.3.4\n", encoding="utf-8")
    monkeypatch.setattr("ssh_vpn_gui.routing_engine.PROXY_ROUTES_FILE", recorded)
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: TUN4_BINDING)
    runner = RecordingRunner()

    add_resolved_ips(runner, "direct", ["5.255.255.77"], 60)

    assert runner.files[recorded] == "1.2.3.4\n"


def test_missing_geoip_database_fails_before_modifying_routing(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("ssh_vpn_gui.geoip.GEOIP_DB", tmp_path / "missing.mmdb")
    runner = RecordingRunner()
    engine = RoutingEngine(parse_routing_text("ip(geoip:ru)->direct"), "203.0.113.10")

    with pytest.raises(RuntimeError, match="Update Routing Data"):
        engine.start(runner)

    assert runner.commands == []
    assert runner.files == {}
