from ssh_vpn_gui.routing_config import parse_routing_text
from ssh_vpn_gui.routing_engine import (
    RoutingEngine,
    add_resolved_ips,
    apply_fail_closed,
    reset_local_routing,
)
from ssh_vpn_gui.system import CommandRunner, TunnelBinding


def test_routing_engine_uses_marked_table_without_forced_default_routes(monkeypatch) -> None:
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
    assert "chain reject6_output" in nft_config
    assert "meta nfproto ipv6 reject;" in nft_config
    assert 'oifname "tun3" ip saddr != 10.255.3.1 snat ip to 10.255.3.1;' in nft_config
    assert not any("0.0.0.0/1 dev tun3" in command for command in commands)


def test_routing_engine_sets_policy_route_for_marked_proxy_traffic(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    routing = parse_routing_text("default: proxy\ndomain(geosite:ru)->direct")
    runner = CommandRunner(dry_run=True)

    RoutingEngine(config=routing, server="203.0.113.10").start(runner)

    assert "ip route replace default dev tun3 src 10.255.3.1 table 2023" in runner.commands
    assert "ip rule add fwmark 2023 table 2023 priority 2023" in runner.commands
    assert "delete routes using claimed tuns" not in runner.commands
    assert not any(command.startswith("delete routes using tun") for command in runner.commands)


def test_reset_local_routing_removes_overlays_without_touching_main_default(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    runner = CommandRunner(dry_run=True)

    reset_local_routing(runner)

    assert "nft delete table inet ssh_vpn_gui" in runner.commands
    assert "ip rule del fwmark 2023 table 2023" in runner.commands
    assert "ip route flush table 2023" in runner.commands
    assert "ip route del 0.0.0.0/1" in runner.commands
    assert "ip route del 128.0.0.0/1" in runner.commands
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
    assert "nft add element inet ssh_vpn_gui direct4 { 192.168.50.2 }" in joined
    assert "ip route replace 1.2.3.4/32 dev tun4 src 10.255.8.1" in joined
    assert "ip route replace 192.168.50.2/32 via 192.168.1.1 dev wlp2s0" in joined


def test_fail_closed_blackholes_proxy_table_and_keeps_underlay(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    runner = CommandRunner(dry_run=True)

    apply_fail_closed(runner, full_tunnel=False, server="203.0.113.10")

    assert "write fail-closed" in runner.commands
    assert "ip route replace blackhole default table 2023" in runner.commands
    assert "ip rule add fwmark 2023 table 2023 priority 2023" in runner.commands
    assert "nft delete table inet ssh_vpn_gui" not in runner.commands
    assert any("ip route get 203.0.113.10" in command for command in runner.commands)


def test_fail_closed_full_tunnel_blackholes_split_defaults(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    runner = CommandRunner(dry_run=True)

    apply_fail_closed(runner, full_tunnel=True, server=None)

    assert "ip route replace blackhole 0.0.0.0/1" in runner.commands
    assert "ip route replace blackhole 128.0.0.0/1" in runner.commands
    assert "ip route replace blackhole default table 2023" not in runner.commands


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


def test_static_proxy_rule_cannot_steal_the_ssh_server(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    routing = parse_routing_text("default: proxy\nip(192.168.50.2)->proxy\n")
    runner = CommandRunner(dry_run=True)

    RoutingEngine(config=routing, server="192.168.50.2").add_static_ip_rules(runner)

    assert not any("proxy4 { 192.168.50.2" in command for command in runner.commands)
    assert any("direct4 { 192.168.50.2" in command for command in runner.commands)
