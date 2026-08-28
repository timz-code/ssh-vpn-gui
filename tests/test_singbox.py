from ssh_vpn_gui.routing_config import parse_routing_text
from ssh_vpn_gui.routing_engine import RoutingEngine, reset_local_routing
from ssh_vpn_gui.system import CommandRunner


def test_routing_engine_uses_marked_table_without_forced_default_routes() -> None:
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
    assert "ip daddr 1.1.1.1 return;" in nft_config
    assert "ip daddr 9.9.9.9 return;" in nft_config
    assert "ip daddr @direct4 return;" in nft_config
    assert "meta mark set 2023;" in nft_config
    assert "chain dns_output" in nft_config
    assert "chain snat_tun" in nft_config
    assert 'oifname "tun3" ip saddr != 10.255.3.1 snat ip to 10.255.3.1;' in nft_config
    assert not any("0.0.0.0/1 dev tun3" in command for command in commands)


def test_routing_engine_sets_policy_route_for_marked_proxy_traffic() -> None:
    routing = parse_routing_text("default: proxy\ndomain(geosite:ru)->direct")
    runner = CommandRunner(dry_run=True)

    RoutingEngine(config=routing, server="203.0.113.10").start(runner)

    assert "ip route replace default dev tun3 src 10.255.3.1 table 2023" in runner.commands
    assert "ip rule add fwmark 2023 table 2023 priority 2023" in runner.commands
    assert "delete routes using claimed tuns" not in runner.commands
    assert not any(command.startswith("delete routes using tun") for command in runner.commands)


def test_reset_local_routing_removes_overlays_without_touching_main_default() -> None:
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
