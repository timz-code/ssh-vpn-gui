import io
import json
import re
import subprocess

import pytest

from ssh_vpn_gui import helper


def test_health_check_keeps_tunnel_when_public_ip_services_timeout(monkeypatch) -> None:
    def timeout_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["curl"], timeout=7)

    monkeypatch.setattr(helper.subprocess, "run", timeout_run)

    assert helper._health_check() == ["public IP health check unavailable; tunnel left running"]


def test_health_check_reports_public_ip_without_rollback(monkeypatch) -> None:
    def public_ip_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(args=["curl"], returncode=0, stdout="198.51.100.10\n", stderr="")

    monkeypatch.setattr(helper.subprocess, "run", public_ip_run)

    assert helper._health_check() == ["public IP: 198.51.100.10"]


def test_cascade_off_dry_run_only_stops_remote_openvpn(tmp_path, capsys) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")

    result = helper.main(
        [
            "cascade-off",
            "--server",
            "203.0.113.10",
            "--password",
            "secret",
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["ok"] is True
    assert "ip rule del table 2124" in payload["messages"][0]
    assert "ip addr flush dev tun3" not in payload["messages"][0]


def test_cascade_on_dry_run_uploads_selected_config(tmp_path, capsys) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    ovpn_file = tmp_path / "client.ovpn"
    ovpn_file.write_text("client\ndev tun\nremote vpn.example 1194\n", encoding="utf-8")

    result = helper.main(
        [
            "cascade-on",
            "--server",
            "203.0.113.10",
            "--password",
            "secret",
            "--ovpn-file",
            str(ovpn_file),
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["ok"] is True
    assert "--config /etc/ssh-vpn-gui/client.ovpn" in payload["messages"][0]
    assert payload["messages"][0].index("SSH_VPN_PROGRESS Clearing the previous second hop") < payload[
        "messages"
    ][0].index("--daemon ssh-vpn-gui-ovpn")
    assert "seq 1 90" in payload["messages"][0]
    assert "--connect-timeout 8" in payload["messages"][0]
    assert "--disable-dco" in payload["messages"][0]
    assert "--connect-retry-max 1" in payload["messages"][0]
    assert "openvpn failed to connect to the VPN server" in payload["messages"][0]
    assert "SSH_VPN_REMOTE_OVPN" in payload["messages"][0]
    assert '--dev "$ovpn_dev"' in payload["messages"][0]
    assert not re.search(r"-w \d+:\d+", payload["messages"][0])


def test_cascade_on_rolls_back_when_connectivity_check_fails(
    monkeypatch, tmp_path, capsys
) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    ovpn_file = tmp_path / "client.ovpn"
    ovpn_file.write_text("client\ndev tun\n", encoding="utf-8")
    stopped = []
    public_ips = iter([None, "198.51.100.10"])

    monkeypatch.setattr(helper, "require_root", lambda: None)
    monkeypatch.setattr(helper, "start_remote_cascade", lambda *_args, **_kwargs: ["cascade ready"])
    monkeypatch.setattr(
        helper,
        "stop_remote_cascade",
        lambda *_args, **_kwargs: stopped.append(True) or ["cascade stopped"],
    )
    monkeypatch.setattr(helper, "_curl_public_ip", lambda **_kwargs: next(public_ips))

    result = helper.main(
        [
            "cascade-on",
            "--server",
            "203.0.113.10",
            "--password",
            "secret",
            "--ovpn-file",
            str(ovpn_file),
            "--routing-file",
            str(routing_file),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 1
    assert payload["ok"] is False
    assert stopped == [True]
    assert "OpenVPN second hop failed its connectivity check and was stopped" in payload["error"]
    assert "198.51.100.10" in payload["error"]


def test_tor_second_hop_gets_a_longer_ip_check(monkeypatch, tmp_path, capsys) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    started = []
    checks = []
    monkeypatch.setattr(helper, "require_root", lambda: None)
    monkeypatch.setattr(
        helper,
        "start_remote_cascade",
        lambda _server, _login, _password, cascade, **_kwargs: started.append(cascade) or ["tor ready"],
    )
    monkeypatch.setattr(
        helper, "_curl_public_ip", lambda **kwargs: checks.append(kwargs["max_time"]) or "198.51.100.77"
    )

    result = helper.main(
        [
            "cascade-on",
            "--server",
            "203.0.113.10",
            "--password",
            "secret",
            "--cascade",
            "tor",
            "--routing-file",
            str(routing_file),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0, payload
    assert started[0].kind == "tor"
    assert checks == [helper.TOR_PUBLIC_IP_TIMEOUT_SECONDS]
    assert payload["messages"][-1] == "public IP: 198.51.100.77"


def test_secrets_stdin_keeps_socks5_password_off_the_command_line(monkeypatch, tmp_path, capsys) -> None:
    from ssh_vpn_gui.cascade import Socks5Proxy

    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    started = []
    monkeypatch.setattr(
        helper,
        "start_remote_cascade",
        lambda _server, _login, password, cascade, **_kwargs: started.append((password, cascade)) or ["ok"],
    )
    monkeypatch.setattr(
        helper.sys,
        "stdin",
        io.StringIO(json.dumps({"password": "ssh secret", "socks5_password": 'p"w\\d'})),
    )

    result = helper.main(
        [
            "cascade-on",
            "--server",
            "203.0.113.10",
            "--secrets-stdin",
            "--cascade",
            "socks5",
            "--socks5-server=proxy.example.com:1080",
            "--socks5-user=-alice",
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    assert result == 0, capsys.readouterr().out
    password, cascade = started[0]
    assert password == "ssh secret"
    assert cascade.socks5 == Socks5Proxy(host="proxy.example.com", port=1080, user="-alice", password='p"w\\d')


def test_connect_rejects_bad_socks5_settings_before_touching_anything(monkeypatch, tmp_path, capsys) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    monkeypatch.setattr(helper, "_connect", lambda *_args, **_kwargs: pytest.fail("connect must not start"))

    result = helper.main(
        [
            "connect",
            "--server",
            "203.0.113.10",
            "--password",
            "secret",
            "--cascade",
            "socks5",
            "--socks5-server",
            "proxy.example.com:70000",
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 1
    assert payload["error"] == "The SOCKS5 port must be between 1 and 65535."


def test_public_ip_check_skips_answers_that_are_not_addresses(monkeypatch) -> None:
    answers = iter(["<html>blocked by proxy</html>\n", "198.51.100.10\n"])
    seen = []

    def fake_run(command, **kwargs):
        seen.append((command, kwargs["timeout"]))
        return subprocess.CompletedProcess(args=command, returncode=0, stdout=next(answers), stderr="")

    monkeypatch.setattr(helper.subprocess, "run", fake_run)

    assert helper._curl_public_ip(max_time=20) == "198.51.100.10"
    assert seen[0][0][:5] == ["curl", "-4", "-sS", "--max-time", "20"]
    assert seen[0][1] == 22


def test_save_routing_validates_and_atomically_replaces_file(
    monkeypatch, tmp_path, capsys
) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    updated = "default: direct\ndomain(domain:example.com)->proxy\n"
    monkeypatch.setattr(helper, "require_root", lambda: None)
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO(updated))

    result = helper.main(
        [
            "save-routing",
            "--content-stdin",
            "--routing-file",
            str(routing_file),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["ok"] is True
    assert routing_file.read_text(encoding="utf-8") == updated
    assert routing_file.stat().st_mode & 0o777 == 0o644
    assert not (tmp_path / ".routing.cfg.tmp").exists()


def test_status_reports_structured_liveness(monkeypatch, capsys) -> None:
    from ssh_vpn_gui.tunnel_watch import TunnelSnapshot

    monkeypatch.setattr(
        helper,
        "inspect_tunnel",
        lambda: TunnelSnapshot(daemon_alive=True, tun_present=True, peer_reachable=False),
    )

    result = helper.main(["status"])

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["ok"] is True
    assert payload["status"] == {
        "alive": False,
        "process_up": True,
        "daemon_alive": True,
        "tun_present": True,
        "peer_reachable": False,
    }
    assert any("unreachable" in line for line in payload["messages"])


def test_disconnect_local_only_skips_remote_cleanup(monkeypatch, tmp_path, capsys) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    remote_calls = []
    monkeypatch.setattr(helper, "require_root", lambda: None)
    monkeypatch.setattr(helper, "stop_dns_proxy", lambda **_kwargs: ["dns stopped"])
    monkeypatch.setattr(helper, "stop_tunnel", lambda **_kwargs: ["tunnel stopped"])
    monkeypatch.setattr(
        helper,
        "cleanup_remote",
        lambda *_args, **_kwargs: remote_calls.append(True) or ["remote cleaned"],
    )

    result = helper.main(
        [
            "disconnect",
            "--local-only",
            "--server",
            "203.0.113.10",
            "--login",
            "root",
            "--password",
            "secret",
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["ok"] is True
    assert remote_calls == []
    assert "remote cleaned" not in payload["messages"]


def test_disconnect_succeeds_when_remote_cleanup_fails(monkeypatch, tmp_path, capsys) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    monkeypatch.setattr(helper, "require_root", lambda: None)
    monkeypatch.setattr(helper, "stop_dns_proxy", lambda **_kwargs: ["dns stopped"])
    monkeypatch.setattr(helper, "stop_tunnel", lambda **_kwargs: ["tunnel stopped"])

    def fail_remote(*_args, **_kwargs):
        raise RuntimeError("Network is unreachable")

    monkeypatch.setattr(helper, "cleanup_remote", fail_remote)

    result = helper.main(
        [
            "disconnect",
            "--server",
            "203.0.113.10",
            "--login",
            "root",
            "--password",
            "secret",
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["ok"] is True
    assert any("remote cleanup skipped" in line for line in payload["messages"])


def test_disconnect_restores_local_routing_without_routing_cfg(monkeypatch, tmp_path, capsys) -> None:
    routing_file = tmp_path / "missing.cfg"
    monkeypatch.setattr(helper, "require_root", lambda: None)
    monkeypatch.setattr(helper, "stop_dns_proxy", lambda **_kwargs: [])
    monkeypatch.setattr(helper, "stop_tunnel", lambda **_kwargs: [])
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)

    result = helper.main(
        [
            "disconnect",
            "--local-only",
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["ok"] is True
    assert "nft delete table inet ssh_vpn_gui" in payload["messages"]
    assert "ip rule del fwmark 2023 table 2023" in payload["messages"]
    assert "ip route flush table 2023" in payload["messages"]
    assert "ip route del 0.0.0.0/1" in payload["messages"]
    assert "ip route del 128.0.0.0/1" in payload["messages"]
    assert "delete routes using claimed tuns" in payload["messages"]


def test_disconnect_fail_closed_blackholes_proxy_without_opening_wan(
    monkeypatch, tmp_path, capsys
) -> None:
    routing_file = tmp_path / "missing.cfg"
    dns_calls = []
    monkeypatch.setattr(helper, "require_root", lambda: None)
    monkeypatch.setattr(
        helper, "stop_dns_proxy", lambda **_kwargs: dns_calls.append(True) or ["dns stopped"]
    )
    monkeypatch.setattr(helper, "stop_tunnel", lambda **_kwargs: ["tunnel stopped"])
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    monkeypatch.setattr("ssh_vpn_gui.system._tuns_holding_app_p2p", lambda: [])

    result = helper.main(
        [
            "disconnect",
            "--fail-closed",
            "--local-only",
            "--server",
            "203.0.113.10",
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["ok"] is True
    assert dns_calls == []
    assert "nft delete table inet ssh_vpn_gui" not in payload["messages"]
    assert "ip route replace blackhole default table 2023 metric 4095" in payload["messages"]
    assert "ip route del 203.0.113.10/32" not in payload["messages"]
    assert "ip route replace 203.0.113.10/32 via <gw> dev <underlay>" in payload["messages"]
    assert any("non-direct traffic is blocked" in line for line in payload["messages"])


def _connect_while_blocked(monkeypatch, tmp_path, extra_args):
    from dataclasses import dataclass

    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    runners = []
    at_ssh_start = []

    @dataclass
    class CapturingRunner(helper.CommandRunner):
        def __post_init__(self):
            runners.append(self)

    def fake_start_tunnel(*_args, **_kwargs):
        at_ssh_start.extend(runners[0].commands)
        return ["ssh started"]

    monkeypatch.setattr(helper, "CommandRunner", CapturingRunner)
    monkeypatch.setattr(helper, "is_fail_closed", lambda: True)
    monkeypatch.setattr(helper, "start_tunnel", fake_start_tunnel)
    monkeypatch.setattr(helper, "stop_tunnel", lambda **_kwargs: [])
    monkeypatch.setattr(helper, "stop_dns_proxy", lambda **_kwargs: [])
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    monkeypatch.setattr("ssh_vpn_gui.system._tuns_holding_app_p2p", lambda: [])

    result = helper.main(
        [
            "connect",
            "--server",
            "198.51.100.7",
            "--password",
            "secret",
            "--routing-file",
            str(routing_file),
            "--dry-run",
            *extra_args,
        ]
    )
    return result, runners[0].commands, at_ssh_start


def test_reconnect_while_blocked_lets_the_server_through_before_ssh(
    monkeypatch, tmp_path, capsys
) -> None:
    result, commands, at_ssh_start = _connect_while_blocked(monkeypatch, tmp_path, [])

    assert result == 0, capsys.readouterr().out
    assert "nft add element inet ssh_vpn_gui direct4 { 198.51.100.7 }" in at_ssh_start
    assert "ip route replace 198.51.100.7/32 via <gw> dev <underlay>" in at_ssh_start
    assert "ip route del 198.51.100.7/32" not in commands
    assert "nft delete table inet ssh_vpn_gui" not in commands
    assert "ip route flush table 2023" not in commands
    assert "ip route replace blackhole default table 2023 metric 4095" in commands


def test_full_tunnel_reconnect_while_blocked_routes_before_dropping_rule_mode(
    monkeypatch, tmp_path, capsys
) -> None:
    result, commands, _ = _connect_while_blocked(monkeypatch, tmp_path, ["--no-routing"])

    assert result == 0, capsys.readouterr().out
    assert "ip route del 198.51.100.7/32" not in commands
    full_tunnel_ready = max(
        commands.index("ip route replace 0.0.0.0/1 dev tun3 src 10.255.3.1"),
        commands.index("ip route replace blackhole 0.0.0.0/1 metric 4095"),
        commands.index("ip route replace 128.0.0.0/1 dev tun3 src 10.255.3.1"),
        commands.index("ip route replace blackhole 128.0.0.0/1 metric 4095"),
    )
    assert commands.index("nft delete table inet ssh_vpn_gui") > full_tunnel_ready
    assert commands.index("ip route flush table 2023") > full_tunnel_ready


def _switch_servers(monkeypatch, tmp_path, secrets, extra_args=()):
    from dataclasses import dataclass

    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    runners = []
    events = []

    @dataclass
    class CapturingRunner(helper.CommandRunner):
        def __post_init__(self):
            runners.append(self)

    def all_commands():
        return [command for runner in runners for command in runner.commands]

    def fake_cleanup_remote(server, login, password, **_kwargs):
        events.append(("cleanup_remote", server, login, password, all_commands()))
        return ["remote cleanup complete"]

    def fake_start_tunnel(server, login, password, **_kwargs):
        events.append(("start_tunnel", server, login, password, all_commands()))
        return ["ssh started"]

    monkeypatch.setattr(helper, "CommandRunner", CapturingRunner)
    monkeypatch.setattr(helper, "is_fail_closed", lambda: False)
    monkeypatch.setattr(helper, "stop_tunnel", lambda **_kwargs: events.append(("stop_tunnel",)) or [])
    monkeypatch.setattr(helper, "cleanup_remote", fake_cleanup_remote)
    monkeypatch.setattr(helper, "start_tunnel", fake_start_tunnel)
    monkeypatch.setattr(helper, "stop_dns_proxy", lambda **_kwargs: [])
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    monkeypatch.setattr("ssh_vpn_gui.system._tuns_holding_app_p2p", lambda: [])
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO(json.dumps(secrets)))

    result = helper.main(
        [
            "connect",
            "--server",
            "192.168.50.3",
            "--previous-server",
            "192.168.50.2",
            "--previous-login",
            "admin",
            "--secrets-stdin",
            "--routing-file",
            str(routing_file),
            "--dry-run",
            *extra_args,
        ]
    )
    return result, events


def test_switching_servers_closes_the_old_tunnel_with_traffic_blocked(monkeypatch, tmp_path, capsys) -> None:
    result, events = _switch_servers(
        monkeypatch, tmp_path, {"password": "new secret", "previous_password": "old secret"}
    )

    captured = capsys.readouterr()
    assert result == 0, captured.out
    names = [event[0] for event in events]
    assert names.index("stop_tunnel") < names.index("cleanup_remote") < names.index("start_tunnel")
    cleanup = events[names.index("cleanup_remote")]
    assert cleanup[1:4] == ("192.168.50.2", "admin", "old secret")
    # The old server is cleaned up behind the block, before its pin goes.
    assert "ip route replace blackhole default table 2023 metric 4095" in cleanup[4]
    assert "ip route del 192.168.50.2/32" not in cleanup[4]
    start = events[names.index("start_tunnel")]
    assert start[1:4] == ("192.168.50.3", "root", "new secret")
    assert "ip route del 192.168.50.2/32" in start[4]
    assert "nft add element inet ssh_vpn_gui direct4 { 192.168.50.3 }" in start[4]
    # Rule mode stays armed until the new tunnel replaces it.
    assert "nft delete table inet ssh_vpn_gui" not in start[4]
    assert "ip route flush table 2023" not in start[4]
    assert "SSH_VPN_GUI_PROGRESS Closing the tunnel to 192.168.50.2..." in captured.err
    assert "SSH_VPN_GUI_PROGRESS Connecting to 192.168.50.3..." in captured.err


def test_switching_servers_without_the_old_password_still_switches(monkeypatch, tmp_path, capsys) -> None:
    result, events = _switch_servers(monkeypatch, tmp_path, {"password": "new secret"}, ["--no-routing"])

    payload = json.loads(capsys.readouterr().out)
    assert result == 0, payload
    names = [event[0] for event in events]
    assert "cleanup_remote" not in names
    assert "start_tunnel" in names
    assert "remote cleanup on 192.168.50.2 skipped: no password" in payload["messages"]
    assert "ip route replace blackhole 0.0.0.0/1 metric 4095" in events[names.index("start_tunnel")][4]


def test_previous_server_is_only_for_connect(tmp_path, capsys) -> None:
    result = helper.main(
        ["disconnect", "--previous-server", "192.168.50.2", "--routing-file", str(tmp_path / "x"), "--dry-run"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 1
    assert payload["error"] == "--previous-server only works with connect"


def test_routing_off_installs_full_tunnel_before_dropping_rule_mode(
    monkeypatch, tmp_path, capsys
) -> None:
    routing_file = tmp_path / "routing.cfg"
    routing_file.write_text("default: proxy\n", encoding="utf-8")
    monkeypatch.setattr(helper, "stop_dns_proxy", lambda **_kwargs: [])
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)

    result = helper.main(
        [
            "routing-off",
            "--server",
            "203.0.113.10",
            "--routing-file",
            str(routing_file),
            "--dry-run",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    messages = payload["messages"]
    assert result == 0
    assert messages.index("ip route replace blackhole 128.0.0.0/1 metric 4095") < messages.index(
        "nft delete table inet ssh_vpn_gui"
    )
    assert "ip route del 0.0.0.0/1" not in messages
    assert not any(line.startswith("delete routes using") for line in messages)


def test_save_routing_rejects_invalid_rules_without_overwriting(
    monkeypatch, tmp_path, capsys
) -> None:
    routing_file = tmp_path / "routing.cfg"
    original = "default: proxy\n"
    routing_file.write_text(original, encoding="utf-8")
    monkeypatch.setattr(helper, "require_root", lambda: None)
    monkeypatch.setattr(helper.sys, "stdin", io.StringIO("this is not a rule\n"))

    result = helper.main(
        [
            "save-routing",
            "--content-stdin",
            "--routing-file",
            str(routing_file),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 1
    assert payload["ok"] is False
    assert "malformed rule" in payload["error"]
    assert routing_file.read_text(encoding="utf-8") == original
