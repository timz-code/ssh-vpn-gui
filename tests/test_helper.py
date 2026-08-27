import io
import json
import subprocess

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
    assert "ip rule del from 10.255.3.0/30 table 2124" in payload["messages"][0]
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
    assert "openvpn --config /etc/ssh-vpn-gui/client.ovpn" in payload["messages"][0]
    assert "-w 3:3" not in payload["messages"][0]


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
    monkeypatch.setattr(helper, "start_remote_ovpn", lambda *_args, **_kwargs: ["cascade ready"])
    monkeypatch.setattr(
        helper,
        "stop_remote_ovpn",
        lambda *_args, **_kwargs: stopped.append(True) or ["cascade stopped"],
    )
    monkeypatch.setattr(helper, "_curl_public_ip", lambda: next(public_ips))

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
    assert "was stopped" in payload["error"]
    assert "198.51.100.10" in payload["error"]


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
    assert "delete routes using tun3" in payload["messages"]


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
