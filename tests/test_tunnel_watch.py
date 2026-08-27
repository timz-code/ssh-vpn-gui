import subprocess

from ssh_vpn_gui import ssh_tunnel
from ssh_vpn_gui.tunnel_watch import (
    TunnelSnapshot,
    evaluate_tunnel_health,
    inspect_tunnel,
    is_tun_peer_reachable,
    is_tun_present,
    should_drop_unresponsive_peer,
)


def test_snapshot_alive_requires_daemon_tun_and_peer() -> None:
    assert TunnelSnapshot(True, True, True).alive is True
    assert TunnelSnapshot(True, True, False).alive is False
    assert TunnelSnapshot(True, False, True).alive is False
    assert TunnelSnapshot(False, True, True).alive is False


def test_snapshot_leftover_and_reason() -> None:
    dead_process = TunnelSnapshot(False, True, False)
    assert dead_process.process_up is False
    assert dead_process.leftover is True
    assert "process is not running" in dead_process.reason

    process_up_peer_down = TunnelSnapshot(True, True, False)
    assert process_up_peer_down.process_up is True
    assert process_up_peer_down.leftover is False
    assert process_up_peer_down.alive is False

    healthy = TunnelSnapshot(True, True, True)
    assert healthy.leftover is False
    assert healthy.as_dict()["alive"] is True
    assert any("reachable" in line for line in healthy.messages())


def test_evaluate_tunnel_health_ignores_peer_until_ping_has_worked() -> None:
    process_only = TunnelSnapshot(True, True, False)
    healthy, usable = evaluate_tunnel_health(
        process_only, require_peer=True, peer_watch_usable=False
    )
    assert healthy is True
    assert usable is False

    healthy, usable = evaluate_tunnel_health(
        process_only, require_peer=True, peer_watch_usable=True
    )
    assert healthy is False
    assert usable is True


def test_evaluate_tunnel_health_marks_peer_usable_after_success() -> None:
    healthy, usable = evaluate_tunnel_health(
        TunnelSnapshot(True, True, True), require_peer=True, peer_watch_usable=False
    )
    assert healthy is True
    assert usable is True


def test_evaluate_tunnel_health_requires_process() -> None:
    healthy, usable = evaluate_tunnel_health(
        TunnelSnapshot(False, True, True), require_peer=False, peer_watch_usable=False
    )
    assert healthy is False
    assert usable is True


def test_should_drop_unresponsive_peer_waits_for_grace_and_failures() -> None:
    assert should_drop_unresponsive_peer(failures=3, elapsed_seconds=5) is False
    assert should_drop_unresponsive_peer(failures=2, elapsed_seconds=20) is False
    assert should_drop_unresponsive_peer(failures=3, elapsed_seconds=15) is True


def test_inspect_tunnel_skips_ping_when_tun_is_down(monkeypatch) -> None:
    ping_calls = []
    monkeypatch.setattr(ssh_tunnel, "is_tunnel_daemon_alive", lambda: True)
    monkeypatch.setattr("ssh_vpn_gui.tunnel_watch.is_tun_present", lambda: False)
    monkeypatch.setattr(
        "ssh_vpn_gui.tunnel_watch.is_tun_peer_reachable",
        lambda **_kwargs: ping_calls.append(True) or True,
    )

    snapshot = inspect_tunnel()

    assert snapshot == TunnelSnapshot(True, False, False)
    assert ping_calls == []


def test_inspect_tunnel_requires_reachable_peer(monkeypatch) -> None:
    monkeypatch.setattr(ssh_tunnel, "is_tunnel_daemon_alive", lambda: True)
    monkeypatch.setattr("ssh_vpn_gui.tunnel_watch.is_tun_present", lambda: True)
    monkeypatch.setattr("ssh_vpn_gui.tunnel_watch.is_tun_peer_reachable", lambda **_kwargs: False)

    snapshot = inspect_tunnel()

    assert snapshot.alive is False
    assert snapshot.peer_reachable is False
    assert "not responding" in snapshot.reason


def test_is_tun_present_reads_operstate(monkeypatch, tmp_path) -> None:
    operstate = tmp_path / "operstate"
    operstate.write_text("up\n", encoding="utf-8")
    monkeypatch.setattr(
        "ssh_vpn_gui.tunnel_watch.Path",
        lambda path: operstate if str(path).endswith("/operstate") else type(operstate)(path),
    )

    assert is_tun_present() is True


def test_is_tun_present_treats_point_to_point_unknown_as_up(monkeypatch, tmp_path) -> None:
    operstate = tmp_path / "operstate"
    operstate.write_text("unknown\n", encoding="utf-8")
    monkeypatch.setattr(
        "ssh_vpn_gui.tunnel_watch.Path",
        lambda path: operstate if str(path).endswith("/operstate") else type(operstate)(path),
    )

    assert is_tun_present() is True


def test_is_tun_peer_reachable_uses_tunnel_interface(monkeypatch) -> None:
    seen = []

    def fake_run(command, **_kwargs):
        seen.append(command)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("ssh_vpn_gui.tunnel_watch.subprocess.run", fake_run)

    assert is_tun_peer_reachable() is True
    assert seen[0][:3] == ["ping", "-n", "-c"]
    assert "-I" in seen[0]
    assert "tun3" in seen[0]
    assert "10.255.3.2" in seen[0]


def test_is_tun_peer_reachable_false_on_timeout(monkeypatch) -> None:
    def timeout_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["ping"], timeout=2)

    monkeypatch.setattr("ssh_vpn_gui.tunnel_watch.subprocess.run", timeout_run)

    assert is_tun_peer_reachable() is False


def test_is_tunnel_daemon_alive_requires_matching_pid(monkeypatch, tmp_path) -> None:
    pid_file = tmp_path / "ssh.pid"
    pid_file.write_text("4242\n", encoding="utf-8")
    monkeypatch.setattr(ssh_tunnel, "SSH_PID", pid_file)
    monkeypatch.setattr(ssh_tunnel, "_pid_runs_module", lambda pid, module: pid == 4242 and "tunnel_daemon" in module)

    assert ssh_tunnel.is_tunnel_daemon_alive() is True

    pid_file.write_text("not-a-pid\n", encoding="utf-8")
    assert ssh_tunnel.is_tunnel_daemon_alive() is False
