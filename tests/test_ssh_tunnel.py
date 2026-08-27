import shlex

import pytest

from ssh_vpn_gui import ssh_tunnel


class HangingDaemon:
    stdin = None
    stdout = None
    stderr = None
    pid = 4242
    terminated = False

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def communicate(self, timeout=None):
        assert self.terminated
        return "", "daemon did not become ready"


class DummyStdin:
    def write(self, _value):
        return None

    def close(self):
        return None


def test_start_tunnel_timeout_terminates_daemon_before_collecting_stderr(monkeypatch, tmp_path) -> None:
    daemon = HangingDaemon()
    daemon.stdin = DummyStdin()
    bootstrap_calls = []

    monkeypatch.setattr(ssh_tunnel, "STATE_DIR", tmp_path)
    monkeypatch.setattr(ssh_tunnel, "ensure_data_dir", lambda: None)
    monkeypatch.setattr(ssh_tunnel, "stop_tunnel", lambda dry_run=False: [])
    monkeypatch.setattr(
        ssh_tunnel,
        "_run_password_ssh",
        lambda command, password, **_kwargs: bootstrap_calls.append((command, password)) or ["remote bootstrap complete"],
    )
    monkeypatch.setattr(ssh_tunnel, "_wait_for_daemon_ready", lambda process, timeout: False)
    monkeypatch.setattr(ssh_tunnel.subprocess, "Popen", lambda *_args, **_kwargs: daemon)

    with pytest.raises(ssh_tunnel.SshTunnelError, match="daemon did not become ready"):
        ssh_tunnel.start_tunnel("203.0.113.10", "root", "secret")

    assert bootstrap_calls
    assert daemon.terminated


def test_start_tunnel_dry_run_bootstraps_before_tun() -> None:
    commands = ssh_tunnel.start_tunnel("203.0.113.10", "root", "secret", dry_run=True)

    assert len(commands) == 2
    assert "-w 3:3" not in commands[0]
    assert "PermitTunnel point-to-point" in commands[0]
    assert "ip rule del from 10.255.3.0/30 table 2124" in commands[0]
    assert "conntrack -D -s 10.255.3.0/30" in commands[0]
    assert "-w 3:3" in commands[1]


def test_ssh_command_quotes_multiline_script_as_one_bash_argument() -> None:
    script = "set -eu\necho 'ready now'\nprintf '%s\\n' \"$HOME\""

    command = ssh_tunnel._ssh_command("203.0.113.10", "root", script, with_tun=False)

    assert shlex.split(command[-1]) == ["bash", "-lc", script]
    assert "TCPKeepAlive=yes" in command
    assert "ServerAliveInterval=5" in command
    assert "ServerAliveCountMax=2" in command


def test_start_tunnel_dry_run_inserts_ovpn_bootstrap_before_tun() -> None:
    commands = ssh_tunnel.start_tunnel(
        "203.0.113.10", "root", "secret", dry_run=True, ovpn_b64="Zm9vYmFy"
    )

    assert len(commands) == 3
    assert "PermitTunnel point-to-point" in commands[0]
    assert "openvpn --config" in commands[1]
    assert "apt-get install -y openvpn conntrack" in commands[1]
    assert "-w 3:3" not in commands[1]
    assert "-w 3:3" in commands[2]


def test_start_tunnel_runs_ovpn_bootstrap_step(monkeypatch, tmp_path) -> None:
    daemon = HangingDaemon()
    daemon.stdin = DummyStdin()
    ssh_calls = []

    monkeypatch.setattr(ssh_tunnel, "STATE_DIR", tmp_path)
    monkeypatch.setattr(ssh_tunnel, "ensure_data_dir", lambda: None)
    monkeypatch.setattr(ssh_tunnel, "stop_tunnel", lambda dry_run=False: [])
    monkeypatch.setattr(
        ssh_tunnel,
        "_run_password_ssh",
        lambda command, password, **kwargs: ssh_calls.append(kwargs.get("success_message"))
        or [kwargs.get("success_message", "")],
    )
    monkeypatch.setattr(ssh_tunnel, "_wait_for_daemon_ready", lambda process, timeout: False)
    monkeypatch.setattr(ssh_tunnel.subprocess, "Popen", lambda *_args, **_kwargs: daemon)

    with pytest.raises(ssh_tunnel.SshTunnelError):
        ssh_tunnel.start_tunnel("203.0.113.10", "root", "secret", ovpn_b64="Zm9vYmFy")

    assert "remote bootstrap complete" in ssh_calls
    assert "remote OpenVPN cascade ready" in ssh_calls


def test_stop_remote_ovpn_only_removes_cascade_state() -> None:
    commands = ssh_tunnel.stop_remote_ovpn(
        "203.0.113.10", "root", "secret", dry_run=True
    )

    assert len(commands) == 1
    assert "ip rule del from 10.255.3.0/30 table 2124" in commands[0]
    assert "ip route flush table 2124" in commands[0]
    assert "conntrack -D -s 10.255.3.0/30" in commands[0]
    assert "ip addr flush dev tun3" not in commands[0]
    assert "-w 3:3" not in commands[0]
