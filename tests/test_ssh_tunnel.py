import re
import shlex

import pytest

from ssh_vpn_gui import ssh_tunnel
from ssh_vpn_gui.system import TunnelBinding

CLAIMED = TunnelBinding(
    local_tun="tun4",
    remote_tun="tun5",
    local_address="10.255.8.1",
    remote_address="10.255.8.2",
    cidr="10.255.8.0/30",
)

BOOTSTRAP_MESSAGES = [
    "remote bootstrap complete",
    "SSH_VPN_REMOTE_TUN tun5",
    "SSH_VPN_ADDR 10.255.8.1 10.255.8.2 10.255.8.0/30",
]
OVPN_MESSAGES = [
    "remote OpenVPN cascade ready",
    "SSH_VPN_REMOTE_OVPN ovpn2",
]


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
        lambda command, password, **_kwargs: bootstrap_calls.append((command, password)) or list(BOOTSTRAP_MESSAGES),
    )
    monkeypatch.setattr(ssh_tunnel, "allocate_tunnel_binding", lambda _output: CLAIMED)
    monkeypatch.setattr(ssh_tunnel, "save_tunnel_state", lambda _binding: None)
    monkeypatch.setattr(ssh_tunnel, "_wait_for_daemon_ready", lambda process, timeout: False)
    monkeypatch.setattr(ssh_tunnel.subprocess, "Popen", lambda *_args, **_kwargs: daemon)

    with pytest.raises(ssh_tunnel.SshTunnelError, match="daemon did not become ready"):
        ssh_tunnel.start_tunnel("203.0.113.10", "root", "secret")

    assert bootstrap_calls
    assert daemon.terminated


def test_start_tunnel_dry_run_bootstraps_before_tun() -> None:
    commands = ssh_tunnel.start_tunnel("203.0.113.10", "root", "secret", dry_run=True)

    assert len(commands) == 2
    assert not re.search(r"-w \d+:\d+", commands[0])
    assert "PermitTunnel point-to-point" in commands[0]
    assert "SSH_VPN_REMOTE_TUN" in commands[0]
    assert "SSH_VPN_ADDR" in commands[0]
    assert "ip rule del table 2124" in commands[0]
    assert "conntrack -D -s 10.255.0.0/16" in commands[0]
    assert re.search(r"-w \d+:\d+", commands[1])


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
    assert "--config /etc/ssh-vpn-gui/client.ovpn" in commands[1]
    assert "SSH_VPN_OVPN_INSTALLING" in commands[1]
    assert "DPkg::Lock::Timeout=300" in commands[1]
    assert "apt-get -o DPkg::Lock::Timeout=300 install -y openvpn conntrack" in commands[1]
    assert "seq 1 90" in commands[1]
    assert "--resolv-retry 3" in commands[1]
    assert "--connect-timeout 8" in commands[1]
    assert "--server-poll-timeout 8" in commands[1]
    assert "--connect-retry-max 1" in commands[1]
    assert "timeout 8 openvpn" not in commands[1]
    assert "timeout 25 openvpn" not in commands[1]
    assert "SSH_VPN_OVPN_PROGRESS" in commands[1]
    assert "SSH_VPN_OVPN_REAP_BEFORE_START" in commands[1]
    assert "openvpn|ssh-vpn-gui-ovpn" in commands[1]
    assert commands[1].index("SSH_VPN_OVPN_REAP_BEFORE_START") < commands[1].index(
        "--daemon ssh-vpn-gui-ovpn"
    )
    assert "openvpn failed to connect to the VPN server" in commands[1]
    assert "AUTH_FAILED" in commands[1]
    assert "SSH_VPN_REMOTE_OVPN" in commands[1]
    assert '--dev "$ovpn_dev"' in commands[1]
    assert "--dev ovpn0" not in commands[1]
    assert not re.search(r"-w \d+:\d+", commands[1])
    assert re.search(r"-w \d+:\d+", commands[2])


def test_start_tunnel_runs_ovpn_bootstrap_step(monkeypatch, tmp_path) -> None:
    daemon = HangingDaemon()
    daemon.stdin = DummyStdin()
    ssh_calls = []

    monkeypatch.setattr(ssh_tunnel, "STATE_DIR", tmp_path)
    monkeypatch.setattr(ssh_tunnel, "ensure_data_dir", lambda: None)
    monkeypatch.setattr(ssh_tunnel, "stop_tunnel", lambda dry_run=False: [])
    def fake_ssh(command, password, **kwargs):
        message = kwargs.get("success_message")
        ssh_calls.append(message)
        if message == "remote bootstrap complete":
            return list(BOOTSTRAP_MESSAGES)
        if message == "remote OpenVPN cascade ready":
            return list(OVPN_MESSAGES)
        return [message or ""]

    monkeypatch.setattr(ssh_tunnel, "_run_password_ssh", fake_ssh)
    monkeypatch.setattr(ssh_tunnel, "allocate_tunnel_binding", lambda _output: CLAIMED)
    monkeypatch.setattr(ssh_tunnel, "save_tunnel_state", lambda _binding: None)
    monkeypatch.setattr(ssh_tunnel, "update_tunnel_ovpn", lambda _dev: None)
    monkeypatch.setattr(ssh_tunnel, "_wait_for_daemon_ready", lambda process, timeout: False)
    monkeypatch.setattr(ssh_tunnel.subprocess, "Popen", lambda *_args, **_kwargs: daemon)

    with pytest.raises(ssh_tunnel.SshTunnelError):
        ssh_tunnel.start_tunnel("203.0.113.10", "root", "secret", ovpn_b64="Zm9vYmFy")

    assert "remote bootstrap complete" in ssh_calls
    assert "remote OpenVPN cascade ready" in ssh_calls


def test_cleanup_remote_reaps_every_managed_openvpn() -> None:
    commands = ssh_tunnel.cleanup_remote(
        "203.0.113.10", "root", "secret", dry_run=True
    )

    assert len(commands) == 1
    assert "_ssh_vpn_gui_ovpn_pids" in commands[0]
    assert "/etc/ssh-vpn-gui/client.ovpn" in commands[0]
    assert 'ip link del "$ovpn_dev"' in commands[0]
    assert "ip addr flush dev tun3" not in commands[0]
    assert "/sys/class/net/tun*" in commands[0]


def test_ovpn_reap_messages_report_leftover_count() -> None:
    assert ssh_tunnel._ovpn_reap_messages("SSH_VPN_OVPN_LEFTOVERS 0") == []
    assert ssh_tunnel._ovpn_reap_messages("SSH_VPN_OVPN_LEFTOVERS 1") == [
        "cleared 1 leftover remote OpenVPN client"
    ]
    assert ssh_tunnel._ovpn_reap_messages("SSH_VPN_OVPN_LEFTOVERS 8") == [
        "cleared 8 leftover remote OpenVPN clients"
    ]
    assert ssh_tunnel._ovpn_reap_messages("SSH_VPN_OVPN_INSTALLING") == [
        "installed OpenVPN packages on the remote server"
    ]


def test_emit_ovpn_progress_reports_install_phase() -> None:
    seen: list[str] = []
    ssh_tunnel._emit_ovpn_progress(
        "SSH_VPN_OVPN_INSTALLING\nSSH_VPN_OVPN_PROGRESS Installing OpenVPN packages on the server\n",
        seen.append,
    )
    assert seen == [
        "Installing OpenVPN packages on the server...",
        "Installing OpenVPN packages on the server",
    ]


def test_stop_remote_ovpn_only_removes_cascade_state() -> None:
    commands = ssh_tunnel.stop_remote_ovpn(
        "203.0.113.10", "root", "secret", dry_run=True
    )

    assert len(commands) == 1
    assert "ip rule del table 2124" in commands[0]
    assert "ip route flush table 2124" in commands[0]
    assert "conntrack -D -s 10.255.0.0/16" in commands[0]
    assert "openvpn|ssh-vpn-gui-ovpn" in commands[0]
    assert "_ssh_vpn_gui_ovpn_pids" in commands[0]
    assert "kill -\"$_sig\"" in commands[0] or "kill -TERM" in commands[0]
    assert 'ip addr flush dev "$ovpn_dev"' in commands[0]
    assert 'ip link del "$ovpn_dev"' in commands[0]
    assert "ip addr flush dev tun3" not in commands[0]
    assert not re.search(r"-w \d+:\d+", commands[0])
