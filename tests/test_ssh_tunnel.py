import os
import re
import shlex

import pytest

from ssh_vpn_gui import ssh_tunnel
from ssh_vpn_gui.cascade import Cascade, socks5_proxy
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
    "SSH_VPN_OBFS 443 " + "ab" * 32,
]
OVPN_MESSAGES = [
    "remote OpenVPN second hop ready",
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
    monkeypatch.setattr(ssh_tunnel, "port_reachable", lambda *_args, **_kwargs: True)
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


def test_start_tunnel_records_server_as_underlay(monkeypatch, tmp_path) -> None:
    saved: list[TunnelBinding] = []
    daemon = HangingDaemon()
    daemon.stdin = DummyStdin()

    monkeypatch.setattr(ssh_tunnel, "STATE_DIR", tmp_path)
    monkeypatch.setattr(ssh_tunnel, "SSH_PID", tmp_path / "ssh.pid")
    monkeypatch.setattr(ssh_tunnel, "ensure_data_dir", lambda: None)
    monkeypatch.setattr(ssh_tunnel, "stop_tunnel", lambda dry_run=False: [])
    monkeypatch.setattr(ssh_tunnel, "port_reachable", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        ssh_tunnel,
        "_run_password_ssh",
        lambda command, password, **_kwargs: list(BOOTSTRAP_MESSAGES),
    )
    monkeypatch.setattr(ssh_tunnel, "allocate_tunnel_binding", lambda _output: CLAIMED)
    monkeypatch.setattr(ssh_tunnel, "save_tunnel_state", saved.append)
    monkeypatch.setattr(ssh_tunnel, "_wait_for_daemon_ready", lambda process, timeout: True)
    monkeypatch.setattr(ssh_tunnel.subprocess, "Popen", lambda *_args, **_kwargs: daemon)

    messages = ssh_tunnel.start_tunnel("192.168.50.2", "root", "secret")

    assert saved[0].server == "192.168.50.2"
    assert saved[0].local_tun == CLAIMED.local_tun
    assert any("started ssh tunnel daemon" in line for line in messages)


def test_start_tunnel_dry_run_bootstraps_before_tun() -> None:
    commands = ssh_tunnel.start_tunnel("203.0.113.10", "root", "secret", dry_run=True)

    assert len(commands) == 2
    assert not re.search(r"-w \d+:\d+", commands[0])
    assert "PermitTunnel point-to-point" in commands[0]
    assert "SSH_VPN_REMOTE_TUN" in commands[0]
    assert "SSH_VPN_OBFS" not in commands[0]
    assert "SSH_VPN_ADDR" in commands[0]
    assert "ip rule del table 2124" in commands[0]
    assert "conntrack -D -s 10.255.0.0/16" in commands[0]
    assert re.search(r"-w \d+:\d+", commands[1])


def test_start_tunnel_dry_run_hides_in_tls_only_when_asked() -> None:
    plain = ssh_tunnel.start_tunnel("192.168.50.2", "root", "secret", dry_run=True)
    hidden = ssh_tunnel.start_tunnel("192.168.50.2", "root", "secret", dry_run=True, tls=True)

    assert "SSH_VPN_OBFS" not in plain[0]
    assert "SSH_VPN_OBFS" in hidden[0]
    assert 'obfs.py" serve' in hidden[0]
    assert not any(part.startswith("ProxyCommand=") for part in plain[1].split())


def test_ssh_command_quotes_multiline_script_as_one_bash_argument() -> None:
    script = "set -eu\necho 'ready now'\nprintf '%s\\n' \"$HOME\""

    command = ssh_tunnel._ssh_command("203.0.113.10", "root", script, with_tun=False)

    assert shlex.split(command[-1]) == ["bash", "-lc", script]
    assert "TCPKeepAlive=yes" in command
    assert "ServerAliveInterval=5" in command
    assert "ServerAliveCountMax=2" in command


def test_tun_ssh_goes_through_the_tls_forwarder() -> None:
    pin = "ab" * 32
    command = ssh_tunnel._ssh_command(
        "192.168.50.2",
        "root",
        "echo SSH_VPN_READY",
        binding=CLAIMED,
        obfs=(443, pin),
    )

    proxy = next(part.split("=", 1)[1] for part in command if part.startswith("ProxyCommand="))
    assert proxy == f"python3 -m ssh_vpn_gui.obfs relay 192.168.50.2 443 {pin}"
    assert "-p" not in command
    plain = ssh_tunnel._ssh_command("192.168.50.2", "root", "echo ok", with_tun=False)
    assert not any(part.startswith("ProxyCommand=") for part in plain)


def test_start_tunnel_dry_run_inserts_ovpn_bootstrap_before_tun() -> None:
    commands = ssh_tunnel.start_tunnel(
        "203.0.113.10", "root", "secret", dry_run=True, cascade=Cascade("ovpn", ovpn_b64="Zm9vYmFy")
    )

    assert len(commands) == 3
    assert "PermitTunnel point-to-point" in commands[0]
    assert "--config /etc/ssh-vpn-gui/client.ovpn" in commands[1]
    assert "SSH_VPN_INSTALLING OpenVPN" in commands[1]
    assert "DPkg::Lock::Timeout=300" in commands[1]
    assert "apt-get -o DPkg::Lock::Timeout=300 install -y openvpn conntrack" in commands[1]
    assert "seq 1 90" in commands[1]
    assert "--resolv-retry 3" in commands[1]
    assert "--connect-timeout 8" in commands[1]
    assert "--disable-dco" in commands[1]
    assert "--persist-tun" in commands[1]
    assert "--server-poll-timeout 8" in commands[1]
    assert "--connect-retry-max 1" in commands[1]
    assert "timeout 8 openvpn" not in commands[1]
    assert "timeout 25 openvpn" not in commands[1]
    assert "SSH_VPN_PROGRESS Starting OpenVPN on the server" in commands[1]
    assert "openvpn|ssh-vpn-gui-ovpn" in commands[1]
    daemon_start = commands[1].index("--daemon ssh-vpn-gui-ovpn")
    assert commands[1].index("SSH_VPN_PROGRESS Clearing the previous second hop") < daemon_start
    assert commands[1].index("unreachable default table 2124") < daemon_start
    assert commands[1].index("|| _ssh_vpn_gui_stop_cascade >/dev/null 2>&1") < daemon_start
    assert 'ip route replace default dev "$ovpn_dev" table 2124' in commands[1]
    assert "openvpn failed to connect to the VPN server" in commands[1]
    assert "AUTH_FAILED" in commands[1]
    assert "SSH_VPN_REMOTE_OVPN" in commands[1]
    assert '--dev "$ovpn_dev"' in commands[1]
    assert "--dev ovpn0" not in commands[1]
    assert not re.search(r"-w \d+:\d+", commands[1])
    assert re.search(r"-w \d+:\d+", commands[2])


def test_start_tunnel_dry_run_runs_tor_and_socks5_before_tun() -> None:
    tor = ssh_tunnel.start_tunnel("203.0.113.10", "root", "secret", dry_run=True, cascade=Cascade("tor"))
    socks5 = ssh_tunnel.start_tunnel(
        "203.0.113.10",
        "root",
        "secret",
        dry_run=True,
        cascade=Cascade("socks5", socks5=socks5_proxy("192.168.50.20", 1080)),
    )

    for commands, marker in ((tor, "tor -f /etc/ssh-vpn-gui/torrc"), (socks5, "redsocks -c /etc/ssh-vpn-gui/redsocks.conf")):
        assert len(commands) == 3
        assert marker in commands[1]
        assert "SSH_VPN_CASCADE_READY" in commands[1]
        assert not re.search(r"-w \d+:\d+", commands[1])
        assert re.search(r"-w \d+:\d+", commands[2])


def test_start_tunnel_runs_ovpn_bootstrap_step(monkeypatch, tmp_path) -> None:
    daemon = HangingDaemon()
    daemon.stdin = DummyStdin()
    ssh_calls = []

    monkeypatch.setattr(ssh_tunnel, "STATE_DIR", tmp_path)
    monkeypatch.setattr(ssh_tunnel, "ensure_data_dir", lambda: None)
    monkeypatch.setattr(ssh_tunnel, "stop_tunnel", lambda dry_run=False: [])
    monkeypatch.setattr(ssh_tunnel, "port_reachable", lambda *_args, **_kwargs: True)
    def fake_ssh(command, password, **kwargs):
        message = kwargs.get("success_message")
        ssh_calls.append(message)
        if message == "remote bootstrap complete":
            return list(BOOTSTRAP_MESSAGES)
        if message == "remote OpenVPN second hop ready":
            return list(OVPN_MESSAGES)
        return [message or ""]

    recorded_devices: list[str] = []
    monkeypatch.setattr(ssh_tunnel, "_run_password_ssh", fake_ssh)
    monkeypatch.setattr(ssh_tunnel, "allocate_tunnel_binding", lambda _output: CLAIMED)
    monkeypatch.setattr(ssh_tunnel, "save_tunnel_state", lambda _binding: None)
    monkeypatch.setattr(ssh_tunnel, "update_tunnel_ovpn", recorded_devices.append)
    monkeypatch.setattr(ssh_tunnel, "_wait_for_daemon_ready", lambda process, timeout: False)
    monkeypatch.setattr(ssh_tunnel.subprocess, "Popen", lambda *_args, **_kwargs: daemon)

    with pytest.raises(ssh_tunnel.SshTunnelError):
        ssh_tunnel.start_tunnel(
            "203.0.113.10", "root", "secret", cascade=Cascade("ovpn", ovpn_b64="Zm9vYmFy")
        )

    assert ssh_calls[:2] == ["remote bootstrap complete", "remote OpenVPN second hop ready"]
    assert recorded_devices == ["ovpn2"]


def test_start_remote_cascade_needs_a_running_tunnel(monkeypatch) -> None:
    monkeypatch.setattr(ssh_tunnel, "load_tunnel_state", lambda: None)

    with pytest.raises(ssh_tunnel.SshTunnelError, match="Connect first"):
        ssh_tunnel.start_remote_cascade("203.0.113.10", "root", "secret", Cascade("tor"))


def test_start_remote_cascade_runs_against_the_live_tunnel(monkeypatch) -> None:
    commands: list[list[str]] = []
    recorded_devices: list[str] = []
    monkeypatch.setattr(ssh_tunnel, "load_tunnel_state", lambda: CLAIMED)
    monkeypatch.setattr(ssh_tunnel, "ensure_data_dir", lambda: None)
    monkeypatch.setattr(ssh_tunnel, "update_tunnel_ovpn", recorded_devices.append)
    monkeypatch.setattr(
        ssh_tunnel,
        "_run_password_ssh",
        lambda command, _password, **kwargs: commands.append(command) or [kwargs["success_message"]],
    )

    messages = ssh_tunnel.start_remote_cascade("203.0.113.10", "root", "secret", Cascade("tor"))

    assert messages == ["remote Tor second hop ready"]
    script = shlex.split(commands[0][-1])[2]
    assert "cidr='10.255.8.0/30'" in script
    assert "ssh_tun='tun5'" in script
    assert recorded_devices == [""]


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


def test_cascade_messages_report_leftovers_and_installs() -> None:
    assert ssh_tunnel._cascade_messages("SSH_VPN_OVPN_LEFTOVERS 0") == []
    assert ssh_tunnel._cascade_messages("SSH_VPN_OVPN_LEFTOVERS 1") == [
        "cleared 1 leftover remote OpenVPN client"
    ]
    assert ssh_tunnel._cascade_messages("SSH_VPN_OVPN_LEFTOVERS 8") == [
        "cleared 8 leftover remote OpenVPN clients"
    ]
    assert ssh_tunnel._cascade_messages("SSH_VPN_INSTALLING OpenVPN") == [
        "installed OpenVPN on the remote server"
    ]
    assert ssh_tunnel._cascade_messages("SSH_VPN_INSTALLING Tor") == ["installed Tor on the remote server"]


def test_emit_progress_forwards_only_progress_lines() -> None:
    seen: list[str] = []
    ssh_tunnel._emit_progress(
        "SSH_VPN_INSTALLING Tor\nSSH_VPN_PROGRESS Installing Tor on the server\r\n"
        "SSH_VPN_PROGRESS Connecting to the Tor network: 45%\n",
        seen.append,
    )
    assert seen == ["Installing Tor on the server", "Connecting to the Tor network: 45%"]


def test_clean_ssh_output_drops_progress_lines() -> None:
    output = "SSH_VPN_PROGRESS Starting Tor on the server\r\ntor exited during startup\r\n"

    assert ssh_tunnel._clean_ssh_output(output) == "tor exited during startup"


def test_stop_remote_cascade_only_removes_second_hop_state(monkeypatch) -> None:
    monkeypatch.setattr("ssh_vpn_gui.system.load_tunnel_state", lambda: None)
    commands = ssh_tunnel.stop_remote_cascade(
        "203.0.113.10", "root", "secret", dry_run=True
    )

    assert len(commands) == 1
    assert "ip rule del priority 2123" in commands[0]
    assert "ip rule del table 2124" in commands[0]
    assert "ip route flush table 2124" in commands[0]
    assert "nft delete table ip ssh_vpn_gui_cascade" in commands[0]
    assert "conntrack -D -s 10.255.0.0/16" in commands[0]
    assert "openvpn|ssh-vpn-gui-ovpn" in commands[0]
    assert "_ssh_vpn_gui_ovpn_pids" in commands[0]
    assert "_ssh_vpn_gui_daemon_pids" in commands[0]
    assert "kill -\"$_sig\"" in commands[0] or "kill -TERM" in commands[0]
    assert 'ip addr flush dev "$ovpn_dev"' in commands[0]
    assert 'ip link del "$ovpn_dev"' in commands[0]
    assert "SSH_VPN_CASCADE_STOPPED" in commands[0]
    assert "ip addr flush dev tun3" not in commands[0]
    assert "route_localnet" not in commands[0]
    assert not re.search(r"-w \d+:\d+", commands[0])


def test_tunnel_daemon_started_at_is_the_pid_file_mtime(monkeypatch, tmp_path) -> None:
    pid_file = tmp_path / "ssh.pid"
    pid_file.write_text("4242\n", encoding="utf-8")
    when = 1_700_000_000
    os.utime(pid_file, (when, when))
    monkeypatch.setattr(ssh_tunnel, "SSH_PID", pid_file)
    monkeypatch.setattr(
        ssh_tunnel, "_pid_runs_module", lambda pid, module: pid == 4242 and "tunnel_daemon" in module
    )

    assert ssh_tunnel.tunnel_daemon_started_at() == when


def test_tunnel_daemon_started_at_is_none_without_a_live_daemon(monkeypatch, tmp_path) -> None:
    pid_file = tmp_path / "ssh.pid"
    pid_file.write_text("4242\n", encoding="utf-8")
    monkeypatch.setattr(ssh_tunnel, "SSH_PID", pid_file)
    monkeypatch.setattr(ssh_tunnel, "_pid_runs_module", lambda *_args: False)

    assert ssh_tunnel.tunnel_daemon_started_at() is None
    pid_file.unlink()
    assert ssh_tunnel.tunnel_daemon_started_at() is None
