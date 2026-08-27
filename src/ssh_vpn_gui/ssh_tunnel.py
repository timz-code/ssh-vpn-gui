from __future__ import annotations

import os
from pathlib import Path
import select
import shlex
import subprocess
import sys
import time

import pexpect

from .system import (
    KNOWN_HOSTS,
    STATE_DIR,
    ensure_data_dir,
    remote_bootstrap_script,
    remote_cleanup_command,
    remote_ovpn_bootstrap_script,
    remote_ovpn_cleanup_command,
    remote_setup_script,
)

SSH_PID = STATE_DIR / "ssh.pid"
OVPN_BOOTSTRAP_TIMEOUT = 240


class SshTunnelError(RuntimeError):
    pass


def start_tunnel(
    server: str,
    login: str,
    password: str,
    *,
    dry_run: bool = False,
    timeout: int = 30,
    ovpn_b64: str | None = None,
) -> list[str]:
    bootstrap_command = _ssh_command(server, login, remote_bootstrap_script(), with_tun=False)
    command = _ssh_command(server, login, remote_setup_script())
    ovpn_command = (
        _ssh_command(server, login, remote_ovpn_bootstrap_script(ovpn_b64), with_tun=False)
        if ovpn_b64
        else None
    )
    if dry_run:
        commands = [" ".join(shlex.quote(part) for part in bootstrap_command)]
        if ovpn_command is not None:
            commands.append(" ".join(shlex.quote(part) for part in ovpn_command))
        commands.append(" ".join(shlex.quote(part) for part in command))
        return commands

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ensure_data_dir()
    stop_tunnel(dry_run=False)
    messages = _run_password_ssh(bootstrap_command, password, timeout=timeout, success_message="remote bootstrap complete")
    if ovpn_command is not None:
        messages.extend(
            _run_password_ssh(
                ovpn_command,
                password,
                timeout=OVPN_BOOTSTRAP_TIMEOUT,
                success_message="remote OpenVPN cascade ready",
            )
        )

    daemon = subprocess.Popen(
        [sys.executable, "-m", "ssh_vpn_gui.tunnel_daemon", server, login],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert daemon.stdin is not None
    daemon.stdin.write(password + "\n")
    daemon.stdin.close()
    daemon.stdin = None

    ready = _wait_for_daemon_ready(daemon, timeout)
    if not ready:
        daemon.terminate()
        try:
            _, stderr = daemon.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            daemon.kill()
            _, stderr = daemon.communicate(timeout=3)
        raise SshTunnelError((stderr or "").strip() or "Timed out waiting for SSH tunnel daemon")

    SSH_PID.write_text(str(daemon.pid), encoding="utf-8")
    return [*messages, f"started ssh tunnel daemon pid {daemon.pid}"]


def is_tunnel_daemon_alive() -> bool:
    if not SSH_PID.exists():
        return False
    try:
        pid = int(SSH_PID.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    return _pid_runs_module(pid, "ssh_vpn_gui.tunnel_daemon")


def stop_tunnel(*, dry_run: bool = False) -> list[str]:
    messages: list[str] = []
    if SSH_PID.exists():
        try:
            pid = int(SSH_PID.read_text(encoding="utf-8").strip())
        except ValueError:
            SSH_PID.unlink(missing_ok=True)
            return messages
        if dry_run:
            return [f"verify ssh_vpn_gui.tunnel_daemon pid {pid}", f"kill {pid}"]
        if _pid_runs_module(pid, "ssh_vpn_gui.tunnel_daemon"):
            _terminate_pid(pid)
            messages.append(f"stopped ssh tunnel pid {pid}")
        SSH_PID.unlink(missing_ok=True)
    return messages


def cleanup_remote(server: str, login: str, password: str, *, dry_run: bool = False, timeout: int = 20) -> list[str]:
    command = _ssh_command(server, login, remote_cleanup_command(), with_tun=False)
    if dry_run:
        return [" ".join(shlex.quote(part) for part in command)]

    ensure_data_dir()
    return _run_password_ssh(command, password, timeout=timeout, success_message="remote cleanup complete")


def start_remote_ovpn(
    server: str,
    login: str,
    password: str,
    ovpn_b64: str,
    *,
    dry_run: bool = False,
) -> list[str]:
    command = _ssh_command(server, login, remote_ovpn_bootstrap_script(ovpn_b64), with_tun=False)
    if dry_run:
        return [" ".join(shlex.quote(part) for part in command)]
    ensure_data_dir()
    return _run_password_ssh(
        command,
        password,
        timeout=OVPN_BOOTSTRAP_TIMEOUT,
        success_message="remote OpenVPN cascade ready",
    )


def stop_remote_ovpn(
    server: str,
    login: str,
    password: str,
    *,
    dry_run: bool = False,
    timeout: int = 30,
) -> list[str]:
    command = _ssh_command(server, login, remote_ovpn_cleanup_command(), with_tun=False)
    if dry_run:
        return [" ".join(shlex.quote(part) for part in command)]
    ensure_data_dir()
    return _run_password_ssh(
        command,
        password,
        timeout=timeout,
        success_message="remote OpenVPN cascade stopped",
    )


def _run_password_ssh(command: list[str], password: str, *, timeout: int, success_message: str | None = None) -> list[str]:
    child = pexpect.spawn(command[0], command[1:], encoding="utf-8", timeout=timeout)
    try:
        transcript = ""
        while True:
            index = child.expect(
                [
                    r"(?i)password:",
                    r"(?i)are you sure you want to continue connecting",
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ]
            )
            transcript += child.before or ""
            if index == 0:
                child.sendline(password)
            elif index == 1:
                child.sendline("yes")
            elif index == 2:
                child.close()
                if child.exitstatus not in (None, 0):
                    raise SshTunnelError(_clean_ssh_output(transcript) or f"SSH exited with {child.exitstatus}")
                output = _clean_ssh_output(transcript)
                return [success_message] if success_message else ([output] if output else [])
            else:
                raise SshTunnelError(_clean_ssh_output(transcript) or "Timed out during SSH command")
    finally:
        child.close(force=True)


def _clean_ssh_output(output: str) -> str:
    lines = [
        line.strip()
        for line in output.replace("\r", "").splitlines()
        if line.strip() and "bind: warning: line editing not enabled" not in line
    ]
    return "\n".join(lines)


def _ssh_command(server: str, login: str, remote_command: str, *, with_tun: bool = True) -> list[str]:
    command = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o",
        "TCPKeepAlive=yes",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
    ]
    if with_tun:
        command.extend(["-o", "ExitOnForwardFailure=yes", "-w", "3:3"])
    # OpenSSH joins all arguments after the host into one remote shell command;
    # argument boundaries are not preserved. Quote the complete script so
    # bash receives it as the single argument belonging to -c.
    command.extend([f"{login}@{server}", f"bash -lc {shlex.quote(remote_command)}"])
    return command


def _terminate_pid(pid: int) -> None:
    if not Path(f"/proc/{pid}").exists():
        return
    os.kill(pid, 15)
    for _ in range(30):
        if not Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    os.kill(pid, 9)


def _pid_runs_module(pid: int, module: str) -> bool:
    try:
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    encoded_module = module.encode()
    return b"-m" in argv and encoded_module in argv


def _wait_for_daemon_ready(process: subprocess.Popen[str], timeout: int) -> bool:
    assert process.stdout is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        remaining = max(0.1, deadline - time.monotonic())
        readable, _, _ = select.select([process.stdout], [], [], min(0.2, remaining))
        if not readable:
            continue
        line = process.stdout.readline()
        if line.strip() == "SSH_VPN_READY":
            return True
    return False
