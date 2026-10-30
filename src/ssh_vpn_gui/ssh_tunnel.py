from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import os
from pathlib import Path
import select
import shlex
import subprocess
import sys
import time

import pexpect

from .cascade import Cascade, remote_cascade_script
from .system import (
    CASCADE_BOOTSTRAP_TIMEOUT_SECONDS,
    KNOWN_HOSTS,
    STATE_DIR,
    TunnelBinding,
    allocate_tunnel_binding,
    ensure_data_dir,
    load_tunnel_state,
    parse_remote_allocation,
    placeholder_tunnel_binding,
    remote_bootstrap_script,
    remote_cascade_cleanup_command,
    remote_cleanup_command,
    remote_setup_script,
    save_tunnel_state,
    update_tunnel_ovpn,
)
from .obfs import parse_obfs_line, port_reachable, proxy_command

SSH_PID = STATE_DIR / "ssh.pid"


class SshTunnelError(RuntimeError):
    pass


def start_tunnel(
    server: str,
    login: str,
    password: str,
    *,
    dry_run: bool = False,
    timeout: int = 30,
    cascade: Cascade | None = None,
    tls: bool = False,
    on_progress: Callable[[str], None] | None = None,
) -> list[str]:
    bootstrap_command = _ssh_command(
        server, login, remote_bootstrap_script(tls=tls), with_tun=False
    )
    if dry_run:
        binding = placeholder_tunnel_binding()
        commands = [_quoted(bootstrap_command)]
        if cascade is not None:
            commands.append(_quoted(_cascade_command(server, login, cascade, binding)))
        commands.append(_quoted(_ssh_command(server, login, remote_setup_script(binding), binding=binding)))
        return commands

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ensure_data_dir()
    stop_tunnel(dry_run=False)
    messages = _run_password_ssh(
        bootstrap_command,
        password,
        timeout=timeout,
        success_message="remote bootstrap complete",
        on_progress=on_progress,
    )
    try:
        binding = allocate_tunnel_binding("\n".join(messages))
    except RuntimeError as exc:
        raise SshTunnelError(str(exc)) from exc
    binding = replace(binding, server=server)
    save_tunnel_state(binding)
    if tls:
        obfs = parse_obfs_line(messages)
        if obfs is None:
            raise SshTunnelError("server did not start the TLS forwarder")
        obfs_port, obfs_pin = obfs
        _save_obfs(obfs_port, obfs_pin)
        if not port_reachable(server, obfs_port):
            raise SshTunnelError(
                f"TLS port {obfs_port} on the server is not reachable. "
                "Open that port in the VPS provider firewall. "
                "The tunnel is sent as TLS data transfer, not as SSH."
            )
        messages.append(f"hiding the tunnel as TLS data transfer on port {obfs_port}")
    else:
        _clear_obfs()
    messages.append(
        f"using {binding.local_tun} <-> {binding.remote_tun} "
        f"({binding.local_address} <-> {binding.remote_address})"
    )
    if cascade is not None:
        messages.extend(_start_cascade(server, login, password, cascade, binding, on_progress))

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
    try:
        SSH_PID.chmod(0o644)
    except OSError:
        pass
    return [*messages, f"started ssh tunnel daemon pid {daemon.pid}"]


def is_tunnel_daemon_alive() -> bool:
    if not SSH_PID.exists():
        return False
    try:
        pid = int(SSH_PID.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    return _pid_runs_module(pid, "ssh_vpn_gui.tunnel_daemon")


def tunnel_daemon_started_at() -> float | None:
    """Wall-clock time the running tunnel daemon was recorded, or None.

    The pid file is written once, when the daemon is ready, so its mtime is
    when this tunnel came up. A GUI opened later can keep counting from there.
    """
    if not is_tunnel_daemon_alive():
        return None
    try:
        return SSH_PID.stat().st_mtime
    except OSError:
        return None


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


def cleanup_remote(
    server: str,
    login: str,
    password: str,
    *,
    dry_run: bool = False,
    timeout: int = 20,
    binding: TunnelBinding | None = None,
) -> list[str]:
    command = _ssh_command(
        server,
        login,
        remote_cleanup_command(binding or load_tunnel_state()),
        with_tun=False,
    )
    if dry_run:
        return [_quoted(command)]

    ensure_data_dir()
    return _run_password_ssh(command, password, timeout=timeout, success_message="remote cleanup complete")


def start_remote_cascade(
    server: str,
    login: str,
    password: str,
    cascade: Cascade,
    *,
    dry_run: bool = False,
    on_progress: Callable[[str], None] | None = None,
) -> list[str]:
    """Switch the running tunnel's second hop on the server to `cascade`."""
    if dry_run:
        binding = placeholder_tunnel_binding()
        return [_quoted(_cascade_command(server, login, cascade, binding))]
    binding = load_tunnel_state()
    if binding is None:
        raise SshTunnelError("Connect first: the second hop runs behind an SSH tunnel.")
    ensure_data_dir()
    return _start_cascade(server, login, password, cascade, binding, on_progress)


def stop_remote_cascade(
    server: str,
    login: str,
    password: str,
    *,
    dry_run: bool = False,
    timeout: int = 30,
) -> list[str]:
    command = _ssh_command(server, login, remote_cascade_cleanup_command(), with_tun=False)
    if dry_run:
        return [_quoted(command)]
    ensure_data_dir()
    messages = _run_password_ssh(
        command,
        password,
        timeout=timeout,
        success_message="remote second hop stopped",
    )
    update_tunnel_ovpn("")
    return messages


def _start_cascade(
    server: str,
    login: str,
    password: str,
    cascade: Cascade,
    binding: TunnelBinding,
    on_progress: Callable[[str], None] | None,
) -> list[str]:
    messages = _run_password_ssh(
        _cascade_command(server, login, cascade, binding),
        password,
        timeout=CASCADE_BOOTSTRAP_TIMEOUT_SECONDS,
        success_message=f"remote {cascade.label} second hop ready",
        on_progress=on_progress,
    )
    ovpn_dev = parse_remote_allocation("\n".join(messages)).get("ovpn_dev", "")
    update_tunnel_ovpn(ovpn_dev)
    if ovpn_dev:
        messages.append(f"remote OpenVPN device {ovpn_dev}")
    return messages


def _cascade_command(server: str, login: str, cascade: Cascade, binding: TunnelBinding) -> list[str]:
    return _ssh_command(server, login, remote_cascade_script(cascade, binding), with_tun=False)


def _clear_obfs() -> None:
    try:
        (STATE_DIR / "obfs.env").unlink(missing_ok=True)
    except OSError:
        pass


def _save_obfs(port: int, fingerprint: str) -> None:
    path = STATE_DIR / "obfs.env"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"port={port}\nfingerprint={fingerprint}\n", encoding="utf-8")
    try:
        path.chmod(0o644)
    except OSError:
        pass


def _quoted(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _run_password_ssh(
    command: list[str],
    password: str,
    *,
    timeout: int,
    success_message: str | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> list[str]:
    child = pexpect.spawn(command[0], command[1:], encoding="utf-8", timeout=timeout)
    try:
        transcript = ""
        while True:
            index = child.expect(
                [
                    r"(?i)password:",
                    r"(?i)are you sure you want to continue connecting",
                    r"SSH_VPN_PROGRESS [^\r\n]+",
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ]
            )
            transcript += child.before or ""
            _emit_progress(child.before or "", on_progress)
            if index == 0:
                child.sendline(password)
            elif index == 1:
                child.sendline("yes")
            elif index == 2:
                transcript += child.after or ""
                _emit_progress(child.after or "", on_progress)
            elif index == 3:
                child.close()
                if child.exitstatus not in (None, 0):
                    raise SshTunnelError(_clean_ssh_output(transcript) or f"SSH exited with {child.exitstatus}")
                output = _clean_ssh_output(transcript)
                messages = [success_message] if success_message else ([output] if output else [])
                messages.extend(_allocation_lines(output))
                messages.extend(_cascade_messages(output))
                return messages
            else:
                raise SshTunnelError(_clean_ssh_output(transcript) or "Timed out during SSH command")
    finally:
        child.close(force=True)


def _emit_progress(chunk: str, on_progress: Callable[[str], None] | None) -> None:
    if on_progress is None:
        return
    for raw in chunk.replace("\r", "").splitlines():
        line = raw.strip()
        if line.startswith("SSH_VPN_PROGRESS "):
            on_progress(line.split(" ", 1)[1])


def _allocation_lines(output: str) -> list[str]:
    prefixes = (
        "SSH_VPN_REMOTE_TUN ",
        "SSH_VPN_REMOTE_OVPN ",
        "SSH_VPN_ADDR ",
        "SSH_VPN_USED",
    )
    return [
        line.strip()
        for line in output.splitlines()
        if line.startswith(prefixes)
    ]


def _cascade_messages(output: str) -> list[str]:
    messages: list[str] = []
    for line in output.splitlines():
        if line.startswith("SSH_VPN_INSTALLING "):
            messages.append(f"installed {line.split(' ', 1)[1]} on the remote server")
            continue
        if not line.startswith("SSH_VPN_OVPN_LEFTOVERS"):
            continue
        parts = line.split()
        try:
            count = int(parts[1])
        except (IndexError, ValueError):
            continue
        if count:
            noun = "client" if count == 1 else "clients"
            messages.append(f"cleared {count} leftover remote OpenVPN {noun}")
    return messages


def _clean_ssh_output(output: str) -> str:
    lines = [
        line.strip()
        for line in output.replace("\r", "").splitlines()
        if line.strip()
        and "bind: warning: line editing not enabled" not in line
        and not line.strip().startswith("SSH_VPN_PROGRESS ")
    ]
    return "\n".join(lines)


def _ssh_command(
    server: str,
    login: str,
    remote_command: str,
    *,
    with_tun: bool = True,
    binding: TunnelBinding | None = None,
    obfs: tuple[int, str] | None = None,
) -> list[str]:
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
        chosen = binding or load_tunnel_state() or placeholder_tunnel_binding()
        command.extend(
            [
                "-o",
                "ExitOnForwardFailure=yes",
                "-w",
                f"{chosen.local_index}:{chosen.remote_index}",
            ]
        )
        cover = obfs
        if cover is not None:
            command.extend(["-o", "ProxyCommand=" + proxy_command(server, cover[0], cover[1])])
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
        stripped = line.strip()
        if stripped.startswith("SSH_VPN_NAT "):
            continue
        if stripped == "SSH_VPN_READY":
            return True
    return False
