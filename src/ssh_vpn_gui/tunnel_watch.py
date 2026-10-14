from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess

from . import ssh_tunnel
from . import system

PEER_GRACE_SECONDS = 15.0
PEER_FAIL_LIMIT = 3


@dataclass(frozen=True)
class TunnelSnapshot:
    daemon_alive: bool
    tun_present: bool
    peer_reachable: bool
    # tunnel.env outlives a session that died without a disconnect, and so
    # do the kill-switch routes it armed.
    session_saved: bool = False

    @property
    def process_up(self) -> bool:
        return self.daemon_alive and self.tun_present

    @property
    def alive(self) -> bool:
        return self.process_up and self.peer_reachable

    @property
    def leftover(self) -> bool:
        return (self.daemon_alive or self.tun_present or self.session_saved) and not self.process_up

    @property
    def reason(self) -> str:
        if self.alive:
            return "tunnel is up"
        if not self.daemon_alive:
            return "SSH tunnel process is not running"
        if not self.tun_present:
            return f"{_watch_tun()} is down"
        return f"tunnel peer {_watch_peer()} is not responding"

    def as_dict(self) -> dict[str, bool]:
        return {
            "alive": self.alive,
            "process_up": self.process_up,
            "daemon_alive": self.daemon_alive,
            "tun_present": self.tun_present,
            "peer_reachable": self.peer_reachable,
        }

    def messages(self) -> list[str]:
        return [
            f"tunnel daemon: {'alive' if self.daemon_alive else 'dead'}",
            f"{_watch_tun()}: {'up' if self.tun_present else 'down'}",
            (
                f"peer {_watch_peer()}: "
                f"{'reachable' if self.peer_reachable else 'unreachable'}"
            ),
        ]


def inspect_tunnel(*, ping_timeout: float = 1.5) -> TunnelSnapshot:
    daemon_alive = ssh_tunnel.is_tunnel_daemon_alive()
    tun_present = is_tun_present()
    peer_reachable = tun_present and is_tun_peer_reachable(timeout=ping_timeout)
    return TunnelSnapshot(
        daemon_alive=daemon_alive,
        tun_present=tun_present,
        peer_reachable=peer_reachable,
        session_saved=system.load_tunnel_state() is not None,
    )


def _watch_binding():
    return system.load_tunnel_state() or system.discover_local_binding()


def _watch_tun() -> str:
    binding = _watch_binding()
    return binding.local_tun if binding else "tun"


def _watch_peer() -> str:
    binding = _watch_binding()
    return binding.remote_address if binding else "peer"


def is_tun_present() -> bool:
    binding = _watch_binding()
    if binding is None:
        return False
    path = Path(f"/sys/class/net/{binding.local_tun}/operstate")
    if not path.exists():
        return False
    try:
        state = path.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    return state in {"up", "unknown"}


def is_tun_peer_reachable(*, timeout: float = 1.5) -> bool:
    binding = _watch_binding()
    if binding is None:
        return False
    wait = max(1, int(timeout))
    try:
        completed = subprocess.run(
            [
                "ping",
                "-n",
                "-c",
                "1",
                "-W",
                str(wait),
                "-I",
                binding.local_tun,
                binding.remote_address,
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout + 1,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def should_drop_unresponsive_peer(*, failures: int, elapsed_seconds: float) -> bool:
    return elapsed_seconds >= PEER_GRACE_SECONDS and failures >= PEER_FAIL_LIMIT


def evaluate_tunnel_health(
    snapshot: TunnelSnapshot,
    *,
    require_peer: bool,
    peer_watch_usable: bool,
) -> tuple[bool, bool]:
    """Return (healthy, peer_watch_usable).

    Unprivileged ICMP can be blocked. Once a peer ping has succeeded, later
    peer failures are treated as a dead tunnel. Until then, the SSH daemon
    and the claimed tun state are enough.
    """
    usable = True if snapshot.peer_reachable else peer_watch_usable
    if not snapshot.process_up:
        return False, usable
    if require_peer and usable:
        return snapshot.peer_reachable, usable
    return True, usable
