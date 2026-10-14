from __future__ import annotations

import signal
import sys
import time

import pexpect

from .ssh_tunnel import _ssh_command
from .system import load_tunnel_state, mark_fail_closed, remote_setup_script
from .tunnel_watch import is_tun_peer_reachable, should_drop_unresponsive_peer


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: tunnel_daemon SERVER LOGIN", file=sys.stderr)
        return 2

    server = args[0]
    login = args[1]
    password = sys.stdin.readline().rstrip("\n")
    if not password:
        print("missing password", file=sys.stderr)
        return 2

    binding = load_tunnel_state()
    if binding is None:
        print("missing tunnel binding in /run/ssh-vpn-gui/tunnel.env", file=sys.stderr)
        return 2

    command = _ssh_command(server, login, remote_setup_script(binding), binding=binding)
    child = pexpect.spawn(
        command[0],
        command[1:],
        encoding="utf-8",
        timeout=30,
        ignore_sighup=True,
    )

    stopping = False
    ready = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        child.close(force=True)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    try:
        while True:
            index = child.expect(
                [
                    r"(?i)password:",
                    r"(?i)are you sure you want to continue connecting",
                    r"SSH_VPN_NAT \S+ \S+",
                    "SSH_VPN_READY",
                    r"Permission denied",
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ]
            )
            if index == 0:
                child.sendline(password)
            elif index == 1:
                child.sendline("yes")
            elif index == 2:
                print(str(child.after).strip(), flush=True)
            elif index == 3:
                print("SSH_VPN_READY", flush=True)
                ready = True
                break
            elif index == 4:
                print("SSH authentication failed", file=sys.stderr, flush=True)
                return 1
            elif index == 5:
                print(f"SSH exited before tunnel was ready: {child.before}", file=sys.stderr, flush=True)
                return 1
            else:
                print("Timed out waiting for SSH tunnel", file=sys.stderr, flush=True)
                return 1

        ready_at = time.monotonic()
        peer_failures = 0
        peer_seen = False
        while child.isalive():
            if is_tun_peer_reachable(timeout=1.5):
                peer_failures = 0
                peer_seen = True
            else:
                peer_failures += 1
                elapsed = time.monotonic() - ready_at
                if peer_seen and should_drop_unresponsive_peer(
                    failures=peer_failures, elapsed_seconds=elapsed
                ):
                    print("Tunnel peer stopped responding", file=sys.stderr, flush=True)
                    child.close(force=True)
                    return 1
            time.sleep(2)
        return child.exitstatus or 0
    finally:
        child.close(force=True)
        if ready and not stopping:
            _mark_dropped()


def _mark_dropped() -> None:
    # The blackholes armed at connect already hold traffic back; the flag
    # makes the GUI show that instead of a plain "disconnected".
    try:
        mark_fail_closed()
    except OSError as exc:
        print(f"could not record the dropped tunnel: {exc}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
