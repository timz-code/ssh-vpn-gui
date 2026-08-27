from __future__ import annotations

import signal
import sys
import time

import pexpect

from .ssh_tunnel import _ssh_command
from .system import remote_setup_script
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

    child = pexpect.spawn(
        _ssh_command(server, login, remote_setup_script())[0],
        _ssh_command(server, login, remote_setup_script())[1:],
        encoding="utf-8",
        timeout=30,
        ignore_sighup=True,
    )

    def stop(_signum: int, _frame: object) -> None:
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
                print("SSH_VPN_READY", flush=True)
                break
            elif index == 3:
                print("SSH authentication failed", file=sys.stderr, flush=True)
                return 1
            elif index == 4:
                print(f"SSH exited before tunnel was ready: {child.before}", file=sys.stderr, flush=True)
                return 1
            else:
                print("Timed out waiting for SSH tunnel", file=sys.stderr, flush=True)
                return 1

        ready_at = time.monotonic()
        peer_failures = 0
        while child.isalive():
            if is_tun_peer_reachable(timeout=1.5):
                peer_failures = 0
            else:
                peer_failures += 1
                elapsed = time.monotonic() - ready_at
                if should_drop_unresponsive_peer(failures=peer_failures, elapsed_seconds=elapsed):
                    print("Tunnel peer stopped responding", file=sys.stderr, flush=True)
                    child.close(force=True)
                    return 1
            time.sleep(2)
        return child.exitstatus or 0
    finally:
        child.close(force=True)


if __name__ == "__main__":
    raise SystemExit(main())
