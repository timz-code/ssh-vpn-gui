import io
import signal

import pytest

from ssh_vpn_gui import tunnel_daemon
from ssh_vpn_gui.system import TunnelBinding

READY = 3
PERMISSION_DENIED = 4


class FakeChild:
    def __init__(self, expect_results, alive):
        self._expect = list(expect_results)
        self._alive = list(alive)
        self.after = ""
        self.before = ""
        self.exitstatus = 255
        self.sent: list[str] = []

    def expect(self, _patterns, timeout=None):
        return self._expect.pop(0)

    def sendline(self, text):
        self.sent.append(text)

    def isalive(self):
        value = self._alive.pop(0) if self._alive else False
        return value() if callable(value) else value

    def close(self, force=False):
        pass


def _run_daemon(monkeypatch, child, *, peer=lambda **_kwargs: True):
    marks = []
    handlers = {}
    monkeypatch.setattr(tunnel_daemon.sys, "stdin", io.StringIO("secret\n"))
    monkeypatch.setattr(
        tunnel_daemon,
        "load_tunnel_state",
        lambda: TunnelBinding(
            local_tun="tun4",
            remote_tun="tun7",
            local_address="10.255.8.1",
            remote_address="10.255.8.2",
            cidr="10.255.8.0/30",
        ),
    )
    monkeypatch.setattr(tunnel_daemon.pexpect, "spawn", lambda *_args, **_kwargs: child)
    monkeypatch.setattr(tunnel_daemon.signal, "signal", lambda signum, handler: handlers.update({signum: handler}))
    monkeypatch.setattr(tunnel_daemon.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(tunnel_daemon, "is_tun_peer_reachable", peer)
    monkeypatch.setattr(tunnel_daemon, "mark_fail_closed", lambda: marks.append(True))
    return marks, handlers


def test_daemon_flags_a_tunnel_that_drops_on_its_own(monkeypatch) -> None:
    child = FakeChild([READY], [True, False])
    marks, _ = _run_daemon(monkeypatch, child)

    assert tunnel_daemon.main(["203.0.113.10", "root"]) == 255
    assert marks == [True]


def test_daemon_flags_a_dead_peer_it_cut_off(monkeypatch) -> None:
    replies = iter([True, False])
    child = FakeChild([READY], [True, True, True])
    marks, _ = _run_daemon(monkeypatch, child, peer=lambda **_kwargs: next(replies))
    monkeypatch.setattr(tunnel_daemon, "should_drop_unresponsive_peer", lambda **_kwargs: True)

    assert tunnel_daemon.main(["203.0.113.10", "root"]) == 1
    assert marks == [True]


def test_daemon_does_not_flag_a_requested_stop(monkeypatch) -> None:
    def terminate():
        handlers[signal.SIGTERM](signal.SIGTERM, None)

    child = FakeChild([READY], [True, terminate])
    marks, handlers = _run_daemon(monkeypatch, child)

    with pytest.raises(SystemExit) as stopped:
        tunnel_daemon.main(["203.0.113.10", "root"])
    assert stopped.value.code == 0
    assert marks == []


def test_daemon_pokes_the_session_and_reads_the_reply(monkeypatch) -> None:
    intervals = iter([0.0, 100.0])
    child = FakeChild([READY, 0], [True, False])
    monkeypatch.setattr(tunnel_daemon.random, "uniform", lambda _low, _high: next(intervals))
    monkeypatch.setattr(tunnel_daemon.random, "choice", lambda items: items[0])
    _run_daemon(monkeypatch, child)

    assert tunnel_daemon.main(["192.168.50.2", "root"]) == 255
    assert child.sent == ["ls"]


def test_daemon_does_not_flag_a_tunnel_that_never_came_up(monkeypatch) -> None:
    child = FakeChild([PERMISSION_DENIED], [])
    marks, _ = _run_daemon(monkeypatch, child)

    assert tunnel_daemon.main(["203.0.113.10", "root"]) == 1
    assert marks == []
