import socket
import subprocess
import threading
import time

import pytest

from ssh_vpn_gui import dns_proxy
from ssh_vpn_gui.dns_proxy import DnsClassifier, ResolvedIpQueue
from ssh_vpn_gui.routing_config import parse_routing_text
from ssh_vpn_gui.routing_engine import ResolvedIp
from ssh_vpn_gui.system import CommandRunner


def test_dns_classifier_applies_domain_rules_in_order() -> None:
    classifier = DnsClassifier(
        parse_routing_text(
            """
            default: proxy
            domain(domain:example.com)->direct
            domain(regexp: '(^|[.])blocked[.]test$')->proxy
            domain(geosite:ru)->direct
            """
        )
    )

    assert classifier._classify_domain("www.example.com") == "direct"
    assert classifier._classify_domain("blocked.test") == "proxy"
    assert classifier._classify_domain("yandex.ru") == "direct"
    assert classifier._classify_domain("ifconfig.me") == "proxy"


class FakeSocket:
    def __init__(self) -> None:
        self.options = []
        self.timeout = None
        self.address = None
        self.closed = False

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def setsockopt(self, level, option, value) -> None:
        self.options.append((level, option, value))

    def connect(self, address) -> None:
        self.address = address

    def close(self) -> None:
        self.closed = True


def test_proxy_dot_socket_is_marked_before_connect(monkeypatch) -> None:
    fake = FakeSocket()
    monkeypatch.setattr(dns_proxy.socket, "socket", lambda *_args: fake)

    result = dns_proxy._connect_dot_socket("1.1.1.1", 853, "proxy")

    assert result is fake
    assert fake.options == [(socket.SOL_SOCKET, socket.SO_MARK, 2023)]
    assert fake.address == ("1.1.1.1", 853)


def test_direct_dot_socket_is_not_marked(monkeypatch) -> None:
    fake = FakeSocket()
    monkeypatch.setattr(dns_proxy.socket, "socket", lambda *_args: fake)

    result = dns_proxy._connect_dot_socket("1.1.1.1", 853, "direct")

    assert result is fake
    assert fake.options == []
    assert fake.address == ("1.1.1.1", 853)


def test_dns_query_uses_domain_routing_action(monkeypatch) -> None:
    classifier = DnsClassifier(
        parse_routing_text(
            """
            default: proxy
            domain(domain:example.com)->direct
            """
        )
    )
    actions = []
    monkeypatch.setattr(dns_proxy, "_query_domain", lambda _packet: "example.com")
    monkeypatch.setattr(
        dns_proxy,
        "_dot_query",
        lambda _packet, action: actions.append(action) or b"response",
    )
    monkeypatch.setattr(dns_proxy, "_answer_addresses", lambda _response: ([], 60))

    classifier._resolve_and_classify(b"query")

    assert actions == ["direct"]


def test_answers_carry_the_ttl_and_whether_a_static_ip_rule_decides(monkeypatch) -> None:
    classifier = DnsClassifier(parse_routing_text("default: proxy\nip(5.255.255.0/24)->direct\n"))
    submitted = []
    done = threading.Event()
    done.set()
    monkeypatch.setattr(classifier.updates, "submit", lambda answers: submitted.extend(answers) or done)
    monkeypatch.setattr(dns_proxy, "_query_domain", lambda _packet: "example.com")
    monkeypatch.setattr(dns_proxy, "_dot_query", lambda _packet, _action: b"response")
    monkeypatch.setattr(dns_proxy, "_answer_addresses", lambda _response: (["5.255.255.77", "1.2.3.4"], 120))

    classifier._resolve_and_classify(b"query")

    assert submitted == [
        ResolvedIp("5.255.255.77", "direct", 120, static=True),
        ResolvedIp("1.2.3.4", "proxy", 120),
    ]


def _wait_for(condition) -> None:
    deadline = time.monotonic() + 5
    while not condition():
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_answers_that_arrive_during_a_batch_share_the_next_one(monkeypatch) -> None:
    batches = []
    release = threading.Event()

    def apply(_runner, answers, *, proxy_set_used, routes_applied):
        batches.append([answer.address for answer in answers])
        if len(batches) == 1:
            release.wait(5)
        return []

    monkeypatch.setattr(dns_proxy, "apply_resolved_ips", apply)
    queue = ResolvedIpQueue(CommandRunner(dry_run=True), proxy_set_used=False)

    first = queue.submit([ResolvedIp("1.2.3.4", "proxy", 60)])
    _wait_for(lambda: batches)
    later = [queue.submit([ResolvedIp(f"5.6.7.{n}", "direct", 60)]) for n in range(1, 4)]
    assert not any(done.is_set() for done in later)
    release.set()

    assert first.wait(5)
    assert all(done.wait(5) for done in later)
    assert batches == [["1.2.3.4"], ["5.6.7.1", "5.6.7.2", "5.6.7.3"]]


def test_repeated_answer_is_not_applied_again_while_its_entry_lasts(monkeypatch) -> None:
    batches = []
    monkeypatch.setattr(
        dns_proxy,
        "apply_resolved_ips",
        lambda _runner, answers, **_kwargs: batches.append(
            [(answer.address, answer.action, answer.timeout) for answer in answers]
        ) or [],
    )
    now = [1000.0]
    queue = ResolvedIpQueue(CommandRunner(dry_run=True), proxy_set_used=False, clock=lambda: now[0])

    assert queue.submit([ResolvedIp("1.2.3.4", "proxy", 300)]).wait(5)
    now[0] += 59
    assert queue.submit([ResolvedIp("1.2.3.4", "proxy", 300)]).is_set()
    now[0] += 2
    assert queue.submit([ResolvedIp("1.2.3.4", "proxy", 300)]).wait(5)
    assert queue.submit([ResolvedIp("1.2.3.4", "direct", 300)]).wait(5)

    assert batches == [
        [("1.2.3.4", "proxy", 360)],
        [("1.2.3.4", "proxy", 360)],
        [("1.2.3.4", "direct", 360)],
    ]


def test_answers_without_set_entries_do_not_wait_for_nft(monkeypatch) -> None:
    nft_done = threading.Event()

    def apply(_runner, _answers, *, proxy_set_used, routes_applied):
        routes_applied()
        nft_done.wait(5)
        return []

    monkeypatch.setattr(dns_proxy, "apply_resolved_ips", apply)
    queue = ResolvedIpQueue(CommandRunner(dry_run=True), proxy_set_used=False)

    proxied = queue.submit([ResolvedIp("1.2.3.4", "proxy", 60)])
    direct = queue.submit([ResolvedIp("5.6.7.8", "direct", 60)])

    assert proxied.wait(5)
    assert not direct.wait(0.2)
    nft_done.set()
    assert direct.wait(5)


def test_classifier_drops_queries_past_the_limit() -> None:
    classifier = DnsClassifier(parse_routing_text("default: proxy\n"))
    classifier.slots = threading.BoundedSemaphore(1)
    release = threading.Event()

    assert classifier._spawn(release.wait, 5)
    assert not classifier._spawn(release.wait, 5)
    release.set()

    def slot_free() -> bool:
        if classifier.slots.acquire(blocking=False):
            classifier.slots.release()
            return True
        return False

    _wait_for(slot_free)
    assert classifier.dropped == 1


@pytest.mark.parametrize(
    ("available", "expected"),
    [("resolvectl", "flush-caches"), ("systemd-resolve", "--flush-caches")],
)
def test_dns_cache_flush_supports_both_resolver_commands(monkeypatch, available, expected) -> None:
    commands = []
    monkeypatch.setattr(dns_proxy.shutil, "which", lambda name: f"/usr/bin/{name}" if name == available else None)
    monkeypatch.setattr(
        dns_proxy.subprocess, "run",
        lambda command, **_kwargs: commands.append(command) or subprocess.CompletedProcess(command, 0, "", ""),
    )

    assert dns_proxy._flush_system_dns_cache() == ["flushed system DNS cache"]
    assert commands == [[f"/usr/bin/{available}", expected]]


def test_dns_cache_flush_failure_keeps_helper_stdout_valid_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr(dns_proxy.shutil, "which", lambda _name: "/usr/bin/resolvectl")
    monkeypatch.setattr(
        dns_proxy.subprocess, "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", "resolver unavailable"),
    )

    assert dns_proxy._flush_system_dns_cache() == ["system DNS cache flush failed: resolver unavailable"]
    assert capsys.readouterr().out == ""


def test_dns_cache_flush_timeout_is_nonfatal(monkeypatch) -> None:
    monkeypatch.setattr(dns_proxy.shutil, "which", lambda _name: "/usr/bin/resolvectl")

    def timed_out(command, **kwargs):
        assert kwargs["timeout"] == 5
        raise subprocess.TimeoutExpired(command, 5)

    monkeypatch.setattr(dns_proxy.subprocess, "run", timed_out)

    assert dns_proxy._flush_system_dns_cache()[0].startswith("system DNS cache flush failed:")

