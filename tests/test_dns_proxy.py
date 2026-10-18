import socket
import subprocess

import pytest

from ssh_vpn_gui import dns_proxy
from ssh_vpn_gui.dns_proxy import DnsClassifier
from ssh_vpn_gui.routing_config import parse_routing_text


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

