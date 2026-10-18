from __future__ import annotations

import os
from pathlib import Path
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

from .geoip import GeoIpStore
from .geosite import GeositeStore
from .routing_config import RoutingConfig, parse_routing_file
from .routing_engine import DNS_PORT, add_resolved_ips
from .system import CommandRunner, PROXY_MARK, STATE_DIR

DNS_PID = STATE_DIR / "dns-proxy.pid"
DNS_LOG = STATE_DIR / "dns-proxy.log"
UPSTREAMS = (("1.1.1.1", 853), ("9.9.9.9", 853))


def start_dns_proxy(routing_file: Path, *, dry_run: bool = False) -> list[str]:
    command = [sys.executable, "-m", "ssh_vpn_gui.dns_proxy", str(routing_file)]
    if dry_run:
        return [" ".join(command), *_flush_system_dns_cache(dry_run=True)]

    stop_dns_proxy(dry_run=False)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    log = DNS_LOG.open("ab")
    process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
    time.sleep(0.4)
    if process.poll() is not None:
        log.close()
        raise RuntimeError(f"DNS proxy exited immediately: {_read_tail(DNS_LOG)}")
    DNS_PID.write_text(str(process.pid), encoding="utf-8")
    return [f"started DNS classifier pid {process.pid}", *_flush_system_dns_cache()]


def _flush_system_dns_cache(*, dry_run: bool = False) -> list[str]:
    resolver = shutil.which("resolvectl") or shutil.which("systemd-resolve")
    if resolver is None:
        return []
    option = "flush-caches" if Path(resolver).name == "resolvectl" else "--flush-caches"
    command = [resolver, option]
    if dry_run:
        return [" ".join(command)]

    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"system DNS cache flush failed: {exc}"]
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        return [f"system DNS cache flush failed: {detail or completed.returncode}"]
    return ["flushed system DNS cache"]


def stop_dns_proxy(*, dry_run: bool = False) -> list[str]:
    messages: list[str] = []
    if not DNS_PID.exists():
        return []

    try:
        pid = int(DNS_PID.read_text(encoding="utf-8").strip())
    except ValueError:
        DNS_PID.unlink(missing_ok=True)
        return messages
    if dry_run:
        return [f"verify ssh_vpn_gui.dns_proxy pid {pid}", f"kill {pid}"]
    if _pid_runs_dns_proxy(pid):
        try:
            os.kill(pid, signal.SIGTERM)
            messages.append(f"stopped DNS classifier pid {pid}")
        except ProcessLookupError:
            pass
    DNS_PID.unlink(missing_ok=True)
    _wait_until_port_free()
    return messages


def _pid_runs_dns_proxy(pid: int) -> bool:
    try:
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    return b"-m" in argv and b"ssh_vpn_gui.dns_proxy" in argv


def diagnose_dns_proxy() -> list[str]:
    messages = []
    if DNS_PID.exists():
        messages.append(f"dns pid: {DNS_PID.read_text(encoding='utf-8').strip()}")
    else:
        messages.append("dns pid: missing")
    messages.append(_read_tail(DNS_LOG, 1200) or "dns log: empty")
    return messages


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: dns_proxy ROUTING_FILE", file=sys.stderr)
        return 2
    server = DnsClassifier(parse_routing_file(args[0]))
    return server.serve_forever()


class DnsClassifier:
    def __init__(self, config: RoutingConfig) -> None:
        self.config = config
        self.geosite = GeositeStore()
        self.geoip = GeoIpStore()
        self.runner = CommandRunner(dry_run=False)
        self.running = True

    def serve_forever(self) -> int:
        signal.signal(signal.SIGTERM, self._stop)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for sock in (udp, tcp):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", int(DNS_PORT)))
        tcp.listen(64)
        print(f"DNS classifier listening on 127.0.0.1:{DNS_PORT}", flush=True)

        while self.running:
            readable, _, _ = select.select([udp, tcp], [], [], 1.0)
            for sock in readable:
                if sock is udp:
                    packet, address = udp.recvfrom(4096)
                    threading.Thread(target=self._handle_udp, args=(udp, packet, address), daemon=True).start()
                else:
                    connection, _ = tcp.accept()
                    threading.Thread(target=self._handle_tcp, args=(connection,), daemon=True).start()
        return 0

    def _handle_udp(self, udp: socket.socket, packet: bytes, address) -> None:
        response = self._safe_resolve(packet)
        udp.sendto(response, address)

    def _handle_tcp(self, connection: socket.socket) -> None:
        with connection:
            length_data = _read_exact(connection, 2)
            if not length_data:
                return
            length = struct.unpack("!H", length_data)[0]
            packet = _read_exact(connection, length)
            response = self._safe_resolve(packet)
            connection.sendall(struct.pack("!H", len(response)) + response)

    def _safe_resolve(self, packet: bytes) -> bytes:
        try:
            return self._resolve_and_classify(packet)
        except Exception as exc:
            domain = _query_domain(packet) or "?"
            print(f"{domain} -> DNS error: {exc}", flush=True)
            return _servfail_response(packet)

    def _resolve_and_classify(self, packet: bytes) -> bytes:
        domain = _query_domain(packet)
        action = self._classify_domain(domain) if domain else self.config.default
        response = _dot_query(packet, action)
        addresses, ttl = _answer_addresses(response)
        direct_addresses: list[str] = []
        proxy_addresses: list[str] = []
        for address in addresses:
            ip_action = self._classify_ip(address)
            if (ip_action or action) == "direct":
                direct_addresses.append(address)
            else:
                proxy_addresses.append(address)
        add_resolved_ips(self.runner, "direct", direct_addresses, ttl)
        add_resolved_ips(self.runner, "proxy", proxy_addresses, ttl)
        print(f"{domain or '?'} -> {action} {addresses}", flush=True)
        return response

    def _classify_domain(self, domain: str) -> str:
        for rule in self.config.rules:
            if rule.kind != "domain":
                continue
            for matcher in rule.matchers:
                if matcher.name == "domain" and _domain_suffix_match(domain, matcher.value):
                    return rule.action
                if matcher.name == "regexp" and __import__("re").search(matcher.value, domain):
                    return rule.action
                if matcher.name == "geosite" and self.geosite.match(matcher.value, domain):
                    return rule.action
        return self.config.default

    def _classify_ip(self, address: str) -> str | None:
        for rule in self.config.rules:
            if rule.kind != "ip":
                continue
            for matcher in rule.matchers:
                if matcher.name == "ip_cidr":
                    import ipaddress

                    if ipaddress.ip_address(address) in ipaddress.ip_network(matcher.value):
                        return rule.action
                if matcher.name == "geoip":
                    try:
                        if self.geoip.matches(address, [matcher.value]):
                            return rule.action
                    except RuntimeError as exc:
                        print(str(exc), flush=True)
        return None

    def _stop(self, _signum, _frame) -> None:
        self.running = False


def _dot_query(packet: bytes, action: str) -> bytes:
    last_error: Exception | None = None
    for host, port in UPSTREAMS:
        try:
            context = ssl.create_default_context()
            with _connect_dot_socket(host, port, action) as raw:
                server_name = "cloudflare-dns.com" if host == "1.1.1.1" else "dns.quad9.net"
                with context.wrap_socket(raw, server_hostname=server_name) as tls:
                    tls.settimeout(8)
                    tls.sendall(struct.pack("!H", len(packet)) + packet)
                    length = struct.unpack("!H", _read_exact(tls, 2))[0]
                    return _read_exact(tls, length)
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"DoT query failed: {last_error}")


def _connect_dot_socket(host: str, port: int, action: str) -> socket.socket:
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(8)
        if action == "proxy":
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, int(PROXY_MARK))
        raw.connect((host, port))
        return raw
    except Exception:
        raw.close()
        raise


def _query_domain(packet: bytes) -> str | None:
    try:
        domain, _ = _read_name(packet, 12)
        return domain.lower()
    except Exception:
        return None


def _servfail_response(packet: bytes) -> bytes:
    if len(packet) < 12:
        return packet
    header = bytearray(packet[:12])
    flags = struct.unpack("!H", header[2:4])[0]
    flags |= 0x8000
    flags = (flags & 0xFFF0) | 0x0002
    header[2:4] = struct.pack("!H", flags)
    header[6:12] = b"\x00\x00\x00\x00\x00\x00"
    return bytes(header) + packet[12:]


def _answer_addresses(packet: bytes) -> tuple[list[str], int]:
    if len(packet) < 12:
        return [], 60
    qdcount, ancount = struct.unpack("!HH", packet[4:8])
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(packet, offset)
        offset += 4

    addresses: list[str] = []
    ttl = 300
    for _ in range(ancount):
        _, offset = _read_name(packet, offset)
        rtype, _, record_ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        data = packet[offset : offset + rdlength]
        offset += rdlength
        ttl = min(ttl, record_ttl)
        if rtype == 1 and rdlength == 4:
            addresses.append(socket.inet_ntop(socket.AF_INET, data))
    return addresses, ttl or 60


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    original_offset = offset
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(packet[offset : offset + length].decode("idna"))
        offset += length
    return ".".join(labels), original_offset if jumped else offset


def _read_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        chunks.extend(chunk)
    return bytes(chunks)


def _domain_suffix_match(domain: str, value: str) -> bool:
    value = value.rstrip(".").lower()
    return domain == value or domain.endswith("." + value)


def _read_tail(path: Path, limit: int = 4000) -> str:
    try:
        return path.read_bytes()[-limit:].decode("utf-8", errors="replace").strip()
    except FileNotFoundError:
        return ""


def _wait_until_port_free() -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", int(DNS_PORT))) != 0:
                return
        time.sleep(0.1)


if __name__ == "__main__":
    raise SystemExit(main())
