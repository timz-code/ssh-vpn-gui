import os
import socket
import ssl
import subprocess
import threading

from ssh_vpn_gui import obfs


PIN = "ab" * 32


class _FakeTLS:
    """Minimal TLS stand-in for _splice_stdio verdict tests."""

    def __init__(self, *, block: threading.Event | None = None) -> None:
        self._block = block
        self.closed = False

    def recv(self, _size: int) -> bytes:
        if self._block is not None:
            self._block.wait()
        return b""  # EOF

    def sendall(self, _data: bytes) -> None:  # pragma: no cover - unused here
        pass

    def close(self) -> None:
        self.closed = True
        if self._block is not None:
            self._block.set()  # release a blocked recv so its thread can exit

    def settimeout(self, _value) -> None:
        pass


def test_splice_reports_tls_closed_first() -> None:
    r_in, w_in = os.pipe()
    r_out, w_out = os.pipe()
    try:
        side, reason = obfs._splice_stdio(_FakeTLS(), incoming=r_in, outgoing=w_out)
        assert side == "tls"
        assert reason == "eof"
    finally:
        for fd in (r_in, w_in, r_out, w_out):
            try:
                os.close(fd)
            except OSError:
                pass


def test_splice_reports_ssh_closed_first() -> None:
    block = threading.Event()
    r_in, w_in = os.pipe()
    r_out, w_out = os.pipe()
    os.close(w_in)  # closing the write end makes the ssh side read EOF first
    try:
        side, reason = obfs._splice_stdio(
            _FakeTLS(block=block), incoming=r_in, outgoing=w_out
        )
        assert side == "ssh"
        assert reason == "eof"
    finally:
        for fd in (r_in, r_out, w_out):
            try:
                os.close(fd)
            except OSError:
                pass


def test_relay_log_records_verdict(tmp_path, monkeypatch) -> None:
    import ssh_vpn_gui.system as system

    monkeypatch.setattr(system, "STATE_DIR", tmp_path)
    obfs.relay_log("connected on port 443")
    obfs.relay_log("TLS tunnel closed first [tls:eof] on port 443")
    assert obfs.last_relay_verdict().endswith("[tls:eof] on port 443")
    assert len(obfs.relay_log_tail()) == 2


def test_installer_script_is_bash_and_pins_the_certificate() -> None:
    script = obfs.remote_installer_script()

    assert "SSH_VPN_OBFS" in script
    assert "install -y python3 openssl" in script
    assert "dnf install -y python3 openssl" in script
    assert "python3 is required" not in script
    assert "openssl req -x509" in script
    mark = "SSH_VPN_OBFS_SOURCE_" + "END"
    closer_at = script.index(f"\n{mark}\n")
    assert 'echo SSH_VPN_OBFS "$port"' in script[closer_at:]
    checked = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True, check=False)
    assert checked.returncode == 0, checked.stderr
    assert "here-document" not in checked.stderr


def test_tls_forwarder_hides_ssh_and_answers_http(tmp_path) -> None:
    cert, key, fingerprint = _certificate(tmp_path)
    upstream, seen = _upstream()
    stop = threading.Event()
    portfile = tmp_path / "obfs.port"
    threading.Thread(
        target=obfs.serve,
        kwargs={
            "cert": str(cert),
            "key": str(key),
            "portfile": str(portfile),
            "ports": (0,),
            "host": "127.0.0.1",
            "upstream": upstream,
            "stop": stop,
        },
        daemon=True,
    ).start()
    port = _wait_port(portfile)
    try:
        pinned = obfs.open_pinned("127.0.0.1", port, fingerprint, timeout=5)
        pinned.sendall(b"SSH-2.0-test\r\n")
        assert pinned.recv(16) == b"pong"
        pinned.close()
        assert seen["banner"].startswith(b"SSH-2.0-")

        probed = _unpinned("127.0.0.1", port)
        probed.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        page = _read_all(probed)
        assert page.startswith(b"HTTP/1.1 200 OK")
        assert b"SSH-" not in page
        assert seen["http"] is False
    finally:
        stop.set()


def test_wrong_certificate_is_rejected_before_ssh(tmp_path) -> None:
    cert, key, _fingerprint = _certificate(tmp_path)
    upstream, _seen = _upstream()
    stop = threading.Event()
    portfile = tmp_path / "obfs.port"
    threading.Thread(
        target=obfs.serve,
        kwargs={
            "cert": str(cert),
            "key": str(key),
            "portfile": str(portfile),
            "ports": (0,),
            "host": "127.0.0.1",
            "upstream": upstream,
            "stop": stop,
        },
        daemon=True,
    ).start()
    port = _wait_port(portfile)
    try:
        try:
            obfs.open_pinned("127.0.0.1", port, PIN, timeout=5)
        except obfs.ObfsPinError:
            return
        raise AssertionError("wrong pin was accepted")
    finally:
        stop.set()


def test_saved_obfs_round_trip(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(obfs, "obfs_state_path", lambda: tmp_path / "obfs.env")

    obfs.save_obfs(8443, PIN)

    assert obfs.load_obfs() == (8443, PIN)


def _certificate(tmp_path):
    cert = tmp_path / "obfs.crt"
    key = tmp_path / "obfs.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=ssh-vpn-gui",
        ],
        check=True,
        capture_output=True,
    )
    der = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    return cert, key, obfs.certificate_fingerprint(der)


def _upstream():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    sock.settimeout(5)
    seen = {"banner": b"", "http": False}

    def accept() -> None:
        try:
            conn, _addr = sock.accept()
        except OSError:
            return
        seen["http"] = True
        data = conn.recv(64)
        seen["banner"] = data
        seen["http"] = data.startswith(b"GET ")
        if data.startswith(b"SSH-"):
            conn.sendall(b"pong")
        conn.close()

    threading.Thread(target=accept, daemon=True).start()
    return ("127.0.0.1", sock.getsockname()[1]), seen


def _wait_port(portfile) -> int:
    for _ in range(50):
        if portfile.exists() and portfile.read_text(encoding="utf-8").strip():
            return int(portfile.read_text(encoding="utf-8"))
        threading.Event().wait(0.05)
    raise AssertionError("forwarder did not write its port")


def _unpinned(host: str, port: int) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=5)
    return context.wrap_socket(raw, server_hostname=host)


def _read_all(sock: ssl.SSLSocket) -> bytes:
    sock.settimeout(5)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    sock.close()
    return data
