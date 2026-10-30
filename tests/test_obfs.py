import socket
import ssl
import subprocess
import threading

from ssh_vpn_gui import obfs


PIN = "ab" * 32


def test_installer_script_is_bash_and_pins_the_certificate() -> None:
    script = obfs.remote_installer_script()

    assert "SSH_VPN_OBFS" in script
    assert "install -y python3 openssl" in script
    assert "dnf install -y python3 openssl" in script
    assert "python3 is required" not in script
    assert "openssl req -x509" in script
    checked = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True, check=False)
    assert checked.returncode == 0, checked.stderr


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
