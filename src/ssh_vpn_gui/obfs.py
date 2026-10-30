"""Carry the SSH tunnel inside TLS so the long connection looks like data transfer.

The bytes on the wire are a TLS handshake followed by TLS application data.
A probe that sends HTTP after the handshake gets a short file response. The
SSH client sends its banner instead, and only that stream is forwarded to
the local sshd. The certificate is pinned, so a different certificate is
rejected before any SSH byte is sent.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import os
import select
import socket
import ssl
import sys
import threading

OBFS_PORTS = (443, 8443, 2053)
_HTTP_PREFACE = (b"GET ", b"POST", b"HEAD", b"PUT ", b"PRI ")
# Split so this file never contains the heredoc terminator as one string.
_SOURCE_MARK = "SSH_VPN_OBFS_SOURCE_" + "END"


class ObfsPinError(RuntimeError):
    pass


def certificate_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def remote_installer_script() -> str:
    """Shell that installs the forwarder on the server and prints its pin."""
    from .system import remote_install_snippet

    source = Path(__file__).read_text(encoding="utf-8")
    if _SOURCE_MARK in source:
        raise RuntimeError("obfs source contains the installer marker")
    install = remote_install_snippet(
        "Python 3 and OpenSSL",
        present="command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1",
        apt="python3 openssl",
        dnf="python3 openssl",
    )
    head = install + """
command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 || {
  echo 'python3 and openssl are still missing after installation' >&2
  exit 1
}
obfs_dir=/var/lib/ssh-vpn-gui
mkdir -p "$obfs_dir"
chmod 700 "$obfs_dir"
cat > "$obfs_dir/obfs.py" << '""" + _SOURCE_MARK + """'
"""
    tail = _SOURCE_MARK + """
chmod 700 "$obfs_dir/obfs.py"
if [ ! -s "$obfs_dir/obfs.crt" ] || [ ! -s "$obfs_dir/obfs.key" ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \\
    -keyout "$obfs_dir/obfs.key" -out "$obfs_dir/obfs.crt" \\
    -subj "/CN=ssh-vpn-gui" || {
    echo 'openssl could not create the TLS certificate' >&2
    exit 1
  }
fi
chmod 600 "$obfs_dir/obfs.key"
if [ -f "$obfs_dir/obfs.pid" ]; then
  old=$(cat "$obfs_dir/obfs.pid" 2>/dev/null || true)
  if [ -n "$old" ] && grep -a -q 'obfs.py' "/proc/$old/cmdline" 2>/dev/null; then
    kill "$old" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      [ -d "/proc/$old" ] || break
      sleep 0.1
    done
  fi
fi
rm -f "$obfs_dir/obfs.port"
python3 "$obfs_dir/obfs.py" serve "$obfs_dir/obfs.crt" "$obfs_dir/obfs.key" "$obfs_dir/obfs.port" >> "$obfs_dir/obfs.log" 2>&1 &
echo $! > "$obfs_dir/obfs.pid"
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if [ -s "$obfs_dir/obfs.port" ]; then
    ready=1
    break
  fi
  sleep 0.1
done
[ "$ready" -eq 1 ] || {
  echo 'TLS forwarder did not start' >&2
  tail -n 20 "$obfs_dir/obfs.log" >&2 || true
  exit 1
}
port=$(cat "$obfs_dir/obfs.port")
fp=$(openssl x509 -in "$obfs_dir/obfs.crt" -outform DER | sha256sum | awk '{print $1}')
if command -v nft >/dev/null 2>&1; then
  nft add table inet ssh_vpn_gui_obfs 2>/dev/null || true
  nft 'add chain inet ssh_vpn_gui_obfs input { type filter hook input priority -10; policy accept; }' 2>/dev/null || true
  if ! nft list table inet ssh_vpn_gui_obfs 2>/dev/null | grep -q "dport $port"; then
    nft add rule inet ssh_vpn_gui_obfs input tcp dport "$port" accept
  fi
fi
if command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \\
    iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow "$port"/tcp >/dev/null 2>&1 || true
fi
echo SSH_VPN_OBFS "$port" "$fp"
""".strip()
    return (head + source + "\n" + tail).strip()


def parse_obfs_line(lines: list[str]) -> tuple[int, str] | None:
    for line in lines:
        parts = line.strip().split()
        if len(parts) == 3 and parts[0] == "SSH_VPN_OBFS" and parts[1].isdigit():
            if len(parts[2]) == 64 and all(char in "0123456789abcdef" for char in parts[2]):
                return int(parts[1]), parts[2]
    return None


def obfs_state_path() -> Path:
    from .system import STATE_DIR

    return STATE_DIR / "obfs.env"


def save_obfs(port: int, fingerprint: str) -> None:
    path = obfs_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"port={port}\nfingerprint={fingerprint}\n", encoding="utf-8")
    try:
        path.chmod(0o644)
    except OSError:
        pass


def load_obfs() -> tuple[int, str] | None:
    try:
        text = obfs_state_path().read_text(encoding="utf-8")
    except OSError:
        return None
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    parsed = parse_obfs_line(
        [f"SSH_VPN_OBFS {values.get('port', '')} {values.get('fingerprint', '')}"]
    )
    return parsed


def proxy_command(server: str, port: int, fingerprint: str) -> str:
    import shlex

    parts = ("python3", "-m", "ssh_vpn_gui.obfs", "relay", server, str(port), fingerprint)
    return " ".join(shlex.quote(part) for part in parts)


def port_reachable(host: str, port: int, *, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def open_pinned(host: str, port: int, fingerprint: str, *, timeout: float = 20.0) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        tls = context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise
    peer = tls.getpeercert(binary_form=True)
    if peer is None or certificate_fingerprint(peer) != fingerprint:
        tls.close()
        raise ObfsPinError("TLS certificate does not match the server pin")
    tls.settimeout(None)
    return tls


def relay(host: str, port: int, fingerprint: str) -> int:
    try:
        tls = open_pinned(host, port, fingerprint)
    except ObfsPinError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"TLS forwarder unreachable: {exc}", file=sys.stderr)
        return 1
    _splice_stdio(tls)
    return 0


def _splice_stdio(tls: ssl.SSLSocket) -> None:
    outgoing = sys.stdout.fileno()
    incoming = sys.stdin.fileno()
    done = threading.Event()

    def from_server() -> None:
        try:
            while True:
                data = tls.recv(65536)
                if not data:
                    break
                os.write(outgoing, data)
        except Exception:
            pass
        done.set()

    threading.Thread(target=from_server, daemon=True).start()
    try:
        while not done.is_set():
            ready, _, _ = select.select([incoming], [], [], 0.5)
            if not ready:
                continue
            data = os.read(incoming, 65536)
            if not data:
                break
            tls.sendall(data)
    except Exception:
        pass
    finally:
        done.set()
        try:
            tls.close()
        except Exception:
            pass


def serve(
    cert: str,
    key: str,
    portfile: str,
    *,
    ports: tuple[int, ...] = OBFS_PORTS,
    host: str = "0.0.0.0",
    upstream: tuple[str, int] = ("127.0.0.1", 22),
    stop: threading.Event | None = None,
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["http/1.1"])
    bound: socket.socket | None = None
    chosen = 0
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            sock.close()
            continue
        sock.listen(16)
        bound = sock
        chosen = sock.getsockname()[1]
        break
    if bound is None:
        print("no free port for the TLS forwarder", file=sys.stderr)
        raise SystemExit(1)
    Path(portfile).write_text(f"{chosen}\n", encoding="utf-8")
    bound.settimeout(0.2)
    try:
        while stop is None or not stop.is_set():
            try:
                conn, _addr = bound.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=_handle_client,
                args=(context, conn, upstream),
                daemon=True,
            ).start()
    finally:
        bound.close()


def _handle_client(
    context: ssl.SSLContext,
    conn: socket.socket,
    upstream: tuple[str, int],
) -> None:
    try:
        tls = context.wrap_socket(conn, server_side=True)
    except ssl.SSLError:
        conn.close()
        return
    try:
        preface = _recv_some(tls, 8)
        if preface.startswith(_HTTP_PREFACE):
            _send_http_ok(tls)
            return
        remote = socket.create_connection(upstream, timeout=10)
    except Exception:
        try:
            tls.close()
        except Exception:
            pass
        return
    try:
        if preface:
            remote.sendall(preface)
        remote.settimeout(None)
        tls.settimeout(None)
        _bridge(tls, remote)
    finally:
        try:
            remote.close()
        except Exception:
            pass
        try:
            tls.close()
        except Exception:
            pass


def _recv_some(sock: ssl.SSLSocket, size: int, *, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _send_http_ok(tls: ssl.SSLSocket) -> None:
    body = b"ok\n"
    message = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )
    try:
        tls.sendall(message)
    except Exception:
        pass
    finally:
        tls.close()


def _bridge(left: socket.socket, right: socket.socket) -> None:
    def copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass

    threads = (
        threading.Thread(target=copy, args=(left, right), daemon=True),
        threading.Thread(target=copy, args=(right, left), daemon=True),
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["relay"] and len(args) == 4:
        return relay(args[1], int(args[2]), args[3])
    if args[:1] == ["serve"] and len(args) == 4:
        serve(args[1], args[2], args[3])
        return 0
    print("usage: obfs relay HOST PORT FINGERPRINT | obfs serve CERT KEY PORTFILE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
