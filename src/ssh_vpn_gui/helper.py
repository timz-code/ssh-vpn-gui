from __future__ import annotations

import argparse
import base64
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

from .cascade import CASCADE_KINDS, Cascade, socks5_proxy, split_endpoint
from .dns_proxy import diagnose_dns_proxy, start_dns_proxy, stop_dns_proxy
from .geoip import update_geoip
from .geosite import update_geosite
from .paths import SYSTEM_ROUTING_FILE
from .routing_config import parse_routing_file, parse_routing_text
from .routing_engine import (
    RoutingEngine,
    apply_fail_closed,
    let_server_through,
    reset_local_routing,
    stop_rule_mode,
)
from .ssh_tunnel import (
    cleanup_remote,
    start_remote_cascade,
    start_tunnel,
    stop_remote_cascade,
    stop_tunnel,
)
from .system import (
    CommandRunner,
    cleanup_legacy_singbox,
    cleanup_local_tun,
    clear_fail_closed,
    load_tunnel_state,
    is_fail_closed,
    preserve_server_route,
    require_root,
    setup_full_tunnel_routes,
    setup_local_tun,
)
from .tunnel_watch import inspect_tunnel

PUBLIC_IP_URLS = (
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://ifconfig.co/ip",
)
PUBLIC_IP_TIMEOUT_SECONDS = 5
# A fresh Tor circuit adds several seconds before the first byte.
TOR_PUBLIC_IP_TIMEOUT_SECONDS = 20


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    messages: list[str] = []
    extra: dict | None = None
    try:
        if args.previous_server and args.command != "connect":
            raise ValueError("--previous-server only works with connect")
        if not args.dry_run and args.command != "status":
            require_root()

        password, socks5_password, previous_password = _read_secrets(args)
        runner = CommandRunner(dry_run=args.dry_run)
        routing_file = Path(args.routing_file)
        config = None if args.command in {"save-routing", "status", "disconnect"} else parse_routing_file(routing_file)

        if args.command == "save-routing":
            content = _read_content(args)
            parse_routing_text(content)
            if args.dry_run:
                messages.append(f"write validated routing rules to {routing_file}")
            else:
                _save_routing_file(routing_file, content)
                messages.append("routing rules saved")
        elif args.command == "connect":
            _require_server(args.server)
            _require_password(password)
            cascade = _cascade_from_args(args, socks5_password)
            messages.extend(
                _connect(
                    args,
                    config,
                    routing_file,
                    runner,
                    password,
                    cascade,
                    previous_password=previous_password,
                )
            )
        elif args.command == "disconnect":
            messages.extend(
                _disconnect(
                    args,
                    runner,
                    server=args.server,
                    login=args.login,
                    password=password,
                    fail_closed=args.fail_closed,
                )
            )
        elif args.command == "status":
            snapshot = inspect_tunnel()
            messages.extend(snapshot.messages())
            extra = {"status": snapshot.as_dict()}
        elif args.command == "routing-on":
            _require_server(args.server)
            engine = RoutingEngine(config=config, server=args.server)
            engine.start(runner)
            messages.extend(start_dns_proxy(routing_file, dry_run=args.dry_run))
            messages.extend(runner.commands)
        elif args.command == "routing-off":
            _require_server(args.server)
            preserve_server_route(runner, args.server)
            setup_full_tunnel_routes(runner)
            messages.extend(stop_dns_proxy(dry_run=args.dry_run))
            stop_rule_mode(runner)
            messages.extend(runner.commands)
        elif args.command == "cascade-on":
            _require_server(args.server)
            _require_password(password)
            cascade = _cascade_from_args(args, socks5_password)
            if cascade is None:
                raise ValueError("choose a second hop with --cascade ovpn, tor or socks5")
            messages.extend(
                start_remote_cascade(
                    args.server,
                    args.login,
                    password,
                    cascade,
                    dry_run=args.dry_run,
                    on_progress=_gui_progress,
                )
            )
            if not args.dry_run:
                _gui_progress("Checking the new public IP...")
                current_ip = _curl_public_ip(max_time=_public_ip_timeout(cascade))
                if not current_ip:
                    messages.extend(
                        stop_remote_cascade(
                            args.server,
                            args.login,
                            password,
                            dry_run=False,
                        )
                    )
                    fallback_ip = _curl_public_ip()
                    fallback = f"; SSH fallback public IP: {fallback_ip}" if fallback_ip else ""
                    raise RuntimeError(
                        f"{cascade.label} second hop failed its connectivity check and was stopped{fallback}"
                    )
                messages.append(f"public IP: {current_ip}")
        elif args.command == "cascade-off":
            _require_server(args.server)
            _require_password(password)
            messages.extend(
                stop_remote_cascade(
                    args.server,
                    args.login,
                    password,
                    dry_run=args.dry_run,
                )
            )
            if not args.dry_run:
                messages.extend(_health_check())
        elif args.command == "update-geo":
            messages.extend(update_geoip(dry_run=args.dry_run))
            messages.extend(update_geosite(dry_run=args.dry_run))
        elif args.command == "diagnose":
            messages.extend(_diagnose(args.server))
            messages.extend(diagnose_dns_proxy())
        else:
            raise ValueError(f"Unsupported command {args.command!r}")

        _print_result(ok=True, messages=messages, extra=extra)
        return 0
    except Exception as exc:
        _print_result(ok=False, error=str(exc), messages=messages)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ssh-vpn-helper")
    parser.add_argument(
        "command",
        choices=[
            "connect",
            "disconnect",
            "routing-on",
            "routing-off",
            "cascade-on",
            "cascade-off",
            "save-routing",
            "update-geo",
            "diagnose",
            "status",
        ],
    )
    parser.add_argument("--server", help="Remote server IP address")
    parser.add_argument("--login", default="root", help="Remote SSH login")
    parser.add_argument(
        "--previous-server",
        help=(
            "On connect, first close the running tunnel to this server and clean it up. "
            "Non-direct traffic stays blocked until the new tunnel is up."
        ),
    )
    parser.add_argument("--previous-login", default="root", help="SSH login for --previous-server")
    parser.add_argument("--password", help="Remote SSH password. Prefer --password-stdin.")
    parser.add_argument("--password-stdin", action="store_true", help="Read remote root password from stdin")
    parser.add_argument("--content-stdin", action="store_true", help="Read routing configuration content from stdin")
    parser.add_argument("--routing-file", default=str(SYSTEM_ROUTING_FILE))
    parser.add_argument("--no-routing", action="store_true", help="Connect SSH TUN without starting routing rules")
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Carry the SSH tunnel inside TLS so it looks like data transfer",
    )
    parser.add_argument(
        "--fail-closed",
        action="store_true",
        help="On disconnect, block non-direct traffic instead of restoring the system default",
    )
    parser.add_argument(
        "--cascade",
        choices=CASCADE_KINDS,
        help="Second hop on the remote server (default: ovpn with --ovpn-file, otherwise none)",
    )
    parser.add_argument("--ovpn-file", help="Path to a .ovpn file to run as a cascaded VPN on the remote server")
    parser.add_argument("--socks5-server", help="SOCKS5 proxy for --cascade socks5, as HOST:PORT")
    parser.add_argument("--socks5-user", default="", help="SOCKS5 proxy login")
    parser.add_argument("--socks5-password", help="SOCKS5 proxy password. Prefer --secrets-stdin.")
    parser.add_argument(
        "--secrets-stdin",
        action="store_true",
        help='Read {"password": ..., "socks5_password": ..., "previous_password": ...} as JSON from stdin',
    )
    parser.add_argument("--skip-health-check", action="store_true", help="Skip rollback health check after connect")
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Disconnect local tunnel and routes without contacting the remote server",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without changing the system")
    return parser


def _read_password(args: argparse.Namespace) -> str | None:
    if args.password_stdin:
        return sys.stdin.read().rstrip("\n")
    return args.password


def _read_secrets(args: argparse.Namespace) -> tuple[str | None, str, str]:
    """The SSH, SOCKS5 and --previous-server passwords, kept off the command line."""
    if not args.secrets_stdin:
        return _read_password(args), args.socks5_password or "", ""
    try:
        secrets = json.loads(sys.stdin.read())
    except json.JSONDecodeError as exc:
        raise ValueError("--secrets-stdin expects a JSON object") from exc
    if not isinstance(secrets, dict):
        raise ValueError("--secrets-stdin expects a JSON object")
    password = secrets.get("password")
    socks5_password = secrets.get("socks5_password") or ""
    previous_password = secrets.get("previous_password") or ""
    if not isinstance(password, (str, type(None))) or not all(
        isinstance(value, str) for value in (socks5_password, previous_password)
    ):
        raise ValueError("--secrets-stdin values must be strings")
    return password, socks5_password, previous_password


def _cascade_from_args(args: argparse.Namespace, socks5_password: str) -> Cascade | None:
    kind = args.cascade or ("ovpn" if args.ovpn_file else "none")
    if kind == "none":
        return None
    if kind == "ovpn":
        ovpn_b64 = _read_ovpn_b64(args.ovpn_file)
        if ovpn_b64 is None:
            raise ValueError("--ovpn-file is required for the OpenVPN second hop")
        return Cascade("ovpn", ovpn_b64=ovpn_b64)
    if kind == "socks5":
        if not args.socks5_server:
            raise ValueError("--socks5-server is required for the SOCKS5 second hop")
        host, port = split_endpoint(args.socks5_server)
        return Cascade("socks5", socks5=socks5_proxy(host, port, args.socks5_user, socks5_password))
    return Cascade(kind)


def _public_ip_timeout(cascade: Cascade | None) -> int:
    if cascade is not None and cascade.kind == "tor":
        return TOR_PUBLIC_IP_TIMEOUT_SECONDS
    return PUBLIC_IP_TIMEOUT_SECONDS


def _read_content(args: argparse.Namespace) -> str:
    if not args.content_stdin:
        raise ValueError("--content-stdin is required")
    content = sys.stdin.read()
    if not content.strip():
        raise ValueError("routing configuration cannot be empty")
    return content


def _save_routing_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(0o644)
    temporary.replace(path)


def _require_server(server: str | None) -> None:
    if not server:
        raise ValueError("--server is required")


def _require_password(password: str | None) -> None:
    if not password:
        raise ValueError("root password is required")


def _gui_progress(message: str) -> None:
    print(f"SSH_VPN_GUI_PROGRESS {message}", file=sys.stderr, flush=True)


def _print_result(*, ok: bool, messages: list[str], error: str | None = None, extra: dict | None = None) -> None:
    payload = {"ok": ok, "messages": messages}
    if error:
        payload["error"] = error
    if extra:
        payload.update(extra)
    print(json.dumps(payload, ensure_ascii=False))


def _read_ovpn_b64(ovpn_file: str | None) -> str | None:
    if not ovpn_file:
        return None
    path = Path(ovpn_file)
    if not path.is_file():
        raise ValueError(f"OpenVPN config not found: {ovpn_file}")
    data = path.read_bytes()
    if not data.strip():
        raise ValueError(f"OpenVPN config is empty: {ovpn_file}")
    return base64.b64encode(data).decode("ascii")


def _connect(
    args: argparse.Namespace,
    config,
    routing_file: Path,
    runner: CommandRunner,
    password: str,
    cascade: Cascade | None = None,
    *,
    previous_password: str = "",
) -> list[str]:
    messages: list[str] = []
    if args.previous_server:
        messages.extend(_drop_previous_tunnel(args, previous_password))
        _gui_progress(f"Connecting to {args.server}...")
    engine = RoutingEngine(config=config, server=args.server)
    # A dry run only pretends to have blocked traffic for the previous server.
    stay_closed = bool(args.previous_server) or is_fail_closed()
    try:
        _cleanup_before_connect(args, config, runner, stay_closed=stay_closed)
        messages.extend(
            start_tunnel(
                args.server,
                args.login,
                password,
                dry_run=args.dry_run,
                cascade=cascade,
                tls=args.tls,
                on_progress=_gui_progress,
            )
        )
        setup_local_tun(runner)
        preserve_server_route(runner, args.server)
        if not args.no_routing:
            engine.start(runner)
            messages.extend(start_dns_proxy(routing_file, dry_run=args.dry_run))
        else:
            setup_full_tunnel_routes(runner)
            stop_dns_proxy(dry_run=args.dry_run)
            stop_rule_mode(runner)
            if not args.dry_run:
                clear_fail_closed()
        messages.extend(runner.commands)
        if not args.dry_run and not args.skip_health_check:
            messages.extend(_health_check(max_time=_public_ip_timeout(cascade)))
        return messages
    except Exception as exc:
        rollback_messages = _rollback_after_failed_connect(
            args, config, password, fail_closed=stay_closed
        )
        raise RuntimeError(f"connect failed, rolled back: {exc}; rollback: {' | '.join(rollback_messages)}") from exc


def _disconnect(
    args: argparse.Namespace,
    runner: CommandRunner,
    *,
    server: str | None,
    login: str,
    password: str | None,
    fail_closed: bool,
) -> list[str]:
    binding = None if args.dry_run else load_tunnel_state()
    messages = stop_tunnel(dry_run=args.dry_run)
    if fail_closed:
        # The server pin stays: reconnects and the remote cleanup
        # below must still reach it past the blackholes.
        cleanup_local_tun(runner)
        apply_fail_closed(runner, full_tunnel=args.no_routing, server=server)
        messages.append("non-direct traffic is blocked until routing is restored")
    else:
        messages.extend(stop_dns_proxy(dry_run=args.dry_run))
        reset_local_routing(runner)
        cleanup_local_tun(runner, server)
    messages.extend(runner.commands)
    if server and password and not args.local_only:
        try:
            messages.extend(
                cleanup_remote(
                    server,
                    login,
                    password,
                    dry_run=args.dry_run,
                    timeout=25,
                    binding=binding,
                )
            )
        except Exception as exc:
            messages.append(f"remote cleanup skipped: {exc}")
    return messages


def _drop_previous_tunnel(args: argparse.Namespace, password: str) -> list[str]:
    """Close the tunnel to --previous-server, block traffic, and clean that server up.

    The cleanup also stops the old server's second hop, so an OpenVPN
    provider with a connection limit sees the old client leave first.
    """
    _gui_progress(f"Closing the tunnel to {args.previous_server}...")
    runner = CommandRunner(dry_run=args.dry_run)
    messages = _disconnect(
        args,
        runner,
        server=args.previous_server,
        login=args.previous_login,
        password=password,
        fail_closed=True,
    )
    if not password:
        messages.append(f"remote cleanup on {args.previous_server} skipped: no password")
    if args.previous_server != args.server:
        # Its pin would keep traffic to the old server off the new tunnel.
        done = len(runner.commands)
        runner.run(["ip", "route", "del", f"{args.previous_server}/32"], check=False)
        messages.extend(runner.commands[done:])
    return messages


def _cleanup_before_connect(
    args: argparse.Namespace, config, runner: CommandRunner, *, stay_closed: bool
) -> None:
    if not stay_closed:
        stop_dns_proxy(dry_run=runner.dry_run)
    stop_tunnel(dry_run=runner.dry_run)
    if stay_closed:
        cleanup_local_tun(runner)
        if args.server:
            let_server_through(runner, args.server)
    else:
        if args.server:
            RoutingEngine(config=config, server=args.server).stop(runner)
        cleanup_local_tun(runner, args.server)
    cleanup_legacy_singbox(runner)


def _rollback_after_failed_connect(
    args: argparse.Namespace, config, password: str, *, fail_closed: bool
) -> list[str]:
    runner = CommandRunner(dry_run=False)
    messages: list[str] = []
    binding = load_tunnel_state()
    try:
        messages.extend(stop_tunnel(dry_run=False))
        if fail_closed:
            cleanup_local_tun(runner)
            apply_fail_closed(runner, full_tunnel=args.no_routing, server=args.server)
            messages.append("non-direct traffic is blocked until routing is restored")
        else:
            messages.extend(stop_dns_proxy(dry_run=False))
            if args.server:
                RoutingEngine(config=config, server=args.server).stop(runner)
            cleanup_local_tun(runner, args.server)
        messages.extend(runner.commands)
    except Exception as exc:
        messages.append(f"rollback error: {exc}")
    if args.server:
        try:
            messages.extend(
                cleanup_remote(args.server, args.login, password, dry_run=False, binding=binding)
            )
        except Exception as exc:
            messages.append(f"remote rollback error: {exc}")
    return messages


def _health_check(*, max_time: int = PUBLIC_IP_TIMEOUT_SECONDS) -> list[str]:
    messages: list[str] = []
    current_ip = _curl_public_ip(max_time=max_time)
    if not current_ip:
        messages.append("public IP health check unavailable; tunnel left running")
        return messages
    messages.append(f"public IP: {current_ip}")
    return messages


def _curl_public_ip(*, max_time: int = PUBLIC_IP_TIMEOUT_SECONDS) -> str | None:
    for url in PUBLIC_IP_URLS:
        try:
            completed = subprocess.run(
                ["curl", "-4", "-sS", "--max-time", str(max_time), url],
                text=True,
                capture_output=True,
                check=False,
                timeout=max_time + 2,
            )
        except subprocess.TimeoutExpired:
            continue
        if completed.returncode != 0:
            continue
        value = completed.stdout.strip()
        # A proxy or captive portal can answer with a page instead of an address.
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            continue
    return None


def _diagnose(server: str | None) -> list[str]:
    messages = inspect_tunnel().messages()
    binding = load_tunnel_state()
    commands = [
        ["ip", "addr", "show", binding.local_tun] if binding else ["ip", "-4", "addr", "show"],
        ["ip", "rule", "show"],
        ["ip", "route", "show", "table", "2023"],
        ["ip", "route", "get", "34.160.111.145"],
        ["ip", "route", "get", "34.160.111.145", "mark", "2023"],
        ["nft", "list", "table", "inet", "ssh_vpn_gui"],
    ]
    if server:
        commands.append(["ip", "route", "get", server])
    for command in commands:
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        messages.append("$ " + " ".join(command))
        messages.append((completed.stdout or completed.stderr).strip())
    return messages


if __name__ == "__main__":
    raise SystemExit(main())
