from ssh_vpn_gui import app


def test_save_config_persists_checkbox_preferences(monkeypatch, tmp_path) -> None:
    config_dir = tmp_path / "config"
    config_file = config_dir / "config.json"
    monkeypatch.setattr(app, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(app, "CONFIG_FILE", config_file)

    app.save_config(
        server="203.0.113.10",
        login="root",
        password="secret",
        routing=False,
        cascade=True,
        ovpn_path="/tmp/client.ovpn",
    )

    assert app.load_saved_config() == {
        "server": "203.0.113.10",
        "login": "root",
        "password": "secret",
        "ovpn_path": "/tmp/client.ovpn",
        "routing": False,
        "cascade": True,
    }
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_reap_disconnect_uses_remote_cleanup_when_credentials_exist() -> None:
    args, password = app.disconnect_args_for_reap(
        server="203.0.113.10",
        login="root",
        password="secret",
    )
    assert args == [
        "disconnect",
        "--fail-closed",
        "--server",
        "203.0.113.10",
        "--login",
        "root",
    ]
    assert password == "secret"
    assert "--local-only" not in args


def test_reap_disconnect_stays_local_without_password() -> None:
    args, password = app.disconnect_args_for_reap(
        server="203.0.113.10",
        login="root",
        password="",
    )
    assert args == [
        "disconnect",
        "--fail-closed",
        "--local-only",
        "--server",
        "203.0.113.10",
    ]
    assert password is None


def test_reap_disconnect_marks_full_tunnel_fail_closed() -> None:
    args, password = app.disconnect_args_for_reap(
        server="203.0.113.10",
        login="root",
        password="secret",
        routing=False,
    )
    assert "--fail-closed" in args
    assert "--no-routing" in args
    assert password == "secret"


def test_cascade_on_uses_install_timeout() -> None:
    assert app._helper_timeout(["cascade-on"]) == 660
    assert app._helper_timeout(["connect", "--ovpn-file", "x.ovpn"]) == 660
    assert app._helper_timeout(["cascade-off"]) == 90
    assert app._helper_timeout(["status"]) == 10
    assert app._helper_timeout(["disconnect", "--local-only"]) == 20
    assert app._helper_timeout(["disconnect"]) == 90


def test_auto_reconnect_budget_is_more_than_one() -> None:
    assert app.MAX_AUTO_RECONNECTS >= 8
    assert app.SLOW_RECONNECT_INTERVAL_MS == 60_000
    assert app.next_reconnect_delay_ms(0) is None
    assert app.next_reconnect_delay_ms(7) is None
    assert app.next_reconnect_delay_ms(8) == 60_000
    assert app.next_reconnect_delay_ms(20) == 60_000


def test_wall_clock_gap_detects_sleep() -> None:
    assert app.wall_clock_implies_sleep(5) is False
    assert app.wall_clock_implies_sleep(24) is False
    assert app.wall_clock_implies_sleep(26) is True
