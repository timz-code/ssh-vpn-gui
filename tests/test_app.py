from ssh_vpn_gui import app


def test_save_config_persists_servers_and_checkboxes(monkeypatch, tmp_path) -> None:
    config_dir = tmp_path / "config"
    config_file = config_dir / "config.json"
    monkeypatch.setattr(app, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(app, "CONFIG_FILE", config_file)

    app.save_config(
        servers=[
            {"host": "203.0.113.10", "login": "root", "password": "secret", "notice": "Vultr"},
            {"host": "198.51.100.4", "login": "ubuntu", "password": "other", "notice": ""},
        ],
        selected=1,
        routing=False,
        cascade=True,
        ovpn_path="/tmp/client.ovpn",
    )

    assert app.load_saved_config() == {
        "servers": [
            {"host": "203.0.113.10", "login": "root", "password": "secret", "notice": "Vultr"},
            {"host": "198.51.100.4", "login": "ubuntu", "password": "other", "notice": ""},
        ],
        "selected": 1,
        "ovpn_path": "/tmp/client.ovpn",
        "routing": False,
        "cascade": True,
    }
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_load_saved_config_migrates_single_server(monkeypatch, tmp_path) -> None:
    config_file = tmp_path / "config.json"
    config_file.write_text(
        '{"server": "203.0.113.10", "login": "root", "password": "secret", "routing": true}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "CONFIG_FILE", config_file)

    loaded = app.load_saved_config()

    assert loaded["servers"] == [
        {"host": "203.0.113.10", "login": "root", "password": "secret", "notice": ""}
    ]
    assert loaded["selected"] == 0
    assert loaded["routing"] is True


def test_upsert_replaces_same_login_and_remove_keeps_neighbor() -> None:
    servers, index = app.upsert_server([], "203.0.113.10", "root", "secret", "Vultr")
    servers, index = app.upsert_server(servers, "198.51.100.4", "ubuntu", "other", "home")
    servers, index = app.upsert_server(servers, "203.0.113.10", "root", "new-secret", "Vultr")

    assert index == 0
    assert servers[0]["password"] == "new-secret"
    assert servers[0]["notice"] == "Vultr"
    assert app.server_label(servers[0]) == "203.0.113.10 Vultr"
    assert len(servers) == 2

    servers, index = app.remove_server(servers, 0)
    assert index == 0
    assert servers == [
        {"host": "198.51.100.4", "login": "ubuntu", "password": "other", "notice": "home"}
    ]
    assert app.server_label(servers[0]) == "198.51.100.4 home"


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
