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
        cascade_mode="socks5",
        tls=True,
        ovpn_files=[{"name": "Netherlands", "path": "/tmp/nl.ovpn"}, {"name": "", "path": "/tmp/de.ovpn"}],
        ovpn_selected=1,
        socks5_proxies=[
            {"name": "Office", "host": "192.168.50.20", "port": "1080", "user": "alice", "password": "s3cret"},
            {"name": "", "host": "192.168.50.21", "port": "1081", "user": "", "password": ""},
        ],
        socks5_selected=1,
    )

    assert app.load_saved_config() == {
        "servers": [
            {"host": "203.0.113.10", "login": "root", "password": "secret", "notice": "Vultr"},
            {"host": "198.51.100.4", "login": "ubuntu", "password": "other", "notice": ""},
        ],
        "selected": 1,
        "routing": False,
        "tls": True,
        "cascade_mode": "socks5",
        "ovpn_files": [{"name": "Netherlands", "path": "/tmp/nl.ovpn"}, {"name": "", "path": "/tmp/de.ovpn"}],
        "ovpn_selected": 1,
        "socks5_proxies": [
            {"name": "Office", "host": "192.168.50.20", "port": "1080", "user": "alice", "password": "s3cret"},
            {"name": "", "host": "192.168.50.21", "port": "1081", "user": "", "password": ""},
        ],
        "socks5_selected": 1,
    }
    assert config_file.stat().st_mode & 0o777 == 0o600


def test_load_saved_config_moves_the_single_ovpn_file_and_proxy_into_lists(monkeypatch, tmp_path) -> None:
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(app, "CONFIG_FILE", config_file)
    config_file.write_text(
        '{"cascade_mode": "socks5", "ovpn_path": "/tmp/nl.ovpn",'
        ' "socks5": {"host": "192.168.50.20", "port": "1080", "user": "alice", "password": "s3cret"}}',
        encoding="utf-8",
    )

    loaded = app.load_saved_config()

    assert loaded["ovpn_files"] == [{"name": "", "path": "/tmp/nl.ovpn"}]
    assert loaded["ovpn_selected"] == 0
    assert loaded["socks5_proxies"] == [
        {"name": "", "host": "192.168.50.20", "port": "1080", "user": "alice", "password": "s3cret"}
    ]
    assert loaded["socks5_selected"] == 0

    # Early 0.2.38 builds saved bare paths and proxies without names.
    config_file.write_text(
        '{"ovpn_files": ["/tmp/nl.ovpn", {"path": "/tmp/de.ovpn", "name": "  Frankfurt \\n VPN "}, "", {}],'
        ' "socks5_proxies": [{"host": "192.168.50.21", "port": "1081", "name": 7}]}',
        encoding="utf-8",
    )
    loaded = app.load_saved_config()
    assert loaded["ovpn_files"] == [
        {"name": "", "path": "/tmp/nl.ovpn"},
        {"name": "Frankfurt VPN", "path": "/tmp/de.ovpn"},
    ]
    assert loaded["socks5_proxies"] == [
        {"name": "7", "host": "192.168.50.21", "port": "1081", "user": "", "password": ""}
    ]

    config_file.write_text(
        '{"ovpn_path": "", "socks5": {}, "ovpn_files": "junk", "socks5_selected": 7}',
        encoding="utf-8",
    )
    loaded = app.load_saved_config()
    assert loaded["ovpn_files"] == []
    assert loaded["socks5_proxies"] == []
    assert loaded["socks5_selected"] == 0


def test_load_saved_config_without_a_file_has_every_setting(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(app, "CONFIG_FILE", tmp_path / "missing.json")

    assert app.load_saved_config() == {
        "servers": [],
        "selected": 0,
        "routing": True,
        "tls": False,
        "cascade_mode": "none",
        "ovpn_files": [],
        "ovpn_selected": 0,
        "socks5_proxies": [],
        "socks5_selected": 0,
    }


def test_load_saved_config_turns_the_old_checkbox_into_a_second_hop(monkeypatch, tmp_path) -> None:
    config_file = tmp_path / "config.json"
    monkeypatch.setattr(app, "CONFIG_FILE", config_file)

    config_file.write_text('{"cascade": true, "ovpn_path": "/tmp/a.ovpn"}', encoding="utf-8")
    assert app.load_saved_config()["cascade_mode"] == "ovpn"
    config_file.write_text('{"cascade": false}', encoding="utf-8")
    assert app.load_saved_config()["cascade_mode"] == "none"
    config_file.write_text('{"cascade_mode": "bogus", "cascade": true}', encoding="utf-8")
    assert app.load_saved_config()["cascade_mode"] == "ovpn"
    config_file.write_text('{"cascade_mode": "tor", "socks5": "junk"}', encoding="utf-8")
    loaded = app.load_saved_config()
    assert loaded["cascade_mode"] == "tor"
    assert loaded["socks5_proxies"] == []


def test_cascade_choices_follow_the_helper_kinds() -> None:
    assert len(app.CASCADE_CHOICES) == len(app.CASCADE_KINDS)
    assert set(app.CASCADE_HINTS) == set(app.CASCADE_KINDS)


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
    assert loaded["tls"] is False


def test_upsert_replaces_same_login_and_remove_keeps_neighbor() -> None:
    servers, index = app.upsert_server([], "203.0.113.10", "root", "secret", "Vultr")
    servers, index = app.upsert_server(servers, "198.51.100.4", "ubuntu", "other", "home")
    servers, index = app.upsert_server(servers, "203.0.113.10", "root", "new-secret", "Vultr")

    assert index == 0
    assert servers[0]["password"] == "new-secret"
    assert servers[0]["notice"] == "Vultr"
    assert app.server_label(servers[0]) == "203.0.113.10 Vultr"
    assert len(servers) == 2

    servers, index = app.remove_item(servers, 0)
    assert index == 0
    assert servers == [
        {"host": "198.51.100.4", "login": "ubuntu", "password": "other", "notice": "home"}
    ]
    assert app.server_label(servers[0]) == "198.51.100.4 home"


def test_proxy_list_replaces_the_name_and_password_of_the_same_login() -> None:
    alice = {"name": "", "host": "192.168.50.20", "port": "1080", "user": "alice", "password": "one"}
    bob = {"name": "Office", "host": "192.168.50.20", "port": "1080", "user": "bob", "password": "two"}

    proxies, index = app.upsert_socks5([], alice)
    proxies, index = app.upsert_socks5(proxies, bob)
    assert index == 1
    proxies, index = app.upsert_socks5(proxies, {**alice, "name": "Home", "password": "three"})

    assert index == 0
    assert [(proxy["name"], proxy["password"]) for proxy in proxies] == [("Home", "three"), ("Office", "two")]
    assert app.socks5_labels(proxies) == ["Home", "Office"]
    assert app.socks5_address(proxies[0]) == "alice@192.168.50.20:1080"

    proxies, index = app.remove_item(proxies, 1)
    assert index == 0
    proxies, index = app.remove_item(proxies, 0)
    assert (proxies, index) == ([], 0)


def test_proxy_labels_fall_back_to_the_address_and_tell_same_names_apart() -> None:
    proxies = [
        {"name": "", "host": "192.168.50.21", "port": "1081", "user": "", "password": ""},
        {"name": "NL", "host": "192.168.50.22", "port": "1080", "user": "alice", "password": "x"},
        {"name": "NL", "host": "192.168.50.23", "port": "1080", "user": "", "password": ""},
    ]

    assert app.socks5_labels(proxies) == [
        "192.168.50.21:1081",
        "NL (alice@192.168.50.22:1080)",
        "NL (192.168.50.23:1080)",
    ]


def test_ovpn_list_keeps_one_entry_per_file_and_tells_same_names_apart() -> None:
    files, index = app.upsert_ovpn([], {"name": "", "path": "/home/user/vpn/home/client.ovpn"})
    files, index = app.upsert_ovpn(files, {"name": "", "path": "/home/user/vpn/work/client.ovpn"})
    files, index = app.upsert_ovpn(files, {"name": "", "path": "/home/user/vpn/nl.ovpn"})
    assert index == 2
    assert app.ovpn_labels(files) == ["client.ovpn (home)", "client.ovpn (work)", "nl.ovpn"]

    files, index = app.upsert_ovpn(files, {"name": "Work", "path": "/home/user/vpn/work/client.ovpn"})

    assert index == 1
    assert len(files) == 3
    assert app.ovpn_labels(files) == ["client.ovpn", "Work", "nl.ovpn"]

    files, _index = app.upsert_ovpn(files, {"name": "Work", "path": "/home/user/vpn/nl.ovpn"})
    files, _index = app.upsert_ovpn(files, {"name": "Work", "path": "/work.ovpn"})
    assert app.ovpn_labels(files) == [
        "client.ovpn",
        "Work (work/client.ovpn)",
        "Work (vpn/nl.ovpn)",
        "Work (work.ovpn)",
    ]


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
    assert app._helper_timeout(["connect", "--cascade", "tor"]) == 660
    assert app._helper_timeout(["connect", "--server", "203.0.113.10"]) == 90
    assert app._helper_timeout(["connect", "--tls", "--server", "192.168.50.2"]) == 660
    assert app._helper_timeout(["cascade-off"]) == 90
    assert app._helper_timeout(["status"]) == 10
    assert app._helper_timeout(["disconnect", "--local-only"]) == 20
    assert app._helper_timeout(["disconnect"]) == 90


def test_switching_servers_waits_for_the_old_server_cleanup_too() -> None:
    assert app._helper_timeout(["connect", "--previous-server", "192.168.50.2"]) == 120
    assert app._helper_timeout(["connect", "--cascade", "tor", "--previous-server", "192.168.50.2"]) == 690


class _FakeHelperProcess:
    def __init__(self, command, **_kwargs) -> None:
        import io

        self.command = command
        self.written: list[str] = []
        self.stdin = self
        self.stdout = io.StringIO('{"ok": true, "messages": []}')
        self.stderr = io.StringIO("")
        self.returncode = 0

    def write(self, text: str) -> None:
        self.written.append(text)

    def close(self) -> None:
        pass

    def wait(self, timeout=None) -> int:
        return 0


def test_run_helper_sends_the_socks5_password_on_stdin(monkeypatch) -> None:
    import json

    started: list[_FakeHelperProcess] = []

    def fake_popen(command, **kwargs):
        started.append(_FakeHelperProcess(command, **kwargs))
        return started[-1]

    monkeypatch.setattr(app.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(app, "_privileged_helper_command", lambda: ["helper"])

    result = app.run_helper(
        ["cascade-on", "--cascade", "socks5", "--socks5-server=192.168.50.20:1080"],
        password="ssh secret",
        socks5_password="proxy secret",
    )

    assert result == {"ok": True, "messages": []}
    assert "--secrets-stdin" in started[0].command
    assert "--password-stdin" not in started[0].command
    assert not any("ssh secret" in part or "proxy secret" in part for part in started[0].command)
    assert json.loads("".join(started[0].written)) == {
        "password": "ssh secret",
        "socks5_password": "proxy secret",
    }

    app.run_helper(["connect", "--server", "203.0.113.10"], password="ssh secret")
    assert "--password-stdin" in started[1].command
    assert started[1].written == ["ssh secret"]

    app.run_helper(
        ["connect", "--server", "192.168.50.3", "--previous-server", "192.168.50.2"],
        password="new secret",
        previous_password="old secret",
    )
    assert "--secrets-stdin" in started[2].command
    assert not any("secret" in part for part in started[2].command if part != "--secrets-stdin")
    assert json.loads("".join(started[2].written)) == {
        "password": "new secret",
        "previous_password": "old secret",
    }


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


def test_connected_button_shows_how_long_the_tunnel_has_been_up() -> None:
    assert app.connected_button_label(0) == "Connected 0:00:00"
    assert app.connected_button_label(7.9) == "Connected 0:00:07"
    assert app.connected_button_label(65) == "Connected 0:01:05"
    assert app.connected_button_label(3600 + 125) == "Connected 1:02:05"
    assert app.connected_button_label(2 * 86400 + 3 * 3600 + 4 * 60 + 5) == "Connected 2d 3:04:05"
    assert app.connected_button_label(-4) == "Connected 0:00:00"


def test_connection_started_at_keeps_a_real_start_and_ignores_a_bad_one() -> None:
    assert app.connection_started_at(940, now=1000) == 940
    assert app.connection_started_at(None, now=1000) == 1000
    assert app.connection_started_at(0, now=1000) == 1000
    assert app.connection_started_at(1005, now=1000) == 1000
