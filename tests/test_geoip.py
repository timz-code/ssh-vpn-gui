import ipaddress

import pytest

from ssh_vpn_gui.geoip import GeoIpStore


def test_private_networks_work_without_a_downloaded_database(tmp_path) -> None:
    store = GeoIpStore(tmp_path / "missing.mmdb")

    assert store.matches("192.168.1.10", ["private"])
    assert store.matches("100.64.0.1", ["private"])
    networks = store.ipv4_networks(["private"])["private"]
    assert any(ipaddress.ip_address("100.64.0.1") in network for network in networks)
    assert store.ipv4_networks([]) == {}


def test_country_expansion_merges_ipv4_and_skips_other_countries_and_ipv6(monkeypatch) -> None:
    store = GeoIpStore()
    records = [
        (ipaddress.ip_network("5.255.255.0/25"), {"country": {"iso_code": "RU"}}),
        (ipaddress.ip_network("5.255.255.128/25"), {"country": {"code": "ru"}}),
        (ipaddress.ip_network("8.8.8.0/24"), {"country": {"iso_code": "US"}}),
        (ipaddress.ip_network("2001:db8::/32"), {"country": {"iso_code": "RU"}}),
    ]
    monkeypatch.setattr(store, "_open_reader", lambda: iter(records))

    assert store.ipv4_networks(["RU"]) == {"ru": (ipaddress.ip_network("5.255.255.0/24"),)}


def test_empty_country_fails_instead_of_installing_an_ineffective_rule(monkeypatch) -> None:
    store = GeoIpStore()
    monkeypatch.setattr(store, "_open_reader", lambda: iter([]))

    with pytest.raises(RuntimeError, match="no IPv4 networks for: ru"):
        store.ipv4_networks(["ru"])


def test_missing_country_database_reports_update_action(tmp_path) -> None:
    store = GeoIpStore(tmp_path / "missing.mmdb")

    with pytest.raises(RuntimeError, match="Update Routing Data"):
        store.matches("77.88.8.8", ["ru"])


def test_corrupt_database_reports_update_action(tmp_path) -> None:
    database = tmp_path / "broken.mmdb"
    database.write_bytes(b"not an MMDB")

    with pytest.raises(RuntimeError, match="Cannot read GeoIP database"):
        GeoIpStore(database).ipv4_networks(["ru"])
