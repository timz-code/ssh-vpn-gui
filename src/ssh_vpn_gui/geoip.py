from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable
import urllib.request

from .system import DATA_DIR

GEOIP_DB = DATA_DIR / "ip66.mmdb"
GEOIP_URL = "https://downloads.ip66.dev/db/ip66.mmdb"
DOWNLOAD_TIMEOUT_SECONDS = 45

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)


class GeoIpStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else GEOIP_DB
        self._reader = None

    def country_code(self, address: str) -> str | None:
        ip = ipaddress.ip_address(address)
        if any(ip in network for network in PRIVATE_NETWORKS):
            return "private"
        reader = self._open_reader()
        return _record_country_code(reader.get(address))

    def matches(self, address: str, tags: list[str]) -> bool:
        code = self.country_code(address)
        return code is not None and code.lower() in {tag.lower() for tag in tags}

    def ipv4_networks(self, tags: Iterable[str]) -> dict[str, tuple[ipaddress.IPv4Network, ...]]:
        """Expand countries once so IP rules do not depend on observing DNS."""
        requested = {tag.lower() for tag in tags}
        networks: dict[str, list[ipaddress.IPv4Network]] = {tag: [] for tag in requested}
        if "private" in requested:
            networks["private"].extend(PRIVATE_NETWORKS)
        countries = requested - {"private"}
        if countries:
            for network, record in self._open_reader():
                if network.version != 4:
                    continue
                code = _record_country_code(record)
                if code in countries:
                    networks[code].append(network)
            missing = sorted(tag for tag in countries if not networks[tag])
            if missing:
                raise RuntimeError(
                    f"GeoIP database has no IPv4 networks for: {', '.join(missing)}. "
                    "Check the geoip tags and click 'Update Routing Data'."
                )
        return {tag: tuple(ipaddress.collapse_addresses(values)) for tag, values in networks.items()}

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None

    def _open_reader(self):
        if self._reader is not None:
            return self._reader
        if not self.path.exists():
            raise RuntimeError(
                f"GeoIP database is missing: {self.path}. Click 'Update Routing Data' before connecting."
            )
        try:
            import maxminddb  # type: ignore
        except ImportError as exc:
            raise RuntimeError("GeoIP MMDB lookup requires the python3-maxminddb package") from exc
        try:
            self._reader = maxminddb.open_database(str(self.path))
        except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            raise RuntimeError(
                f"Cannot read GeoIP database {self.path}: {exc}. Click 'Update Routing Data'."
            ) from exc
        return self._reader


def _record_country_code(record: dict | None) -> str | None:
    country = (record or {}).get("country") or {}
    return (country.get("iso_code") or country.get("code") or "").lower() or None


def update_geoip(*, dry_run: bool = False) -> list[str]:
    if dry_run:
        return [f"download {GEOIP_URL} -> {GEOIP_DB}"]
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = GEOIP_DB.with_suffix(".mmdb.tmp")
    _download_file(GEOIP_URL, temporary)
    temporary.replace(GEOIP_DB)
    return [f"updated {GEOIP_DB}"]


def _download_file(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "ssh-vpn-gui"})
    try:
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            with destination.open("wb") as file:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    file.write(chunk)
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"Download failed: {url}: {exc}") from exc
