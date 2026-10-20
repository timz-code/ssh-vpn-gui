import base64
import re
import shutil
import subprocess

import pytest

from ssh_vpn_gui import cascade, system

BINDING = system.TunnelBinding(
    local_tun="tun4",
    remote_tun="tun7",
    local_address="10.255.8.1",
    remote_address="10.255.8.2",
    cidr="10.255.8.0/30",
)
HOSTILE_PASSWORD = 'p@ss "w\\rd $HOME `id` \'q\''


def test_socks5_proxy_accepts_ipv4_and_host_names() -> None:
    assert cascade.socks5_proxy(" 192.168.50.20 ", "1080") == cascade.Socks5Proxy("192.168.50.20", 1080)
    proxy = cascade.socks5_proxy("proxy.example.com", 443, " alice ", "secret")
    assert proxy == cascade.Socks5Proxy("proxy.example.com", 443, "alice", "secret")
    assert proxy.label == "alice@proxy.example.com:443"


@pytest.mark.parametrize(
    ("host", "port", "user", "password", "message"),
    [
        ("", "1080", "", "", "Enter the SOCKS5 proxy address."),
        ("bad host", "1080", "", "", "bad host is not a valid SOCKS5 proxy address."),
        ("-proxy.example.com", "1080", "", "", "is not a valid SOCKS5 proxy address"),
        ("2001:db8::1", "1080", "", "", "Use an IPv4 address"),
        ("[2001:db8::1]", "1080", "", "", "Use an IPv4 address"),
        ("192.168.50.20", "socks", "", "", "The SOCKS5 port must be a number."),
        ("192.168.50.20", "0", "", "", "between 1 and 65535"),
        ("192.168.50.20", "65536", "", "", "between 1 and 65535"),
        ("192.168.50.20", "1080", "", "secret", "Enter the SOCKS5 login for this password."),
        ("192.168.50.20", "1080", "alice", "x" * 256, "password is longer than 255 bytes"),
        ("192.168.50.20", "1080", "ali\nce", "", "login contains control characters"),
    ],
)
def test_socks5_proxy_rejects_bad_settings(host, port, user, password, message) -> None:
    with pytest.raises(ValueError, match=re.escape(message)):
        cascade.socks5_proxy(host, port, user, password)


def test_split_endpoint_needs_host_and_port() -> None:
    assert cascade.split_endpoint("proxy.example.com:1080") == ("proxy.example.com", "1080")
    for value in ("proxy.example.com", ":1080"):
        with pytest.raises(ValueError, match="HOST:PORT"):
            cascade.split_endpoint(value)


def test_redsocks_config_escapes_credentials() -> None:
    config = cascade.redsocks_config(cascade.socks5_proxy("proxy.example.com", 1080, 'al"ice', HOSTILE_PASSWORD))

    assert 'ip = "proxy.example.com";' in config
    assert "port = 1080;" in config
    assert "type = socks5;" in config
    assert 'login = "al\\"ice";' in config
    assert 'password = "p@ss \\"w\\\\rd $HOME `id` \'q\'";' in config
    assert "local_port = 12380;" in config
    assert "dnstc {" in config


def test_redsocks_config_without_login_sends_no_credentials() -> None:
    config = cascade.redsocks_config(cascade.socks5_proxy("192.168.50.20", 1080))

    assert "login" not in config
    assert "password" not in config


def test_curl_check_config_percent_encodes_credentials() -> None:
    proxy = cascade.socks5_proxy("proxy.example.com", 1080, "al ice", "p@ss:w/rd")

    assert cascade._curl_proxy_config(proxy) == (
        'proxy = "socks5h://al%20ice:p%40ss%3Aw%2Frd@proxy.example.com:1080"\n'
    )
    assert cascade._curl_proxy_config(cascade.socks5_proxy("192.168.50.20", 1080)) == (
        'proxy = "socks5h://192.168.50.20:1080"\n'
    )


def test_tor_script_redirects_only_after_tor_has_bootstrapped() -> None:
    script = cascade.remote_tor_bootstrap_script(BINDING)

    assert "SSH_VPN_INSTALLING Tor" in script
    assert "install -y tor nftables conntrack" in script
    assert "systemctl disable --now tor.service tor@default.service" in script
    assert "TransPort 127.0.0.1:9140" in script
    assert "DNSPort 127.0.0.1:9153" in script
    assert "SocksPort 0" in script
    assert "DataDirectory /var/lib/ssh-vpn-gui/tor" in script
    assert "Bootstrapped" in script
    block = script.index("ip route replace unreachable default table 2124")
    start = script.index("tor -f /etc/ssh-vpn-gui/torrc")
    redirect = script.index("dnat to 127.0.0.1:9140")
    assert script.index("_ssh_vpn_gui_stop_cascade >/dev/null 2>&1' EXIT") < block < start < redirect
    assert script.index('if [ "$bootstrapped" -ne 1 ]') < redirect
    assert 'udp dport 53 dnat to 127.0.0.1:9153' in script
    assert 'iifname "$ssh_tun" ip daddr $cidr return' in script
    assert 'route_localnet=1' in script
    assert "--ctstate DNAT -m comment --comment ssh-vpn-gui-cascade -j ACCEPT" in script
    assert script.index("cascade_ready=1") > redirect


def test_socks5_script_checks_the_proxy_before_replacing_the_old_hop() -> None:
    proxy = cascade.socks5_proxy("proxy.example.com", 1080, "alice", HOSTILE_PASSWORD)
    script = cascade.remote_socks5_bootstrap_script(proxy, BINDING)

    assert HOSTILE_PASSWORD not in script
    assert "alice" not in script
    encoded = re.findall(r"<<'SSH_VPN_REDSOCKS_B64'\n(.+?)\n", script)
    assert base64.b64decode(encoded[0]).decode() == cascade.redsocks_config(proxy)
    check = script.index("curl -4 -sS --max-time 20 -K /etc/ssh-vpn-gui/socks5-check.conf")
    reap = script.index("\n_ssh_vpn_gui_stop_cascade\n")
    assert check < reap < script.index("redsocks -c /etc/ssh-vpn-gui/redsocks.conf")
    assert "the SOCKS5 proxy does not work from the server" in script
    assert "ss -lun" in script and "127.0.0.1:5380 " in script
    assert "dnat to 127.0.0.1:12380" in script
    assert "udp dport 53 dnat to 127.0.0.1:5380" in script
    assert "systemctl disable --now redsocks.service" in script
    assert "dnf" not in script


def test_ovpn_script_blocks_the_table_until_openvpn_is_up() -> None:
    script = cascade.remote_ovpn_bootstrap_script("Zm9v", BINDING)

    block = script.index("ip route replace unreachable default table 2124")
    assert block < script.index("--daemon ssh-vpn-gui-ovpn")
    assert block < script.index('ip route replace default dev "$ovpn_dev" table 2124')
    assert "--persist-tun" in script
    assert "dnf install -y openvpn conntrack-tools" in script


def test_remote_cascade_script_rejects_unknown_kinds() -> None:
    with pytest.raises(ValueError):
        cascade.remote_cascade_script(cascade.Cascade("wireguard"), BINDING)
    with pytest.raises(ValueError):
        cascade.remote_cascade_script(cascade.Cascade("socks5"), BINDING)


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_every_generated_remote_script_is_valid_bash() -> None:
    proxy = cascade.socks5_proxy("proxy.example.com", 1080, 'al"ice', HOSTILE_PASSWORD)
    scripts = {
        "bootstrap": system.remote_bootstrap_script(),
        "session": system.remote_setup_script(BINDING),
        "cleanup": system.remote_cleanup_command(BINDING),
        "second hop off": system.remote_cascade_cleanup_command(BINDING),
        "openvpn": cascade.remote_ovpn_bootstrap_script("Zm9v", BINDING),
        "tor": cascade.remote_tor_bootstrap_script(BINDING),
        "socks5": cascade.remote_socks5_bootstrap_script(proxy, BINDING),
    }
    for name, script in scripts.items():
        checked = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True, check=False)
        assert checked.returncode == 0, f"{name}: {checked.stderr}"
