from ssh_vpn_gui import system


def test_parse_remote_allocation_reads_tun_addr_and_used() -> None:
    parsed = system.parse_remote_allocation(
        "\n".join(
            [
                "SSH_VPN_REMOTE_TUN tun8",
                "SSH_VPN_USED 10.255.3.1 10.255.3.2 192.168.1.1",
                "SSH_VPN_ADDR 10.255.6.1 10.255.6.2 10.255.6.0/30",
                "SSH_VPN_REMOTE_OVPN ovpn1",
            ]
        )
    )

    assert parsed["remote_tun"] == "tun8"
    assert parsed["local_address"] == "10.255.6.1"
    assert parsed["remote_address"] == "10.255.6.2"
    assert parsed["cidr"] == "10.255.6.0/30"
    assert parsed["ovpn_dev"] == "ovpn1"
    assert "10.255.3.1" in parsed["used"].split()


def test_allocate_uses_remote_suggestion_when_locally_free(monkeypatch) -> None:
    monkeypatch.setattr(system, "local_ipv4_addresses", lambda: {"192.168.1.10"})
    monkeypatch.setattr(system, "next_free_tun", lambda **_kwargs: "tun4")

    binding = system.allocate_tunnel_binding(
        "SSH_VPN_REMOTE_TUN tun9\nSSH_VPN_ADDR 10.255.6.1 10.255.6.2 10.255.6.0/30\n"
    )

    assert binding.local_tun == "tun4"
    assert binding.remote_tun == "tun9"
    assert binding.local_address == "10.255.6.1"
    assert binding.remote_address == "10.255.6.2"
    assert binding.cidr == "10.255.6.0/30"


def test_allocate_skips_pair_already_used_locally(monkeypatch) -> None:
    monkeypatch.setattr(system, "local_ipv4_addresses", lambda: {"10.255.3.1"})
    monkeypatch.setattr(system, "next_free_tun", lambda **_kwargs: "tun1")

    binding = system.allocate_tunnel_binding(
        "SSH_VPN_REMOTE_TUN tun8\n"
        "SSH_VPN_USED 10.255.5.1\n"
        "SSH_VPN_ADDR 10.255.3.1 10.255.3.2 10.255.3.0/30\n"
    )

    assert binding.remote_tun == "tun8"
    assert binding.local_address == "10.255.4.1"
    assert binding.cidr == "10.255.4.0/30"


def test_bootstrap_allocates_remote_tun_instead_of_hardcoding_tun3() -> None:
    script = system.remote_bootstrap_script()

    assert "SSH_VPN_REMOTE_TUN" in script
    assert "SSH_VPN_ADDR" in script
    assert "SSH_VPN_USED" in script
    assert "for i in $(seq 0 255)" in script
    assert "ip addr flush dev tun3" not in script


def test_ovpn_bootstrap_picks_free_ovpn_device() -> None:
    script = system.remote_ovpn_bootstrap_script("Zm9v")

    assert "SSH_VPN_REMOTE_OVPN" in script
    assert "ovpn$i" in script
    assert '--dev "$ovpn_dev"' in script
    assert "--dev ovpn0" not in script
    assert "ip addr show ovpn0" not in script
    assert 'from "$cidr" to "$cidr" table main priority 2123' in script
    assert script.index('from "$cidr" to "$cidr" table main') < script.index(
        'from "$cidr" table 2124'
    )
    assert "--disable-dco" in script
    assert "-j SNAT --to-source" not in script


def test_ovpn_stop_removes_keep_tun_rule() -> None:
    script = system.remote_ovpn_cleanup_command()

    assert "ip rule del priority 2123" in script
    assert "ip rule del table 2124" in script


def test_remote_setup_keeps_ssh_peer_off_the_ovpn_table() -> None:
    script = system.remote_setup_script(
        system.TunnelBinding(
            local_tun="tun4",
            remote_tun="tun7",
            local_address="10.255.8.1",
            remote_address="10.255.8.2",
            cidr="10.255.8.0/30",
        )
    )

    assert "from 10.255.8.0/30 to 10.255.8.0/30 table main priority 2123" in script
    assert "ip route replace 10.255.8.0/30 dev tun7 table 2124" in script
    assert "iptables -I FORWARD 1 -i tun7 -j ACCEPT" in script
    assert "net.ipv4.conf.default.rp_filter=0" in script
    assert "/proc/sys/net/ipv4/conf/*/rp_filter" in script
    assert "net.ipv4.conf.all.forwarding=1" in script
    assert "/proc/sys/net/ipv4/conf/*/forwarding" in script
    assert "-j MASQUERADE" in script
    assert "echo SSH_VPN_NAT masquerade" in script
    assert "-j SNAT --to-source" not in script


def test_save_tunnel_state_is_readable_without_root(monkeypatch, tmp_path) -> None:
    state = tmp_path / "tunnel.env"
    monkeypatch.setattr(system, "TUNNEL_STATE", state)
    monkeypatch.setattr(system, "ensure_state_dir", lambda: None)

    system.save_tunnel_state(
        system.TunnelBinding(
            local_tun="tun4",
            remote_tun="tun7",
            local_address="10.255.8.1",
            remote_address="10.255.8.2",
            cidr="10.255.8.0/30",
            server="192.168.50.2",
            underlay_via="192.168.1.1",
            underlay_dev="wlp2s0",
        )
    )

    assert state.stat().st_mode & 0o777 == 0o644
    loaded = system.load_tunnel_state()
    assert loaded is not None
    assert loaded.local_tun == "tun4"
    assert loaded.remote_tun == "tun7"
    assert loaded.server == "192.168.50.2"
    assert loaded.underlay_via == "192.168.1.1"
    assert loaded.underlay_dev == "wlp2s0"


def test_discover_local_binding_reads_claimed_p2p_address(monkeypatch) -> None:
    class Result:
        stdout = "4: tun7    inet 10.255.8.1/32 scope global tun7\n"

    monkeypatch.setattr(system.subprocess, "run", lambda *_args, **_kwargs: Result())

    binding = system.discover_local_binding()
    assert binding is not None
    assert binding.local_tun == "tun7"
    assert binding.local_address == "10.255.8.1"
    assert binding.remote_address == "10.255.8.2"
    assert binding.cidr == "10.255.8.0/30"


def test_remote_cleanup_without_state_does_not_touch_tun3(monkeypatch) -> None:
    monkeypatch.setattr(system, "load_tunnel_state", lambda: None)
    script = system.remote_cleanup_command()

    assert "ip addr flush dev tun3" not in script
    assert "iptables -D FORWARD -s 10.255.0.0/16 -j ACCEPT" in script
    assert "/sys/class/net/tun*" in script
    assert "/etc/ssh-vpn-gui/client.ovpn" in script
    assert 'ip link del "$ovpn_dev"' in script
    assert '*"-s 10.255."*' in script
