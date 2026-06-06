"""SSH 演算法指紋對齊 OpenSSH 7.6 + 多型別 host key,降低被識別為 paramiko 蜜罐。"""
import socket
import paramiko
from layer1.ssh_server import _prefer, _harden_transport, _HOST_KEYS


def test_prefer_keeps_wanted_order_and_drops_unavailable():
    available = ["aes128-ctr", "aes256-cbc", "3des-cbc"]
    wanted = ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr"]
    assert _prefer(available, wanted) == ["aes128-ctr"]


def test_prefer_falls_back_when_no_overlap():
    assert _prefer(["x", "y"], ["a", "b"]) == ["x", "y"]


def test_host_keys_include_rsa_ecdsa_ed25519():
    names = {k.get_name() for k in _HOST_KEYS}
    assert "ssh-rsa" in names
    assert "ecdsa-sha2-nistp256" in names
    assert "ssh-ed25519" in names   # 與真實 OpenSSH 一樣同時提供三型別


def test_transport_drops_legacy_algorithms():
    a, b = socket.socketpair()
    try:
        t = paramiko.Transport(a)
        _harden_transport(t)
        opts = t.get_security_options()
        # OpenSSH 7.6 不會提供這些老演算法
        assert "diffie-hellman-group1-sha1" not in opts.kex
        assert "3des-cbc" not in opts.ciphers
        assert "hmac-md5" not in opts.digests
        assert "ssh-dss" not in opts.key_types
        # 首選為現代演算法
        assert opts.ciphers[0] == "aes128-ctr"
    finally:
        a.close()
        b.close()
