"""Offline regression test for GAP-0022: SSRF via SSH bastion hop validation.

``validate_host`` must reject private / loopback / link-local / CGNAT and AWS
metadata IP literals while continuing to accept legitimate public addresses.

Before the fix these private-IP cases passed silently (no exception); after the
fix they raise :class:`InvalidHop`. No AWS / network access is required.
"""

import pytest

from app.services.ssh_bastion import validate_host, InvalidHop


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",  # AWS instance metadata endpoint
        "127.0.0.1",        # IPv4 loopback
        "10.0.0.5",         # RFC-1918 class A
        "172.16.0.1",       # RFC-1918 class B
        "192.168.1.1",      # RFC-1918 class C
        "100.64.0.1",       # CGNAT
        "::1",              # IPv6 loopback
        "fe80::1",          # IPv6 link-local
        "fc00::1",          # IPv6 unique local
        "0.0.0.0",          # unspecified / 0.0.0.0/8
    ],
)
def test_validate_host_rejects_private_ip(host):
    with pytest.raises(InvalidHop, match="private or reserved"):
        validate_host(host)


@pytest.mark.parametrize(
    "host, expected",
    [
        ("8.8.8.8", "8.8.8.8"),
        ("1.1.1.1", "1.1.1.1"),
        ("203.0.113.10", "203.0.113.10"),
        ("2001:db8::1", "2001:db8::1"),
    ],
)
def test_validate_host_accepts_public_ip(host, expected):
    assert validate_host(host) == expected


def test_validate_host_accepts_public_hostname():
    assert validate_host("bastion.example.com") == "bastion.example.com"
