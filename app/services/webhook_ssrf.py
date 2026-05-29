"""SSRF protection for webhook URL validation (ENTERPRISE-005)."""
from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Private/reserved IP ranges that should not be accessed
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # Shared address space
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
]


def validate_webhook_url(url: str, skip_dns: bool = False) -> None:
    """Validate a webhook URL for SSRF protection.

    Raises ValueError if the URL targets a private/reserved IP range.
    In dev mode, http://localhost is allowed.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("https", "http"):
        raise ValueError("URL must use HTTPS")

    if parsed.scheme == "http":
        from app.core.settings import S
        if S.dev_mode and parsed.hostname in ("localhost", "127.0.0.1"):
            return
        raise ValueError("URL must use HTTPS")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must have a hostname")

    # Check if hostname is a raw IP address
    try:
        ip = ipaddress.ip_address(hostname)
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                raise ValueError(f"URL resolves to blocked IP range: {network}")
        # Even public IPs are allowed if they pass the block check
        return
    except ValueError as e:
        if "blocked" in str(e):
            raise
        # Not an IP address -- it's a hostname, continue to DNS check

    if skip_dns:
        return

    # Resolve hostname and check resolved IPs
    try:
        addrs = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            for network in _BLOCKED_NETWORKS:
                if ip in network:
                    raise ValueError(
                        f"Hostname {hostname} resolves to blocked IP {sockaddr[0]} in {network}"
                    )
    except socket.gaierror:
        # DNS resolution failed -- allow in dev mode, reject in production
        from app.core.settings import S
        if not S.dev_mode:
            raise ValueError(f"Cannot resolve hostname: {hostname}")
