#!/usr/bin/env python3
from __future__ import annotations

import os
import socket
import ssl
import sys
from dataclasses import dataclass
from typing import List
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class TurnEndpoint:
    scheme: str
    host: str
    port: int
    transport: str


MIN_TURN_TTL_SECONDS = 60
MAX_TURN_TTL_SECONDS = 3600


def _is_truthy(raw: str) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_turn_urls(raw: str) -> List[TurnEndpoint]:
    endpoints: list[TurnEndpoint] = []
    for part in [p.strip() for p in str(raw or "").split(",") if p.strip()]:
        parsed = urlparse(part if "://" in part else part.replace(":", "://", 1))
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"turn", "turns"}:
            continue
        host = parsed.hostname or ""
        if not host:
            continue
        default_port = 5349 if scheme.endswith("s") else 3478
        port = int(parsed.port or default_port)
        qs = parse_qs(parsed.query or "")
        transport = (qs.get("transport", ["tcp" if scheme.endswith("s") else "udp"])[0] or "udp").lower()
        endpoints.append(TurnEndpoint(scheme=scheme, host=host, port=port, transport=transport))
    return endpoints


def _tcp_connect(host: str, port: int, timeout_seconds: float = 2.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except Exception:
        return False


def _tls_connect(host: str, port: int, timeout_seconds: float = 3.0) -> bool:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def run_readiness_checks(raw_urls: str) -> int:
    if not _is_truthy(os.getenv("MESSAGING_WEBRTC_TURN_ENABLED", "true")):
        print("SKIP: MESSAGING_WEBRTC_TURN_ENABLED is false; TURN readiness checks not required")
        return 0

    turn_secret = str(os.getenv("MESSAGING_WEBRTC_TURN_SECRET", "") or "").strip()
    ttl_raw = os.getenv("MESSAGING_WEBRTC_TURN_TTL_SECONDS", "600")
    if not turn_secret:
        print("FAIL: missing MESSAGING_WEBRTC_TURN_SECRET")
        return 2
    try:
        ttl_seconds = int(ttl_raw)
    except Exception:
        print("FAIL: MESSAGING_WEBRTC_TURN_TTL_SECONDS must be an integer")
        return 2
    if ttl_seconds < MIN_TURN_TTL_SECONDS or ttl_seconds > MAX_TURN_TTL_SECONDS:
        print(f"FAIL: MESSAGING_WEBRTC_TURN_TTL_SECONDS must be between {MIN_TURN_TTL_SECONDS} and {MAX_TURN_TTL_SECONDS}")
        return 2

    endpoints = parse_turn_urls(raw_urls)
    if not endpoints:
        print("FAIL: no TURN URLs parsed from MESSAGING_WEBRTC_TURN_URLS")
        return 2

    failures = 0
    for ep in endpoints:
        dns_ok = True
        try:
            socket.getaddrinfo(ep.host, ep.port)
        except Exception:
            dns_ok = False
        if not dns_ok:
            failures += 1
            print(f"FAIL: DNS lookup failed for {ep.host}:{ep.port} ({ep.scheme})")
            continue

        if ep.scheme in {"turns", "stuns"}:
            ok = _tls_connect(ep.host, ep.port)
            mode = "tls"
        elif ep.transport == "tcp":
            ok = _tcp_connect(ep.host, ep.port)
            mode = "tcp"
        else:
            # UDP liveness probe uses DNS-only check in this lightweight script.
            ok = True
            mode = "udp-dns"

        if ok:
            print(f"OK: {ep.scheme}://{ep.host}:{ep.port} ({mode})")
        else:
            failures += 1
            print(f"FAIL: {ep.scheme}://{ep.host}:{ep.port} ({mode})")

    return 0 if failures == 0 else 1


def main() -> int:
    raw_urls = os.getenv("MESSAGING_WEBRTC_TURN_URLS", "")
    return run_readiness_checks(raw_urls)


if __name__ == "__main__":
    raise SystemExit(main())
