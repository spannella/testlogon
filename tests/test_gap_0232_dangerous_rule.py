"""Offline regression tests for GAP-0232 (INFRA-009).

``app/services/security_groups.py`` contains ``is_dangerous_rule()``, the guard
that blocks security-group rules opening sensitive ports to the public internet.

Before the fix it blocked exactly ONE case: ``0.0.0.0/0`` -> TCP port 22 (SSH).
The INFRA-009 design mandates the same guard also reject:
  * RDP (TCP 3389)
  * VNC (TCP 5900-5999, a range)
  * any rule sourced from the IPv6 wildcard ``::/0`` (including SSH)

These tests call ``is_dangerous_rule`` and ``_prepare_rule`` directly — both are
pure functions over a dict; ``_prepare_rule`` only additionally reads the frozen
settings flag ``S.security_groups_block_dangerous_rules`` (which we force on via
``object.__setattr__`` since ``S`` is a frozen dataclass). No DynamoDB, no AWS,
no moto interception — fully hermetic.

FAILS BEFORE FIX: the RDP / VNC / IPv6 "blocked" cases return False.
PASSES AFTER FIX: all blocked cases return True, allowed cases return False.
"""
from __future__ import annotations

import unittest

from app.core.settings import S
from app.services.security_groups import (
    DangerousRule,
    _prepare_rule,
    is_dangerous_rule,
)


# Cases that MUST be flagged dangerous (blocked).
_BLOCKED = [
    # Original behaviour: SSH over IPv4 wildcard (regression guard).
    {"protocol": "tcp", "direction": "inbound", "port_from": 22, "port_to": 22,
     "source": "0.0.0.0/0"},
    # RDP over IPv4 wildcard.
    {"protocol": "tcp", "direction": "inbound", "port_from": 3389, "port_to": 3389,
     "source": "0.0.0.0/0"},
    # VNC single port over IPv4 wildcard.
    {"protocol": "tcp", "direction": "inbound", "port_from": 5901, "port_to": 5901,
     "source": "0.0.0.0/0"},
    # VNC full range over IPv4 wildcard.
    {"protocol": "tcp", "direction": "inbound", "port_from": 5900, "port_to": 5999,
     "source": "0.0.0.0/0"},
    # SSH over IPv6 wildcard.
    {"protocol": "tcp", "direction": "inbound", "port_from": 22, "port_to": 22,
     "source": "::/0"},
    # RDP over IPv6 wildcard.
    {"protocol": "tcp", "direction": "inbound", "port_from": 3389, "port_to": 3389,
     "source": "::/0"},
    # Wide range that overlaps VNC.
    {"protocol": "tcp", "direction": "inbound", "port_from": 5000, "port_to": 6000,
     "source": "0.0.0.0/0"},
    # protocol "all" covering RDP over IPv6.
    {"protocol": "all", "direction": "inbound", "port_from": 0, "port_to": 65535,
     "source": "::/0"},
]

# Cases that MUST remain allowed (not dangerous).
_ALLOWED = [
    # Specific CIDR — not a public wildcard.
    {"protocol": "tcp", "direction": "inbound", "port_from": 22, "port_to": 22,
     "source": "10.0.0.0/8"},
    # Outbound SSH — direction not inbound.
    {"protocol": "tcp", "direction": "outbound", "port_from": 22, "port_to": 22,
     "source": "0.0.0.0/0"},
    # HTTPS — not a sensitive port.
    {"protocol": "tcp", "direction": "inbound", "port_from": 443, "port_to": 443,
     "source": "0.0.0.0/0"},
    # UDP RDP — protocol not tcp/all.
    {"protocol": "udp", "direction": "inbound", "port_from": 3389, "port_to": 3389,
     "source": "0.0.0.0/0"},
    # platform_only source.
    {"protocol": "tcp", "direction": "inbound", "port_from": 22, "port_to": 22,
     "source": "platform_only"},
    # Just below VNC range — no overlap.
    {"protocol": "tcp", "direction": "inbound", "port_from": 5800, "port_to": 5899,
     "source": "0.0.0.0/0"},
]


class TestIsDangerousRuleGap0232(unittest.TestCase):
    def test_blocked_cases(self):
        for rule in _BLOCKED:
            with self.subTest(rule=rule):
                self.assertTrue(
                    is_dangerous_rule(rule),
                    f"GAP-0232: rule must be flagged dangerous: {rule}",
                )

    def test_allowed_cases(self):
        for rule in _ALLOWED:
            with self.subTest(rule=rule):
                self.assertFalse(
                    is_dangerous_rule(rule),
                    f"GAP-0232: rule must NOT be flagged dangerous: {rule}",
                )


class TestPrepareRuleRaisesGap0232(unittest.TestCase):
    """``_prepare_rule`` must raise ``DangerousRule`` for the new cases when the
    block flag is on. ``S`` is a frozen dataclass — force the flag via
    ``object.__setattr__`` and restore the original value afterwards."""

    def setUp(self):
        self._orig = S.security_groups_block_dangerous_rules
        object.__setattr__(S, "security_groups_block_dangerous_rules", True)
        self.addCleanup(
            object.__setattr__, S, "security_groups_block_dangerous_rules", self._orig
        )

    def test_prepare_rule_raises_for_rdp_ipv4(self):
        with self.assertRaises(DangerousRule):
            _prepare_rule({
                "protocol": "tcp", "direction": "inbound",
                "port_from": 3389, "port_to": 3389,
                "source": "0.0.0.0/0", "action": "allow",
            })

    def test_prepare_rule_raises_for_vnc_range_ipv4(self):
        with self.assertRaises(DangerousRule):
            _prepare_rule({
                "protocol": "tcp", "direction": "inbound",
                "port_from": 5900, "port_to": 5999,
                "source": "0.0.0.0/0", "action": "allow",
            })

    def test_prepare_rule_raises_for_ssh_ipv6(self):
        with self.assertRaises(DangerousRule):
            _prepare_rule({
                "protocol": "tcp", "direction": "inbound",
                "port_from": 22, "port_to": 22,
                "source": "::/0", "action": "allow",
            })

    def test_prepare_rule_allows_safe_rule(self):
        # HTTPS from anywhere is allowed; should not raise and should round-trip.
        prepared = _prepare_rule({
            "protocol": "tcp", "direction": "inbound",
            "port_from": 443, "port_to": 443,
            "source": "0.0.0.0/0", "action": "allow",
        })
        self.assertEqual(prepared["port_from"], 443)
        self.assertEqual(prepared["source"], "0.0.0.0/0")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
