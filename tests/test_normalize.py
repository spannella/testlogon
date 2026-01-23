import unittest
from types import SimpleNamespace

from fastapi import HTTPException

from app.core.normalize import (
    client_ip_from_request,
    ip_in_any_cidr,
    normalize_cidr,
    normalize_email,
    normalize_phone,
)


class TestNormalizeEmail(unittest.TestCase):
    def test_normalize_email_strips_and_lowercases(self):
        self.assertEqual(normalize_email("  Test@Example.COM "), "test@example.com")

    def test_normalize_email_rejects_invalid(self):
        with self.assertRaises(HTTPException):
            normalize_email("invalid-email")


class TestNormalizePhone(unittest.TestCase):
    def test_normalize_phone_preserves_e164(self):
        self.assertEqual(normalize_phone("+1 (415) 555-1212"), "+14155551212")

    def test_normalize_phone_adds_us_country_code(self):
        self.assertEqual(normalize_phone("415-555-1212"), "+14155551212")

    def test_normalize_phone_rejects_invalid(self):
        with self.assertRaises(HTTPException):
            normalize_phone("not-a-number")


class TestNormalizeCidr(unittest.TestCase):
    def test_normalize_cidr_adds_host_mask(self):
        self.assertEqual(normalize_cidr("192.168.1.10"), "192.168.1.10/32")

    def test_normalize_cidr_normalizes_network(self):
        self.assertEqual(normalize_cidr("10.0.0.1/24"), "10.0.0.0/24")

    def test_normalize_cidr_rejects_empty(self):
        with self.assertRaises(HTTPException):
            normalize_cidr(" ")


class TestIpInAnyCidr(unittest.TestCase):
    def test_ip_in_any_cidr_matches(self):
        self.assertTrue(ip_in_any_cidr("10.0.0.5", ["10.0.0.0/24"]))

    def test_ip_in_any_cidr_ignores_invalid_cidrs(self):
        self.assertTrue(ip_in_any_cidr("10.0.0.5", ["invalid", "10.0.0.0/24"]))

    def test_ip_in_any_cidr_returns_false_when_no_match(self):
        self.assertFalse(ip_in_any_cidr("10.0.1.5", ["10.0.0.0/24"]))


class TestClientIpFromRequest(unittest.TestCase):
    def test_client_ip_from_request_uses_xff(self):
        req = SimpleNamespace(headers={"x-forwarded-for": "203.0.113.5, 10.0.0.1"}, client=None)
        self.assertEqual(client_ip_from_request(req), "203.0.113.5")

    def test_client_ip_from_request_falls_back_to_client(self):
        client = SimpleNamespace(host="198.51.100.2")
        req = SimpleNamespace(headers={}, client=client)
        self.assertEqual(client_ip_from_request(req), "198.51.100.2")

    def test_client_ip_from_request_defaults_when_missing(self):
        req = SimpleNamespace(headers={}, client=None)
        self.assertEqual(client_ip_from_request(req), "0.0.0.0")


if __name__ == "__main__":
    unittest.main()
