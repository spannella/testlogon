import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.models import AddressIn, AddressPrimaryReq, AddressSearchReq
from app.routers import addresses


def run_async(coro):
    return asyncio.run(coro)


def build_request():
    return SimpleNamespace(headers={"user-agent": "agent"}, client=None, state=SimpleNamespace())


def build_ctx():
    return {"user_sub": "user", "session_id": "sid"}


class TestAddressRoutes(unittest.TestCase):
    def test_list_addresses(self):
        ctx = build_ctx()
        with patch.object(addresses, "list_addresses", return_value=[{"address_id": "a1"}]):
            resp = run_async(addresses.ui_list_addresses(ctx=ctx))
        self.assertEqual(resp, [{"address_id": "a1"}])

    def test_create_address(self):
        ctx = build_ctx()
        req = build_request()
        body = AddressIn(line1="1 Main", city="Town", state="CA", postal_code="90001")
        created = {"address_id": "a1", "line1": "1 Main"}
        with patch.object(addresses, "create_address", return_value=created) as create_mock:
            with patch.object(addresses, "audit_event") as audit_mock:
                resp = run_async(addresses.ui_create_address(req, body, ctx=ctx))
        create_mock.assert_called_once()
        audit_mock.assert_called_once()
        self.assertEqual(resp["address_id"], "a1")

    def test_update_address(self):
        ctx = build_ctx()
        req = build_request()
        body = AddressIn(line1="2 Main")
        updated = {"address_id": "a1", "line1": "2 Main"}
        with patch.object(addresses, "update_address", return_value=updated) as update_mock:
            with patch.object(addresses, "audit_event") as audit_mock:
                resp = run_async(addresses.ui_update_address(req, "a1", body, ctx=ctx))
        update_mock.assert_called_once_with("user", "a1", {"line1": "2 Main"})
        audit_mock.assert_called_once()
        self.assertEqual(resp["line1"], "2 Main")

    def test_delete_address(self):
        ctx = build_ctx()
        req = build_request()
        deleted = {"address_id": "a1"}
        with patch.object(addresses, "delete_address", return_value=deleted) as delete_mock:
            with patch.object(addresses, "audit_event") as audit_mock:
                resp = run_async(addresses.ui_delete_address(req, "a1", ctx=ctx))
        delete_mock.assert_called_once_with("user", "a1")
        audit_mock.assert_called_once()
        self.assertTrue(resp["deleted"])
        self.assertEqual(resp["address"]["address_id"], "a1")

    def test_search_addresses(self):
        ctx = build_ctx()
        body = AddressSearchReq(query="home")
        with patch.object(addresses, "search_addresses", return_value=[{"address_id": "a1"}]) as search_mock:
            resp = run_async(addresses.ui_search_addresses(body, ctx=ctx))
        search_mock.assert_called_once_with("user", "home")
        self.assertEqual(resp["query"], "home")
        self.assertEqual(resp["matches"], [{"address_id": "a1"}])

    def test_set_primary_address(self):
        ctx = build_ctx()
        req = build_request()
        body = AddressPrimaryReq(address_id="a1")
        updated = {"address_id": "a1", "is_primary_mailing": True}
        with patch.object(addresses, "set_primary_address", return_value=updated) as primary_mock:
            with patch.object(addresses, "audit_event") as audit_mock:
                resp = run_async(addresses.ui_set_primary_address(req, body, ctx=ctx))
        primary_mock.assert_called_once_with("user", "a1")
        audit_mock.assert_called_once()
        self.assertTrue(resp["is_primary_mailing"])
