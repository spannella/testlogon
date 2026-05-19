from __future__ import annotations

from copy import deepcopy
from unittest.mock import patch

from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.core.tables import T
from app.main import create_app
from app.services.sessions import require_ui_session
from app.services.tickets import STORE
from app.services import api_key_auth_dependency
import app.main as main_app




class FakeUsersTable:
    def __init__(self):
        self.items: dict[str, dict] = {}

    def reset(self):
        self.items.clear()

    def put_user(self, user_sub: str, role: str):
        self.items[user_sub] = {"user_sub": user_sub, "role": role}

    def get_item(self, *, Key: dict, **kwargs):
        item = self.items.get(Key["user_sub"])
        return {"Item": deepcopy(item)} if item else {}

class FakeTicketTable:
    def __init__(self):
        self.items: dict[tuple[str, str], dict] = {}
        self.fail_next_conditional_update = False

    def reset(self):
        self.items.clear()

    def put_item(self, *, Item: dict, **kwargs):
        self.items[(Item["pk"], Item["sk"])] = deepcopy(Item)
        return {}

    def get_item(self, *, Key: dict, **kwargs):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": deepcopy(item)} if item else {}

    def delete_item(self, *, Key: dict, **kwargs):
        self.items.pop((Key["pk"], Key["sk"]), None)
        return {}

    def query(self, **kwargs):
        expr = kwargs.get("KeyConditionExpression", "")
        vals = kwargs.get("ExpressionAttributeValues", {})
        index_name = kwargs.get("IndexName")
        reverse = not kwargs.get("ScanIndexForward", True)
        limit = kwargs.get("Limit")
        exclusive_start_key = kwargs.get("ExclusiveStartKey") or {}

        out: list[dict] = []
        if index_name:
            pk = vals[":pk"]
            if "gsi_space_assignee_pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi_space_assignee_pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi_space_assignee_sk", ""), reverse=reverse)
                sort_attr = "gsi_space_assignee_sk"
            elif "gsi_space_status_pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi_space_status_pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi_space_status_sk", ""), reverse=reverse)
                sort_attr = "gsi_space_status_sk"
            elif "gsi_space_pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi_space_pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi_space_sk", ""), reverse=reverse)
                sort_attr = "gsi_space_sk"
            elif "gsi_member_pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi_member_pk") == pk]
                out.sort(key=lambda x: x.get("gsi_member_sk", ""), reverse=reverse)
                sort_attr = "gsi_member_sk"
            elif "gsi2pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi2pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi2sk", ""), reverse=reverse)
                sort_attr = "gsi2sk"
            elif "gsi1pk" in expr:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi1pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi1sk", ""), reverse=reverse)
                sort_attr = "gsi1sk"
            else:
                out = [deepcopy(v) for v in self.items.values() if v.get("gsi3pk") == pk and v.get("sk") == "META"]
                out.sort(key=lambda x: x.get("gsi3sk", ""), reverse=reverse)
                sort_attr = "gsi3sk"

            if exclusive_start_key:
                start = exclusive_start_key.get(sort_attr)
                if start:
                    out = [item for item in out if (item.get(sort_attr, "") < start if reverse else item.get(sort_attr, "") > start)]

            if isinstance(limit, int):
                page = out[:limit]
                resp = {"Items": page}
                if len(out) > limit and page:
                    resp["LastEvaluatedKey"] = {
                        "pk": page[-1]["pk"],
                        "sk": page[-1]["sk"],
                        sort_attr: page[-1].get(sort_attr),
                    }
                return resp
            return {"Items": out}

        if "begins_with" in expr:
            pk = vals[":pk"]
            prefix = vals[":sk_prefix"]
            out = [deepcopy(v) for (p, _), v in self.items.items() if p == pk and v.get("sk", "").startswith(prefix)]
            out.sort(key=lambda x: x.get("sk", ""), reverse=reverse)
            return {"Items": out}

        return {"Items": []}

    def update_item(self, *, Key: dict, UpdateExpression: str, ConditionExpression: str | None = None, ExpressionAttributeNames: dict | None = None, ExpressionAttributeValues: dict | None = None, **kwargs):
        item = self.items.get((Key["pk"], Key["sk"]))
        if not item:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "missing"}}, "UpdateItem")
        names = ExpressionAttributeNames or {}
        values = ExpressionAttributeValues or {}
        if ConditionExpression and "#version = :expected_version" in ConditionExpression:
            if self.fail_next_conditional_update:
                self.fail_next_conditional_update = False
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "stale"}}, "UpdateItem")
            version_attr = names["#version"]
            if item.get(version_attr) != values[":expected_version"]:
                raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "stale"}}, "UpdateItem")
        if UpdateExpression.startswith("SET "):
            for assignment in UpdateExpression[4:].split(","):
                left, right = assignment.strip().split(" = ", 1)
                attr = names.get(left, left)
                item[attr] = values[right]
        self.items[(Key["pk"], Key["sk"])] = item
        return {}


FAKE_TABLE = FakeTicketTable()
FAKE_USERS_TABLE = FakeUsersTable()
STORE._table = FAKE_TABLE
object.__setattr__(T, "users", FAKE_USERS_TABLE)


def _user(sub: str, role: Role) -> AuthenticatedUser:
    return AuthenticatedUser(sub=sub, role=role)


def _build_client(user: AuthenticatedUser) -> TestClient:
    app = create_app()

    async def _auth_override():
        return user

    async def _session_override():
        return {"user_sub": user.sub, "session_id": "sess_1", "role": user.role.value}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app)


def _build_api_key_client(monkeypatch, *, key_id: str, owner_sub: str, capabilities: list[str]) -> TestClient:
    app = create_app()

    monkeypatch.setattr(
        api_key_auth_dependency.api_keys,
        "parse_api_key",
        lambda raw: {"key_id": key_id, "secret": "test-secret"},
    )
    monkeypatch.setattr(
        api_key_auth_dependency.api_keys,
        "check_api_key_allowed",
        lambda _key_id, _secret, _client_ip: {"key_id": key_id, "user_sub": owner_sub, "capabilities": capabilities},
    )
    monkeypatch.setattr(
        main_app,
        "enforce_api_package_entitlement_pre_request",
        lambda _request: {},
    )
    return TestClient(app)


def setup_function():
    FAKE_TABLE.reset()
    FAKE_USERS_TABLE.reset()
    for sub, role in (
        ("user-1", Role.USER.value),
        ("user-2", Role.USER.value),
        ("admin-1", Role.ADMIN.value),
        ("admin-2", Role.ADMIN.value),
        ("root", Role.ROOT.value),
    ):
        FAKE_USERS_TABLE.put_user(sub, role)


def test_user_can_open_ticket_and_respond():
    client = _build_client(_user("user-1", Role.USER))
    created = client.post("/tickets", json={"subject": "Need account help", "description": "I cannot login"})
    assert created.status_code == 200
    ticket = created.json()["ticket"]
    assert ticket["owner_sub"] == "user-1"
    assert ticket["status"] == "open"

    reply = client.post(f"/tickets/{ticket['ticket_id']}/messages", json={"body": "Any updates?"})
    assert reply.status_code == 200
    updated = reply.json()["ticket"]
    assert len(updated["messages"]) == 2
    assert updated["status"] == "in_progress"


def test_admin_can_assign_and_close_ticket():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Billing issue", "description": "Refund requested"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    assigned = admin_client.post(
        f"/tickets/{created['ticket_id']}/assign",
        json={"assignee_admin_sub": "admin-2"},
    )
    assert assigned.status_code == 200
    assert assigned.json()["ticket"]["assigned_admin_sub"] == "admin-2"

    done = admin_client.post(f"/tickets/{created['ticket_id']}/status", json={"status": "done"})
    assert done.status_code == 200
    assert done.json()["ticket"]["status"] == "done"


def test_api_key_ticket_lifecycle_enforces_write_and_admin_scopes(monkeypatch):
    writer = _build_api_key_client(monkeypatch, key_id="k_writer", owner_sub="user-1", capabilities=["tickets:write", "tickets:read"])
    created = writer.post("/tickets", json={"subject": "API key ticket", "description": "created via key"})
    assert created.status_code == 200
    ticket_id = created.json()["ticket"]["ticket_id"]

    replied = writer.post(f"/tickets/{ticket_id}/messages", json={"body": "Follow-up from API key"})
    assert replied.status_code == 200

    denied_assign = writer.post(f"/tickets/{ticket_id}/assign", json={"assignee_admin_sub": "admin-1"})
    assert denied_assign.status_code == 403
    assert denied_assign.json()["detail"]["reason"] == "missing_scope"

    admin = _build_api_key_client(monkeypatch, key_id="k_admin", owner_sub="user-1", capabilities=["tickets:admin"])
    assigned = admin.post(f"/tickets/{ticket_id}/assign", json={"assignee_admin_sub": "admin-1"})
    assert assigned.status_code == 200
    assert assigned.json()["ticket"]["assigned_admin_sub"] == "admin-1"

    status = admin.post(f"/tickets/{ticket_id}/status", json={"status": "done"})
    assert status.status_code == 200
    assert status.json()["ticket"]["status"] == "done"

    listed = admin.get("/tickets")
    assert listed.status_code == 200
    assert any(item["ticket_id"] == ticket_id for item in listed.json()["items"])


def test_api_key_ticket_audit_events_include_actor_metadata(monkeypatch):
    admin = _build_api_key_client(monkeypatch, key_id="k_admin_audit", owner_sub="user-1", capabilities=["tickets:admin"])
    created = admin.post("/tickets", json={"subject": "Audit metadata", "description": "ensure metadata"})
    ticket_id = created.json()["ticket"]["ticket_id"]

    with patch("app.routers.tickets.audit_event") as audit:
        resp = admin.post(f"/tickets/{ticket_id}/status", json={"status": "done"})
    assert resp.status_code == 200
    matched = [call for call in audit.call_args_list if call.args and call.args[0] == "ticket_status_changed"]
    assert matched, "expected a ticket_status_changed audit event"
    kwargs = matched[0].kwargs
    assert kwargs["auth_type"] == "api_key"
    assert kwargs["api_key_id"] == "k_admin_audit"
    assert kwargs["api_key_owner_sub"] == "user-1"


def test_non_owner_user_cannot_read_ticket():
    owner_client = _build_client(_user("user-1", Role.USER))
    created = owner_client.post("/tickets", json={"subject": "Locked out", "description": "Please unlock"}).json()["ticket"]

    other_client = _build_client(_user("user-2", Role.USER))
    denied = other_client.get(f"/tickets/{created['ticket_id']}")
    assert denied.status_code == 403


def test_invalid_status_transition_returns_structured_400():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Status change", "description": "Test"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    invalid = admin_client.post(f"/tickets/{created['ticket_id']}/status", json={"status": "waiting_on_user"})
    assert invalid.status_code == 400
    detail = invalid.json()["detail"]["error"]
    assert detail["code"] == "invalid_ticket_status_transition"
    assert detail["details"]["current_status"] == "open"
    assert detail["details"]["requested_status"] == "waiting_on_user"


def test_admin_and_user_messages_drive_deterministic_state_changes():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Flow", "description": "Initial"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    admin_reply = admin_client.post(f"/tickets/{created['ticket_id']}/messages", json={"body": "Please provide logs"})
    assert admin_reply.status_code == 200
    assert admin_reply.json()["ticket"]["status"] == "waiting_on_user"

    user_reply = user_client.post(f"/tickets/{created['ticket_id']}/messages", json={"body": "Here are logs"})
    assert user_reply.status_code == 200
    assert user_reply.json()["ticket"]["status"] == "in_progress"


def test_assigning_to_non_admin_fails():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Access issue", "description": "Need help"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    assigned = admin_client.post(
        f"/tickets/{created['ticket_id']}/assign",
        json={"assignee_admin_sub": "user-2"},
    )
    assert assigned.status_code == 400


def test_assignment_persists_assignment_metadata():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Permissions", "description": "Please review"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    assigned = admin_client.post(
        f"/tickets/{created['ticket_id']}/assign",
        json={"assignee_admin_sub": "admin-2"},
    )
    assert assigned.status_code == 200
    payload = assigned.json()["ticket"]
    assert payload["assigned_admin_sub"] == "admin-2"
    assert payload["assigned_by"] == "admin-1"
    assert isinstance(payload["assigned_at"], int)


def test_assignment_conflict_returns_409():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Race", "description": "simulate conflict"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    FAKE_TABLE.fail_next_conditional_update = True
    assigned = admin_client.post(
        f"/tickets/{created['ticket_id']}/assign",
        json={"assignee_admin_sub": "admin-2"},
    )
    assert assigned.status_code == 409
    assert assigned.json()["detail"]["error"]["code"] == "ticket_update_conflict"


def test_status_conflict_returns_409():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Race status", "description": "simulate conflict"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    FAKE_TABLE.fail_next_conditional_update = True
    status_resp = admin_client.post(f"/tickets/{created['ticket_id']}/status", json={"status": "done"})
    assert status_resp.status_code == 409
    assert status_resp.json()["detail"]["error"]["code"] == "ticket_update_conflict"


def test_admin_list_supports_status_filter_and_pagination():
    user_client = _build_client(_user("user-1", Role.USER))
    for i in range(3):
        user_client.post("/tickets", json={"subject": f"Billing {i}", "description": "Refund requested"})

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    page1 = admin_client.get("/tickets", params={"status": "open", "limit": 2})
    assert page1.status_code == 200
    payload1 = page1.json()
    assert len(payload1["items"]) == 2
    assert payload1["next_cursor"]

    page2 = admin_client.get("/tickets", params={"status": "open", "limit": 2, "cursor": payload1["next_cursor"]})
    assert page2.status_code == 200
    payload2 = page2.json()
    assert len(payload2["items"]) >= 1


def test_admin_list_supports_assignee_filter():
    user_client = _build_client(_user("user-1", Role.USER))
    ticket1 = user_client.post("/tickets", json={"subject": "Assignee 1", "description": "help"}).json()["ticket"]
    ticket2 = user_client.post("/tickets", json={"subject": "Assignee 2", "description": "help"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    admin_client.post(f"/tickets/{ticket1['ticket_id']}/assign", json={"assignee_admin_sub": "admin-2"})

    filtered = admin_client.get("/tickets", params={"assignee_admin_sub": "admin-2"})
    assert filtered.status_code == 200
    ids = {item["ticket_id"] for item in filtered.json()["items"]}
    assert ticket1["ticket_id"] in ids
    assert ticket2["ticket_id"] not in ids


def test_user_list_only_returns_own_tickets_with_pagination():
    user1 = _build_client(_user("user-1", Role.USER))
    user2 = _build_client(_user("user-2", Role.USER))

    user1.post("/tickets", json={"subject": "Mine 1", "description": "d"})
    user1.post("/tickets", json={"subject": "Mine 2", "description": "d"})
    user2.post("/tickets", json={"subject": "Not mine", "description": "d"})

    page1 = user1.get("/tickets", params={"limit": 1})
    assert page1.status_code == 200
    payload1 = page1.json()
    assert len(payload1["items"]) == 1
    assert payload1["items"][0]["owner_sub"] == "user-1"
    assert payload1["next_cursor"]

    page2 = user1.get("/tickets", params={"limit": 1, "cursor": payload1["next_cursor"]})
    assert page2.status_code == 200
    payload2 = page2.json()
    assert len(payload2["items"]) == 1
    assert payload2["items"][0]["owner_sub"] == "user-1"


def test_admin_list_supports_owner_filter():
    user1 = _build_client(_user("user-1", Role.USER))
    user2 = _build_client(_user("user-2", Role.USER))
    t1 = user1.post("/tickets", json={"subject": "Owner A", "description": "d"}).json()["ticket"]
    t2 = user2.post("/tickets", json={"subject": "Owner B", "description": "d"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    filtered = admin_client.get("/tickets", params={"owner_sub": "user-1"})
    assert filtered.status_code == 200
    ids = {item["ticket_id"] for item in filtered.json()["items"]}
    assert t1["ticket_id"] in ids
    assert t2["ticket_id"] not in ids


def test_user_cannot_escape_owner_scope_with_owner_filter():
    user1 = _build_client(_user("user-1", Role.USER))
    user2 = _build_client(_user("user-2", Role.USER))
    user1.post("/tickets", json={"subject": "Mine", "description": "d"})
    other = user2.post("/tickets", json={"subject": "Other", "description": "d"}).json()["ticket"]

    filtered = user1.get("/tickets", params={"owner_sub": "user-2"})
    assert filtered.status_code == 200
    ids = {item["ticket_id"] for item in filtered.json()["items"]}
    assert other["ticket_id"] not in ids
    assert all(item["owner_sub"] == "user-1" for item in filtered.json()["items"])


def test_admin_ticket_summary_returns_counts():
    user1 = _build_client(_user("user-1", Role.USER))
    user2 = _build_client(_user("user-2", Role.USER))

    open_ticket = user1.post("/tickets", json={"subject": "Open issue", "description": "d"}).json()["ticket"]
    done_ticket = user2.post("/tickets", json={"subject": "Done issue", "description": "d"}).json()["ticket"]

    admin = _build_client(_user("admin-1", Role.ADMIN))
    admin.post(f"/tickets/{done_ticket['ticket_id']}/status", json={"status": "done"})

    # Force one ticket stale in fake table by mutating header metadata.
    key = (f"TICKET#{open_ticket['ticket_id']}", "META")
    FAKE_TABLE.items[key]["updated_at"] = 1

    resp = admin.get("/tickets/admin/summary", params={"stale_after_seconds": 60})
    assert resp.status_code == 200
    summary = resp.json()["summary"]
    assert summary["by_status"]["open"] >= 1
    assert summary["by_status"]["done"] >= 1
    assert summary["unassigned_count"] >= 1
    assert summary["stale_count"] >= 1
    assert summary["total_count"] >= 2


def test_user_cannot_access_admin_ticket_summary():
    user = _build_client(_user("user-1", Role.USER))
    resp = user.get("/tickets/admin/summary")
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"]["code"] == "admin_role_required"


def test_ticket_assignment_alert_fanout_targets_owner_and_assignee():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Assign me", "description": "d"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    with patch("app.routers.tickets.audit_event") as audit:
        resp = admin_client.post(
            f"/tickets/{created['ticket_id']}/assign",
            json={"assignee_admin_sub": "admin-2"},
        )
    assert resp.status_code == 200
    recipients = [call.args[1] for call in audit.call_args_list if call.args[0] == "ticket_assigned"]
    assert set(recipients) == {"user-1", "admin-2"}


def test_ticket_reply_alert_fanout_targets_user_or_assigned_admin():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Reply fanout", "description": "d"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    admin_client.post(f"/tickets/{created['ticket_id']}/assign", json={"assignee_admin_sub": "admin-2"})

    with patch("app.routers.tickets.audit_event") as audit_admin_reply:
        admin_reply = admin_client.post(f"/tickets/{created['ticket_id']}/messages", json={"body": "Need more info"})
    assert admin_reply.status_code == 200
    admin_recipients = [c.args[1] for c in audit_admin_reply.call_args_list if c.args[0] == "ticket_replied"]
    assert set(admin_recipients) == {"user-1"}

    assignee_client = _build_client(_user("admin-2", Role.ADMIN))
    assignee_client.post(f"/tickets/{created['ticket_id']}/status", json={"status": "done"})

    with patch("app.routers.tickets.audit_event") as audit_user_reply:
        user_reply = user_client.post(f"/tickets/{created['ticket_id']}/messages", json={"body": "here are details"})
    assert user_reply.status_code == 200
    user_recipients = [c.args[1] for c in audit_user_reply.call_args_list if c.args[0] == "ticket_replied"]
    reopened_recipients = [c.args[1] for c in audit_user_reply.call_args_list if c.args[0] == "ticket_reopened"]
    assert set(user_recipients) == {"admin-2"}
    assert set(reopened_recipients) == {"admin-2"}


def test_ticket_status_changed_alert_targets_owner():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Status notify", "description": "d"}).json()["ticket"]

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    with patch("app.routers.tickets.audit_event") as audit:
        resp = admin_client.post(f"/tickets/{created['ticket_id']}/status", json={"status": "done"})
    assert resp.status_code == 200
    recipients = [c.args[1] for c in audit.call_args_list if c.args[0] == "ticket_status_changed"]
    assert set(recipients) == {"user-1"}


def test_ticket_status_change_triggers_incident_sync_hook():
    user_client = _build_client(_user("user-1", Role.USER))
    created = user_client.post("/tickets", json={"subject": "Status sync", "description": "d"}).json()["ticket"]
    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    with patch("app.routers.tickets.sync_incident_from_ticket") as sync_hook:
        resp = admin_client.post(f"/tickets/{created['ticket_id']}/status", json={"status": "done"})
    assert resp.status_code == 200
    sync_hook.assert_called_once()


def test_space_entity_and_owner_membership_persisted():
    space = STORE.create_space(owner_sub="user-1", name="Ops board", visibility="shared")

    assert space["space_id"].startswith("spc_")
    assert space["owner_sub"] == "user-1"
    assert space["name"] == "Ops board"
    assert space["visibility"] == "shared"
    owner_member = next((item for item in space["members"] if item["member_sub"] == "user-1"), None)
    assert owner_member is not None
    assert owner_member["role"] == "owner"


def test_ticket_metadata_supports_space_id_and_assigned_to_sub():
    space = STORE.create_space(owner_sub="user-1", name="Customer board")
    ticket = STORE.create_ticket(owner_sub="user-1", subject="Space scoped", description="Need help", space_id=space["space_id"])

    assert ticket["space_id"] == space["space_id"]
    assert ticket["assigned_to_sub"] is None

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    assigned = admin_client.post(
        f"/tickets/{ticket['ticket_id']}/assign",
        json={"assignee_admin_sub": "admin-2"},
    )
    assert assigned.status_code == 200
    payload = assigned.json()["ticket"]
    assert payload["assigned_admin_sub"] == "admin-2"
    assert payload["assigned_to_sub"] == "admin-2"


def test_add_space_member_persists_membership_record():
    space = STORE.create_space(owner_sub="user-1", name="Project board")
    updated = STORE.add_space_member(space_id=space["space_id"], member_sub="user-2", role="editor")

    assert updated is not None
    membership = next((item for item in updated["members"] if item["member_sub"] == "user-2"), None)
    assert membership is not None
    assert membership["role"] == "editor"


def test_list_space_tickets_supports_index_backed_filters_and_cursor_pagination():
    space = STORE.create_space(owner_sub="user-1", name="Ops")
    first = STORE.create_ticket(owner_sub="user-1", subject="A", description="a", space_id=space["space_id"])
    second = STORE.create_ticket(owner_sub="user-1", subject="B", description="b", space_id=space["space_id"])

    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    admin_client.post(f"/tickets/{first['ticket_id']}/assign", json={"assignee_admin_sub": "admin-2"})

    page1 = STORE.list_space_tickets(space_id=space["space_id"], limit=1)
    assert len(page1["tickets"]) == 1
    assert page1["next_cursor"]

    page2 = STORE.list_space_tickets(space_id=space["space_id"], limit=1, cursor=page1["next_cursor"])
    assert len(page2["tickets"]) == 1
    assert page2["tickets"][0]["ticket_id"] != page1["tickets"][0]["ticket_id"]

    by_status = STORE.list_space_tickets(space_id=space["space_id"], status="open")
    assert {item["ticket_id"] for item in by_status["tickets"]} == {first["ticket_id"], second["ticket_id"]}

    by_assignee = STORE.list_space_tickets(space_id=space["space_id"], assigned_to_sub="admin-2")
    assert [item["ticket_id"] for item in by_assignee["tickets"]] == [first["ticket_id"]]


def test_list_spaces_for_member_is_index_backed_and_paginated():
    s1 = STORE.create_space(owner_sub="user-1", name="S1")
    s2 = STORE.create_space(owner_sub="user-2", name="S2")
    STORE.add_space_member(space_id=s2["space_id"], member_sub="user-1", role="editor")

    page1 = STORE.list_spaces_for_member(member_sub="user-1", limit=1)
    assert len(page1["spaces"]) == 1
    assert page1["next_cursor"]

    page2 = STORE.list_spaces_for_member(member_sub="user-1", limit=10, cursor=page1["next_cursor"])
    ids = {item["space_id"] for item in page1["spaces"] + page2["spaces"]}
    assert ids == {s1["space_id"], s2["space_id"]}


def test_space_acl_owner_editor_viewer_non_member_matrix():
    owner_client = _build_client(_user("user-1", Role.USER))
    editor_client = _build_client(_user("user-2", Role.USER))
    viewer_client = _build_client(_user("admin-2", Role.ADMIN))
    outsider_client = _build_client(_user("admin-1", Role.ADMIN))

    created_space = owner_client.post("/ticket-spaces", json={"name": "ACL Board", "visibility": "shared"})
    assert created_space.status_code == 200
    space_id = created_space.json()["space"]["space_id"]

    add_editor = owner_client.post(f"/ticket-spaces/{space_id}/members", json={"member_sub": "user-2", "role": "editor"})
    assert add_editor.status_code == 200
    add_viewer = owner_client.post(f"/ticket-spaces/{space_id}/members", json={"member_sub": "admin-2", "role": "viewer"})
    assert add_viewer.status_code == 200

    assert owner_client.get(f"/ticket-spaces/{space_id}").status_code == 200
    assert editor_client.get(f"/ticket-spaces/{space_id}").status_code == 200
    assert viewer_client.get(f"/ticket-spaces/{space_id}").status_code == 200
    outsider_get = outsider_client.get(f"/ticket-spaces/{space_id}")
    assert outsider_get.status_code == 403
    assert outsider_get.json()["detail"]["error"]["code"] == "space_access_forbidden"

    outsider_add_member = outsider_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "admin-1", "role": "viewer"},
    )
    assert outsider_add_member.status_code == 403

    viewer_add_member = viewer_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "admin-1", "role": "viewer"},
    )
    assert viewer_add_member.status_code == 403
    assert viewer_add_member.json()["detail"]["error"]["code"] == "space_owner_required"

    editor_ticket = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Editor ticket", "description": "created by editor"},
    )
    assert editor_ticket.status_code == 200
    ticket_id = editor_ticket.json()["ticket"]["ticket_id"]

    viewer_ticket = viewer_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Viewer ticket", "description": "should fail"},
    )
    assert viewer_ticket.status_code == 403
    assert viewer_ticket.json()["detail"]["error"]["code"] == "space_write_forbidden"

    outsider_ticket = outsider_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Outsider ticket", "description": "should fail"},
    )
    assert outsider_ticket.status_code == 403

    viewer_assign = viewer_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/assign",
        json={"assignee_sub": "user-2"},
    )
    assert viewer_assign.status_code == 403

    editor_assign = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/assign",
        json={"assignee_sub": "admin-2"},
    )
    assert editor_assign.status_code == 200

    viewer_message = viewer_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/messages",
        json={"body": "viewer should be blocked"},
    )
    assert viewer_message.status_code == 403

    editor_message = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/messages",
        json={"body": "editor update"},
    )
    assert editor_message.status_code == 200

    viewer_status = viewer_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/status",
        json={"status": "done"},
    )
    assert viewer_status.status_code == 403

    editor_status = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/status",
        json={"status": "done"},
    )
    assert editor_status.status_code == 200


def test_helpdesk_routes_remain_admin_centric_while_space_acls_apply():
    user_client = _build_client(_user("user-1", Role.USER))
    helpdesk = user_client.post("/tickets", json={"subject": "helpdesk", "description": "still works"})
    assert helpdesk.status_code == 200
    helpdesk_ticket_id = helpdesk.json()["ticket"]["ticket_id"]

    user_assign = user_client.post(
        f"/tickets/{helpdesk_ticket_id}/assign",
        json={"assignee_admin_sub": "admin-2"},
    )
    assert user_assign.status_code == 403
    assert user_assign.json()["detail"]["error"]["code"] == "admin_role_required"

    owner_space = user_client.post("/ticket-spaces", json={"name": "owner space"}).json()["space"]
    viewer_client = _build_client(_user("user-2", Role.USER))
    add_viewer = user_client.post(
        f"/ticket-spaces/{owner_space['space_id']}/members",
        json={"member_sub": "user-2", "role": "viewer"},
    )
    assert add_viewer.status_code == 200

    viewer_create = viewer_client.post(
        f"/ticket-spaces/{owner_space['space_id']}/tickets",
        json={"subject": "blocked", "description": "viewer can't write"},
    )
    assert viewer_create.status_code == 403
    assert viewer_create.json()["detail"]["error"]["code"] == "space_write_forbidden"


def test_space_member_delete_requires_owner_and_removes_member():
    owner_client = _build_client(_user("user-1", Role.USER))
    editor_client = _build_client(_user("user-2", Role.USER))

    created_space = owner_client.post("/ticket-spaces", json={"name": "Member delete board", "visibility": "shared"})
    assert created_space.status_code == 200
    space_id = created_space.json()["space"]["space_id"]

    added = owner_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "user-2", "role": "editor"},
    )
    assert added.status_code == 200

    denied = editor_client.delete(f"/ticket-spaces/{space_id}/members/user-2")
    assert denied.status_code == 403
    assert denied.json()["detail"]["error"]["code"] == "space_owner_required"

    removed = owner_client.delete(f"/ticket-spaces/{space_id}/members/user-2")
    assert removed.status_code == 200
    member_subs = {m["member_sub"] for m in removed.json()["space"]["members"]}
    assert member_subs == {"user-1"}

    no_access = editor_client.get(f"/ticket-spaces/{space_id}")
    assert no_access.status_code == 403
    assert no_access.json()["detail"]["error"]["code"] == "space_access_forbidden"


def test_space_member_delete_blocks_owner_removal_with_structured_400():
    owner_client = _build_client(_user("user-1", Role.USER))
    created_space = owner_client.post("/ticket-spaces", json={"name": "Owner delete guard"})
    assert created_space.status_code == 200
    space_id = created_space.json()["space"]["space_id"]

    blocked = owner_client.delete(f"/ticket-spaces/{space_id}/members/user-1")
    assert blocked.status_code == 400
    err = blocked.json()["detail"]["error"]
    assert err["code"] == "cannot_remove_space_owner"
    assert err["details"]["member_sub"] == "user-1"


def test_space_assignment_allows_self_and_other_member_with_metadata_persisted():
    owner_client = _build_client(_user("user-1", Role.USER))
    editor_client = _build_client(_user("user-2", Role.USER))
    viewer_client = _build_client(_user("admin-2", Role.ADMIN))

    created_space = owner_client.post("/ticket-spaces", json={"name": "Assignment Board", "visibility": "shared"})
    assert created_space.status_code == 200
    space_id = created_space.json()["space"]["space_id"]

    assert owner_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "user-2", "role": "editor"},
    ).status_code == 200
    assert owner_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "admin-2", "role": "viewer"},
    ).status_code == 200

    created_ticket = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Assign paths", "description": "validate assignee rules"},
    )
    assert created_ticket.status_code == 200
    ticket_id = created_ticket.json()["ticket"]["ticket_id"]

    assign_self = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/assign",
        json={"assignee_sub": "user-2"},
    )
    assert assign_self.status_code == 200
    self_ticket = assign_self.json()["ticket"]
    assert self_ticket["assigned_to_sub"] == "user-2"
    assert self_ticket["assigned_by"] == "user-2"
    assert isinstance(self_ticket["assigned_at"], int)

    assign_other_member = owner_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/assign",
        json={"assignee_sub": "admin-2"},
    )
    assert assign_other_member.status_code == 200
    other_ticket = assign_other_member.json()["ticket"]
    assert other_ticket["assigned_to_sub"] == "admin-2"
    assert other_ticket["assigned_by"] == "user-1"
    assert isinstance(other_ticket["assigned_at"], int)

    detail = viewer_client.get(f"/ticket-spaces/{space_id}/tickets/{ticket_id}")
    assert detail.status_code == 200
    detail_ticket = detail.json()["ticket"]
    assert detail_ticket["assigned_to_sub"] == "admin-2"
    assert detail_ticket["assigned_by"] == "user-1"
    assert isinstance(detail_ticket["assigned_at"], int)


def test_space_assignment_rejects_non_member_assignees_with_structured_400():
    owner_client = _build_client(_user("user-1", Role.USER))
    editor_client = _build_client(_user("user-2", Role.USER))

    created_space = owner_client.post("/ticket-spaces", json={"name": "Reject Board", "visibility": "shared"})
    assert created_space.status_code == 200
    space_id = created_space.json()["space"]["space_id"]

    assert owner_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "user-2", "role": "editor"},
    ).status_code == 200

    created_ticket = owner_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Invalid assignee", "description": "must fail"},
    )
    assert created_ticket.status_code == 200
    ticket_id = created_ticket.json()["ticket"]["ticket_id"]

    invalid_assign = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/assign",
        json={"assignee_sub": "admin-1"},
    )
    assert invalid_assign.status_code == 400
    err = invalid_assign.json()["detail"]["error"]
    assert err["code"] == "invalid_space_assignee"
    assert err["details"]["assignee_sub"] == "admin-1"


def test_space_ticket_routes_support_filters_and_cursor_pagination():
    owner_client = _build_client(_user("user-1", Role.USER))
    editor_client = _build_client(_user("user-2", Role.USER))

    created_space = owner_client.post("/ticket-spaces", json={"name": "Queue board", "visibility": "shared"})
    assert created_space.status_code == 200
    space_id = created_space.json()["space"]["space_id"]

    assert owner_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "user-2", "role": "editor"},
    ).status_code == 200

    first = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Queue A", "description": "first"},
    )
    second = editor_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Queue B", "description": "second"},
    )
    assert first.status_code == 200
    assert second.status_code == 200
    first_id = first.json()["ticket"]["ticket_id"]
    second_id = second.json()["ticket"]["ticket_id"]

    assign = owner_client.post(
        f"/ticket-spaces/{space_id}/tickets/{first_id}/assign",
        json={"assignee_sub": "user-2"},
    )
    assert assign.status_code == 200

    page1 = owner_client.get(f"/ticket-spaces/{space_id}/tickets", params={"limit": 1})
    assert page1.status_code == 200
    payload1 = page1.json()
    assert len(payload1["items"]) == 1
    assert payload1["next_cursor"]

    page2 = owner_client.get(
        f"/ticket-spaces/{space_id}/tickets",
        params={"limit": 1, "cursor": payload1["next_cursor"]},
    )
    assert page2.status_code == 200
    payload2 = page2.json()
    assert len(payload2["items"]) == 1
    assert {payload1["items"][0]["ticket_id"], payload2["items"][0]["ticket_id"]} == {first_id, second_id}

    by_assignee = owner_client.get(
        f"/ticket-spaces/{space_id}/tickets",
        params={"assignee_sub": "user-2"},
    )
    assert by_assignee.status_code == 200
    assignee_items = by_assignee.json()["items"]
    assert [item["ticket_id"] for item in assignee_items] == [first_id]

    by_status = owner_client.get(
        f"/ticket-spaces/{space_id}/tickets",
        params={"status": "open"},
    )
    assert by_status.status_code == 200
    status_ids = {item["ticket_id"] for item in by_status.json()["items"]}
    assert status_ids == {first_id, second_id}


def test_helpdesk_routes_unchanged_when_using_space_ticket_routes():
    user_client = _build_client(_user("user-1", Role.USER))
    admin_client = _build_client(_user("admin-1", Role.ADMIN))

    space = user_client.post("/ticket-spaces", json={"name": "space + helpdesk"}).json()["space"]
    created_space_ticket = user_client.post(
        f"/ticket-spaces/{space['space_id']}/tickets",
        json={"subject": "Space only", "description": "space flow"},
    )
    assert created_space_ticket.status_code == 200

    created_helpdesk = user_client.post("/tickets", json={"subject": "Helpdesk intact", "description": "default flow"})
    assert created_helpdesk.status_code == 200
    helpdesk_ticket = created_helpdesk.json()["ticket"]
    assert helpdesk_ticket["space_id"] is None

    listed_helpdesk = user_client.get("/tickets")
    assert listed_helpdesk.status_code == 200
    ids = {item["ticket_id"] for item in listed_helpdesk.json()["items"]}
    assert helpdesk_ticket["ticket_id"] in ids

    admin_assign = admin_client.post(
        f"/tickets/{helpdesk_ticket['ticket_id']}/assign",
        json={"assignee_admin_sub": "admin-2"},
    )
    assert admin_assign.status_code == 200
    assert admin_assign.json()["ticket"]["assigned_admin_sub"] == "admin-2"


def test_space_assignment_alert_fanout_targets_creator_and_assignee_without_duplicates():
    owner_client = _build_client(_user("user-1", Role.USER))

    created_space = owner_client.post("/ticket-spaces", json={"name": "fanout board", "visibility": "shared"})
    assert created_space.status_code == 200
    space_id = created_space.json()["space"]["space_id"]
    assert owner_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "user-2", "role": "editor"},
    ).status_code == 200

    created_ticket = owner_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Fanout assign", "description": "d"},
    )
    assert created_ticket.status_code == 200
    ticket_id = created_ticket.json()["ticket"]["ticket_id"]

    with patch("app.routers.ticket_spaces.audit_event") as audit:
        assigned = owner_client.post(
            f"/ticket-spaces/{space_id}/tickets/{ticket_id}/assign",
            json={"assignee_sub": "user-1"},
        )
    assert assigned.status_code == 200
    recipients = [c.args[1] for c in audit.call_args_list if c.args[0] == "ticket_assigned"]
    assert recipients == ["user-1"]


def test_space_reply_and_status_alert_fanout_targets_participants_assignee_and_creator():
    owner_client = _build_client(_user("user-1", Role.USER))
    editor_client = _build_client(_user("user-2", Role.USER))

    created_space = owner_client.post("/ticket-spaces", json={"name": "fanout participants", "visibility": "shared"})
    assert created_space.status_code == 200
    space_id = created_space.json()["space"]["space_id"]
    assert owner_client.post(
        f"/ticket-spaces/{space_id}/members",
        json={"member_sub": "user-2", "role": "editor"},
    ).status_code == 200

    created_ticket = owner_client.post(
        f"/ticket-spaces/{space_id}/tickets",
        json={"subject": "Fanout participants", "description": "d"},
    )
    assert created_ticket.status_code == 200
    ticket_id = created_ticket.json()["ticket"]["ticket_id"]

    assert owner_client.post(
        f"/ticket-spaces/{space_id}/tickets/{ticket_id}/assign",
        json={"assignee_sub": "user-2"},
    ).status_code == 200

    with patch("app.routers.ticket_spaces.audit_event") as audit_reply:
        replied = editor_client.post(
            f"/ticket-spaces/{space_id}/tickets/{ticket_id}/messages",
            json={"body": "editor reply"},
        )
    assert replied.status_code == 200
    reply_recipients = [c.args[1] for c in audit_reply.call_args_list if c.args[0] in {"ticket_replied", "ticket_reopened"}]
    assert set(reply_recipients) == {"user-1", "user-2"}

    with patch("app.routers.ticket_spaces.audit_event") as audit_status:
        status = owner_client.post(
            f"/ticket-spaces/{space_id}/tickets/{ticket_id}/status",
            json={"status": "done"},
        )
    assert status.status_code == 200
    status_recipients = [c.args[1] for c in audit_status.call_args_list if c.args[0] == "ticket_status_changed"]
    assert set(status_recipients) == {"user-1", "user-2"}


def test_admin_can_list_jira_source_with_filters_and_freshness_metadata(monkeypatch):
    admin_client = _build_client(_user("admin-1", Role.ADMIN))

    mirrors = [
        {
            "external_issue_id": "10001",
            "external_issue_key": "PROJ-1",
            "summary": "First",
            "status": "To Do",
            "project_key": "PROJ",
            "assignee_account_id": "acct-1",
            "reporter_account_id": "acct-r",
            "ingested_at": 1_000,
            "updated_at": 1_000,
            "updated_at_remote": "2026-04-01T00:00:00Z",
        },
        {
            "external_issue_id": "10002",
            "external_issue_key": "OPS-1",
            "summary": "Second",
            "status": "Done",
            "project_key": "OPS",
            "assignee_account_id": "acct-2",
            "reporter_account_id": "acct-r2",
            "ingested_at": 2_000,
            "updated_at": 2_000,
            "updated_at_remote": "2026-04-02T00:00:00Z",
        },
    ]
    monkeypatch.setattr(
        "app.routers.tickets.JiraTicketSyncStore.list_issue_mirrors_for_workspace",
        lambda self, *, workspace_id, limit=200: mirrors,
    )

    resp = admin_client.get(
        "/tickets",
        params={"source": "jira", "workspace_id": "ws_1", "jira_project_key": "PROJ", "jira_assignee_account_id": "acct-1"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert len(payload["items"]) == 1
    item = payload["items"][0]
    assert item["source"] == "jira"
    assert item["external_issue_key"] == "PROJ-1"
    assert item["sync_freshness"]["ingested_at"] == 1000
    assert item["sync_freshness"]["sync_state"] == "mirrored"


def test_unified_listing_is_stably_sorted_and_paginates(monkeypatch):
    admin_client = _build_client(_user("admin-1", Role.ADMIN))
    t1 = _build_client(_user("user-1", Role.USER)).post("/tickets", json={"subject": "T1", "description": "d"}).json()["ticket"]
    t2 = _build_client(_user("user-1", Role.USER)).post("/tickets", json={"subject": "T2", "description": "d"}).json()["ticket"]
    assert t1["ticket_id"] != t2["ticket_id"]

    mirrors = [
        {
            "external_issue_id": "20001",
            "external_issue_key": "PROJ-9",
            "summary": "J1",
            "status": "To Do",
            "project_key": "PROJ",
            "assignee_account_id": "acct-1",
            "reporter_account_id": "acct-r",
            "ingested_at": 1_500,
            "updated_at": 1_500,
            "updated_at_remote": "2026-04-01T00:00:00Z",
        }
    ]
    monkeypatch.setattr(
        "app.routers.tickets.JiraTicketSyncStore.list_issue_mirrors_for_workspace",
        lambda self, *, workspace_id, limit=200: mirrors,
    )

    page1 = admin_client.get("/tickets", params={"source": "unified", "workspace_id": "ws_1", "limit": 2})
    assert page1.status_code == 200
    p1 = page1.json()
    assert len(p1["items"]) == 2
    assert p1["next_cursor"]

    page2 = admin_client.get(
        "/tickets",
        params={"source": "unified", "workspace_id": "ws_1", "limit": 2, "cursor": p1["next_cursor"]},
    )
    assert page2.status_code == 200
    p2 = page2.json()
    assert len(p2["items"]) == 1

    combined = p1["items"] + p2["items"]
    keys = [(-int(item["updated_at"]), item["source"], item.get("ticket_id") or item.get("external_issue_id")) for item in combined]
    assert keys == sorted(keys)
    assert {item["source"] for item in combined} == {"internal", "jira"}


def test_non_admin_cannot_use_jira_or_unified_source_filters():
    user_client = _build_client(_user("user-1", Role.USER))
    jira_resp = user_client.get("/tickets", params={"source": "jira", "workspace_id": "ws_1"})
    assert jira_resp.status_code == 403
    unified_resp = user_client.get("/tickets", params={"source": "unified", "workspace_id": "ws_1"})
    assert unified_resp.status_code == 403
