from __future__ import annotations

import pytest

from app.services.questionnaires_repository import DynamoQuestionnaireRepository


class _FakeTable:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}

    def put_item(self, *, Item):
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None, ConditionExpression=None):
        item = self.items[(Key["pk"], Key["sk"])]
        if ConditionExpression == "#status=:in_progress":
            assert item["status"] == ExpressionAttributeValues[":in_progress"]

        assignments = UpdateExpression.replace("SET", "", 1).strip().split(",")
        for assignment in assignments:
            left, right = assignment.strip().split("=")
            left = left.strip()
            right = right.strip()
            if ExpressionAttributeNames and left in ExpressionAttributeNames:
                field = ExpressionAttributeNames[left]
            else:
                field = left
            item[field] = ExpressionAttributeValues[right]
        self.items[(Key["pk"], Key["sk"])] = item

    def query(self, **kwargs):
        vals = kwargs.get("ExpressionAttributeValues", {})
        pk = vals.get(":pk")
        index_name = kwargs.get("IndexName", "")
        out = []
        if "begins_with(sk" in (kwargs.get("KeyConditionExpression") or ""):
            prefix = vals.get(":sk_prefix", "")
            for item in self.items.values():
                if item.get("pk") == pk and item.get("sk", "").startswith(prefix):
                    out.append(item)
        else:
            for item in self.items.values():
                if index_name.endswith("owner-updated-index") and item.get("gsi_owner_pk") == pk:
                    out.append(item)
                if index_name.endswith("status-updated-index") and item.get("gsi_status_pk") == pk:
                    out.append(item)
                if index_name.endswith("published_slug-index") and item.get("gsi_published_pk") == pk:
                    out.append(item)
                if index_name.endswith("response_status-updated-index") and item.get("gsi_response_status_pk") == pk:
                    out.append(item)
        return {"Items": out[: kwargs.get("Limit", 25)]}


def test_submitted_response_cannot_be_reassigned() -> None:
    repo = DynamoQuestionnaireRepository(_table=_FakeTable())
    repo.put_questionnaire(questionnaire_id="q1", owner_id="u1", title="T")
    repo.put_response_session(response_session_id="r1", questionnaire_id="q1", version_id="v1")
    repo.mark_response_submitted(questionnaire_id="q1", response_session_id="r1")

    with pytest.raises(ValueError):
        repo.rebind_response_version(questionnaire_id="q1", response_session_id="r1", new_version_id="v2")


def test_published_lookup_indexed_by_slug() -> None:
    repo = DynamoQuestionnaireRepository(_table=_FakeTable())
    repo.put_questionnaire(questionnaire_id="q1", owner_id="u1", title="T")
    repo.put_version(questionnaire_id="q1", version_id="v1", version_number=1, schema_json={}, published_slug="survey-1")

    got = repo.get_published_by_slug("survey-1")
    assert got is not None
    assert got["version_id"] == "v1"


def test_schema_snapshot_excludes_deleted_questions_and_preserves_order() -> None:
    repo = DynamoQuestionnaireRepository(_table=_FakeTable())
    repo.put_questionnaire(questionnaire_id="q1", owner_id="u1", title="T")
    repo.create_section(questionnaire_id="q1", section_id="s1", title="A", description="", actor_sub="u1")
    repo.create_section(questionnaire_id="q1", section_id="s2", title="B", description="", actor_sub="u1")
    repo.reorder_sections(questionnaire_id="q1", ordered_section_ids=["s2", "s1"], actor_sub="u1")

    repo.create_question(
        questionnaire_id="q1",
        section_id="s2",
        question_id="q1",
        question_type="text",
        label="L1",
        required=False,
        hint="",
        config_json={},
        actor_sub="u1",
    )
    repo.create_question(
        questionnaire_id="q1",
        section_id="s2",
        question_id="q2",
        question_type="text",
        label="L2",
        required=False,
        hint="",
        config_json={},
        actor_sub="u1",
    )
    repo.delete_question(questionnaire_id="q1", section_id="s2", question_id="q1", actor_sub="u1")

    snapshot = repo.build_schema_snapshot("q1")
    assert [s["section_id"] for s in snapshot["sections"]] == ["s2", "s1"]
    assert [q["question_id"] for q in snapshot["sections"][0]["questions"]] == ["q2"]


def test_publish_creates_incrementing_immutable_versions() -> None:
    repo = DynamoQuestionnaireRepository(_table=_FakeTable())
    repo.put_questionnaire(questionnaire_id="q1", owner_id="u1", title="T")
    repo.create_section(questionnaire_id="q1", section_id="s1", title="S1", description="", actor_sub="u1")
    repo.create_question(
        questionnaire_id="q1",
        section_id="s1",
        question_id="q1",
        question_type="text",
        label="Before",
        required=False,
        hint="",
        config_json={},
        actor_sub="u1",
    )

    v1 = repo.publish_draft(questionnaire_id="q1", owner_id="u1", actor_sub="u1")
    assert v1["version_number"] == 1
    assert v1["schema_json"]["sections"][0]["questions"][0]["label"] == "Before"

    repo.update_question(
        questionnaire_id="q1",
        section_id="s1",
        question_id="q1",
        label="After",
        required=None,
        hint=None,
        config_json=None,
        actor_sub="u1",
    )
    v2 = repo.publish_draft(questionnaire_id="q1", owner_id="u1", actor_sub="u1")
    assert v2["version_number"] == 2
    assert v1["schema_json"]["sections"][0]["questions"][0]["label"] == "Before"
    assert v2["schema_json"]["sections"][0]["questions"][0]["label"] == "After"


def test_existing_response_stays_on_prior_version_after_republish() -> None:
    repo = DynamoQuestionnaireRepository(_table=_FakeTable())
    repo.put_questionnaire(questionnaire_id="q1", owner_id="u1", title="T")
    repo.create_section(questionnaire_id="q1", section_id="s1", title="S1", description="", actor_sub="u1")
    repo.create_question(
        questionnaire_id="q1",
        section_id="s1",
        question_id="q1",
        question_type="text",
        label="L1",
        required=False,
        hint="",
        config_json={},
        actor_sub="u1",
    )
    v1 = repo.publish_draft(questionnaire_id="q1", owner_id="u1", actor_sub="u1")
    session = repo.put_response_session(response_session_id="r1", questionnaire_id="q1", version_id=v1["version_id"])

    repo.create_question(
        questionnaire_id="q1",
        section_id="s1",
        question_id="q2",
        question_type="text",
        label="L2",
        required=False,
        hint="",
        config_json={},
        actor_sub="u1",
    )
    v2 = repo.publish_draft(questionnaire_id="q1", owner_id="u1", actor_sub="u1")

    got = repo._table.get_item(Key={"pk": "QNR#q1", "sk": "RESP#r1"})["Item"]
    assert session["version_id"] == v1["version_id"]
    assert got["version_id"] == v1["version_id"]
    assert got["version_id"] != v2["version_id"]


def test_sensitive_answers_are_encrypted_at_rest_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = DynamoQuestionnaireRepository(_table=_FakeTable())
    repo.put_questionnaire(questionnaire_id="q1", owner_id="u1", title="T")
    repo.create_section(questionnaire_id="q1", section_id="s1", title="S1", description="", actor_sub="u1")
    repo.create_question(
        questionnaire_id="q1",
        section_id="s1",
        question_id="q_addr",
        question_type="address",
        label="Address",
        required=False,
        hint="",
        config_json={},
        actor_sub="u1",
    )
    v1 = repo.publish_draft(questionnaire_id="q1", owner_id="u1", actor_sub="u1")
    repo.put_response_session(response_session_id="r1", questionnaire_id="q1", version_id=v1["version_id"])

    from app.core.settings import S

    prev = S.questionnaire_encrypt_sensitive_answers
    object.__setattr__(S, "questionnaire_encrypt_sensitive_answers", True)
    monkeypatch.setattr("app.services.questionnaires_repository.kms_encrypt", lambda plaintext: f"enc::{plaintext}")
    monkeypatch.setattr("app.services.questionnaires_repository.kms_decrypt", lambda ct: ct.replace("enc::", "").encode("utf-8"))
    try:
        repo.save_session_answers(questionnaire_id="q1", response_session_id="r1", answers_by_question_id={"q_addr": {"line1": "123 Main"}})
        raw = repo._table.get_item(Key={"pk": "QNR#q1", "sk": "ANSWER#r1#q_addr"})["Item"]
        assert raw["value_encrypted"] is True
        assert raw.get("value") is None
        assert str(raw.get("value_enc", "")).startswith("enc::")

        hydrated = repo.list_session_answers(questionnaire_id="q1", response_session_id="r1")
        assert hydrated["q_addr"]["line1"] == "123 Main"
    finally:
        object.__setattr__(S, "questionnaire_encrypt_sensitive_answers", prev)
