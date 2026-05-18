from __future__ import annotations

from app.services import messaging_thread_contract as contract


def test_thread_linkage_field_names_are_canonical_and_stable() -> None:
    assert contract.MESSAGE_FIELD_REPLY_TO_ID == "reply_to_message_id"
    assert contract.MESSAGE_FIELD_PARENT_ID == "parent_message_id"
    assert contract.MESSAGE_FIELD_THREAD_ID == "thread_id"
    assert contract.MESSAGE_FIELD_THREAD_ROOT_ID == "thread_root_message_id"


def test_thread_required_fields_include_persistence_basics() -> None:
    assert contract.THREAD_REQUIRED_FIELDS == (
        "id",
        "conversation_id",
        "root_message_id",
        "created_at",
        "created_by",
    )


def test_thread_states_are_defined_for_domain_lifecycle() -> None:
    assert contract.THREAD_STATES == (
        "inline",
        "promoted",
        "reconciling",
        "archived",
    )
