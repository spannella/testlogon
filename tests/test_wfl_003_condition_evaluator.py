"""Tests for WFL-003: Workflow Condition Evaluator."""
from __future__ import annotations

from decimal import Decimal

import pytest

from app.core.settings import S


@pytest.fixture(autouse=True)
def enable_flag():
    object.__setattr__(S, "crm_workflow_enabled", True)
    yield
    object.__setattr__(S, "crm_workflow_enabled", False)


class TestFlagOff:
    def test_flag_off_empty_conditions(self):
        object.__setattr__(S, "crm_workflow_enabled", False)
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions([], {})
        assert matched is False
        assert details == []

    def test_flag_off_with_conditions(self):
        object.__setattr__(S, "crm_workflow_enabled", False)
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions(
            [{"field": "status", "operator": "eq", "value": "open"}],
            {"status": "open"},
        )
        assert matched is False
        assert details == []


class TestEmptyConditions:
    def test_empty_list(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions([], {"status": "open"})
        assert matched is True
        assert details == []

    def test_empty_record(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions([], {})
        assert matched is True
        assert details == []


class TestOperatorEq:
    def test_match(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "status", "operator": "eq", "value": "open"}],
            {"status": "open"},
        )
        assert matched is True

    def test_mismatch(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "status", "operator": "eq", "value": "open"}],
            {"status": "closed"},
        )
        assert matched is False

    def test_case_insensitive(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "status", "operator": "eq", "value": "Open"}],
            {"status": "OPEN"},
        )
        assert matched is True

    def test_int_as_string(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "count", "operator": "eq", "value": "42"}],
            {"count": 42},
        )
        assert matched is True


class TestOperatorNeq:
    def test_neq_different(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "status", "operator": "neq", "value": "closed"}],
            {"status": "open"},
        )
        assert matched is True

    def test_neq_same(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "status", "operator": "neq", "value": "open"}],
            {"status": "open"},
        )
        assert matched is False


class TestOperatorContains:
    def test_contains_match(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "title", "operator": "contains", "value": "bug"}],
            {"title": "This is a BUG report"},
        )
        assert matched is True

    def test_contains_no_match(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "title", "operator": "contains", "value": "bug"}],
            {"title": "Feature request"},
        )
        assert matched is False

    def test_contains_empty_value_always_true(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "title", "operator": "contains", "value": ""}],
            {"title": "anything"},
        )
        assert matched is True


class TestOperatorGtLt:
    def test_gt_match(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "count", "operator": "gt", "value": "5"}],
            {"count": 10},
        )
        assert matched is True

    def test_lt_match(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "count", "operator": "lt", "value": "15"}],
            {"count": 10},
        )
        assert matched is True

    def test_gt_decimal(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "ts", "operator": "gt", "value": "1000000"}],
            {"ts": Decimal("1717000000")},
        )
        assert matched is True

    def test_gt_equal_not_matched(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "count", "operator": "gt", "value": "10"}],
            {"count": 10},
        )
        assert matched is False

    def test_lt_equal_not_matched(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "count", "operator": "lt", "value": "10"}],
            {"count": 10},
        )
        assert matched is False

    def test_non_numeric_type_error(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions(
            [{"field": "name", "operator": "gt", "value": "5"}],
            {"name": "Alice"},
        )
        assert matched is False
        assert details[0].get("error") == "type_error"


class TestOperatorIsEmpty:
    def test_none_is_empty(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "note", "operator": "is_empty"}],
            {"note": None},
        )
        assert matched is True

    def test_blank_string_is_empty(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "note", "operator": "is_empty"}],
            {"note": "   "},
        )
        assert matched is True

    def test_zero_not_empty(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "count", "operator": "is_empty"}],
            {"count": 0},
        )
        assert matched is False

    def test_false_not_empty(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "flag", "operator": "is_empty"}],
            {"flag": False},
        )
        assert matched is False

    def test_non_empty_string_not_empty(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "note", "operator": "is_empty"}],
            {"note": "hello"},
        )
        assert matched is False

    def test_is_not_empty(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "name", "operator": "is_not_empty"}],
            {"name": "Alice"},
        )
        assert matched is True


class TestMissingField:
    def test_absent_key_eq(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "status", "operator": "eq", "value": "open"}],
            {},
        )
        assert matched is False

    def test_absent_key_is_empty(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "status", "operator": "is_empty"}],
            {},
        )
        assert matched is True

    def test_absent_key_gt(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions(
            [{"field": "count", "operator": "gt", "value": "5"}],
            {},
        )
        assert matched is False
        assert details[0].get("error") == "type_error"

    def test_dot_notation_present(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "meta.priority", "operator": "eq", "value": "high"}],
            {"meta": {"priority": "high"}},
        )
        assert matched is True

    def test_dot_notation_absent_parent(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "meta.priority", "operator": "eq", "value": "high"}],
            {},
        )
        assert matched is False

    def test_dot_notation_non_dict_parent(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, _ = evaluate_conditions(
            [{"field": "meta.priority", "operator": "eq", "value": "high"}],
            {"meta": "not a dict"},
        )
        assert matched is False


class TestUnknownOperator:
    def test_unknown_operator(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions(
            [{"field": "status", "operator": "magic_op", "value": "x"}],
            {"status": "x"},
        )
        assert matched is False
        assert details[0].get("error") == "unknown_operator"
        assert len(details) == 1  # short-circuits after unknown


class TestShortCircuit:
    def test_failure_at_index_0(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions(
            [
                {"field": "a", "operator": "eq", "value": "wrong"},
                {"field": "b", "operator": "eq", "value": "right"},
                {"field": "c", "operator": "eq", "value": "right"},
            ],
            {"a": "right", "b": "right", "c": "right"},
        )
        assert matched is False
        assert len(details) == 1

    def test_failure_at_index_1(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions(
            [
                {"field": "a", "operator": "eq", "value": "right"},
                {"field": "b", "operator": "eq", "value": "wrong"},
                {"field": "c", "operator": "eq", "value": "right"},
            ],
            {"a": "right", "b": "right", "c": "right"},
        )
        assert matched is False
        assert len(details) == 2

    def test_all_pass(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        matched, details = evaluate_conditions(
            [
                {"field": "a", "operator": "eq", "value": "right"},
                {"field": "b", "operator": "eq", "value": "right"},
                {"field": "c", "operator": "eq", "value": "right"},
            ],
            {"a": "right", "b": "right", "c": "right"},
        )
        assert matched is True
        assert len(details) == 3


class TestDetails:
    def test_detail_entry_keys(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        _, details = evaluate_conditions(
            [{"field": "status", "operator": "eq", "value": "open"}],
            {"status": "open"},
        )
        entry = details[0]
        assert "field" in entry
        assert "operator" in entry
        assert "value" in entry
        assert "record_value" in entry
        assert "passed" in entry

    def test_record_value_is_str(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        _, details = evaluate_conditions(
            [{"field": "count", "operator": "eq", "value": "5"}],
            {"count": 5},
        )
        assert isinstance(details[0]["record_value"], str)

    def test_absent_value_in_condition(self):
        from app.services.workflow_condition_evaluator import evaluate_conditions
        _, details = evaluate_conditions(
            [{"field": "status", "operator": "is_empty"}],
            {},
        )
        assert details[0]["value"] == ""
