from __future__ import annotations

import pytest

from app.services.questionnaire_validation import (
    evaluate_form_rules,
    evaluate_group_rules,
    validate_form_submission,
    validate_question_answers,
    validate_with_group_rules,
)


def _schema_for(question: dict) -> dict:
    return {"sections": [{"section_id": "s1", "questions": [question]}]}


def _codes(errors: dict, qid: str = "q1") -> list[str]:
    return [e["code"] for e in errors.get(qid, [])]


def test_required_validation() -> None:
    schema = _schema_for({"question_id": "q1", "type": "text", "required": True, "config_json": {}})
    errors = validate_question_answers(schema, {"q1": ""})
    assert _codes(errors) == ["required"]


def test_text_constraints_min_max_and_pattern() -> None:
    schema = _schema_for(
        {
            "question_id": "q1",
            "type": "text",
            "required": True,
            "config_json": {"minLength": 3, "maxLength": 5, "pattern": r"^[A-Z]+$"},
        }
    )
    assert _codes(validate_question_answers(schema, {"q1": "ab"})) == ["too_short", "pattern_mismatch"]
    assert _codes(validate_question_answers(schema, {"q1": "ABCDEF"})) == ["too_long"]
    assert validate_question_answers(schema, {"q1": "ABCD"}) == {}


def test_select_and_radio_validation() -> None:
    base = {"question_id": "q1", "required": True, "config_json": {"options": ["a", "b"]}}
    select_schema = _schema_for({**base, "type": "select"})
    radio_schema = _schema_for({**base, "type": "radio"})

    assert _codes(validate_question_answers(select_schema, {"q1": "c"})) == ["invalid_option"]
    assert _codes(validate_question_answers(radio_schema, {"q1": 2})) == ["invalid_type"]
    assert validate_question_answers(select_schema, {"q1": "a"}) == {}


def test_multiselect_validation_boundaries() -> None:
    schema = _schema_for(
        {
            "question_id": "q1",
            "type": "multiselect",
            "required": True,
            "config_json": {"options": ["x", "y", "z"], "minSelections": 1, "maxSelections": 2},
        }
    )

    assert _codes(validate_question_answers(schema, {"q1": []})) == ["required"]
    assert _codes(validate_question_answers(schema, {"q1": ["x", "bad"]})) == ["invalid_option"]
    assert _codes(validate_question_answers(schema, {"q1": ["x", "y", "z"]})) == ["too_many_choices"]
    assert validate_question_answers(schema, {"q1": ["x", "z"]}) == {}


def test_slider_validation_min_max_step() -> None:
    schema = _schema_for(
        {
            "question_id": "q1",
            "type": "slider",
            "required": True,
            "config_json": {"min": 0, "max": 10, "step": 2},
        }
    )

    assert _codes(validate_question_answers(schema, {"q1": -1})) == ["below_min"]
    assert _codes(validate_question_answers(schema, {"q1": 11})) == ["above_max"]
    assert _codes(validate_question_answers(schema, {"q1": 3})) == ["invalid_step"]
    assert validate_question_answers(schema, {"q1": 4}) == {}


def test_date_validation_format_and_value() -> None:
    schema = _schema_for({"question_id": "q1", "type": "date", "required": True, "config_json": {}})
    assert _codes(validate_question_answers(schema, {"q1": "2024/01/10"})) == ["invalid_date_format"]
    assert _codes(validate_question_answers(schema, {"q1": "2024-13-10"})) == ["invalid_date_format"]
    assert validate_question_answers(schema, {"q1": "2024-01-10"}) == {}


def test_time_validation_format_and_value() -> None:
    schema = _schema_for({"question_id": "q1", "type": "time", "required": True, "config_json": {}})
    assert _codes(validate_question_answers(schema, {"q1": "7pm"})) == ["invalid_time_format"]
    assert _codes(validate_question_answers(schema, {"q1": "24:00"})) == ["invalid_time_format"]
    assert validate_question_answers(schema, {"q1": "23:59"}) == {}


def test_timezone_validation() -> None:
    schema = _schema_for({"question_id": "q1", "type": "timezone", "required": True, "config_json": {}})
    assert _codes(validate_question_answers(schema, {"q1": "Mars/Olympus"})) == ["invalid_timezone"]
    assert validate_question_answers(schema, {"q1": "UTC"}) == {}


def test_address_validation_required_fields() -> None:
    schema = _schema_for(
        {
            "question_id": "q1",
            "type": "address",
            "required": True,
            "config_json": {"requiredFields": ["line1", "city", "postal_code", "country"]},
        }
    )

    errors = validate_question_answers(schema, {"q1": {"line1": "1 Main", "city": "", "country": "US"}})
    assert _codes(errors) == ["missing_address_field", "missing_address_field"]
    assert validate_question_answers(
        schema,
        {"q1": {"line1": "1 Main", "city": "Springfield", "postal_code": "12345", "country": "US"}},
    ) == {}


def test_errors_are_keyed_by_question_id_and_independent_of_order() -> None:
    schema = {
        "sections": [
            {
                "section_id": "s1",
                "questions": [
                    {"question_id": "q_date", "type": "date", "required": True, "config_json": {}},
                    {"question_id": "q_slider", "type": "slider", "required": True, "config_json": {"min": 1, "max": 5, "step": 1}},
                ],
            }
        ]
    }

    answers = {"q_slider": 3, "q_date": "bad"}
    errors = validate_question_answers(schema, answers)
    assert set(errors.keys()) == {"q_date"}
    assert _codes(errors, "q_date") == ["invalid_date_format"]


def test_group_min_answered_with_partial_completion() -> None:
    schema = {
        "sections": [
            {
                "section_id": "employment",
                "questions": [
                    {"question_id": "q_role", "type": "text", "required": False, "config_json": {}},
                    {"question_id": "q_company", "type": "text", "required": False, "config_json": {}},
                    {"question_id": "q_years", "type": "slider", "required": False, "config_json": {"min": 0, "max": 40, "step": 1}},
                ],
            }
        ]
    }
    group_rules = [
        {
            "rule_id": "r_min",
            "group_id": "employment",
            "rule_type": "min_answered",
            "question_ids": ["q_role", "q_company", "q_years"],
            "config_json": {"min_answered": 2},
        }
    ]

    errors = validate_with_group_rules(schema, {"q_role": "Engineer"}, group_rules)
    assert _codes(errors, "group:employment") == ["group_min_answered"]

    no_errors = validate_with_group_rules(schema, {"q_role": "Engineer", "q_company": "Acme"}, group_rules)
    assert "group:employment" not in no_errors


def test_group_dependency_rule() -> None:
    schema = {
        "sections": [
            {
                "section_id": "preferences",
                "questions": [
                    {"question_id": "q_opt_in", "type": "radio", "required": False, "config_json": {"options": ["yes", "no"]}},
                    {"question_id": "q_email", "type": "text", "required": False, "config_json": {}},
                ],
            }
        ]
    }
    rules = [
        {
            "rule_id": "r_dep",
            "group_id": "preferences",
            "rule_type": "requires_if_answered",
            "question_ids": ["q_opt_in", "q_email"],
            "config_json": {"if_question_id": "q_opt_in", "required_question_ids": ["q_email"]},
        }
    ]

    errors = validate_with_group_rules(schema, {"q_opt_in": "yes"}, rules)
    assert _codes(errors, "group:preferences") == ["group_dependency_required"]

    no_errors = validate_with_group_rules(schema, {"q_opt_in": "yes", "q_email": "a@example.com"}, rules)
    assert "group:preferences" not in no_errors


def test_group_mutually_exclusive_constraint() -> None:
    schema = {
        "sections": [
            {
                "section_id": "contact",
                "questions": [
                    {"question_id": "q_phone", "type": "text", "required": False, "config_json": {}},
                    {"question_id": "q_sms", "type": "text", "required": False, "config_json": {}},
                ],
            }
        ]
    }
    rules = [
        {
            "rule_id": "r_excl",
            "group_id": "contact",
            "rule_type": "mutually_exclusive",
            "question_ids": ["q_phone", "q_sms"],
            "config_json": {},
        }
    ]

    errors = validate_with_group_rules(schema, {"q_phone": "111", "q_sms": "222"}, rules)
    assert _codes(errors, "group:contact") == ["group_mutually_exclusive"]


def test_group_errors_merge_with_question_errors() -> None:
    schema = {
        "sections": [
            {
                "section_id": "mix",
                "questions": [
                    {"question_id": "q_date", "type": "date", "required": True, "config_json": {}},
                    {"question_id": "q_other", "type": "text", "required": False, "config_json": {}},
                ],
            }
        ]
    }
    rules = [
        {
            "rule_id": "r_min",
            "group_id": "mix",
            "rule_type": "min_answered",
            "question_ids": ["q_date", "q_other"],
            "config_json": {"min_answered": 2},
        }
    ]

    errors = validate_with_group_rules(schema, {"q_date": "not-a-date"}, rules)
    assert _codes(errors, "q_date") == ["invalid_date_format"]
    assert _codes(errors, "group:mix") == ["group_min_answered"]


def test_group_rule_rejects_unknown_references() -> None:
    questions_by_id = {"q1": {"question_id": "q1", "type": "text", "required": False, "config_json": {}}}
    rules = [
        {
            "rule_id": "r_invalid",
            "group_id": "g1",
            "rule_type": "min_answered",
            "question_ids": ["q1", "missing_q"],
            "config_json": {"min_answered": 1},
        }
    ]

    with pytest.raises(ValueError, match="unknown question IDs"):
        evaluate_group_rules(rules, answers_by_question_id={}, questions_by_id=questions_by_id)


def test_form_rule_cross_section_dependency_and_order() -> None:
    schema = {
        "sections": [
            {
                "section_id": "personal",
                "questions": [
                    {"question_id": "q_country", "type": "select", "required": False, "config_json": {"options": ["US", "CA"]}},
                ],
            },
            {
                "section_id": "tax",
                "questions": [
                    {"question_id": "q_ssn", "type": "text", "required": False, "config_json": {}},
                ],
            },
        ]
    }
    form_rules = [
        {
            "rule_id": "fr1",
            "rule_type": "requires_if_answered",
            "config_json": {"if_question_id": "q_country", "required_question_ids": ["q_ssn"]},
            "blocking": True,
        }
    ]

    result = validate_form_submission(
        schema_json=schema,
        answers_by_question_id={"q_country": "US"},
        group_rules=[],
        form_rules=form_rules,
    )
    assert result["can_submit"] is False
    assert _codes(result["errors"], "form:fr1") == ["form_dependency_required"]


def test_form_level_runs_after_question_and_group_rules() -> None:
    schema = {
        "sections": [
            {
                "section_id": "s1",
                "questions": [
                    {"question_id": "q_date", "type": "date", "required": True, "config_json": {}},
                    {"question_id": "q_toggle", "type": "radio", "required": False, "config_json": {"options": ["yes", "no"]}},
                ],
            },
            {
                "section_id": "s2",
                "questions": [
                    {"question_id": "q_dep", "type": "text", "required": False, "config_json": {}},
                ],
            },
        ]
    }
    group_rules = [
        {
            "rule_id": "gr1",
            "group_id": "s1",
            "rule_type": "min_answered",
            "question_ids": ["q_date", "q_toggle", "q_dep"],
            "config_json": {"min_answered": 3},
        }
    ]
    form_rules = [
        {
            "rule_id": "fr2",
            "rule_type": "requires_if_answered",
            "config_json": {"if_question_id": "q_toggle", "required_question_ids": ["q_dep"]},
            "blocking": True,
        }
    ]

    result = validate_form_submission(
        schema_json=schema,
        answers_by_question_id={"q_date": "bad", "q_toggle": "yes"},
        group_rules=group_rules,
        form_rules=form_rules,
    )

    assert _codes(result["errors"], "q_date") == ["invalid_date_format"]
    assert _codes(result["errors"], "group:s1") == ["group_min_answered"]
    assert _codes(result["errors"], "form:fr2") == ["form_dependency_required"]
    assert result["has_blocking_form_error"] is True
    assert result["can_submit"] is False


def test_form_rule_rejects_unknown_references() -> None:
    with pytest.raises(ValueError, match="Form rule references unknown question IDs"):
        evaluate_form_rules(
            form_rules=[
                {
                    "rule_id": "fr_bad",
                    "rule_type": "mutually_exclusive",
                    "config_json": {"question_ids": ["missing_a", "missing_b"]},
                    "blocking": True,
                }
            ],
            answers_by_question_id={},
            questions_by_id={"q1": {"question_id": "q1", "type": "text"}},
        )
