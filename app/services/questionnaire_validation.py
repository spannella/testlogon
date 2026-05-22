from __future__ import annotations

import re
from decimal import Decimal
from datetime import datetime
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field

from app.contracts.questionnaire_validation_contract import VALIDATION_CONTRACT_VERSION

ERROR_CATALOG: dict[str, str] = {
    "required": "Answer is required.",
    "invalid_type": "Answer has an invalid type.",
    "invalid_option": "Answer is not one of the allowed options.",
    "too_short": "Answer is shorter than minimum length.",
    "too_long": "Answer is longer than maximum length.",
    "pattern_mismatch": "Answer does not match required pattern.",
    "too_few_choices": "Too few options selected.",
    "too_many_choices": "Too many options selected.",
    "below_min": "Answer is below minimum value.",
    "above_max": "Answer is above maximum value.",
    "invalid_step": "Answer does not match slider step increment.",
    "invalid_date_format": "Answer must be in YYYY-MM-DD format.",
    "invalid_time_format": "Answer must be in HH:MM format.",
    "invalid_timezone": "Answer is not a valid IANA timezone.",
    "invalid_address": "Answer must be an object with expected address fields.",
    "missing_address_field": "Address is missing a required field.",
    "group_min_answered": "Not enough questions in the group were answered.",
    "group_dependency_required": "Required dependent answers are missing.",
    "group_mutually_exclusive": "Only one question in this group can be answered.",
    "group_rule_invalid_reference": "Group rule references unknown question IDs.",
    "form_dependency_required": "Form-level dependent answers are missing.",
    "form_mutually_exclusive": "Form-level exclusivity constraint violated.",
    "form_rule_invalid_reference": "Form rule references unknown question IDs.",
}

GroupRuleType = Literal["min_answered", "requires_if_answered", "mutually_exclusive"]
FormRuleType = Literal["requires_if_answered", "mutually_exclusive"]


class GroupValidationRule(BaseModel):
    rule_id: str = Field(..., min_length=1)
    group_id: str = Field(..., min_length=1)
    rule_type: GroupRuleType
    question_ids: list[str] = Field(default_factory=list)
    config_json: dict[str, Any] = Field(default_factory=dict)


class FormValidationRule(BaseModel):
    rule_id: str = Field(..., min_length=1)
    rule_type: FormRuleType
    config_json: dict[str, Any] = Field(default_factory=dict)
    blocking: bool = True


def validate_question_answers(schema_json: dict[str, Any], answers_by_question_id: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    """Validate answer payload against questionnaire schema snapshot.

    Returns structured errors keyed by question_id.
    """
    errors: dict[str, list[dict[str, str]]] = {}
    for question in _iter_questions(schema_json):
        question_id = str(question.get("question_id", "")).strip()
        if not question_id:
            continue
        q_errors = _validate_single_question(question, answers_by_question_id.get(question_id))
        if q_errors:
            errors[question_id] = q_errors
    return errors


def validate_with_group_rules(
    schema_json: dict[str, Any],
    answers_by_question_id: dict[str, Any],
    group_rules: list[dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, str]]]:
    """Run question-level validators and merge group-level rule failures into a unified error map.

    Group-level errors are keyed by `group:<group_id>` so UIs can render separately from per-question errors.
    """
    merged = validate_question_answers(schema_json, answers_by_question_id)
    if not group_rules:
        return merged

    questions_by_id = {q["question_id"]: q for q in _iter_questions(schema_json) if q.get("question_id")}
    group_errors = evaluate_group_rules(group_rules, answers_by_question_id, questions_by_id)
    for key, errs in group_errors.items():
        merged.setdefault(key, []).extend(errs)
    return merged


def validate_form_submission(
    *,
    schema_json: dict[str, Any],
    answers_by_question_id: dict[str, Any],
    group_rules: list[dict[str, Any]] | None = None,
    form_rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run question->group->form validations and return a submission-ready result payload."""
    merged = validate_with_group_rules(
        schema_json=schema_json,
        answers_by_question_id=answers_by_question_id,
        group_rules=group_rules,
    )
    questions_by_id = {q["question_id"]: q for q in _iter_questions(schema_json) if q.get("question_id")}

    form_errors = evaluate_form_rules(
        form_rules=form_rules or [],
        answers_by_question_id=answers_by_question_id,
        questions_by_id=questions_by_id,
    )
    for key, errs in form_errors.items():
        merged.setdefault(key, []).extend(errs)

    has_blocking_form_error = any(err.get("blocking") for errs in form_errors.values() for err in errs)
    return {
        "contract_version": VALIDATION_CONTRACT_VERSION,
        "errors": merged,
        "is_valid": not merged,
        "can_submit": not has_blocking_form_error and not any(k.startswith("form:") for k in merged),
        "has_blocking_form_error": has_blocking_form_error,
    }


def evaluate_group_rules(
    group_rules: list[dict[str, Any]],
    answers_by_question_id: dict[str, Any],
    questions_by_id: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, str]]]:
    errors: dict[str, list[dict[str, str]]] = {}
    for raw_rule in group_rules:
        rule = GroupValidationRule.model_validate(raw_rule)
        scoped_question_ids = rule.question_ids or [qid for qid in questions_by_id.keys()]
        unknown = [qid for qid in scoped_question_ids if qid not in questions_by_id]
        if unknown:
            raise ValueError(f"{ERROR_CATALOG['group_rule_invalid_reference']}: {','.join(unknown)}")

        key = f"group:{rule.group_id}"
        rule_errors: list[dict[str, str]] = []

        if rule.rule_type == "min_answered":
            minimum = int(rule.config_json.get("min_answered", 1))
            answered_count = sum(1 for qid in scoped_question_ids if not _is_empty(answers_by_question_id.get(qid)))
            if answered_count < minimum:
                rule_errors.append(
                    _error(
                        "group_min_answered",
                        f"At least {minimum} answers required in group '{rule.group_id}', got {answered_count}.",
                    )
                )

        if rule.rule_type == "requires_if_answered":
            trigger_question_id = str(rule.config_json.get("if_question_id", "")).strip()
            required_question_ids = [str(v) for v in rule.config_json.get("required_question_ids", []) if isinstance(v, str)]
            unknown_required = [qid for qid in [trigger_question_id, *required_question_ids] if qid and qid not in questions_by_id]
            if unknown_required:
                raise ValueError(f"{ERROR_CATALOG['group_rule_invalid_reference']}: {','.join(unknown_required)}")
            if trigger_question_id and not _is_empty(answers_by_question_id.get(trigger_question_id)):
                missing = [qid for qid in required_question_ids if _is_empty(answers_by_question_id.get(qid))]
                if missing:
                    rule_errors.append(
                        _error(
                            "group_dependency_required",
                            f"Question(s) {', '.join(missing)} required because '{trigger_question_id}' was answered.",
                        )
                    )

        if rule.rule_type == "mutually_exclusive":
            answered = [qid for qid in scoped_question_ids if not _is_empty(answers_by_question_id.get(qid))]
            if len(answered) > 1:
                rule_errors.append(
                    _error(
                        "group_mutually_exclusive",
                        f"Questions {', '.join(answered)} cannot be answered together in group '{rule.group_id}'.",
                    )
                )

        if rule_errors:
            errors.setdefault(key, []).extend(rule_errors)
    return errors


def evaluate_form_rules(
    *,
    form_rules: list[dict[str, Any]],
    answers_by_question_id: dict[str, Any],
    questions_by_id: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    errors: dict[str, list[dict[str, Any]]] = {}
    for raw_rule in form_rules:
        rule = FormValidationRule.model_validate(raw_rule)
        rule_errors: list[dict[str, Any]] = []
        key = f"form:{rule.rule_id}"

        if rule.rule_type == "requires_if_answered":
            trigger_question_id = str(rule.config_json.get("if_question_id", "")).strip()
            required_question_ids = [str(v) for v in rule.config_json.get("required_question_ids", []) if isinstance(v, str)]
            unknown_refs = [qid for qid in [trigger_question_id, *required_question_ids] if qid and qid not in questions_by_id]
            if unknown_refs:
                raise ValueError(f"{ERROR_CATALOG['form_rule_invalid_reference']}: {','.join(unknown_refs)}")
            if trigger_question_id and not _is_empty(answers_by_question_id.get(trigger_question_id)):
                missing = [qid for qid in required_question_ids if _is_empty(answers_by_question_id.get(qid))]
                if missing:
                    rule_errors.append(
                        {
                            **_error(
                                "form_dependency_required",
                                f"Form rule '{rule.rule_id}' requires {', '.join(missing)} when {trigger_question_id} is answered.",
                            ),
                            "blocking": rule.blocking,
                            "rule_id": rule.rule_id,
                        }
                    )

        if rule.rule_type == "mutually_exclusive":
            question_ids = [str(v) for v in rule.config_json.get("question_ids", []) if isinstance(v, str)]
            unknown_refs = [qid for qid in question_ids if qid not in questions_by_id]
            if unknown_refs:
                raise ValueError(f"{ERROR_CATALOG['form_rule_invalid_reference']}: {','.join(unknown_refs)}")
            answered = [qid for qid in question_ids if not _is_empty(answers_by_question_id.get(qid))]
            if len(answered) > 1:
                rule_errors.append(
                    {
                        **_error(
                            "form_mutually_exclusive",
                            f"Form rule '{rule.rule_id}' requires mutual exclusivity; answered: {', '.join(answered)}.",
                        ),
                        "blocking": rule.blocking,
                        "rule_id": rule.rule_id,
                    }
                )

        if rule_errors:
            errors.setdefault(key, []).extend(rule_errors)
    return errors


def _iter_questions(schema_json: dict[str, Any]):
    for section in schema_json.get("sections", []) or []:
        for question in section.get("questions", []) or []:
            yield question


def _error(code: str, message: str | None = None) -> dict[str, str]:
    return {"code": code, "message": message or ERROR_CATALOG[code]}


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def _validate_single_question(question: dict[str, Any], value: Any) -> list[dict[str, str]]:
    q_type = str(question.get("type", "text"))
    config = question.get("config_json") or {}
    required = bool(question.get("required", False))

    if required and _is_empty(value):
        return [_error("required")]
    if _is_empty(value):
        return []

    if q_type == "text":
        return _validate_text(value, config)
    if q_type in {"select", "radio"}:
        return _validate_select(value, config)
    if q_type == "multiselect":
        return _validate_multiselect(value, config)
    if q_type == "slider":
        return _validate_slider(value, config)
    if q_type == "date":
        return _validate_date(value)
    if q_type == "time":
        return _validate_time(value)
    if q_type == "timezone":
        return _validate_timezone(value)
    if q_type == "address":
        return _validate_address(value, config)
    return [_error("invalid_type", "Unsupported question type.")]


def _validate_text(value: Any, config: dict[str, Any]) -> list[dict[str, str]]:
    if not isinstance(value, str):
        return [_error("invalid_type")]
    out: list[dict[str, str]] = []
    min_len = config.get("minLength")
    max_len = config.get("maxLength")
    pattern = config.get("pattern")
    if isinstance(min_len, int) and len(value) < min_len:
        out.append(_error("too_short"))
    if isinstance(max_len, int) and len(value) > max_len:
        out.append(_error("too_long"))
    if isinstance(pattern, str) and pattern:
        if re.fullmatch(pattern, value) is None:
            out.append(_error("pattern_mismatch"))
    return out


def _validate_select(value: Any, config: dict[str, Any]) -> list[dict[str, str]]:
    options = config.get("options")
    if not isinstance(value, str):
        return [_error("invalid_type")]
    if not isinstance(options, list):
        return [_error("invalid_option")]
    if value not in options:
        return [_error("invalid_option")]
    return []


def _validate_multiselect(value: Any, config: dict[str, Any]) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return [_error("invalid_type")]
    options = config.get("options")
    if not isinstance(options, list):
        return [_error("invalid_option")]

    out: list[dict[str, str]] = []
    if any(v not in options for v in value):
        out.append(_error("invalid_option"))

    min_sel = config.get("minSelections")
    max_sel = config.get("maxSelections")
    if isinstance(min_sel, int) and len(value) < min_sel:
        out.append(_error("too_few_choices"))
    if isinstance(max_sel, int) and len(value) > max_sel:
        out.append(_error("too_many_choices"))
    return out


def _validate_slider(value: Any, config: dict[str, Any]) -> list[dict[str, str]]:
    if not isinstance(value, (int, float, Decimal)) or isinstance(value, bool):
        return [_error("invalid_type")]

    out: list[dict[str, str]] = []
    min_v = config.get("min")
    max_v = config.get("max")
    step = config.get("step")

    in_range = True
    if isinstance(min_v, (int, float, Decimal)) and value < min_v:
        out.append(_error("below_min"))
        in_range = False
    if isinstance(max_v, (int, float, Decimal)) and value > max_v:
        out.append(_error("above_max"))
        in_range = False
    if in_range and isinstance(step, (int, float, Decimal)) and step > 0 and isinstance(min_v, (int, float, Decimal)):
        delta = (float(value) - float(min_v)) / float(step)
        if abs(delta - round(delta)) > 1e-9:
            out.append(_error("invalid_step"))
    return out


def _validate_date(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, str):
        return [_error("invalid_type")]
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return [_error("invalid_date_format")]
    return []


def _validate_time(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, str):
        return [_error("invalid_type")]
    try:
        datetime.strptime(value, "%H:%M")
    except ValueError:
        return [_error("invalid_time_format")]
    return []


def _validate_timezone(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, str):
        return [_error("invalid_type")]
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError:
        return [_error("invalid_timezone")]
    return []


def _validate_address(value: Any, config: dict[str, Any]) -> list[dict[str, str]]:
    if not isinstance(value, dict):
        return [_error("invalid_address")]

    required_fields = config.get("requiredFields")
    if not isinstance(required_fields, list) or not required_fields:
        required_fields = ["line1", "city", "country"]

    out: list[dict[str, str]] = []
    for field_name in required_fields:
        if not isinstance(field_name, str):
            continue
        field_val = value.get(field_name)
        if not isinstance(field_val, str) or field_val.strip() == "":
            out.append(_error("missing_address_field", f"Address is missing required field: {field_name}."))
    return out
