"""Offline regression tests for GAP-0265 and GAP-0266 (KYC-008).

Both gaps concern the KYC risk-scoring engine
(``app/services/kyc_risk_scoring.py``):

GAP-0265 — ``_apply_auto_action`` logged a warning and returned
``"auto_escalated"`` for critical-tier cases but never wrote the escalation
flag to DynamoDB. Admins, dashboards and audit trails could not distinguish an
auto-escalated case from an ordinary submitted one. The fix adds a
``KycCaseStore.escalate_case`` call (writing ``review.escalated`` /
``review.escalation_reason`` / ``review.escalated_at``) gated by the new
``KYC_RISK_AUTO_ESCALATE_ENABLED`` setting.

GAP-0266 — the KYC-008 spec requires ``compute_score()`` to run automatically at
case submission so the reviewer queue has a risk tier and auto-approve /
auto-escalate can fire. No such call existed in the submission pathway. The fix
adds a best-effort ``KycRiskScoringService().compute_score(..., trigger="submission")``
call in ``submit_kyc_case`` (router), after the existing sanctions-screening hook.
Because the FastAPI TestClient is unusable in this repo, this regression exercises
the router function body directly with stubbed dependencies and asserts a risk-score
row with ``trigger="submission"`` is written.

Test isolation: a real in-memory DynamoDB is created with moto; the exact frozen
``T`` table handles are monkeypatched via ``object.__setattr__`` so nothing leaks
to real AWS. Functions are called directly. The mutable ``S`` settings are also
modified via ``object.__setattr__`` (the Settings dataclass is frozen) and
restored in cleanup. Each test fails before the fix and passes after.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3
from boto3.dynamodb.conditions import Key

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_kyc_cases_table(ddb):
    return ddb.create_table(
        TableName="kyc_cases_test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_kyc_risk_scores_table(ddb):
    return ddb.create_table(
        TableName="kyc_risk_scores_test",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "timestamp", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "timestamp", "AttributeType": "N"},
            {"AttributeName": "case_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "case-timestamp-index",
                "KeySchema": [
                    {"AttributeName": "case_id", "KeyType": "HASH"},
                    {"AttributeName": "timestamp", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_users_table(ddb):
    return ddb.create_table(
        TableName="users_test",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _KycRiskBase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.cases_table = _make_kyc_cases_table(ddb)
        self.scores_table = _make_kyc_risk_scores_table(ddb)
        self.users_table = _make_users_table(ddb)

        # Patch the exact frozen T handles used by the services (object.__setattr__
        # because Tables is a frozen dataclass). Restored on cleanup.
        from app.core import tables as tables_mod

        T = tables_mod.T
        for name, handle in (
            ("kyc_cases", self.cases_table),
            ("kyc_risk_scores", self.scores_table),
            ("users", self.users_table),
        ):
            original = getattr(T, name)
            object.__setattr__(T, name, handle)
            self.addCleanup(object.__setattr__, T, name, original)

        # Default-enable the new auto-escalate flag for these tests; restore after.
        from app.core.settings import S

        self.S = S
        original_flag = getattr(S, "kyc_risk_auto_escalate_enabled", True)
        object.__setattr__(S, "kyc_risk_auto_escalate_enabled", True)
        self.addCleanup(object.__setattr__, S, "kyc_risk_auto_escalate_enabled", original_flag)

        # Fresh service/store instances bound to the moto tables.
        from app.services.kyc_cases import KycCaseStore
        from app.services.kyc_risk_scoring import KycRiskScoringService

        self.store = KycCaseStore(_table=self.cases_table)
        self.svc = KycRiskScoringService(table=self.scores_table)

    def _seed_case(self, *, user_sub="user_x", status="submitted", **extra):
        case = self.store.create_case(user_sub=user_sub, status="draft")
        case_id = case["kyc_case_id"]
        # Force status directly (bypassing the normal draft->submitted gate).
        item = self.cases_table.get_item(
            Key={"pk": f"KYC#{case_id}", "sk": "META"}
        )["Item"]
        item["status"] = status
        item.update(extra)
        self.cases_table.put_item(Item=item)
        return self.store.get_case(case_id)


class TestAutoEscalateGap0265(_KycRiskBase):
    def test_escalate_case_writes_flags(self):
        """GAP-0265: escalate_case persists review.escalated to DDB.

        FAILS BEFORE FIX: escalate_case did not exist (AttributeError).
        """
        case = self._seed_case(status="submitted")
        case_id = case["kyc_case_id"]

        result = self.store.escalate_case(
            case_id=case_id, score=92, reason="Critical risk score: 92 (tier: critical)"
        )
        self.assertIsNotNone(result)
        review = result.get("review") or {}
        self.assertIs(review.get("escalated"), True)
        self.assertIn("Critical risk score", str(review.get("escalation_reason")))
        self.assertIsNotNone(review.get("escalated_at"))
        self.assertEqual(review.get("escalated_by"), "system_auto_escalate")

        # Persisted on the actual DDB item.
        persisted = self.store.get_case(case_id)
        self.assertIs((persisted.get("review") or {}).get("escalated"), True)

    def test_escalate_case_does_not_increment_version(self):
        """Escalation is an annotation, not a versioned state change."""
        case = self._seed_case(status="submitted")
        v_before = int(case.get("version") or 0)
        self.store.escalate_case(case_id=case["kyc_case_id"], score=90, reason="t")
        updated = self.store.get_case(case["kyc_case_id"])
        self.assertEqual(int(updated.get("version") or 0), v_before)
        # Status unchanged too.
        self.assertEqual(updated.get("status"), "submitted")

    def test_escalate_case_skips_terminal_states(self):
        """No-op (no escalation flag) when the case is already decided."""
        case = self._seed_case(status="approved")
        result = self.store.escalate_case(
            case_id=case["kyc_case_id"], score=95, reason="post-decision rescore"
        )
        self.assertIsNotNone(result)
        self.assertFalse((result.get("review") or {}).get("escalated"))

    def test_escalate_case_missing_returns_none(self):
        self.assertIsNone(
            self.store.escalate_case(case_id="kyc_doesnotexist", score=90, reason="x")
        )

    def test_apply_auto_action_critical_writes_flag(self):
        """GAP-0265: _apply_auto_action('critical') writes the escalation flag.

        FAILS BEFORE FIX: the critical branch only logged + returned; no DDB write,
        so review.escalated was never set.
        """
        case = self._seed_case(status="submitted")
        case_id = case["kyc_case_id"]

        with patch("app.services.kyc_cases.STORE", self.store), patch(
            "app.services.alerts.audit_event"
        ) as audit_spy:
            action = self.svc._apply_auto_action(
                case_id=case_id, score=90, tier="critical", all_checks_passed=False
            )

        self.assertEqual(action, "auto_escalated")
        review = (self.store.get_case(case_id).get("review") or {})
        self.assertIs(review.get("escalated"), True)
        self.assertIsNotNone(review.get("escalated_at"))
        audit_spy.assert_called_once()
        self.assertEqual(audit_spy.call_args.args[0], "kyc_auto_escalated")

    def test_apply_auto_action_disabled_by_flag(self):
        """KYC_RISK_AUTO_ESCALATE_ENABLED=false -> no action, no DDB write."""
        object.__setattr__(self.S, "kyc_risk_auto_escalate_enabled", False)
        case = self._seed_case(status="submitted")
        case_id = case["kyc_case_id"]

        with patch("app.services.kyc_cases.STORE", self.store):
            action = self.svc._apply_auto_action(
                case_id=case_id, score=99, tier="critical", all_checks_passed=False
            )

        self.assertEqual(action, "none")
        self.assertFalse((self.store.get_case(case_id).get("review") or {}).get("escalated"))

    def test_compute_score_critical_escalates_end_to_end(self):
        """GAP-0265 end-to-end: a critical-scoring case is escalated on compute_score.

        FAILS BEFORE FIX: auto_action_taken would still be 'auto_escalated' (it was
        returned without a write) but review.escalated would NOT be set.
        """
        case = self._seed_case(status="submitted", user_sub="user_crit")
        case_id = case["kyc_case_id"]

        critical_factors = {
            name: {
                "score": 100,
                "weight": w,
                "raw_value": "x",
                "description": "test",
            }
            for name, w in self.svc._weights.items()
        }
        with patch.object(self.svc, "_compute_all_factors", return_value=critical_factors), patch(
            "app.services.kyc_cases.STORE", self.store
        ), patch("app.services.alerts.audit_event"):
            result = self.svc.compute_score(case_id=case_id, user_sub="user_crit")

        self.assertEqual(result["risk_tier"], "critical")
        self.assertEqual(result["auto_action_taken"], "auto_escalated")
        review = (self.store.get_case(case_id).get("review") or {})
        self.assertIs(review.get("escalated"), True)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestSubmissionHookGap0266(_KycRiskBase):
    def test_submit_hook_calls_compute_score(self):
        """GAP-0266: submit_kyc_case writes a risk-score row with trigger=submission.

        FAILS BEFORE FIX: no compute_score call in the submission pathway, so the
        kyc_risk_scores table has no row for the submitted case.
        PASSES AFTER FIX: the best-effort hook fires after screening and writes one.
        """
        from types import SimpleNamespace

        from app.routers import kyc_cases as router_mod

        # A draft case ready to submit; bypass readiness/screening with patches.
        case = self.store.create_case(user_sub="user_submit", status="draft")
        case_id = case["kyc_case_id"]

        user = SimpleNamespace(sub="user_submit")
        request = SimpleNamespace(headers={}, state=SimpleNamespace())

        readiness = {
            "ready_to_submit": True,
            "missing_requirements": [],
            "missing_hints": [],
            "requirements": [
                {"refs": {"questionnaire_id": "q1", "response_session_id": "s1", "response_pdf_ref": "p1"}},
                {"refs": {"present_types": "id_front,id_back"}},
                {"refs": {"packet_id": "pk1", "final_pdf_ref": "f1"}},
            ],
        }

        with patch.object(router_mod, "STORE", self.store), patch.object(
            router_mod, "_readiness_for_case", return_value=readiness
        ), patch.object(
            router_mod, "_ensure_review_ticket", side_effect=lambda c: c
        ), patch.object(
            router_mod, "SCREENING_STORE", SimpleNamespace(screen_case=lambda **kw: None)
        ), patch.object(
            router_mod, "_audit_state_transition", lambda **kw: None
        ), patch.object(
            router_mod, "_emit_kyc_metric", lambda *a, **kw: None
        ), patch.object(
            router_mod, "audit_event", lambda *a, **kw: None
        ), patch.object(
            router_mod, "_wrap_case", side_effect=lambda c: c
        ):
            body = SimpleNamespace(expected_version=1)
            router_mod.submit_kyc_case(case_id=case_id, body=body, request=request, _ctx={}, user=user)

        scores = self.scores_table.query(
            IndexName="case-timestamp-index",
            KeyConditionExpression=Key("case_id").eq(case_id),
        )["Items"]
        self.assertGreaterEqual(
            len(scores), 1,
            "GAP-0266: compute_score() must run on submission and write a risk-score row",
        )
        self.assertEqual(str(scores[0]["trigger"]), "submission")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
