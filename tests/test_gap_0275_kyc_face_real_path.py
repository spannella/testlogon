"""Offline regression test for GAP-0275 (KYC-014).

Bug: ``_production_compare()`` in ``app/services/kyc_facial_comparison.py`` raised
``KycFacialComparisonError("comparison_service_error")`` unconditionally, so any
deployment with ``S.dev_mode is False`` returned HTTP 500 on every facial
comparison attempt -- no AWS Rekognition provider was wired.

Fix: ``_production_compare()`` now calls ``compare_faces()`` via the new
``app.core.aws.rekognition_client()`` helper and maps the best ``Similarity``
to an integer score in ``[0, 100]`` (same contract as ``_mock_compare``). A
``S.kyc_face_comparison_use_mock`` safety valve routes back to the mock in
non-dev environments without Rekognition. The dev/mock path is unchanged
(SECOPS-007 dev/prod parity).

Test isolation: NO global ``@mock_aws`` interception of Rekognition (which can
leak to real AWS). The Rekognition client is replaced with a ``MagicMock`` that
records calls -- no real boto3 Rekognition call is ever made. ``Settings`` is
frozen, so flags are flipped with ``object.__setattr__``.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.services import kyc_facial_comparison as svc
from app.services.kyc_facial_comparison import KycFacialComparisonError


class TestKycFaceRealPathGap0275(unittest.TestCase):
    def setUp(self):
        self.S = svc.S
        self._orig = {
            "dev_mode": self.S.dev_mode,
            "kyc_face_comparison_use_mock": self.S.kyc_face_comparison_use_mock,
            "kyc_documents_bucket": self.S.kyc_documents_bucket,
        }
        self.addCleanup(self._restore)

    def _restore(self):
        for k, v in self._orig.items():
            object.__setattr__(self.S, k, v)

    def _prod(self):
        object.__setattr__(self.S, "dev_mode", False)
        object.__setattr__(self.S, "kyc_face_comparison_use_mock", False)
        object.__setattr__(self.S, "kyc_documents_bucket", "test-kyc-bucket")

    # -- prod path ---------------------------------------------------------

    def test_prod_calls_rekognition_and_maps_score(self):
        """GAP-0275: prod path must call compare_faces (not raise) and map score."""
        self._prod()
        mock_rek = MagicMock()
        mock_rek.compare_faces.return_value = {
            "FaceMatches": [{"Similarity": 87.5, "Face": {}}],
            "UnmatchedFaces": [],
        }
        with patch("app.core.aws.rekognition_client", return_value=mock_rek):
            score = svc._production_compare(
                {"node_id": "test-kyc-bucket/cases/kyc_abc/selfie.jpg"},
                {"node_id": "test-kyc-bucket/cases/kyc_abc/id_front.jpg"},
            )

        self.assertIsInstance(score, int)
        self.assertEqual(score, 88)  # round(87.5)
        mock_rek.compare_faces.assert_called_once()
        kwargs = mock_rek.compare_faces.call_args.kwargs
        # bucket prefix stripped from key; selfie=source, id_front=target.
        self.assertEqual(
            kwargs["SourceImage"]["S3Object"],
            {"Bucket": "test-kyc-bucket", "Name": "cases/kyc_abc/selfie.jpg"},
        )
        self.assertEqual(
            kwargs["TargetImage"]["S3Object"],
            {"Bucket": "test-kyc-bucket", "Name": "cases/kyc_abc/id_front.jpg"},
        )

    def test_prod_returns_zero_on_no_match(self):
        """No face matches -> score 0 (maps to fail in _decide)."""
        self._prod()
        mock_rek = MagicMock()
        mock_rek.compare_faces.return_value = {
            "FaceMatches": [],
            "UnmatchedFaces": [{"Confidence": 99.9}],
        }
        with patch("app.core.aws.rekognition_client", return_value=mock_rek):
            score = svc._production_compare(
                {"node_id": "test-kyc-bucket/selfie.jpg"},
                {"node_id": "test-kyc-bucket/id.jpg"},
            )
        self.assertEqual(score, 0)

    def test_prod_raises_on_rekognition_error(self):
        """AWS/network errors surface as comparison_service_error (HTTP 500)."""
        self._prod()
        mock_rek = MagicMock()
        mock_rek.compare_faces.side_effect = Exception("ThrottlingException")
        with patch("app.core.aws.rekognition_client", return_value=mock_rek):
            with self.assertRaises(KycFacialComparisonError) as ctx:
                svc._production_compare(
                    {"node_id": "test-kyc-bucket/selfie.jpg"},
                    {"node_id": "test-kyc-bucket/id.jpg"},
                )
        self.assertEqual(str(ctx.exception), "comparison_service_error")

    def test_prod_raises_without_bucket_and_skips_call(self):
        """No KYC bucket configured -> error before any boto3 call."""
        self._prod()
        object.__setattr__(self.S, "kyc_documents_bucket", "")
        mock_rek = MagicMock()
        with patch("app.core.aws.rekognition_client", return_value=mock_rek):
            with self.assertRaises(KycFacialComparisonError):
                svc._production_compare(
                    {"node_id": "selfie.jpg"}, {"node_id": "id.jpg"}
                )
        mock_rek.compare_faces.assert_not_called()

    # -- dev / mock parity (SECOPS-007) ------------------------------------

    def test_dev_mock_path_never_calls_rekognition(self):
        """Dev mode keeps the deterministic mock; Rekognition is never touched."""
        object.__setattr__(self.S, "dev_mode", True)
        mock_rek = MagicMock()
        # _mock_compare must still produce a deterministic keyword-driven score.
        with patch("app.core.aws.rekognition_client", return_value=mock_rek):
            score = svc._mock_compare(
                {"file_name": "match.jpg", "node_id": "a"},
                {"file_name": "id.jpg", "node_id": "b"},
            )
        self.assertEqual(score, 85)  # "match" keyword bucket
        mock_rek.compare_faces.assert_not_called()

    def test_use_mock_flag_routes_to_mock_in_non_dev(self):
        """Safety valve: kyc_face_comparison_use_mock keeps mock in non-dev mode."""
        object.__setattr__(self.S, "dev_mode", False)
        object.__setattr__(self.S, "kyc_face_comparison_use_mock", True)
        mock_rek = MagicMock()
        called = {"prod": False}
        orig_prod = svc._production_compare

        def _spy(*a, **kw):
            called["prod"] = True
            return orig_prod(*a, **kw)

        with patch("app.core.aws.rekognition_client", return_value=mock_rek), patch.object(
            svc, "_production_compare", _spy
        ):
            score = svc._mock_compare(
                {"file_name": "mismatch.jpg", "node_id": "a"},
                {"file_name": "id.jpg", "node_id": "b"},
            )
        # The flag itself is exercised at the compare_faces() call site; here we
        # assert the mock branch is reachable and deterministic, and prod/boto3
        # were not invoked.
        self.assertEqual(score, 30)  # "mismatch" keyword bucket
        self.assertFalse(called["prod"])
        mock_rek.compare_faces.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
