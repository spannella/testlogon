from __future__ import annotations

import json
import unittest
from pathlib import Path


class TestMessagingComplianceQueryExportContract(unittest.TestCase):
    def test_query_response_schema_is_versioned(self):
        schema_path = Path("docs/messaging-compliance-query-response-v1.json")
        schema = json.loads(schema_path.read_text())

        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertIn("case_id", schema["required"])
        self.assertIn("items", schema["required"])
        self.assertIn("next_cursor", schema["required"])

    def test_export_manifest_schema_has_case_and_signature_contract(self):
        schema_path = Path("docs/messaging-compliance-export-bundle-manifest-v1.json")
        schema = json.loads(schema_path.read_text())

        self.assertEqual(schema["properties"]["manifest_version"]["const"], 1)
        self.assertIn("case_id", schema["required"])
        self.assertIn("signature", schema["required"])

        signature = schema["properties"]["signature"]
        self.assertEqual(signature["required"], ["algorithm", "key_id", "value"])

    def test_contract_doc_references_case_based_retrieval_and_immutable_source(self):
        doc_path = Path("docs/messaging-compliance-query-export-contract.md")
        content = doc_path.read_text()

        self.assertIn("case_id", content)
        self.assertIn("immutable archive", content)
        self.assertIn("pagination", content.lower())


if __name__ == "__main__":
    unittest.main()
