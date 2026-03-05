# Messaging Archive Evidence Package Validation Report (FCA-024)

## Scope
This report documents the golden-case evidence package validation used for compliance/audit response readiness.

Validated artifacts live under:
- `tests/fixtures/messaging_evidence_package/manifest.json`
- `tests/fixtures/messaging_evidence_package/records.jsonl`
- `tests/fixtures/messaging_evidence_package/verification_material.json`

## Validation procedure
1. Recompute per-record SHA-256 from canonical event JSON and compare to `record_sha256` in `records.jsonl`.
2. Recompute `records.jsonl` SHA-256 and compare against:
   - `manifest.records_file.sha256`
   - `manifest.bundle_checksums.records_sha256`
3. Recompute aggregate digest (`sha256("\n".join(per_record_hashes))`) and compare to `manifest.record_checksums.aggregate_digest`.
4. Rebuild unsigned manifest (remove `signature`, blank `bundle_checksums.manifest_sha256`) and verify:
   - `manifest.bundle_checksums.manifest_sha256`
   - HMAC-SHA256 signature value using `verification_material.json` key.
5. Replay the same event set from `.failed_archive_events.jsonl` and verify replayed archive query output hashes match the fixture export hashes.

## Verification commands
- `python -m unittest tests.test_messaging_evidence_package_validation`
- `python -m unittest tests.test_messaging_archive_export tests.test_messaging_archive_replay`

## Result
- Golden evidence package checksum/signature validation: **PASS**.
- Replay consistency versus exported evidence hashes: **PASS**.
- This satisfies FCA-024 acceptance that the evidence package can be independently verified and replay-consistent.
