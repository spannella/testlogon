# KYC-023: KYC Data Encryption & Privacy

**Ticket**: KYC-023
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Critical
**Estimated effort**: 10-12 days
**Depends on**: KYC-001 (Admin Review Dashboard), KYC-012 (Compliance Reporting & Export)

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The KYC system stores highly sensitive personally identifiable information (PII) in DynamoDB: government document numbers (passport, national ID), dates of birth, tax identification numbers (SSN, TIN), bank account details, and facial biometric references. Currently, this data is stored in plaintext in the `kyc_cases` table. Any actor with DDB read access (admin, developer, compromised IAM role, backup leak) can read all PII fields without restriction or audit trail.

This presents several risks:

1. **Regulatory non-compliance**: GDPR Article 32 requires "encryption of personal data" as a security measure. PCI-DSS requires encryption of sensitive cardholder data at rest. AML regulations require secure handling of customer identification data.
2. **Breach amplification**: A DynamoDB table export or backup leak exposes all PII in readable form. Field-level encryption ensures that even if the raw data is exfiltrated, PII fields remain unreadable without the decryption key.
3. **Over-access**: Not all admins reviewing a KYC case need to see the full document number or DOB. Data masking (showing only last 4 characters) reduces exposure for routine reviews.
4. **Data retention**: GDPR's "right to be forgotten" and data minimization principles require the ability to permanently erase PII. With field-level encryption, destroying the encryption key effectively erases the data even if the DDB records persist.

### 1.2 How It Works

1. When sensitive fields are written to DynamoDB (document numbers, DOB, tax IDs, bank details), they are encrypted using the KMS-managed key before storage.
2. The encrypted ciphertext is stored alongside a key reference and algorithm identifier, enabling future key rotation.
3. When an authorized admin requests decrypted PII (e.g., viewing full document number during review), the backend decrypts on-demand and logs the access in the audit table.
4. Non-assigned admins see masked values (e.g., `****1234` for document numbers, `****-**-15` for DOB).
5. When a user exercises their right to be forgotten, the system erases PII by deleting the encryption key material for that user, rendering all encrypted fields permanently unreadable.
6. Every PII field access (read, write, decrypt) is recorded in a dedicated access audit log.

### 1.3 Encrypted Fields

| Field | Location | Masking Rule |
|-------|----------|-------------|
| `document_number` | KYC case files | Show last 4: `****1234` |
| `date_of_birth` | KYC case / user profile | Show year only: `1990-**-**` |
| `tax_id` (SSN/TIN) | KYC case | Show last 4: `***-**-1234` |
| `bank_account_number` | KYC case | Show last 4: `****5678` |
| `bank_routing_number` | KYC case | Fully masked: `*********` |
| `full_ssn` | KYC case (US only) | Show last 4: `***-**-1234` |
| `passport_mrz` | KYC case files | Fully masked: `***...***` |
| `eid_subject_id` | eID assertion (KYC-022) | Fully masked |

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| System | Encrypt PII fields before DDB write | Stored value is ciphertext, not plaintext |
| Admin (assigned) | View decrypted document number during case review | Full value shown; access logged |
| Admin (non-assigned) | See masked document number | Only last 4 characters visible |
| User | Request right to be forgotten | All PII fields rendered permanently unreadable |
| Auditor | Review PII access log | See who accessed which fields, when, and why |
| System | Rotate encryption key | New writes use new key; old ciphertexts remain decryptable via key ID |

---

## 2. Current State Analysis

### 2.1 KMS Infrastructure (`app/core/crypto.py`)

The existing crypto module provides KMS integration:

```python
def kms_encrypt(plaintext: str) -> str:
    """Encrypt using KMS. Returns base64-encoded ciphertext."""

def kms_decrypt(ct_b64: str) -> bytes:
    """Decrypt a KMS ciphertext. Returns plaintext bytes."""
```

The mock KMS server runs on port 7999 (`scripts/mock_kms_server.py`). The `kms_encrypt` function calls `boto3.client("kms").encrypt()` with the `KMS_KEY_ID` from settings. In dev mode, the mock KMS server accepts any key ID and performs reversible AES encryption.

This infrastructure is suitable for field-level encryption, but the current functions operate on single strings. For batch encryption (multiple fields per case), a wrapper is needed to minimize KMS API calls.

### 2.2 KYC Case Storage (`app/services/kyc_cases.py`)

The `KycCaseStore.create_case` (line 97) and `update_draft` (line 200) methods write case data directly to DDB without any encryption layer. The `files` list on each case stores file metadata including `file_type` and S3 references, but document numbers extracted from files (e.g., by OCR in KYC-002) would be stored as plaintext attributes.

### 2.3 GDPR Service (`app/services/gdpr_service.py`)

The existing GDPR service supports:
- `create_export_request(user_sub, categories)` — Data export (DSAR)
- `create_deletion_request(user_sub, reason)` — Data deletion
- `get_request(user_sub, request_id)` — Status check
- `list_user_requests(user_sub)` — List requests

The deletion flow deletes DDB records but does not handle encrypted field key destruction. The encryption service must integrate with the GDPR service so that deletion requests also destroy per-user encryption keys.

### 2.4 Admin Role System (`app/auth/roles.py`, `app/auth/deps.py`)

The `AuthenticatedUser` returned by `get_authenticated_user` includes `user_sub`, `role` (USER/ADMIN/ROOT), and `admin_profile` with `scopes`. The `assigned_admin_sub` field on KYC cases (`KycCaseReviewRef`, line 44 in contract) identifies which admin is currently assigned. Decryption authorization can use the comparison: `requesting_admin_sub == case.review.assigned_admin_sub`.

---

## 3. Technical Design

### 3.1 New Service: `app/services/kyc_encryption.py`

```python
@dataclass
class EncryptedField:
    ciphertext_b64: str        # Base64-encoded KMS ciphertext
    key_id: str                # KMS key ID used for encryption
    algorithm: str             # "AES-256-GCM" (via KMS)
    encrypted_at: int          # Unix timestamp
    field_name: str            # Original field name (for audit)

class KycEncryptionService:
    def encrypt_fields(self, *, data: dict[str, str],
                        user_sub: str) -> dict[str, EncryptedField]:
        """Encrypt multiple PII fields using KMS.
        Uses a per-user data encryption key (DEK) wrapped by the KMS master key.
        Returns dict mapping field_name -> EncryptedField."""

    def decrypt_fields(self, *, encrypted_data: dict[str, EncryptedField],
                        accessor_sub: str, access_reason: str,
                        case_id: str) -> dict[str, str]:
        """Decrypt PII fields. Logs access to audit table.
        Returns dict mapping field_name -> plaintext value."""

    def mask_fields(self, *, encrypted_data: dict[str, EncryptedField],
                     masking_rules: dict[str, str] | None = None) -> dict[str, str]:
        """Return masked representations without decrypting.
        Uses stored metadata (field_name) to determine masking rule.
        Does NOT call KMS — no audit entry generated."""

    def generate_user_dek(self, user_sub: str) -> str:
        """Generate a per-user Data Encryption Key, wrapped by KMS master key.
        Stored in kyc_cases table as PK=USER_DEK#{user_sub}, SK=ACTIVE."""

    def rotate_user_dek(self, user_sub: str) -> str:
        """Generate new DEK, re-encrypt all fields for this user with new key.
        Old DEK kept for 30 days for rollback, then deleted."""

    def destroy_user_keys(self, user_sub: str) -> dict[str, Any]:
        """Permanently delete all DEKs for a user.
        Called by GDPR deletion flow. All encrypted fields become unrecoverable."""

    def log_access(self, *, accessor_sub: str, case_id: str,
                    fields_accessed: list[str], reason: str,
                    action: str) -> None:
        """Write an entry to the PII access audit log."""

    def get_access_log(self, *, case_id: str | None = None,
                       accessor_sub: str | None = None,
                       limit: int = 100) -> list[dict[str, Any]]:
        """Query PII access audit log, filtered by case or accessor."""
```

### 3.2 Encryption Architecture

```
Envelope Encryption Pattern:

  Master Key (KMS)
       |
       | wraps/unwraps
       v
  Data Encryption Key (per-user DEK)
       |
       | encrypts/decrypts
       v
  PII Field Values (document_number, DOB, etc.)

Storage:

  kyc_cases table:
    PK=USER_DEK#{user_sub}  SK=ACTIVE
      wrapped_dek (S)       — KMS-encrypted DEK
      key_id (S)            — KMS key ID
      created_at (N)
      version (N)           — For key rotation

    PK=USER_DEK#{user_sub}  SK=ROTATED#{version}
      wrapped_dek (S)       — Old DEK (retained 30 days)
      rotated_at (N)
      ttl (N)               — DDB TTL, 30 days

  kyc_cases table (on case items):
    encrypted_pii (M)       — Map of field_name -> EncryptedField
```

### 3.3 PII Access Audit Log

Stored in the `kyc_cases` table using single-table design:

```
PK: PII_AUDIT#{case_id}
SK: {timestamp}#{event_id}

Attributes:
  accessor_sub (S)         — Who accessed the data
  action (S)               — "decrypt" | "encrypt" | "mask" | "delete"
  fields (L)               — List of field names accessed
  reason (S)               — Why (e.g., "case_review", "export_request", "admin_override")
  ip_address (S)           — Accessor's IP
  created_at (N)
```

GSI for querying by accessor:

```
GSI pii-audit-accessor-index:
  PK: accessor_sub (S)
  SK: created_at (N)
```

This GSI is added to the existing `kyc_cases` table (not a new table).

### 3.4 Integration with KYC Case Service

Modify `app/services/kyc_cases.py`:

**On case creation / draft update** — encrypt PII fields before DDB write:

```python
def create_case(self, ...):
    # ... existing logic ...
    if pii_fields:
        encrypted = encryption_svc.encrypt_fields(
            data=pii_fields, user_sub=user_sub
        )
        item["encrypted_pii"] = {k: asdict(v) for k, v in encrypted.items()}
    # ... write to DDB ...
```

**On case read (user/admin)** — decrypt or mask based on authorization:

```python
def _prepare_case_for_response(case: dict, *, viewer_sub: str, viewer_role: Role) -> dict:
    encrypted_pii = case.get("encrypted_pii", {})
    if not encrypted_pii:
        return case

    assigned = case.get("review", {}).get("assigned_admin_sub")
    if viewer_role in (Role.ADMIN, Role.ROOT) and viewer_sub == assigned:
        # Assigned admin: decrypt and log
        decrypted = encryption_svc.decrypt_fields(
            encrypted_data=encrypted_pii,
            accessor_sub=viewer_sub,
            access_reason="case_review",
            case_id=case["kyc_case_id"],
        )
        case["pii"] = decrypted
    else:
        # Non-assigned admin or user: mask
        case["pii"] = encryption_svc.mask_fields(encrypted_data=encrypted_pii)
    return case
```

### 3.5 GDPR Integration

Extend `app/services/gdpr_service.py`:

```python
def create_deletion_request(user_sub: str, reason: Optional[str] = None) -> Dict[str, Any]:
    # ... existing logic ...

    # NEW: Destroy encryption keys for all KYC cases
    encryption_svc = KycEncryptionService()
    encryption_svc.destroy_user_keys(user_sub)

    # ... continue with DDB record deletion ...
```

After `destroy_user_keys`, all `encrypted_pii` fields on the user's KYC cases become permanently unrecoverable. The DDB records can be retained for audit (showing that a case existed and was deleted) without exposing PII.

### 3.6 Router Endpoints

Add to `app/routers/kyc_cases.py`:

```python
# PII access endpoints
POST /v1/kyc/cases/{case_id}/pii/decrypt
  — Decrypt specific PII fields for assigned admin
  — Auth: require_admin_session
  — Body: { "fields": ["document_number", "date_of_birth"], "reason": str }
  — Response: { "pii": { "document_number": "AB1234567", "date_of_birth": "1990-01-15" } }

GET /v1/kyc/cases/{case_id}/pii/masked
  — Get masked PII values (any admin)
  — Auth: require_admin_session
  — Response: { "pii": { "document_number": "****4567", "date_of_birth": "1990-**-**" } }

# Audit endpoints
GET /v1/kyc/cases/{case_id}/pii/audit-log
  — Get PII access log for a case
  — Auth: require_root_session
  — Response: { "events": [...] }

GET /v1/kyc/admin/pii/audit-log?accessor={sub}&from={ts}&to={ts}
  — Query PII access log by accessor
  — Auth: require_root_session
  — Response: { "events": [...] }

# Key management (root only)
POST /v1/kyc/admin/encryption/rotate-key/{user_sub}
  — Rotate a user's DEK
  — Auth: require_root_session
  — Response: { "ok": true, "new_version": int }

POST /v1/kyc/admin/encryption/destroy-keys/{user_sub}
  — Permanently destroy user's keys (GDPR erasure)
  — Auth: require_root_session
  — Response: { "ok": true, "fields_affected": int }
```

### 3.7 Data Masking Rules

```python
MASKING_RULES = {
    "document_number": lambda v: "****" + v[-4:] if len(v) >= 4 else "****",
    "date_of_birth": lambda v: v[:4] + "-**-**" if len(v) >= 10 else "****",
    "tax_id": lambda v: "***-**-" + v[-4:] if len(v) >= 4 else "****",
    "bank_account_number": lambda v: "****" + v[-4:] if len(v) >= 4 else "****",
    "bank_routing_number": lambda _: "*********",
    "full_ssn": lambda v: "***-**-" + v[-4:] if len(v) >= 4 else "****",
    "passport_mrz": lambda _: "***...***",
    "eid_subject_id": lambda _: "********",
}
```

These rules are applied by `mask_fields` without calling KMS. The masking function uses the `field_name` metadata stored in `EncryptedField` to select the correct rule. The last N characters are stored as a separate unencrypted `hint` field for masking display (the full value is only in the encrypted ciphertext).

### 3.8 Frontend Changes

**Admin case detail**: Modify the case detail view to show masked PII by default, with a "Reveal" button for assigned admins that triggers the decrypt endpoint.

- `PiiFieldDisplay` — Shows masked value with optional "Reveal" button
- `PiiAuditLog` — Table showing who accessed PII, when, for what reason (root-only view)

**Admin UI flow**:
1. Case detail loads with masked PII (`****4567` for document number)
2. Assigned admin clicks "Reveal" on a field
3. Frontend calls `POST /pii/decrypt` with field name and reason
4. Decrypted value shown temporarily (auto-hides after 30 seconds)
5. Access logged in audit table

---

## 4. E2E Test Plan

**Test file**: `frontend/e2e/kyc-encryption.spec.ts`
**Total**: ~15 tests across 3 sections (234-236)

### Section 234: Field Encryption & Decryption API (6 tests)

```typescript
test("234.1 Encrypted PII fields stored on case creation", async ({ page }) => {
  // Create KYC case with PII fields (document_number, date_of_birth)
  // Direct DDB read -> encrypted_pii map present, values are ciphertext
});

test("234.2 Assigned admin can decrypt PII fields", async ({ page }) => {
  // Assign Charlie to case, POST /pii/decrypt as Charlie
  // Expect decrypted document_number matches original
});

test("234.3 Non-assigned admin gets masked values", async ({ page }) => {
  // Root (not assigned) GET /pii/masked
  // Expect document_number="****4567"
});

test("234.4 Decrypt request logged in audit", async ({ page }) => {
  // After decrypt in 234.2, GET /pii/audit-log
  // Expect event with accessor=charlie_sub, action="decrypt"
});

test("234.5 Regular user sees masked PII on their own case", async ({ page }) => {
  // Alice GET her case -> pii fields masked
});

test("234.6 Decrypt without reason returns 400", async ({ page }) => {
  // POST /pii/decrypt with empty reason -> 400
});
```

### Section 235: Key Management & GDPR Erasure (5 tests)

```typescript
test("235.1 Root rotates user DEK", async ({ page }) => {
  // POST /admin/encryption/rotate-key/{user_sub}
  // Expect ok=true, new_version > 1
});

test("235.2 Decryption works after key rotation", async ({ page }) => {
  // After rotation, assigned admin decrypts -> same plaintext value
});

test("235.3 Destroy keys renders PII unrecoverable", async ({ page }) => {
  // POST /admin/encryption/destroy-keys/{user_sub}
  // Attempt decrypt -> error or empty result
});

test("235.4 GDPR deletion request destroys encryption keys", async ({ page }) => {
  // Create deletion request via GDPR service
  // Attempt to decrypt PII -> fails
});

test("235.5 Non-root cannot rotate or destroy keys", async ({ page }) => {
  // Charlie (admin) POST rotate-key -> 403
});
```

### Section 236: Audit Log & Masking Rules (4 tests)

```typescript
test("236.1 PII audit log records all access events", async ({ page }) => {
  // Multiple decrypt calls by different admins
  // GET audit-log -> events for each access, sorted by timestamp
});

test("236.2 Audit log filterable by accessor", async ({ page }) => {
  // GET /admin/pii/audit-log?accessor=charlie_sub
  // Only Charlie's events returned
});

test("236.3 Masking rules applied correctly per field type", async ({ page }) => {
  // GET masked -> verify:
  //   document_number last 4 visible
  //   date_of_birth year visible, month/day masked
  //   tax_id last 4 visible
  //   bank_routing_number fully masked
});

test("236.4 Masked values returned without calling KMS", async ({ page }) => {
  // Verify mask endpoint does not log a decrypt event in audit
  // (masking uses hint field, not KMS decryption)
});
```

---

## 5. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_encryption.py` | **New** | Field encryption, DEK management, masking, audit logging |
| `app/routers/kyc_cases.py` | Modify | Add 6 PII/encryption endpoints |
| `app/contracts/kyc_cases_contract.py` | Modify | Add `EncryptedField`, `PiiDecryptRequest`, audit models |
| `app/services/kyc_cases.py` | Modify | Integrate encryption on create/read/update |
| `app/services/gdpr_service.py` | Modify | Add key destruction to deletion flow |
| `app/core/crypto.py` | Modify | Add batch encrypt/decrypt helpers, DEK generation |
| `app/core/settings.py` | Modify | Add `kyc_encryption_enabled`, `kyc_dek_rotation_days` settings |
| `frontend/src/api/endpoints/kyc-cases.ts` | Modify | Add `decryptPii`, `getMaskedPii`, `getAuditLog` functions |
| `frontend/src/api/types.ts` | Modify | Add `PiiField`, `PiiAuditEvent` types |
| `frontend/src/components/shared/PiiFieldDisplay.tsx` | **New** | Masked field with reveal button |
| `frontend/src/components/shared/PiiAuditLog.tsx` | **New** | Audit log table (root-only) |
| `frontend/e2e/kyc-encryption.spec.ts` | **New** | 15 E2E tests across sections 234-236 |
