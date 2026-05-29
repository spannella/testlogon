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

The existing crypto module (61 lines) provides KMS integration (see `app/core/crypto.py:16-25`):

```python
def kms_encrypt(plaintext: str) -> str:
    """Encrypt using KMS. Returns base64-encoded ciphertext."""

def kms_decrypt(ct_b64: str) -> bytes:
    """Decrypt a KMS ciphertext. Returns plaintext bytes."""
```

The `kms_encrypt` function uses `S.kms_key_id` (see `app/core/settings.py:176`) to call `kms.encrypt()` via the boto3 KMS client (see `app/core/aws.py`). The mock KMS server runs on port 7999 (see `scripts/mock_kms_server.py:33`). In dev mode, the mock KMS server accepts any key ID and performs reversible AES encryption.

This infrastructure is suitable for field-level encryption, but the current functions operate on single strings. For batch encryption (multiple fields per case), a wrapper is needed to minimize KMS API calls.

### 2.2 KYC Case Storage (`app/services/kyc_cases.py`)

The `KycCaseStore.create_case` (see `app/services/kyc_cases.py:97`) and `update_draft` (see `app/services/kyc_cases.py:200`) methods write case data directly to DDB without any encryption layer. The `files` list on each case stores file metadata including `file_type` and S3 references, but document numbers extracted from files (e.g., by OCR in KYC-002) would be stored as plaintext attributes. The case PK uses `_case_pk` (see `app/services/kyc_cases.py:36`) which returns `KYC#{case_id}`.

### 2.3 GDPR Service (`app/services/gdpr_service.py`)

The existing GDPR service (see `app/services/gdpr_service.py`) supports:
- `create_export_request(user_sub, categories)` (see line 100) -- Data export (DSAR)
- `create_deletion_request(user_sub, reason)` (see line 123) -- Data deletion
- `get_request(user_sub, request_id)` (see line 149) -- Status check
- `list_user_requests(user_sub)` (see line 169) -- List requests

The deletion flow deletes DDB records but does not handle encrypted field key destruction. The encryption service must integrate with the GDPR service so that deletion requests also destroy per-user encryption keys.

### 2.4 Admin Role System (`app/auth/roles.py`, `app/auth/deps.py`)

The `AuthenticatedUser` (see `app/auth/deps.py:126`) returned by `get_authenticated_user` (see `app/auth/deps.py:184`) includes `sub`, `role` (USER/ADMIN/ROOT — see `app/auth/roles.py:8-11`), and `admin_profile` with `scopes`. The `assigned_admin_sub` field on KYC cases (`KycCaseReviewRef`, see `app/contracts/kyc_cases_contract.py:44-46`) identifies which admin is currently assigned. Decryption authorization can use the comparison: `requesting_admin_sub == case.review.assigned_admin_sub`.

---

## 3. Technical Design

### 3.1 Architecture Diagram

```
+-------------------+      +--------------------+      +-------------------+
|   React Frontend  |      |   FastAPI Backend   |      |  AWS KMS (Mock)   |
|                   |      |                    |      |  Port 7999        |
|  Admin: Case      |      |                    |      |                   |
|  Detail View      |      |  KycEncryption     |      |                   |
|                   |      |  Service           |      |                   |
|  PiiFieldDisplay  | ---> |                    | ---> |  GenerateDataKey  |
|  (masked by       |      |  encrypt_fields()  |      |  (returns DEK +   |
|   default)        |      |  decrypt_fields()  |      |   wrapped DEK)    |
|                   |      |  mask_fields()     |      |                   |
|  "Reveal" button  | ---> |  destroy_user_keys |      |  Decrypt          |
|  (assigned admin) |      |                    |      |  (unwrap DEK)     |
|                   |      |  log_access()      |      |                   |
+-------------------+      +--------------------+      +-------------------+
                                    |
                                    v
                           +--------------------+
                           |   DynamoDB Tables   |
                           |                    |
                           |  kyc_cases table:   |
                           |   Case items with   |
                           |   encrypted_pii (M) |
                           |                    |
                           |   USER_DEK#{sub}    |
                           |   (per-user keys)   |
                           |                    |
                           |   PII_AUDIT#{case}  |
                           |   (access log)      |
                           +--------------------+

Encryption Flow (write):

  KycCaseStore                KycEncryptionService           KMS Mock
       |                            |                          |
       | create_case(pii_data)      |                          |
       |--------------------------->|                          |
       |                            | get/create user DEK      |
       |                            |------------------------->|
       |                            | <-- plaintext DEK        |
       |                            |    + wrapped DEK         |
       |                            |                          |
       |                            | AES-256-GCM encrypt      |
       |                            | each PII field with DEK  |
       |                            |                          |
       |  <-- encrypted_pii map     |                          |
       |                            |                          |
       | DDB PutItem with           |                          |
       | encrypted_pii attribute    |                          |

Decryption Flow (read):

  Admin clicks "Reveal"     KycEncryptionService           KMS Mock
       |                            |                          |
       | POST /pii/decrypt          |                          |
       |--------------------------->|                          |
       |                            | get wrapped DEK          |
       |                            | for user                 |
       |                            |------------------------->|
       |                            | <-- plaintext DEK        |
       |                            |                          |
       |                            | AES-256-GCM decrypt      |
       |                            | requested fields         |
       |                            |                          |
       |                            | log_access() to          |
       |                            | PII_AUDIT table          |
       |                            |                          |
       |  <-- decrypted values      |                          |
```

### 3.2 New Service: `app/services/kyc_encryption.py`

<!-- NOTE: app/services/kyc_encryption.py does not exist yet — new implementation required -->

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
        Does NOT call KMS -- no audit entry generated."""

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

### 3.3 Encryption Architecture

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
      wrapped_dek (S)       -- KMS-encrypted DEK
      key_id (S)            -- KMS key ID
      created_at (N)
      version (N)           -- For key rotation

    PK=USER_DEK#{user_sub}  SK=ROTATED#{version}
      wrapped_dek (S)       -- Old DEK (retained 30 days)
      rotated_at (N)
      ttl (N)               -- DDB TTL, 30 days

  kyc_cases table (on case items):
    encrypted_pii (M)       -- Map of field_name -> EncryptedField
```

### 3.4 DynamoDB Access Patterns

| Access Pattern | PK | SK / Index | Operation | Notes |
|---|---|---|---|---|
| Get active DEK for user | `USER_DEK#{user_sub}` | `ACTIVE` | GetItem | Used on every encrypt/decrypt operation |
| Store new DEK | `USER_DEK#{user_sub}` | `ACTIVE` | PutItem | Created on first PII write for a user |
| Archive rotated DEK | `USER_DEK#{user_sub}` | `ROTATED#{version}` | PutItem | Old key, TTL=30 days |
| List all DEKs for user | `USER_DEK#{user_sub}` | begins_with("") | Query | For key destruction (GDPR) |
| Write encrypted PII to case | Case PK/SK | -- | UpdateItem | Sets `encrypted_pii` map attribute |
| Read encrypted PII from case | Case PK/SK | -- | GetItem | Returns `encrypted_pii` for mask/decrypt |
| Write audit log entry | `PII_AUDIT#{case_id}` | `{timestamp}#{event_id}` | PutItem | One entry per access event |
| Query audit log by case | `PII_AUDIT#{case_id}` | -- | Query | Paginated, newest first |
| Query audit log by accessor | GSI `pii-audit-accessor-index` | PK=accessor_sub, SK=created_at | Query | For compliance reporting |

**Example DynamoDB Items:**

User DEK (active):
```json
{
  "pk": "USER_DEK#alice-uuid",
  "sk": "ACTIVE",
  "wrapped_dek": "AQECAHhWPJtG6u...base64-wrapped-key",
  "key_id": "arn:aws:kms:us-east-1:000000000000:key/mock-kms-key-id",
  "created_at": 1748520000,
  "version": 1
}
```

Encrypted PII on case:
```json
{
  "pk": "CASE#kyc_case_001",
  "sk": "META",
  "encrypted_pii": {
    "document_number": {
      "ciphertext_b64": "Wk1E...base64",
      "key_id": "arn:aws:kms:us-east-1:000000000000:key/mock-kms-key-id",
      "algorithm": "AES-256-GCM",
      "encrypted_at": 1748520100,
      "field_name": "document_number"
    },
    "date_of_birth": {
      "ciphertext_b64": "XmJq...base64",
      "key_id": "arn:aws:kms:us-east-1:000000000000:key/mock-kms-key-id",
      "algorithm": "AES-256-GCM",
      "encrypted_at": 1748520100,
      "field_name": "date_of_birth"
    }
  },
  "pii_hints": {
    "document_number": "4567",
    "date_of_birth": "1990"
  }
}
```

PII audit log entry:
```json
{
  "pk": "PII_AUDIT#kyc_case_001",
  "sk": "1748520200#evt_abc123",
  "accessor_sub": "charlie-admin-uuid",
  "action": "decrypt",
  "fields": ["document_number", "date_of_birth"],
  "reason": "case_review",
  "ip_address": "192.168.1.100",
  "created_at": 1748520200
}
```

### 3.5 PII Access Audit Log

Stored in the `kyc_cases` table using single-table design:

```
PK: PII_AUDIT#{case_id}
SK: {timestamp}#{event_id}

Attributes:
  accessor_sub (S)         -- Who accessed the data
  action (S)               -- "decrypt" | "encrypt" | "mask" | "delete"
  fields (L)               -- List of field names accessed
  reason (S)               -- Why (e.g., "case_review", "export_request", "admin_override")
  ip_address (S)           -- Accessor's IP
  created_at (N)
```

GSI for querying by accessor:

```
GSI pii-audit-accessor-index:
  PK: accessor_sub (S)
  SK: created_at (N)
```

This GSI would be added to the existing `kyc_cases` table (not a new table). The table is defined in `scripts/local-ddb-init.py:91-96` and currently has two GSIs: `owner-updated-index` and `status-updated-index` (see `app/core/settings.py:1066-1067`).

### 3.6 Integration with KYC Case Service

Modify `app/services/kyc_cases.py`:

**On case creation / draft update** -- encrypt PII fields before DDB write:

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

**On case read (user/admin)** -- decrypt or mask based on authorization:

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

### 3.7 GDPR Integration

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

### 3.8 Pydantic Models

```python
# -- KYC Data Encryption (KYC-023) -- Add to app/models.py

class EncryptedFieldOut(BaseModel):
    field_name: str
    encrypted: bool = True
    key_id: str = ""
    algorithm: str = "AES-256-GCM"
    encrypted_at: int = 0


class PiiDecryptRequest(BaseModel):
    fields: list[str] = Field(
        ..., min_length=1, max_length=10,
        description="PII field names to decrypt"
    )
    reason: str = Field(
        ..., min_length=3, max_length=500,
        description="Reason for accessing PII (required for audit)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "fields": ["document_number", "date_of_birth"],
                "reason": "Reviewing case for Tier 2 approval"
            }
        }


class PiiDecryptResponse(BaseModel):
    pii: dict[str, str] = Field(
        default_factory=dict,
        description="Map of field_name -> plaintext value"
    )


class PiiMaskedResponse(BaseModel):
    pii: dict[str, str] = Field(
        default_factory=dict,
        description="Map of field_name -> masked value"
    )


class PiiAuditEvent(BaseModel):
    event_id: str
    accessor_sub: str
    accessor_display_name: str = ""
    action: str  # "decrypt", "encrypt", "mask", "delete"
    fields: list[str]
    reason: str
    ip_address: str = ""
    created_at: int = 0


class PiiAuditLogResponse(BaseModel):
    events: list[PiiAuditEvent] = Field(default_factory=list)
    next_cursor: str | None = None


class KeyRotationResponse(BaseModel):
    ok: bool = True
    new_version: int = 0
    fields_re_encrypted: int = 0


class KeyDestroyResponse(BaseModel):
    ok: bool = True
    keys_destroyed: int = 0
    fields_affected: int = 0
```

### 3.9 Router Endpoints

Add to `app/routers/kyc_cases.py` (existing router prefix is `/v1/kyc/cases`, see line 48):

<!-- NOTE: require_admin_session does not exist. The existing KYC admin pattern uses
     require_ui_session + manual role check: normalize_role(user.role) not in {Role.ADMIN, Role.ROOT}
     (see app/routers/kyc_cases.py:1000-1003). require_root_session does exist (see app/auth/deps.py:273)
     but is not currently used in the KYC router. -->

```python
# PII access endpoints
POST /v1/kyc/cases/{case_id}/pii/decrypt
  -- Decrypt specific PII fields for assigned admin
  -- Auth: require_ui_session + admin/root role check (see app/routers/kyc_cases.py:1000-1003 for pattern)
  -- Body: { "fields": ["document_number", "date_of_birth"], "reason": str }
  -- Response: { "pii": { "document_number": "AB1234567", "date_of_birth": "1990-01-15" } }

GET /v1/kyc/cases/{case_id}/pii/masked
  -- Get masked PII values (any admin)
  -- Auth: require_ui_session + admin/root role check
  -- Response: { "pii": { "document_number": "****4567", "date_of_birth": "1990-**-**" } }

# Audit endpoints
GET /v1/kyc/cases/{case_id}/pii/audit-log
  -- Get PII access log for a case
  -- Auth: require_ui_session + root role check (or use require_root_session from app/auth/deps.py:273)
  -- Response: { "events": [...] }

GET /v1/kyc/admin/pii/audit-log?accessor={sub}&from={ts}&to={ts}
  -- Query PII access log by accessor
  -- Auth: require_ui_session + root role check
  -- Response: { "events": [...] }

# Key management (root only)
POST /v1/kyc/admin/encryption/rotate-key/{user_sub}
  -- Rotate a user's DEK
  -- Auth: require_ui_session + root role check
  -- Response: { "ok": true, "new_version": int }

POST /v1/kyc/admin/encryption/destroy-keys/{user_sub}
  -- Permanently destroy user's keys (GDPR erasure)
  -- Auth: require_ui_session + root role check
  -- Response: { "ok": true, "fields_affected": int }
```

### 3.10 API Request/Response Examples

**Decrypt PII fields (assigned admin):**
```bash
curl -X POST http://localhost:8000/v1/kyc/cases/kyc_case_001/pii/decrypt \
  -H "Cookie: ui_session=sess_charlie; ui_csrf=csrf_charlie; ui_access_token=tok_charlie" \
  -H "x-csrf-token: csrf_charlie" \
  -H "Content-Type: application/json" \
  -d '{"fields": ["document_number", "date_of_birth"], "reason": "Reviewing case for Tier 2 approval"}'

# Response 200:
{
  "pii": {
    "document_number": "AB1234567",
    "date_of_birth": "1990-01-15"
  }
}

# Error 403 - not assigned admin:
{
  "detail": "Only the assigned admin can decrypt PII for this case"
}

# Error 400 - missing reason:
{
  "detail": [{"loc": ["body", "reason"], "msg": "field required"}]
}
```

**Get masked PII (any admin):**
```bash
curl http://localhost:8000/v1/kyc/cases/kyc_case_001/pii/masked \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_root; ui_access_token=tok_root"

# Response 200:
{
  "pii": {
    "document_number": "****4567",
    "date_of_birth": "1990-**-**",
    "tax_id": "***-**-1234",
    "bank_routing_number": "*********"
  }
}
```

**Get PII audit log:**
```bash
curl "http://localhost:8000/v1/kyc/cases/kyc_case_001/pii/audit-log" \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_root; ui_access_token=tok_root"

# Response 200:
{
  "events": [
    {
      "event_id": "evt_abc123",
      "accessor_sub": "charlie-admin-uuid",
      "accessor_display_name": "Charlie Admin",
      "action": "decrypt",
      "fields": ["document_number", "date_of_birth"],
      "reason": "Reviewing case for Tier 2 approval",
      "ip_address": "127.0.0.1",
      "created_at": 1748520200
    }
  ],
  "next_cursor": null
}
```

**Rotate DEK (root only):**
```bash
curl -X POST http://localhost:8000/v1/kyc/admin/encryption/rotate-key/alice-uuid \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_root; ui_access_token=tok_root" \
  -H "x-csrf-token: csrf_root"

# Response 200:
{
  "ok": true,
  "new_version": 2,
  "fields_re_encrypted": 5
}
```

**Destroy keys (GDPR erasure, root only):**
```bash
curl -X POST http://localhost:8000/v1/kyc/admin/encryption/destroy-keys/alice-uuid \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_root; ui_access_token=tok_root" \
  -H "x-csrf-token: csrf_root"

# Response 200:
{
  "ok": true,
  "keys_destroyed": 2,
  "fields_affected": 8
}
```

### 3.11 Data Masking Rules

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

### 3.12 Frontend Changes

**Admin case detail**: Modify the case detail view to show masked PII by default, with a "Reveal" button for assigned admins that triggers the decrypt endpoint.

- `PiiFieldDisplay` -- Shows masked value with optional "Reveal" button
- `PiiAuditLog` -- Table showing who accessed PII, when, for what reason (root-only view)

**Frontend Component Tree:**

```
AdminCaseDetailPage
  +-- CaseHeader (status, tier, assignment)
  +-- PiiSection
  |     +-- PiiFieldDisplay (for each encrypted field)
  |     |     +-- MaskedValue ("****4567")
  |     |     +-- RevealButton (visible only for assigned admin)
  |     |     |     -> onClick: POST /pii/decrypt
  |     |     |     -> Shows plaintext for 30 seconds, then re-masks
  |     |     +-- ReasonInput (dialog for decrypt reason)
  |     |
  |     +-- PiiDecryptAllButton (decrypt all fields at once)
  |           -> Opens reason dialog, decrypts all
  |
  +-- PiiAuditLogSection (root-only)
  |     +-- PiiAuditLog
  |           +-- DataTable (event_id, accessor, action, fields, reason, timestamp)
  |           +-- Pagination (cursor-based)
  |
  +-- KeyManagementSection (root-only)
        +-- RotateKeyButton -> POST /rotate-key/{user_sub}
        +-- DestroyKeysButton -> POST /destroy-keys/{user_sub}
              +-- ConfirmDialog ("This action is irreversible...")
```

**TypeScript Props Interfaces:**

```typescript
interface PiiFieldDisplayProps {
  fieldName: string;
  maskedValue: string;
  canReveal: boolean;  // true if viewer is assigned admin
  caseId: string;
  onRevealed?: (plaintext: string) => void;
}

interface PiiAuditLogProps {
  caseId: string;
}

interface PiiDecryptDialogProps {
  caseId: string;
  fields: string[];
  onDecrypted: (values: Record<string, string>) => void;
  onCancel: () => void;
}
```

**Admin UI flow**:
1. Case detail loads with masked PII (`****4567` for document number)
2. Assigned admin clicks "Reveal" on a field
3. Dialog prompts for reason ("Why do you need to see this?")
4. Frontend calls `POST /pii/decrypt` with field name and reason
5. Decrypted value shown temporarily (auto-hides after 30 seconds)
6. Access logged in audit table

---

## 4. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---|---|---|---|
| Not assigned admin for decrypt | 403 | `pii_not_assigned` | "Only the assigned reviewer can decrypt PII for this case." | Assign yourself to the case first |
| Missing decrypt reason | 400 | `pii_reason_required` | "A reason is required to access PII data." | Enter a reason |
| DEK not found for user | 404 | `pii_no_dek` | "No encryption key found for this user." | User has no encrypted PII |
| KMS decrypt failure | 500 | `pii_decrypt_error` | "Unable to decrypt data. Please try again or contact support." | Retry; check KMS availability |
| Keys already destroyed | 410 | `pii_keys_destroyed` | "PII data has been permanently erased and cannot be recovered." | None -- data is gone |
| Non-root accessing audit log | 403 | `pii_audit_forbidden` | "Only root users can access the PII audit log." | Escalate to root |
| Non-root rotating keys | 403 | `pii_rotation_forbidden` | "Only root users can rotate encryption keys." | Escalate to root |
| Case has no encrypted PII | 200 | -- | Returns empty pii map | N/A |
| Field name not in encrypted_pii | 400 | `pii_field_not_found` | "Requested field is not encrypted on this case." | Check available fields |
| KMS service unavailable | 503 | `kms_unavailable` | "Encryption service temporarily unavailable." | Retry after delay |
| Rate limit on decrypt | 429 | `rate_limit` | "Too many decryption requests. Please wait." | Wait and retry |

---

## 5. Observability & Monitoring

### 5.1 Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `kyc_pii_encryptions_total` | Counter | `field` | Total field encryption operations |
| `kyc_pii_decryptions_total` | Counter | `field`, `accessor_role` | Total field decryption operations |
| `kyc_pii_mask_requests_total` | Counter | -- | Total mask operations (no KMS call) |
| `kyc_pii_decrypt_latency_seconds` | Histogram | -- | Decryption latency including KMS unwrap |
| `kyc_pii_key_rotations_total` | Counter | -- | DEK rotation events |
| `kyc_pii_key_destructions_total` | Counter | -- | Permanent key destruction events |
| `kyc_pii_audit_events_total` | Counter | `action` | Total audit log entries written |
| `kyc_pii_kms_errors_total` | Counter | `operation` | KMS API call failures |

### 5.2 Log Events

| Event | Level | Fields | Description |
|---|---|---|---|
| `pii.encrypted` | INFO | `case_id`, `fields`, `user_sub` | PII fields encrypted during case write |
| `pii.decrypted` | INFO | `case_id`, `fields`, `accessor_sub`, `reason` | PII fields decrypted (always logged) |
| `pii.masked` | DEBUG | `case_id`, `fields`, `viewer_sub` | Masked values returned (no KMS) |
| `pii.key.rotated` | INFO | `user_sub`, `old_version`, `new_version` | DEK rotated |
| `pii.key.destroyed` | WARN | `user_sub`, `keys_destroyed`, `fields_affected` | Permanent key destruction |
| `pii.kms.error` | ERROR | `operation`, `error_message` | KMS API failure |
| `pii.audit.written` | DEBUG | `event_id`, `case_id`, `accessor_sub` | Audit log entry recorded |

### 5.3 Alerting Rules

| Alert | Condition | Severity |
|---|---|---|
| PII decryption spike | `kyc_pii_decryptions_total` > 100 in 10 minutes | P2 (unusual access) |
| KMS error rate | `kyc_pii_kms_errors_total` > 5 in 5 minutes | P1 (encryption broken) |
| Key destruction event | Any `pii.key.destroyed` log event | P3 (audit notification) |
| Decryption latency high | P95 > 5 seconds for 5 minutes | P3 |
| Unauthorized decrypt attempts | 403 responses on /pii/decrypt > 10 in 1 hour | P2 |

---

## 6. Rollout Plan

### 6.1 Feature Flags

| Flag | Default (Dev) | Default (Prod) | Description |
|---|---|---|---|
| `KYC_ENCRYPTION_ENABLED` | `true` | `false` | Master enable for PII encryption |
| `KYC_ENCRYPTION_AUDIT_ENABLED` | `true` | `true` | Enable PII access audit logging |
| `KYC_DEK_ROTATION_DAYS` | `90` | `90` | Days between automatic DEK rotation |
| `KYC_PII_REVEAL_TIMEOUT_SECONDS` | `30` | `30` | Auto-hide timeout for revealed PII |

### 6.2 Phased Deployment

| Phase | Scope | Duration | Success Criteria |
|---|---|---|---|
| Phase 1: Schema + models | Deploy encrypted_pii field support, backwards-compatible | 1 day | No runtime errors, existing cases unaffected |
| Phase 2: Encrypt new cases | New cases encrypt PII on creation | 3 days | 100+ cases encrypted, decrypt works correctly |
| Phase 3: Backfill existing | Script to encrypt PII on existing cases | 2 days | All existing PII encrypted, audit log populated |
| Phase 4: Mask by default | Enable masking for non-assigned admins | 1 day | Non-assigned admins see masked values |
| Phase 5: GDPR integration | Connect key destruction to GDPR deletion flow | 2 days | Deletion request destroys keys, fields unrecoverable |

### 6.3 Rollback Procedure

1. Set `KYC_ENCRYPTION_ENABLED=false` -- new cases store PII in plaintext (fallback)
2. Existing encrypted fields remain encrypted and decryptable (no data loss)
3. Masking continues to work (uses metadata, not KMS)
4. To fully revert: run migration script to decrypt all fields back to plaintext and remove `encrypted_pii` attributes
5. Audit log entries are permanent and not affected by rollback

---

## 7. Performance Considerations

### 7.1 Query Cost Analysis

| Operation | DDB Operations | KMS Calls | Estimated Cost |
|---|---|---|---|
| Encrypt PII (case create) | 1 GetItem (DEK) + 1 UpdateItem (case) | 1 GenerateDataKey (or 0 if DEK cached) | 2 WCU + 1 RCU + 1 KMS |
| Decrypt PII (admin reveal) | 1 GetItem (DEK) + 1 GetItem (case) + 1 PutItem (audit) | 1 Decrypt (unwrap DEK) | 1 WCU + 2 RCU + 1 KMS |
| Mask PII (non-assigned view) | 1 GetItem (case) | 0 KMS calls | 1 RCU |
| Rotate DEK | N GetItem + N UpdateItem (re-encrypt) + 2 PutItem (keys) | 1 GenerateDataKey + 1 Decrypt | N*2 WCU + N RCU + 2 KMS |
| Destroy keys | Query + BatchDelete | 0 | Query cost + N WCU |

### 7.2 Caching Strategy

| Data | Cache | TTL | Invalidation |
|---|---|---|---|
| Unwrapped DEK | In-memory per-request | Request scope only | Cleared after request |
| Masking rules | In-memory constant | Never | Application restart |
| Audit log queries | React Query client | 60 seconds | Invalidated on new decrypt |
| Masked PII values | React Query client | 30 seconds | Invalidated on reveal |

**Important**: The plaintext DEK must NEVER be cached across requests or stored in DDB. It is unwrapped via KMS for each decrypt operation and held only in memory during request processing.

### 7.3 Rate Limiting

| Endpoint | Limit | Window | Notes |
|---|---|---|---|
| POST /pii/decrypt | 20 per admin | 15 minutes | Prevents bulk PII extraction |
| GET /pii/masked | 60 per admin | 1 minute | Standard read rate |
| GET /pii/audit-log | 30 per root | 1 minute | Standard read rate |
| POST /rotate-key | 5 per root | 1 hour | Key rotation is expensive |
| POST /destroy-keys | 3 per root | 1 hour | Irreversible, rate-limit tightly |

---

## 8. E2E Test Plan

**Test file**: `frontend/e2e/kyc-encryption.spec.ts`
**Total**: ~22 tests across 4 sections (234-237)

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

### Section 235: Key Management & GDPR Erasure (6 tests)

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

test("235.6 Double key destruction is idempotent", async ({ page }) => {
  // Destroy keys twice -> second call returns ok with 0 keys_destroyed
});
```

### Section 236: Audit Log & Masking Rules (5 tests)

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

test("236.5 Audit log includes IP address of accessor", async ({ page }) => {
  // Decrypt PII, check audit log entry has ip_address set
});
```

### Section 237: Concurrent Access & Edge Cases (5 tests)

```typescript
test("237.1 Two admins decrypt same case concurrently", async ({ page }) => {
  // Both assigned admin and root decrypt simultaneously
  // Both get correct values, both audit entries recorded
});

test("237.2 Encrypt fields for case with no PII returns empty map", async ({ page }) => {
  // Create case without PII fields
  // GET masked -> pii map is empty
});

test("237.3 Re-encryption after draft update preserves old hint values", async ({ page }) => {
  // Create case with document_number, update draft with new document_number
  // Hints updated to reflect new value
});

test("237.4 Decrypt after case deletion returns 404", async ({ page }) => {
  // Delete case, POST decrypt -> 404
});

test("237.5 Audit log pagination works correctly", async ({ page }) => {
  // Generate many audit events, query with limit=5
  // Verify next_cursor returned, second page returns remaining events
});
```

---

## 9. File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/services/kyc_encryption.py` | **New** | Field encryption, DEK management, masking, audit logging |
| `app/routers/kyc_cases.py` | Modify | Add 6 PII/encryption endpoints |
| `app/contracts/kyc_cases_contract.py` | Modify | Add `EncryptedField`, `PiiDecryptRequest`, audit models |
| `app/services/kyc_cases.py` | Modify | Integrate encryption on create/read/update |
| `app/services/gdpr_service.py` | Modify | Add key destruction to deletion flow |
| `app/core/crypto.py` | Modify | Add batch encrypt/decrypt helpers, DEK generation |
| `app/core/settings.py` | Modify | Add `kyc_encryption_enabled`, `kyc_dek_rotation_days` settings |
| `frontend/src/api/endpoints/kyc-cases.ts` | **New** | Add `decryptPii`, `getMaskedPii`, `getAuditLog` functions |
<!-- NOTE: frontend/src/api/endpoints/kyc-cases.ts does not exist yet — new file required -->
| `frontend/src/api/types.ts` | Modify | Add `PiiField`, `PiiAuditEvent` types |
| `frontend/src/components/shared/PiiFieldDisplay.tsx` | **New** | Masked field with reveal button |
| `frontend/src/components/shared/PiiAuditLog.tsx` | **New** | Audit log table (root-only) |
| `frontend/e2e/kyc-encryption.spec.ts` | **New** | 22 E2E tests across sections 234-237 |

---

## Codebase References

| File | Lines | What was verified |
|------|-------|-------------------|
| `app/core/crypto.py` | 16-25 | `kms_encrypt` and `kms_decrypt` function signatures confirmed |
| `app/core/crypto.py` | 10 | Uses `kms` client from `app/core/aws.py` |
| `app/core/settings.py` | 176 | `kms_key_id` setting exists |
| `app/core/settings.py` | 1066-1067 | KYC cases GSI index name settings (owner + status) |
| `app/services/kyc_cases.py` | 36-48 | `_case_pk`, `_updated_sk`, `_owner_pk`, `_status_pk` helpers confirmed |
| `app/services/kyc_cases.py` | 94-97 | `KycCaseStore` dataclass and `create_case` method confirmed |
| `app/services/kyc_cases.py` | 200 | `update_draft` method confirmed |
| `app/services/kyc_cases.py` | 701 | `get_metrics_snapshot` method confirmed |
| `app/services/kyc_cases.py` | 747 | `run_retention_purge` method confirmed |
| `app/services/gdpr_service.py` | 100, 123, 149, 169 | GDPR service functions confirmed: `create_export_request`, `create_deletion_request`, `get_request`, `list_user_requests` |
| `app/contracts/kyc_cases_contract.py` | 44-46 | `KycCaseReviewRef` with `assigned_admin_sub` confirmed |
| `app/auth/deps.py` | 126, 184 | `AuthenticatedUser` class and `get_authenticated_user` confirmed |
| `app/auth/deps.py` | 273 | `require_root_session` exists |
| `app/auth/roles.py` | 8-11 | `Role` enum with ROOT/ADMIN/USER confirmed |
| `app/routers/kyc_cases.py` | 48 | Router prefix `/v1/kyc/cases` confirmed |
| `app/routers/kyc_cases.py` | 946-955 | `get_admin_kyc_metrics` endpoint confirmed |
| `app/routers/kyc_cases.py` | 1000-1003 | Admin auth pattern: `require_ui_session` + manual `Role.ADMIN/ROOT` check |
| `scripts/local-ddb-init.py` | 91-96 | KYC cases table definition with 2 GSIs |
| `scripts/mock_kms_server.py` | 33 | Mock KMS server on port 7999 |
| `app/services/kyc_encryption.py` | -- | **Does not exist yet** — new implementation required |
| `frontend/src/api/endpoints/kyc-cases.ts` | -- | **Does not exist yet** — new file required |
