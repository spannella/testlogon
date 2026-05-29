# INFRA-002: SSH Key Manager

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 5-7 days  
**Dependencies**: INFRA-001 (Host Inventory Management)

---

## 1. Overview & Motivation

### The Gap

The SSH terminal (`app/routers/browser_ssh_terminal.py`, 1,126 lines) supports both password and private key authentication. When using key auth, the user pastes their private key directly into the WebSocket `connect` message payload:

```python
# From browser_ssh_terminal.py — connect payload:
# {host, port, username, authType: "private_key", privateKey: "-----BEGIN...", passphrase?: "..."}
```

The private key is:
1. **Never stored** — the user must paste it on every connection
2. **Transmitted in plaintext** over the WebSocket (TLS protects the wire, but the key exists in browser memory and JS console)
3. **Not associated with hosts** — no way to link a key to specific hosts for one-click connect

The platform has KMS encryption capabilities (`app/core/crypto.py`) with `kms_encrypt()` and `kms_decrypt()` functions backed by a mock KMS server on port 7999. These are used for encrypting sensitive data at rest (e.g., API key hashes). However, there is no SSH key storage system that leverages this encryption infrastructure.

### Why This Matters

1. **Security**: Users pasting private keys into browser forms is an anti-pattern. Keys should be stored encrypted and never exposed to the frontend after upload.
2. **Convenience**: Repeatedly pasting multi-line PEM-encoded keys is error-prone and tedious.
3. **Key management**: Users have no central place to manage their SSH keys — generate new ones, see fingerprints, associate keys with hosts, or rotate keys.
4. **Foundation for automation**: INFRA-003 (EC2 Launcher) and INFRA-004 (K8s Launcher) need to inject SSH keys into launched instances. Without a key store, this is impossible.
5. **Audit trail**: No record of which keys were used to connect to which hosts.

### Architecture After This Change

```
SSH Key Manager Flow

  Upload / Generate key
  POST /ui/remote/ssh-keys
       |
       v
  +------------------+
  | ssh_keys DDB      |  PK=user_sub, SK=KEY#{key_id}
  | private key blob   |  encrypted via KMS (app/core/crypto.py)
  | public key stored  |  plaintext (for export/fingerprint)
  +------------------+
       |
       +---> SshKeyManagerPage (key list, generate, upload, export pubkey)
       |
       +---> SSH terminal auto-connect:
       |     1. User clicks "Connect" on host (INFRA-001)
       |     2. Host has associated key_id
       |     3. Backend decrypts key via KMS
       |     4. Paramiko bridge uses decrypted key
       |     5. Key never reaches the frontend
       |
       +---> EC2 Launcher (INFRA-003): injects public key into instance user-data
       |
       +---> K8s Launcher (INFRA-004): mounts public key as authorized_keys
```

---

## 2. Current State Analysis

### 2.1 SSH Private Key Handling (`app/routers/browser_ssh_terminal.py`)

The `ParamikoSshBridge` class (line ~65) accepts `private_key: str | None` and `passphrase: str | None` in its constructor. The key is parsed using Paramiko's `paramiko.RSAKey.from_private_key()` / `paramiko.Ed25519Key.from_private_key()` / `paramiko.ECDSAKey.from_private_key()` / `paramiko.DSSKey.from_private_key()` from a `StringIO` wrapper. The bridge supports RSA, Ed25519, ECDSA, and DSS key types.

The WebSocket handler receives the key in the `connect` message:

```python
# Simplified from browser_ssh_terminal.py
auth_type = payload.get("authType", "password")
if auth_type == "private_key":
    private_key_pem = payload.get("privateKey", "")
    passphrase = payload.get("passphrase")
    bridge = ParamikoSshBridge(
        host=host, port=port, username=username,
        auth_type="private_key",
        private_key=private_key_pem,
        passphrase=passphrase,
        cols=cols, rows=rows,
    )
```

### 2.2 KMS Encryption (`app/core/crypto.py`)
<!-- VERIFIED: kms_encrypt at app/core/crypto.py:16, kms_decrypt at :22; uses S.kms_key_id at :17 -->

```python
def kms_encrypt(plaintext: str) -> str:
    """Encrypt plaintext using KMS. Returns base64-encoded ciphertext."""
    r = kms.encrypt(KeyId=S.kms_key_id, Plaintext=plaintext.encode("utf-8"))
    return base64.b64encode(r["CiphertextBlob"]).decode("ascii")

def kms_decrypt(ct_b64: str) -> bytes:
    """Decrypt base64-encoded ciphertext. Returns raw bytes."""
    ct = base64.b64decode(ct_b64)
    r = kms.decrypt(CiphertextBlob=ct)
    return r["Plaintext"]
```

KMS key ID is configured via `S.kms_key_id` in `app/core/settings.py`. Mock KMS server runs on port 7999 (`scripts/mock_kms_server.py`).

### 2.3 Key Generation Capabilities

Python's `cryptography` library (already in dependencies) supports key generation:
- RSA: `rsa.generate_private_key(public_exponent=65537, key_size=4096)`
- Ed25519: `ed25519.Ed25519PrivateKey.generate()`

Paramiko also has key generation but `cryptography` is preferred for its serialization options.

### 2.4 Host Inventory (INFRA-001)

The `remote_hosts` table stores host records with fields for SSH key association (to be added by this ticket). The `HostOut` model will gain an `ssh_key_id` field linking to a key in the `ssh_keys` table.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `ssh_keys`
<!-- NOTE: ssh_keys table does not exist yet in scripts/local-ddb-init.py — new table required -->

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.ssh_keys_table_name, "ssh_keys"),
    "user_sub",        # PK — key owner
    "sk",              # SK — KEY#{key_id}
    gsis=[
        {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | Key owner's user ID |
| `sk` | S (SK) | `KEY#{key_id}` |
| `key_id` | S | UUID for the key |
| `label` | S | Human-readable name (e.g., "Production Key") |
| `key_type` | S | `rsa`, `ed25519`, `ecdsa`, `dss` |
| `key_bits` | N | Key size in bits (4096 for RSA, 256 for Ed25519) |
| `public_key_openssh` | S | Public key in OpenSSH format (`ssh-rsa AAAA...`) |
| `public_key_fingerprint` | S | SHA256 fingerprint (`SHA256:xxxx...`) |
| `encrypted_private_key_blob` | S | KMS-encrypted private key PEM (base64) |
| `passphrase_protected` | BOOL | Whether the original key had a passphrase |
| `created_at` | N | Unix timestamp |
| `last_used_at` | N | Unix timestamp of last use for SSH connection |
| `associated_hosts` | L[S] | List of host_ids linked to this key |
| `use_count` | N | Number of times key has been used |

### 3.2 Settings & Table Handle

**`app/core/settings.py`**:

```python
ssh_keys_table_name: str = "ssh_keys"
ssh_key_max_per_user: int = 20
```

**`app/core/tables.py`**:

```python
ssh_keys = _table(S.ssh_keys_table_name)
```

### 3.3 Service Layer: `app/services/ssh_key_manager.py`
<!-- NOTE: app/services/ssh_key_manager.py does not exist yet — new implementation required -->

New file (~350 lines). Core functions:

```python
"""SSH key management — generate, store (KMS-encrypted), retrieve, and associate with hosts."""

from __future__ import annotations
import base64
import hashlib
import io
import uuid
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
import paramiko

from app.core.crypto import kms_encrypt, kms_decrypt
from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts
from app.services.alerts import audit_event


def generate_key(
    user_sub: str,
    *,
    label: str,
    key_type: str = "ed25519",  # ed25519 | rsa
    key_bits: int = 4096,       # only for RSA
) -> Dict[str, Any]:
    """Generate a new SSH key pair. Store encrypted private key in DDB.
    Returns key metadata + public key (private key is never returned)."""

def upload_key(
    user_sub: str,
    *,
    label: str,
    private_key_pem: str,
    passphrase: str | None = None,
) -> Dict[str, Any]:
    """Upload an existing private key. Validate, extract public key + fingerprint,
    encrypt with KMS, store in DDB. Returns key metadata + public key."""

def get_key_metadata(user_sub: str, key_id: str) -> Dict[str, Any] | None:
    """Return key metadata (no private key). Includes public key and fingerprint."""

def list_keys(user_sub: str) -> List[Dict[str, Any]]:
    """List all keys for a user (metadata only, no private keys)."""

def delete_key(user_sub: str, key_id: str) -> bool:
    """Delete a key. Removes host associations. Returns True if deleted."""

def get_decrypted_private_key(user_sub: str, key_id: str) -> str:
    """Decrypt and return private key PEM. INTERNAL USE ONLY — called by SSH bridge,
    never exposed via API. Audit-logged."""

def associate_key_with_host(user_sub: str, key_id: str, host_id: str) -> None:
    """Link a key to a host. Updates both key's associated_hosts and host's ssh_key_id."""

def disassociate_key_from_host(user_sub: str, key_id: str, host_id: str) -> None:
    """Unlink a key from a host."""

def _compute_fingerprint(public_key_bytes: bytes) -> str:
    """Compute SHA256 fingerprint in OpenSSH format."""
    digest = hashlib.sha256(public_key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

def _detect_key_type(private_key_pem: str) -> tuple[str, int]:
    """Detect key type and bits from PEM content. Returns (type, bits)."""

def _validate_key_pem(pem: str, passphrase: str | None) -> None:
    """Validate that PEM is a parseable private key. Raises ValueError if invalid."""
```

**Key generation implementation detail**:

```python
def generate_key(user_sub: str, *, label: str, key_type: str = "ed25519", key_bits: int = 4096):
    if key_type == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
        bits = 256
    elif key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
        bits = key_bits
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    # Serialize private key PEM (no passphrase — encryption handled by KMS)
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_str = pem_bytes.decode("utf-8")

    # Serialize public key in OpenSSH format
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    pub_str = pub_bytes.decode("utf-8")

    # Encrypt private key with KMS
    encrypted_blob = kms_encrypt(pem_str)

    # Compute fingerprint
    fingerprint = _compute_fingerprint(pub_bytes)

    key_id = uuid.uuid4().hex
    item = {
        "user_sub": user_sub,
        "sk": f"KEY#{key_id}",
        "key_id": key_id,
        "label": label,
        "key_type": key_type,
        "key_bits": bits,
        "public_key_openssh": pub_str,
        "public_key_fingerprint": fingerprint,
        "encrypted_private_key_blob": encrypted_blob,
        "passphrase_protected": False,
        "created_at": now_ts(),
        "last_used_at": 0,
        "associated_hosts": [],
        "use_count": 0,
    }
    T.ssh_keys.put_item(Item=item)

    audit_event(user_sub, event="ssh_key.generate", outcome="success",
                details={"key_id": key_id, "key_type": key_type, "bits": bits})

    return {k: v for k, v in item.items() if k != "encrypted_private_key_blob"}
```

### 3.4 SSH Bridge Integration
<!-- VERIFIED: browser_ssh_terminal.py exists (1125 lines); ParamikoSshBridge at ~line 65; registered at app/main.py:404 -->

Modify `app/routers/browser_ssh_terminal.py` to support a new `authType: "stored_key"` with `keyId` field:

```python
# In the WebSocket connect handler:
if auth_type == "stored_key":
    key_id = payload.get("keyId")
    if not key_id:
        raise BrowserSshError("MISSING_KEY_ID", "keyId required for stored_key auth")
    # Decrypt key server-side — never sent to frontend
    private_key_pem = get_decrypted_private_key(user_sub, key_id)
    bridge = ParamikoSshBridge(
        host=host, port=port, username=username,
        auth_type="private_key",
        private_key=private_key_pem,
        passphrase=None,  # KMS-stored keys have no passphrase
        cols=cols, rows=rows,
    )
    # Record key usage
    _record_key_usage(user_sub, key_id)
```

The private key is decrypted server-side and passed directly to Paramiko. It never appears in WebSocket messages or frontend state.

### 3.5 API Router: `app/routers/ssh_key_manager.py`
<!-- NOTE: app/routers/ssh_key_manager.py does not exist yet — new implementation required -->

New file (~180 lines). Prefix: `/ui/remote/ssh-keys`. All endpoints use `Depends(require_ui_session)`.

```python
router = APIRouter(prefix="/ui/remote/ssh-keys", tags=["ssh-key-manager"])
```

#### Endpoints

| Method | Path | Request Body | Response | Description |
|--------|------|-------------|----------|-------------|
| `POST` | `/ui/remote/ssh-keys` | `UploadSshKeyIn` | `SshKeyOut` (201) | Upload existing private key |
| `POST` | `/ui/remote/ssh-keys/generate` | `GenerateSshKeyIn` | `SshKeyOut` (201) | Generate new key pair |
| `GET` | `/ui/remote/ssh-keys` | — | `SshKeyListOut` | List all keys (metadata only) |
| `GET` | `/ui/remote/ssh-keys/{key_id}` | — | `SshKeyOut` | Get single key metadata |
| `DELETE` | `/ui/remote/ssh-keys/{key_id}` | — | `{"ok": true}` | Delete key |
| `GET` | `/ui/remote/ssh-keys/{key_id}/public` | — | `PublicKeyOut` | Export public key text |
| `POST` | `/ui/remote/ssh-keys/{key_id}/associate` | `AssociateKeyIn` | `{"ok": true}` | Link key to host |
| `DELETE` | `/ui/remote/ssh-keys/{key_id}/associate/{host_id}` | — | `{"ok": true}` | Unlink key from host |

#### Pydantic Models

```python
class UploadSshKeyIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    private_key_pem: str = Field(..., min_length=50, max_length=16_384)
    passphrase: Optional[str] = Field(default=None, max_length=256)

class GenerateSshKeyIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    key_type: Literal["rsa", "ed25519"] = "ed25519"
    key_bits: int = Field(default=4096, ge=2048, le=8192)  # only for RSA

class SshKeyOut(BaseModel):
    key_id: str
    label: str
    key_type: str
    key_bits: int
    public_key_openssh: str
    public_key_fingerprint: str
    passphrase_protected: bool
    created_at: int
    last_used_at: int
    associated_hosts: List[str]
    use_count: int

class SshKeyListOut(BaseModel):
    keys: List[SshKeyOut]
    count: int

class PublicKeyOut(BaseModel):
    key_id: str
    public_key_openssh: str
    public_key_fingerprint: str

class AssociateKeyIn(BaseModel):
    host_id: str = Field(..., min_length=1)
```

### 3.6 Host Inventory Extension

Add `ssh_key_id` field to the `remote_hosts` table (INFRA-001):

```python
# In HostOut model
ssh_key_id: Optional[str] = None  # Reference to ssh_keys KEY#{key_id}
```

When `associate_key_with_host()` is called, it updates both:
1. The key's `associated_hosts` list (append host_id)
2. The host's `ssh_key_id` field

### 3.7 Frontend Components

#### SshKeyManagerPage (`frontend/src/pages/remote/SshKeyManagerPage.tsx`)

New page (~350 lines):

- **Header**: "SSH Keys" title with "Generate Key" and "Upload Key" buttons
- **Key list**: DataTable with columns: Label, Type badge (RSA/Ed25519), Fingerprint (truncated), Created, Last Used, Associated Hosts count, Actions
- **Key detail panel**: Slide-over showing full fingerprint, public key (copyable), associated hosts list, usage stats
- **Empty state**: "No SSH keys stored. Generate a new key pair or upload an existing one."

#### GenerateKeyDialog (`frontend/src/pages/remote/GenerateKeyDialog.tsx`)

Dialog (~100 lines):

- Form: Label input, Key Type radio (Ed25519 recommended / RSA), Key Bits select (only for RSA: 2048/4096/8192)
- After generation: show public key in a copyable textarea with "Copy to clipboard" button and instructional text "Add this public key to ~/.ssh/authorized_keys on your target hosts"
- Download public key as `.pub` file

#### UploadKeyDialog (`frontend/src/pages/remote/UploadKeyDialog.tsx`)

Dialog (~120 lines):

- Form: Label input, Private Key textarea (or file upload), Passphrase input (optional)
- File upload accepts `.pem`, `.key`, `id_rsa`, `id_ed25519` files
- Validation feedback: shows detected key type and bits after paste/upload
- Warning banner: "Your private key is encrypted with KMS before storage. It is never exposed after upload."

#### Route & Navigation

```tsx
// App.tsx
<Route path="/remote/ssh-keys" element={<SshKeyManagerPage />} />
```

Sidebar: "SSH Keys" entry with `KeyRound` icon under Infrastructure group.

---

## 4. Implementation Plan

### Phase 1: Backend Key Storage (2 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `ssh_keys_table_name`, `ssh_key_max_per_user` |
| `app/core/tables.py` | Add `ssh_keys` table handle |
| `scripts/local-ddb-init.py` | Add `ssh_keys` TableDef with ByCreatedAt GSI |
| `app/services/ssh_key_manager.py` | New file: generate, upload, list, delete, decrypt, associate |
| `app/models.py` | Add SSH key Pydantic models |
| `app/routers/ssh_key_manager.py` | New file: 8 endpoints |
| `app/main.py` | Register `ssh_key_manager.router` |

### Phase 2: SSH Bridge Integration (1 day)

| File | Change |
|------|--------|
| `app/routers/browser_ssh_terminal.py` | Add `stored_key` auth type handler; decrypt key server-side; record usage |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add SSH key types |
| `frontend/src/api/endpoints/ssh-keys.ts` | New file: API wrappers |
| `frontend/src/pages/remote/SshKeyManagerPage.tsx` | New file: main page |
| `frontend/src/pages/remote/GenerateKeyDialog.tsx` | New file: generate dialog |
| `frontend/src/pages/remote/UploadKeyDialog.tsx` | New file: upload dialog |
| `frontend/src/App.tsx` | Add `/remote/ssh-keys` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "SSH Keys" nav item |

### Phase 4: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/ssh-key-manager.spec.ts` | New file: ~18 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/ssh-key-manager.spec.ts`)

**Section 244: Key Generation API (5 tests)**

1. `Alice generates an Ed25519 key` — POST `/generate` with `key_type: "ed25519"`. Verify 201 response with `key_type: "ed25519"`, `key_bits: 256`, non-empty `public_key_openssh` starting with `ssh-ed25519`, non-empty `public_key_fingerprint` starting with `SHA256:`.
2. `Alice generates an RSA 4096 key` — POST `/generate` with `key_type: "rsa"`, `key_bits: 4096`. Verify response has `key_type: "rsa"`, `key_bits: 4096`, public key starts with `ssh-rsa`.
3. `Generate key enforces max key limit` — Generate `ssh_key_max_per_user` keys (default 20). Attempt one more, verify 409 "Maximum SSH keys reached".
4. `Generated key metadata does not contain private key` — Verify response object has no field named `encrypted_private_key_blob` or `private_key`.
5. `Public key export returns copyable format` — Generate key, GET `/{key_id}/public`. Verify `public_key_openssh` is non-empty and `public_key_fingerprint` matches the generation response.

**Section 245: Key Upload API (4 tests)**

6. `Alice uploads an RSA private key` — POST with valid RSA PEM. Verify 201 with detected `key_type: "rsa"`, fingerprint populated.
7. `Alice uploads a passphrase-protected key` — POST with passphrase-protected PEM + passphrase. Verify 201 with `passphrase_protected: true`.
8. `Upload rejects invalid PEM` — POST with "not a key". Verify 400 "Invalid private key format".
9. `Upload without passphrase for protected key returns 400` — POST with passphrase-protected PEM but no passphrase. Verify 400 "Passphrase required".

**Section 246: Key Association & Deletion API (5 tests)**

10. `Associate key with host` — Create host (INFRA-001), generate key, POST `/associate`. Verify host's `ssh_key_id` is set and key's `associated_hosts` contains host_id.
11. `Disassociate key from host` — DELETE `/associate/{host_id}`. Verify host's `ssh_key_id` is null and key's `associated_hosts` is empty.
12. `Delete key removes host associations` — Associate key with 2 hosts, DELETE key. Verify both hosts have `ssh_key_id: null`.
13. `Alice cannot access Bob's keys` — Alice generates key, Bob tries GET/DELETE → 404.
14. `List keys returns all user keys` — Generate 3 keys. GET list, verify count=3 with all key_ids present.

**Section 247: SSH Key Manager UI (4 tests)**

15. `SshKeyManagerPage renders key list` — Navigate to `/remote/ssh-keys`, verify table headers: Label, Type, Fingerprint, Created, Last Used.
16. `Generate key dialog creates key and shows public key` — Click "Generate Key", fill label, select Ed25519, submit. Verify success toast, new row in table, public key copyable area visible.
17. `Upload key dialog accepts PEM file` — Click "Upload Key", paste valid RSA PEM, fill label, submit. Verify new row with RSA type badge.
18. `Delete key removes from list` — Click delete on key, confirm. Verify key removed from table.

**Test Setup**:

```typescript
const TS = Date.now();
// Generate a test RSA key for upload tests
const TEST_RSA_PEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...  // 2048-bit test key
-----END RSA PRIVATE KEY-----`;

test.beforeAll(async ({ browser }) => {
  // Setup sessions and pages
  sessions["alice"] = await getOrCreateSession("alice");
  sessions["bob"] = await getOrCreateSession("bob");
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
});
```

---

## 6. Security Considerations

### 6.1 Private Key Protection

- **At rest**: Private keys are encrypted with KMS via `kms_encrypt()` before storage. The encrypted blob is stored in DDB as a base64 string. Decryption requires access to the KMS key.
- **In transit (API)**: Private keys are only sent to the backend once during upload. The response never includes the private key. The `SshKeyOut` model deliberately excludes `encrypted_private_key_blob`.
- **In transit (SSH)**: When connecting with a stored key, the backend decrypts the key server-side and passes it directly to Paramiko. The key never traverses the WebSocket to the frontend.
- **In memory**: The decrypted key exists in Python process memory only for the duration of the Paramiko connection setup. After `ParamikoSshBridge.__init__()` parses the key, the PEM string is eligible for garbage collection.

### 6.2 KMS Key Rotation

If the KMS key is rotated, existing encrypted blobs can still be decrypted (AWS KMS retains old key material). New encryptions use the new key version. No data migration is needed.

### 6.3 User Isolation

All key records use `user_sub` as the DDB partition key. The `get_decrypted_private_key()` function requires `user_sub` and verifies ownership before decryption.

### 6.4 Audit Trail

All operations are audit-logged:
- `ssh_key.generate` — key generated
- `ssh_key.upload` — key uploaded
- `ssh_key.delete` — key deleted
- `ssh_key.decrypt` — key decrypted for SSH connection (includes `host`, `port`)
- `ssh_key.associate` / `ssh_key.disassociate` — key-host linking

### 6.5 Rate Limiting

Key generation is rate-limited to 5 per minute per user (CPU-intensive for RSA 4096). Upload is rate-limited to 10 per minute.

---

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ssh_key_generated_total` | Counter | `key_type` | Keys generated (ed25519/rsa) |
| `ssh_key_uploaded_total` | Counter | `key_type`, `passphrase_protected` | Keys uploaded |
| `ssh_key_deleted_total` | Counter | — | Keys deleted |
| `ssh_key_decrypted_total` | Counter | — | Keys decrypted for SSH connections |
| `ssh_key_decrypt_latency_seconds` | Histogram | — | KMS decryption latency |
| `ssh_key_association_total` | Counter | `action` (associate/disassociate) | Key-host linking events |
| `ssh_key_upload_rejected_total` | Counter | `reason` (invalid_pem/passphrase_missing/max_keys) | Upload failures |
| `ssh_key_count` | Gauge | `key_type` | Current key count per user (sampled) |

### 7.2 Structured Log Events

```json
{"logger": "ssh_key_manager", "level": "info", "event": "key_generated", "user_sub": "alice-uuid", "key_id": "k_abc123", "key_type": "ed25519", "bits": 256}

{"logger": "ssh_key_manager", "level": "info", "event": "key_uploaded", "user_sub": "alice-uuid", "key_id": "k_def456", "key_type": "rsa", "bits": 4096, "passphrase_protected": false}

{"logger": "ssh_key_manager", "level": "info", "event": "key_decrypted", "user_sub": "alice-uuid", "key_id": "k_abc123", "target_host": "10.0.1.10", "target_port": 22}

{"logger": "ssh_key_manager", "level": "warn", "event": "upload_rejected", "user_sub": "alice-uuid", "reason": "invalid_pem", "detail": "Could not parse private key"}

{"logger": "ssh_key_manager", "level": "warn", "event": "max_keys_reached", "user_sub": "alice-uuid", "current_count": 20, "max_allowed": 20}
```

### 7.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| KMS decrypt failures | `rate(ssh_key_decrypt_errors_total[5m]) > 5` | Critical | Check KMS key status |
| High decrypt latency | `p99(ssh_key_decrypt_latency_seconds) > 2s` | Warning | KMS throttling; consider caching |
| Key upload spike | `rate(ssh_key_uploaded_total[1h]) > 50` per user | Warning | Possible automated key testing |
| Invalid PEM uploads | `rate(ssh_key_upload_rejected_total{reason=invalid_pem}[1h]) > 20` | Warning | User education or UI issue |

---

## 8. Rollout Plan

### Phase 1: Backend (Days 1-2)

- **Feature flag**: `SSH_KEY_MANAGER_ENABLED=false`
- Deploy DDB table, service, router behind flag
- All endpoints return 404 when flag is off
- Test KMS encrypt/decrypt cycle with mock KMS

### Phase 2: Internal Beta (Days 3-4)

- **Feature flag**: `SSH_KEY_MANAGER_ENABLED=true` for internal users
- Deploy frontend pages
- Test generate + upload + stored_key SSH connection end-to-end
- Validate key never appears in WebSocket messages or browser devtools

### Phase 3: GA (Day 5+)

- **Feature flag**: `SSH_KEY_MANAGER_ENABLED=true` for all users
- Monitor KMS decrypt latency and key usage patterns
- **Rollback**: Set flag to false; users fall back to pasting keys manually

---

## 9. Performance Considerations

### 9.1 Latency Targets

| Operation | Target p50 | Target p99 | Notes |
|-----------|-----------|-----------|-------|
| Generate Ed25519 key | < 50ms | < 150ms | Fast key generation |
| Generate RSA 4096 key | < 500ms | < 2s | CPU-intensive |
| Upload key | < 100ms | < 300ms | Parse + KMS encrypt |
| List keys | < 30ms | < 80ms | Query + no decrypt |
| Decrypt key (SSH connect) | < 50ms | < 200ms | KMS API call |
| Associate key | < 20ms | < 60ms | 2 DDB updates |

### 9.2 DynamoDB Costs

| Operation | RCU | WCU | Notes |
|-----------|-----|-----|-------|
| Get key metadata | 0.5 | — | Single item |
| List keys | 2.0 | — | All keys for user (max 20) |
| Generate/upload | — | 1.0 | Single put |
| Associate/disassociate | — | 2.0 | Update key + host |
| Delete | — | 1.0 | Single delete |

### 9.3 Caching

- **Key metadata**: React Query `staleTime: 30s`. Invalidate on generate/upload/delete.
- **KMS decrypted keys**: NOT cached (security). Each SSH connection triggers a fresh KMS decrypt.
- **Public keys**: Can be cached longer (60s staleTime) since they don't change.

### 9.4 Scalability

- Per-user key limit (20) keeps DDB item count bounded.
- KMS API rate: 10,000 requests/sec per key (shared limit). Platform-wide SSH connections are well under this.
- RSA key generation: CPU-bound. Rate-limit to 5/min per user to prevent DoS.
- Encrypted blob size: RSA 4096 PEM is ~3.2KB. KMS-encrypted blob is ~4.5KB base64. Well within DDB 400KB item limit.
- Key listing is O(n) where n=user's keys (max 20). No pagination needed.

### 9.5 Rate Limiting

| Action | Limit | Window | Key |
|--------|-------|--------|-----|
| Generate key | 5 | 1 minute | user_sub |
| Upload key | 10 | 1 minute | user_sub |
| List keys | 60 | 1 minute | user_sub |
| Decrypt (SSH connect) | 30 | 1 minute | user_sub |

---

## 10. Migration & Rollback

### 7.1 DDB Changes

- New table `ssh_keys` — created by `scripts/local-ddb-init.py`.
- Add `ssh_key_id` field to `remote_hosts` items (backward-compatible: `Optional[str] = None`).

### 7.2 Rollback

- Remove router registration from `app/main.py`.
- Revert `browser_ssh_terminal.py` `stored_key` handler — users fall back to pasting keys manually.
- Encrypted key blobs remain in DDB but are inaccessible without the API.

---

## 8. Acceptance Criteria

1. Users can generate Ed25519 and RSA key pairs with configurable size.
2. Users can upload existing private keys (with optional passphrase).
3. Private keys are KMS-encrypted at rest and never returned via the API.
4. Public keys are exportable in OpenSSH format with SHA256 fingerprints.
5. Keys can be associated with hosts from INFRA-001.
6. SSH terminal supports `stored_key` auth type — private key is decrypted server-side and never reaches the browser.
7. Key usage is tracked (`last_used_at`, `use_count`).
8. All operations produce audit events.
9. Per-user key limit is enforced (default: 20).
10. User isolation: no cross-user key access.

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| `kms_encrypt()` | `app/core/crypto.py` | 16 | Encrypts plaintext using KMS; returns base64 ciphertext |
| `kms_decrypt()` | `app/core/crypto.py` | 22 | Decrypts base64 ciphertext; returns raw bytes |
| `kms_key_id` setting | `app/core/crypto.py` | 17 | Uses `S.kms_key_id`; mock KMS on port 7999 |
| `ParamikoSshBridge` | `app/routers/browser_ssh_terminal.py` | ~65 | SSH WebSocket bridge; accepts `private_key`, `passphrase` params |
| SSH terminal registration | `app/main.py` | 82-84, 404 | `browser_ssh_terminal_router` |
| `browser_ssh_terminal_enabled()` | `app/routers/browser_ssh_terminal.py` | 216 | Feature flag check |
| `audit_event()` | `app/services/alerts.py` | 695 | Audit logging |
| `ssh_keys` DDB table | — | — | Does not exist yet in `scripts/local-ddb-init.py` |
| `ssh_keys_table_name` setting | — | — | Does not exist yet in `app/core/settings.py` |
| `app/services/ssh_key_manager.py` | — | — | Does not exist yet |
| `app/routers/ssh_key_manager.py` | — | — | Does not exist yet |
