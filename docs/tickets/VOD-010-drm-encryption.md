# VOD-010: DRM Encryption Layer

**Ticket**: VOD-010
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-24

---

## 1. Overview & Motivation

The platform's video-on-demand pipeline currently produces unencrypted HLS segments via FFmpeg (`app/services/ffmpeg_abr_pipeline.py`). While playback is gated by entitlement tokens (`app/services/playback_entitlements.py`), the actual media segments sitting in S3 are cleartext `.ts` files. An attacker who discovers or guesses segment URLs can download and redistribute content without any entitlement check. The entitlement layer only gates the *manifest URL*; once a client has the manifest, individual segment fetches bypass token verification.

This ticket adds a **content encryption layer** so that segments are cryptographically protected at rest and during transit. Only clients that acquire a valid decryption key through an authenticated key server can play the content.

### Content Protection Requirements

1. **AES-128 HLS encryption** (Phase 1) -- The industry-standard `#EXT-X-KEY` mechanism built into all HLS players. Content segments are AES-128-CBC encrypted. The decryption key is fetched from a key server URL embedded in the manifest. The key server validates the viewer's entitlement token before serving the key.

2. **Widevine / FairPlay / PlayReady (Phase 2, future)** -- Full multi-DRM via CENC (Common Encryption) using Shaka Packager. The existing `DrmPolicy` contract (`app/contracts/video_pipeline_contract.py`) and `DrmLicenseRequest`/`DrmLicenseResponse` models (`app/contracts/drm_entitlement_contract.py`) already define the envelope. This spec designs the Phase 1 AES-128 implementation and establishes the key storage and rotation infrastructure that Phase 2 will reuse.

3. **Per-content keying** -- Each video asset gets its own content encryption key (CEK). Keys are derived deterministically using HKDF from a root secret plus asset-specific context, allowing re-derivation without storing plaintext keys in DynamoDB.

4. **Key rotation** -- Keys rotate on a configurable interval (default 300 seconds, minimum 60). This limits the exposure window if a key is leaked. The `DrmKeyRotationController` in `app/services/drm_production_provider.py` already implements slot-based rotation logic.

5. **Configurable per-video** -- DRM can be enabled or disabled per video via the `drm_policy_id` field on the video metadata record. Unprotected videos continue to serve cleartext HLS.

---

## 2. Current State Analysis

### 2.1 Existing Crypto Infrastructure

**`app/core/crypto.py`** provides:
- `kms_encrypt(plaintext) -> str` -- Encrypts via AWS KMS (or mocked KMS at port 7999 in dev), returns base64 ciphertext.
- `kms_decrypt(ct_b64) -> bytes` -- Decrypts KMS ciphertext, returns plaintext bytes.
- `b64url(data) / b64url_decode(s)` -- URL-safe base64 encode/decode utilities.
- `mint_ws_token / verify_ws_token` -- HMAC-signed token pattern (reusable pattern for key server tokens).

**`app/core/settings.py`** (lines 175-176, 350-358):
- `kms_key_id` -- The KMS CMK ARN/alias used by `kms_encrypt`/`kms_decrypt`.
- `drm_license_provider_mode` -- `"mock"` or `"production"` (line 351).
- `drm_provider_license_endpoint` -- External DRM license server URL (line 352).
- `drm_provider_api_key` -- API key for the external provider (line 353).
- `drm_key_rotation_enabled` -- Boolean, default `True` (line 356).
- `drm_key_rotation_seconds` -- Rotation interval, default 300 (line 357).
- `drm_key_rotation_salt` -- Salt for key ID derivation (line 358).
- `broadcast_local_drm_token_secret` / `broadcast_local_drm_static_token` / `broadcast_local_drm_key_root` -- Broadcast live DRM settings (lines 453-455).

### 2.2 Playback Entitlements System

**`app/services/playback_entitlements.py`** implements a self-contained HS256 JWT system for playback authorization:

- `issue_playback_entitlement(...)` -- Issues a signed token containing `tenant_id`, `asset_id`, `session_id`, `device_id`, `profile`, `aud`, `iat`, `exp`, `jti`. Signed with `S.playback_entitlement_secret`.
- `validate_playback_entitlement(*, token, expected_audience)` -- Verifies signature, expiry, audience, claim lengths, replay protection, and revocation.
- `revoke_playback_entitlement(...)` -- Revokes by JTI or session ID.

The entitlement token already contains `asset_id` and `tenant_id`, which are exactly the parameters needed to derive the content encryption key. The key server endpoint will validate the entitlement token and, if valid, derive and return the AES-128 key for the requested asset.

### 2.3 DRM Entitlement Contract

**`app/contracts/drm_entitlement_contract.py`** defines:
- `DrmEntitlementClaims` -- Claims model with `key_id`, `key_rotation_seconds`, `per_content_key`, `offline_allowed`.
- `DrmLicenseRequest` -- Contains `profile`, `challenge_b64` (for Widevine/FairPlay challenge-response).
- `DrmLicenseResponse` -- Returns `key_id`, `license_b64`, `expires_at_epoch`, `renewal_url`.

**`app/services/drm_license_service.py`** routes between mock and production providers.

**`app/services/drm_production_provider.py`** contains `DrmKeyRotationController`:
```python
class DrmKeyRotationController:
    def key_id_for(self, *, tenant_id, asset_id, profile, now_epoch) -> str:
        # slot = now_epoch // rotation_seconds
        # basis = f"{tenant_id}|{asset_id}|{profile}|{slot}|{salt}"
        # return sha256(basis)[:32]
```
This deterministic key ID derivation is the foundation for the VOD key derivation scheme.

### 2.4 FFmpeg HLS Output Format

**`app/services/ffmpeg_abr_pipeline.py`** (`build_rendition_ffmpeg_args`):
- Outputs HLS per-rendition playlists at `<output_dir>/<name>/index.m3u8`.
- Segment naming: `seg_%05d.ts`, 2-second segments (`-hls_time 2`).
- Uses `-hls_flags delete_segments+append_list` (live-streaming mode).
- GOP = 60 frames (`-g 60`) with `-sc_threshold 0` for consistent segments.

**`app/services/ffmpeg_abr_pipeline.py`** (`write_master_playlist`):
- Writes `master.m3u8` referencing `<name>/index.m3u8` for each rendition in `CANONICAL_ABR_LADDER`.

**`app/services/local_packaging.py`** (`shaka_packager_config`):
- Generates a Shaka Packager configuration referencing HLS variant playlists and DASH outputs.
- This is the hook point for Phase 2 CENC encryption integration.

### 2.5 Video Pipeline Contract

**`app/contracts/video_pipeline_contract.py`**:
- `DrmPolicy` model: `profile` (none/widevine/fairplay/playready/multi_drm), `key_rotation_seconds`, `per_content_key`, `offline_allowed`.
- `VideoPipelineJobRequest` includes a `drm: DrmPolicy` field.
- This contract is validated by `app/services/video_pipeline_contract_service.py`.

### 2.6 Broadcast Local DRM (Existing Pattern)

**`app/services/broadcast_local_drm.py`** implements AES-128 key management for live broadcasts:
- Keys are 16-byte random values stored on disk at `<key_root>/<stream_key>.key`.
- Token-gated access: `load_local_drm_key(stream_key, token)` validates a signed token before serving the key.
- FFmpeg in broadcast mode uses `-hls_key_info_file` pointing to a key info file that references the key server URL.

This pattern will be extended for VOD, replacing filesystem key storage with KMS-derived keys stored in DynamoDB.

---

## 3. Technical Design

### 3.1 Architecture Overview

```
                            +------------------+
                            |   Video Player   |
                            +------------------+
                                   |
                     1. GET master.m3u8 (needs entitlement token)
                                   |
                                   v
                          +-----------------+
                          |  CDN / Origin   |
                          +-----------------+
                                   |
                 2. Variant playlist contains:
                    #EXT-X-KEY:METHOD=AES-128,
                    URI="/drm/hls-key?asset_id=...&token=...",
                    IV=<segment-sequence-based>
                                   |
                                   v
                          +-----------------+
                          |   Key Server    |
                          | /drm/hls-key    |
                          +-----------------+
                                   |
                    3. Validate entitlement token
                    4. Derive content key via HKDF
                    5. Return 16-byte AES key
                                   |
                                   v
                          +-----------------+
                          |   DynamoDB      |
                          | (ContentKeys)   |
                          +-----------------+
```

### 3.2 Content Key Derivation

Keys are derived deterministically using HKDF-SHA256, not generated randomly. This allows any backend instance to derive the same key without sharing state, and avoids storing plaintext keys.

**Derivation inputs:**
- `IKM` (Input Key Material): `S.drm_key_rotation_salt` (shared secret, must be at least 32 bytes in production).
- `salt`: SHA-256 of `f"{tenant_id}|{asset_id}"` (binds key to content).
- `info`: `f"hls-aes128|{key_slot}"` where `key_slot = now_epoch // rotation_seconds` (supports rotation).
- Output: 16 bytes (128 bits) for AES-128.

```python
import hashlib
import hmac

def derive_content_key(
    *,
    tenant_id: str,
    asset_id: str,
    key_slot: int,
    root_secret: str,
) -> bytes:
    """HKDF-SHA256 to derive a 16-byte AES-128 content encryption key."""
    # Step 1: Extract
    salt = hashlib.sha256(f"{tenant_id}|{asset_id}".encode()).digest()
    prk = hmac.new(salt, root_secret.encode("utf-8"), hashlib.sha256).digest()
    # Step 2: Expand (single iteration since output <= hash length)
    info = f"hls-aes128|{key_slot}".encode("utf-8")
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:16]
    return okm
```

**Key ID**: Same as the existing `DrmKeyRotationController.key_id_for()` -- `sha256(f"{tenant_id}|{asset_id}|aes128|{slot}|{salt}")[:32]`.

### 3.3 DynamoDB Key Metadata Table

**Table name**: `ContentKeys` (env var: `DDB_CONTENT_KEYS`, setting: `content_keys_table_name`)

| Attribute | Type | Role |
|-----------|------|------|
| `key_id` | S | Partition key (the derived 32-char hex key ID) |

#### Item Schema

```json
{
  "key_id": "<32-char-hex>",
  "tenant_id": "<tenant>",
  "asset_id": "<asset>",
  "key_slot": 5666666,
  "drm_profile": "aes128",
  "created_at": 1716566400,
  "expires_at": 1716566700,
  "rotation_seconds": 300,
  "revoked": false,
  "revoked_at": null,
  "revoked_reason": null
}
```

Note: The actual key material is **never stored** in DynamoDB. It is always derived on-the-fly using HKDF. The `ContentKeys` table stores metadata for auditing, revocation, and expiry tracking.

#### Global Secondary Indexes

| Index Name | PK | SK | Purpose |
|-----------|-----|-----|---------|
| `ByAssetCreatedAt` | `asset_id` (S) | `created_at` (N) | List all key rotations for an asset |
| `ByTenantCreatedAt` | `tenant_id` (S) | `created_at` (N) | Admin audit: all keys for a tenant |

```python
TableDef(
    _resolve_table_name(S.content_keys_table_name, "ContentKeys"),
    "key_id",
    gsi=[
        {"index_name": "ByAssetCreatedAt", "partition_key": "asset_id", "sort_key": "created_at"},
        {"index_name": "ByTenantCreatedAt", "partition_key": "tenant_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

### 3.4 Key Server Endpoint

**Path**: `GET /drm/hls-key`

**Query parameters:**
- `asset_id` (required) -- The video asset ID.
- `tenant_id` (required) -- The tenant ID.
- `token` (required) -- A valid playback entitlement token.

**Response:**
- `200 OK` with `Content-Type: application/octet-stream` -- 16 raw bytes (the AES-128 key).
- `401 Unauthorized` -- Token invalid, expired, or revoked.
- `403 Forbidden` -- Token valid but asset_id/tenant_id mismatch.
- `404 Not Found` -- Key ID revoked or not found.

**Implementation logic:**
1. Validate `token` via `validate_playback_entitlement(token=token, expected_audience="hls-key")`.
2. Extract `tenant_id` and `asset_id` from validated claims.
3. Verify the query `asset_id` and `tenant_id` match the token claims.
4. Compute `key_slot = now // S.drm_key_rotation_seconds`.
5. Compute `key_id` using `DrmKeyRotationController.key_id_for(...)`.
6. Check `ContentKeys` table for revocation (optional -- fail-open if record absent since keys are derived, not stored).
7. Derive key via `derive_content_key(...)`.
8. Return raw 16 bytes.

**CORS and caching**: The endpoint must set `Access-Control-Allow-Origin: *` (HLS players make cross-origin requests for keys). Set `Cache-Control: no-store` to prevent key caching in CDN/browser cache.

### 3.5 FFmpeg Encryption Integration

FFmpeg supports AES-128 HLS encryption natively via the `-hls_key_info_file` option. The key info file format is:

```
<key_uri>
<key_file_path>
<IV (optional, hex)>
```

Where:
- `key_uri` is the URL embedded in the `#EXT-X-KEY` tag in the playlist (the key server URL).
- `key_file_path` is the local filesystem path to the 16-byte key file (used by FFmpeg during encoding).
- `IV` is an optional 128-bit initialization vector in hex (if omitted, segment sequence number is used).

**Modified `build_rendition_ffmpeg_args`** will:
1. Accept an optional `encryption_config: HlsEncryptionConfig | None` parameter.
2. If encryption is enabled:
   a. Write the 16-byte derived key to a temp file.
   b. Write the key info file referencing the key server URL.
   c. Add `-hls_key_info_file <path>` to the FFmpeg args.
   d. Change segment extension to `.ts` (already the default).

```python
@dataclass(frozen=True)
class HlsEncryptionConfig:
    key_server_url: str    # e.g., "https://app.example/drm/hls-key?asset_id=...&tenant_id=..."
    key_bytes: bytes       # 16-byte AES key (derived via HKDF)
    iv_hex: str | None     # If None, uses segment sequence number
    key_rotation_period: int  # segments between key rotation (0 = no rotation during encode)
```

**Manifest output** (generated by FFmpeg with encryption enabled):
```m3u8
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-KEY:METHOD=AES-128,URI="https://app.example/drm/hls-key?asset_id=v_abc&tenant_id=t_xyz&token=PLACEHOLDER",IV=0x00000000000000000000000000000001
#EXTINF:2.000,
seg_00001.ts
#EXTINF:2.000,
seg_00002.ts
```

The `token=PLACEHOLDER` in the key URI is intentional. The actual playback system rewrites this placeholder with the viewer's current entitlement token at manifest-serve time. This is handled by the manifest proxy/rewrite layer (out of scope for this ticket but noted for integration).

### 3.6 Key Rotation During Packaging

For VOD content (non-live), key rotation during initial packaging is optional. The primary use case is:

1. **Single key per encode session** (default for VOD): One key per asset per encode. The key URL is the same for all segments. Rotation happens at the entitlement level -- when `drm_key_rotation_seconds` elapses, the key server can be configured to refuse serving the old key, forcing a new entitlement acquisition.

2. **Periodic key rotation during encode** (advanced): FFmpeg's `-hls_enc_key_url` combined with `key_rotate_period` changes the key every N segments. This embeds multiple `#EXT-X-KEY` tags in the playlist. For Phase 1, this is configurable but defaults to off (single key per asset).

### 3.7 Widevine / FairPlay (Phase 2 Architecture)

Phase 2 extends the encryption layer to CENC using Shaka Packager:

1. The `shaka_packager_config()` in `app/services/local_packaging.py` will add encryption flags:
   ```json
   {
     "encryption": {
       "scheme": "cenc",
       "key_id": "<hex>",
       "key": "<hex>",
       "pssh": "<base64>",
       "iv": "<hex>"
     }
   }
   ```

2. License acquisition uses the existing `DrmLicenseRequest` / `DrmLicenseResponse` flow via `app/services/drm_license_service.py`.

3. The manifest (DASH MPD or HLS with EXT-X-SESSION-KEY) will contain:
   - Widevine PSSH box (for Chrome/Android).
   - FairPlay `#EXT-X-KEY:METHOD=SAMPLE-AES,KEYFORMAT="com.apple.streamingkeydelivery"` (for Safari/iOS).
   - PlayReady header in MPD (for Edge/Xbox).

4. The key server at `/drm/license` will proxy to the production DRM provider (`drm_provider_license_endpoint`) or return mock clear-key licenses in dev mode (as `drm_mock_license.py` already does).

Phase 2 requires no changes to the key derivation or storage model -- the same `ContentKeys` table and HKDF scheme are used, with `drm_profile` set to `widevine`/`fairplay` instead of `aes128`.

### 3.8 Content Key Storage in DynamoDB

The `ContentKeys` table serves three purposes:

1. **Revocation**: If a key is compromised, an admin sets `revoked=true`. The key server checks this before serving derived keys.
2. **Audit trail**: Every key rotation creates a new record, providing a history of which keys were active for an asset at what time.
3. **Key lifecycle management**: TTL-based expiry (`ttl_epoch`) auto-deletes old key records after `retention_days`.

**Write path** (at packaging time):
```python
def register_content_key(
    *,
    tenant_id: str,
    asset_id: str,
    key_slot: int,
    rotation_seconds: int,
    drm_profile: str = "aes128",
) -> str:
    key_id = _compute_key_id(tenant_id, asset_id, drm_profile, key_slot)
    now = now_ts()
    T.content_keys.put_item(
        Item={
            "key_id": key_id,
            "tenant_id": tenant_id,
            "asset_id": asset_id,
            "key_slot": key_slot,
            "drm_profile": drm_profile,
            "created_at": now,
            "expires_at": now + rotation_seconds,
            "rotation_seconds": rotation_seconds,
            "revoked": False,
            "ttl_epoch": now + (90 * 86400),  # 90-day retention
        },
        ConditionExpression="attribute_not_exists(key_id)",
    )
    return key_id
```

**Read path** (at key-serve time):
```python
def check_key_revocation(key_id: str) -> bool:
    resp = T.content_keys.get_item(Key={"key_id": key_id})
    item = resp.get("Item")
    if not item:
        return False  # No record = not revoked (key is derivable)
    return bool(item.get("revoked", False))
```

---

## 4. Implementation Plan

### 4.1 Phase 1 — AES-128 HLS Encryption

#### Step 1: Settings and Table Definition

**File: `app/core/settings.py`** -- Add after line 358 (after existing `drm_key_rotation_salt`):

```python
# VOD content encryption (VOD-010)
content_keys_table_name: str = os.environ.get("DDB_CONTENT_KEYS", "ContentKeys")
drm_hls_aes128_enabled: bool = os.environ.get("DRM_HLS_AES128_ENABLED", "1") not in ("0", "false", "False")
drm_hls_key_server_base_url: str = os.environ.get("DRM_HLS_KEY_SERVER_BASE_URL", "http://localhost:8000")
drm_content_key_retention_days: int = int(os.environ.get("DRM_CONTENT_KEY_RETENTION_DAYS", "90"))
```

**File: `scripts/local-ddb-init.py`** -- Add new `TableDef`:

```python
# Content encryption keys (VOD-010)
TableDef(
    _resolve_table_name(S.content_keys_table_name, "ContentKeys"),
    "key_id",
    gsi=[
        {"index_name": "ByAssetCreatedAt", "partition_key": "asset_id", "sort_key": "created_at"},
        {"index_name": "ByTenantCreatedAt", "partition_key": "tenant_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

**File: `app/core/tables.py`** -- Add `content_keys` field to `Tables` dataclass and `T` constructor.

#### Step 2: Key Derivation Service

**New file: `app/services/content_key_derivation.py`**

Functions:
- `derive_content_key(*, tenant_id, asset_id, key_slot, root_secret) -> bytes` -- HKDF-SHA256, returns 16 bytes.
- `compute_key_id(*, tenant_id, asset_id, drm_profile, key_slot, salt) -> str` -- SHA-256-based key ID (32 hex chars).
- `current_key_slot(*, now_epoch, rotation_seconds) -> int` -- Integer division of epoch by rotation period.

Dependencies: `hashlib`, `hmac` (stdlib only -- no external crypto libraries needed for HKDF with SHA-256).

#### Step 3: Content Key Store

**New file: `app/services/content_key_store.py`**

Functions:
- `register_content_key(*, tenant_id, asset_id, key_slot, rotation_seconds, drm_profile) -> str` -- Writes metadata to DynamoDB, returns key_id.
- `check_key_revocation(key_id: str) -> bool` -- Returns True if key is revoked.
- `revoke_content_key(*, key_id, reason, actor) -> None` -- Sets `revoked=True`, `revoked_at`, `revoked_reason`.
- `list_keys_for_asset(asset_id: str, *, limit=50, cursor=None) -> dict` -- Query ByAssetCreatedAt GSI.
- `list_keys_for_tenant(tenant_id: str, *, limit=50, cursor=None) -> dict` -- Query ByTenantCreatedAt GSI.

#### Step 4: HLS Key Server Router

**New file: `app/routers/drm_key_server.py`**

Endpoints:
- `GET /drm/hls-key` -- Serve AES-128 content key (validates entitlement token).
- `POST /drm/keys/revoke` -- Admin endpoint to revoke a key (requires `require_admin_session`).
- `GET /drm/keys/{asset_id}` -- Admin endpoint to list key history (requires `require_admin_session`).

Register in `app/main.py`:
```python
from app.routers.drm_key_server import drm_key_server_router
app.include_router(drm_key_server_router)
```

#### Step 5: FFmpeg Pipeline Encryption Integration

**File: `app/services/ffmpeg_abr_pipeline.py`** -- Modify `build_rendition_ffmpeg_args`:

Add optional parameter `encryption_config: HlsEncryptionConfig | None = None`. When provided:
1. Write key bytes to `<output_dir>/<name>/enc.key` (temp file).
2. Write key info file to `<output_dir>/<name>/enc.keyinfo`:
   ```
   <key_server_url>&key_id=<key_id>
   <output_dir>/<name>/enc.key
   <iv_hex or empty>
   ```
3. Append to ffmpeg args: `"-hls_key_info_file", str(keyinfo_path)`.
4. Remove `delete_segments` from `hls_flags` (encrypted VOD segments must persist).

**New file: `app/services/vod_encryption_orchestrator.py`**

Functions:
- `prepare_encryption_for_rendition(*, tenant_id, asset_id, rendition_name, output_dir) -> HlsEncryptionConfig | None` -- Checks if DRM is enabled for this asset, derives key, writes temp files, returns config.
- `finalize_encryption_metadata(*, tenant_id, asset_id, key_slot) -> None` -- Registers key in ContentKeys table after successful encode.

#### Step 6: Manifest Token Injection

**New file: `app/services/manifest_rewrite.py`**

Functions:
- `rewrite_manifest_key_uri(manifest_text: str, *, entitlement_token: str) -> str` -- Replaces `token=PLACEHOLDER` in `#EXT-X-KEY` URIs with the viewer's actual token.
- `inject_key_tag_if_missing(manifest_text: str, *, key_server_url: str, key_id: str) -> str` -- For manifests without `#EXT-X-KEY` (e.g., pre-existing unencrypted), injects the tag.

This runs at manifest-serve time in the playback endpoint (or CDN edge function).

#### Step 7: Environment Variables

Add to `.env.local.example`:
```bash
# VOD DRM encryption (VOD-010)
DDB_CONTENT_KEYS=ContentKeys
DRM_HLS_AES128_ENABLED=true
DRM_HLS_KEY_SERVER_BASE_URL=http://localhost:8000
DRM_CONTENT_KEY_RETENTION_DAYS=90
DRM_KEY_ROTATION_SALT=dev-vod-drm-rotation-salt-change-in-prod
```

### 4.2 File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/core/settings.py` | Modify | Add `content_keys_table_name`, `drm_hls_aes128_enabled`, `drm_hls_key_server_base_url`, `drm_content_key_retention_days` |
| `app/core/tables.py` | Modify | Add `content_keys` field |
| `scripts/local-ddb-init.py` | Modify | Add `ContentKeys` TableDef with 2 GSIs |
| `app/services/content_key_derivation.py` | New | HKDF key derivation, key ID computation, slot calculation |
| `app/services/content_key_store.py` | New | DynamoDB CRUD for key metadata + revocation |
| `app/routers/drm_key_server.py` | New | HLS key server endpoint + admin key management |
| `app/services/ffmpeg_abr_pipeline.py` | Modify | Add `encryption_config` parameter, key info file generation |
| `app/services/vod_encryption_orchestrator.py` | New | Orchestration: derive key, write temp files, register metadata |
| `app/services/manifest_rewrite.py` | New | Token injection into `#EXT-X-KEY` URIs at serve time |
| `app/services/local_packaging.py` | Modify | Add encryption section to `shaka_packager_config()` for Phase 2 prep |
| `app/main.py` | Modify | Register `drm_key_server_router` |
| `.env.local.example` | Modify | Add VOD-010 env vars |

### 4.3 Dependencies

| Dependency | Required By | Notes |
|-----------|-------------|-------|
| VOD-001 (Video Metadata) | `drm_policy_id` on video record | Must exist to flag per-video DRM |
| VOD-005 (Transcoding) | Encoding pipeline invokes encryption orchestrator | Must be able to call `prepare_encryption_for_rendition` |
| Playback entitlements | Token validation in key server | Already implemented |
| KMS mock (port 7999) | Optional -- only if using KMS to wrap root secret | Already running in dev stack |
| `DRM_KEY_ROTATION_SALT` | Key derivation | Must be set in `.env.local` (already present but may be empty) |

---

## 5. Testing Strategy

### 5.1 Unit Tests: Key Derivation (`tests/test_content_key_derivation.py`)

| Test | What it validates |
|------|-------------------|
| `test_derive_content_key_returns_16_bytes` | Output is exactly 16 bytes for AES-128. |
| `test_derive_same_inputs_same_output` | Deterministic: same inputs produce same key. |
| `test_different_asset_different_key` | Different `asset_id` produces different key. |
| `test_different_tenant_different_key` | Different `tenant_id` produces different key. |
| `test_different_slot_different_key` | Different `key_slot` produces different key (rotation works). |
| `test_key_id_is_32_hex_chars` | `compute_key_id` returns 32-character hex string. |
| `test_key_id_deterministic` | Same inputs produce same key ID. |
| `test_current_key_slot_floor_division` | `current_key_slot(now_epoch=600, rotation_seconds=300)` returns 2. |
| `test_current_key_slot_minimum_rotation` | Rotation seconds below 60 are clamped to 60. |

### 5.2 Unit Tests: Content Key Store (`tests/test_content_key_store.py`)

Follow the `_FakeTable` pattern from `tests/test_broadcast_store.py`:

| Test | What it validates |
|------|-------------------|
| `test_register_key_creates_record` | Record with correct fields appears in table. |
| `test_register_key_idempotent` | Second call with same key_id does not overwrite (ConditionExpression). |
| `test_check_revocation_false_when_no_record` | Missing key = not revoked (fail-open). |
| `test_check_revocation_false_when_not_revoked` | Record exists with `revoked=False`. |
| `test_check_revocation_true_when_revoked` | Record exists with `revoked=True`. |
| `test_revoke_key_sets_fields` | After revoke, `revoked=True`, `revoked_at` set, `revoked_reason` stored. |
| `test_list_keys_for_asset_pagination` | Insert 5 keys, list with limit=2, cursor returned. |
| `test_list_keys_for_tenant` | Keys filtered by tenant_id via GSI. |

### 5.3 Unit Tests: Key Server Endpoint (`tests/test_drm_key_server.py`)

Using FastAPI TestClient with mocked entitlement validation:

| Test | What it validates |
|------|-------------------|
| `test_hls_key_valid_token_returns_16_bytes` | 200 response, Content-Type octet-stream, body is 16 bytes. |
| `test_hls_key_expired_token_returns_401` | Expired entitlement token returns 401. |
| `test_hls_key_invalid_signature_returns_401` | Tampered token returns 401. |
| `test_hls_key_asset_mismatch_returns_403` | Token for asset A, query for asset B returns 403. |
| `test_hls_key_revoked_key_returns_404` | Key marked revoked in DDB returns 404. |
| `test_hls_key_missing_params_returns_422` | Missing `asset_id` or `tenant_id` returns 422. |
| `test_hls_key_cors_headers` | Response includes `Access-Control-Allow-Origin: *`. |
| `test_hls_key_no_cache_headers` | Response includes `Cache-Control: no-store`. |
| `test_admin_revoke_requires_admin_session` | Regular user POST to revoke returns 403. |
| `test_admin_revoke_marks_key_revoked` | Admin POST to revoke sets `revoked=True`. |

### 5.4 Unit Tests: FFmpeg Encryption Args (`tests/test_ffmpeg_abr_pipeline_encryption.py`)

| Test | What it validates |
|------|-------------------|
| `test_build_args_without_encryption_no_key_info` | Default behavior unchanged when no encryption_config. |
| `test_build_args_with_encryption_adds_key_info_file` | `-hls_key_info_file` present in args. |
| `test_key_info_file_format` | Written file has 3 lines: URI, key path, IV. |
| `test_key_file_written_16_bytes` | Temp key file contains exactly 16 bytes. |
| `test_hls_flags_no_delete_segments_when_encrypted` | `delete_segments` removed from `-hls_flags` for VOD. |

### 5.5 Unit Tests: Key Rotation (`tests/test_content_key_rotation.py`)

| Test | What it validates |
|------|-------------------|
| `test_rotation_changes_key_at_boundary` | Key at t=299 differs from key at t=300 (with rotation_seconds=300). |
| `test_rotation_stable_within_slot` | Key at t=0 equals key at t=299. |
| `test_rotation_disabled_always_same_slot` | When `drm_key_rotation_enabled=False`, slot is always 0. |
| `test_key_id_changes_with_slot` | `compute_key_id` returns different values for different slots. |
| `test_key_derivation_uses_correct_slot` | End-to-end: orchestrator derives correct key for current time. |

### 5.6 Integration Tests (pytest with moto DynamoDB)

| Test | What it validates |
|------|-------------------|
| `test_full_key_lifecycle` | Register key, check not revoked, revoke, check revoked. |
| `test_key_server_endpoint_integration` | Issue entitlement, call `/drm/hls-key`, verify 16-byte response. |
| `test_key_server_revoked_integration` | Register + revoke key, then call endpoint, verify 404. |
| `test_manifest_rewrite_injects_token` | Input manifest with PLACEHOLDER, output has real token. |

### 5.7 E2E Tests: `frontend/e2e/drm-encryption.spec.ts`

Using the existing `injectAuth` + `page.request` pattern:

**Section 110: DRM Key Server API**

| Test | What it validates |
|------|-------------------|
| `110.1 Issue entitlement and fetch HLS key` | End-to-end: issue token via `/v1/playback/entitlements/issue`, then GET `/drm/hls-key?asset_id=...&tenant_id=...&token=...`, verify 200 + 16-byte binary response. |
| `110.2 Fetch key with expired token returns 401` | Use token with `ttl_seconds=1`, wait 2s, verify 401. |
| `110.3 Fetch key with wrong asset_id returns 403` | Token for `asset_A`, request for `asset_B`, verify 403. |
| `110.4 Fetch key with invalid token returns 401` | Garbage token string, verify 401. |
| `110.5 Key rotation produces different keys` | Issue two tokens 301s apart (mocked time), fetch keys, verify different 16-byte values. |
| `110.6 Revoke key then fetch returns 404` | Admin revokes key via POST, subsequent fetch returns 404. |
| `110.7 Admin list keys for asset` | Register keys, GET `/drm/keys/{asset_id}` as admin, verify list. |

**Section 111: Encrypted Playback Integration**

| Test | What it validates |
|------|-------------------|
| `111.1 Encrypted manifest contains EXT-X-KEY tag` | Upload video with DRM enabled, wait for processing, fetch manifest, verify `#EXT-X-KEY:METHOD=AES-128` present. |
| `111.2 Key URI in manifest resolves to valid key` | Extract URI from manifest, fetch it with entitlement token, verify 200. |
| `111.3 Unencrypted video has no EXT-X-KEY tag` | Upload video without DRM, verify manifest has no encryption tag. |
| `111.4 Encrypted segments are not cleartext` | Fetch a `.ts` segment, verify first bytes are NOT the MPEG-TS sync byte `0x47` (encrypted data appears random). |

### 5.8 Test Data Considerations

- **Entitlement secret**: Tests require `PLAYBACK_ENTITLEMENT_SECRET` to be set (already present in `.env.local` per `playback-entitlements.spec.ts`).
- **Rotation salt**: Tests should use a fixed `DRM_KEY_ROTATION_SALT` (e.g., `"test-rotation-salt"`) to make key derivation deterministic.
- **Time mocking**: Key rotation tests use `now_epoch` parameter (already supported by entitlement functions) rather than real clock.
- **Unique asset IDs per run**: Use `f"asset_{Date.now()}"` pattern to avoid conflicts across test runs.
- **Binary response handling in Playwright**: Use `response.body()` to get raw bytes; verify `body.length === 16`.

---

## Appendix A: Security Considerations

1. **Root secret management**: `DRM_KEY_ROTATION_SALT` must be at least 32 bytes of high-entropy data in production. In dev mode, the default `"dev-vod-drm-rotation-salt-change-in-prod"` is acceptable.

2. **Key server rate limiting**: The `/drm/hls-key` endpoint should be rate-limited per IP and per session to prevent key-scraping attacks. Apply the existing `admin_action_max_per_window` pattern.

3. **Token audience separation**: HLS key requests use `audience="hls-key"` (not the same `"playback"` audience used for manifest access). This prevents a manifest-access token from being reused to fetch keys if audiences are ever separated.

4. **No key caching at CDN**: The key endpoint MUST NOT be cached by CDN (Cache-Control: no-store, no-cache). Keys are short-lived by design.

5. **IV selection**: Using segment sequence number as IV (the HLS default) is acceptable for AES-128-CBC since each segment has a unique sequence number. Explicit random IVs provide slightly better security but complicate the implementation without material benefit for VOD.

6. **Key material never logged**: The `derive_content_key` function must never log or emit the derived key bytes. Only the key_id (hash) should appear in logs.

---

## Appendix B: Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `DDB_CONTENT_KEYS` | `ContentKeys` | DynamoDB table name for key metadata |
| `DRM_HLS_AES128_ENABLED` | `true` | Master switch for AES-128 HLS encryption |
| `DRM_HLS_KEY_SERVER_BASE_URL` | `http://localhost:8000` | Base URL for key server (used in manifest URIs) |
| `DRM_CONTENT_KEY_RETENTION_DAYS` | `90` | Days before key records are TTL-deleted |
| `DRM_KEY_ROTATION_ENABLED` | `true` | Enable periodic key rotation |
| `DRM_KEY_ROTATION_SECONDS` | `300` | Rotation interval (minimum 60) |
| `DRM_KEY_ROTATION_SALT` | `""` | Root secret for HKDF derivation (MUST be set) |
| `DRM_LICENSE_PROVIDER_MODE` | `mock` | `mock` or `production` |
| `PLAYBACK_ENTITLEMENT_SECRET` | `""` | HMAC secret for entitlement tokens |
