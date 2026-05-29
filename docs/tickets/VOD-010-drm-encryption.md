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

## 2. Architecture Diagram

### 2.1 End-to-End Encryption Flow (Packaging Time)

```
+------------------+     +-------------------------+     +------------------+
|  Transcode Worker|     | VOD Encryption          |     | Content Key      |
|  (VOD-003/004)   |     | Orchestrator            |     | Derivation       |
|                  |     | (vod_encryption_         |     | (content_key_    |
|                  |     |  orchestrator.py)        |     |  derivation.py)  |
+--------+---------+     +------------+------------+     +--------+---------+
         |                            |                           |
  1. Job has                   2. Check DRM policy          3. HKDF-SHA256
     drm_policy_id                 on video record              derive key
         |                            |                           |
         v                            v                           v
+--------+---------+     +------------+------------+     +--------+---------+
|  FFmpeg ABR      |     | Write key bytes to      |     | Return 16-byte   |
|  Pipeline        |<----| temp file + generate    |     | AES-128 CEK      |
|  (ffmpeg_abr_    |     | key info file           |     +------------------+
|   pipeline.py)   |     +------------+------------+
+--------+---------+                  |
         |                     4. Register key metadata
  5. -hls_key_info_file               |
     encrypts segments                v
         |               +------------+------------+
         v               | Content Key Store       |
+--------+---------+     | (content_key_store.py)  |
| Encrypted .ts    |     | -> DynamoDB ContentKeys |
| segments + m3u8  |     +-------------------------+
| with #EXT-X-KEY  |
+--------+---------+
         |
  6. Upload to S3
         |
         v
+--------+---------+
| S3 Bucket        |
| /hls/{asset}/    |
|   master.m3u8    |
|   720p/index.m3u8|
|   720p/seg_*.ts  |  <- encrypted
+------------------+
```

### 2.2 Playback-Time Key Fetch Flow

```
+-------------------+
| Video Player      |
| (HLS.js / Safari) |
+--------+----------+
         |
  1. GET master.m3u8
     with entitlement
     token
         |
         v
+--------+----------+     +---------------------------+
| CDN / S3 Origin   |     | Manifest Rewrite Layer    |
|                   |---->| (manifest_rewrite.py)     |
|                   |     | Replace token=PLACEHOLDER |
|                   |     | with viewer's real token  |
+-------------------+     +-------------+-------------+
                                        |
                          2. Rewritten manifest
                             returned to player
                                        |
                                        v
                          +-------------+-------------+
                          | Player parses #EXT-X-KEY  |
                          | URI contains token param  |
                          +-------------+-------------+
                                        |
                          3. GET /drm/hls-key
                             ?asset_id=...
                             &tenant_id=...
                             &token=<entitlement_jwt>
                                        |
                                        v
                          +-------------+-------------+
                          | Key Server Router         |
                          | (drm_key_server.py)       |
                          +-------------+-------------+
                                        |
                    +-------------------+-------------------+
                    |                   |                   |
             4. Validate          5. Check             6. Derive key
                entitlement          revocation            via HKDF
                token                (DynamoDB)
                    |                   |                   |
                    v                   v                   v
             +-----+-----+    +--------+------+    +------+-------+
             | Playback   |    | ContentKeys  |    | Content Key  |
             | Entitle-   |    | Table        |    | Derivation   |
             | ments      |    | (check       |    | (HKDF-SHA256)|
             | (validate) |    |  revoked)    |    | -> 16 bytes  |
             +-----+------+    +--------+-----+    +------+-------+
                   |                    |                  |
                   +--------------------+------------------+
                                        |
                          7. Return 16 raw bytes
                             Content-Type: application/octet-stream
                             Cache-Control: no-store
                                        |
                                        v
                          +-------------+-------------+
                          | Player decrypts segments  |
                          | using AES-128-CBC         |
                          +---------------------------+
```

### 2.3 Admin Key Management Flow

```
Admin UI / CLI
      |
      v
POST /drm/keys/revoke  (requires admin session)
      |
      v
+-----+--------+       +--------------------+
| Key Server   |------>| ContentKeys Table   |
| Router       |       | Set revoked=true    |
| (admin       |       | Set revoked_at      |
|  endpoints)  |       | Set revoked_reason  |
+--------------+       +---------+----------+
                                 |
                       Subsequent key fetch
                       for this key_id
                       returns 404
                                 |
                                 v
                       Player fails to
                       decrypt -> shows
                       "Content unavailable"
```

### 2.4 Phase 2 CENC Architecture (Future)

```
+-------------------+      +------------------+      +-------------------+
| Shaka Packager    |      | DRM License      |      | External DRM      |
| (local_packaging) |      | Service          |      | Provider          |
|                   |      | (drm_license_    |      | (Widevine/        |
| CENC encryption   |      |  service.py)     |      |  FairPlay/        |
| with PSSH boxes   |      |                  |      |  PlayReady)       |
+--------+----------+      +--------+---------+      +--------+----------+
         |                          |                          |
         | Same HKDF key           | Routes between           | Challenge-
         | derivation              | mock & production        | response
         |                         |                          | protocol
         v                         v                          v
+--------+----------+     +--------+---------+      +--------+----------+
| ContentKeys Table |     | /drm/license     |      | License server    |
| drm_profile=      |     | endpoint         |<---->| (cloud-hosted)    |
| "widevine" etc.   |     | (proxy or mock)  |      |                   |
+-------------------+     +------------------+      +-------------------+
```

---

## 3. Current State Analysis

### 3.1 Existing Crypto Infrastructure

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

### 3.2 Playback Entitlements System

**`app/services/playback_entitlements.py`** implements a self-contained HS256 JWT system for playback authorization:

- `issue_playback_entitlement(...)` -- Issues a signed token containing `tenant_id`, `asset_id`, `session_id`, `device_id`, `profile`, `aud`, `iat`, `exp`, `jti`. Signed with `S.playback_entitlement_secret`.
- `validate_playback_entitlement(*, token, expected_audience)` -- Verifies signature, expiry, audience, claim lengths, replay protection, and revocation.
- `revoke_playback_entitlement(...)` -- Revokes by JTI or session ID.

The entitlement token already contains `asset_id` and `tenant_id`, which are exactly the parameters needed to derive the content encryption key. The key server endpoint will validate the entitlement token and, if valid, derive and return the AES-128 key for the requested asset.

### 3.3 DRM Entitlement Contract

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

### 3.4 FFmpeg HLS Output Format

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

### 3.5 Video Pipeline Contract

**`app/contracts/video_pipeline_contract.py`**:
- `DrmPolicy` model: `profile` (none/widevine/fairplay/playready/multi_drm), `key_rotation_seconds`, `per_content_key`, `offline_allowed`.
- `VideoPipelineJobRequest` includes a `drm: DrmPolicy` field.
- This contract is validated by `app/services/video_pipeline_contract_service.py`.

### 3.6 Broadcast Local DRM (Existing Pattern)

**`app/services/broadcast_local_drm.py`** implements AES-128 key management for live broadcasts:
- Keys are 16-byte random values stored on disk at `<key_root>/<stream_key>.key`.
- Token-gated access: `load_local_drm_key(stream_key, token)` validates a signed token before serving the key.
- FFmpeg in broadcast mode uses `-hls_key_info_file` pointing to a key info file that references the key server URL.

This pattern will be extended for VOD, replacing filesystem key storage with KMS-derived keys stored in DynamoDB.

---

## 4. Technical Design

### 4.1 Content Key Derivation

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

### 4.2 DynamoDB Key Metadata Table

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

### 4.3 Key Server Endpoint

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

### 4.4 FFmpeg Encryption Integration

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

### 4.5 Key Rotation During Packaging

For VOD content (non-live), key rotation during initial packaging is optional. The primary use case is:

1. **Single key per encode session** (default for VOD): One key per asset per encode. The key URL is the same for all segments. Rotation happens at the entitlement level -- when `drm_key_rotation_seconds` elapses, the key server can be configured to refuse serving the old key, forcing a new entitlement acquisition.

2. **Periodic key rotation during encode** (advanced): FFmpeg's `-hls_enc_key_url` combined with `key_rotate_period` changes the key every N segments. This embeds multiple `#EXT-X-KEY` tags in the playlist. For Phase 1, this is configurable but defaults to off (single key per asset).

### 4.6 Widevine / FairPlay (Phase 2 Architecture)

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

### 4.7 Content Key Storage in DynamoDB

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

## 5. DynamoDB Access Patterns

### 5.1 Access Patterns Table

| # | Operation | Table | PK | SK / GSI | Latency | Called By |
|---|-----------|-------|----|----------|---------|-----------|
| 1 | Register key at packaging time | ContentKeys | `key_id` (S) | -- (put_item, ConditionExpression) | <5ms | `content_key_store.register_content_key()` |
| 2 | Check key revocation at serve time | ContentKeys | `key_id` (S) | -- (get_item) | <5ms | `content_key_store.check_key_revocation()` |
| 3 | Revoke a key (admin action) | ContentKeys | `key_id` (S) | -- (update_item) | <5ms | `content_key_store.revoke_content_key()` |
| 4 | List all keys for an asset | ContentKeys | -- | GSI `ByAssetCreatedAt` PK=`asset_id`, SK=`created_at` (N) | <10ms | `content_key_store.list_keys_for_asset()` |
| 5 | List all keys for a tenant (admin audit) | ContentKeys | -- | GSI `ByTenantCreatedAt` PK=`tenant_id`, SK=`created_at` (N) | <10ms | `content_key_store.list_keys_for_tenant()` |
| 6 | Bulk revoke keys for an asset | ContentKeys | -- | GSI `ByAssetCreatedAt` (query), then batch update_item | <50ms | `content_key_store.revoke_all_keys_for_asset()` |
| 7 | TTL auto-delete expired records | ContentKeys | `key_id` (S) | -- (DynamoDB TTL on `ttl_epoch`) | N/A (async) | DynamoDB TTL service |
| 8 | Get video DRM policy | Videos | `video_id` (S) | -- (get_item, ProjectionExpression) | <5ms | `vod_encryption_orchestrator.prepare_encryption_for_rendition()` |

### 5.2 Example DynamoDB Items

**Newly registered content key (at packaging time):**
```json
{
  "key_id": {"S": "a3f8c12b9e0d4567abcd1234ef567890"},
  "tenant_id": {"S": "tenant-a"},
  "asset_id": {"S": "v_8a3b1f0e2c4d"},
  "key_slot": {"N": "5722188"},
  "drm_profile": {"S": "aes128"},
  "created_at": {"N": "1716656400"},
  "expires_at": {"N": "1716656700"},
  "rotation_seconds": {"N": "300"},
  "revoked": {"BOOL": false},
  "ttl_epoch": {"N": "1724432400"}
}
```

**Revoked content key (admin action):**
```json
{
  "key_id": {"S": "b4g9d23c0f1e5678bcde2345fg678901"},
  "tenant_id": {"S": "tenant-a"},
  "asset_id": {"S": "v_9b4c2g1f3d5e"},
  "key_slot": {"N": "5722187"},
  "drm_profile": {"S": "aes128"},
  "created_at": {"N": "1716656100"},
  "expires_at": {"N": "1716656400"},
  "rotation_seconds": {"N": "300"},
  "revoked": {"BOOL": true},
  "revoked_at": {"N": "1716660000"},
  "revoked_reason": {"S": "Key compromised - unauthorized redistribution detected"},
  "revoked_by": {"S": "root.admin@testdev.local"},
  "ttl_epoch": {"N": "1724432100"}
}
```

**Phase 2 Widevine key (future):**
```json
{
  "key_id": {"S": "c5h0e34d1g2f6789cdef3456gh789012"},
  "tenant_id": {"S": "tenant-b"},
  "asset_id": {"S": "v_3c5d4e2f1g0h"},
  "key_slot": {"N": "5722190"},
  "drm_profile": {"S": "widevine"},
  "created_at": {"N": "1716657000"},
  "expires_at": {"N": "1716657300"},
  "rotation_seconds": {"N": "300"},
  "revoked": {"BOOL": false},
  "pssh_b64": {"S": "AAAAR3Bzc2gAAAAA7e+LqXnWSs6..."},
  "license_server_url": {"S": "https://license.example.com/widevine"},
  "ttl_epoch": {"N": "1724433000"}
}
```

**Expired key (pending TTL deletion):**
```json
{
  "key_id": {"S": "d6i1f45e2h3g7890defg4567hi890123"},
  "tenant_id": {"S": "tenant-a"},
  "asset_id": {"S": "v_1a2b3c4d5e6f"},
  "key_slot": {"N": "5720000"},
  "drm_profile": {"S": "aes128"},
  "created_at": {"N": "1716000000"},
  "expires_at": {"N": "1716000300"},
  "rotation_seconds": {"N": "300"},
  "revoked": {"BOOL": false},
  "ttl_epoch": {"N": "1723776000"}
}
```

---

## 6. API Request/Response Examples

### 6.1 Fetch HLS Key (Player Key Request)

```bash
# HLS player fetches decryption key (extracted from #EXT-X-KEY URI)
curl -s "http://localhost:8000/drm/hls-key?asset_id=v_8a3b1f0e2c4d&tenant_id=tenant-a&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhc3NldF9pZCI6InZfOGEzYjFmMGUyYzRkIiwidGVuYW50X2lkIjoidGVuYW50LWEiLCJhdWQiOiJobHMta2V5IiwiZXhwIjoxNzE2NTcwMDAwfQ.abc123" \
  --output - | xxd
```

Response (200, binary):
```
Content-Type: application/octet-stream
Access-Control-Allow-Origin: *
Cache-Control: no-store, no-cache
Content-Length: 16

00000000: 4a7f 2b8c 91d3 e5f0 a6b4 c8d2 3e1f 0a7b  J.+.........>..{
```

### 6.2 Fetch HLS Key with Expired Token

```bash
curl -s -w "\n%{http_code}" \
  "http://localhost:8000/drm/hls-key?asset_id=v_8a3b1f0e2c4d&tenant_id=tenant-a&token=eyJ_EXPIRED_TOKEN"
```

Response (401):
```json
{
  "detail": "Entitlement token expired"
}
```

### 6.3 Fetch HLS Key with Asset Mismatch

```bash
# Token was issued for asset_id=v_OTHER but requesting key for v_8a3b1f0e2c4d
curl -s -w "\n%{http_code}" \
  "http://localhost:8000/drm/hls-key?asset_id=v_8a3b1f0e2c4d&tenant_id=tenant-a&token=eyJ_TOKEN_FOR_OTHER_ASSET"
```

Response (403):
```json
{
  "detail": "Token asset_id does not match requested asset_id"
}
```

### 6.4 Fetch HLS Key for Revoked Key

```bash
curl -s -w "\n%{http_code}" \
  "http://localhost:8000/drm/hls-key?asset_id=v_9b4c2g1f3d5e&tenant_id=tenant-a&token=eyJ_VALID_TOKEN"
```

Response (404):
```json
{
  "detail": "Content key has been revoked"
}
```

### 6.5 Admin: Revoke a Content Key

```bash
curl -s -X POST http://localhost:8000/drm/keys/revoke \
  -H "Cookie: ui_session=sess_root123; ui_csrf=csrf_root; ui_access_token=eyJhbG_ROOT_JWT..." \
  -H "x-csrf-token: csrf_root" \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "a3f8c12b9e0d4567abcd1234ef567890",
    "reason": "Unauthorized redistribution detected on torrent site"
  }'
```

Response (200):
```json
{
  "ok": true,
  "key_id": "a3f8c12b9e0d4567abcd1234ef567890",
  "revoked_at": 1716660000
}
```

### 6.6 Admin: List Keys for an Asset

```bash
curl -s http://localhost:8000/drm/keys/v_8a3b1f0e2c4d \
  -H "Cookie: ui_session=sess_root123; ui_csrf=csrf_root; ui_access_token=eyJhbG_ROOT_JWT..." \
  -H "Accept: application/json"
```

Response (200):
```json
{
  "keys": [
    {
      "key_id": "a3f8c12b9e0d4567abcd1234ef567890",
      "asset_id": "v_8a3b1f0e2c4d",
      "key_slot": 5722188,
      "drm_profile": "aes128",
      "created_at": 1716656400,
      "expires_at": 1716656700,
      "revoked": false
    },
    {
      "key_id": "e7j2g56f3i4h8901efgh5678ij901234",
      "asset_id": "v_8a3b1f0e2c4d",
      "key_slot": 5722189,
      "drm_profile": "aes128",
      "created_at": 1716656700,
      "expires_at": 1716657000,
      "revoked": false
    }
  ],
  "cursor": null
}
```

### 6.7 Admin: Bulk Revoke All Keys for an Asset

```bash
curl -s -X POST http://localhost:8000/drm/keys/v_8a3b1f0e2c4d/revoke-all \
  -H "Cookie: ui_session=sess_root123; ui_csrf=csrf_root; ui_access_token=eyJhbG_ROOT_JWT..." \
  -H "x-csrf-token: csrf_root" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Video takedown request - DMCA notice received"
  }'
```

Response (200):
```json
{
  "ok": true,
  "asset_id": "v_8a3b1f0e2c4d",
  "keys_revoked": 2,
  "revoked_at": 1716660100
}
```

### 6.8 Issue Playback Entitlement for HLS Key Access

```bash
curl -s -X POST http://localhost:8000/v1/playback/entitlements/issue \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=eyJhbG_ALICE..." \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": "v_8a3b1f0e2c4d",
    "tenant_id": "tenant-a",
    "device_id": "browser_a1b2c3",
    "profile": "hls",
    "audience": "hls-key",
    "ttl_seconds": 3600
  }'
```

Response (200):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhc3NldF9pZCI6InZfOGEzYjFmMGUyYzRkIiwidGVuYW50X2lkIjoidGVuYW50LWEiLCJkZXZpY2VfaWQiOiJicm93c2VyX2ExYjJjMyIsInByb2ZpbGUiOiJobHMiLCJhdWQiOiJobHMta2V5IiwiaWF0IjoxNzE2NjU2NDAwLCJleHAiOjE3MTY2NjAwMDAsImp0aSI6ImVudF84YTNiMWYwZTJjNGQifQ.xyz",
  "expires_at": 1716660000,
  "audience": "hls-key"
}
```

---

## 7. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---------------|-------------|------------|---------------------|-----------------|
| 1 | Missing `asset_id` query param | 422 | `VALIDATION_ERROR` | "asset_id is required" | Fix client request |
| 2 | Missing `tenant_id` query param | 422 | `VALIDATION_ERROR` | "tenant_id is required" | Fix client request |
| 3 | Missing `token` query param | 422 | `VALIDATION_ERROR` | "token is required" | Fix client request |
| 4 | Invalid entitlement token (malformed) | 401 | `INVALID_TOKEN` | "Invalid entitlement token" | Re-issue entitlement |
| 5 | Expired entitlement token | 401 | `TOKEN_EXPIRED` | "Entitlement token expired" | Re-issue entitlement with fresh token |
| 6 | Token signature mismatch (tampered) | 401 | `INVALID_SIGNATURE` | "Token signature verification failed" | Re-issue entitlement from trusted source |
| 7 | Token audience mismatch (not "hls-key") | 401 | `AUDIENCE_MISMATCH` | "Token not valid for key access" | Issue token with audience="hls-key" |
| 8 | Token `asset_id` does not match query | 403 | `ASSET_MISMATCH` | "Token does not grant access to this asset" | Use correct asset_id or re-issue token |
| 9 | Token `tenant_id` does not match query | 403 | `TENANT_MISMATCH` | "Token does not grant access for this tenant" | Use correct tenant_id |
| 10 | Content key revoked | 404 | `KEY_REVOKED` | "Content key has been revoked" | Content is no longer available; contact support |
| 11 | DRM disabled for this video | 400 | `DRM_NOT_ENABLED` | "This video is not DRM-protected" | No key needed; play directly |
| 12 | Root secret not configured | 500 | `INTERNAL_ERROR` | "Key derivation failed" | Set `DRM_KEY_ROTATION_SALT` in environment |
| 13 | DynamoDB error during revocation check | 500 | `INTERNAL_ERROR` | "Key verification failed" | Retry; check DynamoDB health |
| 14 | Admin revoke without admin session | 403 | `FORBIDDEN` | "Admin access required" | Authenticate as admin |
| 15 | Admin revoke with non-existent key_id | 404 | `KEY_NOT_FOUND` | "Key not found" | Verify key_id exists |
| 16 | FFmpeg key info file write failure | 500 (internal) | `IO_ERROR` | N/A (background job) | Check disk space; retry job |
| 17 | HKDF derivation with empty root secret | 500 (internal) | `CONFIG_ERROR` | N/A (background job) | Set `DRM_KEY_ROTATION_SALT` |
| 18 | Key rotation seconds below minimum (60) | 400 | `VALIDATION_ERROR` | "Rotation interval must be >= 60 seconds" | Use rotation_seconds >= 60 |
| 19 | Entitlement token revoked (via JTI) | 401 | `TOKEN_REVOKED` | "Playback entitlement has been revoked" | Re-issue entitlement |
| 20 | CORS preflight failure | -- | -- | Browser blocks key fetch | Verify server sends correct CORS headers |

### 7.1 Error Propagation to Player

When the key server returns an error, the HLS player handles it as follows:

| Key Server Response | HLS.js Behavior | Safari Native Behavior |
|--------------------|-----------------|----------------------|
| 401 | Fires `ERROR` event with `type: NETWORK_ERROR`, `fatal: true` | Shows "An error occurred" overlay |
| 403 | Same as 401 | Same as 401 |
| 404 | Same as 401 | Same as 401 |
| 5xx | Retries 3 times, then fires `ERROR` event | Retries, then shows error |

The VideoPlayer component (VOD-008) should listen for HLS.js `ERROR` events and show a
user-friendly message: "This video is currently unavailable. Please try again later." with
a "Retry" button that re-issues the entitlement token and reloads the player.

---

## 8. Pydantic Models

### 8.1 API Request/Response Models (`app/models.py`)

```python
from pydantic import BaseModel, Field, field_validator
from typing import Optional

class HlsKeyRequest(BaseModel):
    """Query parameters for GET /drm/hls-key.
    Parsed from query string, not request body."""
    asset_id: str = Field(..., min_length=1, max_length=128, description="Video asset ID")
    tenant_id: str = Field(..., min_length=1, max_length=128, description="Tenant ID")
    token: str = Field(..., min_length=10, max_length=4096, description="Playback entitlement JWT")

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": "v_8a3b1f0e2c4d",
                "tenant_id": "tenant-a",
                "token": "eyJhbGciOiJIUzI1NiJ9..."
            }
        }


class KeyRevocationRequest(BaseModel):
    """POST /drm/keys/revoke request body."""
    key_id: str = Field(..., min_length=32, max_length=32, description="32-char hex key ID")
    reason: str = Field(..., min_length=1, max_length=1000, description="Reason for revocation")

    @field_validator("key_id")
    @classmethod
    def key_id_must_be_hex(cls, v: str) -> str:
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("key_id must be a 32-character hex string")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "key_id": "a3f8c12b9e0d4567abcd1234ef567890",
                "reason": "Unauthorized redistribution detected"
            }
        }


class KeyRevocationResponse(BaseModel):
    """POST /drm/keys/revoke response body."""
    ok: bool = True
    key_id: str
    revoked_at: int

    class Config:
        json_schema_extra = {
            "example": {
                "ok": True,
                "key_id": "a3f8c12b9e0d4567abcd1234ef567890",
                "revoked_at": 1716660000
            }
        }


class BulkRevocationRequest(BaseModel):
    """POST /drm/keys/{asset_id}/revoke-all request body."""
    reason: str = Field(..., min_length=1, max_length=1000, description="Reason for bulk revocation")

    class Config:
        json_schema_extra = {
            "example": {
                "reason": "DMCA takedown notice received"
            }
        }


class BulkRevocationResponse(BaseModel):
    """POST /drm/keys/{asset_id}/revoke-all response body."""
    ok: bool = True
    asset_id: str
    keys_revoked: int
    revoked_at: int

    class Config:
        json_schema_extra = {
            "example": {
                "ok": True,
                "asset_id": "v_8a3b1f0e2c4d",
                "keys_revoked": 5,
                "revoked_at": 1716660100
            }
        }


class ContentKeyOut(BaseModel):
    """Single key entry in the key list response."""
    key_id: str
    asset_id: str
    key_slot: int
    drm_profile: str
    created_at: int
    expires_at: int
    revoked: bool
    revoked_at: Optional[int] = None
    revoked_reason: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "key_id": "a3f8c12b9e0d4567abcd1234ef567890",
                "asset_id": "v_8a3b1f0e2c4d",
                "key_slot": 5722188,
                "drm_profile": "aes128",
                "created_at": 1716656400,
                "expires_at": 1716656700,
                "revoked": False,
                "revoked_at": None,
                "revoked_reason": None
            }
        }


class ContentKeyListResponse(BaseModel):
    """GET /drm/keys/{asset_id} response body."""
    keys: list[ContentKeyOut]
    cursor: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "keys": [
                    {
                        "key_id": "a3f8c12b9e0d4567abcd1234ef567890",
                        "asset_id": "v_8a3b1f0e2c4d",
                        "key_slot": 5722188,
                        "drm_profile": "aes128",
                        "created_at": 1716656400,
                        "expires_at": 1716656700,
                        "revoked": False
                    }
                ],
                "cursor": None
            }
        }
```

### 8.2 Internal Service Models (`app/services/content_key_derivation.py`)

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class HlsEncryptionConfig:
    """Configuration passed to FFmpeg pipeline for AES-128 encryption."""
    key_server_url: str
    key_bytes: bytes
    iv_hex: str | None = None
    key_rotation_period: int = 0  # 0 = no rotation during encode

    def __post_init__(self):
        if len(self.key_bytes) != 16:
            raise ValueError(f"key_bytes must be exactly 16 bytes, got {len(self.key_bytes)}")
        if self.key_rotation_period < 0:
            raise ValueError("key_rotation_period must be >= 0")


@dataclass(frozen=True)
class ContentKeyMetadata:
    """Metadata about a registered content key (read from DynamoDB)."""
    key_id: str
    tenant_id: str
    asset_id: str
    key_slot: int
    drm_profile: str
    created_at: int
    expires_at: int
    rotation_seconds: int
    revoked: bool
    revoked_at: int | None = None
    revoked_reason: str | None = None
    revoked_by: str | None = None

    @classmethod
    def from_ddb_item(cls, item: dict) -> "ContentKeyMetadata":
        """Construct from a DynamoDB item dict (Decimal-safe)."""
        return cls(
            key_id=item["key_id"],
            tenant_id=item["tenant_id"],
            asset_id=item["asset_id"],
            key_slot=int(item["key_slot"]),
            drm_profile=item["drm_profile"],
            created_at=int(item["created_at"]),
            expires_at=int(item["expires_at"]),
            rotation_seconds=int(item["rotation_seconds"]),
            revoked=bool(item.get("revoked", False)),
            revoked_at=int(item["revoked_at"]) if item.get("revoked_at") else None,
            revoked_reason=item.get("revoked_reason"),
            revoked_by=item.get("revoked_by"),
        )
```

### 8.3 Updated DRM Contract Models (reference)

The existing models in `app/contracts/drm_entitlement_contract.py` do not need modification
for Phase 1. They are already compatible:

```python
# Already exists -- shown for reference
class DrmEntitlementClaims(BaseModel):
    key_id: str
    key_rotation_seconds: int = 300
    per_content_key: bool = True
    offline_allowed: bool = False

class DrmLicenseRequest(BaseModel):
    profile: str  # "widevine" | "fairplay" | "playready" | "clearkey"
    challenge_b64: str | None = None

class DrmLicenseResponse(BaseModel):
    key_id: str
    license_b64: str
    expires_at_epoch: int
    renewal_url: str | None = None
```

---

## 9. Frontend Component Tree

The DRM encryption layer is primarily backend, but the frontend VideoPlayer page (VOD-008)
interacts with it through the HLS.js key fetch mechanism. The component tree below shows
how DRM state flows through the player UI.

### 9.1 VideoPlayer Component Hierarchy

```
<VideoPlayer>                              (page component, route: /videos/:videoId)
  <PageHeader title="Video Player" />
  <VideoMetadataCard>                      (title, description, status, renditions)
    <Badge variant="drm">DRM Protected</Badge>  {/* shown if drm_policy_id is set */}
  </VideoMetadataCard>
  <HlsPlayerContainer>                    (HLS.js wrapper)
    <video ref={videoRef} />
    <HlsErrorOverlay>                     {/* shown on key fetch failure */}
      <AlertCircle />
      <p>"This video is currently unavailable"</p>
      <Button onClick={retryPlayback}>Retry</Button>
    </HlsErrorOverlay>
    <DrmStatusIndicator>                  {/* subtle lock icon + "Encrypted" tooltip */}
      <Lock className="h-4 w-4" />
    </DrmStatusIndicator>
    <QualitySelector>                     (rendition picker)
      <DropdownMenu>
        <DropdownMenuItem>Auto</DropdownMenuItem>
        <DropdownMenuItem>1080p</DropdownMenuItem>
        <DropdownMenuItem>720p</DropdownMenuItem>
        <DropdownMenuItem>360p</DropdownMenuItem>
      </DropdownMenu>
    </QualitySelector>
  </HlsPlayerContainer>
```

### 9.2 Admin Key Management UI (future)

```
<AdminDrmPanel>                            (admin-only, linked from video detail)
  <Card>
    <CardHeader title="Content Key History" />
    <CardContent>
      <DataTable>                          (list of ContentKeyOut records)
        <columns: key_id, key_slot, drm_profile, created_at, revoked, actions>
        <RowAction: "Revoke" -> confirmDialog -> POST /drm/keys/revoke>
      </DataTable>
      <Button variant="destructive">Revoke All Keys</Button>
    </CardContent>
  </Card>
</AdminDrmPanel>
```

### 9.3 React Query Keys for DRM-Related Data

| Query Key | Endpoint | Stale Time | Used By |
|-----------|----------|------------|---------|
| `["playback-entitlement", assetId]` | `POST /v1/playback/entitlements/issue` | 0 (never cached) | VideoPlayer |
| `["drm-keys", assetId]` | `GET /drm/keys/{assetId}` | 30s | AdminDrmPanel |
| `["video", videoId]` | `GET /ui/videos/{videoId}` | 60s | VideoPlayer, VideoMetadataCard |

### 9.4 HLS.js Configuration for DRM

```typescript
// In HlsPlayerContainer
const hls = new Hls({
  xhrSetup: (xhr, url) => {
    // The key URL already contains the entitlement token as a query parameter
    // (injected by manifest_rewrite.py). No additional headers needed.
    // But we set withCredentials: false to avoid sending cookies to CDN.
    xhr.withCredentials = false;
  },
  // Error recovery for key fetch failures
  fragLoadPolicy: {
    default: {
      maxTimeToFirstByteMs: 10000,
      maxLoadTimeMs: 30000,
      timeoutRetry: { maxNumRetry: 3, retryDelayMs: 1000 },
      errorRetry: { maxNumRetry: 3, retryDelayMs: 1000 },
    },
  },
});
```

---

## 10. Implementation Plan

### 10.1 Phase 1 -- AES-128 HLS Encryption

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
- `POST /drm/keys/{asset_id}/revoke-all` -- Admin endpoint to bulk revoke (requires `require_admin_session`).

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

### 10.2 File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/core/settings.py` | Modify | Add `content_keys_table_name`, `drm_hls_aes128_enabled`, `drm_hls_key_server_base_url`, `drm_content_key_retention_days` |
| `app/core/tables.py` | Modify | Add `content_keys` field |
| `app/models.py` | Modify | Add `HlsKeyRequest`, `KeyRevocationRequest`, `KeyRevocationResponse`, `BulkRevocationRequest`, `BulkRevocationResponse`, `ContentKeyOut`, `ContentKeyListResponse` |
| `scripts/local-ddb-init.py` | Modify | Add `ContentKeys` TableDef with 2 GSIs |
| `app/services/content_key_derivation.py` | New | HKDF key derivation, key ID computation, slot calculation, `HlsEncryptionConfig` dataclass |
| `app/services/content_key_store.py` | New | DynamoDB CRUD for key metadata + revocation |
| `app/routers/drm_key_server.py` | New | HLS key server endpoint + admin key management |
| `app/services/ffmpeg_abr_pipeline.py` | Modify | Add `encryption_config` parameter, key info file generation |
| `app/services/vod_encryption_orchestrator.py` | New | Orchestration: derive key, write temp files, register metadata |
| `app/services/manifest_rewrite.py` | New | Token injection into `#EXT-X-KEY` URIs at serve time |
| `app/services/local_packaging.py` | Modify | Add encryption section to `shaka_packager_config()` for Phase 2 prep |
| `app/main.py` | Modify | Register `drm_key_server_router` |
| `.env.local.example` | Modify | Add VOD-010 env vars |

### 10.3 Dependencies

| Dependency | Required By | Notes |
|-----------|-------------|-------|
| VOD-001 (Video Metadata) | `drm_policy_id` on video record | Must exist to flag per-video DRM |
| VOD-005 (Transcoding) | Encoding pipeline invokes encryption orchestrator | Must be able to call `prepare_encryption_for_rendition` |
| Playback entitlements | Token validation in key server | Already implemented |
| KMS mock (port 7999) | Optional -- only if using KMS to wrap root secret | Already running in dev stack |
| `DRM_KEY_ROTATION_SALT` | Key derivation | Must be set in `.env.local` (already present but may be empty) |

---

## 11. Observability & Monitoring

### 11.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `drm_hls_key_serve_total` | Counter | `status` (200/401/403/404), `tenant_id` | Key fetch attempts and outcomes |
| `drm_hls_key_serve_duration_ms` | Histogram | -- | Key server response latency (includes token validation + HKDF derivation) |
| `drm_key_derivation_duration_us` | Histogram | -- | HKDF key derivation time in microseconds (should be <100us) |
| `drm_key_register_total` | Counter | `drm_profile`, `tenant_id` | Keys registered at packaging time |
| `drm_key_revoke_total` | Counter | `drm_profile`, `tenant_id`, `actor` | Keys revoked by admin action |
| `drm_key_revocation_check_total` | Counter | `result` (not_revoked/revoked/no_record) | Revocation check outcomes |
| `drm_key_revocation_check_duration_ms` | Histogram | -- | DynamoDB get_item latency for revocation check |
| `drm_manifest_rewrite_total` | Counter | `result` (rewritten/no_key_tag/error) | Manifest token injection outcomes |
| `drm_manifest_rewrite_duration_ms` | Histogram | -- | Manifest rewrite latency |
| `drm_encryption_config_prepare_total` | Counter | `result` (enabled/disabled/error) | Encryption config preparation outcomes |
| `drm_ffmpeg_encrypted_segments_total` | Counter | `asset_id`, `rendition` | Encrypted segments produced |

### 11.2 Log Events

| Event | Level | Payload | Trigger |
|-------|-------|---------|---------|
| `drm.hls_key.served` | INFO | `{ asset_id, tenant_id, key_id, key_slot }` | Successful key fetch |
| `drm.hls_key.denied` | WARN | `{ asset_id, tenant_id, reason, status_code }` | Key fetch denied (401/403/404) |
| `drm.key.registered` | INFO | `{ key_id, asset_id, tenant_id, drm_profile, key_slot }` | New key metadata written to DDB |
| `drm.key.revoked` | WARN | `{ key_id, asset_id, reason, actor }` | Key revoked by admin |
| `drm.key.bulk_revoked` | WARN | `{ asset_id, count, reason, actor }` | All keys for asset revoked |
| `drm.derivation.completed` | DEBUG | `{ tenant_id, asset_id, key_slot, duration_us }` | HKDF derivation completed |
| `drm.manifest.rewritten` | DEBUG | `{ asset_id, key_tags_found }` | Manifest token placeholder replaced |
| `drm.manifest.no_key_tag` | DEBUG | `{ asset_id }` | Manifest has no #EXT-X-KEY (unencrypted video) |
| `drm.encryption.prepared` | INFO | `{ asset_id, rendition, key_id }` | Encryption config prepared for FFmpeg |
| `drm.encryption.skipped` | DEBUG | `{ asset_id, reason: "drm_disabled" }` | DRM not enabled for this video |
| `drm.config.error` | ERROR | `{ error, context }` | Configuration error (missing salt, etc.) |

### 11.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High key denial rate | `rate(drm_hls_key_serve_total{status!="200"}[5m]) / rate(drm_hls_key_serve_total[5m]) > 0.1` | P2 | Check entitlement service health; possible token issuance bug |
| Key server latency P99 > 200ms | `histogram_quantile(0.99, drm_hls_key_serve_duration_ms) > 200` | P2 | Check DynamoDB latency; HKDF is <1ms so DDB is the bottleneck |
| Zero key registrations for 24h | `sum(increase(drm_key_register_total[24h])) == 0` | P3 | Possible encoding pipeline outage; check transcode worker health |
| Key revocation without admin audit | `increase(drm_key_revoke_total[1h]) > 0` AND no corresponding admin action log | P1 | Possible unauthorized access; investigate immediately |
| DynamoDB errors on revocation check | `rate(drm_key_revocation_check_duration_ms_count{error="true"}[5m]) > 1` | P2 | DynamoDB health issue; key server may be failing open (serving keys without revocation check) |

### 11.4 Dashboard Queries

**Key Fetch Success Rate (last hour):**
```promql
sum(rate(drm_hls_key_serve_total{status="200"}[1h]))
/
sum(rate(drm_hls_key_serve_total[1h]))
```

**Key Server Latency P50/P95/P99:**
```promql
histogram_quantile(0.50, rate(drm_hls_key_serve_duration_ms_bucket[5m]))
histogram_quantile(0.95, rate(drm_hls_key_serve_duration_ms_bucket[5m]))
histogram_quantile(0.99, rate(drm_hls_key_serve_duration_ms_bucket[5m]))
```

**Keys Registered Per Day:**
```promql
sum(increase(drm_key_register_total[1d])) by (drm_profile)
```

**Revocation Activity:**
```promql
sum(increase(drm_key_revoke_total[1d])) by (tenant_id)
```

**Encrypted vs Unencrypted Video Processing:**
```promql
sum(increase(drm_encryption_config_prepare_total{result="enabled"}[1d]))
sum(increase(drm_encryption_config_prepare_total{result="disabled"}[1d]))
```

---

## 12. Rollout Plan

### 12.1 Feature Flag Strategy

The DRM encryption layer uses a dual feature flag approach:

1. **Backend flag**: `DRM_HLS_AES128_ENABLED` (env var, default `true`)
   - Controls whether the encryption orchestrator applies encryption during packaging.
   - When `false`, all videos are packaged without encryption regardless of `drm_policy_id`.
   - Does not affect the key server endpoint (which always runs for backward compatibility).

2. **Per-video flag**: `drm_policy_id` on the video metadata record
   - `null` or `"none"` = no encryption for this video.
   - `"aes128_default"` = AES-128 encryption with default rotation settings.
   - `"aes128_high"` = AES-128 with 60-second rotation (more frequent).
   - Phase 2 values: `"widevine"`, `"fairplay"`, `"multi_drm"`.

### 12.2 Phased Rollout

**Phase 0: Infrastructure (Week 1)**
- Deploy ContentKeys DynamoDB table.
- Deploy key derivation service and content key store.
- Deploy key server router (accepts requests but no content is encrypted yet).
- Deploy with `DRM_HLS_AES128_ENABLED=false`.
- Run unit tests and integration tests.
- Validate: Key server returns 400 "DRM not enabled" for all requests.

**Phase 1: Internal Testing (Week 2)**
- Enable `DRM_HLS_AES128_ENABLED=true` in staging.
- Upload test videos with `drm_policy_id=aes128_default`.
- Validate: Encrypted segments produced, key server serves keys, playback works.
- Run E2E tests (section 110, 111).
- Smoke test on iOS Safari, Chrome, Firefox, and Android Chrome.

**Phase 2: Canary (Week 3)**
- Enable in production with `DRM_HLS_AES128_ENABLED=true`.
- Only new uploads with `drm_policy_id` set will be encrypted.
- Existing videos remain unencrypted (no retroactive encryption).
- Monitor: key fetch success rate, playback error rate, player error events.
- Duration: 7 days.
- Rollback trigger: >1% playback failure rate OR >5% key denial rate.

**Phase 3: Default Encryption (Week 5)**
- Update default `drm_policy_id` for new uploads to `"aes128_default"` (previously `null`).
- Creators can still opt out by setting `drm_policy_id=none` on individual videos.
- Provide UI toggle in video upload form: "Enable content protection" (checked by default).

**Phase 4: Retroactive Encryption (Week 8, optional)**
- Background job re-packages existing videos with encryption.
- Uses `TranscodeJobs` queue to avoid overloading FFmpeg workers.
- Progress tracked via admin dashboard.
- Estimated: 100 videos/hour per worker.

### 12.3 Rollback Procedure

| Step | Action | Time to Execute |
|------|--------|-----------------|
| 1 | Set `DRM_HLS_AES128_ENABLED=false` in production env | Instant (env var change) |
| 2 | Restart backend workers (picks up env change) | 30 seconds |
| 3 | Verify: New uploads are not encrypted (check manifest for no `#EXT-X-KEY`) | 2 minutes |
| 4 | Verify: Key server still serves keys for previously encrypted content | 1 minute |
| 5 | If key server is the issue, revert the router registration in `main.py` | 5 minutes (deploy) |
| 6 | If DDB table is the issue, the key server fails open (returns derived key without revocation check) | Automatic |

**Important**: Rollback does NOT break playback of already-encrypted videos. The key server
continues to derive and serve keys even when `DRM_HLS_AES128_ENABLED=false`. The flag only
controls whether NEW encodes use encryption.

### 12.4 Migration Steps

**DynamoDB table creation:**
```bash
# Run during deployment (idempotent -- skips existing tables)
python scripts/local-ddb-init.py
```

**Environment variable addition:**
```bash
# Add to .env.local (dev) and production config
DDB_CONTENT_KEYS=ContentKeys
DRM_HLS_AES128_ENABLED=true
DRM_HLS_KEY_SERVER_BASE_URL=https://app.example.com
DRM_CONTENT_KEY_RETENTION_DAYS=90
DRM_KEY_ROTATION_SALT=$(openssl rand -hex 32)  # MUST be unique per environment
```

**No data migration needed**: The ContentKeys table starts empty. Keys are registered as
videos are encrypted.

---

## 13. Performance Considerations

### 13.1 Key Derivation Performance

| Operation | Expected Latency | CPU Cost | Notes |
|-----------|-----------------|----------|-------|
| HKDF-SHA256 derivation (16 bytes) | <50us | Negligible | Pure in-memory computation; no I/O |
| `compute_key_id` (SHA-256 hash) | <20us | Negligible | Single hash operation |
| `current_key_slot` (integer division) | <1us | Negligible | Trivial arithmetic |

The HKDF derivation is the cheapest part of the key-serve flow. DynamoDB round-trip for
revocation check dominates latency.

### 13.2 Key Server Endpoint Performance

| Component | Expected Latency | Bottleneck | Notes |
|-----------|-----------------|------------|-------|
| Token validation (HS256 verify) | <1ms | CPU | JWT verification is fast |
| DynamoDB get_item (revocation check) | 2-5ms | Network I/O | Single-item lookup by PK |
| HKDF key derivation | <0.05ms | CPU | Negligible |
| HTTP response (16 bytes) | <0.1ms | Network I/O | Tiny payload |
| **Total P50** | **3-6ms** | | |
| **Total P99** | **10-20ms** | | DynamoDB tail latency |

**Capacity**: A single backend instance can handle ~5,000 key requests/second (limited by
DynamoDB throughput, not CPU). For 1,000 concurrent viewers each fetching a key every 2s
(segment duration), the load is 500 req/s -- well within capacity.

### 13.3 DynamoDB Cost Analysis

| Operation | Frequency | RCU/WCU Cost | Monthly Cost (1M videos) |
|-----------|-----------|-------------|-------------------------|
| Register key (put_item) | Once per encode | 1 WCU | ~$0.25/month |
| Revocation check (get_item) | Once per key fetch | 0.5 RCU (eventually consistent) | ~$0.50/month per 1M fetches |
| List keys (GSI query) | Rare (admin only) | 0.5-5 RCU | Negligible |
| TTL auto-delete | Background | Free | Free |

Total DynamoDB cost for DRM: **<$5/month** for 1M videos with moderate playback.

### 13.4 FFmpeg Encryption Overhead

| Aspect | Impact | Mitigation |
|--------|--------|------------|
| Encode time increase | ~2-5% (AES-128 encryption is fast) | Already parallel across renditions |
| Segment file size | No change (AES-128 does not inflate data) | N/A |
| Key info file write | <1ms per rendition | Written once before encode starts |
| Temp key file on disk | 16 bytes per rendition | Cleaned up after encode |
| Memory overhead | Negligible (FFmpeg handles encryption internally) | N/A |

### 13.5 Manifest Rewrite Performance

| Aspect | Latency | Notes |
|--------|---------|-------|
| String replacement (regex) | <0.1ms | Manifest is typically <2KB |
| Token injection | <0.1ms | Simple string interpolation |
| Full manifest rewrite | <0.5ms | Including regex compile (cached) |

The manifest rewrite is negligible compared to network latency for serving the manifest.

### 13.6 Caching Strategy

| Resource | Cache Policy | Rationale |
|----------|-------------|-----------|
| HLS segments (.ts) | `Cache-Control: public, max-age=86400` | Segments are immutable once encrypted; safe to cache aggressively |
| HLS manifests (.m3u8) | `Cache-Control: private, no-cache` | Manifest contains viewer-specific token; must not be shared |
| Key server response | `Cache-Control: no-store` | Keys must never be cached; each fetch validates entitlement |
| ContentKeys DDB items | No application cache | Revocation must be real-time; caching risks serving revoked keys |

### 13.7 Rate Limiting

| Endpoint | Limit | Per | Rationale |
|----------|-------|-----|-----------|
| `GET /drm/hls-key` | 300 req/min | IP | Prevent key scraping; legitimate players fetch ~30 keys/min |
| `GET /drm/hls-key` | 60 req/min | Session | Per-session limit prevents stolen tokens from mass-fetching |
| `POST /drm/keys/revoke` | 10 req/min | Admin user | Prevent accidental bulk revocation |
| `GET /drm/keys/{asset_id}` | 30 req/min | Admin user | Audit listing; rarely needed frequently |

### 13.8 Hot Partition Warning

The ContentKeys table uses `key_id` as the partition key, which is a SHA-256 hash -- this
provides excellent key distribution and avoids hot partitions.

However, the `ByAssetCreatedAt` GSI could become hot if a single asset has thousands of key
rotations (e.g., a very popular live-to-VOD recording with 60-second rotation over many hours).
For a 4-hour recording with 60-second rotation, that is 240 keys per asset -- well within
DDB limits. For extreme cases (24-hour streams), consider increasing `rotation_seconds` or
archiving old key records more aggressively.

---

## 14. Testing Strategy

### 14.1 Unit Tests: Key Derivation (`tests/test_content_key_derivation.py`)

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
| `test_hkdf_output_not_truncated_prk` | Verify the output is from the expand step, not a truncated PRK. |
| `test_empty_root_secret_raises` | Empty string root_secret raises ValueError. |
| `test_unicode_tenant_id` | Non-ASCII tenant_id produces valid key without error. |

### 14.2 Unit Tests: Content Key Store (`tests/test_content_key_store.py`)

Follow the `_FakeTable` pattern from `tests/test_broadcast_store.py`:

| Test | What it validates |
|------|-------------------|
| `test_register_key_creates_record` | Record with correct fields appears in table. |
| `test_register_key_idempotent` | Second call with same key_id does not overwrite (ConditionExpression). |
| `test_register_key_sets_ttl_epoch` | TTL set to created_at + retention_days * 86400. |
| `test_check_revocation_false_when_no_record` | Missing key = not revoked (fail-open). |
| `test_check_revocation_false_when_not_revoked` | Record exists with `revoked=False`. |
| `test_check_revocation_true_when_revoked` | Record exists with `revoked=True`. |
| `test_revoke_key_sets_fields` | After revoke, `revoked=True`, `revoked_at` set, `revoked_reason` stored. |
| `test_revoke_key_stores_actor` | `revoked_by` field contains the actor's identity. |
| `test_list_keys_for_asset_pagination` | Insert 5 keys, list with limit=2, cursor returned. |
| `test_list_keys_for_asset_sorted_by_created_at` | Results sorted newest-first (ScanIndexForward=False). |
| `test_list_keys_for_tenant` | Keys filtered by tenant_id via GSI. |
| `test_revoke_all_keys_for_asset` | All keys for asset marked revoked; returns count. |

### 14.3 Unit Tests: Key Server Endpoint (`tests/test_drm_key_server.py`)

Using FastAPI TestClient with mocked entitlement validation:

| Test | What it validates |
|------|-------------------|
| `test_hls_key_valid_token_returns_16_bytes` | 200 response, Content-Type octet-stream, body is 16 bytes. |
| `test_hls_key_expired_token_returns_401` | Expired entitlement token returns 401. |
| `test_hls_key_invalid_signature_returns_401` | Tampered token returns 401. |
| `test_hls_key_asset_mismatch_returns_403` | Token for asset A, query for asset B returns 403. |
| `test_hls_key_tenant_mismatch_returns_403` | Token for tenant A, query for tenant B returns 403. |
| `test_hls_key_revoked_key_returns_404` | Key marked revoked in DDB returns 404. |
| `test_hls_key_missing_params_returns_422` | Missing `asset_id` or `tenant_id` returns 422. |
| `test_hls_key_cors_headers` | Response includes `Access-Control-Allow-Origin: *`. |
| `test_hls_key_no_cache_headers` | Response includes `Cache-Control: no-store`. |
| `test_hls_key_response_content_type` | Content-Type is `application/octet-stream`. |
| `test_admin_revoke_requires_admin_session` | Regular user POST to revoke returns 403. |
| `test_admin_revoke_marks_key_revoked` | Admin POST to revoke sets `revoked=True`. |
| `test_admin_list_keys_returns_paginated` | GET with admin session returns key list with cursor support. |
| `test_admin_bulk_revoke` | POST revoke-all marks all keys for asset as revoked. |

### 14.4 Unit Tests: FFmpeg Encryption Args (`tests/test_ffmpeg_abr_pipeline_encryption.py`)

| Test | What it validates |
|------|-------------------|
| `test_build_args_without_encryption_no_key_info` | Default behavior unchanged when no encryption_config. |
| `test_build_args_with_encryption_adds_key_info_file` | `-hls_key_info_file` present in args. |
| `test_key_info_file_format` | Written file has 3 lines: URI, key path, IV. |
| `test_key_file_written_16_bytes` | Temp key file contains exactly 16 bytes. |
| `test_hls_flags_no_delete_segments_when_encrypted` | `delete_segments` removed from `-hls_flags` for VOD. |
| `test_key_info_uri_contains_placeholder_token` | URI in key info file has `token=PLACEHOLDER`. |
| `test_iv_hex_written_when_provided` | Explicit IV hex string appears on line 3. |
| `test_iv_omitted_when_none` | Line 3 is empty when iv_hex is None. |

### 14.5 Unit Tests: Key Rotation (`tests/test_content_key_rotation.py`)

| Test | What it validates |
|------|-------------------|
| `test_rotation_changes_key_at_boundary` | Key at t=299 differs from key at t=300 (with rotation_seconds=300). |
| `test_rotation_stable_within_slot` | Key at t=0 equals key at t=299. |
| `test_rotation_disabled_always_same_slot` | When `drm_key_rotation_enabled=False`, slot is always 0. |
| `test_key_id_changes_with_slot` | `compute_key_id` returns different values for different slots. |
| `test_key_derivation_uses_correct_slot` | End-to-end: orchestrator derives correct key for current time. |
| `test_minimum_rotation_60_seconds` | Rotation seconds <60 are clamped; slot calculation uses 60. |
| `test_large_rotation_interval` | Rotation of 86400 (1 day) produces one slot per day. |

### 14.6 Unit Tests: Manifest Rewrite (`tests/test_manifest_rewrite.py`)

| Test | What it validates |
|------|-------------------|
| `test_rewrite_replaces_placeholder` | `token=PLACEHOLDER` replaced with actual token. |
| `test_rewrite_multiple_key_tags` | All `#EXT-X-KEY` tags in manifest get token injected. |
| `test_rewrite_preserves_non_key_lines` | Non-key lines are unchanged. |
| `test_rewrite_with_no_placeholder_returns_unchanged` | Manifest without PLACEHOLDER is returned as-is. |
| `test_inject_key_tag` | Key tag added to manifest that has none. |
| `test_inject_key_tag_noop_when_exists` | Manifest with existing key tag is not modified. |
| `test_special_chars_in_token` | Tokens with URL-unsafe characters are properly handled. |

### 14.7 Integration Tests (pytest with moto DynamoDB)

| Test | What it validates |
|------|-------------------|
| `test_full_key_lifecycle` | Register key, check not revoked, revoke, check revoked. |
| `test_key_server_endpoint_integration` | Issue entitlement, call `/drm/hls-key`, verify 16-byte response. |
| `test_key_server_revoked_integration` | Register + revoke key, then call endpoint, verify 404. |
| `test_manifest_rewrite_injects_token` | Input manifest with PLACEHOLDER, output has real token. |
| `test_encryption_orchestrator_end_to_end` | Prepare encryption config, verify key info file, finalize metadata. |
| `test_key_rotation_across_slots` | Register keys at slot N and N+1, verify both are independently revokable. |

### 14.8 E2E Tests: `frontend/e2e/drm-encryption.spec.ts`

Using the existing `injectAuth` + `page.request` pattern:

**Section 110: DRM Key Server API (7 tests)**

| # | Test | What it validates |
|---|------|-------------------|
| 110.1 | Issue entitlement and fetch HLS key | End-to-end: issue token via `/v1/playback/entitlements/issue`, then GET `/drm/hls-key?asset_id=...&tenant_id=...&token=...`, verify 200 + 16-byte binary response. |
| 110.2 | Fetch key with expired token returns 401 | Use token with `ttl_seconds=1`, wait 2s, verify 401. |
| 110.3 | Fetch key with wrong asset_id returns 403 | Token for `asset_A`, request for `asset_B`, verify 403. |
| 110.4 | Fetch key with invalid token returns 401 | Garbage token string, verify 401. |
| 110.5 | Key rotation produces different keys | Issue two tokens 301s apart (mocked time), fetch keys, verify different 16-byte values. |
| 110.6 | Revoke key then fetch returns 404 | Admin revokes key via POST, subsequent fetch returns 404. |
| 110.7 | Admin list keys for asset | Register keys, GET `/drm/keys/{asset_id}` as admin, verify list. |

```typescript
test("110.1 issue entitlement and fetch HLS key", async ({ request }) => {
  // Step 1: Issue a playback entitlement token with audience="hls-key"
  const entResp = await request.post(
    `${BASE}/v1/playback/entitlements/issue`,
    {
      headers: { "X-User-Id": ALICE_SUB },
      data: {
        asset_id: `asset_${TS}`,
        tenant_id: "tenant-a",
        device_id: "test-device",
        profile: "hls",
        audience: "hls-key",
        ttl_seconds: 3600,
      },
    },
  );
  expect(entResp.ok()).toBeTruthy();
  const { token } = await entResp.json();

  // Step 2: Fetch the HLS key using the entitlement token
  const keyResp = await request.get(
    `${BASE}/drm/hls-key?asset_id=asset_${TS}&tenant_id=tenant-a&token=${token}`,
  );
  expect(keyResp.status()).toBe(200);
  expect(keyResp.headers()["content-type"]).toContain("application/octet-stream");
  const body = await keyResp.body();
  expect(body.length).toBe(16);
});

test("110.2 fetch key with expired token returns 401", async ({ request }) => {
  // Issue a token with very short TTL
  const entResp = await request.post(
    `${BASE}/v1/playback/entitlements/issue`,
    {
      headers: { "X-User-Id": ALICE_SUB },
      data: {
        asset_id: `asset_exp_${TS}`,
        tenant_id: "tenant-a",
        device_id: "test-device",
        profile: "hls",
        audience: "hls-key",
        ttl_seconds: 1,
      },
    },
  );
  const { token } = await entResp.json();

  // Wait for expiry
  await new Promise((r) => setTimeout(r, 2000));

  const keyResp = await request.get(
    `${BASE}/drm/hls-key?asset_id=asset_exp_${TS}&tenant_id=tenant-a&token=${token}`,
  );
  expect(keyResp.status()).toBe(401);
});

test("110.3 fetch key with wrong asset_id returns 403", async ({ request }) => {
  const entResp = await request.post(
    `${BASE}/v1/playback/entitlements/issue`,
    {
      headers: { "X-User-Id": ALICE_SUB },
      data: {
        asset_id: `asset_a_${TS}`,
        tenant_id: "tenant-a",
        device_id: "test-device",
        profile: "hls",
        audience: "hls-key",
        ttl_seconds: 3600,
      },
    },
  );
  const { token } = await entResp.json();

  // Request key for a DIFFERENT asset
  const keyResp = await request.get(
    `${BASE}/drm/hls-key?asset_id=asset_b_${TS}&tenant_id=tenant-a&token=${token}`,
  );
  expect(keyResp.status()).toBe(403);
});
```

**Section 111: Encrypted Playback Integration (4 tests)**

| # | Test | What it validates |
|---|------|-------------------|
| 111.1 | Encrypted manifest contains EXT-X-KEY tag | Upload video with DRM enabled, wait for processing, fetch manifest, verify `#EXT-X-KEY:METHOD=AES-128` present. |
| 111.2 | Key URI in manifest resolves to valid key | Extract URI from manifest, fetch it with entitlement token, verify 200. |
| 111.3 | Unencrypted video has no EXT-X-KEY tag | Upload video without DRM, verify manifest has no encryption tag. |
| 111.4 | Encrypted segments are not cleartext | Fetch a `.ts` segment, verify first bytes are NOT the MPEG-TS sync byte `0x47` (encrypted data appears random). |

**Section 112: Admin Key Management API (5 tests)**

| # | Test | What it validates |
|---|------|-------------------|
| 112.1 | Admin can list keys for an asset | GET `/drm/keys/{asset_id}` returns paginated list. |
| 112.2 | Admin can revoke a single key | POST `/drm/keys/revoke` marks key as revoked. |
| 112.3 | Admin can bulk revoke all keys for an asset | POST `/drm/keys/{asset_id}/revoke-all` revokes all. |
| 112.4 | Non-admin cannot revoke keys | POST `/drm/keys/revoke` as regular user returns 403. |
| 112.5 | Non-admin cannot list keys | GET `/drm/keys/{asset_id}` as regular user returns 403. |

**Section 113: Edge Cases (6 tests)**

| # | Test | What it validates |
|---|------|-------------------|
| 113.1 | Same key derived from same inputs | Fetch key twice with same params, compare bytes are equal. |
| 113.2 | Different assets produce different keys | Fetch keys for two different asset_ids, verify different bytes. |
| 113.3 | Key fetch with DRM disabled returns 400 | Asset without `drm_policy_id` returns appropriate error. |
| 113.4 | CORS headers present on key response | `Access-Control-Allow-Origin: *` in response. |
| 113.5 | Cache-Control no-store on key response | `Cache-Control: no-store` in response. |
| 113.6 | Missing query params return 422 | Omit asset_id, verify 422 validation error. |

### 14.9 Test Count Summary

| Category | Tests |
|----------|-------|
| Unit: Key Derivation | 12 |
| Unit: Content Key Store | 12 |
| Unit: Key Server Endpoint | 14 |
| Unit: FFmpeg Encryption | 8 |
| Unit: Key Rotation | 7 |
| Unit: Manifest Rewrite | 7 |
| Integration | 6 |
| E2E Section 110 (Key Server API) | 7 |
| E2E Section 111 (Encrypted Playback) | 4 |
| E2E Section 112 (Admin Key Management) | 5 |
| E2E Section 113 (Edge Cases) | 6 |
| **Total** | **88** |

### 14.10 Test Data Considerations

- **Entitlement secret**: Tests require `PLAYBACK_ENTITLEMENT_SECRET` to be set (already present in `.env.local` per `playback-entitlements.spec.ts`).
- **Rotation salt**: Tests should use a fixed `DRM_KEY_ROTATION_SALT` (e.g., `"test-rotation-salt"`) to make key derivation deterministic.
- **Time mocking**: Key rotation tests use `now_epoch` parameter (already supported by entitlement functions) rather than real clock.
- **Unique asset IDs per run**: Use `f"asset_{Date.now()}"` pattern to avoid conflicts across test runs.
- **Binary response handling in Playwright**: Use `response.body()` to get raw bytes; verify `body.length === 16`.
- **Admin session for revocation tests**: Use `e2e_admin_session_setup.py` root identity for admin endpoints.

---

## 15. Security Considerations

### 15.1 Threat Model

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Direct segment download (URL guessing) | AES-128 encryption; segments are ciphertext | Attacker gets encrypted garbage |
| Key URL extraction from manifest | Token in URL validates viewer identity | Token cannot be reused across sessions (JTI-bound) |
| Token replay/sharing | Short TTL (1 hour default), per-session binding, JTI revocation | Brief window between issue and expiry |
| Key scraping (automated fetch) | Rate limiting (300/min per IP, 60/min per session) | Determined attacker with distributed IPs |
| Root secret compromise | Rotate `DRM_KEY_ROTATION_SALT` + re-encode all content | Requires re-packaging (expensive) |
| DynamoDB key record tampering | DynamoDB access gated by IAM; no public access | Insider threat; mitigated by audit logging |
| Man-in-the-middle on key fetch | HTTPS enforced; HSTS headers | Not a concern with TLS |
| CDN caching leaked keys | `Cache-Control: no-store` on all key responses | CDN misconfiguration risk |

### 15.2 Root Secret Management

`DRM_KEY_ROTATION_SALT` must be at least 32 bytes of high-entropy data in production. In dev mode, the default `"dev-vod-drm-rotation-salt-change-in-prod"` is acceptable.

**Production requirements:**
- Store in AWS Secrets Manager or HashiCorp Vault.
- Rotate annually (requires re-encoding affected content).
- Different values per environment (staging, production).
- Never log or expose in error messages.

### 15.3 Token Audience Separation

HLS key requests use `audience="hls-key"` (not the same `"playback"` audience used for manifest access). This prevents a manifest-access token from being reused to fetch keys if audiences are ever separated.

### 15.4 No Key Caching at CDN

The key endpoint MUST NOT be cached by CDN (Cache-Control: no-store, no-cache). Keys are short-lived by design.

### 15.5 IV Selection

Using segment sequence number as IV (the HLS default) is acceptable for AES-128-CBC since each segment has a unique sequence number. Explicit random IVs provide slightly better security but complicate the implementation without material benefit for VOD.

### 15.6 Key Material Never Logged

The `derive_content_key` function must never log or emit the derived key bytes. Only the key_id (hash) should appear in logs. The key server endpoint returns raw bytes with no JSON wrapper, ensuring the key does not accidentally appear in access logs that record response bodies.

### 15.7 Temp File Cleanup

The 16-byte key file written for FFmpeg (`enc.key`) must be securely deleted after the encode completes. Use `os.remove()` in a `finally` block in the encryption orchestrator. On Linux, the file is overwritten by the OS when the inode is released, but explicit deletion prevents the file from persisting on disk after encode.

---

## Appendix A: Configuration Reference

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

---

## Appendix B: HKDF Reference Implementation

For clarity, the full HKDF-SHA256 implementation as used in this ticket:

```python
import hashlib
import hmac


def hkdf_sha256(
    *,
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """RFC 5869 HKDF using HMAC-SHA256.

    Args:
        ikm: Input key material.
        salt: Optional salt (if empty, uses zeros).
        info: Context and application-specific info.
        length: Output key material length (max 8160 bytes = 255 * 32).

    Returns:
        Derived key material of the requested length.
    """
    if length > 255 * 32:
        raise ValueError("Cannot derive more than 255 * HashLen bytes")

    # Step 1: Extract
    if not salt:
        salt = b"\x00" * 32  # SHA-256 hash length
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Step 2: Expand
    okm = b""
    t = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t

    return okm[:length]


def derive_content_key(
    *,
    tenant_id: str,
    asset_id: str,
    key_slot: int,
    root_secret: str,
) -> bytes:
    """Derive a 16-byte AES-128 content encryption key using HKDF-SHA256."""
    if not root_secret:
        raise ValueError("root_secret must not be empty")

    return hkdf_sha256(
        ikm=root_secret.encode("utf-8"),
        salt=hashlib.sha256(f"{tenant_id}|{asset_id}".encode()).digest(),
        info=f"hls-aes128|{key_slot}".encode("utf-8"),
        length=16,
    )


def compute_key_id(
    *,
    tenant_id: str,
    asset_id: str,
    drm_profile: str,
    key_slot: int,
    salt: str,
) -> str:
    """Compute a deterministic 32-char hex key ID."""
    basis = f"{tenant_id}|{asset_id}|{drm_profile}|{key_slot}|{salt}"
    return hashlib.sha256(basis.encode()).hexdigest()[:32]


def current_key_slot(*, now_epoch: int, rotation_seconds: int) -> int:
    """Compute the current key rotation slot."""
    effective_rotation = max(rotation_seconds, 60)  # Minimum 60 seconds
    return now_epoch // effective_rotation
```

---

## Appendix C: HLS Encryption Manifest Examples

### C.1 Encrypted Variant Playlist (Single Key)

```m3u8
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-KEY:METHOD=AES-128,URI="https://app.example.com/drm/hls-key?asset_id=v_abc&tenant_id=t_xyz&token=eyJhbGci...",IV=0x00000000000000000000000000000000
#EXTINF:2.000,
seg_00000.ts
#EXTINF:2.000,
seg_00001.ts
#EXTINF:2.000,
seg_00002.ts
#EXTINF:1.423,
seg_00003.ts
#EXT-X-ENDLIST
```

### C.2 Encrypted Variant Playlist (Rotated Keys)

```m3u8
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-KEY:METHOD=AES-128,URI="https://app.example.com/drm/hls-key?asset_id=v_abc&tenant_id=t_xyz&key_id=key1&token=PLACEHOLDER",IV=0x00000000000000000000000000000000
#EXTINF:2.000,
seg_00000.ts
#EXTINF:2.000,
seg_00001.ts
#EXTINF:2.000,
seg_00002.ts
#EXT-X-KEY:METHOD=AES-128,URI="https://app.example.com/drm/hls-key?asset_id=v_abc&tenant_id=t_xyz&key_id=key2&token=PLACEHOLDER",IV=0x00000000000000000000000000000003
#EXTINF:2.000,
seg_00003.ts
#EXTINF:2.000,
seg_00004.ts
#EXTINF:2.000,
seg_00005.ts
#EXT-X-ENDLIST
```

### C.3 Unencrypted Variant Playlist (No DRM)

```m3u8
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:2.000,
seg_00000.ts
#EXTINF:2.000,
seg_00001.ts
#EXTINF:2.000,
seg_00002.ts
#EXTINF:1.423,
seg_00003.ts
#EXT-X-ENDLIST
```

### C.4 Master Playlist (References Encrypted Variant Playlists)

```m3u8
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360,CODECS="avc1.42e00a,mp4a.40.2"
360p/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2500000,RESOLUTION=1280x720,CODECS="avc1.4d401f,mp4a.40.2"
720p/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080,CODECS="avc1.640028,mp4a.40.2"
1080p/index.m3u8
```
