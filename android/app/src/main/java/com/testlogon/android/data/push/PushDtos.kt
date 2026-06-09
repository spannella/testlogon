package com.testlogon.android.data.push

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-106/109 — wire DTOs for the push device endpoints.
 *
 * VERIFIED against the real backend contract:
 *  - reference/openapi.index.txt:
 *      POST /ui/push/register  req=PushRegisterReq  resp=200;422:HTTPValidationError
 *      POST /ui/push/revoke    req=PushRevokeReq    resp=200;422:HTTPValidationError
 *  - reference/src/api/types.ts:
 *      PushRegisterReq { token: string; platform: string }   (both required; NO app_version/device_id)
 *      PushDevice      { device_id, platform, created_at, last_seen_at }
 *      PushRevokeReq   { device_id: string }
 *      OkResp          { ok: boolean }
 *  - reference/src/api/endpoints/push.ts:
 *      registerPush -> api.post<PushDevice>("/ui/push/register", body)
 *      revokePush   -> api.post<OkResp>("/ui/push/revoke", body)
 *
 * The 200 register body is declared as an empty schema in OpenAPI; the PushDevice shape comes from
 * the frontend type, so it is parsed defensively (all fields nullable-tolerant via defaults).
 */

@JsonClass(generateAdapter = true)
data class PushRegisterRequest(
    @Json(name = "token") val token: String,
    @Json(name = "platform") val platform: String = PLATFORM_ANDROID,
) {
    companion object {
        const val PLATFORM_ANDROID = "android"
    }
}

@JsonClass(generateAdapter = true)
data class PushRevokeRequest(
    @Json(name = "device_id") val deviceId: String,
)

/** Register success body (mirrors `PushDevice`). Parsed defensively — fields may be absent. */
@JsonClass(generateAdapter = true)
data class PushDeviceDto(
    @Json(name = "device_id") val deviceId: String? = null,
    @Json(name = "platform") val platform: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "last_seen_at") val lastSeenAt: Long? = null,
)

/** Generic `{ "ok": boolean }` success envelope (revoke). */
@JsonClass(generateAdapter = true)
data class OkRespDto(
    @Json(name = "ok") val ok: Boolean = true,
)
