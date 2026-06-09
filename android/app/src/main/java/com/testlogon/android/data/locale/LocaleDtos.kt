package com.testlogon.android.data.locale

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-113 — Moshi DTOs for /ui/i18n/locale.
 *
 * Shapes taken from reference/src/api/endpoints/i18n.ts (UserLocaleResponse and the
 * saveUserLocale return type) because OpenAPI types these bodies as empty schemas.
 */

/** GET /ui/i18n/locale 200 body: { "locale": "es" } */
@JsonClass(generateAdapter = true)
data class UserLocaleDto(
    @Json(name = "locale") val locale: String,
)

/** PUT /ui/i18n/locale request body: { "locale": "fr" } */
@JsonClass(generateAdapter = true)
data class SaveLocaleRequest(
    @Json(name = "locale") val locale: String,
)

/** PUT /ui/i18n/locale 200 body: { "ok": true, "locale": "fr" } */
@JsonClass(generateAdapter = true)
data class SaveLocaleResponse(
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "locale") val locale: String,
)
