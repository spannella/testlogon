package com.testlogon.android.data.preferences

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-078 — Moshi DTOs for the UI-preferences endpoint, mirroring the backend
 * `PreferencesPatchReq` / `UiPreferences` (verified: `src/api/endpoints/preferences.ts`).
 *
 * GET wraps the prefs object: `{"preferences": { ...keys... }}`.
 * PATCH body is the patch (only non-null fields are emitted — Moshi omits nulls by default).
 * PATCH response is `{"ok": true}` (no echoed prefs), so the repository re-GETs for server truth.
 *
 * Codegen adapters (KSP) so they decode with a plain `Moshi.Builder().build()` (matches the
 * dashboard/sessions DTO pattern).
 */
@JsonClass(generateAdapter = true)
data class PreferencesEnvelopeDto(
    @Json(name = "preferences") val preferences: PreferencesDto? = null,
)

@JsonClass(generateAdapter = true)
data class PreferencesDto(
    @Json(name = "theme") val theme: String? = null,
    @Json(name = "sidebar_collapsed") val sidebarCollapsed: Boolean? = null,
    @Json(name = "accent_color") val accentColor: String? = null,
    @Json(name = "custom_accent_hex") val customAccentHex: String? = null,
    @Json(name = "font_size") val fontSize: String? = null,
    @Json(name = "density") val density: String? = null,
    @Json(name = "high_contrast") val highContrast: Boolean? = null,
)

/** PATCH body. Null fields are omitted from JSON, giving partial-update semantics. */
@JsonClass(generateAdapter = true)
data class UpdatePreferencesRequestDto(
    @Json(name = "theme") val theme: String? = null,
    @Json(name = "sidebar_collapsed") val sidebarCollapsed: Boolean? = null,
    @Json(name = "accent_color") val accentColor: String? = null,
    @Json(name = "custom_accent_hex") val customAccentHex: String? = null,
    @Json(name = "font_size") val fontSize: String? = null,
    @Json(name = "density") val density: String? = null,
    @Json(name = "high_contrast") val highContrast: Boolean? = null,
)

/** PATCH acknowledgement body: `{"ok": true}`. */
@JsonClass(generateAdapter = true)
data class OkResponseDto(
    @Json(name = "ok") val ok: Boolean = false,
)
