package com.testlogon.android.data.locale

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PUT

/**
 * AND-113 — Retrofit interface for the user's server-side locale preference.
 *
 * Verified against the staged reference:
 *  - GET  /ui/i18n/locale  (op get_user_locale_ui_i18n_locale_get)  -> { "locale": "<tag>" }
 *  - PUT  /ui/i18n/locale  (op save_user_locale_ui_i18n_locale_put) <- { "locale": "<tag>" }
 *                                                                     -> { "ok": true, "locale": "<tag>" }
 * Sources: reference/openapi.index.txt:1515-1516 and reference/src/api/endpoints/i18n.ts
 * (getUserLocale / saveUserLocale). The OpenAPI types the response bodies as empty schemas, so the
 * frontend TS types are authoritative for the shapes. NOTE: locale is NOT on /ui/me (MeResp has no
 * locale field), and the /v1/kyc/i18n/ surface is a separate KYC concern, out of scope.
 *
 * Auth (cookie + Authorization: Bearer + X-CSRF-Token) and the one-shot 401 refresh-and-retry are
 * applied by the shared OkHttp interceptors (CsrfInterceptor / SessionAuthenticator); this API adds
 * nothing auth-specific.
 */
interface LocaleApi {

    @GET("ui/i18n/locale")
    suspend fun getUserLocale(): UserLocaleDto

    @PUT("ui/i18n/locale")
    suspend fun saveUserLocale(@Body body: SaveLocaleRequest): SaveLocaleResponse
}
