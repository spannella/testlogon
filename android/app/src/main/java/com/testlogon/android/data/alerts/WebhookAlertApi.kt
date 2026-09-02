package com.testlogon.android.data.alerts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * Webhook alert-channel Retrofit interface.
 *
 * Verified against app/routers/alerts.py (get_webhook_prefs :268 / set_webhook_prefs :274) and the
 * web contract frontend/src/api/endpoints/alerts.ts (getWebhookPrefs / setWebhookPrefs):
 *  - GET  ui/alerts/webhook_prefs -> { webhook_urls: string[], event_types: string[] }
 *  - POST ui/alerts/webhook_prefs <- { webhook_urls: string[], webhook_event_types: string[] }
 *                                  -> full alert prefs (webhook_urls / webhook_event_types echoed)
 *
 * Note the GET response names the event list `event_types` (see the router) while the POST body names
 * it `webhook_event_types`; both are decoded/emitted below. The 200 bodies are untyped server-side, so
 * unknown keys are tolerated by the shared Moshi converter. CSRF / cookies / Bearer are attached by
 * the core-network interceptor chain.
 */
interface WebhookAlertApi {

    @GET("ui/alerts/webhook_prefs")
    suspend fun getWebhookPrefs(): WebhookPrefsDto

    @Headers("Content-Type: application/json")
    @POST("ui/alerts/webhook_prefs")
    suspend fun setWebhookPrefs(@Body body: WebhookPrefsUpdateDto): WebhookPrefsDto
}

@JsonClass(generateAdapter = true)
data class WebhookPrefsDto(
    @Json(name = "webhook_urls") val webhookUrls: List<String> = emptyList(),
    // GET returns the list as `event_types`; POST echoes the alert-prefs record as `webhook_event_types`.
    @Json(name = "event_types") val eventTypes: List<String>? = null,
    @Json(name = "webhook_event_types") val webhookEventTypes: List<String>? = null,
) {
    /** The event-type list under whichever key the server used for this response. */
    fun events(): List<String> = eventTypes ?: webhookEventTypes ?: emptyList()
}

@JsonClass(generateAdapter = true)
data class WebhookPrefsUpdateDto(
    @Json(name = "webhook_urls") val webhookUrls: List<String>,
    @Json(name = "webhook_event_types") val webhookEventTypes: List<String>,
)
