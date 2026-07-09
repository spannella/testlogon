package com.testlogon.android.core.network.admessaging

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * ADV2-E5 (F5+F6) — Retrofit interface for the AD-MESSAGING surface. Transport only; the repo/VM/UI live
 * in the :app feature. Paths have NO leading slash (relative to the shared Retrofit base URL); the session
 * cookie / Bearer / CSRF are attached globally by the core-network interceptors. Ops return RAW DTOs; the
 * repo folds them into ApiResult.
 *
 * WIRE CONTRACT (backend ADV2-501..610, prod-live 0ddc809b/8acc9e59):
 *  F5 — advertiser proposes a sponsored MESSAGE to a creator; only that creator may approve (which SENDS
 *  the message to the creators audience AS the creator, billing the advertiser hybrid + crediting 70%):
 *   POST ui/ads/sponsored-messages/offers                  body [AdMessageOfferReq]  -> offer (201)
 *   GET  ui/ads/sponsored-messages/offers/inbox            -> { offers: [...] } (the creators queue)
 *   GET  ui/ads/sponsored-messages/offers/outbox           -> { offers: [...] } (the advertisers)
 *   POST ui/ads/sponsored-messages/offers/{id}/approve     body? [AdMessageApproveReq] -> send record
 *   POST ui/ads/sponsored-messages/offers/{id}/reject      body? [AdMessageRejectReq]  -> terminal
 *   GET  ui/ads/sponsored-messages/sends/{id}              -> send record + counters
 *  F6 — advertiser direct mass-DM AS the advertiser to eligible relationships only (platform 100%):
 *   GET  ui/ads/mass-dm/audience/preview                   -> [AdDmAudienceDto] (reachable count)
 *   POST ui/ads/mass-dm/campaigns                          body [AdMassDmCreateReq]   -> send record (201)
 *   GET  ui/ads/mass-dm/campaigns                          -> { sends: [...] }
 *   GET  ui/ads/mass-dm/campaigns/{id}                     -> send record + counters
 *  SHARED — recipient engagement (open/click surcharge, once + idempotent) + the per-user opt-out:
 *   POST ui/ads/messages/{ad_click_id}/open                (NO body) -> +5c open surcharge
 *   POST ui/ads/messages/{ad_click_id}/click               (NO body) -> +10c click surcharge
 *   GET  ui/ads/messages/ad-preferences                    -> { allow_ad_messages }
 *   PUT  ui/ads/messages/ad-preferences                    body [AdMessagePrefsReq] -> { allow_ad_messages }
 *
 * approve / reject / create are NON-idempotent (the repo/VM never auto-retry). open/click are idempotent
 * (the surcharge bills ONCE per message+recipient regardless of repeats). Only the TARGETED creator may
 * approve/reject (server 403); only the recipient may open/click (server 403); a double-approve is 409.
 */
interface AdMessagingApi {

    // ── F5 sponsored mass-messaging ──
    @POST("ui/ads/sponsored-messages/offers")
    suspend fun createOffer(@Body body: AdMessageOfferReq): AdMessageOfferDto

    @GET("ui/ads/sponsored-messages/offers/inbox")
    suspend fun inbox(): AdMessageOfferListDto

    @GET("ui/ads/sponsored-messages/offers/outbox")
    suspend fun outbox(): AdMessageOfferListDto

    @POST("ui/ads/sponsored-messages/offers/{id}/approve")
    suspend fun approve(@Path("id") offerId: String, @Body body: AdMessageApproveReq): AdMessageSendDto

    @POST("ui/ads/sponsored-messages/offers/{id}/reject")
    suspend fun reject(@Path("id") offerId: String, @Body body: AdMessageRejectReq): AdMessageOfferResultDto

    @GET("ui/ads/sponsored-messages/sends/{id}")
    suspend fun sponsoredSend(@Path("id") sendId: String): AdMessageSendDto

    // ── F6 advertiser direct mass-DM ──
    @GET("ui/ads/mass-dm/audience/preview")
    suspend fun audiencePreview(): AdDmAudienceDto

    @POST("ui/ads/mass-dm/campaigns")
    suspend fun createMassDm(@Body body: AdMassDmCreateReq): AdMessageSendDto

    @GET("ui/ads/mass-dm/campaigns")
    suspend fun massDmCampaigns(): AdMessageSendListDto

    @GET("ui/ads/mass-dm/campaigns/{id}")
    suspend fun massDmCampaign(@Path("id") sendId: String): AdMessageSendDto

    // ── Shared recipient engagement + per-user opt-out ──
    @POST("ui/ads/messages/{ad_click_id}/open")
    suspend fun reportOpen(@Path("ad_click_id") adClickId: String): AdMessageEngagementDto

    @POST("ui/ads/messages/{ad_click_id}/click")
    suspend fun reportClick(@Path("ad_click_id") adClickId: String): AdMessageEngagementDto

    @GET("ui/ads/messages/ad-preferences")
    suspend fun getAdPreferences(): AdMessagePrefsDto

    @PUT("ui/ads/messages/ad-preferences")
    suspend fun setAdPreferences(@Body body: AdMessagePrefsReq): AdMessagePrefsDto
}
