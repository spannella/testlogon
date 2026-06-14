package com.testlogon.android.feature.videos.detail

import com.testlogon.android.data.videos.VideoAccess
import com.testlogon.android.data.videos.VideoDetail

/**
 * AND-197 — the playable-state decision for a video, derived from the inline detail flags and the
 * (optional) authoritative `/access` result. Exactly one variant exposes a playable id ([Granted]); all
 * others gate the player. This is the most heavily unit-tested unit in the ticket.
 */
sealed interface Entitlement {
    /** The user may play; [playbackVideoId] is the only non-null playback id surfaced to the UI. */
    data class Granted(val playbackVideoId: String) : Entitlement

    /** access_mode == "subscriber_only" and the user is authenticated. */
    data object SubscriptionRequired : Entitlement

    /** ppv / purchase_available and the user is authenticated. */
    data class PurchaseRequired(val priceCents: Int?) : Entitlement

    /** subscription_upsell and the user is authenticated (buy OR subscribe). */
    data class PurchaseOrSubscribe(val priceCents: Int?) : Entitlement

    /** A gated title but the user is not signed in — prompt sign-in first. */
    data object LoginRequired : Entitlement

    /** Not playable for a non-gating reason (not ready / unknown / 4xx-mapped). */
    data class Unavailable(val reason: UnavailableReason) : Entitlement
}

/** Why a video is [Entitlement.Unavailable]. NOT_FOUND / REGION_BLOCKED come from the HTTP layer. */
enum class UnavailableReason { NOT_FOUND, REGION_BLOCKED, NOT_READY, UNKNOWN }

/**
 * AND-197 — pure, side-effect-free entitlement resolver mirroring the web `VideoAccessGate` contract.
 *
 * Precedence (deterministic, top-down):
 *  1. detail.status not playable -> Unavailable(NOT_READY).
 *  2. entitled (access.entitled == true, OR access == null && detail.isEntitled) -> Granted.
 *     (When the access call failed we fall back to the inline flag but NEVER upgrade a non-entitled
 *      result — fail closed.)
 *  3. access_mode == "subscriber_only" -> LoginRequired if !authed else SubscriptionRequired.
 *  4. subscription_upsell -> LoginRequired if !authed else PurchaseOrSubscribe(price).
 *  5. access_mode == "ppv" || purchase_available -> LoginRequired if !authed else PurchaseRequired(price).
 *  6. fallback -> Unavailable(UNKNOWN).
 *
 * NOT_FOUND and REGION_BLOCKED are produced by the error-mapping layer (404 / 403+geo_blocked), not
 * here, because the access body carries no such status.
 */
object EntitlementResolver {

    /** Statuses where playback is allowed (mirrors VideoDetail.PROCESSING_STATUSES inverse + web gate). */
    private val PLAYABLE_STATUSES = setOf("ready", "published", "live")

    private const val ACCESS_MODE_SUBSCRIBER_ONLY = "subscriber_only"
    private const val ACCESS_MODE_PPV = "ppv"

    fun resolve(
        detail: VideoDetail,
        access: VideoAccess?,
        isAuthenticated: Boolean,
    ): Entitlement {
        // 1. Not playable yet (still encoding/probing or otherwise not a playable status).
        if (!isPlayableStatus(detail.status)) return Entitlement.Unavailable(UnavailableReason.NOT_READY)

        // 2. Entitled — authoritative access wins; else fall back to inline flag (never upgrade).
        val entitled = access?.entitled ?: detail.isEntitled
        if (entitled) return Entitlement.Granted(detail.id)

        // The flags below prefer the authoritative access result, falling back to the inline detail.
        val accessMode = access?.accessMode ?: detail.accessMode
        val priceCents = access?.priceCents ?: detail.priceCentsOrNull
        val purchaseAvailable = access?.purchaseAvailable ?: detail.purchaseAvailableOrFalse
        val subscriptionUpsell = access?.subscriptionUpsell ?: detail.subscriptionUpsellOrFalse

        // 3. Subscriber-only.
        if (accessMode == ACCESS_MODE_SUBSCRIBER_ONLY) {
            return if (!isAuthenticated) Entitlement.LoginRequired else Entitlement.SubscriptionRequired
        }

        // 4. Purchase-or-subscribe upsell.
        if (subscriptionUpsell) {
            return if (!isAuthenticated) {
                Entitlement.LoginRequired
            } else {
                Entitlement.PurchaseOrSubscribe(priceCents)
            }
        }

        // 5. Pay-per-view / purchasable.
        if (accessMode == ACCESS_MODE_PPV || purchaseAvailable) {
            return if (!isAuthenticated) Entitlement.LoginRequired else Entitlement.PurchaseRequired(priceCents)
        }

        // 6. No gating flags matched — unknown.
        return Entitlement.Unavailable(UnavailableReason.UNKNOWN)
    }

    private fun isPlayableStatus(status: String): Boolean =
        status.trim().lowercase() in PLAYABLE_STATUSES
}
