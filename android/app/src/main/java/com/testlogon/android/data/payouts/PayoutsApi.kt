package com.testlogon.android.data.payouts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-258 — Retrofit interface + Moshi DTOs for the real creator-payouts surface.
 *
 * VERIFIED against reference/openapi.index.txt + reference/src/api/endpoints/payouts.ts +
 * reference/src/api/types.ts (PayoutBalance L4116, Payout L4125, PayoutCreateResp L4139,
 * PayoutActionResp L4146, PayoutListResp L4152).
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET  ui/payouts/balance            op=payout_balance_ui_payouts_balance_get  resp=200:PayoutBalanceOut
 *  - GET  ui/payouts                     op=list_payouts_ui_payouts_get            resp=200:PayoutListOut   params=limit,cursor
 *  - POST ui/payouts/request             op=create_payout_request_...              req=PayoutRequestIn resp=201:PayoutCreateOut
 *  - POST ui/payouts/{payout_id}/cancel  op=cancel_payout_request_...              resp=200:PayoutActionOut
 *  - GET  ui/payouts/wallet              PAY-50 op=wallet_summary                   resp=200:WalletSummaryOut
 *  - GET  ui/payouts/{payout_id}         PAY-50 op=payout_detail                    resp=200:PayoutDetailOut
 *
 * PAY-50 added the money-OUT read surface: GET /wallet (WalletSummaryOut) + GET /{payout_id}
 * (PayoutDetailOut w/ lifecycle timeline). Money is uniformly integer cents; timestamps are
 * epoch-SECONDS Longs. Session
 * cookies + Authorization Bearer + X-CSRF-Token are attached by core-network interceptors; the
 * operator-only user_sub / X-SESSION-ID / X-IMPERSONATION-TOKEN params are deliberately NOT sent.
 * Retrofit omits a null @Query so an unset cursor never appears on the wire.
 */
interface PayoutsApi {

    /** Current payout balance/state (available/pending/hold/total + currency + minimum). Idempotent GET. */
    @GET("ui/payouts/balance")
    suspend fun getBalance(): PayoutBalanceDto

    /**
     * PAY-50 wallet home summary: available + held(+release date) + pending + lifetime paid + total
     * earned. Reconciles to PAY-A get_available_balance (single source of truth). Idempotent GET.
     */
    @GET("ui/payouts/wallet")
    suspend fun getWallet(): WalletSummaryDto

    /**
     * PAY-50 payout statement/detail for ONE payout: lifecycle timeline + transfer ref + method
     * last-4 + fail/return/hold reason. User-scoped (403 on another creator's payout, 404 unknown).
     * Idempotent GET. Registered LAST server-side so literal GET routes win over this catch-all.
     */
    @GET("ui/payouts/{payout_id}")
    suspend fun getPayoutDetail(@Path("payout_id") payoutId: String): PayoutDetailDto

    /** Cursor-paginated payout (transfer) history, newest-first. Idempotent GET. */
    @GET("ui/payouts")
    suspend fun listPayouts(
        @Query("limit") limit: Int = DEFAULT_LIMIT,
        @Query("cursor") cursor: String? = null,
    ): PayoutListDto

    /** Request a payout of [PayoutRequestDto.amountCents]. Mutation (CSRF) — NEVER auto-retried. */
    @POST("ui/payouts/request")
    suspend fun requestPayout(@Body body: PayoutRequestDto): PayoutCreateRespDto

    /** Cancel a pending payout request. Mutation (CSRF). */
    @POST("ui/payouts/{payout_id}/cancel")
    suspend fun cancelPayout(@Path("payout_id") payoutId: String): PayoutActionRespDto

    companion object {
        const val DEFAULT_LIMIT = 20
    }
}

// ---- DTOs (AND-258) ----

/**
 * PayoutBalanceOut. All integer cents; currency string; schema defaults (minimum 1000, currency "USD").
 * Verified: types.ts PayoutBalance (L4116). The defensive empty-object defaults tolerate the flaky dev
 * host occasionally returning `200 {}`; they are NOT a relaxation of the contract.
 */
@JsonClass(generateAdapter = true)
data class PayoutBalanceDto(
    @Json(name = "available_cents") val availableCents: Long = 0,
    @Json(name = "pending_cents") val pendingCents: Long = 0,
    @Json(name = "total_earned_cents") val totalEarnedCents: Long = 0,
    @Json(name = "hold_cents") val holdCents: Long = 0,
    @Json(name = "currency") val currency: String = DEFAULT_PAYOUT_CURRENCY,
    @Json(name = "minimum_payout_cents") val minimumPayoutCents: Long = DEFAULT_MINIMUM_PAYOUT_CENTS,
)

/** PayoutListOut. Only `items` + `next_cursor` (NO `total`). Verified: types.ts PayoutListResp (L4152). */
@JsonClass(generateAdapter = true)
data class PayoutListDto(
    @Json(name = "items") val items: List<PayoutDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * PayoutOut. created_at/updated_at/completed_at are INTEGER epoch SECONDS (NOT ISO strings). No
 * per-payout currency; no arrival_at. Failure text is `reject_reason`; `method` is a free string
 * (default "bank_transfer"). Verified: types.ts Payout (L4125). Required upstream: payout_id, user_id,
 * amount_cents, status, created_at, updated_at; the rest carry server defaults.
 */
@JsonClass(generateAdapter = true)
data class PayoutDto(
    @Json(name = "payout_id") val payoutId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "method") val method: String = DEFAULT_PAYOUT_METHOD,
    @Json(name = "status") val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "notes") val notes: String = "",
    @Json(name = "reject_reason") val rejectReason: String = "",
    @Json(name = "approved_by") val approvedBy: String = "",
)

/** PayoutRequestIn. amount_cents required (minimum 100); method default "bank_transfer"; notes optional (<=500). */
@JsonClass(generateAdapter = true)
data class PayoutRequestDto(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "method") val method: String = DEFAULT_PAYOUT_METHOD,
    // PAY-52: the verified PAY-B destination the payout targets (PayoutRequestIn.method_id). Retrofit
    // omits a null field, so a legacy free-string-only request still validates server-side.
    @Json(name = "method_id") val methodId: String? = null,
    @Json(name = "notes") val notes: String = "",
)

/** PayoutCreateOut (201). Verified: types.ts PayoutCreateResp (L4139). */
@JsonClass(generateAdapter = true)
data class PayoutCreateRespDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "payout_id") val payoutId: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "status") val status: String = "",
)

/** PayoutActionOut. Verified: types.ts PayoutActionResp (L4146). */
@JsonClass(generateAdapter = true)
data class PayoutActionRespDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "payout_id") val payoutId: String = "",
    @Json(name = "status") val status: String = "",
)

// ---- PAY-50 wallet + statement DTOs ----

/**
 * WalletSummaryOut (PAY-50). Available + held (+`held_count`/`held_release_at` earliest 7-day-hold
 * release epoch) + pending (+`pending_count`) + lifetime paid + total earned. All integer cents;
 * timestamps epoch-SECONDS. Reconciles to PAY-A get_available_balance.
 */
@JsonClass(generateAdapter = true)
data class WalletSummaryDto(
    @Json(name = "available_cents") val availableCents: Long = 0,
    @Json(name = "held_cents") val heldCents: Long = 0,
    @Json(name = "held_count") val heldCount: Int = 0,
    @Json(name = "held_release_at") val heldReleaseAt: Long? = null,
    @Json(name = "pending_cents") val pendingCents: Long = 0,
    @Json(name = "pending_count") val pendingCount: Int = 0,
    @Json(name = "lifetime_paid_cents") val lifetimePaidCents: Long = 0,
    @Json(name = "total_earned_cents") val totalEarnedCents: Long = 0,
    @Json(name = "currency") val currency: String = DEFAULT_PAYOUT_CURRENCY,
    @Json(name = "minimum_payout_cents") val minimumPayoutCents: Long = DEFAULT_MINIMUM_PAYOUT_CENTS,
)

/** PayoutTimelineEvent (PAY-50). A lifecycle event: status + epoch-SECONDS ts (0 = no stored ts) + note. */
@JsonClass(generateAdapter = true)
data class PayoutTimelineEventDto(
    @Json(name = "status") val status: String = "",
    @Json(name = "ts") val ts: Long = 0,
    @Json(name = "note") val note: String = "",
)

/**
 * PayoutDetailOut (PAY-50) — the statement/detail for ONE payout. Adds to PayoutOut: method_id +
 * method_last4 (resolved from the co-located method row), fail_reason, manual_hold + hold_reason,
 * debit_reversed, transfer_provider + transfer_ref + transfer_attempts, and the lifecycle [timeline].
 */
@JsonClass(generateAdapter = true)
data class PayoutDetailDto(
    @Json(name = "payout_id") val payoutId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "method") val method: String = DEFAULT_PAYOUT_METHOD,
    @Json(name = "method_id") val methodId: String = "",
    @Json(name = "method_last4") val methodLast4: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "notes") val notes: String = "",
    @Json(name = "reject_reason") val rejectReason: String = "",
    @Json(name = "fail_reason") val failReason: String = "",
    @Json(name = "approved_by") val approvedBy: String = "",
    @Json(name = "manual_hold") val manualHold: Boolean = false,
    @Json(name = "hold_reason") val holdReason: String = "",
    @Json(name = "debit_reversed") val debitReversed: Boolean = false,
    @Json(name = "transfer_provider") val transferProvider: String = "",
    @Json(name = "transfer_ref") val transferRef: String = "",
    @Json(name = "transfer_attempts") val transferAttempts: Int = 0,
    @Json(name = "timeline") val timeline: List<PayoutTimelineEventDto> = emptyList(),
)

internal const val DEFAULT_PAYOUT_CURRENCY = "USD"
internal const val DEFAULT_PAYOUT_METHOD = "bank_transfer"
internal const val DEFAULT_MINIMUM_PAYOUT_CENTS = 1000L
