package com.testlogon.android.core.network.callrate

import com.squareup.moshi.Json

/**
 * Call-rate (paid-calls) settings transport DTOs (web parity: src/api/endpoints/callBilling.ts +
 * src/pages/settings/CallRateSettings.tsx).
 *
 * CODEGEN NOTE: core-network has NO Moshi KSP codegen; these decode via the reflective KotlinJsonAdapterFactory on
 * the shared Moshi. Every wire key is pinned with @Json(name = ...). @JsonClass is intentionally OMITTED.
 *
 * WIRE CONTRACT (verified against app/routers/call_billing.py; relative paths, NO leading slash):
 *   GET    ui/calls/rates/{creator_id} -> CallRateDto (404 when no rate configured)
 *   POST   ui/calls/rates  <- CallRateInDto -> CallRateDto   (set/create own rate)
 *   PUT    ui/calls/rates  <- CallRateInDto -> CallRateDto   (update own rate)
 *   DELETE ui/calls/rates  -> {} (disable paid calls)
 */

data class CallRateDto(
    @Json(name = "rate_cents_per_minute") val rateCentsPerMinute: Int = 0,
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "min_balance_minutes") val minBalanceMinutes: Int = 0,
    @Json(name = "max_duration_minutes") val maxDurationMinutes: Int = 0,
)

/** Set/update body. `enabled`/`min_balance_minutes`/`max_duration_minutes` are optional server-side. */
data class CallRateInDto(
    @Json(name = "rate_cents_per_minute") val rateCentsPerMinute: Int,
    @Json(name = "enabled") val enabled: Boolean = true,
    @Json(name = "min_balance_minutes") val minBalanceMinutes: Int = 5,
    @Json(name = "max_duration_minutes") val maxDurationMinutes: Int = 120,
)
