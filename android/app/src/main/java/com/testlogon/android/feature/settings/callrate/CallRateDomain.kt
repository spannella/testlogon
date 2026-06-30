package com.testlogon.android.feature.settings.callrate

/** Framework-free domain model for the caller's paid-call rate (mirrors the web CallRateSettings page). */
data class CallRate(
    val rateCentsPerMinute: Int,
    val enabled: Boolean,
    val currency: String,
    val minBalanceMinutes: Int,
    val maxDurationMinutes: Int,
)
