package com.testlogon.android.core.ui.input

import androidx.compose.ui.unit.dp

/** Shared sizing/spacing constants for core input composables (AND-020). */
internal object InputTokens {
    val FieldSpacing = 4.dp
    val OtpCellSize = 44.dp
    val OtpCellGap = 8.dp
    val ButtonMinHeight = 48.dp
}

/** Filters [raw] down to digits only and caps it at [length]. Single source of OTP sanitization. */
internal fun sanitizeOtp(raw: String, length: Int): String =
    raw.filter { it.isDigit() }.take(length.coerceAtLeast(0))
