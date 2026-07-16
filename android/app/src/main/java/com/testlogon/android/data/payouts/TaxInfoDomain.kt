package com.testlogon.android.data.payouts

/**
 * PAY-22 — framework-free W-9 tax-info domain models + DTO -> domain mapper.
 *
 * The stored view is always MASKED: only [tinLast4] is ever present (the raw SSN/EIN is tokenized
 * server-side and never returned). [W9Submission] is the transient write-only input the form collects;
 * its raw [tin] is sent once over TLS and never persisted app-side.
 */

/** The masked W-9 status for the pre-withdrawal gate. */
data class PayoutTaxInfo(
    val onFile: Boolean,
    val legalName: String,
    val tinLast4: String,
    val tinType: String,
    val addressLine1: String,
    val city: String,
    val state: String,
    val zipCode: String,
    val certified: Boolean,
    val certifiedAt: Long?,
) {
    /** The backend withdraw gate requires a CERTIFIED W-9 on file (a draft is treated as not-on-file). */
    val satisfiesGate: Boolean get() = onFile && certified

    /** A masked TIN string for display (never the raw value); blank when nothing on file. */
    val maskedTin: String get() = if (tinLast4.isNotBlank()) "•••-••-$tinLast4" else ""

    companion object {
        val NONE = PayoutTaxInfo(
            onFile = false,
            legalName = "",
            tinLast4 = "",
            tinType = "",
            addressLine1 = "",
            city = "",
            state = "",
            zipCode = "",
            certified = false,
            certifiedAt = null,
        )
    }
}

/** W-9 TIN kind. */
enum class TinType(val wire: String) { SSN("ssn"), EIN("ein") }

/** The transient W-9 collection input. The raw [tin] is WRITE-ONLY (sent over TLS, never persisted). */
data class W9Submission(
    val legalName: String,
    val tin: String,
    val tinType: TinType,
    val addressLine1: String,
    val city: String,
    val state: String,
    val zipCode: String,
    val certified: Boolean,
)

internal fun PayoutTaxInfoDto.toDomain(): PayoutTaxInfo = PayoutTaxInfo(
    onFile = onFile,
    legalName = legalName,
    tinLast4 = tinLast4,
    tinType = tinType,
    addressLine1 = addressLine1,
    city = city,
    state = state,
    zipCode = zipCode,
    certified = certified,
    certifiedAt = certifiedAt,
)

internal fun W9Submission.toDto(): W9SubmitDto = W9SubmitDto(
    legalName = legalName.trim(),
    tin = tin.filter { it.isDigit() },
    tinType = tinType.wire,
    addressLine1 = addressLine1.trim(),
    city = city.trim(),
    state = state.trim().uppercase(),
    zipCode = zipCode.trim(),
    certified = certified,
)
