package com.testlogon.android.data.affiliates

/**
 * AND-265 (fill) — pure, framework-free affiliate create-form validation + client aggregation math.
 *
 * No Android / Retrofit / coroutine types cross this file so it is fully JVM-testable. The web
 * create contract (reference/src/api/endpoints/affiliates.ts:AffiliateLinkCreateIn) is
 * { target_type, target_id, commission_percent?, custom_code? }; the backend
 * (app/routers/affiliate_links.py:create_link) rejects an empty target_id with 400. This mirrors that
 * guard on the client so an obviously-invalid request never leaves the device, and normalizes the
 * optional custom tracking code the same way the redirect route keys on it (/r/{tracking_code}).
 *
 * Money never enters here — commission_percent is a display-only PERCENTAGE (0..100), consistent with
 * the rest of the affiliate surface which keeps percentages out of the integer-cents money graph.
 */
object AffiliateMath {

    /** Backend default target_type when the caller does not choose one (mirrors create_link's default). */
    const val DEFAULT_TARGET_TYPE: String = "catalog_item"

    /** Inclusive commission-percent bounds. A percentage is display-only, never cents. */
    const val MIN_COMMISSION_PERCENT: Int = 0
    const val MAX_COMMISSION_PERCENT: Int = 100

    /**
     * A tracking/custom code is a URL path segment (`/r/{code}`), so restrict to a safe slug alphabet.
     * Empty is allowed (server auto-generates); non-empty must match this.
     */
    private val CUSTOM_CODE_REGEX = Regex("^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")

    /** Reason a [validateCreate] call failed; null-return convention would lose the specific cause. */
    enum class CreateError { BLANK_TARGET_ID, COMMISSION_OUT_OF_RANGE, INVALID_CUSTOM_CODE }

    /**
     * Trims and validates raw create-form input into a ready-to-send [AffiliateLinkCreateRequest],
     * or returns the first [CreateError]. Blank optional fields collapse to null (omit from the wire),
     * matching the web's optional `commission_percent?` / `custom_code?`.
     */
    fun validateCreate(
        targetType: String?,
        targetId: String?,
        commissionPercent: Int?,
        customCode: String?,
    ): CreateResult {
        val id = targetId?.trim().orEmpty()
        if (id.isEmpty()) return CreateResult.Invalid(CreateError.BLANK_TARGET_ID)

        if (commissionPercent != null &&
            (commissionPercent < MIN_COMMISSION_PERCENT || commissionPercent > MAX_COMMISSION_PERCENT)
        ) {
            return CreateResult.Invalid(CreateError.COMMISSION_OUT_OF_RANGE)
        }

        val code = customCode?.trim().orEmpty()
        if (code.isNotEmpty() && !CUSTOM_CODE_REGEX.matches(code)) {
            return CreateResult.Invalid(CreateError.INVALID_CUSTOM_CODE)
        }

        val type = targetType?.trim().orEmpty().ifEmpty { DEFAULT_TARGET_TYPE }
        return CreateResult.Valid(
            AffiliateLinkCreateRequest(
                targetType = type,
                targetId = id,
                commissionPercent = commissionPercent,
                customCode = code.ifEmpty { null },
            ),
        )
    }

    /** Convenience predicate for enabling a submit button without materializing the request. */
    fun isCreatable(targetId: String?): Boolean = !targetId?.trim().isNullOrEmpty()

    sealed interface CreateResult {
        data class Valid(val request: AffiliateLinkCreateRequest) : CreateResult
        data class Invalid(val error: CreateError) : CreateResult
    }
}
