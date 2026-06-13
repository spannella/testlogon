package com.testlogon.android.feature.kyc

import androidx.annotation.StringRes
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.model.MAX_TIER

// AND-320 — CLIENT-SIDE presentation maps: tier level -> name @StringRes and requirement key -> label
// @StringRes. These are not on the wire (the API returns integer tiers and opaque requirement keys), so
// they live in the feature and resolve to strings.xml entries. Unknown tier levels / requirement keys
// fall back gracefully (a clamped "unverified" name / the raw key as its own label).

/** Maps a tier [level] (0..[MAX_TIER]) to its display-name string resource. */
@StringRes
fun tierNameRes(level: Int): Int = when (level.coerceIn(0, MAX_TIER)) {
    0 -> R.string.kyc_tier_name_0
    1 -> R.string.kyc_tier_name_1
    2 -> R.string.kyc_tier_name_2
    3 -> R.string.kyc_tier_name_3
    else -> R.string.kyc_tier_name_4
}

/**
 * Maps a requirement [key] to its label string resource, or null when the key is unknown (the UI then
 * shows the raw key so a new server-side requirement is never invisible).
 */
@StringRes
fun requirementLabelRes(key: String): Int? = when (key) {
    "email_verified" -> R.string.kyc_req_email_verified
    "phone_verified" -> R.string.kyc_req_phone_verified
    "kyc_case_approved" -> R.string.kyc_req_kyc_case_approved
    "proof_of_address" -> R.string.kyc_req_proof_of_address
    "verification_call" -> R.string.kyc_req_verification_call
    "questionnaire_completed" -> R.string.kyc_req_questionnaire_completed
    "business_kyc_approved" -> R.string.kyc_req_business_kyc_approved
    "api_access_approved" -> R.string.kyc_req_api_access_approved
    "tier_1" -> R.string.kyc_req_tier_1
    "tier_2" -> R.string.kyc_req_tier_2
    "tier_3" -> R.string.kyc_req_tier_3
    else -> null
}
