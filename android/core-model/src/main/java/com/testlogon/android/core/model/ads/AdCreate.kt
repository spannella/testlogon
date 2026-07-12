package com.testlogon.android.core.model.ads

/**
 * ADV-107/108/109 - lightweight domain types for the advertiser CREATE flow outcomes (create ad account /
 * create creative). The created CAMPAIGN reuses the existing AND-369 [AdCampaign] domain, and account/campaign
 * PICKER rows reuse [AdAccountSummary] / [AdCampaign] - so only the two types below are new.
 *
 * core-model has NO Moshi dependency: these are plain domain types mapped from the core-network mutation DTOs
 * by the feature-layer AdsCreateMappers. [status] is the RAW server lifecycle token (pending_review / draft /
 * approved) kept verbatim so the create screens can show the exact state the reviewer will act on.
 */

/** The outcome of creating an advertiser account: the new id + echoed company name + raw lifecycle status. */
data class AdAccountRef(
    val accountId: String,
    val companyName: String? = null,
    val status: String? = null,
)

/**
 * A creative created (and optionally asset-uploaded / submitted) under a campaign. [imageUrl] is populated
 * after a successful asset upload; [status] is the raw lifecycle token (draft before submit, pending_review
 * after). Money/time are not carried here (the create screen only needs identity + status + preview).
 */
data class AdCreative(
    val creativeId: String,
    val campaignId: String? = null,
    val accountId: String? = null,
    val format: String? = null,
    val title: String? = null,
    val status: String? = null,
    val imageUrl: String? = null,
)
