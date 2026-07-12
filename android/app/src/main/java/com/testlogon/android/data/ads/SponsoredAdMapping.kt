package com.testlogon.android.data.ads

import com.testlogon.android.core.model.ads.SponsoredAd
import com.testlogon.android.data.feed.SponsoredInfo

/**
 * ADV — bridge the core-model [SponsoredAd] (carried by the group / syndicate feed domain models) onto
 * the :app [SponsoredInfo] the shared [AdTrackRepository] consumes, so a sponsored unit in ANY feed fires
 * impression / click tracking through the one /ui/ads/track money-path. Kept in :app (which depends on
 * both) since core-model cannot reference SponsoredInfo.
 */
fun SponsoredAd.toSponsoredInfo(): SponsoredInfo = SponsoredInfo(
    label = label,
    headline = headline,
    ctaText = ctaText,
    ctaUrl = ctaUrl,
    adClickId = adClickId,
    creativeId = creativeId,
    campaignId = campaignId,
    accountId = accountId,
    surface = surface,
    slotType = slotType,
    creatorId = creatorId,
    contentId = contentId,
)
