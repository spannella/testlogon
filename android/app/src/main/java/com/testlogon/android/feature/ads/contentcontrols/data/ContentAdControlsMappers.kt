package com.testlogon.android.feature.ads.contentcontrols.data

import com.testlogon.android.core.model.ads.AdDensity
import com.testlogon.android.core.model.ads.AdRevenueBreakdown
import com.testlogon.android.core.model.ads.AdRevenueContent
import com.testlogon.android.core.model.ads.AdvertiserTransparency
import com.testlogon.android.core.model.ads.ContentAdOverride
import com.testlogon.android.core.network.ads.AdRevenueBreakdownContentDto
import com.testlogon.android.core.network.ads.AdRevenueBreakdownDto
import com.testlogon.android.core.network.ads.AdvertiserTransparencyDto
import com.testlogon.android.core.network.ads.ContentAdOverrideDto

/**
 * DTO -> domain mappers for the CONTENT AD-CONTROLS surface. core-model has no core-network dependency, so
 * the bridging mappers live here in the feature (mirrors BoostMappers / OrgMappers). ad_density is parsed
 * via [AdDensity.from] (STANDARD fallback); *_cents stay Long; updated_at stays an epoch Long.
 */

fun ContentAdOverrideDto.toDomain(): ContentAdOverride = ContentAdOverride(
    contentId = contentId,
    contentType = contentType,
    adEnabled = adEnabled,
    adDensity = AdDensity.from(adDensity),
    preRollEnabled = preRollEnabled,
    midRollEnabled = midRollEnabled,
    adsFreeForSubscribers = adsFreeForSubscribers,
    updatedAt = updatedAt,
)

fun AdRevenueBreakdownContentDto.toDomain(): AdRevenueContent = AdRevenueContent(
    contentId = contentId,
    revenueCents = revenueCents,
)

fun AdRevenueBreakdownDto.toDomain(): AdRevenueBreakdown = AdRevenueBreakdown(
    totalAdRevenueCents = totalAdRevenueCents,
    entryCount = entryCount,
    days = days,
    revenueShareBps = revenueShareBps,
    topContent = topContent.map { it.toDomain() },
)

fun AdvertiserTransparencyDto.toDomain(): AdvertiserTransparency = AdvertiserTransparency(
    accountId = accountId,
    companyName = companyName,
    totalImpressions = totalImpressions,
    totalClicks = totalClicks,
    totalRevenueCents = totalRevenueCents,
)
