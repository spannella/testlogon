package com.testlogon.android.feature.ads.create.data

import com.testlogon.android.core.model.ads.AdAccountRef
import com.testlogon.android.core.model.ads.AdCreative
import com.testlogon.android.core.network.ads.AdAccountMutationDto
import com.testlogon.android.core.network.ads.AdCreativeDto

/** ADV-107 - the create-account mutation DTO -> domain [AdAccountRef]. */
fun AdAccountMutationDto.toDomain(): AdAccountRef = AdAccountRef(
    accountId = accountId,
    companyName = companyName,
    status = status,
)

/** ADV-109 - the creative DTO -> domain [AdCreative]. */
fun AdCreativeDto.toDomain(): AdCreative = AdCreative(
    creativeId = creativeId,
    campaignId = campaignId,
    accountId = accountId,
    format = format,
    title = title,
    status = status,
    imageUrl = imageUrl,
)
