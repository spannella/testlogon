package com.testlogon.android.feature.boost.data

import com.testlogon.android.core.model.ads.BoostCancelResult
import com.testlogon.android.core.model.ads.BoostSpend
import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.core.network.ads.ContentBoostCancelOut
import com.testlogon.android.core.network.ads.ContentBoostOut
import com.testlogon.android.core.network.ads.ContentBoostSpendOut

/**
 * AND-364 - DTO -> domain mappers for the content-boost surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so
 * the bridging mappers live here in the feature, which depends on BOTH (mirrors AND-353 OrgMappers). The
 * wire `status` is parsed via [BoostStatus.from] (UNKNOWN fallback) AND retained raw on
 * [ContentBoost.status]; *_cents stay Long (overflow-proof) and ends_at stays an epoch Long.
 */

/** Maps a [ContentBoostOut] to the domain [ContentBoost], keeping the raw status + the typed parse. */
fun ContentBoostOut.toDomain(): ContentBoost = ContentBoost(
    boostId = boostId,
    status = status,
    statusEnum = BoostStatus.from(status),
    budgetCents = budgetCents,
    spentCents = spentCents,
    remainingCents = remainingCents,
    durationSeconds = durationSeconds,
    endsAt = endsAt,
)

/** Maps a [ContentBoostSpendOut] to the domain [BoostSpend]. */
fun ContentBoostSpendOut.toDomain(): BoostSpend = BoostSpend(
    spentCents = spentCents,
    remainingCents = remainingCents,
)

/** Maps a [ContentBoostCancelOut] to the domain [BoostCancelResult]. */
fun ContentBoostCancelOut.toDomain(): BoostCancelResult = BoostCancelResult(
    boostId = boostId,
    status = status,
    refundedCents = refundedCents,
)
