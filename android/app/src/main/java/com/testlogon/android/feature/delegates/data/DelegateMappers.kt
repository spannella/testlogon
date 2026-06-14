package com.testlogon.android.feature.delegates.data

import com.testlogon.android.core.model.delegates.ManagedCreator
import com.testlogon.android.core.network.delegates.ManagedCreatorOut

/**
 * AND-359 - DTO -> domain mappers for the delegate surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so
 * the bridging mapper lives here in the feature, which depends on BOTH - identical to the AND-353
 * OrgMappers placement. The single human field `label` is carried through verbatim; `status` / `preset`
 * stay raw Strings (the contract does not pin confirmed enums).
 */

/** Maps a [ManagedCreatorOut] to the domain [ManagedCreator]. */
fun ManagedCreatorOut.toDomain(): ManagedCreator = ManagedCreator(
    creatorId = creatorId,
    permissions = permissions,
    preset = preset,
    status = status,
    label = label,
    acceptedAt = acceptedAt,
)
