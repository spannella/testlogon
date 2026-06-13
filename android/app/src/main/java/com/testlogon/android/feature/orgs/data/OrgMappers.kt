package com.testlogon.android.feature.orgs.data

import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.network.orgs.OrgInviteOut
import com.testlogon.android.core.network.orgs.OrgMemberOut
import com.testlogon.android.core.network.orgs.OrgOut

/**
 * AND-353 - DTO -> domain mappers for the organizations surface.
 *
 * PLACEMENT: core-model has no dependency on core-network's DTOs (and core-network has no domain dep), so
 * the bridging mappers live here in the feature, which depends on BOTH. org_role is parsed via
 * [OrgRole.from] (UNKNOWN fallback); member `status` is passed through as a raw String (do NOT coerce it
 * into an enum of unconfirmed status values).
 */

/** Maps an [OrgOut] to the domain [Org]; org_role becomes the caller's role. */
fun OrgOut.toDomain(): Org = Org(
    orgId = orgId,
    name = orgName,
    callerRole = OrgRole.from(orgRole),
)

/** Maps an [OrgMemberOut] to the domain [OrgMember]. status is kept raw. */
fun OrgMemberOut.toDomain(): OrgMember = OrgMember(
    userSub = userSub,
    role = OrgRole.from(orgRole),
    status = status,
    joinedAt = joinedAt,
    storageUsedBytes = storageUsedBytes,
    lastActiveAt = lastActiveAt,
)

/** Maps an [OrgInviteOut] to the domain [OrgInvite]. */
fun OrgInviteOut.toDomain(): OrgInvite = OrgInvite(
    inviteId = inviteId,
    email = email,
    role = OrgRole.from(orgRole),
    orgId = orgId,
    orgName = orgName,
    status = status,
    invitedBy = invitedBy,
    createdAt = createdAt,
    expiresAt = expiresAt,
)
