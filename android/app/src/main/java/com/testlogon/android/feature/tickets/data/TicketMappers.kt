package com.testlogon.android.feature.tickets.data

import com.testlogon.android.core.model.tickets.SpaceMember
import com.testlogon.android.core.model.tickets.Ticket
import com.testlogon.android.core.model.tickets.TicketMessage
import com.testlogon.android.core.model.tickets.TicketSpace
import com.testlogon.android.core.network.tickets.SpaceMemberOut
import com.testlogon.android.core.network.tickets.SpaceTicketMessage
import com.testlogon.android.core.network.tickets.SpaceTicketOut
import com.testlogon.android.core.network.tickets.TicketSpaceOut

/**
 * AND-372 - DTO -> domain mappers for the READ-ONLY ticket-spaces surface.
 *
 * PLACEMENT: core-model has NO dependency on core-network's DTOs (and core-network has no domain dep), so the
 * bridging mapper lives here in the :app feature, which depends on BOTH (mirrors AND-358 CollaborationMappers /
 * AND-365 SponsorshipMappers).
 *
 * Key transforms:
 *  - enum-like fields (visibility / status / role) are kept RAW (unknown-safe - no enum parse, never throws).
 *  - memberCount is DERIVED from members.size (the wire has NO member_count field).
 *  - embedded collections (members[], messages[]) map element-wise; a list-fetch row may carry empty lists.
 *  - ownerSub / assignedToSub are NOT on the verified DTO, so they map to null (see the AND-372 assumption).
 *  - timestamps pass through as EPOCH-seconds Longs.
 */
fun TicketSpaceOut.toDomain(): TicketSpace {
    val mappedMembers = members.map { it.toDomain() }
    return TicketSpace(
        spaceId = spaceId,
        name = name,
        visibility = visibility,
        members = mappedMembers,
        memberCount = mappedMembers.size,
        updatedAt = updatedAt,
    )
}

fun SpaceMemberOut.toDomain(): SpaceMember = SpaceMember(
    userSub = userSub,
    role = role,
)

fun SpaceTicketOut.toDomain(): Ticket = Ticket(
    ticketId = ticketId,
    spaceId = spaceId,
    subject = title,
    status = status,
    ownerSub = null,
    assignedToSub = null,
    updatedAt = updatedAt,
    messages = messages.map { it.toDomain() },
)

fun SpaceTicketMessage.toDomain(): TicketMessage = TicketMessage(
    messageId = messageId,
    senderSub = senderSub,
    senderRole = senderRole,
    body = body,
    createdAt = createdAt,
)
