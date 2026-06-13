package com.testlogon.android.feature.guest

import com.testlogon.android.data.broadcast.BroadcastInput
import java.time.Instant

/**
 * AND-312 - canonical (DTO-free) domain + mappers for the broadcast GUEST surface.
 *
 * A guest is a broadcast INPUT whose input_type == "guest" (AND-310 [BroadcastInput]) merged with a
 * guest-invite resource. The host-facing [Guest] joins the two by input_id; its DISPLAY [status] is DERIVED
 * from the invite status plus the matching input's is_live (see [deriveGuestStatus]). [mutedAudio] is
 * CLIENT-TRACKED from the last successful mute POST - there is NO wire echo for it.
 *
 * Unknown wire enum strings coerce to a safe default and NEVER throw. The invite's stream_key is a SECRET
 * and is never logged or surfaced beyond the host invite card.
 */

/**
 * AND-312 - DERIVED display status for a guest as the host sees them.
 *
 * INVITED  - a pending invite, not yet accepted.
 * JOINED   - accepted invite, input present but not live (connected, off-air).
 * ONAIR    - accepted + the matching input is_live == true (on air).
 * MUTED    - client-tracked: accepted/on-air but the host last muted them (overlay over JOINED/ONAIR).
 * LEFT     - invite expired (the guest's window lapsed without an active input).
 * REMOVED  - invite revoked by the host.
 */
enum class GuestStatus {
    INVITED,
    JOINED,
    ONAIR,
    MUTED,
    LEFT,
    REMOVED,
}

/** AND-312 - the wire invite lifecycle status. Unknown / null -> [PENDING] (never throws). */
enum class InviteStatus {
    PENDING,
    ACCEPTED,
    REVOKED,
    EXPIRED,
    ;

    companion object {
        /** Coerces a wire `status` string to an [InviteStatus]; unknown / null -> [PENDING] (never throws). */
        fun fromWire(value: String?): InviteStatus = when (value?.lowercase()) {
            "pending" -> PENDING
            "accepted" -> ACCEPTED
            "revoked" -> REVOKED
            "expired" -> EXPIRED
            else -> PENDING
        }
    }
}

/**
 * AND-312 - a host-facing guest = the merge of an invite and its (optional) matching guest input.
 *
 * [inviteId] is null for an input that has no matching invite (a guest input created out-of-band); [status]
 * is then derived from the input alone. [mutedAudio] is client-tracked (no wire field). [connectedAt] is the
 * input's connection instant (null when off-air / not connected).
 */
data class Guest(
    val inputId: String,
    val inviteId: String?,
    val sessionId: String,
    val displayName: String,
    val status: GuestStatus,
    val mutedAudio: Boolean,
    val connectedAt: Instant?,
    val isLive: Boolean,
)

/**
 * AND-312 - a host-created guest invite (the invite card model). [streamKey] is a SECRET (never logged);
 * [url] is the shareable accept link, [ingestUrl] the RTMP target for rtmp-mode guests.
 */
data class GuestInvite(
    val inviteId: String,
    val sessionId: String,
    val inputId: String?,
    val url: String?,
    val ingestUrl: String?,
    val streamKey: String?,
    val joinMode: String,
    val status: InviteStatus,
    val expiresAt: Instant?,
    val createdAt: String,
    val guestDisplayName: String?,
)

/** AND-312 - the result a guest receives after accepting (surfaced for the AND-308 media handoff). */
data class GuestAcceptResult(
    val inviteId: String,
    val inputId: String,
    val joinMode: String,
    val sessionId: String,
    val ingestUrl: String?,
)

// --- DTO -> domain mappers (pure; android-free) ----------------------------------------------------

/** AND-312 - epoch SECONDS -> Instant (null-safe; never throws). */
private fun Long?.epochSecondsToInstant(): Instant? = this?.let { Instant.ofEpochSecond(it) }

/** AND-312 - maps a [GuestInviteDto] to the [GuestInvite] domain. */
fun GuestInviteDto.toInvite(): GuestInvite = GuestInvite(
    inviteId = inviteId,
    sessionId = sessionId,
    inputId = inputId,
    url = inviteUrl,
    ingestUrl = ingestUrl,
    streamKey = streamKey,
    joinMode = joinMode,
    status = InviteStatus.fromWire(status),
    expiresAt = expiresAt.epochSecondsToInstant(),
    createdAt = createdAt.orEmpty(),
    guestDisplayName = guestDisplayName,
)

/** AND-312 - maps a [GuestAcceptDto] to the [GuestAcceptResult] domain. */
fun GuestAcceptDto.toResult(): GuestAcceptResult = GuestAcceptResult(
    inviteId = inviteId,
    inputId = inputId,
    joinMode = joinMode,
    sessionId = sessionId,
    ingestUrl = ingestUrl,
)

/**
 * AND-312 - derives the display [GuestStatus] from the (optional) invite status and the matching input's
 * is_live. [muted] is the client-tracked mute flag and overlays an accepted/live guest as [GuestStatus.MUTED].
 *
 * Rules (in order):
 *  - revoked invite                          -> REMOVED
 *  - expired invite                          -> LEFT
 *  - matching input is_live == true          -> MUTED (if muted) else ONAIR
 *  - accepted invite (input present, off-air)-> MUTED (if muted) else JOINED
 *  - pending invite (no input yet)           -> INVITED
 */
fun deriveGuestStatus(
    invite: InviteStatus?,
    isLive: Boolean,
    hasInput: Boolean,
    muted: Boolean,
): GuestStatus = when {
    invite == InviteStatus.REVOKED -> GuestStatus.REMOVED
    invite == InviteStatus.EXPIRED -> GuestStatus.LEFT
    isLive -> if (muted) GuestStatus.MUTED else GuestStatus.ONAIR
    invite == InviteStatus.ACCEPTED || hasInput -> if (muted) GuestStatus.MUTED else GuestStatus.JOINED
    else -> GuestStatus.INVITED
}

/**
 * AND-312 - MERGES guest invites with guest inputs into the host-facing [Guest] list, keyed by input_id.
 *
 * The merge prefers a row per matching (invite, input) pair; invites without a matching input still surface
 * (pending invites have no input yet) keyed by their invite_id placeholder, and guest inputs without an
 * invite surface keyed by their input_id. [muted] supplies the per-input client-tracked mute overlay.
 */
fun mergeGuests(
    sessionId: String,
    invites: List<GuestInvite>,
    guestInputs: List<BroadcastInput>,
    muted: Set<String>,
): List<Guest> {
    val inputsById = guestInputs.associateBy { it.inputId }
    val result = mutableListOf<Guest>()
    val consumedInputIds = mutableSetOf<String>()

    // 1) One row per invite, joined to its matching input by input_id when present.
    for (invite in invites) {
        val input = invite.inputId?.let { inputsById[it] }
        if (input != null) consumedInputIds += input.inputId
        val inputId = input?.inputId ?: invite.inputId ?: invite.inviteId
        val isLive = input?.isLive == true
        val isMuted = muted.contains(inputId)
        result += Guest(
            inputId = inputId,
            inviteId = invite.inviteId,
            sessionId = sessionId,
            displayName = displayNameFor(input, invite),
            status = deriveGuestStatus(
                invite = invite.status,
                isLive = isLive,
                hasInput = input != null,
                muted = isMuted,
            ),
            mutedAudio = isMuted,
            connectedAt = input?.connectedAt?.let { Instant.ofEpochSecond(it) },
            isLive = isLive,
        )
    }

    // 2) Guest inputs with NO matching invite (created out-of-band) still surface for host control.
    for (input in guestInputs) {
        if (consumedInputIds.contains(input.inputId)) continue
        val isMuted = muted.contains(input.inputId)
        result += Guest(
            inputId = input.inputId,
            inviteId = null,
            sessionId = sessionId,
            displayName = input.label?.takeIf { it.isNotBlank() } ?: input.inputId,
            status = deriveGuestStatus(
                invite = null,
                isLive = input.isLive,
                hasInput = true,
                muted = isMuted,
            ),
            mutedAudio = isMuted,
            connectedAt = input.connectedAt?.let { Instant.ofEpochSecond(it) },
            isLive = input.isLive,
        )
    }

    return result
}

/** AND-312 - prefer the input label, else the invite's recorded guest display name, else the input id. */
private fun displayNameFor(input: BroadcastInput?, invite: GuestInvite): String =
    input?.label?.takeIf { it.isNotBlank() }
        ?: invite.guestDisplayName?.takeIf { it.isNotBlank() }
        ?: (invite.inputId ?: invite.inviteId)
