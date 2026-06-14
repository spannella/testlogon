package com.testlogon.android.feature.broadcast.host

import com.testlogon.android.data.broadcast.BroadcastSessionStatus

/**
 * AND-309 — PURE (android-free, side-effect-free) policy deciding which host lifecycle actions are
 * permitted for a given [BroadcastSessionStatus]. Drives both the ViewModel double-guard and the UI button
 * enablement so they can never disagree.
 *
 * The shared [BroadcastSessionStatus] enum has DRAFT, SCHEDULED, PROVISIONING, READY, LIVE, STOPPING,
 * STOPPED, CANCELLED, ERROR, UNKNOWN — all members AND-309 needs already exist, so NO additive enum change
 * was required (and no exhaustive `when` over the enum needed fixing).
 *
 * NOTE: there is NO PAUSED / INTERRUPTED member (host media is FLAGGED — no real ingest-drop signal). So
 * resumability is modeled as a CLIENT boolean ([canResume]'s `resumable`), NOT an enum state.
 */
object HostControlPolicy {

    /** Start (go-live) is offered before the session is live: a SCHEDULED or READY session. */
    fun canStart(status: BroadcastSessionStatus): Boolean =
        status == BroadcastSessionStatus.SCHEDULED || status == BroadcastSessionStatus.READY

    /**
     * Stop is offered only for a LIVE session. (PAUSED / INTERRUPTED would also qualify, but those members
     * do not exist — host media is FLAGGED — so the gate is strictly LIVE.)
     */
    fun canStop(status: BroadcastSessionStatus): Boolean =
        status == BroadcastSessionStatus.LIVE

    /**
     * Resume is offered only when the client flags the session [resumable] AND the lifecycle is in a
     * resumable-ish (non-terminal, post-provision) state. Terminal / pre-go-live states never resume.
     */
    fun canResume(status: BroadcastSessionStatus, resumable: Boolean): Boolean =
        resumable && (
            status == BroadcastSessionStatus.LIVE ||
                status == BroadcastSessionStatus.STOPPING ||
                status == BroadcastSessionStatus.READY ||
                status == BroadcastSessionStatus.PROVISIONING
            )

    /** Reschedule is offered only before go-live: a SCHEDULED or READY session. */
    fun canReschedule(status: BroadcastSessionStatus): Boolean =
        status == BroadcastSessionStatus.SCHEDULED || status == BroadcastSessionStatus.READY
}
