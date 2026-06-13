package com.testlogon.android.core.ui.safety

import com.testlogon.android.core.ui.i18n.UiText
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * AND-388 - the four-phase lifecycle of an irreversible / destructive trust and safety action.
 *
 * Every such action (block, report, DMCA filing, account-deletion export) traverses
 * Idle -> Confirming -> Submitting -> (Submitted | Failed). Modelling it as a typed, exhaustive
 * sealed interface lets each host ViewModel render the phase without re-implementing the
 * confirmation invariant, and lets the guard be unit-tested without Android (spec sec.4.1, FR-1).
 *
 * @param A the action payload staged for submission (e.g. a report draft, a DMCA form, or Unit).
 */
sealed interface GuardPhase<out A> {

    /** No staged action; the resting state. */
    data object Idle : GuardPhase<Nothing>

    /**
     * An action has been staged and is awaiting an explicit [IrreversibleActionGuard.confirm].
     * [acknowledged] tracks the typed legal/contractual acknowledgement (FR-2) for actions that
     * require it; it has no effect for guards constructed without that requirement.
     */
    data class Confirming<A>(val action: A, val acknowledged: Boolean = false) : GuardPhase<A>

    /** The action is in flight; repeated confirms are ignored (FR-4 re-entrancy guard). */
    data class Submitting<A>(val action: A) : GuardPhase<A>

    /** Terminal success. */
    data object Submitted : GuardPhase<Nothing>

    /** Terminal failure carrying a resolved-at-the-edge [UiText] for the host banner. */
    data class Failed(val error: UiText) : GuardPhase<Nothing>
}

/**
 * AND-388 - the single, framework-free choke point that enforces the destructive-action invariant
 * for every trust and safety action.
 *
 * It owns no coroutines and performs no I/O: the host ViewModel calls [confirm]; if it returns a
 * non-null action the ViewModel launches the repository call and reports [onSuccess] / [onFailure].
 * This keeps the load-bearing safety invariants (FR-1, FR-2, FR-4) in one exhaustively-tested unit.
 *
 * Invariants:
 *  - [request] only opens [GuardPhase.Confirming]; it never submits (FR-1).
 *  - [confirm] moves to [GuardPhase.Submitting] only from [GuardPhase.Confirming], and only when
 *    acknowledgement (if required) is satisfied (FR-1, FR-2).
 *  - A second [confirm] while [GuardPhase.Submitting] returns null - the duplicate-submission
 *    guard against a double-tap creating two reports / two DMCA filings (FR-4).
 *  - [cancel] returns to [GuardPhase.Idle] only from [GuardPhase.Confirming]; a no-op elsewhere
 *    (FR-3).
 *
 * @param requiresAcknowledgement when true, [confirm] is rejected until [setAcknowledged]`(true)`
 *   has been called during [GuardPhase.Confirming] (DMCA, account-deletion export; spec sec.4.2/R4).
 */
class IrreversibleActionGuard<A>(
    private val requiresAcknowledgement: Boolean = false,
) {

    private val _phase = MutableStateFlow<GuardPhase<A>>(GuardPhase.Idle)

    /** The observable phase; the host ViewModel mirrors this into its UiState. */
    val phase: StateFlow<GuardPhase<A>> = _phase.asStateFlow()

    /** Stage [action] for confirmation. Opens [GuardPhase.Confirming]; never submits (FR-1). */
    fun request(action: A) {
        _phase.value = GuardPhase.Confirming(action)
    }

    /**
     * Toggle the acknowledgement flag while [GuardPhase.Confirming]; a no-op in any other phase
     * (FR-2). For guards without [requiresAcknowledgement] this is purely informational.
     */
    fun setAcknowledged(value: Boolean) {
        val confirming = _phase.value as? GuardPhase.Confirming<A> ?: return
        _phase.value = confirming.copy(acknowledged = value)
    }

    /** Discard the staged action and return to [GuardPhase.Idle], only from Confirming (FR-3). */
    fun cancel() {
        if (_phase.value is GuardPhase.Confirming<*>) {
            _phase.value = GuardPhase.Idle
        }
    }

    /**
     * Attempt to confirm the staged action.
     *
     * @return the action to submit, or null if confirmation is not yet valid (not Confirming,
     *   or acknowledgement required but absent) or a submission is already in flight (FR-1/2/4).
     *   On a successful confirm the phase moves to [GuardPhase.Submitting].
     */
    fun confirm(): A? {
        val confirming = _phase.value as? GuardPhase.Confirming<A> ?: return null
        if (requiresAcknowledgement && !confirming.acknowledged) return null
        _phase.value = GuardPhase.Submitting(confirming.action)
        return confirming.action
    }

    /** Move to terminal [GuardPhase.Submitted] after the repository call succeeded. */
    fun onSuccess() {
        _phase.value = GuardPhase.Submitted
    }

    /** Move to terminal [GuardPhase.Failed] carrying [error] after the repository call failed. */
    fun onFailure(error: UiText) {
        _phase.value = GuardPhase.Failed(error)
    }

    /** Reset to [GuardPhase.Idle] from any phase (e.g. when the host dismisses the flow). */
    fun reset() {
        _phase.value = GuardPhase.Idle
    }
}
