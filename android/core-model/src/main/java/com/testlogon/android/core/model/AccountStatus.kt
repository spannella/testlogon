package com.testlogon.android.core.model

/**
 * AND-082 — account standing, mirroring the backend `AccountState` contract
 * (`{ status, reason?, updated_at?, closed_at? }`; web `src/api/types.ts`).
 *
 * `updatedAtEpochSeconds` / `closedAtEpochSeconds` are epoch SECONDS (web renders `* 1000`).
 * Kept as raw longs (not java.time.Instant) so this stays JVM-unit-test-safe on minSdk 24.
 */
enum class AccountState { ACTIVE, SUSPENDED, CLOSURE_PENDING, CLOSED, UNKNOWN }

data class AccountStatus(
    val state: AccountState,
    val rawState: String,
    val reason: String? = null,
    val updatedAtEpochSeconds: Long? = null,
    val closedAtEpochSeconds: Long? = null,
) {
    companion object {
        fun stateFromWire(value: String?): AccountState = when (value?.lowercase()) {
            "active" -> AccountState.ACTIVE
            "suspended" -> AccountState.SUSPENDED
            "closure_pending" -> AccountState.CLOSURE_PENDING
            "closed" -> AccountState.CLOSED
            else -> AccountState.UNKNOWN
        }
    }
}
