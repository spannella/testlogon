package com.testlogon.android.data.account

import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.AccountStatus
import com.testlogon.android.data.preferences.AccountStatusDto

/**
 * AND-387 - domain result of `closure/start`. CORRECTED (spec §4 / §16 claim 5): closure/start returns the
 * re-auth challenge `{auth_required, challenge_id, required_factors}`, NOT a closure id / grace fields.
 * [challengeId] is carried into `closure/finalize`. The factor list is backend-driven and may be empty.
 */
data class ClosureStartResult(
    val authRequired: Boolean,
    val challengeId: String,
    val requiredFactors: List<String>,
)

/**
 * AND-387 - DTO -> domain mappers (kept in :app per the module contract; core-model has no Moshi/Retrofit).
 */

/** Maps the closure/start DTO to [ClosureStartResult]. A missing/blank challenge id maps to empty string so
 *  the caller (repository) can detect the malformed-contract case rather than crashing. */
fun ClosureStartDto.toDomain(): ClosureStartResult = ClosureStartResult(
    authRequired = authRequired,
    challengeId = challengeId.orEmpty(),
    requiredFactors = requiredFactors,
)

/**
 * Maps the suspend/reactivate AccountState DTO to the shared [AccountStatus] domain model (the same mapper
 * shape AND-082 uses for the status GET). Unknown wire `status` values map to [AccountState.UNKNOWN] and
 * additive fields are ignored; timestamps stay epoch SECONDS.
 */
fun AccountStatusDto.toAccountStatus(): AccountStatus = AccountStatus(
    state = AccountStatus.stateFromWire(status),
    rawState = status.orEmpty(),
    reason = reason,
    updatedAtEpochSeconds = updatedAt,
    closedAtEpochSeconds = closedAt,
)

/**
 * Maps the `closure/finalize` `{status}` body to an [AccountStatus]. Finalize only echoes a status string
 * (no timestamps); a successful finalize yields `status == "closed"` -> [AccountState.CLOSED].
 */
fun StatusOutDto.toAccountStatus(): AccountStatus = AccountStatus(
    state = AccountStatus.stateFromWire(status),
    rawState = status.orEmpty(),
)
