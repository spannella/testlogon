package com.testlogon.android.feature.custody

/**
 * Pure, Android-free formatting + decision logic for the EXTERNAL custody provider surface
 * (internal gateway vs. a qualified custodian like Fireblocks / BitGo). Kept free of Compose,
 * Hilt and repositories so every rule -- the provider-status badge, the kind label, the
 * balances-attested label, and the withdrawal-approval stepper model -- can be unit-tested from
 * the JVM. The provider/vault/approval domain models live in data/custody/CustodyDomain.kt;
 * this object only turns those value types into display-ready primitives.
 */
object CustodyProviderFormat {

    /** Severity of a provider-status badge, ordered worst-last so a UI can pick a colour. */
    enum class Severity { NEUTRAL, GOOD, WARN, BAD }

    /** A resolved badge: the text to show plus its [severity]. */
    data class Badge(val label: String, val severity: Severity)

    // ---- provider connection status ----

    /**
     * Normalized provider connection status. wire matches the backend string; [NOT_CONNECTED] is
     * also the fallback for an unknown / blank status so the UI never shows a raw wire token.
     */
    enum class ProviderStatus(val wire: String) {
        HEALTHY("healthy"),
        DEGRADED("degraded"),
        DOWN("down"),
        NOT_CONNECTED("not_connected"),
        UNKNOWN("");

        companion object {
            fun from(wire: String?): ProviderStatus {
                val w = wire?.trim()?.lowercase().orEmpty()
                return entries.firstOrNull { it.wire == w } ?: UNKNOWN
            }
        }
    }

    /** Map a provider status to its badge (label + severity). */
    fun statusBadge(status: ProviderStatus): Badge = when (status) {
        ProviderStatus.HEALTHY -> Badge("Healthy", Severity.GOOD)
        ProviderStatus.DEGRADED -> Badge("Degraded", Severity.WARN)
        ProviderStatus.DOWN -> Badge("Down", Severity.BAD)
        ProviderStatus.NOT_CONNECTED -> Badge("Not connected", Severity.NEUTRAL)
        ProviderStatus.UNKNOWN -> Badge("Unknown", Severity.NEUTRAL)
    }

    /** Convenience: badge straight from a wire status string. */
    fun statusBadge(wire: String?): Badge = statusBadge(ProviderStatus.from(wire))

    // ---- provider kind ----

    /** The backing custodian kind: the internal MPC gateway, or an external qualified custodian. */
    enum class ProviderKind(val wire: String) {
        INTERNAL("internal"),
        FIREBLOCKS("fireblocks"),
        BITGO("bitgo"),
        UNKNOWN("");

        companion object {
            fun from(wire: String?): ProviderKind {
                val w = wire?.trim()?.lowercase().orEmpty()
                return entries.firstOrNull { it.wire == w } ?: UNKNOWN
            }
        }
    }

    /** Human label for a provider kind (used when the backend does not send a display name). */
    fun kindLabel(kind: ProviderKind): String = when (kind) {
        ProviderKind.INTERNAL -> "Internal gateway"
        ProviderKind.FIREBLOCKS -> "Fireblocks"
        ProviderKind.BITGO -> "BitGo"
        ProviderKind.UNKNOWN -> "External custodian"
    }

    fun kindLabel(wire: String?): String = kindLabel(ProviderKind.from(wire))

    /** True for the external qualified custodians (everything that is not the internal gateway). */
    fun isExternal(kind: ProviderKind): Boolean =
        kind == ProviderKind.FIREBLOCKS || kind == ProviderKind.BITGO

    // ---- attestation ----

    /**
     * Label for the balances-attestation signal returned by a provider status probe. true means the
     * custodian cryptographically attested the on-chain balances; null means the backend did not say.
     */
    fun attestationLabel(attested: Boolean?): String = when (attested) {
        true -> "Balances attested"
        false -> "Not attested"
        null -> "Attestation unknown"
    }

    fun attestationSeverity(attested: Boolean?): Severity = when (attested) {
        true -> Severity.GOOD
        false -> Severity.WARN
        null -> Severity.NEUTRAL
    }

    // ---- withdrawal approval stepper ----

    /**
     * Normalized withdrawal-approval state. The happy path advances
     * pending_approval -> approved -> signed -> broadcast; [REJECTED] is a terminal off-path state.
     */
    enum class ApprovalStatus(val wire: String, val order: Int) {
        PENDING_APPROVAL("pending_approval", 0),
        APPROVED("approved", 1),
        SIGNED("signed", 2),
        BROADCAST("broadcast", 3),
        REJECTED("rejected", -1),
        UNKNOWN("", -2);

        companion object {
            fun from(wire: String?): ApprovalStatus {
                val w = wire?.trim()?.lowercase().orEmpty()
                return entries.firstOrNull { it.wire == w } ?: UNKNOWN
            }
        }
    }

    /** The ordered happy-path steps a provider-backed withdrawal advances through. */
    val APPROVAL_STEPS: List<ApprovalStatus> = listOf(
        ApprovalStatus.PENDING_APPROVAL,
        ApprovalStatus.APPROVED,
        ApprovalStatus.SIGNED,
        ApprovalStatus.BROADCAST,
    )

    /** Human label for one approval step / status. */
    fun approvalLabel(status: ApprovalStatus): String = when (status) {
        ApprovalStatus.PENDING_APPROVAL -> "Pending approval"
        ApprovalStatus.APPROVED -> "Approved"
        ApprovalStatus.SIGNED -> "Signed"
        ApprovalStatus.BROADCAST -> "Broadcast"
        ApprovalStatus.REJECTED -> "Rejected"
        ApprovalStatus.UNKNOWN -> "Unknown"
    }

    /** Where one step stands relative to the current [ApprovalStatus]. */
    enum class StepState { DONE, CURRENT, UPCOMING, REJECTED }

    /** One rendered stepper row: the step, its label, and its state relative to current. */
    data class Step(val status: ApprovalStatus, val label: String, val state: StepState)

    /**
     * Build the ordered stepper model for a withdrawal whose current status is [current].
     *
     * On the happy path each step is DONE (index < current), CURRENT (== current) or UPCOMING
     * (> current). On a REJECTED withdrawal the whole stepper is marked REJECTED so the UI can show
     * the flow was aborted. An UNKNOWN status renders every step UPCOMING (nothing has happened yet).
     */
    fun stepper(current: ApprovalStatus): List<Step> {
        if (current == ApprovalStatus.REJECTED) {
            return APPROVAL_STEPS.map { Step(it, approvalLabel(it), StepState.REJECTED) }
        }
        val curIdx = APPROVAL_STEPS.indexOfFirst { it == current }
        return APPROVAL_STEPS.mapIndexed { idx, step ->
            val state = when {
                curIdx < 0 -> StepState.UPCOMING
                idx < curIdx -> StepState.DONE
                idx == curIdx -> StepState.CURRENT
                else -> StepState.UPCOMING
            }
            Step(step, approvalLabel(step), state)
        }
    }

    fun stepper(wire: String?): List<Step> = stepper(ApprovalStatus.from(wire))

    /** True once the withdrawal has reached a terminal state (broadcast or rejected). */
    fun isTerminal(status: ApprovalStatus): Boolean =
        status == ApprovalStatus.BROADCAST || status == ApprovalStatus.REJECTED

    /**
     * Compact quorum label like "2 of 3" from the approvals collected so far vs. the required quorum.
     * Clamps negatives to 0.
     */
    fun quorumLabel(collected: Int, quorum: Int): String {
        val c = collected.coerceAtLeast(0)
        val q = quorum.coerceAtLeast(0)
        return "$c of $q"
    }
}
