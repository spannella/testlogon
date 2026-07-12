package com.testlogon.android.feature.agents.workers.data

/**
 * AGENTS-BASICS (web-parity) - framework-free domain models for the WORKERS surface. Kept in feature/data (NOT
 * core-model, which cannot depend on core-network). Times are EPOCH SECONDS (0 -> null via the mapper).
 */

/** A worker lifecycle status. UNKNOWN preserves an unrecognised server string for forward-compat display. */
enum class WorkerStatus(val wire: String) {
    PROVISIONING("provisioning"),
    INSTALLING("installing"),
    READY("ready"),
    RUNNING("running"),
    STOPPED("stopped"),
    ERROR("error"),
    TERMINATED("terminated"),
    UNKNOWN("");

    companion object {
        fun from(wire: String): WorkerStatus =
            entries.firstOrNull { it.wire == wire } ?: UNKNOWN
    }
}

/** One provision-log step. */
data class ProvisionStep(
    val step: String,
    val status: String,
    val ts: Long?,
    val detail: String,
)

/** A worker (runtime agent instance). */
data class Worker(
    val id: String,
    val label: String,
    val agentType: String,
    val tool: String,
    val toolVersion: String,
    val computeType: String,
    val instanceType: String,
    val llmKeyId: String,
    val llmProvider: String,
    val publicIp: String,
    val status: WorkerStatus,
    val statusWire: String,
    val repoUrl: String,
    val branchConvention: String,
    val idleTimeoutSeconds: Long,
    val lastActivityAt: Long?,
    val createdAt: Long?,
    val startedAt: Long?,
    val errorMessage: String,
    val provisionLog: List<ProvisionStep>,
) {
    /** True when a start action is meaningful (a stopped/errored worker can be (re)started). */
    val canStart: Boolean get() = status == WorkerStatus.STOPPED || status == WorkerStatus.ERROR
    /** True when a stop action is meaningful (a live worker can be stopped). */
    val canStop: Boolean get() = status == WorkerStatus.RUNNING || status == WorkerStatus.READY
}

/** A selectable tool for worker creation. */
data class ToolInfo(
    val tool: String,
    val displayName: String,
    val description: String,
    val requiredProvider: String,
)

/** A compute option for worker creation. */
data class ComputeOption(
    val computeType: String,
    val instanceType: String,
    val vcpu: Int,
    val memoryGb: Double,
    val costCentsPerMin: Double,
)
