package com.testlogon.android.core.model.delegates

/**
 * AND-359 - domain model for the delegate / delegation surface (manage-as-creator mode).
 *
 * core-model has NO Moshi and NO core-network dependency: these are plain domain types. The wire DTOs
 * (core-network ManagedCreatorOut) are bridged to these domain types by a mapper that lives in the module
 * which depends on BOTH core-network and core-model (mirroring the AND-353 OrgMappers placement) - it can
 * NOT live here because core-model can not see the DTO type. See DelegateMappers in the data layer.
 *
 * The only human-readable field is [label] (there is intentionally NO display_name / username /
 * avatar_url). [status] and [preset] are kept as raw Strings (the contract does not pin confirmed enums).
 */

/**
 * One creator the current principal MAY manage as a delegate (the picker source). [creatorId] is the
 * identity used for path-scoping downstream; [permissions] is the granted permission tokens.
 */
data class ManagedCreator(
    val creatorId: String,
    val permissions: List<String> = emptyList(),
    val preset: String? = null,
    val status: String? = null,
    val label: String? = null,
    val acceptedAt: String? = null,
) {
    /**
     * AND-359 - projects this managed creator into the lighter [ManagingCreator] that the
     * DelegationStateStore observes once the principal ENTERS manage-as mode. Carries creatorId / label /
     * permissions only.
     */
    fun toManagingCreator(): ManagingCreator = ManagingCreator(
        creatorId = creatorId,
        label = label,
        permissions = permissions,
    )
}

/**
 * AND-359 - the ACTIVE manage-as-creator selection. Held by the DelegationStateStore as an observable,
 * process-global flag (mirrors the web authStore.setManagingCreator). When non-null, downstream features
 * path-scope their traffic to ui/.../delegate/{creatorId}/... using [creatorId]; null means the principal
 * is acting as themselves. There is NO enter / exit / current network endpoint - this is pure local state.
 */
data class ManagingCreator(
    val creatorId: String,
    val label: String? = null,
    val permissions: List<String> = emptyList(),
)
