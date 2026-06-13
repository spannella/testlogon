package com.testlogon.android.core.data.delegates

import com.testlogon.android.core.model.delegates.ManagingCreator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-359 - process-global, observable holder for the ACTIVE manage-as-creator selection.
 *
 * STORE DECISION (divergence from the spec's "extend AuthStateStore", deliberate): the existing
 * AuthStateStore is an interface faked across many feature tests, so adding a member there would break
 * every fake. Instead this is a NEW, small, PARALLEL store. It mirrors the web authStore.setManagingCreator
 * flag exactly: entering / exiting delegate mode is a PURE LOCAL mutation - there is NO enter / exit /
 * current network endpoint.
 *
 * State is kept IN-MEMORY (a MutableStateFlow). This matches the web behaviour (the managing-creator
 * selection is session-scoped, not persisted across cold start). If durable persistence is ever required,
 * a DataStore mirror can be layered in here and hydrated on init - intentionally deferred to keep this
 * ticket minimal (no new dependency, no Room).
 *
 * Singleton so the [managingCreator] state is shared by every consumer (the repository re-exposes it).
 */
@Singleton
class DelegationStateStore @Inject constructor() {

    private val _managingCreator = MutableStateFlow<ManagingCreator?>(null)

    /**
     * The active manage-as-creator selection, or null when the principal acts as themselves. Downstream
     * features observe this to decide whether to path-scope their traffic.
     */
    val managingCreator: StateFlow<ManagingCreator?> = _managingCreator.asStateFlow()

    /**
     * ENTER (or switch) manage-as mode by setting the active creator, or pass null to clear. Pure local
     * mutation - NO network round-trip.
     */
    fun setManagingCreator(creator: ManagingCreator?) {
        _managingCreator.value = creator
    }

    /**
     * EXIT manage-as mode (back to acting as oneself). Pure local mutation - can not fail.
     *
     * FR-7 (clear-on-logout): a central logout / auth-reset hook should call this so the selection never
     * leaks across sessions. The codebase's auth reset lives in the app-layer AuthStateStore.clear (which
     * this core-data store must NOT depend on or modify); wiring that call is therefore done additively in
     * the app layer (see DelegationRepository KDoc) - this method is the seam it invokes.
     */
    fun clear() {
        _managingCreator.value = null
    }
}
