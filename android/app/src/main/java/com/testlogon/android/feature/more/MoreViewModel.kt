package com.testlogon.android.feature.more

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.CurrentUserRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-067 / B5 — resolves the static [MoreCatalog] through [MoreAvailabilityResolver] into the [MoreUiState].
 * Hidden entries are filtered out; empty hubs/sections are suppressed; a fully-empty catalog yields
 * [MoreUiState.Empty].
 *
 * B5: on init the VM resolves the caller's admin status once (GET /ui/me.is_admin via [CurrentUserRepository])
 * and sets [AdminVisibility]. When admin, the resolver reveals the operator-only Admin hub entries; the source
 * flow re-emits so the newly-revealed entries appear without a screen reload. Non-admin (or a failed check)
 * leaves them Hidden; the backend 403 stays authoritative.
 */
@HiltViewModel
class MoreViewModel @Inject constructor(
    private val catalog: MoreCatalog,
    private val resolver: MoreAvailabilityResolver,
    private val adminVisibility: AdminVisibility,
    private val currentUser: CurrentUserRepository,
) : ViewModel() {

    // Bumped after the admin check resolves so the mapped state re-emits with the Admin hub revealed.
    private val source = MutableStateFlow(0)

    val uiState: StateFlow<MoreUiState> = source
        .map { catalog.entries.toUiState(resolver) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), MoreUiState.Loading)

    init {
        resolveAdmin()
    }

    private fun resolveAdmin() {
        viewModelScope.launch {
            val result = currentUser.isAdmin()
            if (result is ApiResult.Success && result.data) {
                adminVisibility.isAdmin = true
                source.value += 1 // re-project so operator-only entries surface
            }
        }
    }

    /** Available (non-Hidden) items for a single hub — the hub-detail screen's projection. */
    fun itemsForHub(hub: MoreHub): List<MoreItemUi> =
        catalog.entries.itemsForHub(hub, resolver)
}

/** Pure projection used by both the ViewModel and tests. */
fun List<MoreEntry>.toUiState(resolver: MoreAvailabilityResolver): MoreUiState {
    val sections = MoreSection.entries.mapNotNull { section ->
        val items = filter { it.section == section }
            .map { MoreItemUi(it, resolver.resolve(it)) }
            .filter { it.availability !is EntryAvailability.Hidden }
        if (items.isEmpty()) null else MoreSectionUi(section, items)
    }
    val hubs = MoreHub.entries.mapNotNull { hub ->
        val items = itemsForHub(hub, resolver)
        if (items.isEmpty()) null else MoreHubUi(hub, items)
    }
    return if (sections.isEmpty()) MoreUiState.Empty else MoreUiState.Content(hubs = hubs, sections = sections)
}

/** Available (non-Hidden) items for one hub, preserving catalog order. */
fun List<MoreEntry>.itemsForHub(hub: MoreHub, resolver: MoreAvailabilityResolver): List<MoreItemUi> =
    filter { it.hub == hub }
        .map { MoreItemUi(it, resolver.resolve(it)) }
        .filter { it.availability !is EntryAvailability.Hidden }
