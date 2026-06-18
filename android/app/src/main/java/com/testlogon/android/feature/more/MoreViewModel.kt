package com.testlogon.android.feature.more

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/**
 * AND-067 — resolves the static [MoreCatalog] through [MoreAvailabilityResolver] into the
 * [MoreUiState]. Hidden entries are filtered out; empty hubs/sections are suppressed; a fully-empty
 * catalog yields [MoreUiState.Empty]. The same [MoreUiState.Content] carries both the top-level hub
 * grouping (used by the More tab + hub-detail screen) and the flat section grouping.
 */
@HiltViewModel
class MoreViewModel @Inject constructor(
    private val catalog: MoreCatalog,
    private val resolver: MoreAvailabilityResolver,
) : ViewModel() {

    // Single emission source; re-resolves if the catalog ever becomes reactive.
    private val source = MutableStateFlow(catalog.entries)

    val uiState: StateFlow<MoreUiState> = source
        .map { entries -> entries.toUiState(resolver) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), MoreUiState.Loading)

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
