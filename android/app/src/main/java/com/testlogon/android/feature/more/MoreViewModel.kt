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
 * AND-067 — resolves the static [MoreCatalog] through [MoreAvailabilityResolver] into a sectioned
 * [MoreUiState]. Hidden entries are filtered out; empty sections are suppressed; a fully-empty
 * catalog yields [MoreUiState.Empty].
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
}

/** Pure projection used by both the ViewModel and tests. */
fun List<MoreEntry>.toUiState(resolver: MoreAvailabilityResolver): MoreUiState {
    val sections = MoreSection.entries.mapNotNull { section ->
        val items = filter { it.section == section }
            .map { MoreItemUi(it, resolver.resolve(it)) }
            .filter { it.availability !is EntryAvailability.Hidden }
        if (items.isEmpty()) null else MoreSectionUi(section, items)
    }
    return if (sections.isEmpty()) MoreUiState.Empty else MoreUiState.Content(sections)
}
