package com.testlogon.android.feature.search

/**
 * The kind of a searchable result, used to drive its group header, icon, and (in the ViewModel) its
 * navigation action. Ordering here is the group order rendered in the list.
 */
enum class SearchResultKind { SYMBOL, DESTINATION, ACTION }

/**
 * One render-ready, navigable search result. [id] is stable per kind (a symbolId for [SearchResultKind.SYMBOL],
 * a route/action-id otherwise) and is used as the LazyColumn key. [keywords] are extra terms (aliases)
 * matched by the filter in addition to [title]/[subtitle]. [symbolId] is set only for symbol results so
 * the route can navigate to the per-symbol detail.
 */
data class SearchItem(
    val id: String,
    val kind: SearchResultKind,
    val title: String,
    val subtitle: String? = null,
    val keywords: List<String> = emptyList(),
    val symbolId: Int? = null,
    val actionId: SearchActionId? = null,
)

/** The curated quick-actions the search surface can launch. */
enum class SearchActionId { NEW_PRICE_ALERT, DEPOSIT, TRADE_DEFAULT_SYMBOL }

/** A group of results sharing one [kind], rendered under a single header. */
data class SearchGroup(val kind: SearchResultKind, val items: List<SearchItem>)

/**
 * Single immutable state for the global search screen. [query] is the raw text field value; [groups]
 * is the filtered, ranked, grouped result set; [recents] are the recently-opened result ids surfaced
 * when the query is blank; [phase] is the mutually-exclusive top-level surface.
 */
data class SearchUiState(
    val query: String = "",
    val groups: List<SearchGroup> = emptyList(),
    val recents: List<SearchItem> = emptyList(),
    val phase: Phase = Phase.Idle,
) {
    /** Idle = blank query (show recents/hint); Results = at least one match; Empty = query with no match. */
    enum class Phase { Idle, Results, Empty }
}
