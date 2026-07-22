package com.testlogon.android.feature.contacts

import com.testlogon.android.data.contacts.ContactMatch
import com.testlogon.android.data.contacts.ContactSuggestion
import com.testlogon.android.data.contacts.SavedContact

/** A saved-contact row in the address book (favorites-first). */
data class ContactRow(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    val isFavorite: Boolean,
)

/** A "people you may know" suggestion row. */
data class SuggestionRow(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    val hint: String,
    /** True while an add-to-contacts request for this suggestion is in flight. */
    val adding: Boolean = false,
)

/** Feature 2 — a device-address-book match row. */
data class MatchRow(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    /** "In your contacts by email" / "...by phone" label source. */
    val matchedBy: String,
    val adding: Boolean = false,
)

/**
 * Feature 2 — the device contact-sync phase, an OVERLAY on the hub (permission gate ->
 * hashing/matching progress -> results). Idle until the user taps "Find people you know".
 */
sealed interface MatchSyncState {
    data object Idle : MatchSyncState

    /** Permission denied (soft: can re-ask) or permanently denied (must go to Settings). */
    data class PermissionNeeded(val permanentlyDenied: Boolean) : MatchSyncState

    /** Reading + hashing on-device, then calling the match endpoint. */
    data object Syncing : MatchSyncState

    data class Results(val matches: List<MatchRow>) : MatchSyncState {
        val isEmpty: Boolean get() = matches.isEmpty()
    }

    data class Failed(val message: String, val offline: Boolean) : MatchSyncState
}

/**
 * Feature 1 — Contacts hub screen state. The screen has TWO sections (saved contacts +
 * suggestions); either can be empty independently, so the top-level state is Content whenever
 * the initial load succeeded and Error/Loading only gate the first paint.
 */
sealed interface ContactsHubUiState {
    data object Loading : ContactsHubUiState

    data class Content(
        val contacts: List<ContactRow>,
        val suggestions: List<SuggestionRow>,
        val isRefreshing: Boolean = false,
    ) : ContactsHubUiState {
        val isFullyEmpty: Boolean get() = contacts.isEmpty() && suggestions.isEmpty()
    }

    data class Error(val message: String, val offline: Boolean) : ContactsHubUiState
}

/**
 * Pure reducers — no Android/coroutine deps, so they are directly JVM-unit-testable
 * (the ViewModel delegates all list-shaping to these).
 */
object ContactsHubReducer {

    /** Build the initial Content from a successful load of both sections. */
    fun content(
        contacts: List<SavedContact>,
        suggestions: List<ContactSuggestion>,
    ): ContactsHubUiState.Content = ContactsHubUiState.Content(
        // Sort favorites-first defensively (matches the toggle/promote paths); the backend already
        // returns favorites-first, but re-sorting keeps the UI invariant local + testable.
        contacts = contacts.map { it.toRow() }.sortedFavoritesFirst(),
        // Defensively drop any suggestion that is already a saved contact (belt-and-braces;
        // the backend already excludes saved ids, but the two calls are not transactional).
        suggestions = suggestions
            .filter { s -> contacts.none { it.userId == s.userId } }
            .map { it.toRow() },
    )

    /** Optimistically remove a contact row after a delete. */
    fun removeContact(state: ContactsHubUiState.Content, userId: String): ContactsHubUiState.Content =
        state.copy(contacts = state.contacts.filterNot { it.userId == userId })

    /** Optimistically flip a favorite flag and re-sort favorites-first. */
    fun toggleFavorite(
        state: ContactsHubUiState.Content,
        userId: String,
        favorite: Boolean,
    ): ContactsHubUiState.Content = state.copy(
        contacts = state.contacts
            .map { if (it.userId == userId) it.copy(isFavorite = favorite) else it }
            .sortedFavoritesFirst(),
    )

    /** Mark a suggestion as "adding" (in-flight) or clear the flag. */
    fun markSuggestionAdding(
        state: ContactsHubUiState.Content,
        userId: String,
        adding: Boolean,
    ): ContactsHubUiState.Content = state.copy(
        suggestions = state.suggestions.map {
            if (it.userId == userId) it.copy(adding = adding) else it
        },
    )

    /**
     * Move a just-added suggestion into the saved-contacts section (favorites-first) and drop it
     * from suggestions — the optimistic result of tapping "Add" on a suggestion card.
     */
    fun promoteSuggestion(
        state: ContactsHubUiState.Content,
        added: SavedContact,
    ): ContactsHubUiState.Content = state.copy(
        contacts = (state.contacts + added.toRow()).sortedFavoritesFirst(),
        suggestions = state.suggestions.filterNot { it.userId == added.userId },
    )

    // ── Feature 2: device-match reducers ────────────────────────────────────

    /** Build match results, dropping anyone already saved (belt-and-braces vs the server). */
    fun matchResults(
        matches: List<ContactMatch>,
        contacts: List<ContactRow>,
    ): MatchSyncState.Results = MatchSyncState.Results(
        matches = matches
            .filter { m -> contacts.none { it.userId == m.userId } }
            .map { it.toRow() },
    )

    fun markMatchAdding(state: MatchSyncState.Results, userId: String, adding: Boolean): MatchSyncState.Results =
        state.copy(matches = state.matches.map { if (it.userId == userId) it.copy(adding = adding) else it })

    /** Drop a just-added match from the results overlay. */
    fun removeMatch(state: MatchSyncState.Results, userId: String): MatchSyncState.Results =
        state.copy(matches = state.matches.filterNot { it.userId == userId })
}

private fun SavedContact.toRow() = ContactRow(
    userId = userId,
    displayName = displayName,
    photoUrl = photoUrl,
    isFavorite = isFavorite,
)

private fun ContactMatch.toRow() = MatchRow(
    userId = userId,
    displayName = displayName,
    photoUrl = photoUrl,
    matchedBy = matchedBy,
)

private fun ContactSuggestion.toRow() = SuggestionRow(
    userId = userId,
    displayName = displayName,
    photoUrl = photoUrl,
    hint = hint,
)

private fun List<ContactRow>.sortedFavoritesFirst(): List<ContactRow> =
    sortedWith(compareByDescending<ContactRow> { it.isFavorite }.thenBy { it.displayName.lowercase() })
