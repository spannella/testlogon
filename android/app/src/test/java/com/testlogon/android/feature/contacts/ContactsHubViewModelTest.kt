package com.testlogon.android.feature.contacts

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.contacts.ContactMatch
import com.testlogon.android.data.contacts.ContactSuggestion
import com.testlogon.android.data.contacts.ContactsRepository
import com.testlogon.android.data.contacts.FollowRelationship
import com.testlogon.android.data.contacts.FollowCounts
import com.testlogon.android.data.contacts.FollowGraphUser
import com.testlogon.android.data.contacts.SnoozedFollowing
import com.testlogon.android.data.contacts.SavedContact
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ContactsHubViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    // ── Fake repository ──────────────────────────────────────────────────────

    private class FakeContactsRepository : ContactsRepository {
        var contacts: MutableList<SavedContact> = mutableListOf()
        var suggestionsList: List<ContactSuggestion> = emptyList()
        var listResult: ApiResult<List<SavedContact>>? = null
        var suggestionsResult: ApiResult<List<ContactSuggestion>>? = null
        var addResult: ApiResult<SavedContact>? = null
        var removeResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var favoriteResult: ((Boolean) -> ApiResult<SavedContact>)? = null

        override suspend fun listContacts(): ApiResult<List<SavedContact>> =
            listResult ?: ApiResult.Success(contacts.toList())

        override suspend fun suggestions(): ApiResult<List<ContactSuggestion>> =
            suggestionsResult ?: ApiResult.Success(suggestionsList)

        override suspend fun addContact(userId: String): ApiResult<SavedContact> =
            addResult ?: ApiResult.Success(
                SavedContact(userId, "Name $userId", null, isFavorite = false, isBlocked = false),
            )

        var matchResult: ApiResult<List<ContactMatch>> = ApiResult.Success(emptyList())
        override suspend fun matchDeviceContacts(): ApiResult<List<ContactMatch>> = matchResult

        override suspend fun removeContact(userId: String): ApiResult<Unit> = removeResult

        override suspend fun setFavorite(userId: String, favorite: Boolean): ApiResult<SavedContact> =
            favoriteResult?.invoke(favorite)
                ?: ApiResult.Success(
                    SavedContact(userId, "Name $userId", null, isFavorite = favorite, isBlocked = false),
                )

        override suspend fun follow(userId: String): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun unfollow(userId: String): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun followStatus(userId: String): ApiResult<FollowRelationship> =
            ApiResult.Success(FollowRelationship(false, false, false))
        override suspend fun followers(userId: String, cursor: String?): ApiResult<List<FollowGraphUser>> =
            ApiResult.Success(emptyList())
        override suspend fun following(userId: String, cursor: String?): ApiResult<List<FollowGraphUser>> =
            ApiResult.Success(emptyList())
        override suspend fun followCounts(userId: String): ApiResult<FollowCounts> =
            ApiResult.Success(FollowCounts(0, 0))
        override suspend fun mutualFollowers(userId: String, cursor: String?): ApiResult<List<FollowGraphUser>> =
            ApiResult.Success(emptyList())
        override suspend fun snoozedFollowing(): ApiResult<List<SnoozedFollowing>> =
            ApiResult.Success(emptyList())
        override suspend fun snoozeFollowing(userId: String, days: Int): ApiResult<Long> =
            ApiResult.Success(0L)
        override suspend fun unsnoozeFollowing(userId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)
    }

    private fun saved(id: String, favorite: Boolean = false) =
        SavedContact(id, "Name $id", null, isFavorite = favorite, isBlocked = false)

    private fun suggestion(id: String, hint: String = "Follows you") =
        ContactSuggestion(id, "Name $id", null, hint = hint, mutualCount = 0, source = "follower")

    private fun failure(status: Int) = ApiResult.Failure(ApiError(status = status, message = "boom"))

    // ── Tests ────────────────────────────────────────────────────────────────

    @Test
    fun load_success_populatesBothSections_favoritesFirst() = runTest {
        val repo = FakeContactsRepository().apply {
            contacts = mutableListOf(saved("b"), saved("a", favorite = true))
            suggestionsList = listOf(suggestion("s1"), suggestion("s2"))
        }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()

        val state = vm.state.value
        assertTrue(state is ContactsHubUiState.Content)
        val content = state as ContactsHubUiState.Content
        // Favorite ("a") sorts before non-favorite ("b").
        assertEquals(listOf("a", "b"), content.contacts.map { it.userId })
        assertEquals(listOf("s1", "s2"), content.suggestions.map { it.userId })
    }

    @Test
    fun load_suggestionAlreadySaved_isExcludedDefensively() = runTest {
        val repo = FakeContactsRepository().apply {
            contacts = mutableListOf(saved("dup"))
            // Server *should* exclude it, but assert the reducer also filters it out.
            suggestionsList = listOf(suggestion("dup"), suggestion("fresh"))
        }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()

        val content = vm.state.value as ContactsHubUiState.Content
        assertEquals(listOf("fresh"), content.suggestions.map { it.userId })
    }

    @Test
    fun load_emptyBoth_isFullyEmptyContent() = runTest {
        val repo = FakeContactsRepository()
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()
        val content = vm.state.value as ContactsHubUiState.Content
        assertTrue(content.isFullyEmpty)
    }

    @Test
    fun load_serverFailure_emitsError_notOffline() = runTest {
        val repo = FakeContactsRepository().apply { listResult = failure(500) }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ContactsHubUiState.Error)
        assertFalse((state as ContactsHubUiState.Error).offline)
    }

    @Test
    fun load_networkError_emitsOfflineError() = runTest {
        val repo = FakeContactsRepository().apply {
            listResult = ApiResult.NetworkError(java.io.IOException("x"), isTimeout = true)
        }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ContactsHubUiState.Error)
        assertTrue((state as ContactsHubUiState.Error).offline)
    }

    @Test
    fun saveSuggestion_movesItIntoContacts_andDropsFromSuggestions() = runTest {
        val repo = FakeContactsRepository().apply {
            suggestionsList = listOf(suggestion("s1"))
        }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()

        vm.onSaveSuggestion("s1")
        advanceUntilIdle()

        val content = vm.state.value as ContactsHubUiState.Content
        assertTrue(content.suggestions.isEmpty())
        assertEquals(listOf("s1"), content.contacts.map { it.userId })
    }

    @Test
    fun saveSuggestion_failure_clearsAddingFlag_keepsSuggestion() = runTest {
        val repo = FakeContactsRepository().apply {
            suggestionsList = listOf(suggestion("s1"))
            addResult = failure(409)
        }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()

        vm.onSaveSuggestion("s1")
        advanceUntilIdle()

        val content = vm.state.value as ContactsHubUiState.Content
        assertEquals(listOf("s1"), content.suggestions.map { it.userId })
        assertFalse(content.suggestions.first().adding)
        assertTrue(content.contacts.isEmpty())
    }

    @Test
    fun removeContact_optimisticThenRollbackOnFailure() = runTest {
        val repo = FakeContactsRepository().apply {
            contacts = mutableListOf(saved("c1"))
            removeResult = failure(500)
        }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()

        vm.onRemoveContact("c1")
        advanceUntilIdle()

        // Rolled back — contact is restored.
        val content = vm.state.value as ContactsHubUiState.Content
        assertEquals(listOf("c1"), content.contacts.map { it.userId })
    }

    @Test
    fun toggleFavorite_success_reSortsFavoritesFirst() = runTest {
        val repo = FakeContactsRepository().apply {
            contacts = mutableListOf(saved("a"), saved("b"))
        }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()

        // Favorite "b" -> it should jump to the top.
        vm.onToggleFavorite("b", favorite = true)
        advanceUntilIdle()

        val content = vm.state.value as ContactsHubUiState.Content
        assertEquals(listOf("b", "a"), content.contacts.map { it.userId })
        assertTrue(content.contacts.first { it.userId == "b" }.isFavorite)
    }

    @Test
    fun toggleFavorite_failure_rollsBack() = runTest {
        val repo = FakeContactsRepository().apply {
            contacts = mutableListOf(saved("a"), saved("b"))
            favoriteResult = { failure(500) }
        }
        val vm = ContactsHubViewModel(repo)
        advanceUntilIdle()

        vm.onToggleFavorite("b", favorite = true)
        advanceUntilIdle()

        val content = vm.state.value as ContactsHubUiState.Content
        // Original order + no favorite flip.
        assertEquals(listOf("a", "b"), content.contacts.map { it.userId })
        assertFalse(content.contacts.first { it.userId == "b" }.isFavorite)
    }
}
