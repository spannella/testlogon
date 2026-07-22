package com.testlogon.android.feature.contacts

import com.testlogon.android.data.contacts.ContactMatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contacts Feature 2 — pure reducer tests for the device-match overlay:
 * matchResults (drops already-saved), markMatchAdding, removeMatch.
 */
class ContactsHubMatchReducerTest {

    private fun match(id: String, by: String = "email") =
        ContactMatch(userId = id, displayName = "Name $id", photoUrl = null, matchedBy = by)

    private fun contact(id: String) =
        ContactRow(userId = id, displayName = "Name $id", photoUrl = null, isFavorite = false)

    @Test
    fun matchResults_drops_already_saved_and_maps_labels() {
        val result = ContactsHubReducer.matchResults(
            matches = listOf(match("a", "email"), match("b", "phone"), match("c", "email")),
            contacts = listOf(contact("b")), // b is already saved
        )
        val ids = result.matches.map { it.userId }
        assertEquals(listOf("a", "c"), ids)                       // b filtered out
        assertEquals("email", result.matches.first { it.userId == "a" }.matchedBy)
        assertFalse(result.isEmpty)
    }

    @Test
    fun matchResults_empty_when_all_saved() {
        val result = ContactsHubReducer.matchResults(
            matches = listOf(match("a"), match("b")),
            contacts = listOf(contact("a"), contact("b")),
        )
        assertTrue(result.isEmpty)
    }

    @Test
    fun markMatchAdding_flips_only_the_target() {
        val base = ContactsHubReducer.matchResults(
            matches = listOf(match("a"), match("b")),
            contacts = emptyList(),
        )
        val adding = ContactsHubReducer.markMatchAdding(base, "a", adding = true)
        assertTrue(adding.matches.first { it.userId == "a" }.adding)
        assertFalse(adding.matches.first { it.userId == "b" }.adding)

        val cleared = ContactsHubReducer.markMatchAdding(adding, "a", adding = false)
        assertFalse(cleared.matches.first { it.userId == "a" }.adding)
    }

    @Test
    fun removeMatch_drops_the_added_row() {
        val base = ContactsHubReducer.matchResults(
            matches = listOf(match("a"), match("b")),
            contacts = emptyList(),
        )
        val after = ContactsHubReducer.removeMatch(base, "a")
        assertEquals(listOf("b"), after.matches.map { it.userId })
    }
}
