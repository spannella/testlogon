package com.testlogon.android.feature.messaging.contacts

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.testlogon.android.R
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.messaging.Contact
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-153/154/156 — Compose UI tests for the contacts screen states + callbacks. */
@RunWith(AndroidJUnit4::class)
class ContactsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun contact(id: String, name: String) = Contact(id = id, displayName = name)

    private fun setContent(state: ContactsUiState, onContactClick: (Contact) -> Unit = {}, onQueryChange: (String) -> Unit = {}, onRetry: () -> Unit = {}) {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                ContactsScreen(
                    state = state,
                    onQueryChange = onQueryChange,
                    onClear = {},
                    onRetry = onRetry,
                    onContactClick = onContactClick,
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun idle_showsPrompt() {
        setContent(ContactsUiState(phase = ContactsPhase.Idle))
        rule.onNodeWithText(context.getString(R.string.contacts_idle_prompt)).assertIsDisplayed()
    }

    @Test
    fun results_renderRows_andClickEmitsContact() {
        var clicked: Contact? = null
        setContent(
            ContactsUiState(
                query = "ali",
                phase = ContactsPhase.Results,
                contacts = listOf(contact("u_1", "Alice Nguyen"), contact("u_2", "Khalil")),
            ),
            onContactClick = { clicked = it },
        )
        rule.onNodeWithText("Alice Nguyen").assertIsDisplayed()
        rule.onAllNodesWithTag(ContactsTestTags.ROW).onFirst().performClick()
        assertEquals("u_1", clicked?.id)
    }

    @Test
    fun typing_firesOnQueryChange() {
        var typed: String? = null
        setContent(ContactsUiState(phase = ContactsPhase.Idle), onQueryChange = { typed = it })
        rule.onNodeWithTag(ContactsTestTags.INPUT).performTextInput("ada")
        assertEquals("ada", typed)
    }

    @Test
    fun empty_showsQueryInMessage() {
        setContent(ContactsUiState(query = "zzz", phase = ContactsPhase.Empty("zzz")))
        rule.onNodeWithText(context.getString(R.string.contacts_empty_query, "zzz")).assertIsDisplayed()
    }

    @Test
    fun error_showsRetry_andFiresOnRetry() {
        var retried = false
        setContent(
            ContactsUiState(query = "ada", phase = ContactsPhase.Error("Couldn't search", offline = false)),
            onRetry = { retried = true },
        )
        rule.onNodeWithText(context.getString(R.string.action_retry)).performClick()
        assertEquals(true, retried)
    }
}
