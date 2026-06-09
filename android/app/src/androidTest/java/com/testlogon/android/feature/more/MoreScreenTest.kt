package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Person
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertHasNoClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.R
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-067 — Compose UI tests for the three availability states + navigation. */
@RunWith(AndroidJUnit4::class)
class MoreScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun item(id: String, availability: EntryAvailability) = MoreItemUi(
        entry = MoreEntry(
            id = id,
            labelRes = R.string.more_entry_profile,
            icon = Icons.Outlined.Person,
            route = "route/$id",
            section = MoreSection.ACCOUNT,
        ),
        availability = availability,
    )

    private fun content(vararg items: MoreItemUi) = MoreUiState.Content(
        listOf(MoreSectionUi(MoreSection.ACCOUNT, items.toList())),
    )

    @Test
    fun available_isClickable_andNavigates() {
        var navigated: String? = null
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                MoreScreen(
                    state = content(item("a", EntryAvailability.Available)),
                    onNavigate = { navigated = it },
                )
            }
        }
        rule.onNodeWithTag("more_entry_a").assertHasClickAction().performClick()
        assertEquals("route/a", navigated)
    }

    @Test
    fun disabled_isNotClickable() {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                MoreScreen(
                    state = content(item("b", EntryAvailability.Disabled(R.string.more_unavailable_coming_soon))),
                    onNavigate = {},
                )
            }
        }
        rule.onNodeWithTag("more_entry_b").assertIsDisplayed().assertHasNoClickAction()
    }

    @Test
    fun empty_showsEmptyState() {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                MoreScreen(state = MoreUiState.Empty, onNavigate = {})
            }
        }
        rule.onNodeWithTag("more_empty").assertIsDisplayed()
    }
}
