package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Person
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
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

/**
 * AND-067 — Compose UI tests for the More hub-detail screen (the three availability states +
 * navigation). The top-level More tab now renders hub tiles; item cards live on [MoreHubScreen].
 */
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
            hub = MoreHub.ACCOUNT,
            section = MoreSection.ACCOUNT,
        ),
        availability = availability,
    )

    @Test
    fun available_isClickable_andNavigates() {
        var navigated: String? = null
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                MoreHubScreen(
                    hub = MoreHub.ACCOUNT,
                    items = listOf(item("a", EntryAvailability.Available)),
                    onBack = {},
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
                MoreHubScreen(
                    hub = MoreHub.ACCOUNT,
                    items = listOf(
                        item("b", EntryAvailability.Disabled(R.string.more_unavailable_coming_soon)),
                    ),
                    onBack = {},
                    onNavigate = {},
                )
            }
        }
        // A disabled Material3 Card still exposes an (inert) OnClick semantics action, so it is
        // "not enabled" rather than "no click action". Assert the disabled state, which is the
        // real not-clickable behavior the screen implements (Card enabled = !disabled).
        rule.onNodeWithTag("more_entry_b").assertIsDisplayed().assertIsNotEnabled()
    }

    @Test
    fun empty_showsEmptyState() {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                MoreHubScreen(
                    hub = MoreHub.ACCOUNT,
                    items = emptyList(),
                    onBack = {},
                    onNavigate = {},
                )
            }
        }
        rule.onNodeWithTag("more_hub_empty").assertIsDisplayed()
    }

    @Test
    fun hubTiles_renderAndDrillIn() {
        var openedHub: MoreHub? = null
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                MoreScreen(
                    state = MoreUiState.Content(
                        hubs = listOf(
                            MoreHubUi(MoreHub.ACCOUNT, listOf(item("a", EntryAvailability.Available))),
                        ),
                        sections = emptyList(),
                    ),
                    onOpenHub = { openedHub = it },
                )
            }
        }
        rule.onNodeWithTag("more_hub_account").assertHasClickAction().performClick()
        assertEquals(MoreHub.ACCOUNT, openedHub)
    }
}
