package com.testlogon.android.feature.delegates

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.delegates.ui.DelegationBanner
import com.testlogon.android.feature.delegates.ui.DelegationBannerTestTags
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-360 - Compose UI tests for the stateless [DelegationBanner]: it shows "Managing @creator" with an
 * Exit action that invokes the callback, and (via a host that mirrors the connected variant's null guard)
 * is hidden when there is no active context. createComposeRule (no Hilt); useUnmergedTree; assertDoesNotExist
 * is a MEMBER chained off the node (not imported).
 */
@RunWith(AndroidJUnit4::class)
class DelegationBannerTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun banner_showsManagingCreator_andExitInvokesCallback() {
        var exited = 0
        rule.setContent {
            TestLogonTheme {
                DelegationBanner(creatorName = "Acme", onExit = { exited++ })
            }
        }

        rule.onNodeWithTag(DelegationBannerTestTags.BANNER, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithText("Managing @Acme").assertIsDisplayed()

        rule.onNodeWithTag(DelegationBannerTestTags.EXIT, useUnmergedTree = true).performClick()
        assertEquals(1, exited)
    }

    @Test
    fun banner_hidden_whenNoActiveContext() {
        rule.setContent {
            TestLogonTheme {
                // Mirror the connected host's null-guard: render nothing when the context is null.
                val context by remember { mutableStateOf<String?>(null) }
                if (context != null) {
                    DelegationBanner(creatorName = context, onExit = {})
                }
            }
        }

        rule.onNodeWithTag(DelegationBannerTestTags.BANNER, useUnmergedTree = true).assertDoesNotExist()
    }
}
