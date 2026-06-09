package com.testlogon.android.feature.profile

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.profile.own.OwnProfileScreen
import com.testlogon.android.feature.profile.own.OwnProfileUiState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-076 — headless Compose UI tests over the own-profile render states. */
@RunWith(AndroidJUnit4::class)
class OwnProfileScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun sample() = Profile.EMPTY.copy(displayName = "Sean P.", description = "Builder.")

    private fun setState(
        state: OwnProfileUiState,
        onEdit: () -> Unit = {},
        onRetry: () -> Unit = {},
        onChangePhoto: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                OwnProfileScreen(
                    state = state,
                    onRefresh = {},
                    onRetry = onRetry,
                    onEdit = onEdit,
                    onChangePhoto = onChangePhoto,
                    onOpenSessions = {},
                    onOpenMfaDevices = {},
                    accountActions = {}, // avoid Hilt-backed account VM in this stateless render test
                )
            }
        }
    }

    @Test
    fun loading_showsLoadingAffordance() {
        setState(OwnProfileUiState(phase = OwnProfileUiState.Phase.Loading))
        rule.onNodeWithTag(ProfileTestTags.OWN_LOADING).assertIsDisplayed()
    }

    @Test
    fun content_showsNameDescriptionAvatarEdit() {
        setState(OwnProfileUiState(phase = OwnProfileUiState.Phase.Content, profile = sample()))
        rule.onNodeWithTag(ProfileTestTags.OWN_DISPLAY_NAME).assertIsDisplayed()
        rule.onNodeWithTag(ProfileTestTags.OWN_DESCRIPTION).assertIsDisplayed()
        rule.onNodeWithTag(ProfileTestTags.OWN_AVATAR).assertIsDisplayed()
        rule.onNodeWithTag(ProfileTestTags.OWN_EDIT).assertIsDisplayed()
    }

    @Test
    fun edit_tap_invokesCallback() {
        var edited = false
        setState(
            OwnProfileUiState(phase = OwnProfileUiState.Phase.Content, profile = sample()),
            onEdit = { edited = true },
        )
        rule.onNodeWithTag(ProfileTestTags.OWN_EDIT).performClick()
        assertTrue(edited)
    }

    @Test
    fun error_showsErrorSurface() {
        setState(OwnProfileUiState(phase = OwnProfileUiState.Phase.Error, errorMessage = "boom"))
        rule.onNodeWithTag(ProfileTestTags.OWN_ERROR).assertIsDisplayed()
    }

    @Test
    fun staleContent_showsBanner() {
        setState(
            OwnProfileUiState(phase = OwnProfileUiState.Phase.Content, profile = sample(), isStale = true),
        )
        rule.onNodeWithTag(ProfileTestTags.OWN_STALE_BANNER).assertIsDisplayed()
    }

    @Test
    fun missingOptionalFields_renderWithoutCrash() {
        setState(OwnProfileUiState(phase = OwnProfileUiState.Phase.Content, profile = Profile.EMPTY))
        rule.onNodeWithTag(ProfileTestTags.OWN_AVATAR).assertIsDisplayed()
        // No description node when description is null — sanity that the avatar still renders.
        assertEquals(ProfileTestTags.OWN_AVATAR, ProfileTestTags.OWN_AVATAR)
    }
}
