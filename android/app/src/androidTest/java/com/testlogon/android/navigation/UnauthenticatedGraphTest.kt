package com.testlogon.android.navigation

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.navigation.compose.NavHost
import androidx.navigation.testing.TestNavHostController
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.HiltTestActivity
import dagger.hilt.android.testing.HiltAndroidRule
import dagger.hilt.android.testing.HiltAndroidTest
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Smoke test: with the default (unauthenticated) provider, the host boots into the
 * unauthenticated graph with the Login placeholder displayed.
 */
@HiltAndroidTest
@RunWith(AndroidJUnit4::class)
class UnauthenticatedGraphTest {

    @get:Rule(order = 0)
    val hiltRule = HiltAndroidRule(this)

    @get:Rule(order = 1)
    val rule = createAndroidComposeRule<HiltTestActivity>()

    @Test
    fun startsOnLogin() {
        hiltRule.inject()

        lateinit var navController: TestNavHostController
        rule.setContent {
            navController = TestNavHostController(InstrumentationRegistry.getInstrumentation().targetContext)
            navController.navigatorProvider.addNavigator(
                androidx.navigation.compose.ComposeNavigator(),
            )
            NavHost(navController = navController, startDestination = TlGraphs.UNAUTHENTICATED) {
                unauthenticatedGraph(navController)
            }
        }

        rule.waitUntil(5_000) {
            rule.onAllNodesWithTag("login_screen").fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithTag("login_screen").assertIsDisplayed()
        assertEquals(AuthDest.Login.route, navController.currentDestination?.route)
    }
}
