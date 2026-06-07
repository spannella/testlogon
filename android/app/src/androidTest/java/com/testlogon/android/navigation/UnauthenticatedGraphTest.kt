package com.testlogon.android.navigation

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.navigation.compose.NavHost
import androidx.navigation.testing.TestNavHostController
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Smoke test: with the default (unauthenticated) provider, the host boots into the
 * unauthenticated graph with the Login placeholder displayed.
 */
@RunWith(AndroidJUnit4::class)
class UnauthenticatedGraphTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun startsOnLogin() {
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

        rule.onNodeWithTag("login_screen").assertIsDisplayed()
        assertEquals(AuthDest.Login.route, navController.currentDestination?.route)
    }
}
