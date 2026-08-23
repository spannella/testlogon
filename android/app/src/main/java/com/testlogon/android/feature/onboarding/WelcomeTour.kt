package com.testlogon.android.feature.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * The first-run **Welcome tour**: a stepper dialog that walks the new trading/investing surfaces. It
 * shows automatically ONCE (gated on [OnboardingModel.WELCOME_TOUR_ID] in the seen-set) and can be
 * replayed from Settings. Each step shows a title + body; steps with a route add a "Go there" button
 * that completes the tour and navigates via [onOpenRoute] (the caller uses existing routes). Skip and
 * Done (last step) both persist completion.
 *
 * Drop this at the top of a host screen (the Dashboard):
 *   `WelcomeTour(onOpenRoute = onOpenRoute)`
 * It renders nothing once completed or while the seen-set is loading.
 */
@Composable
fun WelcomeTour(
    onOpenRoute: (String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: OnboardingViewModel = hiltViewModel(),
) {
    val seen by viewModel.seenIds.collectAsStateWithLifecycle()
    val current = seen ?: return // still loading
    if (!OnboardingModel.shouldShow(OnboardingModel.WELCOME_TOUR_ID, current)) return

    WelcomeTourDialog(
        onComplete = { viewModel.markSeen(OnboardingModel.WELCOME_TOUR_ID) },
        onOpenRoute = onOpenRoute,
        modifier = modifier,
    )
}

/** Pure-ish stepper UI (no store); split out so it is easy to preview/drive. */
@Composable
private fun WelcomeTourDialog(
    onComplete: () -> Unit,
    onOpenRoute: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val steps = remember { OnboardingModel.tourSteps() }
    if (steps.isEmpty()) return
    var index by rememberSaveable { mutableIntStateOf(0) }
    val step = steps[index.coerceIn(0, steps.lastIndex)]
    val isFirst = index == 0
    val isLast = index == steps.lastIndex

    AlertDialog(
        onDismissRequest = onComplete,
        modifier = modifier.testTag("welcome_tour_dialog"),
        title = {
            Column {
                Text(
                    text = "Step ${index + 1} of ${steps.size}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(text = step.title, style = MaterialTheme.typography.titleLarge)
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(text = step.body, style = MaterialTheme.typography.bodyMedium)
                step.route?.let { route ->
                    TextButton(
                        onClick = {
                            onComplete()
                            onOpenRoute(route)
                        },
                        modifier = Modifier.testTag("welcome_tour_goto"),
                    ) {
                        Text("Go there")
                    }
                }
            }
        },
        confirmButton = {
            if (isLast) {
                TextButton(
                    onClick = onComplete,
                    modifier = Modifier.testTag("welcome_tour_done"),
                ) {
                    Text("Done")
                }
            } else {
                TextButton(
                    onClick = { index += 1 },
                    modifier = Modifier.testTag("welcome_tour_next"),
                ) {
                    Text("Next")
                }
            }
        },
        dismissButton = {
            Row(
                modifier = Modifier.fillMaxWidth().padding(start = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                if (!isFirst) {
                    TextButton(
                        onClick = { index -= 1 },
                        modifier = Modifier.testTag("welcome_tour_back"),
                    ) {
                        Text("Back")
                    }
                }
                TextButton(
                    onClick = onComplete,
                    modifier = Modifier.testTag("welcome_tour_skip"),
                ) {
                    Text("Skip")
                }
            }
        },
    )
}
