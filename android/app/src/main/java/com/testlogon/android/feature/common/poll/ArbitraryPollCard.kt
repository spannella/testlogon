package com.testlogon.android.feature.common.poll

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.poll.ArbitraryPoll
import com.testlogon.android.core.model.poll.ArbitraryPollOption
import com.testlogon.android.core.model.poll.ArbitraryPollPage
import com.testlogon.android.core.model.poll.ArbitraryPollQuestion
import com.testlogon.android.data.poll.PollVoter
import kotlinx.coroutines.launch

/** Stable test tags for the arbitrary-poll card. */
object ArbitraryPollCardTestTags {
    const val CARD = "poll_card"
    const val TOTAL = "poll_total"
    const val CLOSED = "poll_closed"
    const val CLOSE_BUTTON = "poll_close"
    const val ERROR = "poll_error"
    fun option(optionId: String) = "poll_option_$optionId"
    fun writeInAdd(questionId: String) = "poll_writein_add_$questionId"
    fun writeInInput(questionId: String) = "poll_writein_input_$questionId"
    fun writeInSubmit(questionId: String) = "poll_writein_submit_$questionId"
    fun writeInBadge(optionId: String) = "poll_writein_badge_$optionId"
    fun more(questionId: String) = "poll_more_$questionId"
}

/** Options shown before the "show more" control for write-in questions (matches the backend top_n=5). */
private const val WRITE_IN_TOP_N = 5

/**
 * Self-contained renderer for an ARBITRARY text-option poll embedded in a message / group post /
 * syndicate post. Supports single-choice AND multi-select voting (a re-tap toggles a multi option off),
 * shows live counts + percentages, a closed state, and an owner-only Close-poll action.
 *
 * When a question is sender-enabled for WRITE-INS it renders the TOP 5 options by count, a "+" to add
 * your own answer (submitted to the write-in endpoint) and a "Show more" control that PAGES the rest via
 * the paginated results endpoint. Write-in options are flagged subtly. All state is kept internally;
 * mutations delegate to [voter] which returns a fresh snapshot/page.
 */
@Composable
fun ArbitraryPollCard(
    initial: ArbitraryPoll,
    isOwner: Boolean,
    voter: PollVoter,
    modifier: Modifier = Modifier,
) {
    var poll by remember(initial.pollId) { mutableStateOf(initial) }
    var busyOptionId by remember(initial.pollId) { mutableStateOf<String?>(null) }
    var error by remember(initial.pollId) { mutableStateOf<String?>(null) }
    // Per-question count of options currently revealed (write-in questions page the rest).
    val revealed = remember(initial.pollId) { mutableStateMapOf<String, Int>() }
    // Per-question write-in input visibility + text.
    val writeInOpen = remember(initial.pollId) { mutableStateMapOf<String, Boolean>() }
    val writeInText = remember(initial.pollId) { mutableStateMapOf<String, String>() }
    var writeInBusyQid by remember(initial.pollId) { mutableStateOf<String?>(null) }
    var moreBusyQid by remember(initial.pollId) { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    // Re-sync when the host feeds a newer snapshot (e.g. a paging refresh).
    LaunchedEffect(initial) { poll = initial }

    fun onResult(r: ApiResult<ArbitraryPoll>) {
        when (r) {
            is ApiResult.Success -> {
                poll = r.data
                error = null
            }
            is ApiResult.Failure -> error = r.error.message
            is ApiResult.NetworkError -> error = "Couldn't reach the server. Try again."
        }
        busyOptionId = null
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f))
            .padding(12.dp)
            .testTag(ArbitraryPollCardTestTags.CARD),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        poll.questions.forEach { q ->
            QuestionBlock(
                question = q,
                interactive = poll.isInteractive && busyOptionId == null,
                busyOptionId = busyOptionId,
                revealed = revealed[q.id] ?: WRITE_IN_TOP_N,
                writeInOpen = writeInOpen[q.id] == true,
                writeInText = writeInText[q.id] ?: "",
                writeInBusy = writeInBusyQid == q.id,
                moreBusy = moreBusyQid == q.id,
                onOptionClick = { optionId ->
                    if (poll.isInteractive) {
                        busyOptionId = optionId
                        error = null
                        scope.launch { onResult(voter.vote(poll.pollId, q.id, optionId)) }
                    }
                },
                onToggleWriteIn = { writeInOpen[q.id] = !(writeInOpen[q.id] ?: false) },
                onWriteInTextChange = { writeInText[q.id] = it },
                onSubmitWriteIn = {
                    val text = (writeInText[q.id] ?: "").trim()
                    if (text.isNotEmpty() && writeInBusyQid == null) {
                        writeInBusyQid = q.id
                        error = null
                        scope.launch {
                            when (val r = voter.writeIn(poll.pollId, q.id, text)) {
                                is ApiResult.Success -> {
                                    poll = r.data
                                    writeInText[q.id] = ""
                                    writeInOpen[q.id] = false
                                    // Reveal all so the voter sees their just-added answer counted.
                                    revealed[q.id] = r.data.questions
                                        .firstOrNull { it.id == q.id }?.options?.size ?: WRITE_IN_TOP_N
                                }
                                is ApiResult.Failure -> error = r.error.message
                                is ApiResult.NetworkError -> error = "Couldn't reach the server. Try again."
                            }
                            writeInBusyQid = null
                        }
                    }
                },
                onShowMore = {
                    if (moreBusyQid == null) {
                        moreBusyQid = q.id
                        val current = revealed[q.id] ?: WRITE_IN_TOP_N
                        scope.launch {
                            when (val r = voter.results(poll.pollId, q.id, current, WRITE_IN_TOP_N)) {
                                is ApiResult.Success -> {
                                    poll = poll.mergePage(r.data)
                                    revealed[q.id] = current + r.data.options.size
                                }
                                // On failure, reveal locally from the snapshot we already hold.
                                else -> revealed[q.id] = current + WRITE_IN_TOP_N
                            }
                            moreBusyQid = null
                        }
                    }
                },
            )
        }

        val voteLabel = if (poll.totalVotes == 1) "1 vote" else "${poll.totalVotes} votes"
        Text(
            text = voteLabel,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag(ArbitraryPollCardTestTags.TOTAL),
        )

        if (poll.closed) {
            Text(
                text = "Poll closed",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(ArbitraryPollCardTestTags.CLOSED),
            )
        } else if (isOwner) {
            TextButton(
                onClick = { scope.launch { onResult(voter.close(poll.pollId)) } },
                modifier = Modifier.testTag(ArbitraryPollCardTestTags.CLOSE_BUTTON),
            ) { Text("Close poll") }
        }

        val err = error
        if (err != null) {
            Text(
                text = err,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag(ArbitraryPollCardTestTags.ERROR),
            )
        }
    }
}

/** Upsert a fetched results [page] into the poll snapshot (fresh counts + write-in flags + my-votes). */
private fun ArbitraryPoll.mergePage(page: ArbitraryPollPage): ArbitraryPoll = copy(
    totalVotes = page.totalVotes,
    questions = questions.map { q ->
        if (q.id != page.questionId) {
            q
        } else {
            val byId = q.options.associateBy { it.id }.toMutableMap()
            page.options.forEach { byId[it.id] = it }
            q.copy(options = byId.values.toList(), myVoteOptionIds = page.myVoteOptionIds)
        }
    },
)

@Composable
private fun QuestionBlock(
    question: ArbitraryPollQuestion,
    interactive: Boolean,
    busyOptionId: String?,
    revealed: Int,
    writeInOpen: Boolean,
    writeInText: String,
    writeInBusy: Boolean,
    moreBusy: Boolean,
    onOptionClick: (String) -> Unit,
    onToggleWriteIn: () -> Unit,
    onWriteInTextChange: (String) -> Unit,
    onSubmitWriteIn: () -> Unit,
    onShowMore: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        if (question.text.isNotBlank()) {
            Text(
                text = question.text,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
        }
        if (question.multiSelect) {
            Text(
                text = "Select one or more",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // Write-in questions render the TOP N by count then page the rest; fixed polls render as-is.
        val displayOptions = if (question.allowWriteIn) {
            question.optionsByCount.take(revealed.coerceAtLeast(WRITE_IN_TOP_N))
        } else {
            question.options
        }
        displayOptions.forEach { option ->
            OptionRow(
                question = question,
                option = option,
                interactive = interactive,
                busy = option.id == busyOptionId,
                onClick = { onOptionClick(option.id) },
            )
        }

        if (question.allowWriteIn) {
            val remaining = question.options.size - displayOptions.size
            if (remaining > 0) {
                if (moreBusy) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                } else {
                    TextButton(
                        onClick = onShowMore,
                        modifier = Modifier.testTag(ArbitraryPollCardTestTags.more(question.id)),
                    ) { Text("Show more ($remaining)") }
                }
            }

            if (interactive || writeInOpen) {
                if (writeInOpen) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = writeInText,
                            onValueChange = onWriteInTextChange,
                            enabled = !writeInBusy,
                            singleLine = true,
                            label = { Text("Your answer") },
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                            keyboardActions = KeyboardActions(onDone = { onSubmitWriteIn() }),
                            modifier = Modifier
                                .weight(1f)
                                .testTag(ArbitraryPollCardTestTags.writeInInput(question.id)),
                        )
                        if (writeInBusy) {
                            CircularProgressIndicator(
                                strokeWidth = 2.dp,
                                modifier = Modifier.padding(start = 8.dp).size(18.dp),
                            )
                        } else {
                            TextButton(
                                onClick = onSubmitWriteIn,
                                enabled = writeInText.isNotBlank(),
                                modifier = Modifier.testTag(ArbitraryPollCardTestTags.writeInSubmit(question.id)),
                            ) { Text("Add") }
                        }
                    }
                } else {
                    TextButton(
                        onClick = onToggleWriteIn,
                        modifier = Modifier.testTag(ArbitraryPollCardTestTags.writeInAdd(question.id)),
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Text("Add your own answer", modifier = Modifier.padding(start = 6.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun OptionRow(
    question: ArbitraryPollQuestion,
    option: ArbitraryPollOption,
    interactive: Boolean,
    busy: Boolean,
    onClick: () -> Unit,
) {
    val selected = question.isSelected(option.id)
    val percent = question.percentFor(option.id)
    val fraction by animateFloatAsState(targetValue = percent / 100f, label = "pollBar")

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(44.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surface)
            .selectable(
                selected = selected,
                enabled = interactive,
                role = if (question.multiSelect) Role.Checkbox else Role.RadioButton,
                onClick = onClick,
            )
            .testTag(ArbitraryPollCardTestTags.option(option.id)),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(44.dp)
                .background(
                    if (selected) {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)
                    } else {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
                    },
                ),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp).height(44.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = option.text,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                )
                if (option.isWriteIn) {
                    Text(
                        text = "Added by a voter",
                        style = MaterialTheme.typography.labelSmall,
                        fontStyle = FontStyle.Italic,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag(ArbitraryPollCardTestTags.writeInBadge(option.id)),
                    )
                }
            }
            if (busy) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
            } else {
                Text(
                    text = "$percent% (${option.count})",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
