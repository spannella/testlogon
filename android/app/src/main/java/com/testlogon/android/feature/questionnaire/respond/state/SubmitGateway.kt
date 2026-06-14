package com.testlogon.android.feature.questionnaire.respond.state

import com.testlogon.android.core.model.questionnaire.AnswerValue

/**
 * AND-351 FR-8 - an immutable snapshot of the current answers handed to save/resume and to the submit
 * gateway. A plain Map view (visible-or-not normalization is the VM's concern); aligns with AND-348's
 * answers_by_question_id shape so the session repository can persist it directly.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
data class RespondentAnswers(
    val values: Map<String, AnswerValue>,
)

/**
 * AND-351 FR-7 - the SUBMIT seam (the ONLY side-effecting dependency of the form state machine). The VM
 * transitions Submitting -> Submitted on a returned [SubmitResult.Success] or -> Failed on a
 * [SubmitResult.Failure] (or a thrown exception, which the VM catches). The production binding is AND-349
 * (its repository submit); the DEFAULT here is a NO-OP stub that returns success with a null receipt so
 * the form is independently constructable/testable without the network.
 */
fun interface SubmitGateway {
    /** Submits [answers]; never expected to throw, but the VM also treats a thrown error as a failure. */
    suspend fun submit(answers: RespondentAnswers): SubmitResult
}

/** AND-351 - the result of a [SubmitGateway.submit]. Sealed + exhaustive. */
sealed interface SubmitResult {
    /** Accepted. [receipt] is the optional server handle surfaced in [SubmitPhase.Submitted]. */
    data class Success(val receipt: String?) : SubmitResult

    /** Rejected/failed. [message] is surfaced as [QuestionnaireUiState.Ready.submitError]. */
    data class Failure(val message: String) : SubmitResult
}

/**
 * AND-351 - the DEFAULT no-op [SubmitGateway]: records nothing, always succeeds with a null receipt.
 * AND-349 supplies the real network-backed implementation in production; this keeps the VM Hilt- and
 * test-constructable in isolation (no network in the acceptance test target).
 */
object NoOpSubmitGateway : SubmitGateway {
    override suspend fun submit(answers: RespondentAnswers): SubmitResult = SubmitResult.Success(null)
}
