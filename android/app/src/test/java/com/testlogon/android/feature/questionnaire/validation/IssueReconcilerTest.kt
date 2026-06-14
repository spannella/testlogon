package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.ValidationIssue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-350 - JVM tests for the PURE [IssueReconciler]: local + server union de-duped by code (server wins
 * on display), and the inline-vs-banner key split (bare questionId -> inline; group:/form: -> banner).
 */
class IssueReconcilerTest {

    @Test
    fun bareKeys_inline_prefixedKeys_banner() {
        val server = mapOf(
            "q1" to listOf(ValidationIssue(code = "required", message = "Server required")),
            "group:age" to listOf(ValidationIssue(code = "cross", message = "Ages must agree")),
            "form:total" to listOf(ValidationIssue(code = "sum", message = "Total too high")),
        )
        val result = IssueReconciler.reconcile(localIssues = emptyMap(), serverErrors = server)
        assertEquals("Server required", result.fieldErrors["q1"])
        assertTrue(result.fieldErrors.keys.none { it.startsWith("group:") || it.startsWith("form:") })
        assertEquals(listOf("Ages must agree", "Total too high"), result.formBannerIssues)
    }

    @Test
    fun union_dedupByCode_serverWinsOnDisplay() {
        val local = mapOf(
            "q1" to listOf(ClientValidator.LocalIssue(code = "required", message = "Local required")),
        )
        val server = mapOf(
            "q1" to listOf(ValidationIssue(code = "required", message = "Server required", blocking = true)),
        )
        val result = IssueReconciler.reconcile(localIssues = local, serverErrors = server)
        // Same code -> de-duped; server message wins.
        assertEquals("Server required", result.fieldErrors["q1"])
    }

    @Test
    fun union_distinctCodes_blockingChosenFirst() {
        val local = mapOf(
            "q1" to listOf(ClientValidator.LocalIssue(code = "min_length", message = "Too short")),
        )
        val server = mapOf(
            "q1" to listOf(ValidationIssue(code = "banned", message = "Not allowed", blocking = true)),
        )
        val result = IssueReconciler.reconcile(localIssues = local, serverErrors = server)
        // The blocking server issue is chosen for the inline message even though local was first.
        assertEquals("Not allowed", result.fieldErrors["q1"])
    }

    @Test
    fun localOnly_whenNoServerError() {
        val local = mapOf(
            "q1" to listOf(ClientValidator.LocalIssue(code = "required", message = "Local required")),
        )
        val result = IssueReconciler.reconcile(localIssues = local, serverErrors = emptyMap())
        assertEquals("Local required", result.fieldErrors["q1"])
        assertTrue(result.formBannerIssues.isEmpty())
    }
}
