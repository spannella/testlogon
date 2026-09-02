package com.testlogon.android.feature.files.mounts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** FM-MOUNTS - pure JVM tests for [MountMath] provider-config validation + normalisation. */
class MountMathTest {

    // ---- labels ----

    @Test
    fun modeLabels_areHumanReadable() {
        assertEquals("Read only", mountModeLabel("read_only"))
        assertEquals("Read / write", mountModeLabel("read_write"))
    }

    @Test
    fun modeLabel_unknown_titleCasesRawCode() {
        assertEquals("Weird Mode", mountModeLabel("weird_mode"))
    }

    @Test
    fun statusLabels_areHumanReadable() {
        assertEquals("Active", mountStatusLabel("active"))
        assertEquals("Degraded", mountStatusLabel("degraded"))
        assertEquals("Error", mountStatusLabel("error"))
        assertEquals("Disabled", mountStatusLabel("disabled"))
    }

    // ---- canonicalisation ----

    @Test
    fun canonicalMountPath_addsLeadingSlash_andTrimsTrailing() {
        assertEquals("/docs/reports", canonicalMountPath("docs/reports/"))
    }

    @Test
    fun canonicalMountPath_collapsesDoubleSlashes() {
        assertEquals("/a/b", canonicalMountPath("//a//b//"))
    }

    @Test
    fun canonicalMountPath_blankBecomesRoot() {
        assertEquals("/", canonicalMountPath("   "))
        assertEquals("/", canonicalMountPath("/"))
    }

    @Test
    fun canonicalPrefix_blankBecomesNull_elseTrimmed() {
        assertNull(canonicalPrefix(""))
        assertNull(canonicalPrefix("   "))
        assertNull(canonicalPrefix(null))
        assertEquals("team/", canonicalPrefix("  team/  "))
    }

    // ---- validation: happy path ----

    @Test
    fun validate_validDraft_hasNoErrors() {
        val v = validateMountDraft(
            mountPath = "/docs",
            bucket = "my-bucket",
            prefix = "team/",
            mode = "read_only",
            authRef = "cred-1",
            status = "active",
        )
        assertTrue(v.isValid)
        assertTrue(v.errors.isEmpty())
    }

    // ---- validation: field-level failures ----

    @Test
    fun validate_blankMountPath_reportsMountPathError() {
        val v = validateMountDraft("   ", "my-bucket", null, "read_only", "cred", "active")
        assertFalse(v.isValid)
        assertEquals("Mount path is required", v.errorFor(MountField.MOUNT_PATH))
    }

    @Test
    fun validate_shortBucket_reportsBucketError() {
        val v = validateMountDraft("/d", "ab", null, "read_only", "cred", "active")
        assertFalse(v.isValid)
        assertTrue(v.errorFor(MountField.BUCKET)!!.contains("at least"))
    }

    @Test
    fun validate_bucketWithUppercase_isRejected() {
        val v = validateMountDraft("/d", "MyBucket", null, "read_only", "cred", "active")
        assertFalse(v.isValid)
        assertEquals(MountField.BUCKET, v.errors.first().field)
    }

    @Test
    fun validate_bucketWithUnderscore_isRejected() {
        val v = validateMountDraft("/d", "my_bucket", null, "read_only", "cred", "active")
        assertFalse(v.isValid)
        assertNotNull_(v.errorFor(MountField.BUCKET))
    }

    @Test
    fun validate_badMode_reportsModeError() {
        val v = validateMountDraft("/d", "my-bucket", null, "sideways", "cred", "active")
        assertFalse(v.isValid)
        assertNotNull_(v.errorFor(MountField.MODE))
    }

    @Test
    fun validate_blankAuthRef_reportsAuthRefError() {
        val v = validateMountDraft("/d", "my-bucket", null, "read_only", "  ", "active")
        assertFalse(v.isValid)
        assertNotNull_(v.errorFor(MountField.AUTH_REF))
    }

    @Test
    fun validate_badStatus_reportsStatusError() {
        val v = validateMountDraft("/d", "my-bucket", null, "read_only", "cred", "gone")
        assertFalse(v.isValid)
        assertNotNull_(v.errorFor(MountField.STATUS))
    }

    @Test
    fun validate_accumulatesMultipleErrors() {
        val v = validateMountDraft("", "x", null, "nope", "", "nope")
        // mount_path, bucket, mode, auth_ref, status all fail.
        assertTrue(v.errors.size >= 5)
    }

    // ---- build request ----

    @Test
    fun buildCreateRequest_normalisesFields() {
        val req = buildCreateRequest(
            mountPath = "docs/reports/",
            bucket = "  My-Bucket  ",
            prefix = "  team/  ",
            mode = "READ_WRITE",
            authRef = "  cred-9  ",
            status = "ACTIVE",
        )
        assertEquals("/docs/reports", req.mount_path)
        assertEquals("my-bucket", req.bucket)
        assertEquals("team/", req.prefix)
        assertEquals("read_write", req.mode)
        assertEquals("cred-9", req.auth_ref)
        assertEquals("active", req.status)
    }

    @Test
    fun buildCreateRequest_blankPrefixBecomesNull() {
        val req = buildCreateRequest("/d", "my-bucket", "  ", "read_only", "cred", "active")
        assertNull(req.prefix)
    }

    private fun assertNotNull_(value: String?) {
        assertTrue("expected a non-null error message", value != null)
    }
}
