package com.testlogon.android.feature.files.mounts

import com.testlogon.android.core.model.files.FileMountCreateRequest
import java.util.Locale

/**
 * FM-MOUNTS - PURE (no Android deps), JVM-testable helpers for the file-manager Mounts surface:
 * provider-config VALIDATION, mode/status normalisation + labels, and mount-path/prefix canonicalisation.
 * Kept framework-free so the validation logic is unit-tested without Robolectric (mirrors the FE-170
 * TradingDocsMath idiom).
 *
 * The rules mirror the backend Pydantic constraints (app/routers/filemanager.py FileMountCreateIn):
 * mount_path 1..2048 chars, bucket 3..255 chars, prefix <= 2048 chars, mode in {read_only, read_write},
 * status in {active, degraded, error, disabled}, auth_ref 1..256 chars. We validate CLIENT-SIDE first so
 * the user gets inline field errors before a round-trip; the server remains the source of truth (a 422
 * still surfaces its detail).
 */

/** Canonical mount access modes (backend `mode` values), in display order. */
val MOUNT_MODES: List<String> = listOf("read_only", "read_write")

/** Canonical mount status values (backend `status` values), in display order. */
val MOUNT_STATUSES: List<String> = listOf("active", "degraded", "error", "disabled")

private const val MOUNT_PATH_MAX = 2048
private const val BUCKET_MIN = 3
private const val BUCKET_MAX = 255
private const val PREFIX_MAX = 2048
private const val AUTH_REF_MIN = 1
private const val AUTH_REF_MAX = 256

/** Which field a [MountValidationError] is about (drives inline field highlighting). */
enum class MountField { MOUNT_PATH, BUCKET, PREFIX, MODE, AUTH_REF, STATUS }

/** A single, user-facing validation problem tied to a [field]. */
data class MountValidationError(val field: MountField, val message: String)

/** Result of validating a mount draft: [errors] empty == valid. */
data class MountValidation(val errors: List<MountValidationError>) {
    val isValid: Boolean get() = errors.isEmpty()
    fun errorFor(field: MountField): String? = errors.firstOrNull { it.field == field }?.message
}

/** Human label for a mount [mode] code; unknown codes fall back to a title-cased raw code. */
fun mountModeLabel(mode: String): String = when (mode.lowercase(Locale.ROOT)) {
    "read_only" -> "Read only"
    "read_write" -> "Read / write"
    else -> titleCase(mode)
}

/** Human label for a mount [status] code; unknown codes fall back to a title-cased raw code. */
fun mountStatusLabel(status: String): String = when (status.lowercase(Locale.ROOT)) {
    "active" -> "Active"
    "degraded" -> "Degraded"
    "error" -> "Error"
    "disabled" -> "Disabled"
    else -> titleCase(status)
}

/**
 * Canonicalise a mount path: trim, ensure a single leading slash, drop a trailing slash (except root).
 * Blank input canonicalises to "/". This is what the create/update request should carry.
 */
fun canonicalMountPath(raw: String): String {
    val trimmed = raw.trim()
    if (trimmed.isEmpty()) return "/"
    val withLead = if (trimmed.startsWith("/")) trimmed else "/$trimmed"
    val collapsed = withLead.replace(Regex("/+"), "/")
    return if (collapsed.length > 1) collapsed.trimEnd('/').ifEmpty { "/" } else collapsed
}

/** Canonicalise an optional prefix: trim; blank -> null (the backend treats absent == no prefix). */
fun canonicalPrefix(raw: String?): String? = raw?.trim()?.ifBlank { null }

private val BUCKET_RE = Regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$")

/**
 * Validate a mount draft (the fields the user typed). Returns a [MountValidation]; empty errors == OK.
 * [mode] / [status] are validated against the canonical enum sets. This does NOT hit the network.
 */
fun validateMountDraft(
    mountPath: String,
    bucket: String,
    prefix: String?,
    mode: String,
    authRef: String,
    status: String,
): MountValidation {
    val errors = mutableListOf<MountValidationError>()

    val path = mountPath.trim()
    when {
        path.isEmpty() -> errors += MountValidationError(MountField.MOUNT_PATH, "Mount path is required")
        path.length > MOUNT_PATH_MAX ->
            errors += MountValidationError(MountField.MOUNT_PATH, "Mount path is too long")
    }

    val b = bucket.trim()
    when {
        b.isEmpty() -> errors += MountValidationError(MountField.BUCKET, "Bucket is required")
        b.length < BUCKET_MIN ->
            errors += MountValidationError(MountField.BUCKET, "Bucket must be at least $BUCKET_MIN characters")
        b.length > BUCKET_MAX ->
            errors += MountValidationError(MountField.BUCKET, "Bucket is too long")
        !BUCKET_RE.matches(b) ->
            errors += MountValidationError(
                MountField.BUCKET,
                "Bucket may use lowercase letters, digits, dots and hyphens only",
            )
    }

    val p = prefix?.trim().orEmpty()
    if (p.length > PREFIX_MAX) errors += MountValidationError(MountField.PREFIX, "Prefix is too long")

    if (mode.lowercase(Locale.ROOT) !in MOUNT_MODES) {
        errors += MountValidationError(MountField.MODE, "Choose an access mode")
    }

    val a = authRef.trim()
    when {
        a.length < AUTH_REF_MIN -> errors += MountValidationError(MountField.AUTH_REF, "Credential reference is required")
        a.length > AUTH_REF_MAX -> errors += MountValidationError(MountField.AUTH_REF, "Credential reference is too long")
    }

    if (status.lowercase(Locale.ROOT) !in MOUNT_STATUSES) {
        errors += MountValidationError(MountField.STATUS, "Choose a status")
    }

    return MountValidation(errors)
}

/**
 * Build a canonical [FileMountCreateRequest] from a validated draft (call [validateMountDraft] first).
 * Applies [canonicalMountPath] / [canonicalPrefix] and lowercases the enums + bucket so the wire body is
 * normalised regardless of user casing/whitespace.
 */
fun buildCreateRequest(
    mountPath: String,
    bucket: String,
    prefix: String?,
    mode: String,
    authRef: String,
    status: String,
): FileMountCreateRequest = FileMountCreateRequest(
    mount_path = canonicalMountPath(mountPath),
    bucket = bucket.trim().lowercase(Locale.ROOT),
    prefix = canonicalPrefix(prefix),
    mode = mode.lowercase(Locale.ROOT),
    auth_ref = authRef.trim(),
    status = status.lowercase(Locale.ROOT),
)

private fun titleCase(raw: String): String =
    raw.replace('_', ' ')
        .split(' ')
        .filter { it.isNotEmpty() }
        .joinToString(" ") { w ->
            w.replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.ROOT) else it.toString() }
        }
        .ifBlank { raw }
