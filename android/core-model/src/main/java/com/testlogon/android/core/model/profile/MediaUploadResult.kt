package com.testlogon.android.core.model.profile

/**
 * AND-074 — result of a profile photo upload.
 *
 * `url` is the server's convenience copy of the just-uploaded image; `profile` (when present) is the
 * full updated profile, the preferred source of truth for `profilePhotoUrl`/`coverPhotoUrl`.
 */
data class MediaUploadResult(
    val url: String?,
    val profile: Profile?,
)
