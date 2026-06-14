package com.testlogon.android.data.profile

/**
 * AND-074 — which profile image is being uploaded.
 *
 * The wire `kind` path segment is `profile` (avatar) or `cover` — verified from
 * src/api/endpoints/profile.ts: uploadProfilePhoto(kind: "profile" | "cover", ...).
 */
enum class MediaKind(val wire: String) {
    AVATAR("profile"),
    COVER("cover"),
}
