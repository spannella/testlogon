package com.testlogon.android.feature.profile

/** AND-071..074 — stable Compose test tags for the profile screens. */
object ProfileTestTags {
    // Own profile
    const val OWN_SCREEN = "own_profile_screen"
    const val OWN_LOADING = "own_profile_loading"
    const val OWN_ERROR = "own_profile_error"
    const val OWN_CONTENT = "own_profile_content"
    const val OWN_DISPLAY_NAME = "profile_displayName"
    const val OWN_DESCRIPTION = "profile_description"
    const val OWN_AVATAR = "profile_avatar"
    const val OWN_EDIT = "profile_edit"
    const val OWN_STALE_BANNER = "profile_stale_banner"
    const val OWN_CHANGE_PHOTO = "profile_change_photo"

    // Edit profile
    const val EDIT_SCREEN = "edit_profile_screen"
    const val EDIT_DISPLAY_NAME = "edit_display_name"
    const val EDIT_DESCRIPTION = "edit_description"
    const val EDIT_TITLE = "edit_title"
    const val EDIT_LOCATION = "edit_location"
    const val EDIT_SAVE = "edit_save"
    const val EDIT_DISCARD_DIALOG = "edit_discard_dialog"

    // Public profile
    const val PUBLIC_ROOT = "public_profile_root"
    const val PUBLIC_LOADING = "public_profile_loading"
    const val PUBLIC_CONTENT = "public_profile_content"
    const val PUBLIC_NOT_FOUND = "public_notfound"
    const val PUBLIC_RATE_LIMITED = "public_ratelimited"
    const val PUBLIC_ERROR = "public_error"
    const val PUBLIC_STALE_BANNER = "public_stale_banner"

    // AND-390: public-profile polish (share/copy affordances + unauth Sign-in CTA + auth-only gates).
    const val PUBLIC_SHARE = "public_share"
    const val PUBLIC_COPY_LINK = "public_copy_link"
    const val PUBLIC_SIGN_IN_CTA = "public_sign_in_cta"
    const val PUBLIC_SUBSCRIBE = "public_subscribe"
    const val PUBLIC_OPEN_FANCLUB = "public_open_fanclub"
    const val PUBLIC_REPORT_USER = "public_report_user"
}
