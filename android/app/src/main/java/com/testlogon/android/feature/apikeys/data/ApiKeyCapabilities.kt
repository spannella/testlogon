package com.testlogon.android.feature.apikeys.data

/**
 * Batch 8 (#17) - the CANONICAL set of API-key capabilities, mirrored from the backend
 * `app/services/api_key_capabilities.py` `CANONICAL_API_KEY_CAPABILITIES`. These are the only values the
 * create/scopes endpoints accept; the create + detail screens render this catalog as a labelled multi-select
 * (one chip / checkbox per capability) instead of a free-text field.
 *
 * Grouped by product area for display. [CAPABILITY_IMPLICATIONS] mirrors the server's broader->narrower
 * inheritance so the UI can hint that a broad grant already covers narrower ones (the server expands these
 * server-side regardless).
 */
data class ApiCapability(
    val id: String,
    val group: String,
    val action: String,
)

object ApiKeyCapabilities {

    /**
     * The backend WILDCARD capability id (mirrors `api_key_capabilities.py` WILDCARD_API_KEY_CAPABILITY).
     * A key holding [WILDCARD] can do EVERYTHING via the API; the backend grants it ONLY to admin/root owners
     * (a non-admin owner selecting it gets a 403 `api_key_wildcard_forbidden`, surfaced inline on create).
     */
    const val WILDCARD: String = "admin:all"

    /** Verbatim wire ids, in catalog order (must match the backend canonical set). */
    val ALL: List<ApiCapability> = listOf(
        ApiCapability(WILDCARD, "Full access", "Full access (admin)"),
        ApiCapability("ads:manage", "Ads", "Manage"),
        ApiCapability("ads:read", "Ads", "Read"),
        ApiCapability("ads:serve", "Ads", "Serve"),
        ApiCapability("filemanager:admin", "File manager", "Admin"),
        ApiCapability("filemanager:read", "File manager", "Read"),
        ApiCapability("filemanager:share", "File manager", "Share"),
        ApiCapability("filemanager:write", "File manager", "Write"),
        ApiCapability("kyc:admin", "KYC", "Admin"),
        ApiCapability("kyc:read", "KYC", "Read"),
        ApiCapability("kyc:submit", "KYC", "Submit"),
        ApiCapability("kyc:upload", "KYC", "Upload"),
        ApiCapability("kyc:webhook", "KYC", "Webhook"),
        ApiCapability("messager:manage", "Messaging", "Manage"),
        ApiCapability("messager:read", "Messaging", "Read"),
        ApiCapability("messager:write", "Messaging", "Write"),
        ApiCapability("newsfeed:moderate", "Newsfeed", "Moderate"),
        ApiCapability("newsfeed:read", "Newsfeed", "Read"),
        ApiCapability("newsfeed:write", "Newsfeed", "Write"),
        // APIK-E1-2: distinct standalone money scope (tips / paid-unlock); does NOT imply read/write.
        ApiCapability("newsfeed:tips", "Newsfeed", "Tips (money)"),
        ApiCapability("shopping:cart:write", "Shopping", "Cart write"),
        ApiCapability("shopping:catalog:read", "Shopping", "Catalog read"),
        ApiCapability("shopping:checkout:write", "Shopping", "Checkout write"),
        ApiCapability("shopping:orders:read", "Shopping", "Orders read"),
        ApiCapability("tickets:admin", "Support tickets", "Admin"),
        ApiCapability("tickets:read", "Support tickets", "Read"),
        ApiCapability("tickets:write", "Support tickets", "Write"),
        // APIK-E0-2/E4: groups capability family. manage>=write>=read; treasury is a standalone money scope.
        ApiCapability("groups:read", "Groups", "Read"),
        ApiCapability("groups:write", "Groups", "Write"),
        ApiCapability("groups:manage", "Groups", "Manage"),
        ApiCapability("groups:treasury", "Groups", "Treasury (money)"),
        // APIK-E4: group fundraising campaign/fundraiser CRUD (standalone money scope).
        ApiCapability("fundraising:write", "Fundraising", "Write (money)"),
        // APIK-E0-2/E5: video capability family. manage>=write>=read & manage>=publish; moderate>=read.
        // publish/moderate/monetize are distinct high-priv scopes (monetize/moderate standalone).
        ApiCapability("video:read", "Video", "Read"),
        ApiCapability("video:write", "Video", "Write"),
        ApiCapability("video:manage", "Video", "Manage"),
        ApiCapability("video:publish", "Video", "Publish"),
        ApiCapability("video:moderate", "Video", "Moderate"),
        ApiCapability("video:monetize", "Video", "Monetize (money)"),
    )

    private val BY_ID: Map<String, ApiCapability> = ALL.associateBy { it.id }

    /** True when [id] is the all-powerful wildcard capability. */
    fun isWildcard(id: String): Boolean = id == WILDCARD

    /** Catalog in display order, grouped by product area (groups preserve first-seen order). */
    val GROUPED: List<Pair<String, List<ApiCapability>>> =
        ALL.groupBy { it.group }.map { (group, caps) -> group to caps }

    /** Broad -> narrower implied capabilities (mirrors the server's CAPABILITY_IMPLICATIONS). */
    val IMPLICATIONS: Map<String, List<String>> = mapOf(
        "ads:manage" to listOf("ads:read", "ads:serve"),
        "filemanager:admin" to listOf("filemanager:read", "filemanager:write", "filemanager:share"),
        "kyc:admin" to listOf("kyc:read", "kyc:submit", "kyc:upload", "kyc:webhook"),
        "messager:manage" to listOf("messager:read", "messager:write"),
        "newsfeed:moderate" to listOf("newsfeed:read", "newsfeed:write"),
        "tickets:admin" to listOf("tickets:read", "tickets:write"),
        // APIK-E0-2: groups/video inheritance (treasury/fundraising/monetize/tips are standalone).
        "groups:manage" to listOf("groups:write"),
        "groups:write" to listOf("groups:read"),
        "video:manage" to listOf("video:write", "video:publish"),
        "video:write" to listOf("video:read"),
        "video:moderate" to listOf("video:read"),
    )

    /** A short human label for a capability id (falls back to the raw id for an unknown server value). */
    fun label(id: String): String = BY_ID[id]?.let { "${it.group} · ${it.action}" } ?: id

    /** True if [id] is part of the known canonical catalog. */
    fun isKnown(id: String): Boolean = BY_ID.containsKey(id)
}
