package com.testlogon.android.data.admin

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-403 - the client-side admin-role gate seam (AND-403 §4 "Role gating, two layers").
 *
 * [CORRECTED contract - AND-403 §2/§3 FR-1/§13 Q1/Open-assumption A3]: the admin role is NOT in `GET /ui/me`
 * (which carries no role). The web client derives it from the decoded JWT access-token `role` claim
 * (`"admin"`/`"root"`). The TestLogon Android client, however, is COOKIE-based (AND-027): it does NOT obtain or
 * store a client-readable access token, so there is NO `role` claim to decode on-device today (token issuance is
 * AND-027 scope - spec Open-assumption A3). There is therefore no authoritative client-side role signal yet.
 *
 * Consequently this feature follows the ESTABLISHED admin-screen pattern in this codebase (cf. the AND-377
 * helpdesk dashboard "self-gates via the 403 role signal" and the AND-248 admin billing-config screen): the
 * BACKEND `403` is the final authority (defense in depth - AND-403 §4 data-layer point 2 / §8 / FR-8). This seam
 * exists so the navigation + ViewModel layers have a single, swappable place to consult a client-side role once
 * AND-027 surfaces the token; the default impl returns [AdminRole.UNKNOWN] (do NOT pre-emptively hide the entry
 * or skip the read - let the server `403` decide), which keeps the entry visible and the data-layer 403 -> the
 * Forbidden state authoritative. A real implementation can return [AdminRole.ADMIN]/[AdminRole.ROOT] (-> proceed)
 * or [AdminRole.NONE] (-> emit Forbidden WITHOUT issuing any admin request, satisfying AND-403 AC-2 / TC-03).
 */
enum class AdminRole {
    /** Verified non-admin: the VM emits Forbidden WITHOUT a network call (AC-2 / TC-03). */
    NONE,

    /** General admin (`role == "admin"`): full admin reads allowed. */
    ADMIN,

    /** Root (`role == "root"`): full admin reads allowed. */
    ROOT,

    /**
     * Role not determinable on-device (no client-readable token yet - the cookie-session default). The client
     * gate does NOT block; the backend `403` is the authority. This is the shipped default.
     */
    UNKNOWN,
}

/** True when the role is permitted to attempt admin reads (ADMIN, ROOT, or the undeterminable default). */
val AdminRole.canAttemptAdminReads: Boolean
    get() = this != AdminRole.NONE

/**
 * AND-403 - the swappable role seam consulted by the admin nav guard + ViewModel. Returns [AdminRole.UNKNOWN]
 * by default on this cookie-session client (see [DefaultAdminRoleProvider]); the backend `403` is authoritative.
 */
interface AdminRoleProvider {
    /** The caller's current admin role, best-effort. UNKNOWN on a client with no readable token. */
    fun currentRole(): AdminRole

    /** Convenience: may the caller attempt admin reads? (false ONLY for a verified non-admin). */
    fun mayAttemptAdminReads(): Boolean = currentRole().canAttemptAdminReads
}

/**
 * AND-403 - default role provider for the COOKIE-session client: there is no client-readable JWT `role` claim
 * (AND-027 has not surfaced one), so the role is [AdminRole.UNKNOWN] and the backend `403` decides. Swap this
 * Hilt binding for a token-decoding impl once AND-027 exposes the access token (spec Open-assumption A3).
 */
@Singleton
class DefaultAdminRoleProvider @Inject constructor() : AdminRoleProvider {
    override fun currentRole(): AdminRole = AdminRole.UNKNOWN
}

/** AND-403 - binds the default (cookie-session) admin-role provider seam. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdminRoleModule {

    @Binds
    @Singleton
    abstract fun bindAdminRoleProvider(impl: DefaultAdminRoleProvider): AdminRoleProvider
}
