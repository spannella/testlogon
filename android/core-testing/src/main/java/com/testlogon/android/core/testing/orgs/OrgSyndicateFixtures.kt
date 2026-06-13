package com.testlogon.android.core.testing.orgs

import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.delegates.DelegatePermission
import com.testlogon.android.core.model.delegates.DelegationContext
import com.testlogon.android.core.model.delegates.ManagedCreator
import com.testlogon.android.core.model.delegates.ManagingCreator
import com.testlogon.android.core.model.delegates.toDelegationContext
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SplitMode
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasurySummary

/**
 * AND-362 - SHARED, dependency-light domain fixtures for the orgs / groups / syndicates / collaborations /
 * delegates epic (E46) test suites.
 *
 * SCOPE (obey the core-testing dependency rule): core-testing depends on core-MODEL ONLY, so EVERYTHING here
 * references ONLY core-model types - the AND-353 [Org] / [OrgMember] / [OrgInvite] + [OrgRole], the AND-356
 * [SyndicateOverview] / [TreasurySummary] / [RevenueSplitPolicy] (+ [SplitMode]), the AND-358 [Collaboration]
 * (+ [CollabStatus]), the AND-355 [Group] / [GroupMember] (+ [GroupRole]) and the AND-359 / AND-360 delegate
 * types ([ManagedCreator] / [ManagingCreator] / [DelegationContext] + [DelegatePermission]). There are NO
 * core-network DTOs and NO Moshi adapters here (those are core-network scoped; a fixture needing a :app or
 * core-network type lives in that module's own test source, not here). These are PURE in-memory domain
 * builders, not JSON.
 *
 * WHY (anti-duplication): the existing E46 suites each hand-roll tiny throwaway domain samples. This
 * consolidates one realistic, reusable set covering the varied shapes the suites care about: every [OrgRole]
 * (owner / admin / member / viewer), both a WEIGHTED and an EQUAL [RevenueSplitPolicy] (weighted balanced AND
 * a >1bp mismatch), a collaboration whose split totals 100 AND one that does NOT, a group with an admin +
 * member + pending-invite roster, and a delegate [DelegationContext] with a varied permission set. It is
 * ADDITIVE - it does NOT replace the narrow per-test builders any suite already uses.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object OrgSyndicateFixtures {

    // ---- stable ids referenced across fixtures ----

    const val ORG_ID = "org_fixture_1"
    const val SYNDICATE_ID = "syn_fixture_1"
    const val COLLAB_ID = "collab_fixture_1"
    const val GROUP_ID = "grp_fixture_1"
    const val CREATOR_ID = "usr_creator_1"

    const val USER_OWNER = "usr_owner"
    const val USER_ADMIN = "usr_admin"
    const val USER_MEMBER = "usr_member"
    const val USER_VIEWER = "usr_viewer"

    // ---- AND-353: organizations (members / roles / invites) ----

    /** A sample org whose [callerRole] defaults to [OrgRole.ADMIN] (a manager, so management is gated open). */
    fun org(callerRole: OrgRole = OrgRole.ADMIN): Org =
        Org(orgId = ORG_ID, name = "Acme Studios", callerRole = callerRole)

    /** One org member with the given [role] / [status] (status kept raw - the contract pins no enum). */
    fun orgMember(
        userSub: String,
        role: OrgRole,
        status: String = "active",
    ): OrgMember = OrgMember(userSub = userSub, role = role, status = status)

    /**
     * A varied roster carrying ONE member of each typed [OrgRole] (owner / admin / member / viewer), so a
     * test can exercise role-gating and the self-protection (sole-owner / self-remove) paths off one list.
     */
    fun orgRoster(): List<OrgMember> = listOf(
        orgMember(USER_OWNER, OrgRole.OWNER),
        orgMember(USER_ADMIN, OrgRole.ADMIN),
        orgMember(USER_MEMBER, OrgRole.MEMBER),
        orgMember(USER_VIEWER, OrgRole.VIEWER),
    )

    /** A pending org invite (a separate resource from members) defaulting to a viewer-role grant. */
    fun orgInvite(
        inviteId: String = "inv_fixture_1",
        email: String = "invitee@example.com",
        role: OrgRole = OrgRole.VIEWER,
    ): OrgInvite = OrgInvite(
        inviteId = inviteId,
        email = email,
        role = role,
        orgId = ORG_ID,
        orgName = "Acme Studios",
        status = "pending",
        token = "tok_fixture",
    )

    // ---- AND-356: syndicate overview / treasury / revenue-split ----

    /** A sample syndicate overview header; [isAdmin] drives the role badge, [isMember] gates NotMember. */
    fun syndicateOverview(
        isAdmin: Boolean = true,
        isMember: Boolean = true,
    ): SyndicateOverview = SyndicateOverview(
        id = SYNDICATE_ID,
        name = "Aces Collective",
        memberCount = 4,
        isAdmin = isAdmin,
        isMember = isMember,
        currency = "USD",
    )

    /** A sample treasury summary (all amounts are *_cents). */
    fun treasury(): TreasurySummary = TreasurySummary(
        balanceCents = 150_000,
        depositedCents = 200_000,
        disbursedCents = 50_000,
        currency = "USD",
    )

    /**
     * A WEIGHTED revenue-split policy whose weights sum to exactly 10000bps -> [RevenueSplitPolicy.weightSumOk]
     * is true (the balanced, no-banner case).
     */
    fun weightedSplitBalanced(): RevenueSplitPolicy = RevenueSplitPolicy(
        mode = SplitMode.WEIGHTED,
        platformFeeBps = 500,
        weightsBps = mapOf(USER_ADMIN to 6_000, USER_MEMBER to 4_000),
    )

    /**
     * A WEIGHTED revenue-split policy whose weights sum to 9000bps (off by 1000bps, well beyond the 1bp
     * tolerance) -> [RevenueSplitPolicy.weightSumOk] is false (the mismatch-banner case).
     */
    fun weightedSplitMismatch(): RevenueSplitPolicy = RevenueSplitPolicy(
        mode = SplitMode.WEIGHTED,
        platformFeeBps = 500,
        weightsBps = mapOf(USER_ADMIN to 6_000, USER_MEMBER to 3_000),
    )

    /** An EQUAL revenue-split policy (weights are never checked under equal mode -> weightSumOk always true). */
    fun equalSplit(): RevenueSplitPolicy = RevenueSplitPolicy(
        mode = SplitMode.EQUAL,
        platformFeeBps = 0,
    )

    // ---- AND-358: collaborations (two-party revenue-sharing) ----

    /**
     * A collaboration whose percent split totals EXACTLY 100 -> [Collaboration.splitTotalsOk] is true. The
     * [status] raw string and [statusEnum] are kept consistent (active).
     */
    fun collaborationBalanced(): Collaboration = Collaboration(
        id = COLLAB_ID,
        title = "Title Track",
        description = "A two-party split",
        status = "active",
        statusEnum = CollabStatus.ACTIVE,
        initiatorId = USER_ADMIN,
        recipientId = USER_MEMBER,
        split = mapOf(USER_ADMIN to 60, USER_MEMBER to 40),
    )

    /**
     * A collaboration whose percent split totals 99 (NOT 100) -> [Collaboration.splitTotalsOk] is false,
     * driving the non-blocking split-total warning at the UI.
     */
    fun collaborationMismatch(): Collaboration = collaborationBalanced().copy(
        split = mapOf(USER_ADMIN to 60, USER_MEMBER to 39),
    )

    // ---- AND-355: social groups (no owner role; admin_user_id identifies the owner) ----

    /** A sample social group whose [myRole] defaults to [GroupRole.ADMIN] (a manager). */
    fun group(myRole: GroupRole = GroupRole.ADMIN): Group = Group(
        id = GROUP_ID,
        name = "Producers Lounge",
        description = "Studio collaborators",
        memberCount = 3,
        myRole = myRole,
        adminUserId = USER_ADMIN,
    )

    /** One group member with the given [role] / [status] (status raw; "invited" marks a pending entry). */
    fun groupMember(
        userId: String,
        role: GroupRole,
        status: String = "active",
        displayName: String? = null,
    ): GroupMember = GroupMember(
        userId = userId,
        role = role,
        status = status,
        displayName = displayName,
    )

    /**
     * A group roster with an admin, a moderator, a plain member and one PENDING (status == "invited") row,
     * so a test can exercise the canManage gate plus the pending-vs-active partition off one list.
     */
    fun groupRoster(): List<GroupMember> = listOf(
        groupMember(USER_ADMIN, GroupRole.ADMIN, displayName = "Ada"),
        groupMember(USER_MEMBER, GroupRole.MODERATOR, displayName = "Mo"),
        groupMember(USER_VIEWER, GroupRole.MEMBER, displayName = "Vi"),
        groupMember("usr_pending", GroupRole.MEMBER, status = GroupMember.STATUS_INVITED, displayName = "Pat"),
    )

    // ---- AND-359 / AND-360: delegates / manage-as-creator ----

    /**
     * A managed creator the principal MAY manage, carrying a varied wire-permission set (feed read + post and
     * chat read + respond) plus one UNKNOWN-mapping token to prove forward-compat tolerance downstream.
     */
    fun managedCreator(): ManagedCreator = ManagedCreator(
        creatorId = CREATOR_ID,
        permissions = listOf(
            DelegatePermission.FEED_READ.wire,
            DelegatePermission.FEED_POST.wire,
            DelegatePermission.CHAT_READ.wire,
            DelegatePermission.CHAT_RESPOND.wire,
            "future_capability",
        ),
        preset = "manager",
        status = "active",
        label = "Nova",
        acceptedAt = "2026-01-01T00:00:00Z",
    )

    /** The lighter [ManagingCreator] selection (projected from [managedCreator]). */
    fun managingCreator(): ManagingCreator = managedCreator().toManagingCreator()

    /**
     * The typed [DelegationContext] overlay (projected from [managingCreator]); its permission set contains
     * the four recognized typed permissions plus a retained-but-inert [DelegatePermission.UNKNOWN].
     */
    fun delegationContext(): DelegationContext = managingCreator().toDelegationContext()
}
