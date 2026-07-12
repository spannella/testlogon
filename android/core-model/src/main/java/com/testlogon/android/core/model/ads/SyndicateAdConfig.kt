package com.testlogon.android.core.model.ads

/**
 * ADV2-710 (F7) — the per-syndicate ad-placement split, as shown/edited in the split-config UI.
 *
 * When the SYNDICATE ITSELF advertises in front of a member's content, the 70% content-owner share splits
 * into the MEMBER's cut ([memberShareBps] of that 70%) + the syndicate TREASURY ([treasuryShareBps] = the
 * remainder). Platform's 30% of the gross charge is unchanged. An EXTERNAL advertiser never triggers this
 * split (the member keeps the full 70%, treasury 0). All bps are out of 10000 (100%).
 */
data class SyndicateAdPlacementConfig(
    val syndicateId: String,
    val memberShareBps: Int,
    val treasuryShareBps: Int,
    val defaultMemberShareBps: Int,
) {
    /** The member's cut of the 70% content-owner share, as a percent string (e.g. "70%"). */
    val memberPercentOfOwner: Int get() = (memberShareBps + 50) / 100

    /** The treasury's cut of the 70% content-owner share, as a percent (integer). */
    val treasuryPercentOfOwner: Int get() = (treasuryShareBps + 50) / 100

    /** The member's NET share of the GROSS charge (member cut of the 70%), rounded to a percent. */
    val memberNetPercent: Int get() = (memberShareBps * 70 / 100 + 50) / 100

    /** The treasury's NET share of the GROSS charge, rounded to a percent. */
    val treasuryNetPercent: Int get() = (treasuryShareBps * 70 / 100 + 50) / 100
}
