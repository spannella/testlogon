package com.testlogon.android.core.data.paywall

import androidx.room.ColumnInfo
import androidx.room.Entity

/**
 * AND-177 — durable record of a locked post the current user has unlocked (paid for).
 *
 * Keyed by the composite (user_sub, post_id) so one user's entitlements never leak to another on a
 * shared device; [com.testlogon.android.core.data.paywall.EntitlementDao.clearForUser] runs on
 * logout/account switch. The presence of a row means the content may be revealed without re-charging,
 * surviving a fresh feed fetch, process death, or an offline open (AND-177 FR-4). No payment data /
 * card / PAN is ever stored here.
 *
 * Backed by the shared [com.testlogon.android.core.data.db.TestLogonDatabase] (DB v4).
 */
@Entity(tableName = "entitlement", primaryKeys = ["user_sub", "post_id"])
data class EntitlementEntity(
    @ColumnInfo(name = "user_sub") val userSub: String,
    @ColumnInfo(name = "post_id") val postId: String,
    @ColumnInfo(name = "unlocked_at_epoch_ms") val unlockedAtEpochMs: Long,
    /** purchase | already_entitled | sync */
    @ColumnInfo(name = "source") val source: String = "purchase",
)
