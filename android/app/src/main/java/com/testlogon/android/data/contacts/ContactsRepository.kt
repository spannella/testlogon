package com.testlogon.android.data.contacts

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

// ── Domain models (surface-facing; DTOs stay in the Api file) ────────────────

/** A saved address-book contact. */
data class SavedContact(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    val isFavorite: Boolean,
    val isBlocked: Boolean,
)

/** A "people you may know" suggestion card. */
data class ContactSuggestion(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    val hint: String,
    val mutualCount: Int,
    val source: String,
)

/** A device-address-book match (Feature 2). */
data class ContactMatch(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    /** Which identifier matched: "email" or "phone" (for the UI label). */
    val matchedBy: String,
)

/** Bidirectional follow relationship snapshot for the contact card. */
data class FollowRelationship(
    val isFollowing: Boolean,
    val isFollowedBy: Boolean,
    val isMutual: Boolean,
    val isBlockedByMe: Boolean = false,
    val isBlockingMe: Boolean = false,
) {
    /** The collapsed relationship the UI switches on. */
    val relationship: SocialRelationship
        get() = SocialGraphMath.relationshipOf(
            isFollowing = isFollowing,
            isFollowedBy = isFollowedBy,
            isMutual = isMutual,
            isBlockedByMe = isBlockedByMe,
            isBlockingMe = isBlockingMe,
        )
}

/** A user in a followers / following / mutual list. */
data class FollowGraphUser(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    val isFollowing: Boolean,
    val isMutual: Boolean,
    val snoozedUntilSeconds: Long?,
    val isSnoozed: Boolean,
)

/** Follower / following totals for a user. */
data class FollowCounts(
    val followerCount: Int,
    val followingCount: Int,
)

/** A currently-snoozed following the viewer owns. */
data class SnoozedFollowing(
    val userId: String,
    val displayName: String,
    val photoUrl: String?,
    val snoozedUntilSeconds: Long,
    val remainingHours: Int?,
)

/**
 * Feature 1 — Contacts data layer over [ContactsApi] + [FollowApi]. Every method returns
 * [ApiResult] so ViewModels get a uniform success / server-failure / offline split (and a
 * distinct offline retry affordance).
 */
interface ContactsRepository {
    suspend fun listContacts(): ApiResult<List<SavedContact>>
    suspend fun suggestions(): ApiResult<List<ContactSuggestion>>
    suspend fun addContact(userId: String): ApiResult<SavedContact>
    suspend fun removeContact(userId: String): ApiResult<Unit>
    suspend fun setFavorite(userId: String, favorite: Boolean): ApiResult<SavedContact>

    /**
     * Feature 2 — read the device address book, hash every email/phone ON-DEVICE, and match
     * against platform users. Raw contacts NEVER leave the device (only hashes are sent).
     * Requires READ_CONTACTS to already be granted.
     */
    suspend fun matchDeviceContacts(): ApiResult<List<ContactMatch>>

    // Follow graph (existing social routes, newly wired on Android).
    suspend fun follow(userId: String): ApiResult<Unit>
    suspend fun unfollow(userId: String): ApiResult<Unit>
    suspend fun followStatus(userId: String): ApiResult<FollowRelationship>

    /**
     * Followers of [userId] (first page). Degrades-on-404: a missing relationship / user surface
     * returns an EMPTY list as Success, never a Failure (this is an additive read).
     */
    suspend fun followers(userId: String, cursor: String? = null): ApiResult<List<FollowGraphUser>>

    /** Followings of [userId] (first page). Degrades-on-404 to an empty list. */
    suspend fun following(userId: String, cursor: String? = null): ApiResult<List<FollowGraphUser>>

    /** Follower / following totals for [userId]. Degrades-on-404 to zeroes. */
    suspend fun followCounts(userId: String): ApiResult<FollowCounts>

    /** Followers the viewer shares with [userId]. Degrades-on-404 to an empty list. */
    suspend fun mutualFollowers(userId: String, cursor: String? = null): ApiResult<List<FollowGraphUser>>

    /** The viewer's currently-snoozed followings. Degrades-on-404 to an empty list. */
    suspend fun snoozedFollowing(): ApiResult<List<SnoozedFollowing>>

    /** Snooze [userId]'s content for [days] (clamped to 1..90). Returns the new expiry (epoch s). */
    suspend fun snoozeFollowing(userId: String, days: Int): ApiResult<Long>

    /** Remove snooze from [userId] (idempotent — a 404 counts as success). */
    suspend fun unsnoozeFollowing(userId: String): ApiResult<Unit>
}

@Singleton
class ContactsRepositoryImpl @Inject constructor(
    private val contactsApi: ContactsApi,
    private val followApi: FollowApi,
    private val deviceContactsReader: DeviceContactsReader,
    private val hasher: ContactMatchHasher,
    private val errorParser: ApiErrorParser,
) : ContactsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listContacts(): ApiResult<List<SavedContact>> = withContext(io) {
        call { contactsApi.listContacts().contacts.map { it.toDomain() } }
    }

    override suspend fun suggestions(): ApiResult<List<ContactSuggestion>> = withContext(io) {
        call { contactsApi.suggestions().suggestions.map { it.toDomain() } }
    }

    override suspend fun addContact(userId: String): ApiResult<SavedContact> = withContext(io) {
        call { contactsApi.addContact(AddContactDto(userId = userId)).toDomain() }
    }

    override suspend fun removeContact(userId: String): ApiResult<Unit> = withContext(io) {
        call { unitFrom(contactsApi.deleteContact(userId)) }
    }

    override suspend fun setFavorite(userId: String, favorite: Boolean): ApiResult<SavedContact> =
        withContext(io) {
            call { contactsApi.updateContact(userId, UpdateContactDto(isFavorite = favorite)).toDomain() }
        }

    override suspend fun matchDeviceContacts(): ApiResult<List<ContactMatch>> = withContext(io) {
        call {
            val ids = deviceContactsReader.read()
            // Hash on-device; drop un-normalizable values; dedupe.
            val emailHashes = ids.emails.mapNotNull { hasher.hashEmail(it) }.distinct()
            val phoneHashes = ids.phones.mapNotNull { hasher.hashPhone(it) }.distinct()
            if (emailHashes.isEmpty() && phoneHashes.isEmpty()) {
                emptyList()
            } else {
                // Cap/batch so a huge address book never exceeds the server's per-field cap.
                val cap = MATCH_HASH_BATCH
                val seen = LinkedHashMap<String, ContactMatch>()
                val emailBatches = emailHashes.chunked(cap)
                val phoneBatches = phoneHashes.chunked(cap)
                val rounds = maxOf(emailBatches.size, phoneBatches.size, 1)
                for (i in 0 until rounds) {
                    val body = ContactMatchDto(
                        emailHashes = emailBatches.getOrElse(i) { emptyList() },
                        phoneHashes = phoneBatches.getOrElse(i) { emptyList() },
                    )
                    if (body.emailHashes.isEmpty() && body.phoneHashes.isEmpty()) continue
                    val res = contactsApi.matchContacts(body)
                    for (c in res.matches) {
                        // First occurrence wins; email label preferred if it appears.
                        val existing = seen[c.userId]
                        if (existing == null) {
                            seen[c.userId] = c.toDomain()
                        } else if (existing.matchedBy != "email" && c.matchedBy == "email") {
                            seen[c.userId] = c.toDomain()
                        }
                    }
                }
                seen.values.sortedBy { it.displayName.lowercase() }
            }
        }
    }

    override suspend fun follow(userId: String): ApiResult<Unit> = withContext(io) {
        call { followApi.follow(FollowTargetDto(userId)); Unit }
    }

    override suspend fun unfollow(userId: String): ApiResult<Unit> = withContext(io) {
        call { followApi.unfollow(FollowTargetDto(userId)); Unit }
    }

    override suspend fun followStatus(userId: String): ApiResult<FollowRelationship> = withContext(io) {
        call {
            val s = followApi.followStatus(userId)
            FollowRelationship(
                isFollowing = s.isFollowing,
                isFollowedBy = s.isFollowedBy,
                isMutual = s.isMutual,
                isBlockedByMe = s.isBlockedByMe,
                isBlockingMe = s.isBlockingMe,
            )
        }
    }

    override suspend fun followers(userId: String, cursor: String?): ApiResult<List<FollowGraphUser>> =
        withContext(io) {
            degradeToEmpty { bodyFrom(followApi.followers(userId, cursor)).items.map { it.toDomain() } }
        }

    override suspend fun following(userId: String, cursor: String?): ApiResult<List<FollowGraphUser>> =
        withContext(io) {
            degradeToEmpty { bodyFrom(followApi.following(userId, cursor)).items.map { it.toDomain() } }
        }

    override suspend fun followCounts(userId: String): ApiResult<FollowCounts> = withContext(io) {
        val result = call {
            val c = bodyFrom(followApi.counts(userId))
            FollowCounts(followerCount = c.followerCount, followingCount = c.followingCount)
        }
        // Degrade-on-404: an absent user surfaces as zeroed counts, not an error.
        if (result is ApiResult.Failure &&
            SocialGraphMath.isBenignSocialReadFailure(result.error.status)
        ) {
            ApiResult.Success(FollowCounts(followerCount = 0, followingCount = 0))
        } else {
            result
        }
    }

    override suspend fun mutualFollowers(userId: String, cursor: String?): ApiResult<List<FollowGraphUser>> =
        withContext(io) {
            degradeToEmpty { bodyFrom(followApi.mutual(userId, cursor)).items.map { it.toDomain() } }
        }

    override suspend fun snoozedFollowing(): ApiResult<List<SnoozedFollowing>> = withContext(io) {
        degradeToEmptySnoozed { bodyFrom(followApi.snoozedFollowing()).snoozed.map { it.toDomain() } }
    }

    override suspend fun snoozeFollowing(userId: String, days: Int): ApiResult<Long> = withContext(io) {
        val clamped = SocialGraphMath.clampSnoozeDays(days)
        call { bodyFrom(followApi.snoozeFollowing(userId, SnoozeFollowingDto(days = clamped))).snoozedUntil }
    }

    override suspend fun unsnoozeFollowing(userId: String): ApiResult<Unit> = withContext(io) {
        val result = call { unitFrom(followApi.unsnoozeFollowing(userId)) }
        // Un-snoozing is idempotent: a 404 ("not snoozed" / "not following") is a success.
        if (result is ApiResult.Failure &&
            SocialGraphMath.isBenignUnsnoozeFailure(result.error.status)
        ) {
            ApiResult.Success(Unit)
        } else {
            result
        }
    }

    // ── helpers (mirror BlockingRepositoryImpl's uniform error mapping) ──────

    private fun unitFrom(response: Response<*>) {
        if (!response.isSuccessful) throw HttpException(response)
    }

    /** Unwrap a 2xx body or throw HttpException so [call] maps it to Failure. */
    private fun <T> bodyFrom(response: Response<T>): T {
        if (!response.isSuccessful) throw HttpException(response)
        return requireNotNull(response.body()) { "Empty body on a 2xx response" }
    }

    /**
     * Run an additive social read; on a benign 404/410 (see [SocialGraphMath.isBenignSocialReadFailure])
     * degrade to an empty list as Success rather than surfacing an error.
     */
    private suspend fun degradeToEmpty(
        block: suspend () -> List<FollowGraphUser>,
    ): ApiResult<List<FollowGraphUser>> = when (val r = call(block)) {
        is ApiResult.Success -> r
        is ApiResult.Failure ->
            if (SocialGraphMath.isBenignSocialReadFailure(r.error.status)) ApiResult.Success(emptyList())
            else r
        is ApiResult.NetworkError -> r
    }

    private suspend fun degradeToEmptySnoozed(
        block: suspend () -> List<SnoozedFollowing>,
    ): ApiResult<List<SnoozedFollowing>> = when (val r = call(block)) {
        is ApiResult.Success -> r
        is ApiResult.Failure ->
            if (SocialGraphMath.isBenignSocialReadFailure(r.error.status)) ApiResult.Success(emptyList())
            else r
        is ApiResult.NetworkError -> r
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    } catch (e: IllegalArgumentException) {
        ApiResult.Failure(ApiError(status = ApiError.STATUS_PARSE, message = "Malformed response", raw = e.message))
    }
}

private const val MATCH_HASH_BATCH = 1000

private fun ContactMatchCardDto.toDomain() = ContactMatch(
    userId = userId,
    displayName = displayName,
    photoUrl = profilePhotoUrl,
    matchedBy = matchedBy,
)

private fun ContactEntryDto.toDomain() = SavedContact(
    userId = contactId,
    displayName = displayName,
    photoUrl = profilePhotoUrl,
    isFavorite = isFavorite,
    isBlocked = isBlocked,
)

private fun SuggestionCardDto.toDomain() = ContactSuggestion(
    userId = userId,
    displayName = displayName,
    photoUrl = profilePhotoUrl,
    hint = hint,
    mutualCount = mutualCount,
    source = source,
)

private fun FollowUserDto.toDomain() = FollowGraphUser(
    userId = userId,
    displayName = displayName?.takeIf { it.isNotBlank() } ?: userId,
    photoUrl = profilePhotoUrl,
    isFollowing = isFollowing,
    isMutual = isMutual,
    snoozedUntilSeconds = snoozedUntil,
    isSnoozed = isSnoozed,
)

private fun SnoozedFollowingDto.toDomain() = SnoozedFollowing(
    userId = followingSub,
    displayName = followingName?.takeIf { it.isNotBlank() } ?: followingSub,
    photoUrl = followingAvatarUrl,
    snoozedUntilSeconds = snoozedUntil,
    remainingHours = snoozeRemainingHours,
)
