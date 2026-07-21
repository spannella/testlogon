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

/** Bidirectional follow relationship snapshot for the contact card. */
data class FollowRelationship(
    val isFollowing: Boolean,
    val isFollowedBy: Boolean,
    val isMutual: Boolean,
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

    // Follow graph (existing social routes, newly wired on Android).
    suspend fun follow(userId: String): ApiResult<Unit>
    suspend fun unfollow(userId: String): ApiResult<Unit>
    suspend fun followStatus(userId: String): ApiResult<FollowRelationship>
}

@Singleton
class ContactsRepositoryImpl @Inject constructor(
    private val contactsApi: ContactsApi,
    private val followApi: FollowApi,
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
            )
        }
    }

    // ── helpers (mirror BlockingRepositoryImpl's uniform error mapping) ──────

    private fun unitFrom(response: Response<*>) {
        if (!response.isSuccessful) throw HttpException(response)
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
