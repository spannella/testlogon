package com.testlogon.android.feature.settings.emojis

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.customemojis.CustomEmojiApi
import com.testlogon.android.core.network.customemojis.CustomEmojiDto
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for personal custom emojis over [CustomEmojiApi]. Mirrors the web CustomEmojisPage (personal scope
 * only): list the caller's personal emojis, upload a new one (multipart), and delete one. The list endpoint
 * returns personal + global; the screen shows only personal (owner_scope startsWith "USER#"), matching the web.
 */
interface CustomEmojiRepository {

    /** GET the caller's PERSONAL emojis + the personal-quota count used. */
    suspend fun list(): ApiResult<EmojiListResult>

    /** POST a new personal emoji (multipart). */
    suspend fun upload(upload: EmojiUpload): ApiResult<CustomEmoji>

    /** DELETE one of the caller's personal emojis. */
    suspend fun delete(emojiId: String): ApiResult<Unit>
}

/** The personal-scope slice of the list response (the screen renders only these). */
data class EmojiListResult(
    val personal: List<CustomEmoji>,
    val personalCount: Int,
)

@Singleton
class DefaultCustomEmojiRepository @Inject constructor(
    private val api: CustomEmojiApi,
    private val errorParser: ApiErrorParser,
) : CustomEmojiRepository {

    override suspend fun list(): ApiResult<EmojiListResult> =
        withContext(Dispatchers.IO) {
            call {
                val dto = api.list()
                val personal = dto.emojis
                    .filter { (it.ownerScope ?: "").startsWith("USER#") }
                    .map { it.toDomain() }
                EmojiListResult(
                    personal = personal,
                    personalCount = dto.personalCount.takeIf { it > 0 } ?: personal.size,
                )
            }
        }

    override suspend fun upload(upload: EmojiUpload): ApiResult<CustomEmoji> =
        withContext(Dispatchers.IO) {
            call {
                val textType = "text/plain".toMediaTypeOrNull()
                val fileBody = upload.bytes.toRequestBody(upload.contentType.toMediaTypeOrNull())
                val filePart = MultipartBody.Part.createFormData("file", upload.fileName, fileBody)
                api.upload(
                    shortcode = upload.shortcode.toRequestBody(textType),
                    name = upload.name.toRequestBody(textType),
                    altText = upload.altText.toRequestBody(textType),
                    category = upload.category.toRequestBody(textType),
                    file = filePart,
                ).toDomain()
            }
        }

    override suspend fun delete(emojiId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.delete(emojiId); Unit } }

    private fun CustomEmojiDto.toDomain(): CustomEmoji = CustomEmoji(
        emojiId = emojiId,
        shortcode = shortcode,
        name = name.orEmpty().ifBlank { shortcode },
        imageUrl = imageUrl?.takeIf { it.isNotBlank() },
        altText = altText.orEmpty(),
        category = category.orEmpty().ifBlank { "Uncategorized" },
        ownerScope = ownerScope.orEmpty(),
    )

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
