package com.testlogon.android.data.messaging.typing

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-146 — best-effort typing send/poll wrapper. Send is fire-and-forget: failures (timeout/5xx/
 * offline) are swallowed (FR-8) and never surface to the user. A stale start auto-expires receiver
 * side, so there is no retry.
 */
interface TypingRepository {
    suspend fun start(conversationId: String)
    suspend fun stop(conversationId: String)

    /** Fallback poll of the current typers for a conversation; returns empty on any failure. */
    suspend fun poll(conversationId: String): List<TypingUserDto>
}

@Singleton
class DefaultTypingRepository @Inject constructor(
    private val api: TypingApi,
) : TypingRepository {

    override suspend fun start(conversationId: String) {
        runCatching { api.setTyping(conversationId, TypingReq(isTyping = true)) }
    }

    override suspend fun stop(conversationId: String) {
        runCatching { api.setTyping(conversationId, TypingReq(isTyping = false)) }
    }

    override suspend fun poll(conversationId: String): List<TypingUserDto> =
        runCatching { api.getTyping(conversationId) }.getOrDefault(emptyList())
}

/** AND-146 — typing API + repository wiring on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object TypingApiModule {
    @Provides
    @Singleton
    fun provideTypingApi(retrofit: Retrofit): TypingApi = retrofit.create(TypingApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class TypingDataModule {
    @Binds
    @Singleton
    abstract fun bindTypingRepository(impl: DefaultTypingRepository): TypingRepository
}
