package com.testlogon.android.core.network.customemojis

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * Hilt wiring for the custom-emoji transport. Provides [CustomEmojiApi] from the shared singleton [Retrofit]
 * (no new Retrofit/OkHttp/Moshi). Mirrors ApiKeysNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object CustomEmojiNetworkModule {

    @Provides
    @Singleton
    fun provideCustomEmojiApi(retrofit: Retrofit): CustomEmojiApi =
        retrofit.create(CustomEmojiApi::class.java)
}
