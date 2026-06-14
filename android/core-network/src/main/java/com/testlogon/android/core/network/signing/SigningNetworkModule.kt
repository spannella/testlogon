package com.testlogon.android.core.network.signing

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-339 - Hilt wiring for the signing transport layer.
 *
 * Provides [SigningApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced).
 * The four signing enum adapters (PacketStatus / SignatureFieldType / PacketRole / SignatureInputMode)
 * are registered on the shared Moshi in NetworkModule.provideMoshi so these DTOs decode with the
 * UNKNOWN fallback. Mirrors the AND-331 FilesNetworkModule / AND-319 KycNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object SigningNetworkModule {

    @Provides
    @Singleton
    fun provideSigningApi(retrofit: Retrofit): SigningApi =
        retrofit.create(SigningApi::class.java)
}
