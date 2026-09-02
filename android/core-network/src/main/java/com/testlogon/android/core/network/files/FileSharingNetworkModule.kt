package com.testlogon.android.core.network.files

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * FM-SHARE - Hilt wiring for the user-to-user sharing / archive / storage-usage transport
 * ([FileSharingApi]). Provides the interface from the shared singleton [Retrofit] (reusing the
 * production OkHttp / Moshi config; no new Retrofit, OkHttp, Moshi or dependency). The DTOs decode via
 * the reflective KotlinJsonAdapterFactory already registered in NetworkModule.provideMoshi. Mirrors
 * [FilesNetworkModule].
 */
@Module
@InstallIn(SingletonComponent::class)
object FileSharingNetworkModule {

    @Provides
    @Singleton
    fun provideFileSharingApi(retrofit: Retrofit): FileSharingApi =
        retrofit.create(FileSharingApi::class.java)
}
