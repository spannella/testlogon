package com.testlogon.android.core.network.files

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * FM-MOUNTS - Hilt wiring for the file-manager mount CRUD transport layer.
 *
 * Provides [FileMountsApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced). The
 * mount DTOs decode via the reflective KotlinJsonAdapterFactory already registered in
 * NetworkModule.provideMoshi. Mirrors the AND-331 FilesNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object FileMountsNetworkModule {

    @Provides
    @Singleton
    fun provideFileMountsApi(retrofit: Retrofit): FileMountsApi = retrofit.create(FileMountsApi::class.java)
}
