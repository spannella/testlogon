package com.testlogon.android.data.messaging.presence

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-145 — provides the [PresenceApi] on the shared Retrofit (no new OkHttp/Retrofit). */
@Module
@InstallIn(SingletonComponent::class)
object PresenceApiModule {

    @Provides
    @Singleton
    fun providePresenceApi(retrofit: Retrofit): PresenceApi =
        retrofit.create(PresenceApi::class.java)
}
