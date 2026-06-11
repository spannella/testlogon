package com.testlogon.android.data.gcal

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-273 — provides [GoogleCalendarApi] on the shared Retrofit (no new OkHttp/Retrofit) and binds the
 * repository + DataStore store.
 */
@Module
@InstallIn(SingletonComponent::class)
object GoogleCalendarApiModule {

    @Provides
    @Singleton
    fun provideGoogleCalendarApi(retrofit: Retrofit): GoogleCalendarApi =
        retrofit.create(GoogleCalendarApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class GoogleCalendarDataModule {

    @Binds
    @Singleton
    abstract fun bindGoogleCalendarRepository(
        impl: GoogleCalendarRepositoryImpl,
    ): GoogleCalendarRepository

    @Binds
    @Singleton
    abstract fun bindGoogleCalendarStore(impl: DataStoreGoogleCalendarStore): GoogleCalendarStore
}
