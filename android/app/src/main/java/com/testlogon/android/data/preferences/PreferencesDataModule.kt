package com.testlogon.android.data.preferences

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-078/079/080/082 — provides the preferences/account Retrofit APIs on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object PreferencesApiModule {

    @Provides
    @Singleton
    fun providePreferencesApi(retrofit: Retrofit): PreferencesApi =
        retrofit.create(PreferencesApi::class.java)

    @Provides
    @Singleton
    fun provideMediaPreferencesApi(retrofit: Retrofit): MediaPreferencesApi =
        retrofit.create(MediaPreferencesApi::class.java)

    @Provides
    @Singleton
    fun provideNotificationPreferencesApi(retrofit: Retrofit): NotificationPreferencesApi =
        retrofit.create(NotificationPreferencesApi::class.java)

    @Provides
    @Singleton
    fun provideAccountStatusApi(retrofit: Retrofit): AccountStatusApi =
        retrofit.create(AccountStatusApi::class.java)
}

/** AND-078/079/080/082 — binds the preferences/account repositories to their implementations. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PreferencesDataModule {

    @Binds
    @Singleton
    abstract fun bindPreferencesRepository(impl: PreferencesRepositoryImpl): PreferencesRepository

    @Binds
    @Singleton
    abstract fun bindMediaPreferencesRepository(
        impl: MediaPreferencesRepositoryImpl,
    ): MediaPreferencesRepository

    @Binds
    @Singleton
    abstract fun bindMediaPreferencesMirror(impl: MediaPreferencesStore): MediaPreferencesMirror

    @Binds
    @Singleton
    abstract fun bindNotificationPreferencesRepository(
        impl: NotificationPreferencesRepositoryImpl,
    ): NotificationPreferencesRepository

    @Binds
    @Singleton
    abstract fun bindAccountStatusRepository(
        impl: AccountStatusRepositoryImpl,
    ): AccountStatusRepository
}
