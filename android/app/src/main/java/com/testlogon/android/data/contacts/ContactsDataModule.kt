package com.testlogon.android.data.contacts

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides the contacts + follow Retrofit services on the shared authenticated Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object ContactsApiModule {

    @Provides
    @Singleton
    fun provideContactsApi(retrofit: Retrofit): ContactsApi =
        retrofit.create(ContactsApi::class.java)

    @Provides
    @Singleton
    fun provideFollowApi(retrofit: Retrofit): FollowApi =
        retrofit.create(FollowApi::class.java)

    /**
     * Feature 2 — the on-device contact-match hasher, pinned to the compile-time
     * CONTACT_MATCH_SALT (must stay byte-identical to the backend APP_CONTACT_MATCH_SALT).
     */
    @Provides
    @Singleton
    fun provideContactMatchHasher(): ContactMatchHasher =
        ContactMatchHasher(com.testlogon.android.BuildConfig.CONTACT_MATCH_SALT)
}

/** Binds the contacts repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class ContactsDataModule {

    @Binds
    @Singleton
    abstract fun bindContactsRepository(impl: ContactsRepositoryImpl): ContactsRepository

    @Binds
    @Singleton
    abstract fun bindDeviceContactsReader(impl: DeviceContactsReaderImpl): DeviceContactsReader
}
