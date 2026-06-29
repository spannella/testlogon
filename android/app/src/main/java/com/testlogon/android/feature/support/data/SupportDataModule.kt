package com.testlogon.android.feature.support.data

import com.testlogon.android.core.network.support.SupportApi
import com.testlogon.android.core.network.support.SupportLiveChatApi
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** B-SUP (batch 7) — provides the SupportApi + binds the SupportRepository on the shared authed Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object SupportApiModule {
    @Provides
    @Singleton
    fun provideSupportApi(retrofit: Retrofit): SupportApi = retrofit.create(SupportApi::class.java)

    @Provides
    @Singleton
    fun provideSupportLiveChatApi(retrofit: Retrofit): SupportLiveChatApi =
        retrofit.create(SupportLiveChatApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class SupportDataModule {
    @Binds
    @Singleton
    abstract fun bindSupportRepository(impl: SupportRepositoryImpl): SupportRepository

    @Binds
    @Singleton
    abstract fun bindSupportLiveChatRepository(impl: SupportLiveChatRepositoryImpl): SupportLiveChatRepository

    /** B10 B-HELPMEDIA #5 - the ticket-media uploader (image / video / file / file-manager pick). */
    @Binds
    @Singleton
    abstract fun bindSupportMediaUploader(impl: SupportMediaUploaderImpl): SupportMediaUploader
}
