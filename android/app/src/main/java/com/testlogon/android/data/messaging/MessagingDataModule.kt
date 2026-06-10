package com.testlogon.android.data.messaging

import com.testlogon.android.data.messaging.group.GroupApi
import com.testlogon.android.data.messaging.group.GroupRepository
import com.testlogon.android.data.messaging.group.GroupRepositoryImpl
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-120 — provides the [MessagingApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object MessagingApiModule {

    @Provides
    @Singleton
    fun provideMessagingApi(retrofit: Retrofit): MessagingApi =
        retrofit.create(MessagingApi::class.java)

    /** AND-157..159 — provides the group [GroupApi] on the shared Retrofit. */
    @Provides
    @Singleton
    fun provideGroupApi(retrofit: Retrofit): GroupApi =
        retrofit.create(GroupApi::class.java)
}

/** AND-120..124 — binds the messaging repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MessagingDataModule {

    @Binds
    @Singleton
    abstract fun bindMessagingRepository(impl: MessagingRepositoryImpl): MessagingRepository

    /** AND-157..159 — binds the group repository (create / participants / settings). */
    @Binds
    @Singleton
    abstract fun bindGroupRepository(impl: GroupRepositoryImpl): GroupRepository

    /** AND-130 — binds the runtime image processor (faked in unit tests). */
    @Binds
    @Singleton
    abstract fun bindMessageImageProcessor(impl: DefaultMessageImageProcessor): MessageImageProcessor

    /** AND-132 — binds the attachment downloader (grant -> consume? -> GET bytes -> cache). */
    @Binds
    @Singleton
    abstract fun bindAttachmentDownloader(impl: DefaultAttachmentDownloader): AttachmentDownloader

    /**
     * AND-139 — billing seam. Defaults to [StubBillingAuthorizer] (NotConfigured, no faked charge)
     * until AND-031 supplies a real vendor-backed implementation; swap this @Binds then.
     */
    @Binds
    @Singleton
    abstract fun bindBillingAuthorizer(impl: StubBillingAuthorizer): BillingAuthorizer
}
