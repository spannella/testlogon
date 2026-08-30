package com.testlogon.android.data.messaging

import com.testlogon.android.data.messaging.group.GroupApi
import com.testlogon.android.data.messaging.group.GroupRepository
import com.testlogon.android.data.messaging.group.GroupRepositoryImpl
import com.testlogon.android.data.messaging.helpdesk.HelpdeskApi
import com.testlogon.android.data.messaging.mute.ConversationMuteStore
import com.testlogon.android.data.messaging.mute.DataStoreConversationMuteStore
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepository
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepositoryImpl
import com.testlogon.android.data.messaging.mass.MassMessageApi
import com.testlogon.android.data.messaging.mass.MassMessageConfigRepository
import com.testlogon.android.data.messaging.mass.MassMessageConfigRepositoryImpl
import com.testlogon.android.data.messaging.mass.MassMessageRepository
import com.testlogon.android.data.messaging.mass.MassMessageRepositoryImpl
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

    /** AND-160 — provides the mass-message [MassMessageApi] on the shared Retrofit. */
    @Provides
    @Singleton
    fun provideMassMessageApi(retrofit: Retrofit): MassMessageApi =
        retrofit.create(MassMessageApi::class.java)

    /** AND-161/AND-162 — provides the helpdesk [HelpdeskApi] on the shared Retrofit. */
    @Provides
    @Singleton
    fun provideHelpdeskApi(retrofit: Retrofit): HelpdeskApi =
        retrofit.create(HelpdeskApi::class.java)
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

    /** AND-160 — binds the mass-message repository (list / create / cancel). */
    @Binds
    @Singleton
    abstract fun bindMassMessageRepository(impl: MassMessageRepositoryImpl): MassMessageRepository

    /** AND-160 — binds the mass-send capability gate repository. */
    @Binds
    @Singleton
    abstract fun bindMassMessageConfigRepository(
        impl: MassMessageConfigRepositoryImpl,
    ): MassMessageConfigRepository

    /** AND-161/AND-162 — binds the helpdesk repository (queue / claim). */
    @Binds
    @Singleton
    abstract fun bindHelpdeskRepository(impl: HelpdeskRepositoryImpl): HelpdeskRepository

    /** AND-130 — binds the runtime image processor (faked in unit tests). */
    @Binds
    @Singleton
    abstract fun bindMessageImageProcessor(impl: DefaultMessageImageProcessor): MessageImageProcessor

    /** AND-132 — binds the attachment downloader (grant -> consume? -> GET bytes -> cache). */
    @Binds
    @Singleton
    abstract fun bindAttachmentDownloader(impl: DefaultAttachmentDownloader): AttachmentDownloader

    /**
     * TIP-103 (AND-031/AND-139) — billing seam. Bound to [RealBillingAuthorizer], which in a RELEASE
     * build resolves a real payment_method_id (tip-default -> general default -> first saved method)
     * so tips POST for real; in DEBUG it keeps the dev/demo blank-PM mock-charge path.
     */
    @Binds
    @Singleton
    abstract fun bindBillingAuthorizer(impl: RealBillingAuthorizer): BillingAuthorizer

    /** FE-140 — binds the per-conversation mute mirror (DataStore-backed muted_until map). */
    @Binds
    @Singleton
    abstract fun bindConversationMuteStore(
        impl: DataStoreConversationMuteStore,
    ): ConversationMuteStore
}
