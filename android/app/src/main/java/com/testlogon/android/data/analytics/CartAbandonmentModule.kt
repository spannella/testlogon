package com.testlogon.android.data.analytics

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-216 — binds the cart-abandonment collaborators. [EmitCartAbandonmentUseCase] and
 * [CartAbandonmentTracker] are @Inject-constructed (no binding needed). No network surface is added.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class CartAbandonmentModule {

    @Binds
    @Singleton
    abstract fun bindCartEventSink(impl: DefaultCartEventSink): CartEventSink

    @Binds
    @Singleton
    abstract fun bindAbandonmentMarkerStore(impl: DataStoreAbandonmentMarkerStore): AbandonmentMarkerStore

    @Binds
    @Singleton
    abstract fun bindAbandonmentClock(impl: SystemAbandonmentClock): AbandonmentClock
}
