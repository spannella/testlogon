package com.testlogon.android.feature.broadcast.host

import javax.inject.Qualifier

/**
 * AND-317 — qualifies the CPU/default [kotlinx.coroutines.CoroutineDispatcher] the host VM runs its effect
 * pipeline + health ticker on (FR-8). No existing dispatcher qualifier was found in this repo, so this
 * minimal one is added (a bare CoroutineDispatcher cannot be Hilt-injected unqualified). Tests inject a
 * StandardTestDispatcher for this binding.
 */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class DefaultDispatcher
