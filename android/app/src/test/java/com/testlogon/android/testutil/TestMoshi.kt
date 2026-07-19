package com.testlogon.android.testutil

import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.di.NetworkModule

/**
 * P2 — production-parity [Moshi] for contract/mapper tests. A bare Moshi.Builder().build() lacks the
 * app's custom adapters + the reflective KotlinJsonAdapterFactory that NetworkModule wires, so DTOs with
 * nested non-codegen types (e.g. MessageDto -> PollSnapshotDto) fail with 'Unable to create converter'.
 * Delegating to the real provider keeps the tests honest against the shipped JSON contract.
 */
fun testMoshi(): Moshi = NetworkModule.provideMoshi()
