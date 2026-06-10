package com.testlogon.android.data.payments

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-231 — shared singleton that broadcasts parsed [PaymentReturn]s to the provider sub-flows
 * (PayPal AND-228, CCBill AND-229). The originating screen collects this filtered on its provider id:
 *
 *     dispatcher.returns.filter { it.provider == "paypal" }.collect(viewModel::onReturn)
 *
 * The handler ([PaymentReturnHandler]) emits here for every recognized billing return; routing of the
 * generic terminal screens (Stale/Cancelled/Failed) is done by the connector independently.
 */
@Singleton
class PaymentReturnDispatcher @Inject constructor() {

    // replay=1 so a return that arrives just before the screen subscribes (cold-start race) is still
    // delivered exactly once to a late collector. extraBufferCapacity guards against suspension drops.
    private val _returns = MutableSharedFlow<PaymentReturn>(replay = 1, extraBufferCapacity = 8)
    val returns: SharedFlow<PaymentReturn> = _returns.asSharedFlow()

    fun emit(paymentReturn: PaymentReturn) {
        _returns.tryEmit(paymentReturn)
    }
}
