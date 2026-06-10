package com.testlogon.android.feature.checkout.address

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.address.Address
import com.testlogon.android.data.address.AddressDraft
import com.testlogon.android.data.address.AddressRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-214 / AND-217 — [AddressShippingViewModel]: primary pre-selection, selection, add+auto-select,
 * 422 field-error projection, and apply -> set-primary -> Applied event.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AddressShippingViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun address(id: String, primary: Boolean = false) = Address(
        addressId = id, name = "N-$id", line1 = "L-$id", line2 = null, city = "City",
        state = "ST", postalCode = "00000", country = "US", label = null, notes = null,
        isPrimaryMailing = primary, createdAtEpochSeconds = 1L, updatedAtEpochSeconds = 1L,
    )

    private fun vm(repo: AddressRepository) = AddressShippingViewModel(repo)

    @Test
    fun init_preselectsPrimaryAddress() = runTest {
        val repo = FakeAddressRepository().apply {
            listResult = ApiResult.Success(listOf(address("a1"), address("a2", primary = true)))
        }
        val model = vm(repo)
        advanceUntilIdle()
        val state = model.state.value
        assertTrue(state is AddressShippingUiState.Ready)
        assertEquals("a2", (state as AddressShippingUiState.Ready).selectedAddressId)
    }

    @Test
    fun selectAddress_updatesSelection() = runTest {
        val repo = FakeAddressRepository().apply {
            listResult = ApiResult.Success(listOf(address("a1"), address("a2")))
        }
        val model = vm(repo)
        advanceUntilIdle()
        model.onSelectAddress("a1")
        assertEquals("a1", (model.state.value as AddressShippingUiState.Ready).selectedAddressId)
    }

    @Test
    fun addAddress_appendsAndAutoSelects() = runTest {
        val repo = FakeAddressRepository().apply {
            listResult = ApiResult.Success(listOf(address("a1")))
            createResult = ApiResult.Success(address("a_new"))
        }
        val model = vm(repo)
        advanceUntilIdle()
        model.onAddAddress(AddressDraft(line1 = "New St"))
        advanceUntilIdle()
        val state = model.state.value as AddressShippingUiState.Ready
        assertEquals(2, state.addresses.size)
        assertEquals("a_new", state.selectedAddressId)
    }

    @Test
    fun addAddress_invalidDraft_emitsLine1Validation_noCreateCall() = runTest {
        val repo = FakeAddressRepository().apply {
            listResult = ApiResult.Success(emptyList())
        }
        val model = vm(repo)
        advanceUntilIdle()
        val events = mutableListOf<AddressShippingEvent>()
        val job = launch { model.events.collect { events += it } }

        model.onAddAddress(AddressDraft(line1 = "")) // invalid
        advanceUntilIdle()

        assertEquals(0, repo.createCalls)
        val validation = events.filterIsInstance<AddressShippingEvent.ValidationFailed>().single()
        assertTrue(validation.fieldErrors.containsKey(AddressShippingViewModel.FIELD_LINE1))
        job.cancel()
    }

    @Test
    fun addAddress_422_projectsFieldErrors() = runTest {
        val raw = """{"detail":[{"loc":["body","line1"],"msg":"field required"}]}"""
        val repo = FakeAddressRepository().apply {
            listResult = ApiResult.Success(emptyList())
            createResult = ApiResult.Failure(ApiError(status = 422, message = "field required", raw = raw))
        }
        val model = vm(repo)
        advanceUntilIdle()
        val events = mutableListOf<AddressShippingEvent>()
        val job = launch { model.events.collect { events += it } }

        model.onAddAddress(AddressDraft(line1 = "x"))
        advanceUntilIdle()

        val validation = events.filterIsInstance<AddressShippingEvent.ValidationFailed>().single()
        assertEquals("field required", validation.fieldErrors["line1"])
        job.cancel()
    }

    @Test
    fun apply_setsPrimary_andEmitsApplied() = runTest {
        val repo = FakeAddressRepository().apply {
            listResult = ApiResult.Success(listOf(address("a1"), address("a2")))
            setPrimaryResult = ApiResult.Success(address("a1", primary = true))
        }
        val model = vm(repo)
        advanceUntilIdle()
        model.onSelectAddress("a1")
        val events = mutableListOf<AddressShippingEvent>()
        val job = launch { model.events.collect { events += it } }

        model.onApply()
        advanceUntilIdle()

        assertEquals("a1", repo.lastSetPrimaryId)
        val applied = events.filterIsInstance<AddressShippingEvent.Applied>().single()
        assertEquals("a1", applied.addressId)
        job.cancel()
    }

    @Test
    fun apply_failure_clearsApplyingAndEmitsActionFailed() = runTest {
        val repo = FakeAddressRepository().apply {
            listResult = ApiResult.Success(listOf(address("a1")))
            setPrimaryResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        advanceUntilIdle()
        model.onSelectAddress("a1")
        val events = mutableListOf<AddressShippingEvent>()
        val job = launch { model.events.collect { events += it } }

        model.onApply()
        advanceUntilIdle()

        val state = model.state.value as AddressShippingUiState.Ready
        assertEquals(false, state.applying)
        assertTrue(events.any { it is AddressShippingEvent.ActionFailed })
        job.cancel()
    }

    @Test
    fun load_failure_isRetryableError() = runTest {
        val repo = FakeAddressRepository().apply {
            listResult = ApiResult.Failure(ApiError(status = 500, message = "down"))
        }
        val model = vm(repo)
        advanceUntilIdle()
        assertTrue(model.state.value is AddressShippingUiState.Error)
    }
}

private class FakeAddressRepository : AddressRepository {
    var listResult: ApiResult<List<Address>> = ApiResult.Success(emptyList())
    var createResult: ApiResult<Address> =
        ApiResult.Failure(ApiError(status = 500, message = "unset"))
    var setPrimaryResult: ApiResult<Address> =
        ApiResult.Failure(ApiError(status = 500, message = "unset"))

    var createCalls = 0
    var lastSetPrimaryId: String? = null

    override suspend fun listAddresses(): ApiResult<List<Address>> = listResult
    override suspend fun createAddress(draft: AddressDraft): ApiResult<Address> {
        createCalls++
        return createResult
    }

    override suspend fun setPrimary(addressId: String): ApiResult<Address> {
        lastSetPrimaryId = addressId
        return setPrimaryResult
    }
}
