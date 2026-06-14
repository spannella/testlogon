package com.testlogon.android.data.address

/**
 * AND-214 — framework-free domain models for saved addresses. DTO -> domain mapping lives here so the
 * repository never leaks raw DTOs. Timestamps stay Long epoch seconds (JVM-safe; no java.time on the
 * unit-tested path).
 */

/** A saved shipping/mailing address. Mirrors AddressOut; `isPrimaryMailing` is the only "default" flag. */
data class Address(
    val addressId: String,
    val name: String?,
    val line1: String?,
    val line2: String?,
    val city: String?,
    val state: String?,
    val postalCode: String?,
    val country: String?,
    val label: String?,
    val notes: String?,
    val isPrimaryMailing: Boolean,
    val createdAtEpochSeconds: Long?,
    val updatedAtEpochSeconds: Long?,
)

/**
 * UI-layer input model for the address form. Converted to [AddressInDto] on submit. Only `line1` is
 * required client-side (web parity); the server imposes no required fields.
 */
data class AddressDraft(
    val name: String = "",
    val line1: String = "",
    val line2: String = "",
    val city: String = "",
    val state: String = "",
    val postalCode: String = "",
    val country: String = "",
    val label: String = "",
    val notes: String = "",
) {
    /** Web parity (Addresses.tsx zod): submit allowed iff `line1` is non-blank. */
    val isValid: Boolean get() = line1.isNotBlank()
}

// ---- Mappers ----

internal fun AddressOutDto.toDomain(): Address = Address(
    addressId = addressId,
    name = name?.takeIf { it.isNotBlank() },
    line1 = line1?.takeIf { it.isNotBlank() },
    line2 = line2?.takeIf { it.isNotBlank() },
    city = city?.takeIf { it.isNotBlank() },
    state = state?.takeIf { it.isNotBlank() },
    postalCode = postalCode?.takeIf { it.isNotBlank() },
    country = country?.takeIf { it.isNotBlank() },
    label = label?.takeIf { it.isNotBlank() },
    notes = notes?.takeIf { it.isNotBlank() },
    isPrimaryMailing = isPrimaryMailing,
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
)

/** Builds the create-request body, sending only the non-blank fields (blank -> null/omitted). */
internal fun AddressDraft.toRequest(): AddressInDto = AddressInDto(
    name = name.trim().ifBlank { null },
    line1 = line1.trim().ifBlank { null },
    line2 = line2.trim().ifBlank { null },
    city = city.trim().ifBlank { null },
    state = state.trim().ifBlank { null },
    postalCode = postalCode.trim().ifBlank { null },
    country = country.trim().ifBlank { null },
    label = label.trim().ifBlank { null },
    notes = notes.trim().ifBlank { null },
)
