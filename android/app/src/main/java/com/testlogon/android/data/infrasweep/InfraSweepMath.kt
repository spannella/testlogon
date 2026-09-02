package com.testlogon.android.data.infrasweep

import com.testlogon.android.data.infrak8s.K8sPodDto
import com.testlogon.android.data.sshbastion.BastionHopDto
import com.testlogon.android.data.sshbastion.BastionHopReq
import com.testlogon.android.data.sshbastion.BastionPathDto
import com.testlogon.android.data.sshbastion.UpdateBastionPathReq

/**
 * Dev-platform SWEEP: pure, Android-free logic shared by the K8s pod-detail read
 * (GET /ui/remote/k8s/pods/{id}) and the SSH-bastion edit-path write
 * (PATCH /ui/compute/bastion/paths/{id}). Kept in a *Math file with a JVM test so the
 * branching (change-detection, degrade-on-404 merge, edit-form -> PATCH mapping) is
 * exercised without Compose/Moshi/Retrofit.
 */
object InfraSweepMath {

    // ---- K8s pod-detail: degrade-on-404 merge ----------------------------------

    /**
     * Merge a freshly-fetched single-pod detail over the list-row summary.
     *
     * The detail read can 404 (pod GC'd) or fail transiently; on any non-success the
     * caller passes [detail] = null and we degrade to the [fallback] list row so the
     * user still sees *something*. When [detail] is present we prefer it, but never let
     * a blank/zero field from the detail blank-out a value the list row already had
     * (defensive against partial serialisations).
     */
    fun mergePodDetail(fallback: K8sPodDto, detail: K8sPodDto?): K8sPodDto {
        if (detail == null) return fallback
        return detail.copy(
            podId = detail.podId.ifBlank { fallback.podId },
            k8sPodName = detail.k8sPodName.ifBlank { fallback.k8sPodName },
            namespace = detail.namespace.ifBlank { fallback.namespace },
            label = detail.label.ifBlank { fallback.label },
            image = detail.image.ifBlank { fallback.image },
            imageDisplayName = detail.imageDisplayName.ifBlank { fallback.imageDisplayName },
            preset = detail.preset.ifBlank { fallback.preset },
            status = detail.status.ifBlank { fallback.status },
            podIp = detail.podIp.ifBlank { fallback.podIp },
            serviceHostname = detail.serviceHostname.ifBlank { fallback.serviceHostname },
            cpuMillicores = if (detail.cpuMillicores != 0) detail.cpuMillicores else fallback.cpuMillicores,
            memoryMb = if (detail.memoryMb != 0) detail.memoryMb else fallback.memoryMb,
            createdAt = if (detail.createdAt != 0L) detail.createdAt else fallback.createdAt,
            expiresAt = if (detail.expiresAt != 0L) detail.expiresAt else fallback.expiresAt,
        )
    }

    // ---- SSH-bastion edit form -> PATCH body -----------------------------------

    /** True once the edit form has enough to PATCH: a non-blank target host + user. */
    fun isEditValid(targetHost: String, targetUser: String, label: String): Boolean =
        targetHost.isNotBlank() && targetUser.isNotBlank() && label.isNotBlank()

    /**
     * Extract the single jump hop (the bastion) from a path for pre-filling the edit form.
     * Returns the first hop flagged is_bastion, else the first non-last hop, else null.
     */
    fun primaryJumpHop(path: BastionPathDto): BastionHopDto? {
        val hops = path.hops
        if (hops.isEmpty()) return null
        hops.firstOrNull { it.isBastion }?.let { return it }
        return if (hops.size >= 2) hops.first() else null
    }

    /** Extract the target hop (last hop) from a path for pre-filling the edit form. */
    fun targetHop(path: BastionPathDto): BastionHopDto? = path.hops.lastOrNull()

    /**
     * Build the PATCH body from the edited form. Backend semantics: any field left null is
     * unchanged; jump_hops + target are replaced *together* when the chain is edited. We always
     * send label/description (cheap idempotent) and, since this form always edits the chain,
     * send jump_hops + target together. A blank jump host means "no bastion" -> empty jump list.
     */
    fun buildUpdate(
        original: BastionPathDto,
        label: String,
        description: String,
        jumpHost: String,
        jumpUser: String,
        targetHost: String,
        targetUser: String,
    ): UpdateBastionPathReq {
        val jumps = if (jumpHost.isNotBlank()) {
            listOf(
                BastionHopReq(
                    hostname = jumpHost.trim(),
                    username = jumpUser.trim(),
                    label = "bastion",
                ),
            )
        } else {
            emptyList()
        }
        return UpdateBastionPathReq(
            label = label.trim().takeIf { it != original.label } ?: label.trim(),
            description = description.trim(),
            jumpHops = jumps,
            target = BastionHopReq(
                hostname = targetHost.trim(),
                username = targetUser.trim(),
                label = "target",
            ),
        )
    }
}
