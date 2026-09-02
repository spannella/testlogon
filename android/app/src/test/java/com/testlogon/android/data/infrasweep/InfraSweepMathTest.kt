package com.testlogon.android.data.infrasweep

import com.testlogon.android.data.infrak8s.K8sPodDto
import com.testlogon.android.data.sshbastion.BastionHopDto
import com.testlogon.android.data.sshbastion.BastionPathDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM unit tests for the PURE [InfraSweepMath] dev-platform sweep logic (no Android/Moshi/Retrofit):
 * K8s pod-detail degrade-on-404 merge + SSH-bastion edit-form -> PATCH mapping.
 */
class InfraSweepMathTest {

    // ---- mergePodDetail --------------------------------------------------------

    private fun listRow() = K8sPodDto(
        podId = "p1",
        k8sPodName = "pod-p1",
        namespace = "ns",
        label = "web",
        image = "img:1",
        imageDisplayName = "Web Image",
        preset = "small",
        cpuMillicores = 250,
        memoryMb = 512,
        status = "running",
        podIp = "10.0.0.1",
        serviceHostname = "web.svc",
        createdAt = 100L,
        expiresAt = 200L,
    )

    @Test
    fun merge_nullDetail_degradesToListRow() {
        val row = listRow()
        assertEquals(row, InfraSweepMath.mergePodDetail(row, null))
    }

    @Test
    fun merge_prefersDetailFields() {
        val row = listRow()
        val detail = row.copy(status = "terminated", podIp = "10.0.0.9", cpuMillicores = 500)
        val merged = InfraSweepMath.mergePodDetail(row, detail)
        assertEquals("terminated", merged.status)
        assertEquals("10.0.0.9", merged.podIp)
        assertEquals(500, merged.cpuMillicores)
    }

    @Test
    fun merge_blankDetailStringDoesNotBlankRow() {
        val row = listRow()
        val detail = row.copy(status = "", podIp = "", imageDisplayName = "")
        val merged = InfraSweepMath.mergePodDetail(row, detail)
        assertEquals("running", merged.status)
        assertEquals("10.0.0.1", merged.podIp)
        assertEquals("Web Image", merged.imageDisplayName)
    }

    @Test
    fun merge_zeroNumericDetailDoesNotZeroRow() {
        val row = listRow()
        val detail = row.copy(cpuMillicores = 0, memoryMb = 0, createdAt = 0L, expiresAt = 0L)
        val merged = InfraSweepMath.mergePodDetail(row, detail)
        assertEquals(250, merged.cpuMillicores)
        assertEquals(512, merged.memoryMb)
        assertEquals(100L, merged.createdAt)
        assertEquals(200L, merged.expiresAt)
    }

    @Test
    fun merge_keepsNonZeroDetailNumerics() {
        val row = listRow()
        val detail = row.copy(memoryMb = 1024, expiresAt = 999L)
        val merged = InfraSweepMath.mergePodDetail(row, detail)
        assertEquals(1024, merged.memoryMb)
        assertEquals(999L, merged.expiresAt)
    }

    // ---- isEditValid -----------------------------------------------------------

    @Test
    fun isEditValid_requiresAllThree() {
        assertTrue(InfraSweepMath.isEditValid("host", "user", "label"))
        assertFalse(InfraSweepMath.isEditValid("", "user", "label"))
        assertFalse(InfraSweepMath.isEditValid("host", "", "label"))
        assertFalse(InfraSweepMath.isEditValid("host", "user", ""))
        assertFalse(InfraSweepMath.isEditValid("  ", "user", "label"))
    }

    // ---- primaryJumpHop / targetHop --------------------------------------------

    private fun path(vararg hops: BastionHopDto) = BastionPathDto(
        pathId = "b1",
        label = "chain",
        description = "d",
        hops = hops.toList(),
        totalHops = hops.size,
    )

    @Test
    fun primaryJumpHop_prefersBastionFlag() {
        val p = path(
            BastionHopDto(hostname = "j1", isBastion = true, hopNumber = 0),
            BastionHopDto(hostname = "t", hopNumber = 1),
        )
        assertEquals("j1", InfraSweepMath.primaryJumpHop(p)?.hostname)
    }

    @Test
    fun primaryJumpHop_fallsBackToFirstOfMulti() {
        val p = path(
            BastionHopDto(hostname = "j1", hopNumber = 0),
            BastionHopDto(hostname = "t", hopNumber = 1),
        )
        assertEquals("j1", InfraSweepMath.primaryJumpHop(p)?.hostname)
    }

    @Test
    fun primaryJumpHop_singleHop_isNull() {
        val p = path(BastionHopDto(hostname = "only", hopNumber = 0))
        assertNull(InfraSweepMath.primaryJumpHop(p))
    }

    @Test
    fun primaryJumpHop_emptyHops_isNull() {
        assertNull(InfraSweepMath.primaryJumpHop(path()))
    }

    @Test
    fun targetHop_isLast() {
        val p = path(
            BastionHopDto(hostname = "j1", hopNumber = 0),
            BastionHopDto(hostname = "target", hopNumber = 1),
        )
        assertEquals("target", InfraSweepMath.targetHop(p)?.hostname)
        assertNull(InfraSweepMath.targetHop(path()))
    }

    // ---- buildUpdate -----------------------------------------------------------

    @Test
    fun buildUpdate_withJump_includesSingleBastion() {
        val req = InfraSweepMath.buildUpdate(
            original = path(),
            label = " prod ",
            description = " desc ",
            jumpHost = " bastion.example ",
            jumpUser = " ec2-user ",
            targetHost = " app.internal ",
            targetUser = " root ",
        )
        assertEquals("prod", req.label)
        assertEquals("desc", req.description)
        assertEquals(1, req.jumpHops!!.size)
        assertEquals("bastion.example", req.jumpHops!![0].hostname)
        assertEquals("ec2-user", req.jumpHops!![0].username)
        assertEquals("bastion", req.jumpHops!![0].label)
        assertEquals("app.internal", req.target!!.hostname)
        assertEquals("root", req.target!!.username)
        assertEquals("target", req.target!!.label)
    }

    @Test
    fun buildUpdate_blankJump_emptyJumpList() {
        val req = InfraSweepMath.buildUpdate(
            original = path(),
            label = "direct",
            description = "",
            jumpHost = "   ",
            jumpUser = "ignored",
            targetHost = "host",
            targetUser = "user",
        )
        assertTrue(req.jumpHops!!.isEmpty())
        assertEquals("host", req.target!!.hostname)
    }
}
