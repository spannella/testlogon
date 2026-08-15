package com.testlogon.android.feature.custody

/*
 * A tiny, self-contained QR Code generator (byte mode) — vendored so the Deposit screen can render a
 * scannable address WITHOUT adding a gradle dependency (e.g. zxing). This is a compact, from-scratch
 * implementation of the QR Code model-2 encoding for the low-to-medium version range that a crypto
 * address / URI needs; it produces a square boolean matrix that a Compose Canvas paints as modules.
 *
 * Adapted from the public-domain "QR Code generator" reference algorithm (Nayuki), trimmed to the
 * byte-mode / single-segment path this feature uses. No external I/O, no reflection, no dependency.
 */
object QrCode {

    /** Error-correction level. MEDIUM is a good default for on-screen scanning of a wallet address. */
    enum class Ecc(val formatBits: Int) {
        LOW(1), MEDIUM(0), QUARTILE(3), HIGH(2)
    }

    /**
     * Encodes [text] (UTF-8, byte mode) into a square QR matrix. Returns the module grid where true =
     * dark. Returns null if the text is too long for the largest supported version (should not happen
     * for an address). Never throws on ordinary input.
     */
    fun encode(text: String, ecc: Ecc = Ecc.MEDIUM): Array<BooleanArray>? {
        val data = text.toByteArray(Charsets.UTF_8)
        // Byte-mode segment: 4-bit mode indicator + char-count + payload bytes.
        for (version in 1..40) {
            val dataCapacityBits = numDataCodewords(version, ecc) * 8
            val ccBits = if (version <= 9) 8 else 16
            val usedBits = 4 + ccBits + data.size * 8
            if (usedBits <= dataCapacityBits) {
                return build(version, ecc, data, ccBits)
            }
        }
        return null
    }

    private fun build(version: Int, ecc: Ecc, data: ByteArray, ccBits: Int): Array<BooleanArray> {
        val bb = BitBuffer()
        bb.appendBits(0x4, 4) // byte mode
        bb.appendBits(data.size, ccBits)
        for (b in data) bb.appendBits(b.toInt() and 0xFF, 8)

        val dataCapacityBits = numDataCodewords(version, ecc) * 8
        // Terminator + bit/byte padding.
        bb.appendBits(0, minOf(4, dataCapacityBits - bb.size))
        bb.appendBits(0, (8 - bb.size % 8) % 8)
        var pad = 0xEC
        while (bb.size < dataCapacityBits) {
            bb.appendBits(pad, 8)
            pad = pad xor 0xFD // toggles 0xEC <-> 0x11
        }

        val allCodewords = addEccAndInterleave(bb.toBytes(), version, ecc)
        val qr = QrMatrix(version, ecc)
        qr.drawFunctionPatterns()
        qr.drawCodewords(allCodewords)
        qr.applyBestMask()
        return qr.modules
    }

    // ---- capacity tables (data codewords per version+ecc), model 2 ----

    private val ECC_CODEWORDS_PER_BLOCK = arrayOf(
        // version 1..40 (index 0 unused)
        intArrayOf(-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30), // LOW
        intArrayOf(-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28), // MEDIUM
        intArrayOf(-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30), // QUARTILE
        intArrayOf(-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30), // HIGH
    )
    private val NUM_ERROR_CORRECTION_BLOCKS = arrayOf(
        intArrayOf(-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25), // LOW
        intArrayOf(-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49), // MEDIUM
        intArrayOf(-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68), // QUARTILE
        intArrayOf(-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81), // HIGH
    )

    private fun eccIndex(ecc: Ecc) = when (ecc) {
        Ecc.LOW -> 0; Ecc.MEDIUM -> 1; Ecc.QUARTILE -> 2; Ecc.HIGH -> 3
    }

    private fun numRawDataModules(ver: Int): Int {
        var result = (16 * ver + 128) * ver + 64
        if (ver >= 2) {
            val numAlign = ver / 7 + 2
            result -= (25 * numAlign - 10) * numAlign - 55
            if (ver >= 7) result -= 36
        }
        return result
    }

    private fun numDataCodewords(ver: Int, ecc: Ecc): Int {
        val e = eccIndex(ecc)
        val numBlocks = NUM_ERROR_CORRECTION_BLOCKS[e][ver]
        val eccPerBlock = ECC_CODEWORDS_PER_BLOCK[e][ver]
        return numRawDataModules(ver) / 8 - eccPerBlock * numBlocks
    }

    // ---- Reed-Solomon ECC + interleave ----

    private fun addEccAndInterleave(data: ByteArray, ver: Int, ecc: Ecc): ByteArray {
        val e = eccIndex(ecc)
        val numBlocks = NUM_ERROR_CORRECTION_BLOCKS[e][ver]
        val blockEccLen = ECC_CODEWORDS_PER_BLOCK[e][ver]
        val rawCodewords = numRawDataModules(ver) / 8
        val numShortBlocks = numBlocks - rawCodewords % numBlocks
        val shortBlockLen = rawCodewords / numBlocks

        val blocks = ArrayList<ByteArray>()
        val rsDiv = reedSolomonComputeDivisor(blockEccLen)
        var k = 0
        for (i in 0 until numBlocks) {
            val datLen = shortBlockLen - blockEccLen + (if (i < numShortBlocks) 0 else 1)
            val dat = data.copyOfRange(k, k + datLen)
            k += datLen
            val block = ByteArray(shortBlockLen + 1)
            System.arraycopy(dat, 0, block, 0, dat.size)
            val eccBytes = reedSolomonComputeRemainder(dat, rsDiv)
            System.arraycopy(eccBytes, 0, block, block.size - blockEccLen, eccBytes.size)
            blocks.add(block)
        }

        val result = ByteArray(rawCodewords)
        var idx = 0
        for (i in 0 until blocks[0].size) {
            for (j in blocks.indices) {
                if (i != shortBlockLen - blockEccLen || j >= numShortBlocks) {
                    result[idx] = blocks[j][i]
                    idx++
                }
            }
        }
        return result
    }

    private fun reedSolomonComputeDivisor(degree: Int): ByteArray {
        val result = ByteArray(degree)
        result[degree - 1] = 1
        var root = 1
        for (i in 0 until degree) {
            for (j in 0 until degree) {
                result[j] = reedSolomonMultiply(result[j].toInt() and 0xFF, root).toByte()
                if (j + 1 < degree) {
                    result[j] = (result[j].toInt() xor (result[j + 1].toInt() and 0xFF)).toByte()
                }
            }
            root = reedSolomonMultiply(root, 0x02)
        }
        return result
    }

    private fun reedSolomonComputeRemainder(data: ByteArray, divisor: ByteArray): ByteArray {
        val result = ByteArray(divisor.size)
        for (b in data) {
            val factor = (b.toInt() xor result[0].toInt()) and 0xFF
            System.arraycopy(result, 1, result, 0, result.size - 1)
            result[result.size - 1] = 0
            for (i in result.indices) {
                result[i] = (result[i].toInt() xor reedSolomonMultiply(divisor[i].toInt() and 0xFF, factor)).toByte()
            }
        }
        return result
    }

    private fun reedSolomonMultiply(x: Int, y: Int): Int {
        var z = 0
        for (i in 7 downTo 0) {
            z = (z shl 1) xor ((z ushr 7) * 0x11D)
            z = z xor ((y ushr i) and 1) * x
        }
        return z and 0xFF
    }

    // ---- matrix builder + masking ----

    private class QrMatrix(val version: Int, val ecc: Ecc) {
        val size = version * 4 + 17
        val modules = Array(size) { BooleanArray(size) }
        private val isFunction = Array(size) { BooleanArray(size) }

        fun drawFunctionPatterns() {
            for (i in 0 until size) {
                setFunctionModule(6, i, i % 2 == 0)
                setFunctionModule(i, 6, i % 2 == 0)
            }
            drawFinderPattern(3, 3)
            drawFinderPattern(size - 4, 3)
            drawFinderPattern(3, size - 4)

            val alignPos = alignmentPatternPositions()
            val n = alignPos.size
            for (i in 0 until n) {
                for (j in 0 until n) {
                    if (!((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0))) {
                        drawAlignmentPattern(alignPos[i], alignPos[j])
                    }
                }
            }
            drawFormatBits(0)
            drawVersion()
        }

        private fun setFunctionModule(x: Int, y: Int, isDark: Boolean) {
            modules[y][x] = isDark
            isFunction[y][x] = true
        }

        private fun drawFinderPattern(x: Int, y: Int) {
            for (dy in -4..4) {
                for (dx in -4..4) {
                    val dist = maxOf(Math.abs(dx), Math.abs(dy))
                    val xx = x + dx
                    val yy = y + dy
                    if (xx in 0 until size && yy in 0 until size) {
                        setFunctionModule(xx, yy, dist != 2 && dist != 4)
                    }
                }
            }
        }

        private fun drawAlignmentPattern(x: Int, y: Int) {
            for (dy in -2..2) {
                for (dx in -2..2) {
                    setFunctionModule(x + dx, y + dy, maxOf(Math.abs(dx), Math.abs(dy)) != 1)
                }
            }
        }

        private fun alignmentPatternPositions(): IntArray {
            if (version == 1) return IntArray(0)
            val numAlign = version / 7 + 2
            val step = if (version == 32) 26 else (version * 4 + numAlign * 2 + 1) / (numAlign * 2 - 2) * 2
            val result = IntArray(numAlign)
            var pos = size - 7
            for (i in numAlign - 1 downTo 1) {
                result[i] = pos
                pos -= step
            }
            result[0] = 6
            return result
        }

        private var currentFormatMask = 0

        fun drawFormatBits(mask: Int) {
            currentFormatMask = mask
            val data = ecc.formatBits shl 3 or mask
            var rem = data
            for (i in 0 until 10) rem = (rem shl 1) xor ((rem ushr 9) * 0x537)
            val bits = (data shl 10 or rem) xor 0x5412
            for (i in 0..5) setFunctionModule(8, i, getBit(bits, i))
            setFunctionModule(8, 7, getBit(bits, 6))
            setFunctionModule(8, 8, getBit(bits, 7))
            setFunctionModule(7, 8, getBit(bits, 8))
            for (i in 9 until 15) setFunctionModule(14 - i, 8, getBit(bits, i))
            for (i in 0 until 8) setFunctionModule(size - 1 - i, 8, getBit(bits, i))
            for (i in 8 until 15) setFunctionModule(8, size - 15 + i, getBit(bits, i))
            setFunctionModule(8, size - 8, true)
        }

        private fun drawVersion() {
            if (version < 7) return
            var rem = version
            for (i in 0 until 12) rem = (rem shl 1) xor ((rem ushr 11) * 0x1F25)
            val bits = version shl 12 or rem
            for (i in 0 until 18) {
                val bit = getBit(bits, i)
                val a = size - 11 + i % 3
                val b = i / 3
                setFunctionModule(a, b, bit)
                setFunctionModule(b, a, bit)
            }
        }

        fun drawCodewords(dataArg: ByteArray) {
            var i = 0
            var col = size - 1
            while (col >= 1) {
                if (col == 6) col = 5
                for (vert in 0 until size) {
                    for (j in 0 until 2) {
                        val x = col - j
                        val upward = ((col + 1) and 2) == 0
                        val y = if (upward) size - 1 - vert else vert
                        if (!isFunction[y][x] && i < dataArg.size * 8) {
                            modules[y][x] = getBit(dataArg[i ushr 3].toInt(), 7 - (i and 7))
                            i++
                        }
                    }
                }
                col -= 2
            }
        }

        fun applyBestMask() {
            var minPenalty = Int.MAX_VALUE
            var bestMask = 0
            for (mask in 0 until 8) {
                applyMask(mask)
                drawFormatBits(mask)
                val penalty = penaltyScore()
                if (penalty < minPenalty) {
                    minPenalty = penalty
                    bestMask = mask
                }
                applyMask(mask) // undo (XOR is its own inverse)
            }
            applyMask(bestMask)
            drawFormatBits(bestMask)
        }

        private fun applyMask(mask: Int) {
            for (y in 0 until size) {
                for (x in 0 until size) {
                    if (isFunction[y][x]) continue
                    val invert = when (mask) {
                        0 -> (x + y) % 2 == 0
                        1 -> y % 2 == 0
                        2 -> x % 3 == 0
                        3 -> (x + y) % 3 == 0
                        4 -> (x / 3 + y / 2) % 2 == 0
                        5 -> x * y % 2 + x * y % 3 == 0
                        6 -> (x * y % 2 + x * y % 3) % 2 == 0
                        else -> ((x + y) % 2 + x * y % 3) % 2 == 0
                    }
                    if (invert) modules[y][x] = !modules[y][x]
                }
            }
        }

        private fun penaltyScore(): Int {
            var result = 0
            // adjacent-same in rows/cols
            for (y in 0 until size) {
                var runColor = false
                var runX = 0
                for (x in 0 until size) {
                    if (modules[y][x] == runColor) {
                        runX++
                        if (runX == 5) result += 3 else if (runX > 5) result++
                    } else {
                        runColor = modules[y][x]; runX = 1
                    }
                }
            }
            for (x in 0 until size) {
                var runColor = false
                var runY = 0
                for (y in 0 until size) {
                    if (modules[y][x] == runColor) {
                        runY++
                        if (runY == 5) result += 3 else if (runY > 5) result++
                    } else {
                        runColor = modules[y][x]; runY = 1
                    }
                }
            }
            // 2x2 blocks
            for (y in 0 until size - 1) {
                for (x in 0 until size - 1) {
                    val c = modules[y][x]
                    if (c == modules[y][x + 1] && c == modules[y + 1][x] && c == modules[y + 1][x + 1]) result += 3
                }
            }
            // dark ratio
            var dark = 0
            for (row in modules) for (v in row) if (v) dark++
            val total = size * size
            val k = (Math.abs(dark * 20 - total * 10) + total - 1) / total - 1
            result += k * 10
            return result
        }

        private fun getBit(x: Int, i: Int): Boolean = ((x ushr i) and 1) != 0
    }

    private fun getBit(x: Int, i: Int): Boolean = ((x ushr i) and 1) != 0

    private class BitBuffer {
        private val data = ArrayList<Boolean>()
        val size: Int get() = data.size
        fun appendBits(value: Int, len: Int) {
            for (i in len - 1 downTo 0) data.add(((value ushr i) and 1) != 0)
        }
        fun toBytes(): ByteArray {
            val out = ByteArray((data.size + 7) / 8)
            for (i in data.indices) if (data[i]) out[i ushr 3] = (out[i ushr 3].toInt() or (0x80 ushr (i and 7))).toByte()
            return out
        }
    }
}
