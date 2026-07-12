package com.testlogon.android.data.messaging

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * MSG — real client-side message encryption for the encrypted-message demo: AES-256-GCM with a
 * PBKDF2-SHA256-derived key (passphrase + per-message salt). Produces / consumes the
 * [MessageEncryptionEnvelopeDto] wire shape (16-byte salt, 12-byte IV, ciphertext+GCM tag). The
 * passphrase is NEVER sent to the server; only the receiver who knows it can decrypt.
 */
object MessageCrypto {
    private const val ITERATIONS = 100_000
    private const val KEY_BITS = 256
    private const val GCM_TAG_BITS = 128
    private const val SALT_BYTES = 16
    private const val IV_BYTES = 12

    private fun deriveKey(passphrase: String, salt: ByteArray, iterations: Int): SecretKeySpec {
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, iterations, KEY_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    // java.util.Base64 (NOT android.util.Base64) so the crypto is unit-testable on the JVM.
    private fun b64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)
    private fun unb64(s: String): ByteArray = java.util.Base64.getDecoder().decode(s)

    /** Encrypt [plaintext] under [passphrase], returning a wire envelope. */
    fun encrypt(plaintext: String, passphrase: String): MessageEncryptionEnvelopeDto {
        val rnd = SecureRandom()
        val salt = ByteArray(SALT_BYTES).also { rnd.nextBytes(it) }
        val iv = ByteArray(IV_BYTES).also { rnd.nextBytes(it) }
        val key = deriveKey(passphrase, salt, ITERATIONS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return MessageEncryptionEnvelopeDto(
            version = 1,
            alg = "AES-256-GCM",
            kdf = "PBKDF2-SHA256",
            iterations = ITERATIONS,
            saltB64 = b64(salt),
            ivB64 = b64(iv),
            ciphertextB64 = b64(ct),
        )
    }

    /**
     * MSG (encrypted media) — encrypt raw [plain] bytes. The ciphertext is uploaded to storage, so the
     * returned envelope carries only salt/iv/iterations (ciphertextB64 = null). Returns (envelope, ct).
     */
    fun encryptBytes(plain: ByteArray, passphrase: String): Pair<MessageEncryptionEnvelopeDto, ByteArray> {
        val rnd = SecureRandom()
        val salt = ByteArray(SALT_BYTES).also { rnd.nextBytes(it) }
        val iv = ByteArray(IV_BYTES).also { rnd.nextBytes(it) }
        val key = deriveKey(passphrase, salt, ITERATIONS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ct = cipher.doFinal(plain)
        val envelope = MessageEncryptionEnvelopeDto(
            version = 1,
            alg = "AES-256-GCM",
            kdf = "PBKDF2-SHA256",
            iterations = ITERATIONS,
            saltB64 = b64(salt),
            ivB64 = b64(iv),
            ciphertextB64 = null,
        )
        return envelope to ct
    }

    /**
     * MSG (encrypted media) — decrypt the storage [cipher] bytes with the [envelope] + [passphrase].
     * Returns the plaintext bytes, or null on a wrong passphrase / malformed input.
     */
    fun decryptBytes(cipher: ByteArray, envelope: MessageEncryption, passphrase: String): ByteArray? = try {
        val salt = unb64(envelope.saltB64)
        val iv = unb64(envelope.ivB64)
        val key = deriveKey(passphrase, salt, envelope.iterations.coerceAtLeast(1))
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        c.doFinal(cipher)
    } catch (_: Exception) {
        null
    }

    /**
     * Decrypt the [envelope] with [passphrase]. Returns the plaintext, or null when the passphrase is
     * wrong (GCM tag mismatch) or the envelope is malformed — the caller surfaces "wrong passphrase".
     */
    fun decrypt(envelope: MessageEncryption, passphrase: String): String? = try {
        val ctB64 = envelope.ciphertextB64 ?: return null
        val salt = unb64(envelope.saltB64)
        val iv = unb64(envelope.ivB64)
        val key = deriveKey(passphrase, salt, envelope.iterations.coerceAtLeast(1))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        String(cipher.doFinal(unb64(ctB64)), Charsets.UTF_8)
    } catch (_: Exception) {
        null
    }
}
