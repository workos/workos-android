// @oagen-ignore-file
// Pure-JVM port of Iron's Fe26.2 seal/unseal format -- the same format Hapi's "iron"
// and the npm "iron-webcrypto" package produce. Interoperable with the sealed session
// cookies WorkOS Node writes, which is verified by a fixed cross-SDK vector in
// IronTest. Ported from workos-kotlin's com.workos.session.Iron.
package com.workos.android.helpers

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** Thrown when an Iron-sealed token cannot be unsealed. */
public class IronException(
    message: String,
) : RuntimeException(message)

/**
 * Iron Fe26.2 sealing primitives.
 *
 * Format:
 * ```
 * Fe26.2*<passwordId>*<encSalt>*<iv>*<ciphertext>*<expiration>*<intSalt>*<hmac>
 * ```
 * `iv`, `ciphertext` and `hmac` are base64url without padding; the salts are hex;
 * `expiration` is empty when there is no TTL. Passwords must be at least 32 characters.
 *
 * ⚠️ **Key derivation is PBKDF2-HMAC-SHA1 with ONE iteration.** That is not a mistake
 * and must not be "hardened": it is exactly what iron-webcrypto does, and the iteration
 * count is part of the wire format. Raising it would make every existing session cookie
 * — and every cookie written by the Node and Python SDKs — permanently unreadable.
 * This is a sealing primitive for high-entropy random passwords, **not** a
 * password-hashing KDF, and must never be reused as one.
 */
public object Iron {
    private const val MAC_PREFIX = "Fe26.2"
    private const val PASSWORD_ID = "1"
    private const val SALT_BITS = 256
    private const val KEY_BITS = 256
    private const val IV_BITS = 128
    private const val MIN_PASSWORD_CHARS = 32
    private val URL = Base64.getUrlEncoder().withoutPadding()
    private val URL_DECODER = Base64.getUrlDecoder()
    private val random = SecureRandom()

    /**
     * Seal [data] (UTF-8, usually JSON) into an Iron Fe26.2 token.
     *
     * @param ttlMillis lifetime of the seal; `0` means no expiration.
     * @param nowMillis injectable clock, so expiry is testable without sleeping.
     */
    public fun seal(
        data: String,
        password: String,
        ttlMillis: Long = 0,
        nowMillis: Long = System.currentTimeMillis(),
    ): String {
        require(password.length >= MIN_PASSWORD_CHARS) {
            "Password must be at least $MIN_PASSWORD_CHARS characters"
        }
        val encSalt = hex(randomBytes(SALT_BITS / 8))
        val iv = randomBytes(IV_BITS / 8)
        val encKey = deriveKey(password, encSalt, KEY_BITS / 8)
        val ciphertext = aesCbc(Cipher.ENCRYPT_MODE, data.toByteArray(Charsets.UTF_8), encKey, iv)

        val expiration = if (ttlMillis > 0) (nowMillis + ttlMillis).toString() else ""
        val macBase = macBase(encSalt, URL.encodeToString(iv), URL.encodeToString(ciphertext), expiration)

        // A fresh integrity salt per seal, independent of the encryption salt.
        val intSalt = hex(randomBytes(SALT_BITS / 8))
        val intKey = deriveKey(password, intSalt, KEY_BITS / 8)
        val hmac = hmacSha256(intKey, macBase.toByteArray(Charsets.UTF_8))
        return "$macBase*$intSalt*${URL.encodeToString(hmac)}"
    }

    /**
     * Unseal a token produced by [seal].
     *
     * The HMAC is checked **before** decryption, so a tampered ciphertext surfaces as a
     * bad MAC rather than as a padding error — which is what keeps this from being a
     * padding oracle.
     *
     * @throws IronException when malformed, the password does not match, the HMAC is
     *   invalid, or the TTL has passed.
     */
    public fun unseal(
        sealed: String,
        password: String,
        nowMillis: Long = System.currentTimeMillis(),
    ): String {
        require(password.length >= MIN_PASSWORD_CHARS) {
            "Password must be at least $MIN_PASSWORD_CHARS characters"
        }
        val parts = sealed.split("*")
        if (parts.size != 8) throw IronException("Incorrect number of sealed components")
        val (prefix, _, encSaltHex, ivB64) = parts
        val ctB64 = parts[4]
        val expiration = parts[5]
        val intSaltHex = parts[6]
        val hmacB64 = parts[7]
        if (prefix != MAC_PREFIX) throw IronException("Wrong mac prefix")

        val macBase = macBase(encSaltHex, ivB64, ctB64, expiration)
        val intKey = deriveKey(password, intSaltHex, KEY_BITS / 8)
        val expectedHmac = hmacSha256(intKey, macBase.toByteArray(Charsets.UTF_8))
        val givenHmac =
            try {
                URL_DECODER.decode(hmacB64)
            } catch (e: IllegalArgumentException) {
                throw IronException("Bad hmac encoding")
            }
        if (!constantTimeEquals(expectedHmac, givenHmac)) throw IronException("Bad hmac value")

        if (expiration.isNotEmpty()) {
            val exp = expiration.toLongOrNull() ?: throw IronException("Invalid expiration")
            if (nowMillis > exp) throw IronException("Expired seal")
        }

        val encKey = deriveKey(password, encSaltHex, KEY_BITS / 8)
        return try {
            String(
                aesCbc(Cipher.DECRYPT_MODE, URL_DECODER.decode(ctB64), encKey, URL_DECODER.decode(ivB64)),
                Charsets.UTF_8,
            )
        } catch (e: GeneralSecurityExceptionAlias) {
            throw IronException("Could not decrypt seal")
        }
    }

    private fun macBase(
        encSalt: String,
        ivB64: String,
        ctB64: String,
        expiration: String,
    ): String = listOf(MAC_PREFIX, PASSWORD_ID, encSalt, ivB64, ctB64, expiration).joinToString("*")

    private fun randomBytes(length: Int): ByteArray = ByteArray(length).also { random.nextBytes(it) }

    /**
     * iron-webcrypto hex-encodes the random salt, then feeds the UTF-8 bytes of that hex
     * STRING into PBKDF2 — not the salt's raw bytes. Deriving from the raw bytes would
     * produce a different key and break interop invisibly.
     */
    private fun deriveKey(
        password: String,
        salt: String,
        keyLengthBytes: Int,
    ): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt.toByteArray(Charsets.UTF_8), 1, keyLengthBytes * 8)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).encoded
    }

    private fun aesCbc(
        mode: Int,
        input: ByteArray,
        key: ByteArray,
        iv: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(input)
    }

    private fun hmacSha256(
        key: ByteArray,
        data: ByteArray,
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun constantTimeEquals(
        a: ByteArray,
        b: ByteArray,
    ): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) result = result or (a[i].toInt() xor b[i].toInt())
        return result == 0
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}

private typealias GeneralSecurityExceptionAlias = java.security.GeneralSecurityException
