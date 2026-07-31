// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.RequestOptions
import com.workos.android.WorkOSClient
import com.workos.android.vault
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val IV_LENGTH_BYTES = 12
private const val TAG_LENGTH_BYTES = 16
private const val GCM_TAG_BITS = 128
private const val MAX_LEB128_BYTES_U32 = 5

/**
 * H18 — Vault client-side envelope encryption.
 *
 * The Vault HTTP endpoints are spec-driven and generated (`client.vault`); this is the
 * local AES-GCM layer over the data-key APIs, which has no endpoint of its own and so
 * can never be generated.
 *
 * Wire format, ported byte-for-byte from `workos-kotlin`'s Vault crypto so ciphertext
 * is interchangeable between SDKs:
 *
 * ```
 * base64( [IV:12] [TAG:16] [LEB128 u32 keyBlobLen] [keyBlob] [ciphertext] )
 * ```
 *
 * AES-256-GCM with a 128-bit tag. The tag is stored **before** the key blob rather
 * than appended to the ciphertext as JCE returns it, so `encrypt` splits it out and
 * `decrypt` reassembles it — a detail that silently breaks interop if reordered.
 *
 * `associatedData` is authenticated but not encrypted: the same value must be supplied
 * to [decrypt], or authentication fails.
 */
public class VaultCrypto internal constructor(
    private val client: WorkOSClient,
) {
    private val secureRandom = SecureRandom()
    private val base64 = Base64.getEncoder()
    private val base64Decoder = Base64.getDecoder()

    /**
     * Encrypt [data] with a fresh data key derived from [keyContext].
     *
     * Each call mints a new data key, so encrypting the same input twice yields
     * different ciphertext — that is correct for GCM, which must never reuse an IV
     * with a key.
     */
    public suspend fun encrypt(
        data: String,
        keyContext: Map<String, String>,
        associatedData: String? = null,
        requestOptions: RequestOptions? = null,
    ): String {
        val pair = client.vault.createDataKey(context = keyContext, requestOptions = requestOptions)
        val key = base64Decoder.decode(pair.dataKey)
        val keyBlob = base64Decoder.decode(pair.encryptedKeys)
        val iv = ByteArray(IV_LENGTH_BYTES).also { secureRandom.nextBytes(it) }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        associatedData?.let { cipher.updateAAD(it.toByteArray(Charsets.UTF_8)) }
        // JCE returns ciphertext||tag; the envelope stores them separately.
        val combined = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        val ciphertext = combined.copyOfRange(0, combined.size - TAG_LENGTH_BYTES)
        val tag = combined.copyOfRange(combined.size - TAG_LENGTH_BYTES, combined.size)

        val lenPrefix = encodeU32Leb128(keyBlob.size)
        val payload = ByteArray(iv.size + tag.size + lenPrefix.size + keyBlob.size + ciphertext.size)
        var offset = 0
        iv.copyInto(payload, offset)
        offset += iv.size
        tag.copyInto(payload, offset)
        offset += tag.size
        lenPrefix.copyInto(payload, offset)
        offset += lenPrefix.size
        keyBlob.copyInto(payload, offset)
        offset += keyBlob.size
        ciphertext.copyInto(payload, offset)
        return base64.encodeToString(payload)
    }

    /**
     * Decrypt a payload produced by [encrypt].
     *
     * Throws from JCE (`AEADBadTagException`) when the ciphertext, tag, or
     * [associatedData] does not authenticate — a tamper is a hard failure, never a
     * silently truncated plaintext.
     */
    public suspend fun decrypt(
        encryptedData: String,
        associatedData: String? = null,
        requestOptions: RequestOptions? = null,
    ): String {
        val decoded = decodeEncryptedPayload(encryptedData)
        val dataKey = client.vault.createDecrypt(keys = decoded.keys, requestOptions = requestOptions)
        val key = base64Decoder.decode(dataKey.dataKey)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, decoded.iv))
        associatedData?.let { cipher.updateAAD(it.toByteArray(Charsets.UTF_8)) }
        val input = ByteArray(decoded.ciphertext.size + decoded.tag.size)
        decoded.ciphertext.copyInto(input, 0)
        decoded.tag.copyInto(input, decoded.ciphertext.size)
        return String(cipher.doFinal(input), Charsets.UTF_8)
    }

    private class DecodedPayload(
        val iv: ByteArray,
        val tag: ByteArray,
        val keys: String,
        val ciphertext: ByteArray,
    )

    private fun decodeEncryptedPayload(b64: String): DecodedPayload {
        val raw = base64Decoder.decode(b64)
        require(raw.size >= IV_LENGTH_BYTES + TAG_LENGTH_BYTES + 1) { "Encrypted payload is too short" }
        val iv = raw.copyOfRange(0, IV_LENGTH_BYTES)
        val tag = raw.copyOfRange(IV_LENGTH_BYTES, IV_LENGTH_BYTES + TAG_LENGTH_BYTES)
        val (keyLen, lebLen) = decodeU32Leb128(raw, IV_LENGTH_BYTES + TAG_LENGTH_BYTES)
        val keysStart = IV_LENGTH_BYTES + TAG_LENGTH_BYTES + lebLen
        val keysEnd = keysStart + keyLen
        require(keysEnd <= raw.size) { "Encrypted payload key blob length exceeds the payload" }
        return DecodedPayload(
            iv = iv,
            tag = tag,
            keys = base64.encodeToString(raw.copyOfRange(keysStart, keysEnd)),
            ciphertext = raw.copyOfRange(keysEnd, raw.size),
        )
    }

    private fun encodeU32Leb128(value: Int): ByteArray {
        require(value >= 0) { "LEB128 value must be non-negative" }
        var remaining = value
        val out = ArrayList<Byte>(MAX_LEB128_BYTES_U32)
        while (true) {
            var byte = remaining and 0x7F
            remaining = remaining ushr 7
            if (remaining != 0) byte = byte or 0x80
            out += byte.toByte()
            if (remaining == 0) break
        }
        return ByteArray(out.size) { out[it] }
    }

    private fun decodeU32Leb128(
        buf: ByteArray,
        offset: Int,
    ): Pair<Int, Int> {
        var result = 0
        var shift = 0
        var bytesRead = 0
        var index = offset
        while (index < buf.size) {
            val b = buf[index].toInt() and 0xFF
            bytesRead++
            if (bytesRead > MAX_LEB128_BYTES_U32) {
                throw IllegalArgumentException("LEB128 sequence exceeds maximum length for uint32")
            }
            result = result or ((b and 0x7F) shl shift)
            index++
            if (b and 0x80 == 0) return result to bytesRead
            shift += 7
        }
        throw IllegalArgumentException("Truncated LEB128 encoding")
    }
}

/** Hand-maintained accessor for the local crypto layer over `client.vault`. */
public val WorkOSClient.vaultCrypto: VaultCrypto
    get() = VaultCrypto(this)
