// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.WorkOSException
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// Signature primitives shared by webhook verification (H01/H02) and AuthKit Actions
// (H03). Both use the same construction -- HMAC-SHA256("<timestamp>.<payload>"),
// lowercase hex, constant-time compared -- so it lives in one place. They differ only
// in tolerance and accepted header keys, which are parameters here.

/**
 * Raised when a webhook or Actions signature cannot be verified.
 *
 * Deliberately an SDK-native error rather than `java.security.SignatureException`
 * (which `workos-kotlin` uses), so callers catch one hierarchy —
 * `sdk-runtime-contract.md` §3. `statusCode` is 0: a signature failure is local, with
 * no HTTP status behind it, matching `NetworkException` and `DecodingException`.
 */
public class SignatureVerificationException(
    message: String,
) : WorkOSException(0, message)

/** A parsed `WorkOS-Signature` header. */
internal data class SignatureHeader(
    val timestamp: String,
    val signature: String,
)

/**
 * Parse a `WorkOS-Signature` header: comma-separated `key=value` pairs, where `t` is
 * the issue timestamp and the signature is under the first present key in
 * [signatureKeys].
 *
 * Webhooks accept both `v1` and the legacy `s`; Actions accepts only `v1`. Ported from
 * `workos-kotlin`'s `parseSignatureHeader` so both SDKs accept the same headers.
 */
internal fun parseSignatureHeader(
    signatureHeader: String,
    signatureKeys: Set<String>,
): SignatureHeader {
    val parts =
        signatureHeader
            .split(",")
            .mapNotNull { part ->
                val trimmed = part.trim()
                val index = trimmed.indexOf('=')
                if (index <= 0 || index >= trimmed.lastIndex) {
                    null
                } else {
                    trimmed.substring(0, index) to trimmed.substring(index + 1)
                }
            }.toMap(LinkedHashMap())

    val timestamp = parts["t"].orEmpty()
    val signature = signatureKeys.firstNotNullOfOrNull { parts[it] }?.takeIf { it.isNotEmpty() }.orEmpty()
    if (timestamp.isEmpty() || signature.isEmpty()) {
        throw SignatureVerificationException("Missing timestamp or signature component in WorkOS-Signature header")
    }
    return SignatureHeader(timestamp, signature)
}

/** `HMAC-SHA256("<timestamp>.<payload>")`, lowercase hex. */
internal fun hmacSha256Hex(
    timestamp: String,
    payload: String,
    secret: String,
): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(secret.toByteArray(), "HmacSHA256"))
    return mac.doFinal("$timestamp.$payload".toByteArray()).toHex()
}

/**
 * Compare two hex signatures in constant time.
 *
 * Both sides are decoded first and compared with [MessageDigest.isEqual]: a plain
 * string `==` short-circuits on the first differing character, which leaks how much of
 * a forged signature was correct.
 */
internal fun verifyHexSignaturesMatch(
    expectedHex: String,
    providedHex: String,
) {
    val expected =
        expectedHex.decodeHexOrNull()
            ?: throw SignatureVerificationException("Generated signature was not valid hex")
    val provided =
        providedHex.decodeHexOrNull()
            ?: throw SignatureVerificationException("Signature was not valid hex")
    if (expected.size != provided.size || !MessageDigest.isEqual(expected, provided)) {
        throw SignatureVerificationException("Signatures do not match")
    }
}

private val HEX_DIGITS = "0123456789abcdef".toCharArray()

internal fun ByteArray.toHex(): String {
    val chars = CharArray(size * 2)
    forEachIndexed { i, byte ->
        val v = byte.toInt() and 0xff
        chars[i * 2] = HEX_DIGITS[v ushr 4]
        chars[i * 2 + 1] = HEX_DIGITS[v and 0x0f]
    }
    return String(chars)
}

internal fun String.decodeHexOrNull(): ByteArray? {
    val s = trim()
    if (s.length % 2 != 0) return null
    val out = ByteArray(s.length / 2)
    var i = 0
    while (i < s.length) {
        val hi = Character.digit(s[i], 16)
        val lo = Character.digit(s[i + 1], 16)
        if (hi < 0 || lo < 0) return null
        out[i / 2] = ((hi shl 4) + lo).toByte()
        i += 2
    }
    return out
}
