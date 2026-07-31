// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.WorkOSException
import com.workos.android.internal.workosJson
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Raised when a webhook or Actions signature cannot be verified.
 *
 * Deliberately an SDK-native error rather than `java.security.SignatureException`
 * (which `workos-kotlin` uses), so callers catch one hierarchy —
 * `sdk-runtime-contract.md` §3. `statusCode` is 0: a signature failure is local,
 * with no HTTP status behind it, matching `NetworkException` and `DecodingException`.
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
 * Ported from `workos-kotlin`'s `parseSignatureHeader`, including accepting both
 * `v1` and the legacy `s` key, so both SDKs accept the same headers.
 */
internal fun parseSignatureHeader(
    signatureHeader: String,
    signatureKeys: Set<String> = setOf("v1", "s"),
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

/**
 * H01 / H02 — webhook signature verification.
 *
 * Deliberately independent of [com.workos.android.WorkOSClient]: a handler verifying
 * an inbound webhook has a signing secret, not an API key, and needs no client.
 *
 * The scheme is ported from `workos-kotlin`'s `com.workos.webhooks.Webhook` so both
 * SDKs accept exactly the same signatures: `HMAC-SHA256("<timestamp>.<payload>")`
 * keyed with the raw secret bytes, lowercase hex, compared in constant time, with a
 * timestamp tolerance to bound replay.
 *
 * ⚠️ [payload] must be the **raw** request body, byte-for-byte as received.
 * Re-serializing parsed JSON changes key order and whitespace, which changes the
 * HMAC and fails every verification.
 */
public class WebhookVerification {
    /**
     * Verify [signatureHeader] against [payload] and return the event as raw JSON.
     *
     * Returns [JsonElement] rather than a typed event: android has no aggregate event
     * sum type yet (see the design doc's future enhancements), and raw JSON is
     * forward-compatible with event types this SDK release does not model.
     *
     * @throws SignatureVerificationException if the signature or timestamp is invalid.
     */
    public fun constructEvent(
        payload: String,
        signatureHeader: String,
        secret: String,
        toleranceMillis: Long = DEFAULT_TOLERANCE_MILLIS,
        nowMillis: Long = System.currentTimeMillis(),
    ): JsonObject {
        verifyHeader(payload, signatureHeader, secret, toleranceMillis, nowMillis)
        val parsed = workosJson.parseToJsonElement(payload)
        return parsed as? JsonObject
            ?: throw SignatureVerificationException("Webhook payload was not a JSON object")
    }

    /**
     * H02 — verify the header without parsing the body.
     *
     * @param nowMillis injectable clock, so tolerance behavior is testable without
     *   sleeping or freezing global time.
     */
    public fun verifyHeader(
        payload: String,
        signatureHeader: String,
        secret: String,
        toleranceMillis: Long = DEFAULT_TOLERANCE_MILLIS,
        nowMillis: Long = System.currentTimeMillis(),
    ) {
        val (timestamp, provided) = parseSignatureHeader(signatureHeader)
        val timestampMs =
            timestamp.toLongOrNull()
                ?: throw SignatureVerificationException("Timestamp is not a valid long value")
        if (kotlin.math.abs(nowMillis - timestampMs) > toleranceMillis) {
            throw SignatureVerificationException("Timestamp outside the tolerance zone")
        }
        val expectedBytes =
            createSignature(timestamp, payload, secret).decodeHexOrNull()
                ?: throw SignatureVerificationException("Generated signature was not valid hex")
        val providedBytes =
            provided.decodeHexOrNull()
                ?: throw SignatureVerificationException("Signature was not valid hex")
        // Constant-time: a length-dependent early return would leak the prefix length.
        if (expectedBytes.size != providedBytes.size || !MessageDigest.isEqual(expectedBytes, providedBytes)) {
            throw SignatureVerificationException("Signatures do not match")
        }
    }

    /** H02 — compute the expected `HMAC-SHA256("<timestamp>.<data>")`, lowercase hex. */
    public fun createSignature(
        timestamp: String,
        data: String,
        key: String,
    ): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.toByteArray(), "HmacSHA256"))
        return mac.doFinal("$timestamp.$data".toByteArray()).toHex()
    }

    public companion object {
        /** 3 minutes, matching every other WorkOS SDK. */
        public const val DEFAULT_TOLERANCE_MILLIS: Long = 180_000L
    }
}
