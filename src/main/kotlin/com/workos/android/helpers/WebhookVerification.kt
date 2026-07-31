// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.internal.workosJson
import kotlinx.serialization.json.JsonObject

/**
 * H01 / H02 — webhook signature verification.
 *
 * Deliberately independent of [com.workos.android.WorkOSClient]: a handler verifying
 * an inbound webhook has a signing secret, not an API key, and needs no client.
 *
 * Ported from `workos-kotlin`'s `com.workos.webhooks.Webhook` so both SDKs accept
 * exactly the same signatures. Primitives live in `Signing.kt`, shared with Actions.
 *
 * ⚠️ [payload] must be the **raw** request body, byte-for-byte as received.
 * Re-serializing parsed JSON changes key order and whitespace, which changes the HMAC
 * and fails every verification.
 */
public class WebhookVerification {
    /**
     * Verify [signatureHeader] against [payload] and return the event as raw JSON.
     *
     * Returns [JsonObject] rather than a typed event: android has no aggregate event
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
        return workosJson.parseToJsonElement(payload) as? JsonObject
            ?: throw SignatureVerificationException("Webhook payload was not a JSON object")
    }

    /**
     * H02 — verify the header without parsing the body.
     *
     * The tolerance is **two-sided** here (`abs(now - t)`), unlike Actions, which only
     * rejects stale timestamps. Both match their `workos-kotlin` counterparts.
     *
     * @param nowMillis injectable clock, so tolerance is testable without freezing
     *   global time.
     */
    public fun verifyHeader(
        payload: String,
        signatureHeader: String,
        secret: String,
        toleranceMillis: Long = DEFAULT_TOLERANCE_MILLIS,
        nowMillis: Long = System.currentTimeMillis(),
    ) {
        // Webhooks accept the legacy `s` key as well as `v1`.
        val (timestamp, provided) = parseSignatureHeader(signatureHeader, setOf("v1", "s"))
        val timestampMs =
            timestamp.toLongOrNull()
                ?: throw SignatureVerificationException("Timestamp is not a valid long value")
        if (kotlin.math.abs(nowMillis - timestampMs) > toleranceMillis) {
            throw SignatureVerificationException("Timestamp outside the tolerance zone")
        }
        verifyHexSignaturesMatch(createSignature(timestamp, payload, secret), provided)
    }

    /** H02 — compute the expected `HMAC-SHA256("<timestamp>.<data>")`, lowercase hex. */
    public fun createSignature(
        timestamp: String,
        data: String,
        key: String,
    ): String = hmacSha256Hex(timestamp, data, key)

    public companion object {
        /** 3 minutes, matching every other WorkOS SDK. */
        public const val DEFAULT_TOLERANCE_MILLIS: Long = 180_000L
    }
}
