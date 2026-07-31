// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.WorkOSClient
import com.workos.android.internal.workosJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Whether an action was approved or denied. */
public enum class ActionVerdict(
    /** The wire value sent in the signed response payload. */
    public val value: String,
) {
    ALLOW("Allow"),
    DENY("Deny"),
}

/** Type of action whose response is being signed. */
public enum class ActionResponseType(
    /** The `object` discriminator sent in the signed response. */
    public val objectName: String,
) {
    AUTHENTICATION("authentication_action_response"),
    USER_REGISTRATION("user_registration_action_response"),
}

/** A signed response payload ready to be returned to AuthKit. */
public data class SignedActionResponse(
    /** The object type discriminator, e.g. `"authentication_action_response"`. */
    public val objectName: String,
    /** The signed payload: `timestamp`, `verdict`, and `error_message` when denying. */
    public val payload: JsonObject,
    /** Lowercase-hex HMAC-SHA256 of the payload. */
    public val signature: String,
)

/**
 * H03 — AuthKit Actions: verify signed action requests and sign action responses.
 *
 * Stateless. Ported from `workos-kotlin`'s `com.workos.actions.Actions`, whose wire
 * format matches `workos-node` exactly: `HMAC-SHA256("<timestamp>.<payload>")` with
 * the header form `t=<ms>,v1=<hex>`.
 *
 * Two details differ from webhook verification and are deliberate, not oversights:
 *
 * 1. **30-second tolerance**, not 3 minutes — an action blocks a live sign-in, so the
 *    acceptable window is much tighter.
 * 2. **One-sided tolerance.** Only stale timestamps are rejected; a timestamp in the
 *    future passes. Webhooks use `abs()`. Both mirror their `workos-kotlin`
 *    counterparts, so changing either would diverge from the other SDKs.
 */
public class Actions {
    /**
     * Verify the signature on an incoming action request and return the parsed payload.
     *
     * ⚠️ [payload] must be the **raw** request body — re-serializing changes the HMAC.
     *
     * @throws SignatureVerificationException on any verification failure.
     */
    public fun constructAction(
        payload: String,
        sigHeader: String,
        secret: String,
        toleranceMillis: Long = DEFAULT_TOLERANCE_MILLIS,
        nowMillis: Long = System.currentTimeMillis(),
    ): JsonObject {
        verifyHeader(payload, sigHeader, secret, toleranceMillis, nowMillis)
        return workosJson.parseToJsonElement(payload) as? JsonObject
            ?: throw SignatureVerificationException("Action payload was not a JSON object")
    }

    /** @throws SignatureVerificationException if the signature is invalid or stale. */
    public fun verifyHeader(
        payload: String,
        sigHeader: String,
        secret: String,
        toleranceMillis: Long = DEFAULT_TOLERANCE_MILLIS,
        nowMillis: Long = System.currentTimeMillis(),
    ) {
        // Actions accepts only `v1` — no legacy `s` key, unlike webhooks.
        val (timestamp, provided) = parseSignatureHeader(sigHeader, setOf("v1"))
        val timestampMs =
            timestamp.toLongOrNull()
                ?: throw SignatureVerificationException("Timestamp is not a valid long value")
        // One-sided on purpose; see the class doc.
        if (timestampMs < nowMillis - toleranceMillis) {
            throw SignatureVerificationException("Timestamp outside the tolerance zone")
        }
        verifyHexSignaturesMatch(computeSignature(timestamp, payload, secret), provided)
    }

    /**
     * Sign an action response.
     *
     * `error_message` is included only when denying and a message is supplied, matching
     * `workos-node` — an empty key would change the JSON and therefore the signature.
     */
    public fun signResponse(
        type: ActionResponseType,
        verdict: ActionVerdict,
        secret: String,
        errorMessage: String? = null,
        nowMillis: Long = System.currentTimeMillis(),
    ): SignedActionResponse {
        // Insertion order is load-bearing: the HMAC covers the serialized JSON, so
        // reordering these keys would produce a signature AuthKit rejects.
        val fields = LinkedHashMap<String, JsonPrimitive>()
        fields["timestamp"] = JsonPrimitive(nowMillis)
        fields["verdict"] = JsonPrimitive(verdict.value)
        if (verdict == ActionVerdict.DENY && !errorMessage.isNullOrEmpty()) {
            fields["error_message"] = JsonPrimitive(errorMessage)
        }
        val payload = JsonObject(fields)
        val serialized = workosJson.encodeToString(JsonObject.serializer(), payload)
        return SignedActionResponse(
            objectName = type.objectName,
            payload = payload,
            signature = computeSignature(nowMillis.toString(), serialized, secret),
        )
    }

    /** Low-level primitive: `HMAC-SHA256("<timestamp>.<payload>")`, lowercase hex. */
    public fun computeSignature(
        timestamp: String,
        payload: String,
        secret: String,
    ): String = hmacSha256Hex(timestamp, payload, secret)

    public companion object {
        /** 30 seconds, matching `workos-node`'s `constructAction` default. */
        public const val DEFAULT_TOLERANCE_MILLIS: Long = 30_000L
    }
}

/** Hand-maintained accessor on the client. */
public val WorkOSClient.actions: Actions
    get() = Actions()
