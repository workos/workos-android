// @oagen-ignore-file
package com.workos.android

import com.workos.android.helpers.SignatureVerificationException
import com.workos.android.helpers.WebhookVerification
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * H01 / H02 webhook signature verification.
 *
 * The expected HMAC is recomputed here from first principles rather than by calling
 * the implementation, so an implementation that is self-consistent but wrong — the
 * failure mode that matters, since it would reject every real WorkOS webhook — cannot
 * pass. The construction under test is `HMAC-SHA256("<timestamp>.<payload>")` keyed
 * with the raw secret bytes, lowercase hex.
 */
class WebhookVerificationTest {
    private val webhooks = WebhookVerification()
    private val secret = "secret_test_123"
    private val payload = """{"id":"event_1","event":"user.created","data":{"id":"user_1"}}"""
    private val now = 1_700_000_000_000L

    /** Independent HMAC, deliberately not routed through the implementation. */
    private fun hmacHex(
        timestamp: Long,
        body: String,
        key: String,
    ): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.toByteArray(), "HmacSHA256"))
        return mac.doFinal("$timestamp.$body".toByteArray()).joinToString("") { "%02x".format(it) }
    }

    private fun header(
        timestamp: Long = now,
        sig: String = hmacHex(timestamp, payload, secret),
        key: String = "v1",
    ) = "t=$timestamp, $key=$sig"

    @Test
    fun `H02 createSignature matches an independently computed HMAC-SHA256`() {
        assertEquals(hmacHex(now, payload, secret), webhooks.createSignature(now.toString(), payload, secret))
    }

    @Test
    fun `H02 signature is lowercase hex of the right length`() {
        val sig = webhooks.createSignature(now.toString(), payload, secret)
        assertEquals(64, sig.length, "SHA-256 is 32 bytes => 64 hex chars")
        assertEquals(sig.lowercase(), sig)
    }

    @Test
    fun `H01 accepts a correctly signed payload and returns the parsed event`() {
        val event = webhooks.constructEvent(payload, header(), secret, nowMillis = now)
        assertEquals("event_1", event["id"]?.jsonPrimitive?.content)
        assertEquals("user.created", event["event"]?.jsonPrimitive?.content)
    }

    @Test
    fun `H01 accepts the legacy s signature key as well as v1`() {
        // workos-kotlin accepts both; rejecting `s` would break older webhook configs.
        val event = webhooks.constructEvent(payload, header(key = "s"), secret, nowMillis = now)
        assertEquals("event_1", event["id"]?.jsonPrimitive?.content)
    }

    @Test
    fun `H01 rejects a tampered payload`() {
        val sigForOriginal = hmacHex(now, payload, secret)
        val tampered = payload.replace("user_1", "user_ATTACKER")

        val e =
            assertFailsWith<SignatureVerificationException> {
                webhooks.constructEvent(tampered, "t=$now, v1=$sigForOriginal", secret, nowMillis = now)
            }
        assertTrue(e.message.contains("do not match"), e.message)
    }

    @Test
    fun `H01 rejects a signature made with the wrong secret`() {
        val wrong = hmacHex(now, payload, "secret_WRONG")
        assertFailsWith<SignatureVerificationException> {
            webhooks.constructEvent(payload, "t=$now, v1=$wrong", secret, nowMillis = now)
        }
    }

    @Test
    fun `H01 rejects a timestamp outside the tolerance, in either direction`() {
        val stale = now - WebhookVerification.DEFAULT_TOLERANCE_MILLIS - 1
        val future = now + WebhookVerification.DEFAULT_TOLERANCE_MILLIS + 1
        for (ts in listOf(stale, future)) {
            val e =
                assertFailsWith<SignatureVerificationException> {
                    webhooks.constructEvent(payload, header(timestamp = ts), secret, nowMillis = now)
                }
            assertTrue(e.message.contains("tolerance"), "ts=$ts -> ${e.message}")
        }
    }

    @Test
    fun `H01 accepts a timestamp exactly at the tolerance boundary`() {
        val edge = now - WebhookVerification.DEFAULT_TOLERANCE_MILLIS
        webhooks.constructEvent(payload, header(timestamp = edge), secret, nowMillis = now)
    }

    @Test
    fun `H02 rejects malformed headers`() {
        for (bad in listOf("", "v1=abc", "t=$now", "t=notanumber, v1=abc", "garbage")) {
            assertFailsWith<SignatureVerificationException>("should reject: '$bad'") {
                webhooks.verifyHeader(payload, bad, secret, nowMillis = now)
            }
        }
    }

    @Test
    fun `H02 rejects a non-hex signature rather than crashing`() {
        val e =
            assertFailsWith<SignatureVerificationException> {
                webhooks.verifyHeader(payload, "t=$now, v1=zzzz", secret, nowMillis = now)
            }
        assertTrue(e.message.contains("hex") || e.message.contains("match"), e.message)
    }

    @Test
    fun `H01 rejects a truncated signature instead of matching on a prefix`() {
        val full = hmacHex(now, payload, secret)
        assertFailsWith<SignatureVerificationException> {
            webhooks.verifyHeader(payload, "t=$now, v1=${full.take(32)}", secret, nowMillis = now)
        }
    }

    @Test
    fun `H01 rejects a payload that is not a JSON object`() {
        val body = "[1,2,3]"
        assertFailsWith<SignatureVerificationException> {
            webhooks.constructEvent(body, "t=$now, v1=${hmacHex(now, body, secret)}", secret, nowMillis = now)
        }
    }

    @Test
    fun `H01 verification is whitespace-sensitive, so the raw body must be used`() {
        // Re-serializing parsed JSON changes whitespace and breaks the HMAC. Pinning it
        // so the requirement is visible rather than folklore.
        val reserialized = """{"id": "event_1", "event": "user.created", "data": {"id": "user_1"}}"""
        assertFailsWith<SignatureVerificationException> {
            webhooks.verifyHeader(reserialized, header(), secret, nowMillis = now)
        }
    }
}
