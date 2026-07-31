// @oagen-ignore-file
package com.workos.android

import com.workos.android.helpers.ActionResponseType
import com.workos.android.helpers.ActionVerdict
import com.workos.android.helpers.Actions
import com.workos.android.helpers.SignatureVerificationException
import com.workos.android.helpers.actions
import com.workos.android.support.testClient
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * H03 AuthKit Actions.
 *
 * As with webhooks, the expected HMAC is recomputed here from first principles so an
 * implementation that is self-consistent but wrong cannot pass.
 */
class ActionsTest {
    private val actions = Actions()
    private val secret = "secret_action_123"
    private val payload = """{"id":"action_1","object":"authentication_action_context"}"""
    private val now = 1_700_000_000_000L

    private fun hmacHex(
        timestamp: Long,
        body: String,
        key: String,
    ): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.toByteArray(), "HmacSHA256"))
        return mac.doFinal("$timestamp.$body".toByteArray()).joinToString("") { "%02x".format(it) }
    }

    @Test
    fun `H03 computeSignature matches an independently computed HMAC`() {
        assertEquals(hmacHex(now, payload, secret), actions.computeSignature(now.toString(), payload, secret))
    }

    @Test
    fun `H03 accepts a correctly signed action and returns the parsed payload`() {
        val action =
            actions.constructAction(
                payload,
                "t=$now, v1=${hmacHex(now, payload, secret)}",
                secret,
                nowMillis = now,
            )
        assertEquals("action_1", action["id"]?.jsonPrimitive?.content)
    }

    @Test
    fun `H03 rejects a tampered payload and the wrong secret`() {
        val sig = hmacHex(now, payload, secret)
        assertFailsWith<SignatureVerificationException> {
            actions.verifyHeader(payload.replace("action_1", "action_EVIL"), "t=$now, v1=$sig", secret, nowMillis = now)
        }
        assertFailsWith<SignatureVerificationException> {
            actions.verifyHeader(payload, "t=$now, v1=${hmacHex(now, payload, "WRONG")}", secret, nowMillis = now)
        }
    }

    @Test
    fun `H03 uses a 30 second tolerance, not the webhook 3 minutes`() {
        assertEquals(30_000L, Actions.DEFAULT_TOLERANCE_MILLIS)
        val stale = now - 30_001
        assertFailsWith<SignatureVerificationException> {
            actions.verifyHeader(payload, "t=$stale, v1=${hmacHex(stale, payload, secret)}", secret, nowMillis = now)
        }
        // just inside the window
        val fresh = now - 29_000
        actions.verifyHeader(payload, "t=$fresh, v1=${hmacHex(fresh, payload, secret)}", secret, nowMillis = now)
    }

    @Test
    fun `H03 tolerance is one-sided, so a future timestamp is accepted`() {
        // Deliberate divergence from webhook verification, which uses abs(). Pinned so
        // nobody "fixes" it into symmetry and diverges from workos-node.
        val future = now + 600_000
        actions.verifyHeader(payload, "t=$future, v1=${hmacHex(future, payload, secret)}", secret, nowMillis = now)
    }

    @Test
    fun `H03 does not accept the legacy s signature key`() {
        // Webhooks accept `s`; Actions must not.
        assertFailsWith<SignatureVerificationException> {
            actions.verifyHeader(payload, "t=$now, s=${hmacHex(now, payload, secret)}", secret, nowMillis = now)
        }
    }

    @Test
    fun `H03 signs an allow response over the exact serialized payload`() {
        val signed = actions.signResponse(ActionResponseType.AUTHENTICATION, ActionVerdict.ALLOW, secret, nowMillis = now)

        assertEquals("authentication_action_response", signed.objectName)
        assertEquals(
            now,
            signed.payload["timestamp"]
                ?.jsonPrimitive
                ?.content
                ?.toLong(),
        )
        assertEquals("Allow", signed.payload["verdict"]?.jsonPrimitive?.content)
        // The signature must cover the serialized payload with keys in this order.
        assertEquals(hmacHex(now, """{"timestamp":$now,"verdict":"Allow"}""", secret), signed.signature)
    }

    @Test
    fun `H03 includes error_message only when denying with a message`() {
        val denied =
            actions.signResponse(
                ActionResponseType.USER_REGISTRATION,
                ActionVerdict.DENY,
                secret,
                errorMessage = "nope",
                nowMillis = now,
            )
        assertEquals("user_registration_action_response", denied.objectName)
        assertEquals("nope", denied.payload["error_message"]?.jsonPrimitive?.content)
        assertEquals(
            hmacHex(now, """{"timestamp":$now,"verdict":"Deny","error_message":"nope"}""", secret),
            denied.signature,
        )

        // Allow never carries error_message, even if one is passed — an extra key would
        // change the JSON and therefore the signature AuthKit verifies.
        val allowed =
            actions.signResponse(
                ActionResponseType.AUTHENTICATION,
                ActionVerdict.ALLOW,
                secret,
                errorMessage = "ignored",
                nowMillis = now,
            )
        assertTrue(!allowed.payload.containsKey("error_message"))

        // Deny with no message likewise omits the key.
        val bare = actions.signResponse(ActionResponseType.AUTHENTICATION, ActionVerdict.DENY, secret, nowMillis = now)
        assertTrue(!bare.payload.containsKey("error_message"))
    }

    @Test
    fun `H03 is reachable from the client`() {
        val (client, _) = testClient()
        assertNotNull(client.actions.computeSignature(now.toString(), payload, secret))
    }
}
