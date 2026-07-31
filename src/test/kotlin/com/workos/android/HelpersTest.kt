// @oagen-ignore-file
package com.workos.android

import com.workos.android.helpers.CreatePasswordlessSessionOptions
import com.workos.android.helpers.Pkce
import com.workos.android.helpers.PublicClient
import com.workos.android.helpers.getAuthorizationUrlWithPkce
import com.workos.android.helpers.passwordless
import com.workos.android.helpers.pkce
import com.workos.android.support.bodyJson
import com.workos.android.support.pathOnly
import com.workos.android.support.testClient
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Behavior tests for the hand-maintained helper layer. Each covers a helper ID from
 * `docs/lang-gen/non-spec-endpoints.md`; existence alone is not coverage.
 */
class HelpersTest {
    // --- H08: PKCE utilities ------------------------------------------------

    @Test
    fun `H08 code verifier respects the RFC 7636 length bounds`() {
        val pkce = Pkce()
        assertEquals(43, pkce.generateCodeVerifier().length)
        assertEquals(128, pkce.generateCodeVerifier(128).length)
        // RFC 7636 §4.1 permits 43..128 only.
        assertFailsWith<IllegalArgumentException> { pkce.generateCodeVerifier(42) }
        assertFailsWith<IllegalArgumentException> { pkce.generateCodeVerifier(129) }
    }

    @Test
    fun `H08 code verifier is url-safe and unpredictable`() {
        val pkce = Pkce()
        val a = pkce.generateCodeVerifier()
        val b = pkce.generateCodeVerifier()
        assertTrue(a != b, "two verifiers must not collide")
        // Unreserved characters only, so it needs no escaping in a query string.
        assertTrue(a.all { it.isLetterOrDigit() || it == '-' || it == '_' }, "not url-safe: $a")
    }

    @Test
    fun `H08 challenge is the base64url SHA-256 of the verifier`() {
        val pkce = Pkce()
        val verifier = pkce.generateCodeVerifier()

        val challenge = pkce.generateCodeChallenge(verifier)

        // Recompute independently rather than trusting the implementation.
        val expected =
            Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))
        assertEquals(expected, challenge)
        // The RFC 7636 §B worked example, as a fixed vector.
        assertEquals(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            pkce.generateCodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        )
    }

    @Test
    fun `H08 generate returns a matching pair using S256`() {
        val pair = Pkce().generate()
        assertEquals("S256", pair.codeChallengeMethod)
        assertEquals(Pkce().generateCodeChallenge(pair.codeVerifier), pair.codeChallenge)
    }

    @Test
    fun `H08 is reachable from the client`() {
        val (client, _) = testClient()
        assertNotNull(client.pkce.generate().codeVerifier)
    }

    // --- H10: AuthKit PKCE authorization URL --------------------------------

    @Test
    fun `H10 authorization url carries the generated challenge and state`() {
        val (client, _) = testClient()

        val result = client.userManagement.getAuthorizationUrlWithPkce(redirectUri = "app://cb")

        val query = URI(result.url).query
        assertTrue(query.contains("code_challenge_method=S256"), query)
        assertTrue(query.contains("code_challenge="), query)
        // The verifier must NOT be on the wire — only its hash may be.
        assertTrue(!result.url.contains(result.codeVerifier), "verifier leaked into the URL")
        // And the challenge in the URL must derive from the returned verifier.
        assertEquals(Pkce().generateCodeChallenge(result.codeVerifier), result.codeChallenge)
        assertTrue(result.state.isNotEmpty())
    }

    @Test
    fun `H10 state differs per call, so it is usable as CSRF protection`() {
        val (client, _) = testClient()
        val a = client.userManagement.getAuthorizationUrlWithPkce(redirectUri = "app://cb")
        val b = client.userManagement.getAuthorizationUrlWithPkce(redirectUri = "app://cb")
        assertTrue(a.state != b.state, "state must not repeat")
        assertTrue(a.codeVerifier != b.codeVerifier, "verifier must not repeat")
    }

    // --- H19: public client factory -----------------------------------------

    @Test
    fun `H19 public client exposes the pkce surface and carries no api key`() {
        val public = PublicClient.create(clientId = "client_123")

        assertEquals("client_123", public.clientId)
        assertNotNull(public.pkce.generate().codeChallenge)
        // An empty API key is deliberate: a mobile binary cannot hold a secret, so
        // reaching past this facade must fail at the server rather than silently work.
        assertEquals("", public.client.configuration.apiKey)
    }

    @Test
    fun `H19 builds an authorization url with an auto-generated pkce pair`() {
        val public = PublicClient.create(clientId = "client_123")

        val result = public.getAuthorizationUrlWithPkce(redirectUri = "app://cb")

        assertTrue(result.url.contains("code_challenge="))
        assertTrue(result.url.contains("client_id=client_123"), result.url)
    }

    // --- Passwordless --------------------------------------------------------

    @Test
    fun `passwordless createSession posts the documented wire shape`() =
        runTest {
            val (client, server) =
                testClient(
                    responding =
                        """
                        {"id":"pwl_1","email":"a@b.com","expires_at":"2026-01-01T00:00:00Z",
                        "link":"https://auth.workos.com/x","object":"passwordless_session"}
                        """.trimIndent()
                            .replace("\n", "")
                            .replace("  ", ""),
                )

            val session =
                client.passwordless.createSession(
                    CreatePasswordlessSessionOptions(email = "a@b.com", redirectUri = "https://app/cb"),
                )

            val request = server.takeRequest()
            assertEquals("POST", request.method)
            assertEquals("/passwordless/sessions", request.pathOnly())
            val body = request.bodyJson()
            assertEquals("a@b.com", body["email"]?.jsonPrimitive?.content)
            // `type` defaults to MagicLink, matching workos-kotlin's wire shape.
            assertEquals("MagicLink", body["type"]?.jsonPrimitive?.content)
            assertEquals("https://app/cb", body["redirect_uri"]?.jsonPrimitive?.content)
            assertEquals("pwl_1", session.id)
            assertEquals("https://auth.workos.com/x", session.link)
        }

    @Test
    fun `passwordless createSession omits absent optionals rather than sending null`() =
        runTest {
            val (client, server) =
                testClient(
                    responding = """{"id":"pwl_1","email":"a@b.com","expires_at":"t","link":"l"}""",
                )

            client.passwordless.createSession(CreatePasswordlessSessionOptions(email = "a@b.com"))

            val body = server.takeRequest().bodyJson()
            assertTrue(!body.containsKey("redirect_uri"), "absent optional must be omitted, not null")
            assertTrue(!body.containsKey("state"))
            assertTrue(!body.containsKey("expires_in"))
        }

    @Test
    fun `passwordless sendSession percent-encodes the session id in the path`() =
        runTest {
            val (client, server) = testClient(responding = """{"success":true}""")

            val response = client.passwordless.sendSession("pwl/../evil")

            val request = server.takeRequest()
            assertEquals("POST", request.method)
            // The threat is dot-segment removal, which needs `/../` — encoding the
            // SLASHES is what defeats it. Bare dots inside a single segment are inert,
            // so the id staying one segment is the invariant that matters.
            assertTrue(!request.pathOnly().contains("/../"), request.pathOnly())
            assertEquals(
                listOf("", "passwordless", "sessions", "pwl%2F..%2Fevil", "send"),
                request.pathOnly().split("/"),
                "the id must occupy exactly one path segment",
            )
            assertEquals("/passwordless/sessions/pwl%2F..%2Fevil/send", request.pathOnly())
            assertEquals(true, response.success)
        }
}
